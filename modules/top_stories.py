"""AI-curated top stories.

Selects the 5-8 most significant incidents from the article corpus for the
security team's daily briefing. Extracted from `briefing_generator.py` to
keep that file under the 800-line cap. Shares the LLM plumbing
(`_detect_provider`, `_call_openai_compatible`, `_parse_json`) via imports
from briefing_generator so there is only one source of truth for provider
routing / rate limits / response parsing.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from modules.ai_cache import get_cached_result, cache_result
from modules.briefing_generator import (
    _detect_provider,
    _call_openai_compatible,
    _parse_json,
    _build_digest,
    _MAX_DIGEST_ARTICLES,
)
from modules.config import OUTPUT_DIR, LLM_MODEL

logger = logging.getLogger(__name__)


_TOP_STORIES_PATH = OUTPUT_DIR / "top_stories.json"
_TOP_STORIES_COOLDOWN = 3600  # 1 hour
_LAST_TOP_STORIES_PATH = OUTPUT_DIR / ".top_stories_last_call"

_TOP_STORIES_PROMPT = """You are a cyber threat intelligence editor selecting the most significant incidents for a security team's daily briefing. Your job: cut through the noise and surface what actually matters.

SELECTION CRITERIA (in order of priority):
1. Active exploitation of vulnerabilities (especially with high EPSS scores)
2. Major breaches affecting large organizations or critical infrastructure
3. Nation-state campaigns with new TTPs or targets
4. Ransomware attacks on critical services (healthcare, utilities, government)
5. Supply chain compromises affecting widely-used software
6. Novel attack techniques or malware families emerging

RULES:
- Select exactly 5-8 stories — no more, no less
- Each summary must be 1-2 sentences explaining WHAT happened and WHY it matters
- Do NOT select generic cybersecurity news, opinion pieces, market reports, or vendor announcements
- If two articles cover the same incident, pick the one with more detail
- Include the article number [N] from the input so we can link back to the source

Respond ONLY with valid JSON (no markdown, no code fences):
{
  "top_stories": [
    {
      "article_index": <number from [N] in input>,
      "headline": "<concise headline, max 100 chars>",
      "summary": "<1-2 sentences: what happened + why it matters>",
      "significance": "CRITICAL|HIGH|MODERATE",
      "category": "<threat category>"
    }
  ]
}"""


def _filter_for_briefing(articles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter and prioritize articles for LLM consumption.

    Removes darkweb victim posts (repetitive), deduplicates by title,
    and prioritizes high-value articles (high confidence, named actors/CVEs).
    """
    seen_titles = set()
    filtered = []
    for a in articles:
        # Skip darkweb victim posts — too repetitive for briefing
        if a.get("darkweb") or a.get("isDarkweb"):
            continue
        # Skip noise
        if a.get("category") == "Noise" or a.get("confidence", 0) == 0:
            continue
        # Title dedup (case-insensitive, strip source suffix)
        title = a.get("title", "").strip().lower()
        # Normalize: remove "- Source Name" suffixes
        title_key = title.rsplit(" - ", 1)[0].rsplit(" | ", 1)[0]
        if title_key in seen_titles:
            continue
        seen_titles.add(title_key)
        filtered.append(a)

    # Sort: most recent first
    filtered.sort(
        key=lambda a: a.get("timestamp", "1970-01-01"),
        reverse=True,
    )
    return filtered


def _split_by_age(articles: list[dict[str, Any]]) -> tuple[list, list, list]:
    """Split articles into (last_24h, days_2_3, days_4_7) buckets."""
    now = datetime.now(timezone.utc)
    day1, day3, older = [], [], []
    for a in articles:
        ts = a.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts)
            age = (now - dt).total_seconds() / 86400
            if age <= 1:
                day1.append(a)
            elif age <= 3:
                day3.append(a)
            else:
                older.append(a)
        except (ValueError, TypeError):
            older.append(a)
    return day1, day3, older


def generate_top_stories(articles: list[dict[str, Any]]) -> list[dict[str, Any]] | None:
    """Generate AI-curated top stories from the article collection.

    Uses a separate rate limit and cache from the main briefing.
    Returns a list of top story dicts or None.
    """
    provider = _detect_provider()
    if not provider or provider == "anthropic":
        return None  # Only use Groq/OpenAI-compatible for this

    if not articles or len(articles) < 10:
        return None

    # Filter and limit to last 72 hours for top stories
    all_filtered = _filter_for_briefing(articles)
    if len(all_filtered) < 10:
        all_filtered = articles

    day1, day3, older = _split_by_age(all_filtered)
    briefing_articles = (day1 + day3)[:_MAX_DIGEST_ARTICLES]  # Last 72h
    if len(briefing_articles) < 10:
        briefing_articles = all_filtered[:_MAX_DIGEST_ARTICLES]

    digest = _build_digest(briefing_articles)
    # Date-bucket the cache key so a near-static corpus still triggers a
    # fresh editorial pass at least once per day. Without the bucket, the
    # ai_cache (no read-side TTL) returns the same selection forever.
    date_bucket = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cache_key = f"topstories_{date_bucket}_" + hashlib.sha256(digest.encode()).hexdigest()

    cached = get_cached_result(cache_key)
    if cached is not None:
        logger.info("Top stories loaded from cache.")
        _save_top_stories(cached)
        return cached

    # Rate limit check
    try:
        if _LAST_TOP_STORIES_PATH.exists():
            last_ts = float(_LAST_TOP_STORIES_PATH.read_text().strip())
            elapsed = datetime.now(timezone.utc).timestamp() - last_ts
            if elapsed < _TOP_STORIES_COOLDOWN:
                existing = load_top_stories()
                if existing:
                    return existing
                return None
    except (ValueError, OSError):
        pass

    now = datetime.now(timezone.utc)
    user_content = (
        f"DATE: {now.strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"TOTAL ARTICLES: {len(briefing_articles)} (filtered from {len(articles)})\n\n"
        f"BEGIN ARTICLES:\n{digest}\nEND ARTICLES"
    )

    try:
        reply = _call_openai_compatible(
            user_content,
            system_prompt=_TOP_STORIES_PROMPT,
            max_tokens=1500,
            caller="top_stories",
        )
        result = _parse_json(reply)
        if not result or "top_stories" not in result:
            logger.warning("Failed to parse top stories response.")
            return None

        stories = result["top_stories"]

        # Enrich with source article data (from filtered list, not raw)
        for story in stories:
            idx = story.get("article_index", 0) - 1  # 1-indexed in prompt
            if 0 <= idx < len(briefing_articles):
                src = briefing_articles[idx]
                story["link"] = src.get("link", "")
                story["source_name"] = src.get("source_name", "")
                story["published"] = src.get("published", "")
                story["original_title"] = src.get("title", "")

        story_data = {
            "stories": stories,
            "generated_at": now.isoformat(),
            "articles_analyzed": min(len(articles), _MAX_DIGEST_ARTICLES),
            "provider": f"{provider}/{LLM_MODEL}",
        }

        # Record and cache
        try:
            _LAST_TOP_STORIES_PATH.parent.mkdir(parents=True, exist_ok=True)
            _LAST_TOP_STORIES_PATH.write_text(str(now.timestamp()))
        except OSError:
            pass
        cache_result(cache_key, story_data)
        _save_top_stories(story_data)
        logger.info(f"Top stories generated: {len(stories)} stories selected.")
        return story_data

    except Exception as e:
        logger.error(f"Top stories generation failed: {e}")
        return None


def _save_top_stories(data: dict[str, Any]) -> None:
    _TOP_STORIES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(_TOP_STORIES_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)


def load_top_stories() -> dict[str, Any] | None:
    if not _TOP_STORIES_PATH.exists():
        return None
    try:
        with open(_TOP_STORIES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None
