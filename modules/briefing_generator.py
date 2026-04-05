"""AI-powered cyber threat intelligence briefing generator.

Generates analyst-grade intelligence briefings using any LLM provider.
Supports OpenAI-compatible APIs (OpenAI, Groq, Together, Ollama, Mistral, DeepSeek)
and Anthropic SDK as a fallback.

Configure via environment variables:
  LLM_API_KEY    — API key (falls back to OPENAI_API_KEY, then ANTHROPIC_API_KEY)
  LLM_BASE_URL   — API base URL (default: https://api.openai.com/v1)
  LLM_MODEL      — Model name (default: gpt-4o-mini)
  LLM_PROVIDER   — auto|openai|anthropic|ollama (default: auto)
"""

import json
import logging
import hashlib
from typing import Any

logger = logging.getLogger(__name__)
from datetime import datetime, timezone
from pathlib import Path


from modules.config import (
    LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, LLM_PROVIDER,
    LLM_API_KEYS, ANTHROPIC_API_KEY, MAX_CONTENT_CHARS, OUTPUT_DIR,
)
from modules.ai_cache import get_cached_result, cache_result
from modules.llm_client import call_llm as _call_groq

BRIEFING_PATH = OUTPUT_DIR / "briefing.json"
_LAST_API_CALL_PATH = OUTPUT_DIR / ".briefing_last_call"
_BRIEFING_COOLDOWN_SECONDS = 3600  # 1 hour minimum between API calls

_BRIEFING_PROMPT = """You are a senior cyber threat intelligence analyst writing a daily intelligence digest. Write like a national CERT analyst — precise, authoritative, grounded in the data. Never fabricate incidents.

THREAT LEVEL:
- CRITICAL: Active exploitation of widespread vulnerabilities, critical infrastructure breaches, coordinated nation-state campaigns
- ELEVATED: Multiple ransomware campaigns, significant breaches, high-CVSS vulns with public exploits
- MODERATE: Typical activity — ongoing ransomware, phishing, routine disclosures
- GUARDED/LOW: Below-average activity

RULES:
- Name SPECIFIC threat actors, CVEs, organizations, malware — never say "ransomware is increasing" without naming which groups and victims
- Every claim must cite source article numbers [N] in the "sources" array
- "what_happened" is the MAIN SECTION — write it as a narrative that covers the most significant incidents, weaving in trending patterns, CVE details, and ATT&CK tactics. Do NOT repeat information across sections.
- "what_to_do" actions must reference the SPECIFIC threats from what_happened — never generic ("patch your systems", "train employees")
- If CVEs have EPSS scores, include them in the narrative (e.g., "CVE-2026-5212 affecting D-Link routers has a 94% EPSS exploitation probability — patch immediately")
- If EARLIER THIS WEEK data is provided, write a "week_in_review" catching readers up on what they missed
- "outlook" should project what SPECIFIC developments mean for the next 7-30 days

Respond ONLY with valid JSON (no markdown, no code fences):
{
  "threat_level": "CRITICAL|ELEVATED|MODERATE|GUARDED|LOW",
  "assessment_basis": "<1 sentence: WHY this level, citing the key driver>",
  "what_happened": "<4-6 sentence narrative covering the most significant incidents from the last 24 hours. Name actors, victims, CVEs, and attack methods. Weave in trending patterns and vulnerability details rather than listing them separately. Each incident should be distinct — no repetition.>",
  "what_happened_sources": [<article numbers>],
  "what_to_do": [
    {
      "action": "<specific defensive measure tied to an incident above>",
      "threat": "<which specific incident or CVE this addresses>",
      "sources": [<article numbers>]
    }
  ],
  "week_in_review": "<2-3 sentences on the most significant incidents from days 2-7 that readers should know about. Name specific incidents. Omit if no EARLIER THIS WEEK data provided.>",
  "week_in_review_sources": [<article numbers if available>],
  "outlook": "<2-3 sentences: what do these SPECIFIC developments mean for the next 7-30 days? What should defenders prepare for?>"
}"""


def _detect_provider() -> str | None:
    """Auto-detect the LLM provider from config."""
    if LLM_PROVIDER != "auto":
        return LLM_PROVIDER
    if not LLM_API_KEY:
        return None
    base = LLM_BASE_URL.lower()
    if "anthropic" in base:
        return "anthropic"
    if "localhost" in base or "127.0.0.1" in base:
        return "ollama"
    # Default to openai-compatible (works with OpenAI, Groq, Together, Mistral, etc.)
    return "openai"


_MAX_DIGEST_ARTICLES = 80  # articles sent to the LLM


def _build_digest(articles: list[dict[str, Any]]) -> str:
    """Build compact article digest with enrichment data for the prompt."""
    lines = []
    for i, a in enumerate(articles[:_MAX_DIGEST_ARTICLES], 1):
        title = a.get("translated_title") or a.get("title", "")
        category = a.get("category", "Unknown")
        region = a.get("feed_region", "Global")
        source = a.get("source_name", "")
        published = a.get("published", "")[:16]
        summary = (a.get("summary") or "")[:250]
        lines.append(f"[{i}] [{category}] [{region}] {title}")
        meta_parts = []
        if source:
            meta_parts.append(f"Source: {source}")
        if published:
            meta_parts.append(f"Published: {published}")
        # Include CVE/EPSS/CVSS enrichment
        cve_id = a.get("cve_id", "")
        if cve_id:
            meta_parts.append(f"CVE: {cve_id}")
        cvss = a.get("cvss_score")
        if cvss:
            meta_parts.append(f"CVSS: {cvss}")
        epss_max = a.get("epss_max_score")
        if epss_max and epss_max > 0:
            meta_parts.append(f"EPSS: {epss_max:.1%}")
        epss_risk = a.get("epss_risk", "")
        if epss_risk and epss_risk != "LOW":
            meta_parts.append(f"Exploit risk: {epss_risk}")
        # Include ATT&CK tactics
        tactics = a.get("attack_tactics", [])
        if tactics:
            meta_parts.append(f"ATT&CK: {', '.join(tactics[:3])}")
        if meta_parts:
            lines.append(f"    {' | '.join(meta_parts)}")
        if summary:
            lines.append(f"    {summary}")
    return "\n".join(lines)


def _build_trend_context() -> str:
    """Load trend spike data and format for the LLM prompt."""
    trends_path = OUTPUT_DIR.parent / "state" / "trends.json"
    if not trends_path.exists():
        return ""
    try:
        with open(trends_path, "r", encoding="utf-8") as f:
            trends = json.load(f)
        spikes = trends.get("spikes", [])
        if not spikes:
            return ""
        lines = ["TRENDING THREATS (keywords/categories spiking above baseline):"]
        for spike in spikes[:10]:
            keyword = spike.get("keyword", "")
            current = spike.get("current_count", 0)
            avg = spike.get("average", 0)
            ratio = spike.get("ratio", 0)
            lines.append(
                f"  - {keyword}: {current} mentions today "
                f"({ratio:.1f}x the 14-day average of {avg:.1f})"
            )
        return "\n".join(lines)
    except (json.JSONDecodeError, IOError):
        return ""


def _build_vuln_context(articles: list[dict[str, Any]]) -> str:
    """Extract top CVEs by EPSS/CVSS from enriched articles."""
    cves = []
    for a in articles:
        cve_id = a.get("cve_id", "")
        if not cve_id:
            continue
        cvss = a.get("cvss_score", 0) or 0
        epss = a.get("epss_max_score", 0) or 0
        cves.append({
            "cve_id": cve_id,
            "cvss": cvss,
            "epss": epss,
            "epss_risk": a.get("epss_risk", ""),
            "severity": a.get("cvss_severity", ""),
            "products": ", ".join(a.get("affected_products", [])[:3]),
            "title": a.get("title", "")[:80],
        })
    if not cves:
        return ""
    # Sort by EPSS desc, then CVSS desc
    cves.sort(key=lambda c: (c["epss"], c["cvss"]), reverse=True)
    lines = ["TOP VULNERABILITIES BY EXPLOITATION PROBABILITY:"]
    for c in cves[:8]:
        parts = [f"{c['cve_id']}"]
        if c["cvss"]:
            parts.append(f"CVSS {c['cvss']}")
        if c["epss"]:
            parts.append(f"EPSS {c['epss']:.1%}")
        if c["severity"]:
            parts.append(c["severity"])
        if c["products"]:
            parts.append(f"Affects: {c['products']}")
        lines.append(f"  - {' | '.join(parts)}")
    return "\n".join(lines)


def _compute_reporting_window(articles: list[dict[str, Any]]) -> str:
    """Determine the actual reporting window from article dates."""
    from collections import Counter
    dates = []
    for a in articles:
        pub = a.get("published", "")
        if pub:
            try:
                date_str = pub[:10] if pub[:4].isdigit() else ""
                if date_str:
                    dates.append(date_str)
            except (ValueError, IndexError):
                pass
    if not dates:
        return "Last 7 days"
    date_counts = Counter(dates)
    unique_dates = sorted(date_counts.keys())
    if len(unique_dates) <= 1:
        return "Last 24 hours"
    span = len(unique_dates)
    return f"Last {span} days ({unique_dates[0]} to {unique_dates[-1]})"




def _call_openai_compatible(user_content: str, system_prompt: str = None,
                            max_tokens: int = 2000) -> str:
    """Call Groq/OpenAI-compatible API via shared llm_client."""
    return _call_groq(
        user_content,
        system_prompt=system_prompt or _BRIEFING_PROMPT,
        max_tokens=max_tokens,
    )


def _call_anthropic(user_content: str) -> str:
    """Call Anthropic API using the SDK."""
    import anthropic
    import httpx

    client = anthropic.Anthropic(
        api_key=ANTHROPIC_API_KEY,
        timeout=httpx.Timeout(90.0, connect=15.0),
        max_retries=2,
    )

    response = client.messages.create(
        model=LLM_MODEL,
        max_tokens=1500,
        system=[{
            "type": "text",
            "text": _BRIEFING_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }],
        messages=[{"role": "user", "content": user_content}],
        temperature=0.3,
    )

    # Track cost if available
    try:
        from modules.cost_tracker import track_usage
        track_usage(response)
    except Exception:
        pass

    return response.content[0].text.strip()


def _is_rate_limited() -> bool:
    """Check if we should skip the API call due to hourly rate limit."""
    try:
        if _LAST_API_CALL_PATH.exists():
            last_ts = float(_LAST_API_CALL_PATH.read_text().strip())
            elapsed = datetime.now(timezone.utc).timestamp() - last_ts
            if elapsed < _BRIEFING_COOLDOWN_SECONDS:
                remaining = int(_BRIEFING_COOLDOWN_SECONDS - elapsed)
                logger.info(
                    f"Briefing rate-limited — last call {int(elapsed)}s ago, "
                    f"next allowed in {remaining}s."
                )
                return True
    except (ValueError, OSError):
        pass
    return False


def _record_api_call() -> None:
    """Record timestamp of successful API call."""
    try:
        _LAST_API_CALL_PATH.parent.mkdir(parents=True, exist_ok=True)
        _LAST_API_CALL_PATH.write_text(
            str(datetime.now(timezone.utc).timestamp())
        )
    except OSError:
        pass


def generate_briefing(articles: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Generate an AI-powered intelligence briefing from enriched articles.

    Works with any LLM provider configured via environment variables.
    Rate-limited to 1 API call per hour. Returns the briefing dict or None.
    """
    provider = _detect_provider()
    if not provider:
        logger.info("No LLM API key configured — skipping intelligence briefing.")
        return None

    if not articles:
        logger.info("No articles to brief on.")
        return None

    # Filter and split by time window
    all_filtered = _filter_for_briefing(articles)
    if len(all_filtered) < 10:
        all_filtered = articles

    day1, day3, older = _split_by_age(all_filtered)

    # Digest focuses on last 24h (with overflow from day 2-3 if sparse)
    briefing_articles = day1[:]
    if len(briefing_articles) < 30:
        briefing_articles.extend(day3[:30 - len(briefing_articles)])
    briefing_articles = briefing_articles[:_MAX_DIGEST_ARTICLES]

    # Build trailing "this week" context from older articles
    trailing_articles = day3 + older
    trailing_context = ""
    if trailing_articles:
        # Quick summary of what happened earlier this week
        from collections import Counter
        trail_cats = Counter(a.get("category", "") for a in trailing_articles)
        top_trail = trail_cats.most_common(5)
        trail_titles = [a.get("title", "")[:80] for a in trailing_articles[:15]]
        trailing_context = (
            f"\nEARLIER THIS WEEK ({len(trailing_articles)} articles from days 2-7):\n"
            f"Category breakdown: {', '.join(f'{c} ({n})' for c, n in top_trail)}\n"
            f"Notable incidents:\n" + "\n".join(f"  - {t}" for t in trail_titles)
        )

    digest = _build_digest(briefing_articles)
    cache_key = hashlib.sha256(digest.encode()).hexdigest()

    # Check content cache first
    cached = get_cached_result(cache_key)
    if cached is not None:
        logger.info("Intelligence briefing loaded from cache.")
        _save_briefing(cached)
        return cached

    # Hourly rate limit — serve stale briefing if available
    if _is_rate_limited():
        existing = load_briefing()
        if existing:
            logger.info("Serving existing briefing (rate-limited).")
            return existing
        return None

    now = datetime.now(timezone.utc)
    reporting_window = "Last 24 hours"
    trend_context = _build_trend_context()
    vuln_context = _build_vuln_context(briefing_articles)

    context_sections = [
        f"INTELLIGENCE COLLECTION DATE: {now.strftime('%Y-%m-%d %H:%M UTC')}",
        f"TOTAL ARTICLES IN COLLECTION: {len(briefing_articles)} (filtered from {len(articles)} total)",
        f"REPORTING PERIOD: {reporting_window}",
    ]
    if trend_context:
        context_sections.append(f"\n{trend_context}")
    if vuln_context:
        context_sections.append(f"\n{vuln_context}")
    context_sections.append(
        f"\nBEGIN INCIDENT DATA (LAST 24 HOURS):\n{digest}\nEND INCIDENT DATA"
    )
    if trailing_context:
        context_sections.append(trailing_context)
    user_content = "\n".join(context_sections)

    try:
        if provider == "anthropic":
            reply = _call_anthropic(user_content)
        else:
            reply = _call_openai_compatible(user_content)

        briefing = _parse_json(reply)
        if briefing is None:
            logger.warning("Failed to parse intelligence briefing response.")
            return None

        # Schema validation — new 5-section schema
        required = {"threat_level", "what_happened"}
        # Backwards compat: map old field names to new
        if "situation_overview" in briefing and "what_happened" not in briefing:
            briefing["what_happened"] = briefing.pop("situation_overview")
        if "priority_actions" in briefing and "what_to_do" not in briefing:
            briefing["what_to_do"] = briefing.pop("priority_actions")
        if "threat_forecast" in briefing and "outlook" not in briefing:
            briefing["outlook"] = briefing.pop("threat_forecast")
        missing = required - briefing.keys()
        if missing:
            logger.warning(f"Intelligence briefing missing required fields: {missing}")
            return None

        # Normalise threat_level
        valid_levels = {"CRITICAL", "ELEVATED", "MODERATE", "GUARDED", "LOW"}
        tl = (briefing.get("threat_level") or "").upper()
        if tl not in valid_levels:
            briefing["threat_level"] = "MODERATE"

        # Ensure optional sections have defaults
        briefing.setdefault("what_to_do", [])
        briefing.setdefault("week_in_review", "")
        briefing.setdefault("outlook", "")

        # Build source article map so frontend can resolve [N] → link/title
        source_map = []
        for i, a in enumerate(briefing_articles[:_MAX_DIGEST_ARTICLES], 1):
            source_map.append({
                "index": i,
                "title": (a.get("translated_title") or a.get("title", ""))[:120],
                "link": a.get("link", ""),
                "source_name": a.get("source_name", ""),
            })
        briefing["source_articles"] = source_map

        briefing["generated_at"] = now.isoformat()
        briefing["articles_analyzed"] = min(len(briefing_articles), _MAX_DIGEST_ARTICLES)
        briefing["total_articles"] = len(articles)  # total including darkweb
        briefing["reporting_window"] = reporting_window
        briefing["provider"] = f"{provider}/{LLM_MODEL}"

        _record_api_call()
        cache_result(cache_key, briefing)
        _save_briefing(briefing)
        logger.info(f"Intelligence briefing generated via {provider}/{LLM_MODEL}.")
        return briefing

    except Exception as e:
        logger.error(f"Intelligence briefing generation failed ({provider}): {e}")
        return None


from modules.utils import extract_json as _parse_json


def _save_briefing(briefing: dict[str, Any]) -> None:
    """Save briefing to disk for the server to serve."""
    BRIEFING_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(BRIEFING_PATH, "w", encoding="utf-8") as f:
        json.dump(briefing, f, ensure_ascii=False)
    logger.info(f"Briefing saved to {BRIEFING_PATH}")


def load_briefing() -> dict[str, Any] | None:
    """Load the latest briefing from disk."""
    if not BRIEFING_PATH.exists():
        return None
    try:
        with open(BRIEFING_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


# --- Top Stories: AI-curated most significant incidents ---

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
    cache_key = "topstories_" + hashlib.sha256(digest.encode()).hexdigest()

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


# --- AI Article Summaries: batch-summarize articles missing summaries ---

_SUMMARY_BATCH_SIZE = 10  # articles per LLM call
_MAX_SUMMARIES_PER_RUN = 30  # cap per pipeline run to stay within budget

_SUMMARY_PROMPT = """You are a cyber threat intelligence analyst. For each article, extract key intelligence details in a structured format.

Rules:
- Keep each field concise (under 80 chars per field)
- "what": the incident or event (e.g. "ransomware attack", "data breach", "vulnerability disclosed")
- "who": affected organization, threat actor, or both (e.g. "LockBit targeted NHS hospitals")
- "impact": the consequence or scale (e.g. "500K records exposed", "systems offline for 3 days")
- "summary": 1 sentence combining the above into a readable intelligence summary
- If a field is unknown from the content, use null
- For CVE/vulnerability articles, include product and severity in "what"
- Return ONLY valid JSON array — no markdown, no explanation

Input format: numbered articles with title and content snippet.
Output format:
[
  {"index": 1, "what": "...", "who": "...", "impact": "...", "summary": "..."},
  {"index": 2, "what": "...", "who": "...", "impact": "...", "summary": "..."}
]"""


def summarize_articles(articles: list[dict[str, Any]]) -> int:
    """Generate AI summaries for articles that lack them.

    Modifies articles in-place. Returns count of summaries generated.
    Uses batched calls to minimize token usage.
    """
    provider = _detect_provider()
    if not provider or provider == "anthropic":
        return 0

    # Find articles missing summaries
    needs_summary = [
        (i, a) for i, a in enumerate(articles)
        if not a.get("summary") and a.get("is_cyber_attack")
        and a.get("title")
    ]

    if not needs_summary:
        return 0

    # Cap to prevent budget overrun
    needs_summary = needs_summary[:_MAX_SUMMARIES_PER_RUN]
    total_generated = 0

    # Process in batches
    for batch_start in range(0, len(needs_summary), _SUMMARY_BATCH_SIZE):
        batch = needs_summary[batch_start:batch_start + _SUMMARY_BATCH_SIZE]

        # Build batch prompt
        lines = []
        for batch_idx, (_, article) in enumerate(batch, 1):
            title = article.get("translated_title") or article.get("title", "")
            content = (article.get("full_content") or "")[:500]
            lines.append(f"[{batch_idx}] {title}")
            if content:
                lines.append(f"    {content}")

        user_content = "\n".join(lines)
        cache_key = "summaries_" + hashlib.sha256(user_content.encode()).hexdigest()

        cached = get_cached_result(cache_key)
        if cached is not None:
            summaries = cached
        else:
            try:
                reply = _call_openai_compatible(
                    user_content,
                    system_prompt=_SUMMARY_PROMPT,
                    max_tokens=800,
                )
                summaries = _parse_json(reply)
                if summaries is None:
                    continue
                # Handle both list and dict-with-list responses
                if isinstance(summaries, dict):
                    summaries = summaries.get("summaries", [])
                cache_result(cache_key, summaries)
            except Exception as e:
                logger.warning(f"Summary batch failed: {e}")
                continue

        # Apply summaries back to articles
        if isinstance(summaries, list):
            for item in summaries:
                batch_idx = item.get("index", 0) - 1
                summary_text = item.get("summary", "")
                if 0 <= batch_idx < len(batch) and summary_text:
                    orig_idx = batch[batch_idx][0]
                    articles[orig_idx]["summary"] = summary_text
                    # Store structured intel fields if available
                    if item.get("what"):
                        articles[orig_idx]["intel_what"] = item["what"]
                    if item.get("who"):
                        articles[orig_idx]["intel_who"] = item["who"]
                    if item.get("impact"):
                        articles[orig_idx]["intel_impact"] = item["impact"]
                    total_generated += 1

    if total_generated > 0:
        logger.info(f"AI summaries generated: {total_generated} articles enriched.")
    return total_generated
