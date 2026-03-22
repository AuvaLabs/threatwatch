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

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from modules.config import (
    LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, LLM_PROVIDER,
    ANTHROPIC_API_KEY, MAX_CONTENT_CHARS, OUTPUT_DIR,
)
from modules.ai_cache import get_cached_result, cache_result

BRIEFING_PATH = OUTPUT_DIR / "briefing.json"
_LAST_API_CALL_PATH = OUTPUT_DIR / ".briefing_last_call"
_BRIEFING_COOLDOWN_SECONDS = 3600  # 1 hour minimum between API calls

_BRIEFING_PROMPT = """You are a senior cyber threat intelligence analyst producing a classified intelligence assessment. Write with the precision and authority of a national CERT or intelligence agency analyst. Every claim must be grounded in the provided incident data — do not fabricate threat actors, CVEs, or incidents not present in the input.

ANALYTICAL STANDARDS:
- Use intelligence community confidence language: "we assess with HIGH/MODERATE/LOW confidence"
- Be specific: name the actual threat actors, malware families, CVEs, and affected organizations from the data
- Identify correlations: if multiple incidents share TTPs, infrastructure, or timing, connect them
- Forecast: project what these developments mean for the next 7-30 days
- Recommendations must be SPECIFIC to the threats observed — never generic ("patch your systems")
- If the data is insufficient to make a confident assessment, say so — do not pad with boilerplate

Respond ONLY with valid JSON (no markdown, no code fences, no explanation):
{
  "threat_level": "CRITICAL|ELEVATED|MODERATE|GUARDED|LOW",
  "assessment_basis": "<1 sentence explaining WHY this threat level was assigned based on the data>",
  "situation_overview": "<2-3 sentence analyst assessment of the current threat landscape, citing specific incidents>",
  "key_intelligence": [
    {
      "finding": "<specific intelligence finding tied to observed data>",
      "confidence": "HIGH|MODERATE|LOW",
      "source_count": <number of articles supporting this finding>
    }
  ],
  "threat_forecast": "<2-3 sentence forward-looking projection. What do these developments indicate for the next 7-30 days? What should defenders prepare for?>",
  "sector_impact": ["<top 3 sectors at elevated risk, each with the specific threat driving that risk>"],
  "priority_actions": [
    {
      "action": "<specific, immediately actionable defensive measure>",
      "threat_context": "<which observed threat this addresses>"
    }
  ]
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
    """Build compact article digest for the prompt."""
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
        if meta_parts:
            lines.append(f"    {' | '.join(meta_parts)}")
        if summary:
            lines.append(f"    {summary}")
    return "\n".join(lines)


def _get_http_session() -> requests.Session:
    """Return a requests session with retry logic for transient errors."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def _call_openai_compatible(user_content: str) -> str:
    """Call any OpenAI-compatible API using requests with retry."""
    url = f"{LLM_BASE_URL.rstrip('/')}/chat/completions"
    payload = {
        "model": LLM_MODEL,
        "max_tokens": 2000,
        "temperature": 0.3,
        "messages": [
            {"role": "system", "content": _BRIEFING_PROMPT},
            {"role": "user", "content": user_content},
        ],
    }

    headers = {"Content-Type": "application/json"}
    if LLM_API_KEY:
        headers["Authorization"] = f"Bearer {LLM_API_KEY}"

    session = _get_http_session()
    resp = session.post(url, json=payload, headers=headers, timeout=90)
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"].strip()


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

    digest = _build_digest(articles)
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
    user_content = (
        f"INTELLIGENCE COLLECTION DATE: {now.strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"TOTAL INCIDENTS IN COLLECTION: {len(articles)}\n"
        f"REPORTING PERIOD: Last 24 hours\n\n"
        f"BEGIN INCIDENT DATA:\n{digest}\n"
        f"END INCIDENT DATA"
    )

    try:
        if provider == "anthropic":
            reply = _call_anthropic(user_content)
        else:
            reply = _call_openai_compatible(user_content)

        briefing = _parse_json(reply)
        if briefing is None:
            logger.warning("Failed to parse intelligence briefing response.")
            return None

        # Schema validation — accept both new and legacy schema
        required = {"threat_level", "situation_overview", "priority_actions"}
        # Fallback: accept legacy field names
        if "executive_summary" in briefing and "situation_overview" not in briefing:
            briefing["situation_overview"] = briefing.pop("executive_summary")
        if "recommended_actions" in briefing and "priority_actions" not in briefing:
            # Convert legacy string list to new format
            legacy = briefing.pop("recommended_actions")
            briefing["priority_actions"] = [
                {"action": a, "threat_context": ""} if isinstance(a, str) else a
                for a in legacy
            ]
        missing = required - briefing.keys()
        if missing:
            logger.warning(f"Intelligence briefing missing required fields: {missing}")
            return None

        # Normalise threat_level
        valid_levels = {"CRITICAL", "ELEVATED", "MODERATE", "GUARDED", "LOW"}
        tl = (briefing.get("threat_level") or "").upper()
        if tl not in valid_levels:
            briefing["threat_level"] = "MODERATE"

        briefing["generated_at"] = now.isoformat()
        briefing["articles_analyzed"] = min(len(articles), _MAX_DIGEST_ARTICLES)
        briefing["total_articles"] = len(articles)
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
