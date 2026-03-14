"""AI-powered threat intelligence briefing generator.

Generates one briefing per pipeline run using any LLM provider.
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

_BRIEFING_PROMPT = """You are a senior cyber threat intelligence analyst writing a classified-style briefing.

Analyze the following cyber threat articles and produce a structured intelligence briefing in JSON format.

Requirements:
- Write in authoritative, concise intelligence-agency style
- Focus on actionable insights, not just summaries
- Identify patterns and connections between incidents
- Assess overall threat posture

Respond ONLY with valid JSON (no markdown, no explanation):
{
  "threat_level": "CRITICAL|ELEVATED|MODERATE|GUARDED|LOW",
  "executive_summary": "<2-3 sentence high-level assessment>",
  "key_developments": ["<3-5 most significant developments, one sentence each>"],
  "active_threats": {
    "nation_state": "<1-2 sentences on nation-state activity or 'No significant nation-state activity detected.'>",
    "ransomware": "<1-2 sentences on ransomware landscape or 'No significant ransomware activity detected.'>",
    "emerging": "<1-2 sentences on emerging/novel threats or 'No emerging threats identified.'>"
  },
  "sector_risk": ["<top 3 sectors at risk with brief reason>"],
  "recommended_actions": ["<3-4 actionable recommendations>"],
  "outlook": "<1-2 sentence forward-looking assessment>"
}"""


def _detect_provider():
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


def _build_digest(articles):
    """Build compact article digest for the prompt."""
    lines = []
    for a in articles[:60]:
        title = a.get("translated_title") or a.get("title", "")
        category = a.get("category", "Unknown")
        region = a.get("feed_region", "Global")
        summary = (a.get("summary") or "")[:200]
        lines.append(f"- [{category}] [{region}] {title}")
        if summary:
            lines.append(f"  Summary: {summary}")
    return "\n".join(lines)


def _get_http_session():
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


def _call_openai_compatible(user_content):
    """Call any OpenAI-compatible API using requests with retry."""
    url = f"{LLM_BASE_URL.rstrip('/')}/chat/completions"
    payload = {
        "model": LLM_MODEL,
        "max_tokens": 1000,
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


def _call_anthropic(user_content):
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
        max_tokens=1000,
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


def generate_briefing(articles):
    """Generate an AI briefing from enriched articles.

    Works with any LLM provider configured via environment variables.
    Returns the briefing dict or None if unavailable.
    """
    provider = _detect_provider()
    if not provider:
        logging.info("No LLM API key configured — skipping AI briefing.")
        return None

    if not articles:
        logging.info("No articles to brief on.")
        return None

    digest = _build_digest(articles)
    cache_key = hashlib.sha256(digest[:MAX_CONTENT_CHARS].encode()).hexdigest()

    # Check cache
    cached = get_cached_result(cache_key)
    if cached is not None:
        logging.info("AI briefing loaded from cache.")
        _save_briefing(cached)
        return cached

    user_content = (
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
        f"Total incidents tracked: {len(articles)}\n\n"
        f"ARTICLES:\n{digest}"
    )

    try:
        if provider == "anthropic":
            reply = _call_anthropic(user_content)
        else:
            reply = _call_openai_compatible(user_content)

        briefing = _parse_json(reply)
        if briefing is None:
            logging.warning("Failed to parse AI briefing response.")
            return None

        briefing["generated_at"] = datetime.now(timezone.utc).isoformat()
        briefing["articles_analyzed"] = len(articles)
        briefing["provider"] = f"{provider}/{LLM_MODEL}"

        cache_result(cache_key, briefing)
        _save_briefing(briefing)
        logging.info(f"AI briefing generated via {provider}/{LLM_MODEL}.")
        return briefing

    except Exception as e:
        logging.error(f"AI briefing generation failed ({provider}): {e}")
        return None


def _parse_json(text):
    """Extract JSON from response text."""
    import re
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return None


def _save_briefing(briefing):
    """Save briefing to disk for the server to serve."""
    BRIEFING_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(BRIEFING_PATH, "w", encoding="utf-8") as f:
        json.dump(briefing, f, ensure_ascii=False)
    logging.info(f"Briefing saved to {BRIEFING_PATH}")


def load_briefing():
    """Load the latest briefing from disk."""
    if not BRIEFING_PATH.exists():
        return None
    try:
        with open(BRIEFING_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None
