"""AI-powered threat intelligence briefing generator.

Generates one briefing per pipeline run using Claude Haiku.
Cost: ~$0.01-0.02 per run ($0.50-1.00/day at 30-min intervals).
"""

import json
import logging
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from modules.config import ANTHROPIC_API_KEY, MAX_CONTENT_CHARS, OUTPUT_DIR
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


def generate_briefing(articles):
    """Generate an AI briefing from enriched articles. One API call per run."""
    if not ANTHROPIC_API_KEY:
        logging.info("No API key — skipping AI briefing generation.")
        return None

    if not articles:
        logging.info("No articles to brief on.")
        return None

    # Build compact article digest for the prompt
    digest_lines = []
    for a in articles[:60]:  # Cap at 60 articles to control token usage
        title = a.get("translated_title") or a.get("title", "")
        category = a.get("category", "Unknown")
        region = a.get("feed_region", "Global")
        summary = (a.get("summary") or "")[:200]
        digest_lines.append(f"- [{category}] [{region}] {title}")
        if summary:
            digest_lines.append(f"  Summary: {summary}")

    digest = "\n".join(digest_lines)
    cache_key = hashlib.sha256(digest[:MAX_CONTENT_CHARS].encode()).hexdigest()

    # Check cache
    cached = get_cached_result(cache_key)
    if cached is not None:
        logging.info("AI briefing loaded from cache.")
        _save_briefing(cached)
        return cached

    try:
        import anthropic
        import httpx

        client = anthropic.Anthropic(
            api_key=ANTHROPIC_API_KEY,
            timeout=httpx.Timeout(90.0, connect=15.0),
            max_retries=2,
        )

        user_content = (
            f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
            f"Total incidents tracked: {len(articles)}\n\n"
            f"ARTICLES:\n{digest}"
        )

        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1000,
            system=[{
                "type": "text",
                "text": _BRIEFING_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{"role": "user", "content": user_content}],
            temperature=0.3,
        )

        # Track cost
        from modules.cost_tracker import track_usage
        track_usage(response)

        reply = response.content[0].text.strip()
        briefing = _parse_json(reply)

        if briefing is None:
            logging.warning("Failed to parse AI briefing response.")
            return None

        briefing["generated_at"] = datetime.now(timezone.utc).isoformat()
        briefing["articles_analyzed"] = len(articles)

        cache_result(cache_key, briefing)
        _save_briefing(briefing)
        logging.info("AI briefing generated successfully.")
        return briefing

    except Exception as e:
        logging.error(f"AI briefing generation failed: {e}")
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
