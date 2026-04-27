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
import os
from typing import Any

logger = logging.getLogger(__name__)
from datetime import datetime, timezone
from pathlib import Path


from modules.config import (
    LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, LLM_PROVIDER, BRIEFING_MODEL,
    LLM_API_KEYS, ANTHROPIC_API_KEY, MAX_CONTENT_CHARS, OUTPUT_DIR,
)
from modules.ai_cache import get_cached_result, cache_result
from modules.llm_client import call_llm as _call_groq

BRIEFING_PATH = OUTPUT_DIR / "briefing.json"

_VALID_THREAT_LEVELS = frozenset({"CRITICAL", "ELEVATED", "MODERATE", "GUARDED", "LOW"})
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
- "headline" is the front-of-page TL;DR — 1 sentence, ≤140 chars, leading with the SINGLE most impactful item from what_happened. Name the specific actor/CVE/victim. Active voice. No throat-clearing ("Over the last 24 hours...", "Several incidents..."). Examples of good vs bad: GOOD = "CISA adds Cisco ASA zero-day CVE-2026-1234 to KEV after Volt Typhoon mass exploitation." BAD = "There were several significant cybersecurity events today including..."
- "what_happened" is the MAIN SECTION — write it as a narrative that covers the most significant incidents, weaving in trending patterns, CVE details, and ATT&CK tactics. Do NOT repeat information across sections.
- "what_to_do" actions must reference the SPECIFIC threats from what_happened — never generic ("patch your systems", "train employees")
- KEV-listed CVEs (marked "KEV-listed [date]" in the vuln context) are CONFIRMED exploited in the wild by CISA — when one appears, lead with it and surface the KEV status explicitly (e.g., "CVE-2026-3844 was added to the CISA KEV catalog on 2026-04-25, confirming active in-the-wild exploitation"). Mark the matching what_to_do action as urgent.
- If CVEs have EPSS scores, include them in the narrative (e.g., "CVE-2026-5212 affecting D-Link routers has a 94% EPSS exploitation probability — patch immediately"). EPSS = probability; KEV = confirmed fact. Prefer KEV phrasing when both exist.
- If EARLIER THIS WEEK data is provided, write a "week_in_review" catching readers up on what they missed
- "outlook" should project what SPECIFIC developments mean for the next 7-30 days

Respond ONLY with valid JSON (no markdown, no code fences). All arrays must use strict JSON — use `[]` for empty arrays, never `[none]`, `[None]`, or `[undefined]`. Use `null` or an empty string for missing string values.
{
  "threat_level": "CRITICAL|ELEVATED|MODERATE|GUARDED|LOW",
  "headline": "<1 sentence, ≤140 chars: the single most important development right now. Active voice, named entities, no boilerplate openers.>",
  "assessment_basis": "<1 sentence: WHY this level, citing the key driver>",
  "what_happened": "<4-6 sentence narrative covering the most significant incidents from the last 24 hours. Name actors, victims, CVEs, and attack methods. Weave in trending patterns and vulnerability details rather than listing them separately. Each incident should be distinct — no repetition.>",
  "what_happened_sources": [1, 2, 3],
  "what_to_do": [
    {
      "action": "<specific defensive measure tied to an incident above>",
      "threat": "<which specific incident or CVE this addresses>",
      "sources": [1, 2]
    }
  ],
  "week_in_review": "<2-3 sentences on the most significant incidents from days 2-7 that readers should know about. Name specific incidents. Use an empty string if no EARLIER THIS WEEK data provided.>",
  "week_in_review_sources": [1, 2],
  "outlook": "<2-3 sentences: what do these SPECIFIC developments mean for the next 7-30 days? What should defenders prepare for?>"
}
Every array field (`what_happened_sources`, `what_to_do[].sources`, `week_in_review_sources`) must be a JSON array of integers like `[1, 4, 7]` or an empty array `[]`. Never use the words `none`, `null`, or `undefined` inside an array."""


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


_MAX_DIGEST_ARTICLES = 80  # articles sent to the LLM (regional briefings)
# Global briefing has a tighter cap because Groq free-tier TPM is 6K per request
# (system prompt ~1.5K + max_tokens reserve ~1.5K leaves ~3K for the digest).
# Regional digests are fine at 80 because their per-region article count rarely
# fills the cap. Lift if the briefing moves to a paid tier or larger context.
_MAX_BRIEFING_ARTICLES = 40
_HEADLINE_SOFT_CAP = 160   # belt-and-braces trim if model overshoots the prompt cap
# Per-article summary char budget in the briefing prompt. Sized so the full
# digest stays under Groq free-tier 6K TPM ceiling. Lift if the briefing moves
# to a paid tier or larger context model.
_DIGEST_SUMMARY_CHARS = 80


def _normalise_headline(raw: str | None) -> str:
    """Trim a model-supplied headline to a clause boundary near the soft cap.

    The prompt asks for ≤140 chars, but models occasionally overshoot. We
    accept up to 160 silently; beyond that, prefer to cut at ", "/"; "/". "
    so the result still reads as a complete thought, falling back to a
    word-boundary trim with an ellipsis.
    """
    text = (raw or "").strip()
    if len(text) <= _HEADLINE_SOFT_CAP:
        return text
    cut = text[:_HEADLINE_SOFT_CAP]
    clause = max(cut.rfind(", "), cut.rfind("; "), cut.rfind(". "))
    if clause >= 100:
        return cut[:clause] + "…"
    return cut.rstrip() + "…"


def _build_digest(articles: list[dict[str, Any]]) -> str:
    """Build compact article digest with enrichment data for the prompt."""
    lines = []
    for i, a in enumerate(articles[:_MAX_DIGEST_ARTICLES], 1):
        title = a.get("translated_title") or a.get("title", "")
        category = a.get("category", "Unknown")
        region = a.get("feed_region", "Global")
        source = a.get("source_name", "")
        published = a.get("published", "")[:16]
        summary = (a.get("summary") or "")[:_DIGEST_SUMMARY_CHARS]
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
        # CISA KEV — authoritative "actively exploited" flag
        if a.get("kev_listed"):
            kev_tag = "KEV-listed"
            kev_date = a.get("kev_min_date_added", "")
            if kev_date:
                kev_tag = f"KEV-listed {kev_date}"
            if a.get("kev_ransomware_use") == "Known":
                kev_tag += " (ransomware-linked)"
            meta_parts.append(kev_tag)
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
    """Extract top CVEs by KEV listing → EPSS → CVSS from enriched articles."""
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
            "kev_listed": bool(a.get("kev_listed")),
            "kev_date": a.get("kev_min_date_added", ""),
            "kev_ransomware": a.get("kev_ransomware_use") == "Known",
        })
    if not cves:
        return ""
    # KEV-listed first, then EPSS desc, then CVSS desc — defenders should see
    # confirmed-in-the-wild CVEs at the top regardless of probability scores.
    cves.sort(key=lambda c: (c["kev_listed"], c["epss"], c["cvss"]), reverse=True)
    lines = ["TOP VULNERABILITIES (KEV-listed first, then EPSS/CVSS):"]
    for c in cves[:8]:
        parts = [f"{c['cve_id']}"]
        if c["kev_listed"]:
            kev_part = "KEV-listed"
            if c["kev_date"]:
                kev_part = f"KEV-listed {c['kev_date']}"
            if c["kev_ransomware"]:
                kev_part += " (ransomware-linked)"
            parts.append(kev_part)
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
                            max_tokens: int = 2000,
                            caller: str | None = None,
                            model: str | None = None) -> str:
    """Call Groq/OpenAI-compatible API via shared llm_client.

    All briefing callers expect strict JSON back, so we opt into Groq's
    structured output mode (``response_format={"type": "json_object"}``) here
    — the single choke point for global/regional/top-stories/summary LLM calls.
    The shared client auto-falls back to a plain call if the provider rejects
    the field, so this is safe to ship even if Groq ever drops support.

    The ``model`` kwarg lets a caller opt into a lighter Groq model (e.g.
    ``llama-3.1-8b-instant``) for tasks where the default 70B is too
    token-heavy for free-tier TPM. Defaults to the global ``LLM_MODEL``.
    """
    return _call_groq(
        user_content,
        system_prompt=system_prompt or _BRIEFING_PROMPT,
        max_tokens=max_tokens,
        response_format={"type": "json_object"},
        caller=caller,
        model=model,
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
    # Final fallback: if every article lacked a parseable timestamp so day1
    # and day3 both came back empty, still generate a briefing from the full
    # filtered corpus. Without this the briefing silently returns 0 articles
    # analysed — much worse than a slightly-less-time-focused digest.
    if not briefing_articles:
        briefing_articles = list(all_filtered)
    briefing_articles = briefing_articles[:_MAX_BRIEFING_ARTICLES]

    # Build trailing "this week" context from older articles, excluding
    # anything already pulled into briefing_articles (day3 overflow).
    briefing_ids = {id(a) for a in briefing_articles}
    trailing_articles = [
        a for a in (day3 + older) if id(a) not in briefing_ids
    ]
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
    # Include trailing context in the cache key so the briefing regenerates
    # when "earlier this week" content changes, even if the last-24h set is
    # identical between runs.
    cache_key = hashlib.sha256((digest + trailing_context).encode()).hexdigest()

    # Check content cache first
    cached = get_cached_result(cache_key)
    if cached is not None:
        logger.info("Intelligence briefing loaded from cache.")
        # Re-stamp generated_at: the digest is unchanged, so the analysis is
        # still current. Without this, a run-to-run cache hit keeps the old
        # timestamp and the staleness alarm fires even though the pipeline is
        # healthy and the content is valid.
        cached = {**cached, "generated_at": datetime.now(timezone.utc).isoformat()}
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
            reply = _call_openai_compatible(
                user_content, caller="briefing",
                model=BRIEFING_MODEL, max_tokens=1200,
            )

        briefing = _parse_json(reply)
        if briefing is None:
            logger.warning("Failed to parse intelligence briefing response.")
            return None

        # Schema validation — new 5-section schema
        required = {"threat_level", "what_happened"}
        # Backwards compat: accept both v1 (executive_summary / recommended_actions)
        # and middle-era (situation_overview / priority_actions) field names.
        # Each alternative maps to the current canonical field if the current
        # field is not already present.
        _LEGACY_MAP = (
            ("situation_overview", "what_happened"),
            ("executive_summary",  "what_happened"),
            ("priority_actions",   "what_to_do"),
            ("recommended_actions","what_to_do"),
            ("threat_forecast",    "outlook"),
        )
        for legacy_key, new_key in _LEGACY_MAP:
            if legacy_key in briefing and new_key not in briefing:
                briefing[new_key] = briefing.pop(legacy_key)
        # Normalise what_to_do shape: legacy versions sent a list of strings,
        # current schema expects a list of dicts with at least {action: ...}.
        wtd = briefing.get("what_to_do")
        if isinstance(wtd, list):
            briefing["what_to_do"] = [
                {"action": a} if isinstance(a, str) else a for a in wtd
            ]
        missing = required - briefing.keys()
        if missing:
            logger.warning(f"Intelligence briefing missing required fields: {missing}")
            return None

        # Normalise threat_level
        tl = (briefing.get("threat_level") or "").upper()
        if tl not in _VALID_THREAT_LEVELS:
            briefing["threat_level"] = "MODERATE"

        # Ensure optional sections have defaults
        briefing.setdefault("what_to_do", [])
        briefing.setdefault("week_in_review", "")
        briefing.setdefault("outlook", "")
        # Surface as TL;DR hero on the dashboard; blank string lets the
        # frontend's regex distillation of what_happened take over.
        briefing["headline"] = _normalise_headline(briefing.get("headline"))

        # Build source article map so frontend can resolve [N] → link/title
        source_map = []
        for i, a in enumerate(briefing_articles[:_MAX_BRIEFING_ARTICLES], 1):
            source_map.append({
                "index": i,
                "title": (a.get("translated_title") or a.get("title", ""))[:120],
                "link": a.get("link", ""),
                "source_name": a.get("source_name", ""),
            })
        briefing["source_articles"] = source_map

        # Stamp generated_at at save time, not function entry. The LLM call above
        # can block for a long time under rate-limit backoff; using the pre-call
        # `now` made the briefing look hours old the moment it hit disk and
        # tripped the staleness alarm immediately on save.
        briefing["generated_at"] = datetime.now(timezone.utc).isoformat()
        briefing["articles_analyzed"] = min(len(briefing_articles), _MAX_BRIEFING_ARTICLES)
        briefing["total_articles"] = len(articles)  # total including darkweb
        briefing["reporting_window"] = reporting_window
        briefing_model_name = LLM_MODEL if provider == "anthropic" else BRIEFING_MODEL
        briefing["provider"] = f"{provider}/{briefing_model_name}"

        _record_api_call()
        cache_result(cache_key, briefing)
        _save_briefing(briefing)
        logger.info(f"Intelligence briefing generated via {provider}/{briefing_model_name}.")
        return briefing

    except Exception as e:
        logger.error(f"Intelligence briefing generation failed ({provider}): {e}")
        return None


from modules.utils import extract_json as _parse_json


def _read_prior_level(path: Path) -> tuple[str | None, str | None]:
    """Return (threat_level, generated_at) of the briefing currently on disk.

    Used to stamp `previous_threat_level` on the new briefing so the dashboard
    can render an escalation/de-escalation banner. Returns (None, None) for
    first-ever runs or unreadable files — the frontend treats those as "no
    prior to compare against" and suppresses the banner.
    """
    if not path.exists():
        return (None, None)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return (None, None)
    # Validate before returning: a tampered or hand-edited briefing.json
    # could otherwise feed garbage into the dashboard escalation banner.
    level = data.get("threat_level")
    if level not in _VALID_THREAT_LEVELS:
        level = None
    generated_at = data.get("generated_at")
    if not isinstance(generated_at, str):
        generated_at = None
    return (level, generated_at)


def _stamp_previous_level(briefing: dict[str, Any], path: Path) -> dict[str, Any]:
    """Return a new briefing dict carrying the prior on-disk level/timestamp.

    Non-mutating: callers receive a fresh dict so the original (which may
    still be held by the cache layer) is not silently modified.
    """
    prev_level, prev_at = _read_prior_level(path)
    return {
        **briefing,
        "previous_threat_level": prev_level,
        "previous_generated_at": prev_at,
    }


def _save_briefing(briefing: dict[str, Any]) -> None:
    """Save briefing to disk for the server to serve."""
    stamped = _stamp_previous_level(briefing, BRIEFING_PATH)
    BRIEFING_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(BRIEFING_PATH, "w", encoding="utf-8") as f:
        json.dump(stamped, f, ensure_ascii=False)
    logger.info("Briefing saved to %s", BRIEFING_PATH)


def load_briefing() -> dict[str, Any] | None:
    """Load the latest briefing from disk."""
    if not BRIEFING_PATH.exists():
        return None
    try:
        with open(BRIEFING_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


# --- Regional Intelligence Digests ---

_REGIONAL_CONFIGS = {
    "na": {
        "name": "North America",
        "labels": {"US", "Canada", "Mexico", "NA"},
    },
    "emea": {
        "name": "EMEA",
        "labels": {"UK", "Germany", "France", "Italy", "Spain", "Netherlands",
                   "EU", "EMEA", "Europe", "South Africa", "Africa",
                   "Poland", "Sweden", "Norway", "Denmark", "Switzerland",
                   "Ireland", "Belgium", "Portugal", "Romania", "Czech"},
    },
    "apac": {
        "name": "Asia-Pacific",
        "labels": {"Japan", "South Korea", "Singapore", "Australia", "India",
                   "China", "Southeast Asia", "APAC", "Taiwan", "Indonesia",
                   "Malaysia", "Thailand", "Vietnam", "Philippines", "New Zealand",
                   "Hong Kong", "Pakistan", "Bangladesh"},
    },
}

_REGIONAL_COOLDOWN = 3600  # 1 hour between regional digest calls


def _filter_articles_by_region(articles: list[dict], region_key: str) -> list[dict]:
    """Filter articles matching a region."""
    labels = _REGIONAL_CONFIGS[region_key]["labels"]
    return [
        a for a in articles
        if any(l in a.get("feed_region", "").split(",") for l in labels)
    ]


def _regional_rate_limit_path(region_key: str) -> Path:
    return OUTPUT_DIR / f".briefing_{region_key}_last_call"


def _regional_briefing_path(region_key: str) -> Path:
    return OUTPUT_DIR / f"briefing_{region_key}.json"


def generate_regional_briefings(articles: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate regional intelligence digests for NA, EMEA, APAC.

    Uses the same prompt as the global digest but with region-filtered articles.
    Returns dict of {region_key: briefing_dict}.
    """
    provider = _detect_provider()
    if not provider:
        return {}

    results = {}
    now = datetime.now(timezone.utc)

    for region_key, config in _REGIONAL_CONFIGS.items():
        region_name = config["name"]
        rate_path = _regional_rate_limit_path(region_key)
        briefing_path = _regional_briefing_path(region_key)

        # Rate limit check
        try:
            if rate_path.exists():
                last_ts = float(rate_path.read_text().strip())
                elapsed = now.timestamp() - last_ts
                if elapsed < _REGIONAL_COOLDOWN:
                    # Serve existing
                    if briefing_path.exists():
                        results[region_key] = json.loads(
                            briefing_path.read_text(encoding="utf-8")
                        )
                    continue
        except (ValueError, OSError):
            pass

        # Filter articles for this region
        regional_articles = _filter_articles_by_region(articles, region_key)
        if len(regional_articles) < 5:
            logger.info(f"Regional digest {region_key}: only {len(regional_articles)} articles, skipping.")
            continue

        # Filter and prepare
        filtered = _filter_for_briefing(regional_articles)
        if len(filtered) < 5:
            filtered = regional_articles

        day1, day3, older = _split_by_age(filtered)
        briefing_articles = day1[:]
        if len(briefing_articles) < 15:
            briefing_articles.extend(day3[:20 - len(briefing_articles)])
        briefing_articles = briefing_articles[:_MAX_DIGEST_ARTICLES]

        if len(briefing_articles) < 3:
            continue

        digest = _build_digest(briefing_articles)
        cache_key = f"regional_{region_key}_" + hashlib.sha256(digest.encode()).hexdigest()

        cached = get_cached_result(cache_key)
        if cached is not None:
            _save_regional_briefing(region_key, cached)
            results[region_key] = cached
            continue

        # Build prompt with regional context
        user_content = (
            f"INTELLIGENCE COLLECTION DATE: {now.strftime('%Y-%m-%d %H:%M UTC')}\n"
            f"REGION: {region_name}\n"
            f"TOTAL ARTICLES: {len(briefing_articles)} ({region_name}-specific)\n"
            f"REPORTING PERIOD: Last 24 hours\n\n"
            f"IMPORTANT: Focus ONLY on incidents affecting {region_name}. "
            f"Name specific organizations, cities, and national agencies in this region.\n\n"
            f"BEGIN INCIDENT DATA:\n{digest}\nEND INCIDENT DATA"
        )

        try:
            if provider == "anthropic":
                reply = _call_anthropic(user_content)
            else:
                reply = _call_openai_compatible(user_content, caller="regional")

            briefing = _parse_json(reply)
            if not briefing:
                continue

            # Normalize fields (same as global)
            if "situation_overview" in briefing and "what_happened" not in briefing:
                briefing["what_happened"] = briefing.pop("situation_overview")
            if "priority_actions" in briefing and "what_to_do" not in briefing:
                briefing["what_to_do"] = briefing.pop("priority_actions")
            if "threat_forecast" in briefing and "outlook" not in briefing:
                briefing["outlook"] = briefing.pop("threat_forecast")

            if "what_happened" not in briefing:
                continue

            tl = (briefing.get("threat_level") or "").upper()
            if tl not in _VALID_THREAT_LEVELS:
                briefing["threat_level"] = "MODERATE"

            briefing.setdefault("what_to_do", [])
            briefing.setdefault("outlook", "")
            briefing["headline"] = _normalise_headline(briefing.get("headline"))

            # Source article map
            source_map = []
            for i, a in enumerate(briefing_articles[:_MAX_DIGEST_ARTICLES], 1):
                source_map.append({
                    "index": i,
                    "title": (a.get("translated_title") or a.get("title", ""))[:120],
                    "link": a.get("link", ""),
                    "source_name": a.get("source_name", ""),
                })
            briefing["source_articles"] = source_map
            briefing["generated_at"] = datetime.now(timezone.utc).isoformat()
            briefing["region"] = region_key
            briefing["region_name"] = region_name
            briefing["articles_analyzed"] = len(briefing_articles)
            briefing["total_articles"] = len(regional_articles)
            briefing["reporting_window"] = "Last 24 hours"
            briefing["provider"] = f"{provider}/{LLM_MODEL}"

            # Record rate limit and cache
            try:
                rate_path.parent.mkdir(parents=True, exist_ok=True)
                rate_path.write_text(str(now.timestamp()))
            except OSError:
                pass
            cache_result(cache_key, briefing)
            _save_regional_briefing(region_key, briefing)
            results[region_key] = briefing
            logger.info(
                f"Regional digest ({region_name}): generated from "
                f"{len(briefing_articles)} articles."
            )

        except Exception as e:
            logger.warning(f"Regional digest ({region_name}) failed: {e}")

    return results


def _save_regional_briefing(region_key: str, briefing: dict) -> None:
    path = _regional_briefing_path(region_key)
    stamped = _stamp_previous_level(briefing, path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(stamped, f, ensure_ascii=False)


def load_regional_briefing(region_key: str) -> dict[str, Any] | None:
    path = _regional_briefing_path(region_key)
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None


def load_all_regional_briefings() -> dict[str, Any]:
    """Load all regional briefings as {region_key: briefing}."""
    result = {}
    for key in _REGIONAL_CONFIGS:
        b = load_regional_briefing(key)
        if b:
            result[key] = b
    return result


# --- Top Stories: AI-curated most significant incidents ---

# Top-stories and article-summariser machinery now lives in dedicated modules
# to keep this file under the 800-line cap. Re-exported here so every caller
# that already imports `generate_top_stories` / `summarize_articles` from
# `briefing_generator` continues to work unchanged.
from modules.top_stories import (  # noqa: E402
    generate_top_stories,
    load_top_stories,
    _save_top_stories,
    _TOP_STORIES_PATH,
    _filter_for_briefing,
    _split_by_age,
)
from modules.article_summariser import (  # noqa: E402
    summarize_articles,
    _MAX_SUMMARIES_PER_RUN,
)
