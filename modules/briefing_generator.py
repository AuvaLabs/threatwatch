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
import re
from typing import Any

logger = logging.getLogger(__name__)
from datetime import datetime, timezone
from pathlib import Path


from modules.config import (
    LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, LLM_PROVIDER, BRIEFING_MODEL,
    LLM_API_KEYS, ANTHROPIC_API_KEY, MAX_CONTENT_CHARS, OUTPUT_DIR,
    FEATHERLESS_MODEL, BRIEFING_FALLBACK_MODEL,
)
from modules.ai_cache import get_cached_result, cache_result
from modules.date_utils import article_datetime
from modules.llm_client import (
    call_llm as _call_groq,
    call_featherless as _call_featherless,
    featherless_available as _featherless_available,
    call_briefing_fallback as _call_briefing_fallback,
    briefing_fallback_available as _briefing_fallback_available,
)

BRIEFING_PATH = OUTPUT_DIR / "briefing.json"

_VALID_THREAT_LEVELS = frozenset({"CRITICAL", "ELEVATED", "MODERATE", "GUARDED", "LOW"})

# Models regularly emit reasonable synonyms outside the enum. Map the common
# ones to their closest level instead of silently flattening everything to
# MODERATE — "HIGH" downgraded to the median was an honesty bug, not safety.
_THREAT_LEVEL_ALIASES = {
    "HIGH": "ELEVATED",
    "SEVERE": "ELEVATED",
    "MEDIUM": "MODERATE",
    "EXTREME": "CRITICAL",
}


def _normalise_threat_level(briefing: dict) -> None:
    """Normalise threat_level in place and record its provenance.

    Sets `threat_level_source` to one of:
      model            — the model produced a valid enum value
      model_alias      — a recognised synonym was mapped (e.g. HIGH→ELEVATED)
      fallback_invalid — unrecognised value; defaulted to MODERATE

    The source field is served to the UI so an analyst can tell an assessed
    MODERATE from a we-couldn't-parse-the-model MODERATE.
    """
    raw = (briefing.get("threat_level") or "").upper().strip()
    if raw in _VALID_THREAT_LEVELS:
        briefing["threat_level"] = raw
        briefing["threat_level_source"] = "model"
    elif raw in _THREAT_LEVEL_ALIASES:
        briefing["threat_level"] = _THREAT_LEVEL_ALIASES[raw]
        briefing["threat_level_source"] = "model_alias"
        logger.info("Threat level alias mapped: %r -> %s", raw, briefing["threat_level"])
    else:
        briefing["threat_level"] = "MODERATE"
        briefing["threat_level_source"] = "fallback_invalid"
        logger.warning(
            "Threat level %r not recognised — defaulted to MODERATE "
            "(threat_level_source=fallback_invalid)", raw,
        )
_LAST_API_CALL_PATH = OUTPUT_DIR / ".briefing_last_call"
_BRIEFING_COOLDOWN_SECONDS = 3600  # 1 hour minimum between API calls

_BRIEFING_PROMPT = """You are a senior cyber threat intelligence analyst writing a daily intelligence digest. Write like a national CERT analyst — precise, authoritative, grounded in the data. Never fabricate incidents.

THREAT LEVEL:
- CRITICAL: Active exploitation of widespread vulnerabilities, critical infrastructure breaches, coordinated nation-state campaigns
- ELEVATED: Multiple ransomware campaigns, significant breaches, high-CVSS vulns with public exploits
- MODERATE: Typical activity — ongoing ransomware, phishing, routine disclosures
- GUARDED/LOW: Below-average activity

RULES:
- GROUNDING (CRITICAL): Cite ONLY CVE IDs, dates, threat-actor names, victim organizations, products, and other identifiers that appear verbatim in the article digest or vulnerability context below. Any token shown in these instructions in angle-bracket form (e.g. <CVE-ID>, <YYYY-MM-DD>, <ACTOR>, <PRODUCT>, <NN>%) is a schema placeholder, NOT data — never echo it or fabricate similar-looking IDs. If no qualifying CVE/actor/etc. exists in the data, do not invent one — write the section without that detail.
- Name SPECIFIC threat actors, CVEs, organizations, malware — never say "ransomware is increasing" without naming which groups and victims
- Every claim must cite source article numbers [N] in the "sources" array
- "headline" is the front-of-page TL;DR — 1 sentence, ≤140 chars, leading with the SINGLE most impactful item from what_happened. Name the specific actor/CVE/victim from the digest. Active voice. No throat-clearing ("Over the last 24 hours...", "Several incidents..."). Style template (replace placeholders with real values from the digest): GOOD = "CISA adds <PRODUCT> zero-day <CVE-ID> to KEV after <ACTOR> mass exploitation." BAD = "There were several significant cybersecurity events today including..."
- "headline_source" (CRITICAL): an integer — the SINGLE source article index [N] from the digest below that the headline is sourced from. Every named entity (CVE, actor, victim org, product) in the headline MUST appear in that one article. Do NOT fuse facts from two unrelated articles into one headline (e.g., do not put a CVE from article [2] alongside a victim from article [3] unless article [2] also names that victim).
- "what_happened" is the MAIN SECTION — write it as a narrative that covers the most significant incidents, weaving in trending patterns, CVE details, and ATT&CK tactics. Do NOT repeat information across sections.
- "what_to_do" actions must reference the SPECIFIC threats from what_happened — never generic ("patch your systems", "train employees")
- KEV-listed CVEs (marked "KEV-listed [date]" in the vuln context) are CONFIRMED exploited in the wild by CISA — when one appears, lead with it and surface the KEV status explicitly. Style template: "<CVE-ID> was added to the CISA KEV catalog on <YYYY-MM-DD>, confirming active in-the-wild exploitation." Use the actual CVE ID and date from the vulnerability context, not the placeholders. Mark the matching what_to_do action as urgent.
- If CVEs have EPSS scores, include them in the narrative. Style template: "<CVE-ID> affecting <PRODUCT> has a <NN>% EPSS exploitation probability — patch immediately." EPSS = probability; KEV = confirmed fact. Prefer KEV phrasing when both exist.
- If EARLIER THIS WEEK data is provided, write a "week_in_review" catching readers up on what they missed
- "outlook" should project what SPECIFIC developments mean for the next 7-30 days

Respond ONLY with valid JSON (no markdown, no code fences). All arrays must use strict JSON — use `[]` for empty arrays, never `[none]`, `[None]`, or `[undefined]`. Use `null` or an empty string for missing string values.
{
  "threat_level": "CRITICAL|ELEVATED|MODERATE|GUARDED|LOW",
  "headline": "<1 sentence, ≤140 chars: the single most important development right now. Active voice, named entities, no boilerplate openers.>",
  "headline_source": <single integer — the source article index [N] this headline is sourced from. Every CVE/actor/victim/product named in the headline MUST appear in that one article.>,
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
_HIGH_PRIORITY_TENURE_H = int(os.getenv("HIGH_PRIORITY_TENURE_HOURS", "72"))
# Tier-aware downgrade guard: when the new briefing was served by a lower-
# quality tier than the one currently on disk AND the prior is younger than
# this window, keep the prior. Prevents 8b fallback briefings from wiping out
# Featherless/Claude-Bridge briefings during transient outages on tier 1/2.
# Set to 0 to disable the guard and always overwrite (legacy behavior).
_BRIEFING_DOWNGRADE_GUARD_H = float(os.getenv("BRIEFING_DOWNGRADE_GUARD_HOURS", "4"))
_HEADLINE_SOFT_CAP = 160   # belt-and-braces trim if model overshoots the prompt cap
# Per-article summary char budget in the briefing prompt. Sized so the full
# digest stays under Groq free-tier 6K TPM ceiling. Lift if the briefing moves
# to a paid tier or larger context model.
_DIGEST_SUMMARY_CHARS = 80


def _extract_cited_cve_ids(briefing: dict[str, Any]) -> set[str]:
    """Return uppercase CVE IDs cited anywhere in the briefing's text fields."""
    from modules.entities import CVE_RE
    cited: set[str] = set()
    for field in ("headline", "assessment_basis", "what_happened",
                  "week_in_review", "outlook"):
        text = briefing.get(field) or ""
        if isinstance(text, str):
            cited.update(m.upper() for m in CVE_RE.findall(text))
    for action in briefing.get("what_to_do") or []:
        if isinstance(action, dict):
            for k in ("action", "threat"):
                v = action.get(k) or ""
                if isinstance(v, str):
                    cited.update(m.upper() for m in CVE_RE.findall(v))
    return cited


def _validate_cve_grounding(briefing: dict[str, Any], source_text: str) -> set[str]:
    """Return the set of CVE IDs cited in the briefing but NOT in source_text.

    A non-empty return value means the LLM fabricated identifiers (most often
    by echoing schema-example IDs from the prompt) and the briefing must be
    rejected — a false CRITICAL alert is far worse than a stale or missing one.
    """
    from modules.entities import CVE_RE
    allowed = {m.upper() for m in CVE_RE.findall(source_text or "")}
    return _extract_cited_cve_ids(briefing) - allowed


def _strip_ungrounded_cves(
    briefing: dict[str, Any], ungrounded: set[str]
) -> dict[str, Any]:
    """Return a copy of ``briefing`` with every ungrounded CVE ID removed from
    its text fields, tidying the punctuation/parentheses left behind.

    Stripping the offending identifiers is deterministically grounding (the
    cited set becomes a subset of the allowed set), so the salvaged briefing is
    safe to publish — far better than wedging on stale content for days because
    the model hallucinated one CVE. See the 2026-06 stale-briefing incident.
    """
    if not ungrounded:
        return briefing
    patterns = [
        re.compile(r"\s*[\(\[]?\b" + re.escape(cve) + r"\b[\)\]]?", re.IGNORECASE)
        for cve in ungrounded
    ]

    def _clean(text: Any) -> Any:
        if not isinstance(text, str) or not text:
            return text
        out = text
        for pat in patterns:
            out = pat.sub("", out)
        # Tidy artifacts the removal can leave: empty brackets, dangling
        # "tracked as" connectors, space-before-punctuation, doubled spaces.
        out = re.sub(r"[\(\[]\s*[\)\]]", "", out)
        out = re.sub(
            r"\b(?:tracked|identified|designated)\s+as\s*(?=[,.;:]|$)",
            "", out, flags=re.IGNORECASE,
        )
        out = re.sub(r"\s+([,.;:])", r"\1", out)
        out = re.sub(r"\s{2,}", " ", out).strip()
        return out

    new = dict(briefing)
    for field in ("headline", "assessment_basis", "what_happened",
                  "week_in_review", "outlook"):
        if field in new:
            new[field] = _clean(new[field])
    wtd = new.get("what_to_do")
    if isinstance(wtd, list):
        new["what_to_do"] = [
            {**a, **{k: _clean(a[k]) for k in ("action", "threat")
                     if isinstance(a.get(k), str)}}
            if isinstance(a, dict) else a
            for a in wtd
        ]
    return new


def _briefing_has_body(briefing: dict[str, Any] | None) -> bool:
    """True if the briefing carries enough narrative to be worth publishing.

    Guards against salvage stripping a load-bearing CVE down to an empty stub.
    """
    if not briefing:
        return False
    return len((briefing.get("what_happened") or "").strip()) >= 80


def _serve_stale(reason: str) -> dict[str, Any] | None:
    """Re-serve the last good briefing, flagged so consumers (UI badge,
    /api/briefing) know it is older than the run that produced it. Returns None
    when no prior briefing exists.
    """
    existing = load_briefing()
    if existing:
        existing = {**existing, "served_stale": True, "stale_reason": reason}
        _save_briefing(existing)
        return existing
    return None


# Capitalized common-words and analyst jargon that aren't named entities. The
# headline-coupling guard treats anything else (≥3 char, capitalized) as a
# proper noun that must be traceable to the source article. Tuned to be lax —
# the goal is to catch LLM fabrications like fusing two unrelated victims and
# CVEs into one sentence, not to flag every adjective.
_HEADLINE_ENTITY_STOPWORDS = frozenset({
    # Articles, conjunctions, prepositions, demonstratives
    "The", "And", "But", "For", "Nor", "With", "From", "Into", "Onto",
    "This", "That", "These", "Those", "Such", "Some", "Most", "Many",
    # Question words / time
    "What", "When", "Where", "Why", "How", "Who", "Whom", "Whose", "Which",
    "Today", "Yesterday", "Tomorrow", "Now", "Then", "After", "Before",
    "Recently", "Currently", "Soon",
    # Severity / threat-level vocabulary
    "Critical", "Elevated", "Moderate", "Guarded", "High", "Medium", "Low",
    "Severe", "Severity", "Urgent",
    # Counters / quantifiers
    "Multiple", "Several", "Various", "Numerous", "Few", "Many", "All", "Both",
    "Million", "Thousand", "Hundred", "Billion",
    # Generic security verbs/nouns commonly capitalized at clause start
    "Active", "Confirms", "Confirmed", "Discloses", "Disclosed", "Reports",
    "Reported", "Detects", "Detected", "Reveals", "Revealed", "Warns",
    "Warned", "Targets", "Targeted", "Targeting", "Suspects", "Suspected",
    "Linked", "Tied", "Allegedly", "Likely", "Probable", "Possible",
    "Exploits", "Exploited", "Exploiting", "Exploitation", "Exploit",
    "Attacks", "Attacked", "Attacking", "Attack", "Attackers", "Attacker",
    "Hackers", "Hacker", "Hacked", "Hacks", "Hacking",
    "Researchers", "Researcher", "Defenders", "Defender", "Investigators",
    "Vulnerability", "Vulnerabilities", "Vulnerable", "Flaw", "Flaws",
    "Patch", "Patches", "Patched", "Update", "Updates", "Updated",
    "Breach", "Breaches", "Breached", "Compromise", "Compromised",
    "Disclosure", "Disclosures", "Advisory", "Advisories",
    "Campaign", "Campaigns", "Operation", "Operations",
    "Ransomware", "Malware", "Spyware", "Phishing", "Smishing", "Vishing",
    "Botnet", "Trojan", "Wiper", "Backdoor", "Loader",
    # Generic objects of attacks
    "User", "Users", "Customer", "Customers", "Client", "Clients",
    "Account", "Accounts", "Credential", "Credentials", "Password", "Passwords",
    "Data", "Records", "Record", "Email", "Emails", "Files", "File",
    "Service", "Services", "Server", "Servers", "System", "Systems",
    "Network", "Networks", "Cloud", "Endpoint", "Endpoints",
    "Software", "Hardware", "Application", "Applications",
    "Vendor", "Vendors", "Researcher",
    "Source", "Sources",
    # Days / months
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
    # Generic security acronyms — too broad to identify a specific entity.
    # CVE IDs are validated by the separate CVE grounding check, not here.
    "CVE", "CVSS", "EPSS", "KEV", "RCE", "DoS", "DDoS", "XSS", "CSRF",
    "URL", "API", "DNS", "TLS", "VPN", "HTTP", "HTTPS", "SSH", "FTP",
    "SQL", "AI", "ML", "OS", "IT", "PII", "PHI",
})

# Capture capitalized tokens — supports "ShinyHunters", "PowerShell", "Cisco",
# "L'Oreal". 3+ chars excludes most short pronouns. The leading-uppercase
# anchor naturally skips lowercase verbs/nouns at sentence interior.
_PROPER_NOUN_RE = re.compile(r"\b[A-Z][\w\-'.]{2,}\b")


def _extract_proper_nouns(text: str) -> set[str]:
    """Extract capitalized tokens that look like named entities.

    Drops common security jargon (see `_HEADLINE_ENTITY_STOPWORDS`) so the
    headline guard only fires on meaningful proper nouns (companies, actors,
    products), not on words like "Multiple" or "Vulnerability" that just
    happen to start a clause.
    """
    if not text:
        return set()
    return {tok for tok in _PROPER_NOUN_RE.findall(text)
            if tok not in _HEADLINE_ENTITY_STOPWORDS}


def _validate_headline_grounding(
    briefing: dict[str, Any],
    briefing_articles: list[dict[str, Any]],
) -> str | None:
    """Verify every named entity in the headline traces to a single source article.

    Returns a short reason string if the headline conflates entities from
    unrelated articles, or None if it's grounded.

    Targets the "narrative coupling" failure mode: each component (CVE,
    victim, actor, product) is real and in the corpus, but the LLM glued
    them into one sentence implying a causal link that doesn't exist.

    On failure the caller should clear the headline so the frontend's regex
    distillation of `what_happened` (which IS source-cited) takes over.
    """
    headline = (briefing.get("headline") or "").strip()
    if not headline:
        return None  # nothing to validate — frontend fallback will fire

    src_idx = briefing.get("headline_source")
    # The schema requires an integer; tolerate string-typed integers as a
    # courtesy ("3" instead of 3) but reject anything else.
    if isinstance(src_idx, str) and src_idx.strip().isdigit():
        src_idx = int(src_idx.strip())
    if not isinstance(src_idx, int) or src_idx < 1 or src_idx > len(briefing_articles):
        return f"missing or invalid headline_source: {briefing.get('headline_source')!r}"

    article = briefing_articles[src_idx - 1]
    article_text = " ".join([
        article.get("title") or "",
        article.get("translated_title") or "",
        article.get("summary") or "",
    ])

    from modules.entities import CVE_RE
    headline_cves = {m.upper() for m in CVE_RE.findall(headline)}
    article_cves = {m.upper() for m in CVE_RE.findall(article_text)}
    missing_cves = headline_cves - article_cves
    if missing_cves:
        return (
            f"headline cites CVEs {sorted(missing_cves)} "
            f"not in source article #{src_idx}"
        )

    nouns = _extract_proper_nouns(headline)
    article_lower = article_text.lower()
    missing_nouns = {n for n in nouns if n.lower() not in article_lower}
    if missing_nouns:
        return (
            f"headline names {sorted(missing_nouns)} "
            f"not in source article #{src_idx}"
        )

    return None


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


def _hoist_kev_listed(
    day1: list[dict[str, Any]],
    day3: list[dict[str, Any]],
    max_age_hours: int,
    now: datetime | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Move KEV-listed articles from day3 -> day1 if within the high-priority
    tenure window. Once CISA confirms a CVE is actively exploited, the
    operational patch window stays urgent for ~72h — readers expect to see
    the item leading what_happened even after it ages past 24h. Articles
    with unparseable timestamps are kept in day3 (defensive)."""
    if not day3:
        return day1, day3
    now = now or datetime.now(timezone.utc)
    hoisted: list[dict[str, Any]] = []
    keep: list[dict[str, Any]] = []
    for a in day3:
        if not a.get("kev_listed"):
            keep.append(a)
            continue
        # Age from the publication date (ingestion time only as fallback) —
        # ingestion-time age made stale KEV coverage look hoist-fresh.
        art_dt = article_datetime(a)
        if art_dt is None:
            keep.append(a)
            continue
        age_h = (now - art_dt).total_seconds() / 3600
        if age_h <= max_age_hours:
            hoisted.append(a)
        else:
            keep.append(a)
    if hoisted:
        logger.info(
            "Hoisted %d KEV-listed article(s) from days 2-3 -> headline section "
            "(within %dh tenure window)", len(hoisted), max_age_hours,
        )
    return day1 + hoisted, keep


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




# Module-level sentinel for tier-aware logging. Set as a side effect of
# `_call_openai_compatible` so callers can stamp the actual served tier on
# the briefing's `provider` field and the success log instead of always
# echoing the configured `BRIEFING_MODEL` (issue #3).
#
# Single-threaded pipeline assumption — `generate_briefing` and
# `generate_regional_briefings` run sequentially in a single Python process
# (see threatdigest_main.py). If concurrent briefing generation is ever
# added, switch this to a tuple return on `_call_openai_compatible`.
_LAST_SERVED_TIER: str | None = None


# Lower rank = higher quality. Featherless is the primary tier; Anthropic and
# the secondary briefing provider ("fallback") are second-tier; Groq + 8b is the
# last-resort fallback. Keep this in sync with the tier branches inside
# `_call_openai_compatible`.
_TIER_RANKS = {
    "featherless":   1,
    "anthropic":     2,
    "fallback":      2,
    "openai":        3,
    "groq":          3,
    "ollama":        4,
}


def _tier_rank(provider: str | None) -> int:
    """Return the tier rank for a provider string (lower = higher quality).

    Provider format is ``'<tier>/<model>'`` (e.g. ``'featherless/deepseek-ai/DeepSeek-V3.2'``,
    ``'groq/llama-3.1-8b-instant'``). Unknown tiers rank 99.
    """
    if not provider:
        return 99
    head = provider.split("/", 1)[0]
    return _TIER_RANKS.get(head, 99)


def _briefing_age_hours(briefing: dict[str, Any] | None) -> float:
    """Hours since the briefing's ``generated_at``, or ``inf`` if missing/unparseable."""
    if not briefing or not briefing.get("generated_at"):
        return float("inf")
    try:
        gen_at = briefing["generated_at"].replace("Z", "+00:00")
        gen = datetime.fromisoformat(gen_at)
        if gen.tzinfo is None:
            gen = gen.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - gen).total_seconds() / 3600.0
    except (ValueError, TypeError, AttributeError):
        return float("inf")


def _should_skip_downgrade(prior: dict[str, Any] | None, new_tier: str) -> bool:
    """Return True if the prior briefing should be kept instead of overwritten
    by a new lower-tier briefing.

    Triggers when ALL of the following are true:
      - ``BRIEFING_DOWNGRADE_GUARD_HOURS`` > 0 (guard enabled)
      - A prior briefing exists with a parseable ``provider`` field
      - The new tier rank is strictly worse than the prior tier rank
      - The prior briefing is younger than the guard window

    The user-stated invariant is "primary will always be featherless" — this
    function enforces it by refusing to drop a Featherless briefing for a Groq
    one within the guard window. Same logic protects secondary-provider
    (fallback-tier) briefings from being clobbered by Groq.
    """
    if _BRIEFING_DOWNGRADE_GUARD_H <= 0:
        return False
    if not prior or not prior.get("provider"):
        return False
    prior_rank = _tier_rank(prior.get("provider"))
    new_rank = _tier_rank(new_tier)
    if new_rank <= prior_rank:
        return False  # same-or-better tier — always overwrite
    return _briefing_age_hours(prior) < _BRIEFING_DOWNGRADE_GUARD_H


def _call_openai_compatible(user_content: str, system_prompt: str = None,
                            max_tokens: int = 2000,
                            caller: str | None = None,
                            model: str | None = None,
                            prefer_featherless: bool = False,
                            feather_max_tokens: int | None = None) -> str:
    """Call Groq/OpenAI-compatible API via shared llm_client.

    All briefing callers expect strict JSON back, so we opt into Groq's
    structured output mode (``response_format={"type": "json_object"}``) here
    — the single choke point for global/regional/top-stories/summary LLM calls.
    The shared client auto-falls back to a plain call if the provider rejects
    the field, so this is safe to ship even if Groq ever drops support.

    The ``model`` kwarg lets a caller opt into a lighter Groq model (e.g.
    ``llama-3.1-8b-instant``) for tasks where the default 70B is too
    token-heavy for free-tier TPM. Defaults to the global ``LLM_MODEL``.

    When ``prefer_featherless=True`` and Featherless is configured, the
    call is routed there first (32K context — required for the global
    briefing prompt that exceeds Groq's 6K TPM ceiling). Any failure
    transparently falls back to Groq with the ``model`` kwarg, so the
    caller never sees a Featherless-specific error. This is the only
    Featherless usage in the codebase by design — keep the shared token
    spend minimal so other projects sharing it aren't crowded out.

    ``feather_max_tokens`` (optional) decouples the Featherless output cap
    from the Groq cap. Featherless's 32K context lets the briefing produce
    a richer narrative than Groq's 6K TPM allows. If None, Featherless uses
    the same ``max_tokens`` as the Groq fallback — preserves prior behavior
    for callers that don't opt in.

    Side effect: writes the served tier identifier to
    ``_LAST_SERVED_TIER`` (one of ``'featherless/<model>'``,
    ``'fallback/<model>'``, ``'groq/<model>'``) so the caller can log
    and stamp the actual tier that served instead of guessing from the
    configured ``BRIEFING_MODEL`` env. Single-threaded only.
    """
    global _LAST_SERVED_TIER
    sys_prompt = system_prompt or _BRIEFING_PROMPT
    if prefer_featherless and _featherless_available():
        try:
            reply = _call_featherless(
                user_content,
                system_prompt=sys_prompt,
                max_tokens=feather_max_tokens or max_tokens,
                response_format={"type": "json_object"},
                caller=caller,
                model=FEATHERLESS_MODEL,
            )
            _LAST_SERVED_TIER = f"featherless/{FEATHERLESS_MODEL}"
            return reply
        except Exception as e:
            logger.warning(
                "Featherless briefing call failed (%s); trying briefing fallback.", e,
            )
    # 2nd tier: secondary briefing provider (any authenticated OpenAI-compatible
    # API, e.g. Cerebras). Independent of the base Groq tier, so it gives the
    # flagship briefing a third distinct path before the final Groq+8B fallback.
    # feather_max_tokens is passed so the prompt cap stays consistent with the
    # Featherless path.
    if prefer_featherless and _briefing_fallback_available():
        try:
            reply = _call_briefing_fallback(
                user_content,
                system_prompt=sys_prompt,
                max_tokens=feather_max_tokens or max_tokens,
                response_format={"type": "json_object"},
                caller=caller,
                model=BRIEFING_FALLBACK_MODEL,
            )
            _LAST_SERVED_TIER = f"fallback/{BRIEFING_FALLBACK_MODEL}"
            return reply
        except Exception as e:
            logger.warning(
                "Briefing fallback call failed (%s); falling back to Groq+%s.",
                e, model or LLM_MODEL,
            )
    reply = _call_groq(
        user_content,
        system_prompt=sys_prompt,
        max_tokens=max_tokens,
        response_format={"type": "json_object"},
        caller=caller,
        model=model,
    )
    _LAST_SERVED_TIER = f"groq/{model or LLM_MODEL}"
    return reply


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

    # Re-apply KEV enrichment so out-of-band briefings
    # (AI_ENRICHMENT_INLINE=0, which loads from disk without per-article
    # kev_listed) have current KEV signal. Idempotent on already-enriched
    # articles. Defensive: catalog fetch failure leaves articles unchanged.
    try:
        from modules.kev_enricher import enrich_articles_with_kev
        all_filtered = enrich_articles_with_kev(all_filtered)
    except Exception as _kev_err:
        logger.debug("KEV enrichment in briefing path skipped: %s", _kev_err)

    day1, day3, older = _split_by_age(all_filtered)
    day1, day3 = _hoist_kev_listed(day1, day3, _HIGH_PRIORITY_TENURE_H)

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
        # generated_at stays the TRUE generation time — re-stamping it on
        # every cache hit told users the analysis was newer than it was and
        # permanently reset the staleness alarm while the cache stayed hot.
        # last_validated_at records "we re-checked the inputs and they are
        # unchanged as of now"; the staleness check accepts either stamp.
        cached = {**cached, "last_validated_at": datetime.now(timezone.utc).isoformat()}
        cached.pop("served_stale", None)
        cached.pop("stale_reason", None)
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

    def _attempt(extra_instruction: str = "") -> dict[str, Any] | None:
        """Call the provider once and return a schema-normalised briefing dict
        (pre-grounding), or None on provider/parse/schema failure.

        ``extra_instruction`` is appended to the user content so a corrective
        retry can forbid CVE IDs an earlier draft hallucinated.
        """
        content = user_content
        if extra_instruction:
            content = f"{user_content}\n\n{extra_instruction}"

        if provider == "anthropic":
            reply = _call_anthropic(content)
        else:
            reply = _call_openai_compatible(
                content, caller="briefing",
                model=BRIEFING_MODEL,
                max_tokens=1200,           # Groq fallback — fits 6K TPM
                feather_max_tokens=4000,   # Featherless 32K — richer narrative
                prefer_featherless=True,
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

        # Normalise threat_level (records threat_level_source provenance)
        _normalise_threat_level(briefing)

        # Ensure optional sections have defaults
        briefing.setdefault("what_to_do", [])
        briefing.setdefault("week_in_review", "")
        briefing.setdefault("outlook", "")
        # Surface as TL;DR hero on the dashboard; blank string lets the
        # frontend's regex distillation of what_happened take over.
        briefing["headline"] = _normalise_headline(briefing.get("headline"))
        return briefing

    try:
        briefing = _attempt()
        if briefing is None:
            return None

        # Guard against ungrounded CVE IDs (prompt-example leakage / hallucination).
        # A false CRITICAL alert citing a fabricated CVE is worse than a stale
        # brief — but one hallucinated identifier must not wedge the whole
        # briefing for days (the 2026-06 stale-briefing incident: featherless
        # repeatedly cited an ungrounded CVE, so every regeneration was rejected
        # and the brief sat 26h+ stale). Recovery ladder: (1) strip the
        # ungrounded IDs and publish the salvaged-but-grounded brief; (2) if that
        # guts the narrative, retry once with an explicit prohibition; (3) only
        # then fall back to re-serving the last good brief flagged stale.
        ungrounded = _validate_cve_grounding(briefing, user_content)
        if ungrounded:
            salvaged = _strip_ungrounded_cves(briefing, ungrounded)
            if _briefing_has_body(salvaged):
                logger.warning(
                    "Briefing cited ungrounded CVE IDs %s — stripped them and "
                    "published the salvaged (grounded) briefing.",
                    sorted(ungrounded),
                )
                briefing = salvaged
            else:
                logger.warning(
                    "Briefing cited ungrounded CVE IDs %s; salvage gutted the "
                    "narrative — retrying once with an explicit prohibition.",
                    sorted(ungrounded),
                )
                forbid = (
                    "CORRECTION: A previous draft cited CVE IDs that do NOT "
                    "appear in the incident data: "
                    + ", ".join(sorted(ungrounded))
                    + ". Do NOT mention these identifiers. Cite only CVE IDs "
                    "present verbatim in the data above; if none apply, omit "
                    "CVE references entirely."
                )
                retry = _attempt(forbid)
                briefing = None
                if retry is not None:
                    ug2 = _validate_cve_grounding(retry, user_content)
                    if ug2:
                        retry = _strip_ungrounded_cves(retry, ug2)
                    if _briefing_has_body(retry):
                        briefing = retry
                if briefing is None:
                    return _serve_stale(
                        "latest generation rejected: ungrounded CVE citations"
                    )

        # Guard against headline narrative-coupling (entities welded from
        # unrelated source articles). On failure, clear the headline so the
        # frontend's regex distillation of what_happened (which IS source-cited)
        # takes over — we don't reject the whole briefing because what_happened
        # has already passed the per-claim source check.
        headline_issue = _validate_headline_grounding(briefing, briefing_articles)
        if headline_issue:
            logger.warning(
                "Briefing headline cleared — %s. Frontend will distill from what_happened.",
                headline_issue,
            )
            briefing["headline"] = ""

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
        briefing["last_validated_at"] = briefing["generated_at"]
        briefing.pop("served_stale", None)
        briefing.pop("stale_reason", None)
        briefing["articles_analyzed"] = min(len(briefing_articles), _MAX_BRIEFING_ARTICLES)
        briefing["total_articles"] = len(articles)  # total including darkweb
        briefing["reporting_window"] = reporting_window
        # Resolve the actual served tier (issue #3 fix). Anthropic branch is
        # explicit; openai-compatible branch reads the sentinel set by
        # `_call_openai_compatible`. Falls back to the configured BRIEFING_MODEL
        # only if the sentinel is unset (defensive — should never happen in
        # the openai-compatible path post-fix).
        if provider == "anthropic":
            served_tier = f"anthropic/{LLM_MODEL}"
        else:
            served_tier = _LAST_SERVED_TIER or f"openai/{BRIEFING_MODEL}"
        briefing["provider"] = served_tier

        # Tier-aware downgrade guard. When tier 1 (Featherless) is the primary
        # and falls through to tier 3 (Groq 8b), the resulting briefing is
        # noticeably shallower. Don't overwrite a fresher higher-tier briefing
        # within `BRIEFING_DOWNGRADE_GUARD_HOURS`. Skip cache_result +
        # _save_briefing + _record_api_call so the next pipeline tick can retry
        # the premium tier without the hourly cooldown blocking it.
        prior = load_briefing()
        if _should_skip_downgrade(prior, served_tier):
            prior_age = _briefing_age_hours(prior)
            logger.info(
                "Briefing downgrade skipped — kept prior %s (age %.1fh) instead "
                "of overwriting with %s (BRIEFING_DOWNGRADE_GUARD_HOURS=%.1f).",
                prior.get("provider"), prior_age, served_tier,
                _BRIEFING_DOWNGRADE_GUARD_H,
            )
            return prior

        _record_api_call()
        cache_result(cache_key, briefing)
        _save_briefing(briefing)
        logger.info(f"Intelligence briefing generated via {served_tier}.")
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
        if any(lbl in a.get("feed_region", "").split(",") for lbl in labels)
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

            _normalise_threat_level(briefing)

            briefing.setdefault("what_to_do", [])
            briefing.setdefault("outlook", "")
            briefing["headline"] = _normalise_headline(briefing.get("headline"))

            ungrounded = _validate_cve_grounding(briefing, user_content)
            if ungrounded:
                logger.warning(
                    "Regional digest (%s) rejected — ungrounded CVE IDs %s.",
                    region_name, sorted(ungrounded),
                )
                continue

            # Headline narrative-coupling guard (same logic as global digest).
            headline_issue = _validate_headline_grounding(briefing, briefing_articles)
            if headline_issue:
                logger.warning(
                    "Regional digest (%s) headline cleared — %s.",
                    region_name, headline_issue,
                )
                briefing["headline"] = ""

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
            # Stamp the actual served tier (issue #3). Regional briefings do
            # NOT pass `prefer_featherless`, so they always go to Groq —
            # `_LAST_SERVED_TIER` will reflect that, but the conditional
            # keeps the anthropic branch correct and is defensive against
            # future changes to the regional dispatch path.
            if provider == "anthropic":
                regional_tier = f"anthropic/{LLM_MODEL}"
            else:
                regional_tier = _LAST_SERVED_TIER or f"openai/{LLM_MODEL}"
            briefing["provider"] = regional_tier

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
                f"{len(briefing_articles)} articles via {regional_tier}."
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
