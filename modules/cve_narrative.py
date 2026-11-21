"""CVE exploitation narrative generator.

Turns raw NVD CVE metadata (CVSS score, vector, CWE, affected products,
EPSS percentile) into a short analyst-facing exploitation narrative:

    "What an attacker does with this, who's exposed, and how urgent."

Cached by CVE ID (cve_id alone, since CVE descriptions are immutable
per NVD) so we only pay the token cost once per CVE — subsequent
pipeline runs reuse the cached narrative.

Caller label: ``cve_narrative``.

Gating rule (decide_should_narrate):
    CVSS >= 8.0 OR EPSS percentile >= 0.80

Budget envelope at 20-30 new high-severity CVEs/day * ~1.5K tokens/call
≈ 30-45K tokens/day, before cache hits.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any

from modules.ai_cache import cache_result, get_cached_result
from modules.llm_client import call_llm

logger = logging.getLogger(__name__)

CVE_NARRATIVE_CVSS_THRESHOLD = 8.0
CVE_NARRATIVE_EPSS_PCTL_THRESHOLD = 0.80
CVE_NARRATIVE_MAX_TOKENS = 400
CVE_NARRATIVE_CALLER = "cve_narrative"

_SYSTEM_PROMPT = (
    "You are a senior threat-intelligence analyst. Given a CVE's raw metadata, "
    "produce a concise exploitation narrative for a SOC audience.\n\n"
    "Output exactly 3 sentences, plain text, no headings:\n"
    "  1. What an attacker practically does with this (attack chain, access gained).\n"
    "  2. Who is exposed (typical deployments, who runs it in production).\n"
    "  3. How urgent patching is, grounded in CVSS + EPSS + known exploitation.\n\n"
    "Do NOT restate CVSS numbers or CWE IDs verbatim. Do NOT speculate beyond "
    "what the metadata supports. Do NOT invent IOC details. If insufficient "
    "context, say so briefly in sentence 3."
)


def should_narrate(article: dict[str, Any]) -> bool:
    """Return True when the CVE deserves an LLM narrative.

    Gating rule: CVSS >= 8.0 OR EPSS percentile >= 0.80. Articles that
    are not NVD CVE records (no ``cve_id``) are skipped.
    """
    cve_id = article.get("cve_id")
    if not cve_id:
        return False
    cvss = float(article.get("cvss_score") or 0)
    if cvss >= CVE_NARRATIVE_CVSS_THRESHOLD:
        return True
    pctl = float(article.get("epss_percentile") or 0)
    if pctl >= CVE_NARRATIVE_EPSS_PCTL_THRESHOLD:
        return True
    return False


def _cache_key(cve_id: str) -> str:
    return "cve_narrative:" + hashlib.sha256(cve_id.encode("utf-8")).hexdigest()


def _build_prompt(article: dict[str, Any]) -> str:
    cve_id = article.get("cve_id", "")
    cvss = article.get("cvss_score", "")
    severity = article.get("cvss_severity", "")
    vector = article.get("cvss_vector", "")
    cwe_ids = ", ".join(article.get("cwe_ids") or []) or "unknown"
    products = ", ".join(article.get("affected_products") or []) or "unspecified"
    desc = article.get("summary") or article.get("title") or ""
    epss_score = article.get("epss_max_score")
    epss_pctl = article.get("epss_percentile") or article.get("epss_max_percentile")

    epss_line = (
        f"EPSS: score={epss_score}, percentile={epss_pctl}"
        if epss_score is not None or epss_pctl is not None
        else "EPSS: not available"
    )

    return (
        f"CVE: {cve_id}\n"
        f"CVSS: {cvss} ({severity}) — vector {vector}\n"
        f"CWE: {cwe_ids}\n"
        f"Affected: {products}\n"
        f"{epss_line}\n"
        f"NVD description: {desc[:800]}"
    )


def generate_cve_narrative(article: dict[str, Any]) -> str | None:
    """Return a 3-sentence exploitation narrative for a CVE article.

    Cache-first by CVE ID. Returns None on LLM failure (callers should
    treat missing narrative as non-fatal).
    """
    cve_id = article.get("cve_id")
    if not cve_id:
        return None

    cached = get_cached_result(_cache_key(cve_id))
    if isinstance(cached, str) and cached.strip():
        return cached

    from modules.llm_policy import caller_enabled
    if not caller_enabled(CVE_NARRATIVE_CALLER):
        return None

    try:
        narrative = call_llm(
            user_content=_build_prompt(article),
            system_prompt=_SYSTEM_PROMPT,
            max_tokens=CVE_NARRATIVE_MAX_TOKENS,
            caller=CVE_NARRATIVE_CALLER,
        )
    except Exception as exc:
        logger.warning("cve_narrative: LLM call failed for %s: %s", cve_id, exc)
        return None

    narrative = (narrative or "").strip()
    if not narrative:
        return None

    cache_result(_cache_key(cve_id), narrative)
    return narrative


def enrich_articles_with_cve_narratives(
    articles: list[dict[str, Any]],
    max_calls: int = 30,
) -> list[dict[str, Any]]:
    """Attach ``cve_narrative`` to qualifying CVE articles.

    Budget-capped at ``max_calls`` LLM calls per pipeline run to protect
    daily token budget. Cache hits do not count against the cap.
    """
    llm_calls = 0
    for article in articles:
        if not should_narrate(article):
            continue
        cve_id = article.get("cve_id")
        cached = get_cached_result(_cache_key(cve_id)) if cve_id else None
        if isinstance(cached, str) and cached.strip():
            article["cve_narrative"] = cached
            continue
        if llm_calls >= max_calls:
            continue
        narrative = generate_cve_narrative(article)
        if narrative:
            article["cve_narrative"] = narrative
            llm_calls += 1
    if llm_calls:
        logger.info("cve_narrative: generated %d narratives (budget %d)", llm_calls, max_calls)
    return articles
