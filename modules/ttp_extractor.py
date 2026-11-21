"""Deep-article TTP extractor.

Today's pipeline classifies and tags articles off title + short summary.
The tactical gold — exact persistence mechanisms, lateral-movement paths,
C2 behaviours — lives in the body paragraphs and is discarded. This
module runs a second LLM pass over high-signal incident articles using
the full scraped body, producing a structured analyst note.

Output field: ``tactical_analysis`` attached to each qualifying article:

    {
      "summary": "2-3 sentence tactical takeaway",
      "ttps": ["Abuse of MSBuild for execution", "..."],
      "persistence": ["Scheduled task creation", ...],
      "lateral_movement": ["SMB-based tool transfer", ...],
      "impact": ["LockBit encryption deployed to domain controller"],
      "confidence": "high|medium|low"
    }

Cache-first by article hash. Budget-capped via ``TTP_EXTRACT_MAX_CALLS``
(default 40/run) so a noisy feed day can't blow the daily Groq budget.

Caller label: ``ttp_extract``.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any

from modules.ai_cache import cache_result, get_cached_result

logger = logging.getLogger(__name__)

TTP_EXTRACT_MAX_CALLS = int(os.environ.get("TTP_EXTRACT_MAX_CALLS", "40"))
TTP_EXTRACT_MIN_BODY_CHARS = int(os.environ.get("TTP_EXTRACT_MIN_BODY_CHARS", "500"))
TTP_EXTRACT_MAX_TOKENS = int(os.environ.get("TTP_EXTRACT_MAX_TOKENS", "900"))
TTP_EXTRACT_BODY_BUDGET = int(os.environ.get("TTP_EXTRACT_BODY_CHARS", "6000"))
TTP_EXTRACT_CALLER = "ttp_extract"

_SYSTEM_PROMPT = (
    "You are a senior threat-intelligence analyst extracting TTPs from a "
    "cybersecurity news article body. Read the article and return ONLY a "
    "JSON object with this exact shape:\n"
    '{"summary": "2-3 sentence tactical takeaway",'
    ' "ttps": ["..."],'
    ' "persistence": ["..."],'
    ' "lateral_movement": ["..."],'
    ' "impact": ["..."],'
    ' "confidence": "high|medium|low"}\n\n'
    "Rules:\n"
    "- Every list is OPTIONAL. Omit keys with nothing supported by the text "
    "(don't pad with generic answers).\n"
    "- Each bullet must be grounded in the article. Do NOT invent IOCs, "
    "CVEs, or actor attributions.\n"
    "- Use short, specific phrases (3-12 words). No filler.\n"
    "- confidence reflects how well the article supports concrete TTPs; "
    'use "low" if the article is speculative or vendor marketing.'
)


def _article_cache_key(article: dict) -> str:
    raw = article.get("hash") or article.get("link") or article.get("title") or ""
    return "ttp_extract:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _eligible(article: dict) -> bool:
    if not article.get("is_cyber_attack"):
        return False
    body = article.get("full_content") or ""
    if len(body) < TTP_EXTRACT_MIN_BODY_CHARS:
        return False
    return True


def _build_prompt(article: dict) -> str:
    title = article.get("title", "") or ""
    summary = article.get("summary", "") or ""
    body = (article.get("full_content") or "")[:TTP_EXTRACT_BODY_BUDGET]
    cves = ", ".join(article.get("cve_ids") or []) or "none"
    return (
        f"Title: {title}\n"
        f"CVEs referenced: {cves}\n\n"
        f"Lead summary: {summary}\n\n"
        f"Article body:\n{body}"
    )


_ALLOWED_KEYS = {"summary", "ttps", "persistence", "lateral_movement", "impact", "confidence"}
_LIST_KEYS = {"ttps", "persistence", "lateral_movement", "impact"}


def _parse_response(raw: str) -> dict | None:
    """Parse the LLM response, keeping only well-formed fields.

    Returns None on unrecoverable output. Lists are truncated to 6 items
    and items to 160 chars — protects downstream consumers and keeps
    the dashboard payload small.
    """
    if not raw:
        return None
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None

    cleaned: dict[str, Any] = {}
    for key in _ALLOWED_KEYS:
        val = obj.get(key)
        if key == "summary" and isinstance(val, str) and val.strip():
            cleaned["summary"] = val.strip()[:400]
        elif key == "confidence" and isinstance(val, str) and val.strip():
            c = val.strip().lower()
            if c in {"high", "medium", "low"}:
                cleaned["confidence"] = c
        elif key in _LIST_KEYS and isinstance(val, list):
            items = []
            for item in val:
                if isinstance(item, str) and item.strip():
                    items.append(item.strip()[:160])
                if len(items) >= 6:
                    break
            if items:
                cleaned[key] = items
    return cleaned or None


def _extract_ttps(article: dict) -> dict | None:
    cache_key = _article_cache_key(article)
    cached = get_cached_result(cache_key)
    if isinstance(cached, dict):
        return cached

    from modules.llm_policy import caller_enabled
    if not caller_enabled(TTP_EXTRACT_CALLER):
        return None

    try:
        from modules.llm_client import call_llm
        raw = call_llm(
            user_content=_build_prompt(article),
            system_prompt=_SYSTEM_PROMPT,
            max_tokens=TTP_EXTRACT_MAX_TOKENS,
            response_format={"type": "json_object"},
            caller=TTP_EXTRACT_CALLER,
        )
    except Exception as exc:
        logger.debug("ttp_extract LLM call failed for %s: %s", article.get("link", ""), exc)
        return None

    parsed = _parse_response(raw)
    if parsed:
        cache_result(cache_key, parsed)
    return parsed


def enrich_articles_with_ttps(
    articles: list[dict[str, Any]],
    max_calls: int | None = None,
) -> list[dict[str, Any]]:
    """Attach ``tactical_analysis`` to qualifying incident articles.

    Eligibility: ``is_cyber_attack=True`` AND full_content >= 500 chars.
    Cache hits never count against the LLM budget.
    """
    cap = max_calls if max_calls is not None else TTP_EXTRACT_MAX_CALLS
    llm_calls = 0
    cache_hits = 0

    for article in articles:
        if not _eligible(article):
            continue
        cache_key = _article_cache_key(article)
        cached = get_cached_result(cache_key)
        if isinstance(cached, dict):
            article["tactical_analysis"] = cached
            cache_hits += 1
            continue
        if llm_calls >= cap:
            continue
        result = _extract_ttps(article)
        llm_calls += 1
        if result:
            article["tactical_analysis"] = result

    if llm_calls or cache_hits:
        logger.info(
            "ttp_extract: %d LLM calls, %d cache hits (cap=%d)",
            llm_calls, cache_hits, cap,
        )
    return articles
