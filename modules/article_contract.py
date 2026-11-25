"""Canonical, backward-compatible article boundary normalization."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from modules.date_utils import parse_datetime
from modules.deduplicator import normalize_url


_SOURCE_ALIASES = {
    "nvd:cve": "NVD",
    "darkweb:ransomware.live": "Ransomware.live",
    "darkweb:threatfox": "ThreatFox",
}
_LEADING_SYSTEM_NOTICE = re.compile(
    r"\A\s*SYSTEM\s+NOTICE\s*(?:\r?\n|\Z)",
    re.IGNORECASE,
)


def _source_label(source: str) -> str:
    if source in _SOURCE_ALIASES:
        return _SOURCE_ALIASES[source]
    if source.startswith("newsapi:"):
        return source.split(":", 1)[1] or "NewsAPI"
    parsed = urlparse(source)
    host = (parsed.hostname or "").lower().removeprefix("www.")
    if host == "news.google.com":
        return "Google News"
    labels = [part for part in host.split(".") if part not in {"feeds", "feed", "www"}]
    label = labels[-2] if len(labels) >= 2 else (labels[0] if labels else "Unknown source")
    return label.replace("-", " ").replace("_", " ").title()


def _published_at(article: dict[str, Any]) -> str | None:
    parsed = parse_datetime(article.get("published", ""))
    return parsed.isoformat() if parsed else None


def _clean_source_text(value: Any) -> str:
    text = str(value or "").strip()
    while match := _LEADING_SYSTEM_NOTICE.match(text):
        text = text[match.end():].lstrip()
    return text


def _summary_method(article: dict[str, Any], summary: str, fallback: bool) -> str:
    if fallback:
        return "fallback"
    if not summary:
        return "none"
    if article.get("_ai_enhanced") or article.get("summary_generated"):
        return "ai"
    return str(article.get("summary_method") or "source")


def _summary_fields(article: dict[str, Any]) -> tuple[str, str, bool]:
    summary = _clean_source_text(article.get("summary"))
    fallback = False
    if not summary:
        summary = _clean_source_text(article.get("intel_what"))
        if not summary:
            title = _clean_source_text(
                article.get("translated_title") or article.get("title")
            )
            summary = f"Source report headline: {title}" if title else ""
        fallback = bool(summary)
    return summary[:500], _summary_method(article, summary, fallback), fallback


def normalize_article(article: dict[str, Any]) -> dict[str, Any]:
    """Return a canonical article copy while preserving legacy fields."""
    source = str(article.get("source") or "")
    source_name = str(article.get("source_name") or "").strip() or _source_label(source)
    link = str(article.get("link") or "").strip()
    confidence = article.get("confidence")
    if article.get("is_cyber_attack") is True and (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 1 <= confidence <= 100
    ):
        confidence = 60
    summary, summary_method, needs_enrichment = _summary_fields(article)
    normalized = {
        **article,
        "confidence": confidence,
        "source_name": source_name,
        "canonical_url": normalize_url(link) if link else "",
        "published_at": _published_at(article),
        "region": article.get("region") or article.get("feed_region") or "Global",
        "content_hash": article.get("content_hash") or article.get("hash") or "",
        "summary": summary,
        "summary_method": summary_method,
        "cve_ids": list(article.get("cve_ids") or []),
        "asset_tags": list(article.get("asset_tags") or []),
        "brand_tags": list(article.get("brand_tags") or []),
        "victim_sectors": list(article.get("victim_sectors") or []),
    }
    if "full_content" in article:
        content = article.get("full_content")
        normalized["full_content"] = (
            None if content is None else _clean_source_text(content)
        )
    if needs_enrichment:
        normalized["summary_needs_enrichment"] = True
    else:
        normalized.pop("summary_needs_enrichment", None)
    return normalized


def validate_article(article: dict[str, Any]) -> list[str]:
    """Return stable error codes for invalid required boundary fields."""
    errors: list[str] = []
    if not str(article.get("title") or "").strip():
        errors.append("title_missing")
    if not str(article.get("hash") or "").strip():
        errors.append("hash_missing")
    link = str(article.get("link") or "").strip()
    parsed = urlparse(link)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        errors.append("link_invalid")
    return errors
