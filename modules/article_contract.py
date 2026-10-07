"""Canonical, backward-compatible article boundary normalization."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from modules.date_utils import parse_datetime
from modules.deduplicator import normalize_url


_SOURCE_ALIASES = {
    "nvd:cve": "NVD",
    "darkweb:ransomware.live": "Ransomware.live",
    "darkweb:threatfox": "ThreatFox",
}


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


def _summary_method(article: dict[str, Any]) -> str:
    if not str(article.get("summary") or "").strip():
        return "none"
    if article.get("_ai_enhanced") or article.get("summary_generated"):
        return "ai"
    return str(article.get("summary_method") or "source")


def normalize_article(article: dict[str, Any]) -> dict[str, Any]:
    """Return a canonical article copy while preserving legacy fields."""
    source = str(article.get("source") or "")
    source_name = str(article.get("source_name") or "").strip() or _source_label(source)
    link = str(article.get("link") or "").strip()
    return {
        **article,
        "source_name": source_name,
        "canonical_url": normalize_url(link) if link else "",
        "published_at": _published_at(article),
        "region": article.get("region") or article.get("feed_region") or "Global",
        "content_hash": article.get("content_hash") or article.get("hash") or "",
        "summary": str(article.get("summary") or ""),
        "summary_method": _summary_method(article),
        "cve_ids": list(article.get("cve_ids") or []),
        "asset_tags": list(article.get("asset_tags") or []),
        "brand_tags": list(article.get("brand_tags") or []),
        "victim_sectors": list(article.get("victim_sectors") or []),
    }


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
