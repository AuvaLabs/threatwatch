"""Article-aware observable validation and provenance helpers."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from modules.ioc_extractor import refang

_IOC_TYPES = ("ipv4", "ipv6", "domains", "urls", "sha256", "sha1", "md5", "emails")
_STRONG_TYPES = frozenset({"ipv4", "ipv6", "sha256", "sha1", "md5"})
_AGGREGATORS = frozenset({"bing", "google", "google news", "feedburner"})
_NETWORK_CONTEXT = re.compile(
    r"\b(?:c2|c&c|command(?: and |-)control|malicious|malware|phish(?:ing)?|"
    r"payload|beacon|indicator|ioc|infrastructure|callback|exfiltrat|botnet|"
    r"ransomware|compromise[ds]?|infected|attacker)\b",
    re.IGNORECASE,
)
_WEAK_CONTEXT = re.compile(
    r"\b(?:c2|c&c|command(?: and |-)control|malicious|phish(?:ing)?|payload|"
    r"beacon|indicator|ioc|callback|botnet|download(?:ed|ing)?|dropper)\b",
    re.IGNORECASE,
)
_VERSION_CONTEXT = re.compile(r"(?:\bversion\s*|\bv\s*|[<>=]\s*)$", re.IGNORECASE)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _host(value: Any) -> str:
    raw = _text(value)
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    return (parsed.hostname or "").casefold().removeprefix("www.")


def _registrable_token(domain: str) -> str:
    labels = domain.casefold().split(".")
    return labels[-2] if len(labels) > 1 else labels[0]


def publisher_name(article: dict[str, Any]) -> str:
    """Return the best available publisher identity, not the RSS aggregator."""
    source = _text(article.get("source_name")) or "Unknown publisher"
    if source.casefold() not in _AGGREGATORS | {"unknown publisher"}:
        return source
    title = _text(article.get("title"))
    suffix = title.rsplit(" - ", 1)[-1].strip() if " - " in title else ""
    if suffix and len(suffix) <= 80:
        return suffix
    hostname = _host(article.get("canonical_url") or article.get("link"))
    if hostname and not any(name in hostname for name in ("google.", "bing.", "feedburner.")):
        return hostname
    return source


def _publisher_tokens(article: dict[str, Any]) -> set[str]:
    name = publisher_name(article).casefold()
    return {token for token in re.findall(r"[a-z0-9]{4,}", name) if token not in {"news", "security", "finance"}}


def _context(text: str, value: str, radius: int = 120) -> str:
    folded = text.casefold()
    needle = value.casefold()
    index = folded.find(needle)
    if index < 0 and value.startswith("http"):
        index = folded.find(_host(value))
    if index < 0:
        return ""
    return text[max(0, index - radius):index + len(value) + radius].strip()


def _is_version_ip(value: str, text: str) -> bool:
    for match in re.finditer(re.escape(value), text, re.IGNORECASE):
        prefix = text[max(0, match.start() - 30):match.start()]
        if _VERSION_CONTEXT.search(prefix):
            return True
    return False


def _is_publisher_reference(value: str, article: dict[str, Any]) -> bool:
    candidate_host = _host(value) if "://" in value else value.casefold()
    candidate_host = candidate_host.removeprefix("www.")
    known_hosts = {
        _host(article.get("link")),
        _host(article.get("canonical_url")),
        _host(article.get("source")),
    }
    if candidate_host and any(
        candidate_host == host or candidate_host.endswith(f".{host}")
        for host in known_hosts if host
    ):
        return True
    domain_token = _registrable_token(candidate_host)
    return bool(domain_token and domain_token in _publisher_tokens(article))


def _values(article: dict[str, Any]) -> list[tuple[str, str]]:
    raw = article.get("iocs")
    if not isinstance(raw, dict):
        return []
    values: list[tuple[str, str]] = []
    for ioc_type in _IOC_TYPES:
        items = raw.get(ioc_type)
        if not isinstance(items, list):
            continue
        for item in items:
            value = _text(item.get("value") if isinstance(item, dict) else item)
            if value:
                values.append((ioc_type, value))
    return values


def article_observables(article: dict[str, Any]) -> list[dict[str, Any]]:
    """Return actionable observables after article-aware false-positive checks."""
    text = refang(" ".join(_text(article.get(key)) for key in ("title", "summary", "full_content")))
    source = {
        "article_id": _text(article.get("hash")),
        "title": _text(article.get("translated_title") or article.get("title")) or "Untitled report",
        "publisher": publisher_name(article),
        "published": article.get("published_at") or article.get("published") or article.get("timestamp"),
        "url": _text(article.get("canonical_url") or article.get("link")),
    }
    structured = bool(article.get("darkweb_source") == "threatfox" or article.get("darkwebSource") == "threatfox")
    observables: list[dict[str, Any]] = []
    for ioc_type, value in _values(article):
        context = _context(text, value)
        if ioc_type in {"domains", "urls"} and _is_publisher_reference(value, article):
            continue
        if ioc_type == "ipv4" and _is_version_ip(value, text):
            continue
        if ioc_type not in _STRONG_TYPES and not structured and not _WEAK_CONTEXT.search(context):
            continue
        if ioc_type in {"ipv4", "ipv6"} and not structured and not _NETWORK_CONTEXT.search(context):
            continue
        observables.append({
            "type": ioc_type,
            "value": value,
            "context": context[:280],
            "structured": structured,
            "source": source,
        })
    return observables
