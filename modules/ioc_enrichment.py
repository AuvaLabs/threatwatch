"""Optional, cached corroboration for validated observables."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from modules.db import load_observable_enrichments, upsert_observable_enrichment
from modules.ioc_quality import article_observables

_TIMEOUT_SECONDS = 12
_DEFAULT_TTL_HOURS = 24
_DEFAULT_MAX_LOOKUPS = 40


class ThreatFoxProvider:
    name = "threatfox"
    endpoint = "https://threatfox-api.abuse.ch/api/v1/"
    supported_types = frozenset({"ipv4", "ipv6", "domains", "urls", "sha256", "sha1", "md5"})

    def __init__(self, auth_key: str, *, session: Any = requests):
        self.auth_key = auth_key
        self.session = session

    def lookup(self, observable_type: str, value: str) -> dict[str, Any] | None:
        if observable_type not in self.supported_types:
            return None
        response = self.session.post(
            self.endpoint,
            headers={"Auth-Key": self.auth_key},
            json={"query": "search_ioc", "search_term": value, "exact_match": True},
            timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
        matches = payload.get("data") if isinstance(payload, dict) else None
        matched = payload.get("query_status") == "ok" and isinstance(matches, list) and bool(matches)
        return {
            "status": "matched" if matched else "not_found",
            "confidence": 95 if matched else 0,
            "payload": {"matches": matches[:5]} if matched else {},
        }


class UrlhausProvider:
    name = "urlhaus"
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    supported_types = frozenset({"urls"})

    def __init__(self, auth_key: str, *, session: Any = requests):
        self.auth_key = auth_key
        self.session = session

    def lookup(self, observable_type: str, value: str) -> dict[str, Any] | None:
        if observable_type not in self.supported_types:
            return None
        response = self.session.post(
            self.endpoint,
            headers={"Auth-Key": self.auth_key},
            data={"url": value},
            timeout=_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
        matched = isinstance(payload, dict) and payload.get("query_status") == "ok"
        return {
            "status": "matched" if matched else "not_found",
            "confidence": 95 if matched else 0,
            "payload": payload if matched else {},
        }


def configured_providers() -> list[Any]:
    """Create only providers with explicit operator credentials."""
    providers: list[Any] = []
    if key := os.getenv("THREATFOX_AUTH_KEY", "").strip():
        providers.append(ThreatFoxProvider(key))
    if key := os.getenv("URLHAUS_AUTH_KEY", "").strip():
        providers.append(UrlhausProvider(key))
    return providers


def _candidates(articles: list[dict[str, Any]]) -> list[tuple[str, str]]:
    values = {
        (item["type"], item["value"])
        for article in articles
        for item in article_observables(article)
    }
    return sorted(values)


def refresh_observable_enrichments(
    articles: list[dict[str, Any]],
    *,
    providers: list[Any] | None = None,
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Refresh a bounded number of uncached observables, then return the cache."""
    active = configured_providers() if providers is None else providers
    if not active:
        return load_observable_enrichments()
    cached = load_observable_enrichments()
    limit = max(0, int(os.getenv("HUNT_ENRICHMENT_MAX_LOOKUPS", str(_DEFAULT_MAX_LOOKUPS))))
    ttl = max(1, int(os.getenv("HUNT_ENRICHMENT_TTL_HOURS", str(_DEFAULT_TTL_HOURS))))
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl)).isoformat()
    attempted = 0
    for observable_type, value in _candidates(articles):
        for provider in active:
            if observable_type not in provider.supported_types:
                continue
            existing = cached.get((observable_type, value.casefold()), [])
            if any(item["provider"] == provider.name for item in existing):
                continue
            if attempted >= limit:
                return load_observable_enrichments()
            attempted += 1
            try:
                result = provider.lookup(observable_type, value)
            except (requests.RequestException, ValueError, TypeError):
                continue
            if result is None:
                continue
            upsert_observable_enrichment({
                "provider": provider.name,
                "type": observable_type,
                "value": value,
                "expires_at": expires_at,
                **result,
            })
    return load_observable_enrichments()
