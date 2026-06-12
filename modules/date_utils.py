"""Consolidated datetime parsing for feed/article dates.

ThreatWatch previously had four separate `_parse_*` helpers across
`feed_fetcher`, `output_writer`, `darkweb_monitor`, and `incident_correlator`.
Two of them were subtly wrong — `darkweb_monitor` sliced the *format* string by
the *input* length (inverted logic), and `output_writer` fell back to
`datetime.now()` on parse failure, silently marking old corrupt-date articles
as brand new and keeping them past the cutoff window indefinitely.

This module is the single source of truth. It returns a timezone-aware UTC
`datetime` on success and `None` on failure. Callers decide what to do with
unparseable dates (skip, log, treat as oldest — never treat as "now").
"""
from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Iterable

# Bare formats without timezone info — assumed UTC when matched.
_BARE_FORMATS: tuple[str, ...] = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d",
)


def parse_datetime(raw: str | None) -> datetime | None:
    """Best-effort parse of an article date string.

    Accepts RFC 2822 (`Mon, 14 Apr 2026 12:00:00 GMT`), ISO 8601
    (`2026-04-14T12:00:00Z`, `2026-04-14T12:00:00.123+00:00`, etc.), and a
    short list of bare formats used by darkweb feeds. Any returned
    `datetime` is timezone-aware UTC.
    """
    if not raw or not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s:
        return None
    # ThreatFox and some darkweb sources suffix "UTC" — the original darkweb
    # parser accidentally tolerated this by slicing the input; we normalise it
    # explicitly here so the consolidated parser behaves the same way.
    if s.endswith(" UTC"):
        s = s[:-4].rstrip()

    # ISO 8601 first — cheapest and covers the bulk of feeds.
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        pass

    # RFC 2822 — mail/RSS feeds.
    try:
        dt = parsedate_to_datetime(s)
        if dt is not None:
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        pass

    # Bare formats — try each against the full input, no slicing.
    for fmt in _BARE_FORMATS:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue

    return None


def earliest(dates: Iterable[datetime | None]) -> datetime | None:
    """Return the earliest non-None datetime, or None if all are None."""
    valid = [d for d in dates if d is not None]
    return min(valid) if valid else None


def article_datetime(article: dict) -> datetime | None:
    """Best event-time for an article, as a timezone-aware UTC datetime.

    Prefers the article's own publication date; falls back to the pipeline
    ingestion time (`ingested_at`, then the legacy `timestamp` alias) when
    `published` is missing or unparseable. Returns None when no field
    parses — callers decide how to handle undatable articles and must never
    substitute "now".
    """
    for field in ("published", "ingested_at", "timestamp"):
        dt = parse_datetime(article.get(field))
        if dt is not None:
            return dt
    return None
