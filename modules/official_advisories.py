"""Collect revision-aware official advisories for the Exposure workspace."""

import hashlib
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from modules.config import FEED_CUTOFF_DAYS, MAX_FUTURE_MINUTES, OUTPUT_DIR
from modules.date_utils import parse_datetime
from modules.utils import write_json_atomic

logger = logging.getLogger(__name__)
ADVISORIES_FILENAME = "official_advisories.json"
ADVISORY_TYPE = "official_advisory"
MAX_ADVISORIES = 200
_REVISION = re.compile(r"\bSSA-\d+\s+V(\d{1,4}(?:\.\d{1,4}){0,3})\b", re.IGNORECASE)


def _time(value):
    parsed = parse_datetime(value)
    return parsed.astimezone(timezone.utc) if parsed else None


def _official_link(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parts = urlsplit(value.strip())
        if parts.scheme != "https" or not parts.hostname or parts.username is not None:
            return None
    except ValueError:
        return None
    # Preserve fragments so separate entries in a JPCERT weekly report stay distinct.
    return urlunsplit(parts)


def _effective_time(record):
    return _time(record.get("updated_at")) or _time(record.get("published_at"))


def _revision(record):
    match = _REVISION.search(str(record.get("title") or ""))
    return tuple(int(part) for part in match[1].split(".")) if match else ()


def _store_latest(records, record):
    key = record["id"]
    previous = records.get(key)
    if previous is None:
        records[key] = record
        return
    winner = max((record, previous), key=lambda row: (_effective_time(row), _revision(row)))
    original_dates = [_time(row.get("published_at")) for row in (record, previous)]
    original = min((stamp for stamp in original_dates if stamp), default=None)
    records[key] = {**winner, "published_at": original.isoformat() if original else None}


def parse_advisory_entries(entries, source_url, source_name, region, now):
    """Read publisher dates and select the latest revision of each document."""
    latest = None
    items = {}
    cutoff = now - timedelta(days=FEED_CUTOFF_DAYS)
    future_limit = now + timedelta(minutes=MAX_FUTURE_MINUTES)
    for entry in entries:
        title = entry.get("title")
        url = _official_link(entry.get("link"))
        if not isinstance(title, str) or not title.strip() or url is None:
            continue
        published, updated = (_time(entry.get(key)) for key in ("published", "updated"))
        observed = max((stamp for stamp in (published, updated) if stamp), default=None)
        if observed is None or observed > future_limit:
            continue
        latest = max(latest, observed) if latest else observed
        if observed < cutoff:
            continue
        identity = hashlib.sha256(f"{source_url}|{url}".encode()).hexdigest()
        _store_latest(items, {
            "record_type": ADVISORY_TYPE,
            "id": identity,
            "source": source_name,
            "source_url": source_url,
            "region": region,
            "title": " ".join(title.split())[:500],
            "url": url,
            "published_at": published.isoformat() if published else None,
            "updated_at": updated.isoformat() if updated and (not published or updated >= published) else None,
        })
    return list(items.values()), latest


def _cached_advisories(path):
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    records = payload.get("advisories") if isinstance(payload, dict) else None
    return records if isinstance(records, list) else []


def split_and_publish_advisories(articles, feeds, *, path: Path | None = None, now=None):
    """Publish a recent advisory snapshot and return only news for enrichment."""
    news, incoming = [], []
    for item in articles:
        (incoming if item.get("record_type") == ADVISORY_TYPE else news).append(item)
    sources = {f["url"] for f in feeds if f.get("official_advisory") is True}
    path = path or OUTPUT_DIR / ADVISORIES_FILENAME
    if not sources and not path.exists():
        return news

    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=FEED_CUTOFF_DAYS)
    future_limit = now + timedelta(minutes=MAX_FUTURE_MINUTES)
    records = {}
    for record in [*_cached_advisories(path), *incoming]:
        if not isinstance(record, dict):
            continue
        source = record.get("source_url")
        if not isinstance(source, str) or source not in sources:
            continue
        stamp = _effective_time(record)
        if isinstance(record.get("id"), str) and stamp and cutoff <= stamp <= future_limit:
            _store_latest(records, record)
    recent = sorted(records.values(), key=lambda row: (_effective_time(row), row["id"]), reverse=True)
    try:
        write_json_atomic(path, {"generated_at": now.isoformat(), "advisories": recent[:MAX_ADVISORIES]})
    except OSError:
        logger.exception("Could not publish the official advisories snapshot")
    return news
