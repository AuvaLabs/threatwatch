"""Campaign persistence — stable IDs for threat campaigns across pipeline runs.

`incident_correlator` re-clusters the whole corpus on every pipeline tick,
so the cluster dict it produces is *ephemeral*: no stable identifier, and
the cluster's `first_seen` only reflects the earliest article still inside
the rolling 7-day window. A Volt Typhoon cluster that has been reported on
for 9 months will show "first seen 5 days ago" every Monday after the old
coverage ages out.

This module persists a separate `campaigns.json` that survives across runs:

- A campaign is keyed by the `(entity_type, entity_name)` composite — the
  same key the correlator uses to build clusters. Matching a cluster to a
  campaign is therefore deterministic: the same Volt Typhoon cluster always
  maps to the same campaign UUID.
- `first_observed` never rolls forward. Once assigned, it only gets *earlier*
  if a cluster's `first_seen` happens to be earlier than the stored value
  (e.g., a backfilled feed).
- `last_observed` rolls forward to track current activity.
- `status` tracks dormancy: active (< 14d since last sighting), dormant
  (14-90d), archived (>90d). Gives an analyst a fast "is this still hot?"
  signal.
- `article_hashes` is capped (default 500) so an actor like "LockBit" with
  thousands of articles over a year doesn't bloat the file.

Design choice: resurfacing after a long dormancy is NOT modelled as a new
campaign. Once a campaign UUID is assigned to `(actor, CVE, etc.)`, the same
UUID persists even after years of silence. Analysts who want to split
"Volt Typhoon 2023 era" from "Volt Typhoon 2026 era" should do so manually;
automated splitting would require analyst-labelled TTP deltas, which we
don't have.
"""
from __future__ import annotations

import json
import logging
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from modules.config import OUTPUT_DIR
from modules.date_utils import parse_datetime

logger = logging.getLogger(__name__)

CAMPAIGNS_PATH = OUTPUT_DIR / "campaigns.json"

# Dormancy thresholds (days since last_observed) driving the `status` field.
_ACTIVE_THRESHOLD_DAYS = 14
_ARCHIVED_THRESHOLD_DAYS = 90

# Per-campaign cap on the rolling article-hash set. Kept small because the
# hashes are not the source of truth — the pipeline's daily_latest.json is.
# This set is only used for cheap "have we seen this before?" checks.
_MAX_HASHES_PER_CAMPAIGN = 500

# Load/save take this lock; cluster_articles is called from the pipeline
# thread but the tracker may also run inside incident_correlator, which can
# be invoked from cron or manual backfill.
_save_lock = threading.Lock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _cluster_key(entity_type: str, entity_name: str) -> str:
    """Composite key used for stable campaign identity."""
    return f"{entity_type}:{entity_name}"


def _status_for_age(last_observed: datetime | None) -> str:
    if last_observed is None:
        return "unknown"
    age_days = (_now() - last_observed).days
    if age_days <= _ACTIVE_THRESHOLD_DAYS:
        return "active"
    if age_days <= _ARCHIVED_THRESHOLD_DAYS:
        return "dormant"
    return "archived"


def load_campaigns() -> dict[str, dict[str, Any]]:
    """Return campaigns keyed by campaign_id (UUID). Empty dict if missing."""
    if not CAMPAIGNS_PATH.exists():
        return {}
    try:
        with open(CAMPAIGNS_PATH, encoding="utf-8") as f:
            data = json.load(f)
        # File may be an index-by-id dict OR a legacy list — tolerate both.
        if isinstance(data, list):
            return {c["campaign_id"]: c for c in data if c.get("campaign_id")}
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, IOError, KeyError):
        logger.warning("campaigns.json unreadable — starting fresh")
        return {}


def save_campaigns(campaigns: dict[str, dict[str, Any]]) -> None:
    """Atomic write to CAMPAIGNS_PATH with tmp+rename."""
    CAMPAIGNS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CAMPAIGNS_PATH.with_suffix(".tmp")
    with _save_lock:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(campaigns, f, ensure_ascii=False, indent=2)
        tmp.replace(CAMPAIGNS_PATH)


def _index_by_key(campaigns: dict[str, dict]) -> dict[str, str]:
    """Return {cluster_key: campaign_id} from the current campaigns dict."""
    return {
        _cluster_key(c["entity_type"], c["entity_name"]): cid
        for cid, c in campaigns.items()
        if c.get("entity_type") and c.get("entity_name")
    }


def record_clusters(clusters: list[dict[str, Any]]) -> dict[str, str]:
    """Persist campaign state for this batch of clusters.

    For each cluster, either extend the existing campaign (matched by
    entity_type + entity_name) or mint a new one. Returns a
    `{cluster_key: campaign_id}` mapping that the correlator can use to
    annotate each cluster with its stable campaign UUID + ever-earliest
    first_observed.

    Side effects: writes campaigns.json atomically on every call. Failure to
    persist is logged but does NOT raise — the correlator should still be
    able to emit clusters.json in a degraded-but-functional mode.
    """
    campaigns = load_campaigns()
    key_to_id = _index_by_key(campaigns)
    now_iso = _now().isoformat()
    mapping: dict[str, str] = {}

    for cluster in clusters:
        entity_type = cluster.get("entity_type", "")
        entity_name = cluster.get("entity_name", "")
        if not entity_type or not entity_name:
            continue
        key = _cluster_key(entity_type, entity_name)

        cluster_first_seen = parse_datetime(cluster.get("first_seen"))
        # `article_hashes` is always present on clusters from the correlator
        # (we added it in the earlier batch). Default defensively to [].
        new_hashes = list(cluster.get("article_hashes") or [])

        cid = key_to_id.get(key)
        if cid is None:
            cid = str(uuid.uuid4())
            campaigns[cid] = {
                "campaign_id": cid,
                "entity_type": entity_type,
                "entity_name": entity_name,
                "first_observed": cluster.get("first_seen") or now_iso,
                "last_observed": cluster.get("first_seen") or now_iso,
                "total_observed_articles": len(new_hashes) or cluster.get("article_count", 0),
                "article_hashes": new_hashes[-_MAX_HASHES_PER_CAMPAIGN:],
                "status": "active",
                "created_at": now_iso,
                "updated_at": now_iso,
            }
            key_to_id[key] = cid
        else:
            existing = campaigns[cid]
            # first_observed only ever gets earlier. Compare parsed datetimes
            # so a mixed RFC 2822 / ISO 8601 corpus doesn't lexicographically
            # misorder.
            existing_first = parse_datetime(existing.get("first_observed"))
            if cluster_first_seen and (existing_first is None or cluster_first_seen < existing_first):
                existing["first_observed"] = cluster.get("first_seen")
            # last_observed rolls forward when the cluster has fresher hits.
            # We take the cluster's first_seen here (its earliest) AND push
            # last_observed to now_iso because the article was just seen in
            # this run; that is the only defensible "latest activity" signal
            # we have without re-scanning article timestamps.
            existing["last_observed"] = now_iso
            # Merge hashes with dedup, cap at the tail (most recent).
            merged = list(dict.fromkeys((existing.get("article_hashes") or []) + new_hashes))
            existing["article_hashes"] = merged[-_MAX_HASHES_PER_CAMPAIGN:]
            existing["total_observed_articles"] = max(
                existing.get("total_observed_articles", 0),
                len(merged),
                cluster.get("article_count", 0),
            )
            existing["status"] = "active"
            existing["updated_at"] = now_iso

        mapping[key] = cid

    # Re-compute status for campaigns NOT in this batch — they may have aged
    # into dormant / archived territory since the last run.
    for cid, c in campaigns.items():
        if _cluster_key(c.get("entity_type", ""), c.get("entity_name", "")) in mapping:
            continue
        last = parse_datetime(c.get("last_observed"))
        c["status"] = _status_for_age(last)

    try:
        save_campaigns(campaigns)
    except Exception as exc:
        logger.warning(f"campaigns.json save failed (non-fatal): {exc}")

    # Phase 1 JSON->SQLite dual-write. Failure is non-fatal; campaigns.json
    # remains the source of truth until the read-path migration lands.
    try:
        from modules.db import upsert_campaign
        for c in campaigns.values():
            upsert_campaign(c)
    except Exception as exc:
        logger.debug(f"SQLite campaign dual-write skipped: {exc}")

    logger.info(
        f"Campaigns: {len(mapping)} active this run, {len(campaigns)} total tracked"
    )
    return mapping


def get_campaign(campaign_id: str) -> dict[str, Any] | None:
    """Lookup by ID — used by /api/campaign/<id> and anywhere a cluster's
    stable campaign metadata needs to be resolved."""
    return load_campaigns().get(campaign_id)


def list_campaigns(status: str | None = None) -> list[dict[str, Any]]:
    """Return campaigns, optionally filtered by status, sorted by updated_at
    descending so the freshest activity is first."""
    campaigns = load_campaigns()
    items = list(campaigns.values())
    if status:
        items = [c for c in items if c.get("status") == status]
    items.sort(key=lambda c: c.get("updated_at", ""), reverse=True)
    return items
