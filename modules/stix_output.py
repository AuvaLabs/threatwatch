"""STIX 2.1 output generator.

Converts ThreatWatch articles and IOCs to a minimal but valid STIX 2.1 Bundle
suitable for import into threat intelligence platforms (OpenCTI, MISP, etc.).

No external dependency — generates JSON directly per the STIX 2.1 spec:
https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
"""
import hashlib
import json
import logging
import re

logger = logging.getLogger(__name__)
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Strip characters that could break STIX pattern string literals
_UNSAFE_STIX_RE = re.compile(r"['\\\[\]]")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _deterministic_id(prefix: str, seed: str) -> str:
    """Generate a deterministic UUID-like STIX ID from a seed string.

    Uses SHA-256 of the seed, formatted as a STIX id (prefix--<uuid>).
    Deterministic so the same article produces the same STIX object on re-runs.
    """
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    uuid_part = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
    return f"{prefix}--{uuid_part}"


def _article_to_report(article: dict[str, Any]) -> dict[str, Any]:
    """Convert a single ThreatWatch article to a STIX 2.1 Report object."""
    title = article.get("translated_title") or article.get("title", "Untitled")
    url = article.get("link") or article.get("url", "")
    summary = article.get("summary") or ""
    published = article.get("published") or _now_iso()
    category = article.get("category", "General Cyber Threat")
    region = article.get("feed_region", "Global")

    # Normalise timestamp to Z-suffix format
    try:
        dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
        published_ts = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        published_ts = _now_iso()

    stix_id = _deterministic_id("report", url or title)
    identity_id = _IDENTITY_ID

    # Map article confidence to STIX confidence (0-100)
    confidence = article.get("confidence")
    if isinstance(confidence, (int, float)):
        confidence = max(0, min(100, int(confidence)))
    else:
        confidence = None

    report: dict[str, Any] = {
        "type": "report",
        "spec_version": "2.1",
        "id": stix_id,
        "created": published_ts,
        "modified": published_ts,
        "name": title,
        "description": summary,
        "published": published_ts,
        "report_types": ["threat-report"],
        "object_refs": [identity_id],
        "labels": [category.lower().replace(" ", "-"), region.lower().replace(" ", "-")],
        "external_references": [
            {
                "source_name": article.get("source_name", "Unknown"),
                "url": url,
            }
        ] if url else [],
    }
    if confidence is not None:
        report["confidence"] = confidence
    return report


def _ioc_to_indicator(ioc: dict[str, Any]) -> dict[str, Any] | None:
    """Convert a ThreatFox IOC entry to a STIX 2.1 Indicator."""
    ioc_value = ioc.get("iocValue") or ioc.get("title", "")
    ioc_type = (ioc.get("iocType") or "").lower()
    malware = ioc.get("malwareFamily") or ioc.get("category", "unknown")
    published = ioc.get("published") or _now_iso()

    try:
        dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
        ts = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        ts = _now_iso()

    # Map IOC type to STIX pattern — sanitize value to prevent pattern injection
    safe_value = _UNSAFE_STIX_RE.sub("", ioc_value)
    if ioc_type in ("md5_hash", "sha256_hash", "sha1_hash"):
        hash_type = ioc_type.upper().replace("_HASH", "")
        pattern = f"[file:hashes.'{hash_type}' = '{safe_value}']"
    elif ioc_type == "ip:port":
        ip = safe_value.split(":")[0]
        pattern = f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{ip}']"
    elif ioc_type == "domain":
        pattern = f"[domain-name:value = '{safe_value}']"
    elif ioc_type == "url":
        pattern = f"[url:value = '{safe_value}']"
    else:
        return None  # unsupported IOC type

    stix_id = _deterministic_id("indicator", ioc_value)
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id,
        "created": ts,
        "modified": ts,
        "name": f"{malware} — {ioc_type} indicator",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ts,
        "labels": ["malicious-activity"],
        "indicator_types": ["malicious-activity"],
    }


def _make_relationship(source_id: str, target_id: str, rel_type: str, ts: str) -> dict[str, Any]:
    """Create a STIX 2.1 Relationship object."""
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": _deterministic_id("relationship", f"{source_id}:{target_id}:{rel_type}"),
        "created": ts,
        "modified": ts,
        "relationship_type": rel_type,
        "source_ref": source_id,
        "target_ref": target_id,
    }


# STIX 2.1 ids MUST be `<type>--<UUID>`. The old literal
# "identity--threatwatch-system" was not UUID-form, so validating consumers
# (OpenCTI, MISP, Sentinel TAXII import) rejected every object that
# referenced it — i.e. the entire bundle. Deterministic so it is stable
# across runs and installs.
_IDENTITY_ID = _deterministic_id("identity", "threatwatch-system")


def build_stix_bundle(articles: list[dict], ioc_items: list[dict] | None = None) -> dict:
    """Build a STIX 2.1 Bundle from ThreatWatch articles and IOC items."""
    identity_id = _IDENTITY_ID
    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "name": "ThreatWatch",
            "identity_class": "system",
            "description": "Automated cyber threat intelligence aggregation system",
        }
    ]

    report_ids: list[str] = []
    for article in articles:
        try:
            report = _article_to_report(article)
            objects.append(report)
            report_ids.append(report["id"])
        except Exception as e:
            logger.debug("STIX: skipping article: %s", e)

    indicator_ids: list[str] = []
    for ioc in (ioc_items or []):
        try:
            indicator = _ioc_to_indicator(ioc)
            if indicator:
                objects.append(indicator)
                indicator_ids.append(indicator["id"])
        except Exception as e:
            logger.debug("STIX: skipping IOC: %s", e)

    # Provenance: stamp created_by_ref on every report/indicator instead of
    # the old `indicator indicates identity` relationships — "indicates" is
    # defined for indicator→(malware|campaign|threat-actor|...) and pointing
    # it at a system identity was semantically invalid; validating TAXII
    # importers discarded those objects.
    for obj in objects:
        if obj.get("type") in ("report", "indicator"):
            obj["created_by_ref"] = identity_id
        if obj.get("type") == "report" and indicator_ids:
            obj["object_refs"] = [identity_id] + indicator_ids

    # Bundle id derived from the CONTENT (sorted member ids), not the wall
    # clock: TAXII clients dedup on bundle id, and a fresh id per request
    # forced full re-ingestion on every poll (and defeated ETag caching).
    member_ids = ",".join(sorted(o["id"] for o in objects))
    bundle_id = _deterministic_id("bundle", member_ids)
    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }


def build_stix_bytes(articles: list[dict], ioc_items: list[dict] | None = None) -> bytes:
    bundle = build_stix_bundle(articles, ioc_items)
    return json.dumps(bundle, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
