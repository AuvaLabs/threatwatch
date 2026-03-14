"""STIX 2.1 output generator.

Converts ThreatWatch articles and IOCs to a minimal but valid STIX 2.1 Bundle
suitable for import into threat intelligence platforms (OpenCTI, MISP, etc.).

No external dependency — generates JSON directly per the STIX 2.1 spec:
https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
"""
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


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
    identity_id = "identity--threatwatch-system"

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

    # Map IOC type to STIX pattern
    if ioc_type in ("md5_hash", "sha256_hash", "sha1_hash"):
        hash_type = ioc_type.upper().replace("_HASH", "")
        pattern = f"[file:hashes.'{hash_type}' = '{ioc_value}']"
    elif ioc_type == "ip:port":
        ip = ioc_value.split(":")[0]
        pattern = f"[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '{ip}']"
    elif ioc_type == "domain":
        pattern = f"[domain-name:value = '{ioc_value}']"
    elif ioc_type == "url":
        pattern = f"[url:value = '{ioc_value}']"
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


def build_stix_bundle(articles: list[dict], ioc_items: list[dict] | None = None) -> dict:
    """Build a STIX 2.1 Bundle from ThreatWatch articles and IOC items."""
    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--threatwatch-system",
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
            "name": "ThreatWatch",
            "identity_class": "system",
            "description": "Automated cyber threat intelligence aggregation system",
        }
    ]

    for article in articles:
        try:
            objects.append(_article_to_report(article))
        except Exception as e:
            logging.debug("STIX: skipping article: %s", e)

    for ioc in (ioc_items or []):
        try:
            indicator = _ioc_to_indicator(ioc)
            if indicator:
                objects.append(indicator)
        except Exception as e:
            logging.debug("STIX: skipping IOC: %s", e)

    bundle_id = _deterministic_id("bundle", _now_iso())
    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }


def build_stix_bytes(articles: list[dict], ioc_items: list[dict] | None = None) -> bytes:
    bundle = build_stix_bundle(articles, ioc_items)
    return json.dumps(bundle, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
