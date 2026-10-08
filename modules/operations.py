"""Deterministic operational prioritization for the ThreatWatch workspace."""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from typing import Any


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value) if value is not None else None
        return number if number is not None and math.isfinite(number) else None
    except (TypeError, ValueError):
        return None


def _article_id(article: dict[str, Any]) -> str:
    existing = str(article.get("hash") or "").strip()
    if existing:
        return existing
    identity = f"{article.get('title', '')}|{article.get('link', '')}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _watchlist_terms(watchlist: dict[str, Any]) -> list[str]:
    values = [*_list(watchlist.get("brands")), *_list(watchlist.get("assets"))]
    return [str(value).strip() for value in values if str(value).strip()]


def _watchlist_matches(article: dict[str, Any], terms: list[str]) -> list[str]:
    fields = [
        article.get("title"), article.get("translated_title"), article.get("summary"),
        article.get("intel_what"), article.get("source_name"), article.get("category"),
        *_list(article.get("asset_tags")), *_list(article.get("brand_tags")),
    ]
    haystack = " ".join(str(value or "") for value in fields).casefold()
    return [term for term in terms if term.casefold() in haystack]


def _techniques(article: dict[str, Any]) -> list[str]:
    rendered: list[str] = []
    for value in _list(article.get("attack_techniques")):
        if isinstance(value, dict):
            technique_id = value.get("technique_id") or value.get("id")
            technique_name = value.get("technique_name") or value.get("name")
            text = " ".join(str(item or "") for item in (technique_id, technique_name)).strip()
        else:
            text = str(value).strip()
        if text:
            rendered.append(text)
    return rendered[:12]


def _indicators(article: dict[str, Any]) -> tuple[list[str], int]:
    raw = article.get("iocs")
    if not isinstance(raw, dict):
        return [], 0
    values: list[str] = []
    count = 0
    for items in raw.values():
        if not isinstance(items, list):
            continue
        count += len(items)
        for item in items:
            rendered = item if isinstance(item, str) else json.dumps(item, sort_keys=True)
            if rendered and rendered not in values and len(values) < 12:
                values.append(rendered)
    return values, count


def _score(article: dict[str, Any], matches: list[str], ioc_count: int, techniques: list[str]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    kev = bool(article.get("kev_listed") or article.get("kevListed"))
    cvss = _number(article.get("cvss_score"))
    epss = _number(article.get("epss_score"))
    if kev:
        score += 35
        reasons.append("CISA KEV confirms active exploitation")
    if cvss is not None and cvss >= 9:
        score += 15
        reasons.append(f"Critical CVSS score of {cvss:g}")
    elif cvss is not None and cvss >= 7:
        score += 8
        reasons.append(f"High CVSS score of {cvss:g}")
    if epss is not None and epss >= 0.1:
        score += 20
        reasons.append(f"EPSS indicates {epss * 100:.1f}% exploitation probability")
    elif epss is not None and epss >= 0.03:
        score += 10
        reasons.append(f"EPSS indicates {epss * 100:.1f}% exploitation probability")
    if matches:
        score += 30
        reasons.append(f"Matches monitored context: {', '.join(matches[:3])}")
    if ioc_count:
        score += 8
        reasons.append(f"Contains {ioc_count} extracted indicator{'s' if ioc_count != 1 else ''}")
    if techniques:
        score += 5
        reasons.append("Includes observed ATT&CK behavior")
    category = str(article.get("category") or "").casefold()
    if any(term in category for term in ("ransomware", "data breach", "cyber attack")):
        score += 10
        reasons.append("Reports operationally disruptive activity")
    return min(score, 100), reasons


def _action(score: int, article: dict[str, Any], matches: list[str], ioc_count: int) -> tuple[str, str]:
    kev = bool(article.get("kev_listed") or article.get("kevListed"))
    cves = _list(article.get("cve_ids"))
    if kev or (cves and score >= 45):
        return "patch", "Validate affected technology, then patch or isolate confirmed exposure."
    if ioc_count:
        return "hunt", "Hunt for the extracted indicators and preserve any matching telemetry."
    if matches:
        return "investigate", "Validate the watchlist match and determine whether the activity affects your environment."
    return "monitor", "Monitor corroborating evidence and reassess when the threat state changes."


def _priority(article: dict[str, Any], terms: list[str]) -> dict[str, Any] | None:
    matches = _watchlist_matches(article, terms)
    indicators, ioc_count = _indicators(article)
    techniques = _techniques(article)
    score, reasons = _score(article, matches, ioc_count, techniques)
    if score < 20:
        return None
    urgency = "critical" if score >= 70 else "high" if score >= 45 else "medium"
    action_type, recommended_action = _action(score, article, matches, ioc_count)
    summary = str(article.get("summary") or article.get("intel_what") or "").strip()
    return {
        "id": _article_id(article),
        "title": str(article.get("translated_title") or article.get("title") or "Untitled intelligence"),
        "summary": summary[:500],
        "source_name": article.get("source_name"),
        "published": article.get("published_at") or article.get("published") or article.get("timestamp"),
        "region": article.get("region"),
        "score": score,
        "urgency": urgency,
        "action_type": action_type,
        "recommended_action": recommended_action,
        "reasons": reasons,
        "watchlist_matches": matches,
        "evidence": {
            "cves": [str(value) for value in _list(article.get("cve_ids"))[:12]],
            "techniques": techniques,
            "iocs": indicators,
            "ioc_count": ioc_count,
            "kev": bool(article.get("kev_listed") or article.get("kevListed")),
            "cvss": _number(article.get("cvss_score")),
            "epss": _number(article.get("epss_score")),
            "confidence": _number(article.get("confidence")),
        },
    }


def _deduplicated_priorities(articles: list[dict[str, Any]], terms: list[str]) -> list[dict[str, Any]]:
    candidates = [item for article in articles if (item := _priority(article, terms))]
    candidates.sort(key=lambda item: (-item["score"], item["title"].casefold()))
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in candidates:
        cves = item["evidence"]["cves"]
        keys = {f"cve:{cve}" for cve in cves} or {f"title:{item['title'].casefold()}"}
        if keys & seen:
            continue
        seen.update(keys)
        selected.append(item)
        if len(selected) == 12:
            break
    return selected


def _cluster_list(clusters: Any) -> list[dict[str, Any]]:
    if isinstance(clusters, dict):
        clusters = clusters.get("clusters")
    return [value for value in _list(clusters) if isinstance(value, dict)]


def build_operational_summary(articles: Any, clusters: Any, watchlist: Any) -> dict[str, Any]:
    """Build a bounded decision queue from real evidence and monitored context."""
    article_list = [value for value in _list(articles) if isinstance(value, dict)]
    watchlist_data = watchlist if isinstance(watchlist, dict) else {}
    terms = _watchlist_terms(watchlist_data)
    priorities = _deduplicated_priorities(article_list, terms)
    cluster_items = _cluster_list(clusters)
    watchlist_matches = [item for item in priorities if item["watchlist_matches"]]
    kev_records = sum(
        1 for article in article_list
        if article.get("kev_listed") or article.get("kevListed")
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metrics": {
            "decision_queue": len(priorities),
            "critical_priorities": sum(item["urgency"] == "critical" for item in priorities),
            "watchlist_matches": len(watchlist_matches),
            "kev_records": kev_records,
            "active_threats": len(cluster_items),
            "sources_reviewed": len(article_list),
        },
        "priorities": priorities,
        "exposure": {
            "configured": bool(terms),
            "brands": [str(value) for value in _list(watchlist_data.get("brands"))],
            "assets": [str(value) for value in _list(watchlist_data.get("assets"))],
            "matches": watchlist_matches,
            "disclaimer": "Watchlist relevance is not confirmation of asset exposure.",
        },
    }
