"""Build persistent, evidence-linked threat records and meaningful change events."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from modules.config import OUTPUT_DIR
from modules.ioc_quality import publisher_name
from modules.utils import write_json_atomic

LEDGER_PATH = OUTPUT_DIR / "threat_ledger.json"
SCHEMA_VERSION = 1
MAX_RECORDS = 5_000
MAX_RECORD_CHANGES = 30
MAX_GLOBAL_CHANGES = 500
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_EXPLOIT_RE = re.compile(
    r"\b(?:actively exploited|active exploitation|exploited in the wild|in-the-wild exploitation)\b",
    re.IGNORECASE,
)


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _article_id(article: dict[str, Any]) -> str:
    existing = str(article.get("hash") or "").strip()
    if existing:
        return existing
    identity = f"{article.get('title', '')}|{article.get('link', '')}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _cves(article: dict[str, Any]) -> set[str]:
    values = {str(value).upper() for value in _list(article.get("cve_ids")) if value}
    if article.get("cve_id"):
        values.add(str(article["cve_id"]).upper())
    text = " ".join(str(article.get(field) or "") for field in ("title", "translated_title", "summary"))
    values.update(match.group(0).upper() for match in _CVE_RE.finditer(text))
    return {value for value in values if _CVE_RE.fullmatch(value)}


def _entity_id(entity_type: str, entity_name: str) -> str:
    digest = hashlib.sha256(f"{entity_type}:{entity_name.casefold()}".encode("utf-8")).hexdigest()[:16]
    return f"threat-{digest}"


def _source(article: dict[str, Any]) -> dict[str, Any]:
    source = str(article.get("source") or "")
    return {
        "article_id": _article_id(article),
        "title": str(article.get("translated_title") or article.get("title") or "Untitled report"),
        "publisher": publisher_name(article),
        "published": article.get("published_at") or article.get("published") or article.get("timestamp"),
        "url": str(article.get("canonical_url") or article.get("link") or ""),
        "source_type": "structured" if source == "nvd:cve" else "reporting",
    }


def _cluster_items(clusters: Any) -> list[dict[str, Any]]:
    raw = clusters.get("clusters") if isinstance(clusters, dict) else clusters
    return [item for item in _list(raw) if isinstance(item, dict)]


def _hunt_items(hunts: Any) -> list[dict[str, Any]]:
    raw = hunts.get("hunts") if isinstance(hunts, dict) else hunts
    return [item for item in _list(raw) if isinstance(item, dict)]


def _groups(
    articles: list[dict[str, Any]], clusters: Any,
) -> dict[tuple[str, str], dict[str, Any]]:
    by_id = {_article_id(article): article for article in articles}
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    cve_members: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for article in articles:
        for cve in _cves(article):
            cve_members[cve].append(article)
    for cve, members in cve_members.items():
        grouped[("cve", cve)] = {"members": members, "cluster": {}}
    for cluster in _cluster_items(clusters):
        entity_type = str(cluster.get("entity_type") or "").strip().casefold()
        entity_name = str(cluster.get("entity_name") or "").strip()
        if entity_type not in {"cve", "actor"} or not entity_name:
            continue
        if entity_type == "cve":
            entity_name = entity_name.upper()
            if not _CVE_RE.fullmatch(entity_name):
                continue
        members = [by_id[value] for value in _list(cluster.get("article_hashes")) if value in by_id]
        key = (entity_type, entity_name)
        existing = grouped.get(key, {"members": [], "cluster": {}})
        combined = {**{_article_id(item): item for item in existing["members"]}, **{
            _article_id(item): item for item in members
        }}
        grouped[key] = {"members": list(combined.values()), "cluster": cluster}
    return grouped


def _techniques(members: list[dict[str, Any]], hunt: dict[str, Any] | None) -> list[dict[str, str]]:
    found: dict[str, dict[str, str]] = {}
    values = [value for member in members for value in _list(member.get("attack_techniques"))]
    values.extend(_list((hunt or {}).get("techniques")))
    for value in values:
        if isinstance(value, dict):
            technique_id = str(value.get("technique_id") or value.get("id") or "").strip().upper()
            name = str(value.get("technique_name") or value.get("name") or "").strip()
            tactic = str(value.get("tactic") or "").strip()
        else:
            rendered = str(value or "").strip()
            technique_id, name, tactic = rendered.split(" ", 1)[0], rendered, ""
        if technique_id.startswith("T") and technique_id[1:].replace(".", "").isdigit():
            found[technique_id] = {"id": technique_id, "name": name, "tactic": tactic}
    return [found[key] for key in sorted(found)]


def _products(members: list[dict[str, Any]]) -> list[str]:
    products: set[str] = set()
    for member in members:
        products.update(str(value).strip() for value in _list(member.get("affected_products")) if str(value).strip())
        for entry in _list(member.get("kev_entries")):
            if not isinstance(entry, dict):
                continue
            product = " ".join(str(entry.get(field) or "").strip() for field in ("vendor", "product")).strip()
            if product:
                products.add(product)
    return sorted(products, key=str.casefold)[:20]


def _remediation(members: list[dict[str, Any]]) -> dict[str, Any]:
    entries = [entry for member in members for entry in _list(member.get("kev_entries")) if isinstance(entry, dict)]
    actions = [str(entry.get("required_action") or "").strip() for entry in entries]
    due_dates = [str(entry.get("due_date") or "").strip() for entry in entries]
    return {
        "required_action": next((value for value in actions if value), None),
        "due_date": min((value for value in due_dates if value), default=None),
        "affected_versions": [],
        "fixed_versions": [],
    }


def _summary(members: list[dict[str, Any]], cluster: dict[str, Any]) -> str:
    synthesis = str(cluster.get("synthesis") or "").strip()
    if synthesis:
        return synthesis[:800]
    candidates = [str(member.get("summary") or "").strip() for member in members]
    return max(candidates, key=len, default="No narrative assessment is available.")[:800]


def _vulnerability(entity_name: str, members: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not _CVE_RE.fullmatch(entity_name):
        return None
    cvss = [value for member in members if (value := _number(member.get("cvss_score"))) is not None]
    epss = [value for member in members if (value := _number(member.get("epss_score"))) is not None]
    return {
        "cve": entity_name,
        "kev": any(member.get("kev_listed") or member.get("kevListed") for member in members),
        "max_cvss": max(cvss) if cvss else None,
        "max_epss": max(epss) if epss else None,
    }


def _states(
    members: list[dict[str, Any]], sources: list[dict[str, Any]], hunt: dict[str, Any] | None,
    vulnerability: dict[str, Any] | None,
) -> dict[str, str]:
    text = " ".join(str(member.get(field) or "") for member in members for field in ("title", "summary"))
    if vulnerability and vulnerability["kev"]:
        exploitation = "confirmed"
    elif _EXPLOIT_RE.search(text):
        exploitation = "reported"
    else:
        exploitation = "unknown"
    source_count = len({source["publisher"].casefold() for source in sources})
    return {
        "activity": "active",
        "exploitation": exploitation,
        "evidence": "corroborated" if source_count >= 2 else "single_source",
        "hunt": str((hunt or {}).get("status") or "unavailable"),
        "remediation": "action_available" if _remediation(members)["required_action"] else "unknown",
    }


def _decision(
    entity_type: str, states: dict[str, str], vulnerability: dict[str, Any] | None,
) -> dict[str, str]:
    if vulnerability and vulnerability["kev"]:
        return {"action": "patch", "urgency": "critical", "rationale": "CISA KEV confirms active exploitation."}
    if states["hunt"] == "qualified":
        return {"action": "hunt", "urgency": "high", "rationale": "The evidence-gated hunt package is qualified."}
    if states["exploitation"] == "reported" or (vulnerability and vulnerability["max_epss"] is not None and vulnerability["max_epss"] >= 0.1):
        return {"action": "investigate", "urgency": "high", "rationale": "Exploitation risk requires independent validation."}
    if entity_type == "actor" and states["evidence"] == "corroborated":
        return {"action": "investigate", "urgency": "medium", "rationale": "Independent reporting supports continued investigation."}
    return {"action": "monitor", "urgency": "medium", "rationale": "Monitor for stronger exploitation or environment evidence."}


def _evidence(
    states: dict[str, str], vulnerability: dict[str, Any] | None,
    techniques: list[dict[str, str]], source_count: int,
) -> list[dict[str, str]]:
    return [
        {"key": "sources", "label": "Independent reporting", "status": states["evidence"], "detail": f"{source_count} independent publisher{'s' if source_count != 1 else ''}."},
        {"key": "exploitation", "label": "Exploitation", "status": states["exploitation"], "detail": "Confirmed through CISA KEV." if vulnerability and vulnerability["kev"] else "No authoritative exploitation confirmation is present."},
        {"key": "behavior", "label": "ATT&CK behavior", "status": "mapped" if techniques else "missing", "detail": f"{len(techniques)} supported technique{'s' if len(techniques) != 1 else ''}."},
        {"key": "hunt", "label": "Hunt package", "status": states["hunt"], "detail": "Qualification is controlled by the hunt evidence gate."},
    ]


def _open_questions(states: dict[str, str], products: list[str], remediation: dict[str, Any]) -> list[str]:
    questions: list[str] = []
    if states["evidence"] == "single_source":
        questions.append("Needs independent corroboration")
    if states["exploitation"] == "unknown":
        questions.append("No authoritative exploitation confirmation")
    if not products:
        questions.append("Affected product mapping is unavailable")
    if not remediation["required_action"]:
        questions.append("No authoritative remediation action is attached")
    return questions


def _tracked(record: dict[str, Any]) -> dict[str, Any]:
    vulnerability = record.get("vulnerability") or {}
    return {
        "decision": record["decision"]["action"],
        "urgency": record["decision"]["urgency"],
        "activity": record["state"]["activity"],
        "exploitation": record["state"]["exploitation"],
        "evidence": record["state"]["evidence"],
        "hunt": record["state"]["hunt"],
        "kev": bool(vulnerability.get("kev")),
        "source_count": record["source_count"],
        "affected_products": record["affected_products"],
        "techniques": [item["id"] for item in record["techniques"]],
    }


def _change_summary(field: str, current: Any, entity_name: str) -> str:
    if field == "record":
        return f"ThreatWatch began tracking {entity_name}."
    if field == "exploitation" and current == "confirmed":
        return f"{entity_name} gained confirmed exploitation evidence."
    if field == "decision":
        return f"The recommended action for {entity_name} changed to {current}."
    if field == "hunt" and current == "qualified":
        return f"The hunt package for {entity_name} passed the evidence gate."
    if field == "activity" and current == "not_recent":
        return f"{entity_name} left the current reporting window."
    return f"{entity_name} changed: {field.replace('_', ' ')} is now {current}."


def _history(previous: dict[str, Any]) -> list[dict[str, Any]]:
    history = copy.deepcopy(_list(previous.get("changes")))
    for change in history:
        if not isinstance(change, dict):
            continue
        if change.get("kind") == "tracking_started" and change.get("field") == "record":
            entity_name = str(change.get("entity_name") or previous.get("entity_name") or "this record")
            change["summary"] = _change_summary("record", change.get("current"), entity_name)
    return history


def _change(record: dict[str, Any], kind: str, field: str, previous: Any, current: Any, changed_at: str) -> dict[str, Any]:
    identity = f"{record['id']}|{changed_at}|{field}|{current}"
    return {
        "id": hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20],
        "record_id": record["id"],
        "entity_name": record["entity_name"],
        "changed_at": changed_at,
        "kind": kind,
        "field": field,
        "previous": previous,
        "current": current,
        "summary": _change_summary(field, current, record["entity_name"]),
        "source_ids": [source["article_id"] for source in record.get("sources", [])[:12]],
    }


def _apply_history(record: dict[str, Any], previous: dict[str, Any] | None, generated_at: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if previous is None:
        event = _change(record, "tracking_started", "record", None, "active", generated_at)
        return {**record, "version": 1, "last_changed": generated_at, "changes": [event]}, [event]
    events: list[dict[str, Any]] = []
    before, after = _tracked(previous), _tracked(record)
    for field, current in after.items():
        if before.get(field) != current:
            events.append(_change(record, "state_changed", field, before.get(field), current, generated_at))
    history = [*events, *_history(previous)][:MAX_RECORD_CHANGES]
    return {
        **record,
        "version": int(previous.get("version") or 1) + (1 if events else 0),
        "last_changed": generated_at if events else previous.get("last_changed") or generated_at,
        "changes": history,
    }, events


def _record(
    entity_type: str, entity_name: str, members: list[dict[str, Any]], cluster: dict[str, Any],
    hunt: dict[str, Any] | None, generated_at: str,
) -> dict[str, Any]:
    sources = [_source(member) for member in members]
    sources.sort(key=lambda item: str(item.get("published") or ""), reverse=True)
    source_count = len({source["publisher"].casefold() for source in sources})
    vulnerability = _vulnerability(entity_name, members)
    techniques = _techniques(members, hunt)
    products = _products(members)
    remediation = _remediation(members)
    states = _states(members, sources, hunt, vulnerability)
    decision = _decision(entity_type, states, vulnerability)
    first_seen_values = [str(source.get("published") or "") for source in sources if source.get("published")]
    return {
        "id": _entity_id(entity_type, entity_name),
        "entity_type": entity_type,
        "entity_name": entity_name,
        "title": entity_name if entity_type == "cve" else f"{entity_name} activity",
        "summary": _summary(members, cluster),
        "decision": decision,
        "state": states,
        "first_seen": cluster.get("first_observed") or cluster.get("first_seen") or (min(first_seen_values) if first_seen_values else None),
        "last_updated": generated_at,
        "report_count": len(sources),
        "source_count": source_count,
        "sources": sources[:50],
        "vulnerability": vulnerability,
        "affected_products": products,
        "remediation": remediation,
        "techniques": techniques,
        "hunt_id": str((hunt or {}).get("id") or "") or None,
        "readiness_score": int((hunt or {}).get("readiness_score") or 0),
        "observable_count": len(_list((hunt or {}).get("observables"))),
        "evidence": _evidence(states, vulnerability, techniques, source_count),
        "open_questions": _open_questions(states, products, remediation),
    }


def _archive(previous: dict[str, Any], generated_at: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    archived = copy.deepcopy(previous)
    archived["last_updated"] = generated_at
    archived["state"] = {**archived.get("state", {}), "activity": "not_recent"}
    archived["decision"] = {
        "action": "monitor", "urgency": "medium",
        "rationale": "The record is outside the current reporting window; retain it for history.",
    }
    return _apply_history(archived, previous, generated_at)


def build_ledger(
    articles: Any, clusters: Any, hunts: Any, *, previous: Any = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build the current public ledger while preserving prior record history."""
    generated_at = generated_at or datetime.now(timezone.utc).isoformat()
    article_list = [item for item in _list(articles) if isinstance(item, dict)]
    previous_records = {
        str(item.get("id")): item for item in _list((previous or {}).get("records"))
        if isinstance(item, dict) and item.get("id")
    } if isinstance(previous, dict) else {}
    hunt_index = {
        (str(item.get("entity_type") or "").casefold(), str(item.get("entity_name") or "").casefold()): item
        for item in _hunt_items(hunts)
        if item.get("entity_type") and item.get("entity_name")
    }
    records: list[dict[str, Any]] = []
    new_events: list[dict[str, Any]] = []
    active_ids: set[str] = set()
    for (entity_type, entity_name), group in _groups(article_list, clusters).items():
        if not group["members"]:
            continue
        hunt = hunt_index.get((entity_type, entity_name.casefold()))
        candidate = _record(entity_type, entity_name, group["members"], group["cluster"], hunt, generated_at)
        active_ids.add(candidate["id"])
        versioned, events = _apply_history(candidate, previous_records.get(candidate["id"]), generated_at)
        records.append(versioned)
        new_events.extend(events)
    for record_id, old_record in previous_records.items():
        if record_id in active_ids:
            continue
        archived, events = _archive(old_record, generated_at)
        records.append(archived)
        new_events.extend(events)
    urgency_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    records.sort(key=lambda item: (
        item["state"]["activity"] != "active",
        urgency_order.get(item["decision"]["urgency"], 9),
        -item["source_count"], item["entity_name"].casefold(),
    ))
    records = records[:MAX_RECORDS]
    retained_ids = {record["id"] for record in records}
    new_events = [event for event in new_events if event.get("record_id") in retained_ids]
    changes = [change for record in records for change in _list(record.get("changes"))]
    changes.sort(key=lambda item: str(item.get("changed_at") or ""), reverse=True)
    action_counts = {action: sum(record["decision"]["action"] == action for record in records) for action in ("patch", "hunt", "investigate", "monitor")}
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "run_change_count": len(new_events),
        "summary": {
            "total_records": len(records),
            "active_records": sum(record["state"]["activity"] == "active" for record in records),
            "qualified_hunts": sum(record["state"]["hunt"] == "qualified" for record in records),
            **action_counts,
        },
        "changes": changes[:MAX_GLOBAL_CHANGES],
        "records": records,
    }


def _load_previous() -> dict[str, Any] | None:
    try:
        payload = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def write_ledger(
    articles: Any, clusters: Any, hunts: Any, *, generated_at: str | None = None,
) -> dict[str, Any]:
    """Build and atomically publish the ledger without losing version history."""
    payload = build_ledger(
        articles, clusters, hunts, previous=_load_previous(), generated_at=generated_at,
    )
    write_json_atomic(LEDGER_PATH, payload)
    return payload
