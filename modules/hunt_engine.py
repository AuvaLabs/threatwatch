"""Build evidence-gated hunt packages from correlated reporting."""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from modules.config import OUTPUT_DIR
from modules.ioc_quality import article_observables, publisher_name
from modules.utils import write_json_atomic

MIN_REPORTS = 2
MIN_PUBLISHERS = 2
QUALIFICATION_SCORE = 60
MAX_OBSERVABLES = 200
HUNTS_PATH = OUTPUT_DIR / "hunts.json"


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _cluster_list(value: Any) -> list[dict[str, Any]]:
    raw = value.get("clusters") if isinstance(value, dict) else value
    return [item for item in _list(raw) if isinstance(item, dict)]


def _article_id(article: dict[str, Any]) -> str:
    existing = str(article.get("hash") or "").strip()
    if existing:
        return existing
    raw = f"{article.get('title', '')}|{article.get('link', '')}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _techniques(articles: list[dict[str, Any]]) -> list[dict[str, str]]:
    found: dict[str, dict[str, str]] = {}
    for article in articles:
        for value in _list(article.get("attack_techniques")):
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


def _sources(articles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sources: list[dict[str, Any]] = []
    for article in articles:
        sources.append({
            "article_id": _article_id(article),
            "title": str(article.get("translated_title") or article.get("title") or "Untitled report"),
            "publisher": publisher_name(article),
            "published": article.get("published_at") or article.get("published") or article.get("timestamp"),
            "url": str(article.get("canonical_url") or article.get("link") or ""),
        })
    return sources


def _number(value: Any) -> float | None:
    try:
        number = float(value) if value is not None and not isinstance(value, bool) else None
    except (TypeError, ValueError):
        return None
    return number if number is not None and math.isfinite(number) else None


def _vulnerability(cluster: dict[str, Any], articles: list[dict[str, Any]]) -> dict[str, Any]:
    cves = {
        str(value).upper()
        for article in articles
        for value in _list(article.get("cve_ids"))
        if str(value).upper().startswith("CVE-")
    }
    entity_name = str(cluster.get("entity_name") or "").upper()
    if cluster.get("entity_type") == "cve" and entity_name.startswith("CVE-"):
        cves.add(entity_name)
    cvss = [value for article in articles if (value := _number(article.get("cvss_score"))) is not None]
    epss = [value for article in articles if (value := _number(article.get("epss_score"))) is not None]
    return {
        "cves": sorted(cves),
        "kev": any(article.get("kev_listed") or article.get("kevListed") for article in articles),
        "max_cvss": max(cvss) if cvss else None,
        "max_epss": max(epss) if epss else None,
    }


def _observables(
    articles: list[dict[str, Any]],
    enrichments: dict[tuple[str, str], list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    contexts: dict[tuple[str, str], list[str]] = defaultdict(list)
    structured: dict[tuple[str, str], bool] = defaultdict(bool)
    display_values: dict[tuple[str, str], str] = {}
    for article in articles:
        for observable in article_observables(article):
            key = (observable["type"], observable["value"].casefold())
            grouped[key].append(observable["source"])
            display_values[key] = observable["value"]
            if observable["context"]:
                contexts[key].append(observable["context"])
            structured[key] = structured[key] or observable["structured"]

    results: list[dict[str, Any]] = []
    for (ioc_type, normalized), evidence in grouped.items():
        unique_sources = {item["article_id"]: item for item in evidence}
        publishers = {str(item["publisher"]).casefold() for item in unique_sources.values()}
        provider_evidence = [
            {
                "provider": str(item.get("provider") or "unknown"),
                "status": str(item.get("status") or "unknown"),
                "confidence": int(item.get("confidence") or 0),
            }
            for item in enrichments.get((ioc_type, normalized), [])
            if isinstance(item, dict)
        ]
        provider_match = any(item["status"] == "matched" for item in provider_evidence)
        disposition = "confirmed" if structured[(ioc_type, normalized)] or len(publishers) >= 2 or provider_match else "reported"
        results.append({
            "type": ioc_type,
            "value": display_values[(ioc_type, normalized)],
            "disposition": disposition,
            "confidence": 90 if disposition == "confirmed" else 65,
            "contexts": list(dict.fromkeys(contexts[(ioc_type, normalized)]))[:3],
            "sources": list(unique_sources.values()),
            "enrichments": provider_evidence,
        })
    results.sort(key=lambda item: (item["disposition"] != "confirmed", item["type"], item["value"]))
    return results[:MAX_OBSERVABLES]


def _quoted(values: list[str]) -> str:
    return ", ".join(f'"{value.replace(chr(34), "")}"' for value in values)


def _queries(observables: list[dict[str, Any]]) -> list[dict[str, str]]:
    by_type: dict[str, list[str]] = defaultdict(list)
    for observable in observables:
        by_type[observable["type"]].append(observable["value"])
    queries: list[dict[str, str]] = []
    ips = by_type["ipv4"] + by_type["ipv6"]
    if ips:
        queries.append({
            "name": "Network connections to reported infrastructure",
            "language": "KQL",
            "telemetry": "Microsoft Defender DeviceNetworkEvents",
            "query": f"DeviceNetworkEvents | where RemoteIP in ({_quoted(ips)}) | project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort",
        })
    domains = by_type["domains"]
    if domains:
        queries.append({
            "name": "DNS requests for reported domains",
            "language": "KQL",
            "telemetry": "Microsoft Defender DeviceNetworkEvents",
            "query": f"DeviceNetworkEvents | where RemoteUrl in~ ({_quoted(domains)}) | project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl",
        })
    hashes = by_type["sha256"] + by_type["sha1"] + by_type["md5"]
    if hashes:
        queries.append({
            "name": "Files matching reported hashes",
            "language": "KQL",
            "telemetry": "Microsoft Defender DeviceFileEvents",
            "query": f"DeviceFileEvents | where SHA256 in~ ({_quoted(hashes)}) or SHA1 in~ ({_quoted(hashes)}) | project Timestamp, DeviceName, FileName, FolderPath, SHA256, SHA1",
        })
    return queries


def _telemetry(observables: list[dict[str, Any]], techniques: list[dict[str, str]]) -> list[str]:
    types = {item["type"] for item in observables}
    values: list[str] = []
    if types & {"ipv4", "ipv6", "domains", "urls"}:
        values.extend(["DNS query logs", "Proxy or secure web gateway logs", "Endpoint network connections"])
    if types & {"sha256", "sha1", "md5"}:
        values.append("Endpoint file creation and execution telemetry")
    if techniques:
        values.append("Identity, process, and endpoint telemetry mapped to the observed ATT&CK behaviors")
    return list(dict.fromkeys(values))


def _qualification(
    report_count: int,
    source_count: int,
    observables: list[dict[str, Any]],
    techniques: list[dict[str, str]],
) -> tuple[str, int, list[str], list[str]]:
    provider_match = any(
        evidence.get("status") == "matched"
        for observable in observables
        for evidence in observable.get("enrichments", [])
    )
    actionable = [
        item for item in observables
        if item["disposition"] == "confirmed" or item["type"] in {"ipv4", "ipv6", "sha256", "sha1", "md5"}
    ]
    score = min(report_count, 4) * 5 + min(source_count, 4) * 10
    score += 25 if actionable else 0
    score += 20 if techniques else 0
    score += 20 if provider_match else 0
    score = min(score, 100)
    limitations: list[str] = []
    if (report_count < MIN_REPORTS or source_count < MIN_PUBLISHERS) and not provider_match:
        limitations.append("Needs two independent publishers")
    if not actionable:
        limitations.append("No validated actionable observables")
    if not techniques:
        limitations.append("No ATT&CK behavior mapped from source evidence")
    qualified = not limitations and score >= QUALIFICATION_SCORE
    reasons = [
        (
            "Corroborated by an authoritative structured indicator provider"
            if provider_match and source_count < MIN_PUBLISHERS
            else f"Corroborated by {source_count} independent publishers across {report_count} reports"
        ),
        f"Includes {len(actionable)} actionable observable{'s' if len(actionable) != 1 else ''}",
        f"Maps to {len(techniques)} ATT&CK technique{'s' if len(techniques) != 1 else ''}",
    ]
    return ("qualified" if qualified else "lead"), score, reasons, limitations


def _markdown(hunt: dict[str, Any]) -> str:
    lines = [
        f"# ThreatWatch Hunt Package: {hunt['title']}", "",
        f"Status: {hunt['status'].title()} | Readiness: {hunt['readiness_score']}/100",
        "", "## Hypothesis", hunt["hypothesis"], "", "## Why this package exists",
        *[f"- {reason}" for reason in hunt["why_qualified"]],
    ]
    if hunt["observables"]:
        lines.extend(["", "## Observables"])
        lines.extend(
            f"- `{item['value']}` ({item['type']}, {item['disposition']}, {len(item['sources'])} report(s))"
            for item in hunt["observables"]
        )
    if hunt["techniques"]:
        lines.extend(["", "## ATT&CK behaviors"])
        lines.extend(f"- {item['id']} {item['name']}".rstrip() for item in hunt["techniques"])
    vulnerability = hunt["vulnerability"]
    if vulnerability["cves"]:
        lines.extend(["", "## Vulnerability context", f"- CVEs: {', '.join(vulnerability['cves'])}"])
        if vulnerability["kev"]:
            lines.append("- CISA KEV listed: yes")
        if vulnerability["max_cvss"] is not None:
            lines.append(f"- Maximum reported CVSS: {vulnerability['max_cvss']:g}")
        if vulnerability["max_epss"] is not None:
            lines.append(f"- Maximum reported EPSS: {vulnerability['max_epss'] * 100:.1f}%")
    if hunt["queries"]:
        lines.extend(["", "## Starter queries"])
        for query in hunt["queries"]:
            lines.extend([f"### {query['name']}", f"Telemetry: {query['telemetry']}", "```", query["query"], "```"])
    lines.extend(["", "## Sources"])
    lines.extend(
        f"- [{source['title']}]({source['url']}) - {source['publisher']}" if source["url"] else f"- {source['title']} - {source['publisher']}"
        for source in hunt["sources"]
    )
    if hunt["limitations"]:
        lines.extend(["", "## Limitations", *[f"- {value}" for value in hunt["limitations"]]])
    lines.extend(["", "Validate scope, syntax, and observables against local telemetry before production use."])
    return "\n".join(lines)


def _hunt(
    cluster: dict[str, Any],
    articles: list[dict[str, Any]],
    enrichments: dict[tuple[str, str], list[dict[str, Any]]],
) -> dict[str, Any]:
    entity_type = str(cluster.get("entity_type") or "topic")
    entity_name = str(cluster.get("entity_name") or "Unresolved threat")
    sources = _sources(articles)
    source_count = len({source["publisher"].casefold() for source in sources})
    observables = _observables(articles, enrichments)
    techniques = _techniques(articles)
    vulnerability = _vulnerability(cluster, articles)
    status, score, reasons, limitations = _qualification(len(articles), source_count, observables, techniques)
    risk_reasons = []
    if vulnerability["kev"]:
        risk_reasons.append("CISA KEV marks the associated vulnerability as exploited in the wild")
    if vulnerability["max_epss"] is not None:
        risk_reasons.append(f"Highest reported EPSS is {vulnerability['max_epss'] * 100:.1f}%")
    digest = hashlib.sha256(f"{entity_type}:{entity_name}".encode("utf-8")).hexdigest()[:16]
    hunt = {
        "id": f"hunt-{digest}",
        "entity_type": entity_type,
        "entity_name": entity_name,
        "title": f"Investigate activity associated with {entity_name}",
        "status": status,
        "readiness_score": score,
        "confidence": "high" if status == "qualified" else "developing",
        "summary": f"Correlated reporting about {entity_name} across {len(articles)} source reports.",
        "hypothesis": f"Systems in the environment may show observables or behaviors associated with {entity_name}.",
        "why_qualified": [*reasons, *risk_reasons],
        "report_count": len(articles),
        "source_count": source_count,
        "first_seen": cluster.get("first_observed") or cluster.get("first_seen"),
        "sources": sources,
        "observables": observables,
        "techniques": techniques,
        "vulnerability": vulnerability,
        "telemetry": _telemetry(observables, techniques),
        "queries": _queries(observables),
        "false_positives": [
            "Shared hosting, security scanners, and legitimate administration may contact reported infrastructure.",
            "Confirm process, user, device, and time context before escalation.",
        ],
        "triage_steps": [
            "Search the listed telemetry for the package observables and behaviors.",
            "Correlate matches with process lineage, identity activity, and adjacent network connections.",
            "Preserve matching evidence and escalate only after local validation.",
        ],
        "limitations": limitations,
    }
    return {**hunt, "markdown": _markdown(hunt)}


def build_hunts(
    articles: Any,
    clusters: Any,
    enrichments: dict[tuple[str, str], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Build qualified packages and developing leads from current cluster evidence."""
    article_list = [item for item in _list(articles) if isinstance(item, dict)]
    by_id = {_article_id(article): article for article in article_list}
    hunts: list[dict[str, Any]] = []
    for cluster in _cluster_list(clusters):
        if str(cluster.get("entity_type") or "") not in {"cve", "actor"}:
            continue
        members = [by_id[str(value)] for value in _list(cluster.get("article_hashes")) if str(value) in by_id]
        if not members:
            continue
        hunts.append(_hunt(cluster, members, enrichments or {}))
    hunts.sort(key=lambda item: (item["status"] != "qualified", -item["readiness_score"], item["title"]))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "qualified_count": sum(item["status"] == "qualified" for item in hunts),
        "lead_count": sum(item["status"] == "lead" for item in hunts),
        "hunts": hunts,
    }


def write_hunts(
    articles: Any,
    clusters: Any,
    enrichments: dict[tuple[str, str], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Build and atomically publish the current hunt desk artifact."""
    payload = build_hunts(articles, clusters, enrichments)
    write_json_atomic(HUNTS_PATH, payload, indent=2)
    return payload
