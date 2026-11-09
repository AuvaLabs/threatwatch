"""Build a bounded machine-readable graph from an incident record."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any


MAX_GRAPH_SOURCES = 100
MAX_GRAPH_CLAIMS = 100


def _claim_id(claim: dict[str, Any]) -> str:
    identity = f"{claim.get('subject', '')}|{claim.get('statement', '')}"
    return f"claim:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:20]}"


def build_incident_evidence_graph(
    record: dict[str, Any], generated_at: str | None = None,
) -> dict[str, Any]:
    """Return incident, source, and claim nodes with explicit support edges."""
    incident_id = str(record.get("id") or "incident-unknown")
    sources = [item for item in record.get("sources", []) if isinstance(item, dict)][:MAX_GRAPH_SOURCES]
    claims = [item for item in record.get("claims", []) if isinstance(item, dict)][:MAX_GRAPH_CLAIMS]
    source_ids = {str(source.get("article_id")) for source in sources if source.get("article_id")}
    unsupported_references = sum(
        str(source_id) not in source_ids
        for claim in claims
        for source_id in claim.get("source_ids", [])
    )
    nodes = [{
        "id": incident_id,
        "type": "incident",
        "label": str(record.get("title") or record.get("organization") or incident_id),
        "state": record.get("state"),
    }]
    nodes.extend(_source_node(source) for source in sources if source.get("article_id"))
    nodes.extend(_claim_node(claim) for claim in claims)
    edges: list[dict[str, str]] = []
    for claim in claims:
        claim_id = _claim_id(claim)
        edges.append({"from": claim_id, "to": incident_id, "relationship": "describes"})
        edges.extend(
            {"from": f"source:{source_id}", "to": claim_id, "relationship": "supports"}
            for source_id in claim.get("source_ids", [])
            if str(source_id) in source_ids
        )
    return {
        "schema_version": 1,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "incident_id": incident_id,
        "assessment": record.get("evidence_assessment") or {},
        "summary": {
            "nodes": len(nodes), "edges": len(edges),
            "sources": len(sources), "claims": len(claims),
            "unsupported_references": unsupported_references,
        },
        "nodes": nodes,
        "edges": edges,
    }


def _source_node(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"source:{source['article_id']}",
        "type": "source",
        "label": str(source.get("title") or source.get("publisher") or "Source"),
        "publisher": source.get("publisher"),
        "role": source.get("role") or "reporting",
        "source_family": source.get("source_family"),
        "published": source.get("published"),
        "url": source.get("url"),
    }


def _claim_node(claim: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _claim_id(claim),
        "type": "claim",
        "label": str(claim.get("statement") or "Claim"),
        "subject": claim.get("subject"),
        "state": claim.get("state"),
        "confidence": claim.get("confidence"),
        "evidence": claim.get("evidence") or {},
    }
