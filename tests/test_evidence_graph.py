from modules.evidence_graph import build_incident_evidence_graph


def test_builds_bounded_graph_with_source_to_claim_edges():
    record = {
        "id": "incident-abc123",
        "title": "Acme intrusion",
        "organization": "Acme",
        "evidence_assessment": {"grade": "corroborated"},
        "sources": [
            {"article_id": "article-1", "title": "Report", "publisher": "CERT", "role": "authoritative"},
        ],
        "claims": [
            {"subject": "event", "statement": "Acme reported an intrusion.", "state": "confirmed", "confidence": "high", "source_ids": ["article-1"]},
        ],
    }

    graph = build_incident_evidence_graph(record, generated_at="2026-11-09T10:00:00Z")

    assert graph["incident_id"] == "incident-abc123"
    assert graph["summary"] == {
        "nodes": 3, "edges": 2, "sources": 1, "claims": 1,
        "unsupported_references": 0,
    }
    assert {node["type"] for node in graph["nodes"]} == {"incident", "source", "claim"}
    supports = next(edge for edge in graph["edges"] if edge["relationship"] == "supports")
    assert supports["from"] == "source:article-1"
    assert supports["to"].startswith("claim:")


def test_ignores_claim_references_not_present_in_sources():
    record = {
        "id": "incident-abc123",
        "sources": [],
        "claims": [{"statement": "Unsupported", "source_ids": ["missing"]}],
    }

    graph = build_incident_evidence_graph(record)

    assert all(edge["relationship"] != "supports" for edge in graph["edges"])
    assert graph["summary"]["sources"] == 0
    assert graph["summary"]["unsupported_references"] == 1
