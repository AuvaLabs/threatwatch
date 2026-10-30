"""Live-corpus smoke harness tests."""

import json

from scripts import rebuild_analyst_artifacts as rebuild


def test_smoke_build_handles_malformed_url_and_publishes_valid_shapes(tmp_path, monkeypatch):
    output = tmp_path / "output"
    output.mkdir()
    article = {
        "hash": "article-1",
        "title": "Actor malware callback report",
        "summary": "Malware callback https://oauth2:[email was reported.",
        "source_name": "Research Lab",
        "link": "https://example.test/report",
        "iocs": {"urls": ["https://oauth2:[email"]},
    }
    (output / "daily_latest.json").write_text(json.dumps([article]))
    (output / "clusters.json").write_text(json.dumps({
        "clusters": [{
            "id": "cluster-1",
            "entity_type": "actor",
            "entity_name": "Example Actor",
            "article_hashes": ["article-1"],
        }],
    }))
    monkeypatch.setattr(rebuild, "load_articles_from_db", lambda: [])

    incidents, hunts, ledger = rebuild.publish_artifacts(output)

    assert isinstance(incidents["records"], list)
    assert isinstance(hunts["hunts"], list)
    assert isinstance(ledger["records"], list)
    assert (output / "hunts.json").exists()
    assert (output / "incidents-v2.json").exists()
    assert (output / "threat_ledger.json").exists()
    assert (tmp_path / "state" / "operational_artifact_health.json").exists()
