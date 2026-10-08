"""Living threat record and change-ledger tests."""

from pathlib import Path

from modules.threat_ledger import build_ledger, write_ledger


NOW = "2026-10-08T10:00:00+00:00"
LATER = "2026-10-08T11:00:00+00:00"


def _article(article_id: str, publisher: str, **overrides) -> dict:
    article = {
        "hash": article_id,
        "title": "CVE-2026-1000 exploitation report",
        "summary": "Researchers published technical details for the vulnerability.",
        "source_name": publisher,
        "source": f"https://{publisher.casefold().replace(' ', '')}.example/feed",
        "link": f"https://{publisher.casefold().replace(' ', '')}.example/report",
        "published": "2026-10-08T08:00:00+00:00",
        "cve_ids": ["CVE-2026-1000"],
        "attack_techniques": [{
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
        }],
    }
    return {**article, **overrides}


def _clusters(*article_ids: str, entity_type: str = "cve", entity_name: str = "CVE-2026-1000") -> dict:
    return {
        "generated_at": NOW,
        "clusters": [{
            "entity_type": entity_type,
            "entity_name": entity_name,
            "article_hashes": list(article_ids),
            "first_seen": "2026-10-08T08:00:00+00:00",
            "synthesis": "Independent reporting describes active exploitation.",
        }],
    }


def _hunts(status: str = "qualified", entity_type: str = "cve", entity_name: str = "CVE-2026-1000") -> dict:
    return {
        "generated_at": NOW,
        "hunts": [{
            "id": "hunt-abc123",
            "entity_type": entity_type,
            "entity_name": entity_name,
            "status": status,
            "readiness_score": 85 if status == "qualified" else 40,
            "observables": [{"disposition": "confirmed"}],
            "techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
        }],
    }


class TestThreatLedger:
    def test_builds_source_linked_cve_record_from_all_reports(self):
        articles = [
            _article(
                "a", "NVD",
                source="nvd:cve",
                affected_products=["Acme Gateway"],
                cvss_score=9.8,
                epss_score=0.72,
            ),
            _article(
                "b", "Incident Lab",
                kev_listed=True,
                kev_entries=[{
                    "vendor": "Acme",
                    "product": "Gateway",
                    "required_action": "Apply updates per vendor instructions.",
                    "due_date": "2026-10-15",
                }],
            ),
        ]

        payload = build_ledger(articles, _clusters("a", "b"), _hunts(), generated_at=NOW)

        record = payload["records"][0]
        assert record["entity_name"] == "CVE-2026-1000"
        assert record["decision"]["action"] == "patch"
        assert record["decision"]["urgency"] == "critical"
        assert record["state"]["exploitation"] == "confirmed"
        assert record["state"]["evidence"] == "corroborated"
        assert record["state"]["hunt"] == "qualified"
        assert record["source_count"] == 2
        assert {source["article_id"] for source in record["sources"]} == {"a", "b"}
        assert record["affected_products"] == ["Acme Gateway"]
        assert record["vulnerability"]["max_cvss"] == 9.8
        assert record["vulnerability"]["max_epss"] == 0.72
        assert record["remediation"]["required_action"] == "Apply updates per vendor instructions."
        assert payload["summary"]["patch"] == 1
        assert payload["changes"][0]["kind"] == "tracking_started"
        assert payload["changes"][0]["summary"] == "ThreatWatch began tracking CVE-2026-1000."

    def test_keeps_single_source_claims_explicitly_unverified(self):
        payload = build_ledger(
            [_article("a", "Research Blog", title="CVE-2026-1000 reportedly exploited in the wild")],
            {"clusters": []},
            {"hunts": []},
            generated_at=NOW,
        )

        record = payload["records"][0]
        assert record["state"]["exploitation"] == "reported"
        assert record["state"]["evidence"] == "single_source"
        assert record["decision"]["action"] == "investigate"
        assert "Needs independent corroboration" in record["open_questions"]

    def test_qualified_actor_hunt_becomes_hunt_decision(self):
        articles = [
            _article("a", "Lab One", title="Qilin campaign infrastructure", cve_ids=[]),
            _article("b", "Lab Two", title="Qilin campaign activity", cve_ids=[]),
        ]
        payload = build_ledger(
            articles,
            _clusters("a", "b", entity_type="actor", entity_name="Qilin"),
            _hunts(entity_type="actor", entity_name="Qilin"),
            generated_at=NOW,
        )

        record = payload["records"][0]
        assert record["entity_type"] == "actor"
        assert record["decision"]["action"] == "hunt"
        assert record["decision"]["urgency"] == "high"

    def test_unchanged_record_preserves_version_and_history(self):
        articles = [_article("a", "Lab One"), _article("b", "Lab Two")]
        first = build_ledger(articles, _clusters("a", "b"), _hunts("lead"), generated_at=NOW)

        second = build_ledger(
            articles,
            _clusters("a", "b"),
            _hunts("lead"),
            previous=first,
            generated_at=LATER,
        )

        assert second["records"][0]["version"] == 1
        assert second["records"][0]["last_changed"] == NOW
        assert second["records"][0]["changes"] == first["records"][0]["changes"]
        assert second["run_change_count"] == 0

    def test_normalizes_legacy_tracking_started_summary(self):
        articles = [_article("a", "Lab One")]
        first = build_ledger(articles, {"clusters": []}, {"hunts": []}, generated_at=NOW)
        first["records"][0]["changes"][0]["summary"] = "CVE-2026-1000 changed: record is now active."

        second = build_ledger(
            articles,
            {"clusters": []},
            {"hunts": []},
            previous=first,
            generated_at=LATER,
        )

        assert second["records"][0]["changes"][0]["summary"] == "ThreatWatch began tracking CVE-2026-1000."

    def test_meaningful_state_change_increments_version(self):
        articles = [_article("a", "Lab One"), _article("b", "Lab Two")]
        first = build_ledger(articles, _clusters("a", "b"), _hunts("lead"), generated_at=NOW)
        changed_articles = [{**article, "kev_listed": True} for article in articles]

        second = build_ledger(
            changed_articles,
            _clusters("a", "b"),
            _hunts("lead"),
            previous=first,
            generated_at=LATER,
        )

        record = second["records"][0]
        assert record["version"] == 2
        assert record["last_changed"] == LATER
        assert second["run_change_count"] >= 1
        assert any(change["field"] == "exploitation" for change in record["changes"])
        assert any("confirmed exploitation" in change["summary"].casefold() for change in record["changes"])

    def test_null_and_unknown_shapes_are_safe(self):
        payload = build_ledger(
            [{"hash": "a", "title": None, "summary": None, "cve_ids": [None, "bad"]}],
            {"clusters": [{"entity_type": "actor", "entity_name": None, "article_hashes": ["a"]}]},
            None,
            generated_at=NOW,
        )

        assert payload["records"] == []
        assert payload["summary"]["total_records"] == 0

    def test_write_ledger_preserves_previous_versions(self, tmp_path: Path, monkeypatch):
        path = tmp_path / "ledger.json"
        monkeypatch.setattr("modules.threat_ledger.LEDGER_PATH", path)
        articles = [_article("a", "Lab One")]

        first = write_ledger(articles, {"clusters": []}, {"hunts": []}, generated_at=NOW)
        second = write_ledger(articles, {"clusters": []}, {"hunts": []}, generated_at=LATER)

        assert path.exists()
        assert first["records"][0]["version"] == 1
        assert second["records"][0]["version"] == 1
        assert second["run_change_count"] == 0
