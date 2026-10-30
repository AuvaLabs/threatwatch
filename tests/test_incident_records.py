"""Regression tests for evidence-linked, victim-centred incident records."""

from datetime import datetime, timezone

import modules.incident_records as ir


NOW = datetime(2026, 10, 30, 6, tzinfo=timezone.utc)


def _article(
    article_id: str,
    title: str,
    publisher: str,
    published: str,
    **extra,
):
    return {
        "hash": article_id,
        "title": title,
        "summary": extra.pop("summary", "Unauthorized transfers disrupted exchange operations."),
        "source_name": publisher,
        "link": f"https://{publisher.casefold().replace(' ', '')}.example/{article_id}",
        "published": published,
        "category": "Cryptocurrency/Blockchain Theft",
        "is_cyber_attack": True,
        **extra,
    }


def _binance_fixture():
    return [
        _article(
            "binance-1",
            "Binance investigates suspicious transfers after exchange compromise",
            "Reuters",
            "2026-10-29T08:00:00Z",
            victim_organizations=["Binance"],
            attack_techniques=[{"technique_id": "T1078", "technique_name": "Valid Accounts"}],
            victim_sectors=["Finance"],
            tactical_analysis={
                "summary": "Signing credentials may have been compromised.",
                "ttps": ["Unauthorized hot-wallet transfers"],
                "impact": ["Withdrawals were temporarily halted"],
                "confidence": "medium",
            },
        ),
        _article(
            "binance-2",
            "Binance probes potential multi-billion crypto theft",
            "BBC",
            "2026-10-29T09:00:00Z",
            victim_organizations=["Binance"],
            victim_sectors=["Finance"],
        ),
        _article(
            "binance-3",
            "Binance probes potential multi-billion crypto theft",
            "Syndicated Daily",
            "2026-10-29T09:05:00Z",
            victim_organizations=["Binance"],
            victim_sectors=["Finance"],
        ),
    ]


def test_builds_one_corroborated_non_cve_incident_with_source_bound_claims():
    payload = ir.build_incident_records(_binance_fixture(), generated_at=NOW)

    assert payload["summary"]["total_records"] == 1
    record = payload["records"][0]
    assert record["organization"] == "Binance"
    assert record["event_type"] == "intrusion"
    assert record["state"] == "corroborated"
    assert record["source_count"] == 3
    assert record["independent_source_count"] == 2
    assert record["score"] >= 60
    assert record["priority"] == "high"
    source_ids = {source["article_id"] for source in record["sources"]}
    assert record["claims"]
    assert all(set(claim["source_ids"]) <= source_ids for claim in record["claims"])
    assert any(claim["state"] == "assessed" for claim in record["claims"])
    assert "full_content" not in str(payload)


def test_same_organization_with_unrelated_events_does_not_merge():
    articles = [
        _article(
            "acme-breach",
            "Acme confirms customer data breach",
            "Wire One",
            "2026-10-20T08:00:00Z",
            victim_organizations=["Acme"],
            category="Data Breach",
        ),
        _article(
            "acme-outage",
            "Acme restores service after ransomware outage",
            "Wire Two",
            "2026-10-29T08:00:00Z",
            victim_organizations=["Acme"],
            category="Ransomware",
        ),
    ]

    payload = ir.build_incident_records(articles, generated_at=NOW)

    assert len(payload["records"]) == 2
    assert {record["event_type"] for record in payload["records"]} == {"data_breach", "ransomware"}
    assert all(record["source_count"] == 1 for record in payload["records"])


def test_same_org_same_event_window_still_requires_second_signal():
    articles = [
        _article(
            "acme-cloud",
            "Acme hit by cloud account intrusion through phishing",
            "Wire One",
            "2026-10-29T08:00:00Z",
            victim_organizations=["Acme"],
        ),
        _article(
            "acme-office",
            "Acme suffers badge system intrusion at headquarters",
            "Wire Two",
            "2026-10-29T09:00:00Z",
            victim_organizations=["Acme"],
        ),
    ]
    for article in articles:
        article.pop("victim_organizations")

    payload = ir.build_incident_records(articles, generated_at=NOW)

    assert len(payload["records"]) == 2
    assert all(record["state"] == "developing" for record in payload["records"])
    assert len({record["id"] for record in payload["records"]}) == 2


def test_generic_title_words_do_not_become_organizations():
    article = _article(
        "generic",
        "Massive data breach exposes customer records",
        "Wire",
        "2026-10-29T08:00:00Z",
    )

    assert ir.build_incident_records([article], generated_at=NOW)["records"] == []


def test_compatible_intrusion_and_data_loss_reporting_merge_into_one_record():
    articles = [
        _article(
            "acme-intrusion",
            "Acme hit by wallet compromise and unauthorized transfers",
            "Wire One",
            "2026-10-29T08:00:00Z",
            victim_organizations=["Acme"],
            category="General Cyber Threat",
        ),
        _article(
            "acme-breach",
            "Acme data breach follows wallet compromise and unauthorized transfers",
            "Wire Two",
            "2026-10-29T09:00:00Z",
            victim_organizations=["Acme"],
            category="Data Breach",
        ),
    ]

    payload = ir.build_incident_records(articles, generated_at=NOW)

    assert len(payload["records"]) == 1
    assert payload["records"][0]["event_type"] == "data_breach"
    assert payload["records"][0]["source_count"] == 2


def test_actor_descriptors_and_reporting_verbs_are_not_victim_names():
    articles = [
        _article("actor", "China-Linked Hackers Exploit Server Flaw", "Wire", "2026-10-29T08:00:00Z"),
        _article("reporter", "Tokyo Police Investigate Cyberattack on Acme", "Wire", "2026-10-29T09:00:00Z"),
    ]

    records = ir.build_incident_records(articles, generated_at=NOW)["records"]

    assert all(record["organization"] not in {"China-Linked", "Tokyo Police Investigate"} for record in records)


def test_corroborated_components_with_overlap_merge_into_one_event():
    articles = [
        _article("one", "Acme hit by exchange wallet theft", "Wire One", "2026-10-29T08:00:00Z"),
        _article("two", "Acme suffers exchange wallet compromise", "Wire Two", "2026-10-29T09:00:00Z"),
        _article("three", "Acme hit by customer wallet losses", "Wire Three", "2026-10-29T10:00:00Z"),
        _article("four", "Acme suffers customer wallet fraud", "Wire Four", "2026-10-29T11:00:00Z"),
    ]

    payload = ir.build_incident_records(articles, generated_at=NOW)

    assert len(payload["records"]) == 1
    assert payload["records"][0]["source_count"] == 4


def test_geographic_alias_is_not_propagated_from_unrelated_trend_coverage():
    articles = [
        _article("direct", "Japan hit by nationwide service outage", "Wire One", "2026-10-29T08:00:00Z"),
        _article("trend", "Japan firms prepare for waves of cyberattacks", "Wire Two", "2026-10-29T09:00:00Z"),
    ]

    records = ir.build_incident_records(articles, generated_at=NOW)["records"]

    japan = [record for record in records if record["organization"] == "Japan"]
    assert len(japan) == 1
    assert japan[0]["source_count"] == 1


def test_extracts_title_prefix_org_and_does_not_treat_security_breach_as_data_loss():
    article = _article(
        "binance-title-only",
        "Binance Suffers Security Breach Affecting Wallet Operations",
        "Wire",
        "2026-10-29T08:00:00Z",
        category="Data Breach",
    )

    payload = ir.build_incident_records([article], generated_at=NOW)

    assert payload["records"][0]["organization"] == "Binance"
    assert payload["records"][0]["event_type"] == "intrusion"


def test_single_source_candidate_remains_developing_and_below_today_threshold():
    payload = ir.build_incident_records(_binance_fixture()[:1], generated_at=NOW)

    assert payload["summary"]["total_records"] == 1
    record = payload["records"][0]
    assert record["state"] == "developing"
    assert record["independent_source_count"] == 1
    assert record["score"] < ir.TODAY_THRESHOLD


def test_invalid_source_references_are_removed():
    articles = _binance_fixture()[:2]
    articles[0]["incident_claims"] = [
        {
            "statement": "An unsupported claim",
            "state": "confirmed",
            "confidence": "high",
            "source_ids": ["missing-source"],
        }
    ]

    payload = ir.build_incident_records(articles, generated_at=NOW)

    statements = {claim["statement"] for claim in payload["records"][0]["claims"]}
    assert "An unsupported claim" not in statements


def test_confirmed_claim_requires_explicit_authoritative_evidence():
    articles = _binance_fixture()[:2]
    articles[0]["incident_claims"] = [{
        "statement": "The signing key was compromised",
        "state": "confirmed",
        "confidence": "high",
    }]

    untrusted = ir.build_incident_records(articles, generated_at=NOW)
    claim = next(
        item for item in untrusted["records"][0]["claims"]
        if item["statement"] == "The signing key was compromised"
    )
    assert claim["state"] == "reported"

    articles[0]["authoritative_source"] = True
    trusted = ir.build_incident_records(articles, generated_at=NOW)
    claim = next(
        item for item in trusted["records"][0]["claims"]
        if item["statement"] == "The signing key was compromised"
    )
    assert claim["state"] == "confirmed"


def test_conflicting_structured_claims_are_preserved_as_disputed():
    articles = _binance_fixture()[:2]
    articles[0]["incident_claims"] = [{
        "subject": "initial_access",
        "statement": "Initial access used a compromised signing key",
        "state": "reported",
        "confidence": "medium",
    }]
    articles[1]["incident_claims"] = [{
        "subject": "initial_access",
        "statement": "Initial access used a vulnerable hot-wallet service",
        "state": "reported",
        "confidence": "medium",
    }]

    payload = ir.build_incident_records(articles, generated_at=NOW)
    claims = [
        claim for claim in payload["records"][0]["claims"]
        if claim.get("subject") == "initial_access"
    ]

    assert len(claims) == 2
    assert {claim["state"] for claim in claims} == {"disputed"}


def test_previous_matching_record_keeps_id_and_versions_material_change():
    initial = ir.build_incident_records(_binance_fixture()[:2], generated_at=NOW)
    updated_articles = _binance_fixture()
    updated_articles[0]["iocs"] = {"ipv4": ["192.0.2.4"]}

    updated = ir.build_incident_records(
        updated_articles,
        previous=initial,
        generated_at=datetime(2026, 10, 30, 8, tzinfo=timezone.utc),
    )

    before = initial["records"][0]
    after = updated["records"][0]
    assert after["id"] == before["id"]
    assert after["version"] == before["version"] + 1
    assert after["changes"][0]["field"] in {"observable_count", "source_count"}


def test_load_returns_empty_contract_for_missing_or_corrupt_artifact(tmp_path, monkeypatch):
    path = tmp_path / "incidents-v2.json"
    monkeypatch.setattr(ir, "INCIDENTS_PATH", path)
    assert ir.load_incident_records()["records"] == []
    path.write_text("{broken", encoding="utf-8")
    assert ir.load_incident_records()["records"] == []
