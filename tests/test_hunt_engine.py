"""Qualification and evidence tests for correlated hunt packages."""

from modules.hunt_engine import build_hunts


def _article(
    article_hash: str,
    source: str,
    *,
    iocs: dict | None = None,
    techniques: list[dict] | None = None,
    title: str = "CVE-2026-1000 exploitation observed",
) -> dict:
    return {
        "hash": article_hash,
        "title": title,
        "summary": "Researchers observed command and control at 185.220.101.50.",
        "link": f"https://{source.lower().replace(' ', '')}.example/report",
        "source_name": source,
        "published": "2026-10-08T00:00:00+00:00",
        "iocs": iocs or {},
        "attack_techniques": techniques or [],
    }


def _cluster(*hashes: str, entity_type: str = "cve", entity_name: str = "CVE-2026-1000") -> dict:
    return {
        "clusters": [{
            "entity_type": entity_type,
            "entity_name": entity_name,
            "article_hashes": list(hashes),
            "article_count": len(hashes),
            "first_seen": "2026-10-08T00:00:00+00:00",
        }]
    }


class TestHuntQualification:
    def test_multi_source_cluster_with_validated_evidence_qualifies(self):
        articles = [
            _article(
                "a", "Research Lab",
                iocs={"ipv4": ["185.220.101.50"]},
                techniques=[{
                    "technique_id": "T1190",
                    "technique_name": "Exploit Public-Facing Application",
                    "tactic": "Initial Access",
                }],
            ),
            _article("b", "Incident Response Co", iocs={"ipv4": ["185.220.101.50"]}),
        ]
        articles[0].update({"cve_ids": ["CVE-2026-1000"], "kev_listed": True, "cvss_score": 9.8, "epss_score": 0.72})

        payload = build_hunts(articles, _cluster("a", "b"))

        hunt = payload["hunts"][0]
        assert hunt["status"] == "qualified"
        assert hunt["source_count"] == 2
        assert hunt["report_count"] == 2
        assert hunt["techniques"][0]["id"] == "T1190"
        assert hunt["observables"][0]["disposition"] == "confirmed"
        assert hunt["vulnerability"] == {
            "cves": ["CVE-2026-1000"], "kev": True, "max_cvss": 9.8, "max_epss": 0.72,
        }
        assert {source["article_id"] for source in hunt["observables"][0]["sources"]} == {"a", "b"}
        assert "DeviceNetworkEvents" in hunt["queries"][0]["query"]
        assert "## Sources" in hunt["markdown"]

    def test_single_report_never_qualifies(self):
        articles = [_article("a", "Research Lab", iocs={"ipv4": ["185.220.101.50"]})]

        hunt = build_hunts(articles, _cluster("a"))["hunts"][0]

        assert hunt["status"] == "lead"
        assert "Needs two independent publishers" in hunt["limitations"]

    def test_authoritative_provider_can_corroborate_one_technical_report(self):
        articles = [_article(
            "a", "Research Lab",
            iocs={"ipv4": ["185.220.101.50"]},
            techniques=[{"technique_id": "T1071", "technique_name": "Application Layer Protocol"}],
        )]
        enrichment = {
            ("ipv4", "185.220.101.50"): [{
                "provider": "threatfox", "status": "matched", "confidence": 95,
            }],
        }

        hunt = build_hunts(articles, _cluster("a"), enrichment)["hunts"][0]

        assert hunt["status"] == "qualified"
        assert hunt["observables"][0]["enrichments"][0]["provider"] == "threatfox"

    def test_publisher_domains_do_not_create_actor_hunt(self):
        articles = [
            _article(
                "a", "Bing",
                iocs={"domains": ["asahi.com"]},
                title="Qilin ransomware claims victim - Asahi",
            ),
            _article(
                "b", "Google",
                iocs={"domains": ["finance.biggo.com"]},
                title="Qilin ransomware coverage - BigGo Finance",
            ),
        ]

        hunt = build_hunts(
            articles,
            _cluster("a", "b", entity_type="actor", entity_name="Qilin"),
        )["hunts"][0]

        assert hunt["status"] == "lead"
        assert hunt["observables"] == []
        assert "No validated actionable observables" in hunt["limitations"]

    def test_null_and_unknown_shapes_are_safe(self):
        payload = build_hunts(
            [{"hash": "a", "title": None, "source_name": None, "iocs": None}],
            {"clusters": [{"entity_type": "actor", "entity_name": None, "article_hashes": ["a"]}]},
        )

        assert payload["hunts"][0]["status"] == "lead"
        assert payload["hunts"][0]["observables"] == []
