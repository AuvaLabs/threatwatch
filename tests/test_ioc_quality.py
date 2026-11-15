"""Boundary tests for article observable validation."""

from modules.ioc_quality import article_observables


def test_malformed_url_ioc_is_rejected_without_aborting_article():
    article = {
        "hash": "malformed-url",
        "title": "Malware callback infrastructure",
        "summary": "The malware callback used https://oauth2:[email during execution.",
        "source_name": "Example Research",
        "link": "https://research.example/report",
        "iocs": {
            "urls": ["https://oauth2:[email"],
            "sha256": ["a" * 64],
        },
    }

    observables = article_observables(article)

    assert [item["value"] for item in observables] == ["a" * 64]


def test_structured_provider_ioc_is_source_bound_and_preserved():
    article = {
        "hash": "threatfox-1",
        "title": "ThreatFox Emotet infrastructure",
        "summary": "ThreatFox reports malicious command and control infrastructure.",
        "source_name": "ThreatFox",
        "link": "https://threatfox.abuse.ch/browse/malware/win.emotet/",
        "darkweb_source": "threatfox",
        "structured_iocs": [{
            "type": "domains",
            "value": "emotet-c2.example",
            "provider": "threatfox",
        }],
    }

    observables = article_observables(article)

    assert observables[0]["value"] == "emotet-c2.example"
    assert observables[0]["structured"] is True
    assert observables[0]["provider"] == "threatfox"


def test_untrusted_structured_provider_cannot_self_attest():
    article = {
        "hash": "forged-1",
        "title": "Untrusted report",
        "summary": "Claims a malicious domain.",
        "link": "https://publisher.example/report",
        "darkweb_source": "untrusted",
        "structured_iocs": [{
            "type": "domains",
            "value": "forged-c2.example",
            "provider": "untrusted",
        }],
    }

    assert article_observables(article) == []
