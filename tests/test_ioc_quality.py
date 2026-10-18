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
