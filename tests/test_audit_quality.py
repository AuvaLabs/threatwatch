"""Regression tests for the corpus quality audit."""

from scripts.audit_quality import audit_classification


def _article(title: str, category: str) -> dict:
    return {
        "title": title,
        "category": category,
        "confidence": 85,
    }


def test_bec_signal_requires_a_standalone_token():
    articles = [
        _article(
            "Why narrative intelligence is becoming essential to cybersecurity",
            "Disinformation/Influence Operation",
        ),
        _article(
            "Webcams at war: defenders harden connected devices",
            "IoT/OT Security",
        ),
        _article(
            "CVE-2026-1000 exists because token validation fails",
            "Vulnerability Disclosure",
        ),
    ]

    stats, _ = audit_classification(articles)

    assert stats["misclassified_count"] == 0


def test_standalone_bec_remains_a_phishing_signal():
    articles = [
        _article("BEC campaign targets finance teams", "Security Policy/Regulation"),
    ]

    stats, findings = audit_classification(articles)

    assert stats["misclassified_count"] == 1
    assert any(item["issue"] == "Potential misclassifications" for item in findings)


def test_valid_actor_and_espionage_compounds_are_not_conflicts():
    articles = [
        _article("Kimsuky phishing campaign targets researchers", "Nation-State Attack"),
        _article("Flax Typhoon cyber-espionage tools disrupted", "Cyber Espionage"),
        _article("Phishing kit operation disrupted", "Nation-State Attack"),
    ]

    stats, _ = audit_classification(articles)

    assert stats["misclassified_count"] == 1
