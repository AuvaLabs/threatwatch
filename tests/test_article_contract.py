"""Canonical article contract tests."""

from modules.article_contract import normalize_article, validate_article


def test_normalizes_legacy_article_without_mutating_input():
    original = {
        "hash": "abc",
        "title": "Security report",
        "link": "https://example.com/story?utm_source=feed",
        "source": "https://feeds.example.com/rss",
        "feed_region": "Europe",
        "published": "2026-10-07T10:00:00Z",
        "summary": "",
    }

    normalized = normalize_article(original)

    assert "source_name" not in original
    assert normalized["source_name"] == "Example"
    assert normalized["canonical_url"] == "https://example.com/story"
    assert normalized["published_at"] == "2026-10-07T10:00:00+00:00"
    assert normalized["region"] == "Europe"
    assert normalized["content_hash"] == "abc"
    assert normalized["summary"] == "Source report headline: Security report"
    assert normalized["summary_method"] == "fallback"
    assert normalized["summary_needs_enrichment"] is True
    assert normalized["cve_ids"] == []


def test_preserves_explicit_source_name_and_marks_summary_source():
    normalized = normalize_article({
        "hash": "abc",
        "title": "Report",
        "link": "https://example.com/report",
        "source": "newsapi:Ignored",
        "source_name": "SecurityWeek",
        "feed_region": "Global",
        "published": "2026-10-07T10:00:00+00:00",
        "summary": "A useful source excerpt.",
    })
    assert normalized["source_name"] == "SecurityWeek"
    assert normalized["summary_method"] == "source"


def test_validation_reports_required_boundary_errors():
    errors = validate_article({"title": "", "link": "not-a-url", "hash": ""})
    assert "title_missing" in errors
    assert "hash_missing" in errors
    assert "link_invalid" in errors


def test_normalizes_invalid_cyber_confidence_to_reviewable_default():
    normalized = normalize_article({
        "hash": "abc",
        "title": "Attackers abuse Teams to steal company data",
        "link": "https://example.com/report",
        "source": "https://example.com/feed",
        "is_cyber_attack": True,
        "confidence": 0,
    })

    assert normalized["confidence"] == 60


def test_removes_leading_source_notice_from_summary_and_content():
    normalized = normalize_article({
        "hash": "abc",
        "title": "Critical NGINX vulnerabilities disclosed",
        "link": "https://example.com/report",
        "source": "https://example.com/feed",
        "summary": "SYSTEM NOTICE\nCritical flaws affect supported NGINX releases.",
        "full_content": " SYSTEM NOTICE\r\nResearchers published technical details.",
    })

    assert normalized["summary"] == "Critical flaws affect supported NGINX releases."
    assert normalized["full_content"] == "Researchers published technical details."
    assert normalized["summary_method"] == "source"
    assert "summary_needs_enrichment" not in normalized


def test_does_not_remove_notice_words_inside_source_text():
    normalized = normalize_article({
        "hash": "abc",
        "title": "Security report",
        "link": "https://example.com/report",
        "summary": "The vendor issued a system notice after the incident.",
    })

    assert normalized["summary"] == "The vendor issued a system notice after the incident."


def test_uses_existing_intelligence_as_missing_summary_fallback():
    normalized = normalize_article({
        "hash": "abc",
        "title": "Security report",
        "link": "https://example.com/report",
        "summary": "SYSTEM NOTICE",
        "intel_what": "A ransomware attack disrupted hospital systems.",
    })

    assert normalized["summary"] == "A ransomware attack disrupted hospital systems."
    assert normalized["summary_method"] == "fallback"
    assert normalized["summary_needs_enrichment"] is True
