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
    assert normalized["summary_method"] == "none"
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
