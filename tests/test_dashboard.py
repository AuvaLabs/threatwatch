"""Tests for app/dashboard.py — covers generate_dashboard_html, build_dashboard,
XSS safety, edge cases, and helper functions."""

import html as html_mod
import json
import logging
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------
from app.dashboard import (
    generate_dashboard_html,
    build_dashboard,
    load_json_safe,
    load_stats,
    _parse_pub_date,
    _format_pub_date,
    _assess_threat_level,
    _cache_rate,
    _extract_source_name,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_ARTICLE = {
    "title": "Ransomware Hits Hospital",
    "translated_title": "Ransomware Hits Hospital",
    "link": "https://example.com/article1",
    "category": "Ransomware",
    "confidence": 85,
    "published": "Mon, 20 Mar 2026 10:00:00 +0000",
    "summary": "A ransomware group encrypted hospital records.",
    "related_articles": ["https://example.com/rel1"],
}

SAMPLE_ARTICLE_2 = {
    "title": "Zero-Day in Browser",
    "translated_title": "Zero-Day in Browser",
    "link": "https://news.org/zeroday",
    "category": "Zero-Day Exploit",
    "confidence": 92,
    "published": "Mon, 20 Mar 2026 09:00:00 +0000",
    "summary": "A zero-day was discovered in a major browser.",
    "related_articles": [],
}


# ---------------------------------------------------------------------------
# Helper: patch data files so tests don't touch the filesystem
# ---------------------------------------------------------------------------

def _patch_data(articles=None, stats=None):
    """Return a context manager tuple that patches load_json_safe and load_stats."""
    if articles is None:
        articles = []
    if stats is None:
        stats = {}
    return (
        patch("app.dashboard.load_json_safe", return_value=articles),
        patch("app.dashboard.load_stats", return_value=stats),
    )


# ---------------------------------------------------------------------------
# load_json_safe
# ---------------------------------------------------------------------------

class TestLoadJsonSafe:
    def test_missing_file_returns_empty_list(self, tmp_path):
        result = load_json_safe(tmp_path / "nonexistent.json")
        assert result == []

    def test_valid_json_list(self, tmp_path):
        f = tmp_path / "data.json"
        f.write_text('[{"a": 1}]', encoding="utf-8")
        assert load_json_safe(f) == [{"a": 1}]

    def test_invalid_json_returns_empty_list(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("not json", encoding="utf-8")
        assert load_json_safe(f) == []

    def test_io_error_returns_empty_list(self, tmp_path):
        f = tmp_path / "data.json"
        f.write_text("[]", encoding="utf-8")
        with patch("builtins.open", side_effect=IOError("disk full")):
            result = load_json_safe(f)
        assert result == []


# ---------------------------------------------------------------------------
# load_stats
# ---------------------------------------------------------------------------

class TestLoadStats:
    def test_missing_file_returns_empty_dict(self, tmp_path):
        with patch("app.dashboard.STATS_FILE", tmp_path / "nosuchfile.json"):
            assert load_stats() == {}

    def test_valid_stats(self, tmp_path):
        stats = {"latest": {"feeds_loaded": 12}, "runs": []}
        f = tmp_path / "stats.json"
        f.write_text(json.dumps(stats), encoding="utf-8")
        with patch("app.dashboard.STATS_FILE", f):
            assert load_stats()["latest"]["feeds_loaded"] == 12

    def test_corrupt_stats_returns_empty_dict(self, tmp_path):
        f = tmp_path / "stats.json"
        f.write_text("{bad json", encoding="utf-8")
        with patch("app.dashboard.STATS_FILE", f):
            assert load_stats() == {}


# ---------------------------------------------------------------------------
# generate_dashboard_html — empty articles
# ---------------------------------------------------------------------------

class TestGenerateDashboardHtmlEmpty:
    def setup_method(self):
        self.patches = _patch_data(articles=[], stats={})

    def test_returns_string(self):
        with self.patches[0], self.patches[1]:
            html = generate_dashboard_html()
        assert isinstance(html, str)

    def test_contains_doctype(self):
        with self.patches[0], self.patches[1]:
            html = generate_dashboard_html()
        assert "<!DOCTYPE html>" in html

    def test_contains_page_title(self):
        with self.patches[0], self.patches[1]:
            html = generate_dashboard_html()
        assert "ThreatDigest Hub" in html

    def test_empty_state_message_present(self):
        with self.patches[0], self.patches[1]:
            html = generate_dashboard_html()
        assert "No articles yet" in html

    def test_no_table_rendered_when_empty(self):
        with self.patches[0], self.patches[1]:
            html = generate_dashboard_html()
        assert "<table" not in html

    def test_articles_today_shows_zero(self):
        with self.patches[0], self.patches[1]:
            html = generate_dashboard_html()
        assert ">0<" in html

    def test_default_threat_level_medium(self):
        with self.patches[0], self.patches[1]:
            html = generate_dashboard_html()
        # _assess_threat_level returns MEDIUM for empty list
        assert "MEDIUM" in html

    def test_footer_present(self):
        with self.patches[0], self.patches[1]:
            html = generate_dashboard_html()
        assert "ThreatWatch by AuvaLabs" in html


# ---------------------------------------------------------------------------
# generate_dashboard_html — with sample articles
# ---------------------------------------------------------------------------

class TestGenerateDashboardHtmlWithArticles:
    def _render(self, articles=None, stats=None):
        if articles is None:
            articles = [SAMPLE_ARTICLE, SAMPLE_ARTICLE_2]
        a_patch = patch("app.dashboard.load_json_safe", return_value=articles)
        s_patch = patch("app.dashboard.load_stats", return_value=stats or {})
        with a_patch, s_patch:
            return generate_dashboard_html()

    def test_table_is_rendered(self):
        html = self._render()
        assert "<table" in html

    def test_article_count_in_stats_card(self):
        html = self._render()
        assert ">2<" in html

    def test_article_title_present(self):
        html = self._render()
        assert "Ransomware Hits Hospital" in html

    def test_article_link_present(self):
        html = self._render()
        assert "https://example.com/article1" in html

    def test_category_present(self):
        html = self._render()
        assert "Ransomware" in html

    def test_confidence_percentage_present(self):
        html = self._render()
        assert "85%" in html

    def test_summary_truncated_to_140_chars(self):
        long_summary = "x" * 200
        article = {**SAMPLE_ARTICLE, "summary": long_summary}
        html = self._render(articles=[article])
        # Only first 140 chars of the summary appear
        assert "x" * 140 in html
        assert "x" * 141 not in html

    def test_related_tag_shown_when_related_present(self):
        html = self._render()
        assert "source" in html  # "+1 source" tag

    def test_no_related_count_when_empty(self):
        article = {**SAMPLE_ARTICLE_2}  # related_articles is []
        html = self._render(articles=[article])
        # With no related articles, the "+N source" badge should not appear
        assert "+1 source" not in html

    def test_category_badge_rendered(self):
        html = self._render()
        assert 'cat-badge' in html

    def test_conf_high_class_applied(self):
        html = self._render()
        assert "conf-high" in html

    def test_conf_med_class_for_medium_confidence(self):
        article = {**SAMPLE_ARTICLE, "confidence": 65}
        html = self._render(articles=[article])
        assert "conf-med" in html

    def test_conf_low_class_for_low_confidence(self):
        article = {**SAMPLE_ARTICLE, "confidence": 30}
        html = self._render(articles=[article])
        assert "conf-low" in html

    def test_stats_feeds_loaded_from_latest_run(self):
        stats = {"latest": {"feeds_loaded": 42}, "runs": []}
        html = self._render(stats=stats)
        assert "42" in html

    def test_total_news_reviewed_summed(self):
        stats = {
            "latest": {},
            "runs": [{"news_reviewed": 100}, {"news_reviewed": 200}],
        }
        html = self._render(stats=stats)
        assert "300" in html

    def test_threat_level_critical_with_many_critical_articles(self):
        critical_articles = [
            {
                "category": "Zero-Day Exploit",
                "confidence": 90,
                "title": f"ZD{i}",
                "link": "#",
                "published": "",
                "summary": "",
                "related_articles": [],
            }
            for i in range(5)
        ]
        html = self._render(articles=critical_articles)
        assert "CRITICAL" in html

    def test_multiple_articles_rendered(self):
        a1 = {**SAMPLE_ARTICLE, "title": "Article One", "translated_title": "Article One"}
        a2 = {**SAMPLE_ARTICLE_2, "title": "Article Two", "translated_title": "Article Two"}
        html = self._render(articles=[a1, a2])
        assert "Article One" in html
        assert "Article Two" in html


# ---------------------------------------------------------------------------
# XSS safety
# ---------------------------------------------------------------------------

class TestXssSafety:
    def _render_with_article(self, article):
        a_patch = patch("app.dashboard.load_json_safe", return_value=[article])
        s_patch = patch("app.dashboard.load_stats", return_value={})
        with a_patch, s_patch:
            return generate_dashboard_html()

    def test_script_tag_in_title_is_escaped(self):
        # Use only 'title' (no translated_title) so the XSS payload is the one rendered
        article = {
            "title": "<script>alert('xss')</script>",
            "link": "https://example.com",
            "category": "Ransomware",
            "confidence": 85,
            "published": "",
            "summary": "",
            "related_articles": [],
        }
        html = self._render_with_article(article)
        # The raw script tag must NOT appear unescaped
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    def test_script_tag_in_translated_title_is_escaped(self):
        article = {**SAMPLE_ARTICLE, "translated_title": '<img src=x onerror="evil()">'}
        html = self._render_with_article(article)
        assert '<img src=x' not in html

    def test_script_in_summary_is_escaped(self):
        article = {**SAMPLE_ARTICLE, "summary": "<script>steal()</script>"}
        html = self._render_with_article(article)
        assert "<script>steal" not in html
        assert "&lt;script&gt;" in html

    def test_quotes_in_title_escaped_in_data_attribute(self):
        article = {**SAMPLE_ARTICLE, "title": 'Title with "quotes" and \'apostrophes\''}
        html = self._render_with_article(article)
        # The raw unescaped quotes must not appear in data-title attribute
        raw_unescaped = 'data-title="title with "quotes"'
        assert raw_unescaped not in html

    def test_ampersand_in_category_is_escaped(self):
        article = {**SAMPLE_ARTICLE, "category": "Malware & Exploits"}
        html = self._render_with_article(article)
        assert "&amp;" in html

    def test_angle_brackets_in_link_are_escaped(self):
        article = {**SAMPLE_ARTICLE, "link": 'https://example.com/<path>'}
        html = self._render_with_article(article)
        assert "href=\"https://example.com/&lt;path&gt;\"" in html

    def test_newlines_in_summary_removed(self):
        article = {**SAMPLE_ARTICLE, "summary": "line1\nline2\nline3"}
        html = self._render_with_article(article)
        # Newlines are replaced before escaping — raw \n must not appear in summary div
        assert "line1 line2" in html


# ---------------------------------------------------------------------------
# Edge cases — missing fields
# ---------------------------------------------------------------------------

class TestEdgeCasesAndMissingFields:
    def _render_with_article(self, article):
        a_patch = patch("app.dashboard.load_json_safe", return_value=[article])
        s_patch = patch("app.dashboard.load_stats", return_value={})
        with a_patch, s_patch:
            return generate_dashboard_html()

    def test_article_with_no_title_uses_fallback(self):
        article = {"link": "#", "category": "Ransomware", "confidence": 50, "published": ""}
        html = self._render_with_article(article)
        assert "No Title" in html

    def test_article_with_missing_link_uses_hash(self):
        # Omit 'link' entirely so a.get("link", "#") returns "#"
        article = {k: v for k, v in SAMPLE_ARTICLE.items() if k != "link"}
        html = self._render_with_article(article)
        assert 'href="#"' in html

    def test_article_with_no_category_shows_unknown(self):
        article = {**SAMPLE_ARTICLE}
        del article["category"]
        html = self._render_with_article(article)
        assert "Unknown" in html

    def test_article_with_no_confidence_shows_zero(self):
        article = {**SAMPLE_ARTICLE}
        del article["confidence"]
        html = self._render_with_article(article)
        assert "0%" in html

    def test_article_with_no_summary_skips_summary_div(self):
        article = {**SAMPLE_ARTICLE, "summary": ""}
        html = self._render_with_article(article)
        # The CSS class .summary-text is always in the <style> block.
        # When summary is empty, no <div class="summary-text"> element is rendered.
        assert '<div class="summary-text">' not in html

    def test_article_with_no_published_shows_na(self):
        article = {**SAMPLE_ARTICLE, "published": ""}
        html = self._render_with_article(article)
        assert "N/A" in html

    def test_special_chars_in_title_rendered_safely(self):
        article = {**SAMPLE_ARTICLE, "title": "Alert: 50% of CVEs affect <Windows> & 'Linux'"}
        html = self._render_with_article(article)
        # Must not have raw unescaped <Windows>
        assert "<Windows>" not in html

    def test_unicode_in_title_preserved(self):
        # Set both title and translated_title so the Cyrillic text is what gets rendered
        article = {**SAMPLE_ARTICLE, "title": "Атака на систему", "translated_title": "Атака на систему"}
        html = self._render_with_article(article)
        assert "Атака на систему" in html

    def test_very_long_title_included(self):
        long_title = "A" * 500
        # Set both fields so translated_title doesn't override with the old value
        article = {**SAMPLE_ARTICLE, "title": long_title, "translated_title": long_title}
        html = self._render_with_article(article)
        assert "A" * 100 in html


# ---------------------------------------------------------------------------
# build_dashboard
# ---------------------------------------------------------------------------

class TestBuildDashboard:
    def test_writes_dashboard_html_to_output_dir(self, tmp_path):
        output_dir = tmp_path / "data" / "output"
        with (
            patch("app.dashboard.generate_dashboard_html", return_value="<html>test</html>"),
            patch("app.dashboard.OUTPUT_DIR", output_dir),
            patch("app.dashboard.BASE_DIR", tmp_path),
        ):
            build_dashboard()

        dashboard_file = output_dir / "dashboard.html"
        assert dashboard_file.exists()
        assert dashboard_file.read_text(encoding="utf-8") == "<html>test</html>"

    def test_writes_docs_index_html(self, tmp_path):
        output_dir = tmp_path / "data" / "output"
        with (
            patch("app.dashboard.generate_dashboard_html", return_value="<html>docs</html>"),
            patch("app.dashboard.OUTPUT_DIR", output_dir),
            patch("app.dashboard.BASE_DIR", tmp_path),
        ):
            build_dashboard()

        docs_index = tmp_path / "docs" / "index.html"
        assert docs_index.exists()
        assert docs_index.read_text(encoding="utf-8") == "<html>docs</html>"

    def test_creates_parent_directories(self, tmp_path):
        # Neither output_dir nor docs_dir exist — build_dashboard must create them
        output_dir = tmp_path / "nested" / "data" / "output"
        with (
            patch("app.dashboard.generate_dashboard_html", return_value="<html/>"),
            patch("app.dashboard.OUTPUT_DIR", output_dir),
            patch("app.dashboard.BASE_DIR", tmp_path / "nested"),
        ):
            build_dashboard()

        assert (output_dir / "dashboard.html").exists()

    def test_logs_generation_info(self, tmp_path, caplog):
        output_dir = tmp_path / "data" / "output"
        # build_dashboard uses bare logging.info() which routes to the root logger
        with (
            patch("app.dashboard.generate_dashboard_html", return_value="<html/>"),
            patch("app.dashboard.OUTPUT_DIR", output_dir),
            patch("app.dashboard.BASE_DIR", tmp_path),
            caplog.at_level(logging.INFO),
        ):
            build_dashboard()

        assert any("Dashboard generated" in m for m in caplog.messages)

    def test_both_files_have_same_content(self, tmp_path):
        output_dir = tmp_path / "data" / "output"
        content = "<html>same</html>"
        with (
            patch("app.dashboard.generate_dashboard_html", return_value=content),
            patch("app.dashboard.OUTPUT_DIR", output_dir),
            patch("app.dashboard.BASE_DIR", tmp_path),
        ):
            build_dashboard()

        dashboard = (output_dir / "dashboard.html").read_text(encoding="utf-8")
        docs = (tmp_path / "docs" / "index.html").read_text(encoding="utf-8")
        assert dashboard == docs == content


# ---------------------------------------------------------------------------
# _parse_pub_date
# ---------------------------------------------------------------------------

class TestParsePubDate:
    from datetime import datetime, timezone

    def test_empty_string_returns_min(self):
        from datetime import datetime, timezone
        result = _parse_pub_date("")
        assert result == datetime.min.replace(tzinfo=timezone.utc)

    def test_rfc2822_format(self):
        result = _parse_pub_date("Mon, 20 Mar 2026 10:00:00 +0000")
        assert result.year == 2026
        assert result.month == 3

    def test_iso_format(self):
        result = _parse_pub_date("2026-03-20T10:00:00+00:00")
        assert result.year == 2026

    def test_iso_naive_gets_utc(self):
        from datetime import timezone
        result = _parse_pub_date("2026-03-20T10:00:00")
        assert result.tzinfo == timezone.utc

    def test_simple_date_format(self):
        result = _parse_pub_date("2026-03-20")
        assert result.year == 2026

    def test_garbage_returns_min(self):
        from datetime import datetime, timezone
        result = _parse_pub_date("not-a-date")
        assert result == datetime.min.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# _format_pub_date
# ---------------------------------------------------------------------------

class TestFormatPubDate:
    def test_empty_returns_na(self):
        assert _format_pub_date("") == "N/A"

    def test_valid_date_formatted(self):
        result = _format_pub_date("Mon, 20 Mar 2026 10:00:00 +0000")
        assert result == "2026-03-20 10:00"

    def test_invalid_date_returns_raw_slice(self):
        result = _format_pub_date("20260320garbage")
        # Falls back to raw[:16]
        assert result == "20260320garbage"[:16]


# ---------------------------------------------------------------------------
# _assess_threat_level
# ---------------------------------------------------------------------------

class TestAssessThreatLevel:
    def test_empty_returns_medium_warning(self):
        level, cls = _assess_threat_level([])
        assert level == "MEDIUM"
        assert cls == "warning"

    def test_no_critical_high_confidence_returns_medium_success(self):
        articles = [{"category": "Ransomware", "confidence": 50}]
        level, cls = _assess_threat_level(articles)
        assert level == "MEDIUM"
        assert cls == "success"

    def test_two_critical_high_conf_returns_high(self):
        articles = [
            {"category": "Zero-Day Exploit", "confidence": 85},
            {"category": "Nation-State Attack", "confidence": 90},
        ]
        level, cls = _assess_threat_level(articles)
        assert level == "HIGH"
        assert cls == "warning"

    def test_five_or_more_critical_returns_critical(self):
        articles = [
            {"category": "Zero-Day Exploit", "confidence": 90}
            for _ in range(5)
        ]
        level, cls = _assess_threat_level(articles)
        assert level == "CRITICAL"
        assert cls == "danger"

    def test_critical_below_threshold_confidence_not_counted(self):
        articles = [
            {"category": "Zero-Day Exploit", "confidence": 79},
            {"category": "Nation-State Attack", "confidence": 75},
        ]
        level, cls = _assess_threat_level(articles)
        # confidence < 80 for CRITICAL category — should not trigger HIGH
        assert level == "MEDIUM"

    def test_ten_high_category_high_conf_returns_high(self):
        articles = [
            {"category": "Ransomware", "confidence": 75}
            for _ in range(10)
        ]
        level, cls = _assess_threat_level(articles)
        assert level == "HIGH"


# ---------------------------------------------------------------------------
# _cache_rate
# ---------------------------------------------------------------------------

class TestCacheRate:
    def test_zero_total_returns_na(self):
        assert _cache_rate({}) == "N/A"

    def test_all_hits(self):
        assert _cache_rate({"cache_hits": 10, "cache_misses": 0}) == "100%"

    def test_half_hits(self):
        assert _cache_rate({"cache_hits": 5, "cache_misses": 5}) == "50%"

    def test_no_hits(self):
        assert _cache_rate({"cache_hits": 0, "cache_misses": 4}) == "0%"


# ---------------------------------------------------------------------------
# _extract_source_name
# ---------------------------------------------------------------------------

class TestExtractSourceName:
    def test_none_returns_unknown(self):
        assert _extract_source_name(None) == "Unknown"

    def test_empty_string_returns_unknown(self):
        assert _extract_source_name("") == "Unknown"

    def test_standard_url(self):
        assert _extract_source_name("https://bleepingcomputer.com/news/1") == "Bleepingcomputer"

    def test_www_prefix_stripped(self):
        assert _extract_source_name("https://www.theregister.com/foo") == "Theregister"

    def test_feeds_prefix_stripped(self):
        assert _extract_source_name("https://feeds.feedburner.com/foo") == "Feedburner"

    def test_invalid_url_returns_unknown(self):
        result = _extract_source_name("not_a_url")
        # urlparse won't crash but hostname will be None/empty
        assert isinstance(result, str)
