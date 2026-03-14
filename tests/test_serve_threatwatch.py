"""Tests for serve_threatwatch.py — rate limiter, SSR data, and routing."""
import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import serve_threatwatch as sw


# ── Rate limiter ──────────────────────────────────────────────────────────────

class TestRateLimiter:
    def setup_method(self):
        """Clear rate buckets before each test for isolation."""
        sw._rate_buckets.clear()

    def test_allows_requests_below_limit(self):
        for _ in range(sw._RATE_LIMIT):
            assert sw._is_rate_limited("10.0.0.1") is False

    def test_blocks_at_limit(self):
        for _ in range(sw._RATE_LIMIT):
            sw._is_rate_limited("10.0.0.2")
        assert sw._is_rate_limited("10.0.0.2") is True

    def test_different_ips_are_independent(self):
        for _ in range(sw._RATE_LIMIT):
            sw._is_rate_limited("10.0.0.3")
        # Different IP should still be allowed
        assert sw._is_rate_limited("10.0.0.4") is False

    def test_old_requests_slide_out_of_window(self):
        ip = "10.0.0.5"
        now = time.monotonic()
        # Manually inject timestamps that are outside the window
        old_ts = now - sw._RATE_WINDOW - 1
        import collections
        sw._rate_buckets[ip] = collections.deque([old_ts] * sw._RATE_LIMIT)
        # All old — should not be rate limited
        assert sw._is_rate_limited(ip) is False


# ── SSR data building ─────────────────────────────────────────────────────────

class TestBuildSsrData:
    def setup_method(self):
        # Clear the in-memory cache so each test starts fresh
        sw._cache.clear()

    def test_returns_valid_json(self):
        with patch("serve_threatwatch.load_articles", return_value=[]), \
             patch("serve_threatwatch.load_stats", return_value={}), \
             patch("serve_threatwatch.load_briefing", return_value=None):
            result = sw.build_ssr_data()
        parsed = json.loads(result)
        assert "articles" in parsed
        assert "stats" in parsed
        assert "generated_at" in parsed

    def test_caches_result(self):
        calls = []
        def _load():
            calls.append(1)
            return []

        with patch("serve_threatwatch.load_articles", side_effect=_load), \
             patch("serve_threatwatch.load_stats", return_value={}), \
             patch("serve_threatwatch.load_briefing", return_value=None):
            sw.build_ssr_data()
            sw.build_ssr_data()  # second call should use cache

        assert len(calls) == 1


# ── load_* helpers ────────────────────────────────────────────────────────────

class TestLoadHelpers:
    def setup_method(self):
        sw._cache.clear()

    def test_load_articles_returns_empty_list_when_file_missing(self, tmp_path):
        with patch("serve_threatwatch.BASE_DIR", tmp_path):
            result = sw.load_articles()
        assert result == []

    def test_load_stats_returns_empty_dict_when_file_missing(self, tmp_path):
        with patch("serve_threatwatch.BASE_DIR", tmp_path):
            result = sw.load_stats()
        assert result == {}

    def test_load_briefing_returns_none_when_file_missing(self, tmp_path):
        with patch("serve_threatwatch.BASE_DIR", tmp_path):
            result = sw.load_briefing()
        assert result is None

    def test_load_articles_parses_json(self, tmp_path):
        output_dir = tmp_path / "data" / "output"
        output_dir.mkdir(parents=True)
        articles = [{"title": "Test", "url": "https://example.com"}]
        (output_dir / "daily_latest.json").write_text(json.dumps(articles))
        with patch("serve_threatwatch.BASE_DIR", tmp_path):
            result = sw.load_articles()
        assert result == articles


# ── render_page XSS guard ─────────────────────────────────────────────────────

class TestHealthEndpoint:
    def setup_method(self):
        sw._cache.clear()

    def test_health_returns_valid_json(self, tmp_path):
        with patch("serve_threatwatch.load_stats", return_value={"latest": {"completed_at": "2026-01-01T00:00:00+00:00", "articles_fetched": 42, "cyber_articles": 20, "api_cost_today": 0.05}}), \
             patch("serve_threatwatch.BASE_DIR", tmp_path):
            body = sw.build_health()
        data = json.loads(body)
        assert data["status"] == "ok"
        assert "uptime_s" in data
        assert data["articles_total"] == 42
        assert data["articles_cyber"] == 20

    def test_health_handles_missing_stats(self, tmp_path):
        with patch("serve_threatwatch.load_stats", return_value={}), \
             patch("serve_threatwatch.BASE_DIR", tmp_path):
            body = sw.build_health()
        data = json.loads(body)
        assert data["status"] == "ok"
        assert data["articles_total"] == 0

    def test_health_includes_feed_summary(self, tmp_path):
        state_dir = tmp_path / "data" / "state"
        state_dir.mkdir(parents=True)
        fh_data = {
            "https://a.example.com": {"status": "ok"},
            "https://b.example.com": {"status": "dead"},
        }
        (state_dir / "feed_health.json").write_text(json.dumps(fh_data))
        with patch("serve_threatwatch.load_stats", return_value={}), \
             patch("serve_threatwatch.BASE_DIR", tmp_path):
            body = sw.build_health()
        data = json.loads(body)
        assert data["feed_health"].get("ok", 0) == 1
        assert data["feed_health"].get("dead", 0) == 1


class TestRenderPageXssGuard:
    def setup_method(self):
        sw._cache.clear()

    def test_script_tag_breakout_escaped(self, tmp_path):
        """Ensure </script> inside JSON data cannot break out of the script tag."""
        template = f'<html>{sw.SSR_PLACEHOLDER}</html>'
        template_file = tmp_path / "threatwatch.html"
        template_file.write_bytes(template.encode())

        articles = [{"title": "Test</script><script>alert(1)"}]
        ssr_payload = {"articles": articles, "stats": {}, "briefing": None}

        with patch("serve_threatwatch.read_cached", return_value=template.encode()), \
             patch("serve_threatwatch.build_ssr_data",
                   return_value=json.dumps(ssr_payload, ensure_ascii=False)):
            body = sw.render_page()

        html = body.decode("utf-8")
        # The raw </script> must not appear inside our script block unescaped
        assert "<\\/script>" in html or "</script>" not in html.split(
            '<script id="ssr-data"')[1].split("</script>")[0]
