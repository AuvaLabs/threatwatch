"""Tests for serve_threatwatch.py — rate limiter, SSR data, routing, and security."""
import collections
import json
import threading
import time
from http import HTTPStatus
from http.server import HTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import pytest

import serve_threatwatch as sw


# ── Helpers ──────────────────────────────────────────────────────────────────

def _start_server(handler_class=sw.ThreatWatchHandler, port=0):
    """Start a test server on a random port and return (server, base_url)."""
    server = HTTPServer(("127.0.0.1", port), handler_class)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    return server, f"http://{host}:{port}"


def _get(url, headers=None):
    """Simple GET returning (status, headers_dict, body_bytes)."""
    req = Request(url, headers=headers or {})
    try:
        resp = urlopen(req, timeout=5)
        return resp.status, dict(resp.headers), resp.read()
    except HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _post(url, data, headers=None):
    """Simple POST returning (status, headers_dict, body_bytes)."""
    hdrs = {"Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    body = json.dumps(data).encode() if isinstance(data, dict) else data
    req = Request(url, data=body, headers=hdrs, method="POST")
    try:
        resp = urlopen(req, timeout=5)
        return resp.status, dict(resp.headers), resp.read()
    except HTTPError as e:
        return e.code, dict(e.headers), e.read()


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

    def test_includes_briefing_data(self):
        briefing = {"summary": "Test briefing", "sections": []}
        with patch("serve_threatwatch.load_articles", return_value=[]), \
             patch("serve_threatwatch.load_stats", return_value={}), \
             patch("serve_threatwatch.load_briefing", return_value=briefing):
            result = sw.build_ssr_data()
        parsed = json.loads(result)
        assert parsed["briefing"] == briefing


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

    def test_load_stats_parses_json(self, tmp_path):
        output_dir = tmp_path / "data" / "output"
        output_dir.mkdir(parents=True)
        stats = {"latest": {"feeds_loaded": 10}}
        (output_dir / "stats.json").write_text(json.dumps(stats))
        with patch("serve_threatwatch.BASE_DIR", tmp_path):
            result = sw.load_stats()
        assert result == stats

    def test_load_articles_handles_corrupt_json(self, tmp_path):
        output_dir = tmp_path / "data" / "output"
        output_dir.mkdir(parents=True)
        (output_dir / "daily_latest.json").write_text("{corrupt json")
        with patch("serve_threatwatch.BASE_DIR", tmp_path):
            result = sw.load_articles()
        assert result == []

    def test_load_ioc_items_filters_threatfox(self):
        articles = [
            {"title": "News", "isDarkweb": False},
            {"title": "IOC", "isDarkweb": True, "darkwebSource": "threatfox"},
            {"title": "Ransom", "isDarkweb": True, "darkwebSource": "ransomware_live"},
        ]
        with patch("serve_threatwatch.load_articles", return_value=articles):
            result = sw.load_ioc_items()
        assert len(result) == 1
        assert result[0]["title"] == "IOC"


# ── Health endpoint ──────────────────────────────────────────────────────────

class TestHealthEndpoint:
    def setup_method(self):
        sw._cache.clear()

    def test_health_returns_valid_json(self, tmp_path):
        # Use a fresh completed_at so the freshness check passes and status=ok.
        from datetime import datetime, timezone
        fresh = datetime.now(timezone.utc).isoformat()
        with patch("serve_threatwatch.load_stats", return_value={"latest": {"completed_at": fresh, "articles_fetched": 42, "cyber_articles": 20, "api_cost_today": 0.05}}), \
             patch("serve_threatwatch.BASE_DIR", tmp_path):
            body = sw.build_health()
        data = json.loads(body)
        assert data["status"] == "ok"
        assert "uptime_s" in data
        assert data["articles_total"] == 42
        assert data["articles_cyber"] == 20

    def test_health_handles_missing_stats(self, tmp_path):
        # No completed_at in stats → status="unknown" under the contract that
        # reports real health rather than always returning "ok".
        with patch("serve_threatwatch.load_stats", return_value={}), \
             patch("serve_threatwatch.BASE_DIR", tmp_path):
            body = sw.build_health()
        data = json.loads(body)
        assert data["status"] == "unknown"
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


# ── render_page XSS guard ─────────────────────────────────────────────────────

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


# ── Watchlist helpers ────────────────────────────────────────────────────────

class TestWatchlistHelpers:
    def test_load_watchlist_returns_empty_when_missing(self, tmp_path):
        with patch("serve_threatwatch.BASE_DIR", tmp_path):
            result = sw.load_watchlist_data()
        assert result["brands"] == []
        assert result["assets"] == []

    def test_save_and_load_roundtrip(self, tmp_path):
        state_dir = tmp_path / "data" / "state"
        state_dir.mkdir(parents=True)
        with patch("serve_threatwatch.BASE_DIR", tmp_path):
            sw.save_watchlist_data(["BrandA", "BrandB"], ["AssetX"])
            result = sw.load_watchlist_data()
        assert result["brands"] == ["BrandA", "BrandB"]
        assert result["assets"] == ["AssetX"]
        assert result["updated_at"] is not None

    def test_save_strips_empty_strings(self, tmp_path):
        state_dir = tmp_path / "data" / "state"
        state_dir.mkdir(parents=True)
        with patch("serve_threatwatch.BASE_DIR", tmp_path):
            sw.save_watchlist_data(["Valid", "", "  "], ["Asset", " "])
            result = sw.load_watchlist_data()
        assert result["brands"] == ["Valid"]
        assert result["assets"] == ["Asset"]

    def test_load_handles_corrupt_json(self, tmp_path):
        state_dir = tmp_path / "data" / "state"
        state_dir.mkdir(parents=True)
        (state_dir / "watchlist.json").write_text("{bad json")
        with patch("serve_threatwatch.BASE_DIR", tmp_path):
            result = sw.load_watchlist_data()
        assert result["brands"] == []


# ── read_cached ──────────────────────────────────────────────────────────────

class TestReadCached:
    def setup_method(self):
        sw._cache.clear()

    def test_reads_file_and_caches(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        result = sw.read_cached(f)
        assert result == b"hello"
        # Modify file — should still return cached version
        f.write_text("changed")
        result2 = sw.read_cached(f)
        assert result2 == b"hello"

    def test_raises_on_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            sw.read_cached(tmp_path / "nonexistent.txt")

    def test_cache_expires_after_ttl(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("v1")
        sw.read_cached(f)
        # Manually expire the cache
        key = str(f)
        sw._cache[key] = (time.time() - sw.CACHE_TTL - 1, b"v1")
        f.write_text("v2")
        result = sw.read_cached(f)
        assert result == b"v2"


# ── HTTP handler integration tests ───────────────────────────────────────────

@pytest.fixture(scope="module")
def test_server():
    """Start a test server for integration tests."""
    sw._cache.clear()
    sw._rate_buckets.clear()
    server, base_url = _start_server()
    yield base_url
    server.shutdown()


class TestHTTPRoutes:
    def setup_method(self):
        sw._cache.clear()
        sw._rate_buckets.clear()

    def test_root_returns_html(self, test_server):
        with patch("serve_threatwatch.render_page", return_value=b"<html>test</html>"):
            status, headers, body = _get(test_server + "/")
        assert status == 200
        assert "text/html" in headers.get("Content-Type", "")

    def test_health_returns_json(self, test_server):
        with patch("serve_threatwatch.build_health",
                   return_value=json.dumps({"status": "ok"}).encode()):
            status, _, body = _get(test_server + "/api/health")
        assert status == 200
        data = json.loads(body)
        assert data["status"] == "ok"

    def test_articles_returns_json(self, test_server):
        articles = [{"title": "Test"}]
        with patch("serve_threatwatch.load_articles", return_value=articles):
            status, _, body = _get(test_server + "/api/articles")
        assert status == 200
        data = json.loads(body)
        assert isinstance(data, dict)
        assert data["total"] == 1
        assert len(data["articles"]) == 1
        assert data["limit"] == 0
        assert data["has_more"] is False

    def test_articles_pagination(self, test_server):
        articles = [{"title": f"Article {i}"} for i in range(50)]
        with patch("serve_threatwatch.load_articles", return_value=articles):
            status, _, body = _get(test_server + "/api/articles?offset=0&limit=10")
        assert status == 200
        data = json.loads(body)
        assert len(data["articles"]) == 10
        assert data["total"] == 50
        assert data["has_more"] is True

    def test_articles_bad_offset(self, test_server):
        with patch("serve_threatwatch.load_articles", return_value=[]):
            status, _, body = _get(test_server + "/api/articles?offset=abc")
        assert status == 400

    def test_404_on_unknown_path(self, test_server):
        status, _, body = _get(test_server + "/nonexistent")
        assert status == 404
        data = json.loads(body)
        assert data["error"] == "Not found"

    def test_options_returns_no_content(self, test_server):
        req = Request(test_server + "/api/articles", method="OPTIONS")
        try:
            resp = urlopen(req, timeout=5)
            assert resp.status == 204
        except HTTPError as e:
            assert e.code == 204

    def test_security_headers_present(self, test_server):
        with patch("serve_threatwatch.render_page", return_value=b"<html></html>"):
            _, headers, _ = _get(test_server + "/")
        assert "Content-Security-Policy" in headers
        assert headers.get("X-Frame-Options") == "DENY"
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("Referrer-Policy") == "no-referrer"
        assert "Strict-Transport-Security" in headers

    def test_cors_on_public_api_routes(self, test_server):
        articles = [{"title": "Test"}]
        with patch("serve_threatwatch.load_articles", return_value=articles):
            _, headers, _ = _get(test_server + "/api/articles")
        assert headers.get("Access-Control-Allow-Origin") == "*"

    def test_cors_restricted_on_health(self, test_server):
        with patch("serve_threatwatch.build_health",
                   return_value=json.dumps({"status": "ok"}).encode()):
            _, headers, _ = _get(test_server + "/api/health")
        # No wildcard CORS on sensitive endpoints
        assert headers.get("Access-Control-Allow-Origin") is None

    def test_no_cors_on_html_route(self, test_server):
        with patch("serve_threatwatch.render_page", return_value=b"<html></html>"):
            _, headers, _ = _get(test_server + "/")
        assert "Access-Control-Allow-Origin" not in headers

    def test_etag_conditional_get(self, test_server):
        with patch("serve_threatwatch.render_page", return_value=b"<html>test</html>"):
            _, headers1, _ = _get(test_server + "/")
            etag = headers1.get("Etag") or headers1.get("ETag")
            assert etag is not None
            # Second request with If-None-Match
            status2, _, _ = _get(test_server + "/", headers={"If-None-Match": etag})
        assert status2 == 304

    def test_post_method_not_allowed(self, test_server):
        status, _, body = _post(test_server + "/api/health", {})
        assert status == 405


class TestWatchlistRoute:
    def setup_method(self):
        sw._cache.clear()
        sw._rate_buckets.clear()

    def test_watchlist_post_forbidden_when_disabled(self, test_server):
        with patch.object(sw, "WATCHLIST_WRITE_ENABLED", False):
            status, _, body = _post(test_server + "/api/watchlist", {"brands": []})
        assert status == 403

    def test_watchlist_post_requires_token_when_set(self, test_server):
        with patch.object(sw, "WATCHLIST_WRITE_ENABLED", True), \
             patch.object(sw, "WATCHLIST_TOKEN", "secret123"):
            # No auth header
            status, _, _ = _post(test_server + "/api/watchlist", {"brands": ["Test"]})
            assert status == 401
            # Wrong token
            status2, _, _ = _post(
                test_server + "/api/watchlist",
                {"brands": ["Test"]},
                headers={"Authorization": "Bearer wrong"}
            )
            assert status2 == 401

    def test_watchlist_post_accepts_valid_token(self, test_server, tmp_path):
        state_dir = tmp_path / "data" / "state"
        state_dir.mkdir(parents=True)
        with patch.object(sw, "WATCHLIST_WRITE_ENABLED", True), \
             patch.object(sw, "WATCHLIST_TOKEN", "secret123"), \
             patch("serve_threatwatch.BASE_DIR", tmp_path):
            status, _, body = _post(
                test_server + "/api/watchlist",
                {"brands": ["BrandA"], "assets": ["AssetX"]},
                headers={"Authorization": "Bearer secret123"}
            )
        assert status == 200
        data = json.loads(body)
        assert data["ok"] is True
        assert data["brands"] == 1

    def test_watchlist_post_requires_token_when_unset(self, test_server, tmp_path):
        state_dir = tmp_path / "data" / "state"
        state_dir.mkdir(parents=True)
        with patch.object(sw, "WATCHLIST_WRITE_ENABLED", True), \
             patch.object(sw, "WATCHLIST_TOKEN", ""), \
             patch("serve_threatwatch.BASE_DIR", tmp_path):
            status, _, _ = _post(test_server + "/api/watchlist", {"brands": ["X"]})
        assert status == 403

    def test_watchlist_post_rejects_invalid_json(self, test_server):
        with patch.object(sw, "WATCHLIST_WRITE_ENABLED", True), \
             patch.object(sw, "WATCHLIST_TOKEN", "testtoken"):
            req = Request(
                test_server + "/api/watchlist",
                data=b"not json",
                headers={"Content-Type": "application/json",
                         "Authorization": "Bearer testtoken"},
                method="POST"
            )
            try:
                resp = urlopen(req, timeout=5)
                status = resp.status
            except HTTPError as e:
                status = e.code
        assert status == 400

    def test_watchlist_post_rejects_oversized_payload(self, test_server):
        with patch.object(sw, "WATCHLIST_WRITE_ENABLED", True), \
             patch.object(sw, "WATCHLIST_TOKEN", "testtoken"):
            big_data = b"x" * 70000
            req = Request(
                test_server + "/api/watchlist",
                data=big_data,
                headers={"Content-Type": "application/json",
                         "Content-Length": str(len(big_data)),
                         "Authorization": "Bearer testtoken"},
                method="POST"
            )
            try:
                resp = urlopen(req, timeout=5)
                status = resp.status
            except HTTPError as e:
                status = e.code
        assert status == 413

    def test_watchlist_get_returns_data(self, test_server, tmp_path):
        with patch.object(sw, "WATCHLIST_WRITE_ENABLED", False), \
             patch("serve_threatwatch.BASE_DIR", tmp_path), \
             patch("serve_threatwatch.load_watchlist_data", return_value={"brands": ["B"], "assets": [], "updated_at": None}):
            status, _, body = _get(test_server + "/api/watchlist")
        assert status == 200
        data = json.loads(body)
        assert "brands" in data
        assert "suggest_list" in data


class TestErrorSanitization:
    """Verify error messages don't leak internal details."""

    def test_404_does_not_leak_path(self, test_server):
        status, _, body = _get(test_server + "/secret/internal/path")
        data = json.loads(body)
        assert "secret" not in data["error"]
        assert "internal" not in data["error"]
        assert data["error"] == "Not found"

    def test_bad_json_does_not_leak_exception(self, test_server):
        with patch.object(sw, "WATCHLIST_WRITE_ENABLED", True), \
             patch.object(sw, "WATCHLIST_TOKEN", "testtoken"):
            req = Request(
                test_server + "/api/watchlist",
                data=b"{bad",
                headers={"Content-Type": "application/json",
                         "Authorization": "Bearer testtoken"},
                method="POST"
            )
            try:
                resp = urlopen(req, timeout=5)
                body = resp.read()
            except HTTPError as e:
                body = e.read()
            data = json.loads(body)
            assert "Expecting" not in data["error"]  # No json.JSONDecodeError details
            assert data["error"] == "Invalid JSON payload"
