"""Tests for serve_threatwatch.py: rate limiter, data loading, routing, and security."""
import collections
import hashlib
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

    def test_load_hunts_rebuilds_when_artifact_predates_clusters(self, tmp_path):
        output = tmp_path / "data" / "output"
        output.mkdir(parents=True)
        (output / "hunts.json").write_text(json.dumps({
            "generated_at": "2026-10-08T00:00:00+00:00", "hunts": [{"id": "stale"}],
        }))
        clusters = {"generated_at": "2026-10-08T01:00:00+00:00", "clusters": []}
        rebuilt = {"generated_at": "2026-10-08T01:00:01+00:00", "hunts": []}

        with patch("serve_threatwatch.BASE_DIR", tmp_path), \
             patch("serve_threatwatch.load_clusters", return_value=clusters), \
             patch("serve_threatwatch.load_articles", return_value=[]), \
             patch("serve_threatwatch.build_hunts", return_value=rebuilt):
            result = sw.load_hunts()

        assert result == rebuilt

    def test_load_ledger_rebuilds_when_artifact_predates_hunts(self, tmp_path):
        output = tmp_path / "data" / "output"
        output.mkdir(parents=True)
        stale = {
            "generated_at": "2026-10-08T00:00:00+00:00",
            "records": [{"id": "threat-old"}],
        }
        (output / "threat_ledger.json").write_text(json.dumps(stale))
        hunts = {"generated_at": "2026-10-08T01:00:00+00:00", "hunts": []}
        rebuilt = {"generated_at": "2026-10-08T01:00:01+00:00", "records": []}

        with patch("serve_threatwatch.BASE_DIR", tmp_path), \
             patch("serve_threatwatch.load_hunts", return_value=hunts), \
             patch("serve_threatwatch.load_clusters", return_value={"clusters": []}), \
             patch("serve_threatwatch.load_articles", return_value=[]), \
             patch("serve_threatwatch.build_ledger", return_value=rebuilt) as builder:
            result = sw.load_ledger()

        assert result == rebuilt
        builder.assert_called_once_with([], {"clusters": []}, hunts, previous=stale)


class TestOperationalSummary:
    def test_prioritizes_exploited_watchlist_matches_without_raw_content(self):
        articles = [
            {
                "hash": "kev-1",
                "title": "Ivanti gateway exploited in the wild",
                "summary": "Attackers are targeting internet-facing gateways.",
                "full_content": "must not cross the operational API boundary",
                "asset_tags": ["Ivanti"],
                "cve_ids": ["CVE-2026-1000"],
                "kev_listed": True,
                "cvss_score": 9.8,
                "epss_score": 0.41,
                "confidence": 92,
                "iocs": {"ipv4": ["192.0.2.10"]},
            },
            {
                "hash": "routine-1",
                "title": "Routine product announcement",
                "summary": "No exploitation reported.",
            },
        ]
        watchlist = {"brands": [], "assets": ["Ivanti"]}

        payload = sw.build_operational_summary(articles, [], watchlist)

        assert payload["metrics"]["decision_queue"] == 1
        assert payload["metrics"]["watchlist_matches"] == 1
        priority = payload["priorities"][0]
        assert priority["id"] == "kev-1"
        assert priority["urgency"] == "critical"
        assert priority["action_type"] == "patch"
        assert priority["watchlist_matches"] == ["Ivanti"]
        assert priority["evidence"]["ioc_count"] == 1
        assert "full_content" not in json.dumps(payload)

    def test_deduplicates_shared_cves_and_handles_missing_values(self):
        articles = [
            {"hash": "older", "title": "CVE duplicate", "cve_ids": ["CVE-2026-2000"], "cvss_score": 7.5},
            {"hash": "newer", "title": "CVE duplicate confirmed exploited", "cve_ids": ["CVE-2026-2000"], "kev_listed": True},
            {"hash": "empty", "title": "Unscored report", "confidence": float("nan")},
        ]

        payload = sw.build_operational_summary(articles, None, {})

        matching = [item for item in payload["priorities"] if "CVE-2026-2000" in item["evidence"]["cves"]]
        assert len(matching) == 1
        assert matching[0]["id"] == "newer"
        assert payload["exposure"]["configured"] is False
        json.dumps(payload, allow_nan=False)

    def test_reads_pipeline_attack_technique_shape(self):
        articles = [{
            "hash": "attack-1",
            "title": "Observed exploitation behavior",
            "kev_listed": True,
            "iocs": {"ipv4": ["185.220.101.50"]},
            "attack_techniques": [{
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            }],
        }]

        payload = sw.build_operational_summary(articles, [], {})

        assert payload["priorities"][0]["evidence"]["techniques"] == [
            "T1190 Exploit Public-Facing Application"
        ]


# ── Health endpoint ──────────────────────────────────────────────────────────

class TestComputeStatus:
    """Direct unit tests for _compute_status briefing-freshness signals
    (the 2026-07 AI-provider outage hid behind a green status for 3 days
    because staleness never reached _compute_status)."""

    def _live(self):
        # heartbeat and last run both fresh => pipeline demonstrably live.
        return dict(latest_run={"articles_enriched": 20, "analysis_failures": 0},
                    feed_summary={}, last_run_age=60.0, heartbeat_age=30.0)

    def test_fresh_briefing_is_ok(self):
        status, reasons = sw._compute_status(
            **self._live(), briefing_stale=False, briefing_age_hours=1.0)
        assert status == "ok"
        assert reasons == []

    def test_stale_briefing_degrades_status(self):
        # Signal 1: stale (but not severe) => degraded with a briefing_stale reason.
        status, reasons = sw._compute_status(
            **self._live(), briefing_stale=True, briefing_age_hours=4.0)
        assert status == "degraded"
        assert any(r.startswith("briefing_stale_") for r in reasons)
        # Not severe (4h < 2*3h=6h) => no AI-outage discriminator.
        assert "ai_generation_failing" not in reasons

    def test_frozen_briefing_while_pipeline_live_flags_ai_outage(self):
        # Signal 2: pipeline live + briefing severely stale => AI generation failing.
        status, reasons = sw._compute_status(
            **self._live(), briefing_stale=True, briefing_age_hours=77.0)
        assert status == "degraded"
        assert "ai_generation_failing" in reasons
        assert any("briefing_stale_77h" == r for r in reasons)

    def test_severe_stale_but_pipeline_dead_is_not_ai_outage(self):
        # If the pipeline itself is stale, a frozen briefing is expected — don't
        # misattribute it to the AI layer. (last_run beyond RUN_STALE_S.)
        status, reasons = sw._compute_status(
            latest_run={}, feed_summary={}, last_run_age=sw._RUN_STALE_S + 10,
            heartbeat_age=30.0, briefing_stale=True, briefing_age_hours=77.0)
        assert "ai_generation_failing" not in reasons

    def test_none_freshness_never_fabricates_reason(self):
        # briefing_health import/read failure => briefing_stale None => skip.
        status, reasons = sw._compute_status(
            **self._live(), briefing_stale=None, briefing_age_hours=None)
        assert status == "ok"
        assert reasons == []

    def test_missing_briefing_infinite_age_does_not_crash(self):
        # briefing.json missing => age_hours inf; int(inf) must not raise.
        status, reasons = sw._compute_status(
            **self._live(), briefing_stale=True, briefing_age_hours=float("inf"))
        assert status == "degraded"
        assert "briefing_stale_?h" in reasons
        assert "ai_generation_failing" in reasons


class TestHealthEndpoint:
    def setup_method(self):
        sw._cache.clear()

    def test_health_returns_valid_json(self, tmp_path):
        # Use a fresh completed_at so the freshness check passes and status=ok.
        # Patch briefing freshness fresh too — otherwise status depends on the
        # real briefing.json on disk (a stale checkout would degrade status).
        from datetime import datetime, timezone
        fresh = datetime.now(timezone.utc).isoformat()
        with patch("serve_threatwatch.load_stats", return_value={"latest": {"completed_at": fresh, "articles_fetched": 42, "cyber_articles": 20, "api_cost_today": 0.05}}), \
             patch("serve_threatwatch.BASE_DIR", tmp_path), \
             patch("modules.briefing_health.check_briefing_freshness",
                   return_value={"stale": False, "age_hours": 0.5,
                                 "generated_at": fresh, "reason": "fresh"}):
            body = sw.build_health()
        data = json.loads(body)
        assert data["status"] == "ok"
        assert "uptime_s" in data
        # articles_total is the served corpus size (comparable with
        # /api/articles total); the per-run fetch count has its own field.
        assert data["last_run_fetched"] == 42
        assert data["articles_total"] == 0  # no corpus in tmp BASE_DIR
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

    def test_health_serializes_missing_briefing_age_as_null(self, tmp_path):
        with patch("serve_threatwatch.load_stats", return_value={}), \
             patch("serve_threatwatch.BASE_DIR", tmp_path), \
             patch("modules.briefing_health.check_briefing_freshness",
                   return_value={"stale": True, "age_hours": float("inf")}):
            body = sw.build_health()

        assert b"Infinity" not in body
        assert json.loads(body)["briefing_age_hours"] is None

    def test_health_includes_feed_summary(self, tmp_path):
        from datetime import datetime, timezone
        state_dir = tmp_path / "data" / "state"
        state_dir.mkdir(parents=True)
        # last_checked is required for entries to count — feeds without a
        # recent check are treated as disabled and excluded from the health
        # summary (prevents abandoned feed_health entries from inflating
        # error counts).
        now_iso = datetime.now(timezone.utc).isoformat()
        fh_data = {
            "https://a.example.com": {"status": "ok", "last_checked": now_iso},
            "https://b.example.com": {"status": "dead", "last_checked": now_iso},
        }
        (state_dir / "feed_health.json").write_text(json.dumps(fh_data))
        with patch("serve_threatwatch.load_stats", return_value={}), \
             patch("serve_threatwatch.BASE_DIR", tmp_path):
            body = sw.build_health()
        data = json.loads(body)
        assert data["feed_health"].get("ok", 0) == 1
        assert data["feed_health"].get("dead", 0) == 1

    def test_health_excludes_abandoned_feeds(self, tmp_path):
        """Feeds not checked in >24h (e.g. disabled in config) don't count."""
        from datetime import datetime, timezone, timedelta
        state_dir = tmp_path / "data" / "state"
        state_dir.mkdir(parents=True)
        now = datetime.now(timezone.utc)
        fh_data = {
            "https://recent-ok.example.com": {
                "status": "ok",
                "last_checked": now.isoformat(),
            },
            "https://abandoned-error.example.com": {
                "status": "error",
                "last_checked": (now - timedelta(days=5)).isoformat(),
            },
            "https://never-checked.example.com": {"status": "ok"},
        }
        (state_dir / "feed_health.json").write_text(json.dumps(fh_data))
        with patch("serve_threatwatch.load_stats", return_value={}), \
             patch("serve_threatwatch.BASE_DIR", tmp_path):
            body = sw.build_health()
        data = json.loads(body)
        assert data["feed_health"].get("ok", 0) == 1
        assert data["feed_health"].get("error", 0) == 0


# ── render_page XSS guard ─────────────────────────────────────────────────────

class TestFrontendApplicationShell:
    def setup_method(self):
        sw._cache.clear()

    def test_render_page_reads_built_frontend_without_embedded_corpus(self, tmp_path):
        dist = tmp_path / "frontend" / "dist"
        dist.mkdir(parents=True)
        index = dist / "index.html"
        index.write_text('<html><main id="app"></main></html>', encoding="utf-8")

        with patch.object(sw, "FRONTEND_DIST", dist):
            body = sw.render_page()

        html = body.decode("utf-8")
        assert '<main id="app">' in html
        assert "ssr-data" not in html

    def test_frontend_asset_rejects_path_traversal(self, tmp_path):
        dist = tmp_path / "frontend" / "dist"
        assets = dist / "assets"
        assets.mkdir(parents=True)
        expected = assets / "app.js"
        expected.write_text("console.log('ok')", encoding="utf-8")
        with patch.object(sw, "FRONTEND_DIST", dist):
            assert sw.resolve_frontend_asset("/assets/../../secret") is None
            assert sw.resolve_frontend_asset("/assets/nested/app.js") is None
            assert sw.resolve_frontend_asset("/assets/app.js") == expected

    def test_response_metadata_uses_safe_allowlists(self):
        assert sw._normalized_content_type("text/css") == "text/css"
        assert sw._normalized_content_type("text/plain\r\nX-Evil: true") == "application/octet-stream"
        assert sw._build_etag(b"body") == f'"{hashlib.sha256(b"body").hexdigest()}"'


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
        # Unchanged file within TTL is served from cache.
        assert sw.read_cached(f) == b"hello"
        assert str(f) in sw._cache

    def test_modified_file_invalidates_cache(self, tmp_path):
        """The pipeline rewrites outputs atomically (mtime bumps); the cache
        must serve the NEW bytes immediately, not pin stale data for the TTL."""
        f = tmp_path / "test.txt"
        f.write_text("hello")
        assert sw.read_cached(f) == b"hello"
        f.write_text("changed")
        assert sw.read_cached(f) == b"changed"

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
        assert data["limit"] == 50
        assert data["has_more"] is False

    def test_articles_default_is_bounded(self, test_server):
        articles = [{"title": f"Article {i}"} for i in range(75)]
        with patch("serve_threatwatch.load_articles", return_value=articles):
            status, _, body = _get(test_server + "/api/articles")
        assert status == 200
        data = json.loads(body)
        assert len(data["articles"]) == 50
        assert data["has_more"] is True

    def test_articles_pagination(self, test_server):
        articles = [{"title": f"Article {i}"} for i in range(50)]
        with patch("serve_threatwatch.load_articles", return_value=articles):
            status, _, body = _get(test_server + "/api/articles?offset=0&limit=10")
        assert status == 200
        data = json.loads(body)
        assert len(data["articles"]) == 10
        assert data["total"] == 50
        assert data["has_more"] is True

    def test_v1_articles_uses_same_bounded_contract(self, test_server):
        articles = [{"hash": str(i), "title": f"Article {i}"} for i in range(60)]
        with patch("serve_threatwatch.load_articles", return_value=articles):
            status, _, body = _get(test_server + "/api/v1/articles")
        data = json.loads(body)
        assert status == 200
        assert data["limit"] == 50
        assert len(data["articles"]) == 50

    def test_articles_supports_search_and_faceted_filters(self, test_server):
        articles = [
            {
                "hash": "1",
                "title": "Critical cloud breach",
                "summary": "Identity provider compromised",
                "category": "Data Breach",
                "region": "EMEA",
                "source_name": "Trusted Source",
            },
            {
                "hash": "2",
                "title": "Routine patch update",
                "summary": "Product maintenance release",
                "category": "Patch/Security Update",
                "region": "NA",
                "source_name": "Vendor Blog",
            },
        ]
        with patch("serve_threatwatch.load_articles", return_value=articles):
            status, _, body = _get(
                test_server + "/api/v1/articles?q=identity&category=Data%20Breach&region=EMEA"
            )
        data = json.loads(body)
        assert status == 200
        assert data["total"] == 1
        assert data["articles"][0]["hash"] == "1"
        assert data["filters"]["q"] == "identity"

    def test_articles_vulnerability_view_keeps_cve_records(self, test_server):
        articles = [
            {"hash": "1", "title": "CVE record", "source": "nvd:cve", "cve_ids": ["CVE-2026-1"]},
            {"hash": "2", "title": "Campaign report", "category": "Ransomware", "cve_ids": []},
        ]
        with patch("serve_threatwatch.load_articles", return_value=articles):
            status, _, body = _get(test_server + "/api/v1/articles?view=vulnerabilities")
        data = json.loads(body)
        assert status == 200
        assert data["total"] == 1
        assert data["articles"][0]["hash"] == "1"

    def test_news_view_hides_only_bulk_machine_cve_records(self, test_server):
        articles = [
            {"hash": "1", "title": "Raw CVE", "source": "nvd:cve", "cve_ids": ["CVE-2026-1"]},
            {
                "hash": "2",
                "title": "Researchers report active CVE exploitation",
                "source": "https://example.com/feed",
                "category": "Vulnerability",
                "cve_ids": ["CVE-2026-1"],
            },
        ]
        with patch("serve_threatwatch.load_articles", return_value=articles):
            status, _, body = _get(test_server + "/api/v1/articles?view=news")
        data = json.loads(body)
        assert status == 200
        assert [article["hash"] for article in data["articles"]] == ["2"]

    def test_v1_article_detail(self, test_server):
        articles = [{"hash": "abc123", "title": "Matched", "full_content": "private body"}]
        with patch("serve_threatwatch.load_articles", return_value=articles):
            status, _, body = _get(test_server + "/api/v1/articles/abc123")
        data = json.loads(body)
        assert status == 200
        assert data["title"] == "Matched"
        assert "full_content" not in data

    def test_v1_sources_aggregates_named_publishers(self, test_server):
        articles = [
            {"source_name": "Source A", "source": "https://a.test/rss"},
            {"source_name": "Source A", "source": "https://a.test/rss"},
            {"source_name": "Source B", "source": "https://b.test/rss"},
        ]
        with patch("serve_threatwatch.load_articles", return_value=articles):
            status, _, body = _get(test_server + "/api/v1/sources")
        data = json.loads(body)
        assert status == 200
        assert data["total"] == 2
        assert data["sources"][0]["article_count"] == 2

    def test_v1_openapi_is_available(self, test_server):
        status, _, body = _get(test_server + "/api/v1/openapi.json")
        data = json.loads(body)
        assert status == 200
        assert data["openapi"].startswith("3.")
        assert "/api/v1/articles" in data["paths"]
        assert "/api/v1/health/feeds" in data["paths"]

    def test_v1_feed_health_is_available(self, test_server):
        expected = {"total_tracked": 2, "ok": 1, "dead": 1}
        with patch("modules.feed_health.get_health_json", return_value=expected):
            status, _, body = _get(test_server + "/api/v1/health/feeds")
        assert status == 200
        assert json.loads(body) == expected

    def test_articles_bad_offset(self, test_server):
        with patch("serve_threatwatch.load_articles", return_value=[]):
            status, _, body = _get(test_server + "/api/articles?offset=abc")
        assert status == 400

    def test_404_on_unknown_path(self, test_server):
        status, _, body = _get(test_server + "/nonexistent")
        assert status == 404
        data = json.loads(body)
        assert data["error"] == "Not found"

    def test_known_frontend_route_returns_application_shell(self, test_server):
        with patch("serve_threatwatch.render_page", return_value=b"<html>app</html>"):
            status, headers, body = _get(test_server + "/vulnerabilities")
        assert status == 200
        assert "text/html" in headers.get("Content-Type", "")
        assert body == b"<html>app</html>"

    @pytest.mark.parametrize("path", [
        "/ledger", "/threats", "/exposure", "/investigations", "/hunts", "/reports",
        "/automation", "/sources", "/sources/article-1", "/ledger/threat-abc123",
    ])
    def test_operational_frontend_routes_return_application_shell(self, test_server, path):
        with patch("serve_threatwatch.render_page", return_value=b"<html>operations</html>"):
            status, _, body = _get(test_server + path)
        assert status == 200
        assert body == b"<html>operations</html>"

    def test_operational_summary_endpoint_returns_bounded_payload(self, test_server):
        priority = {"hash": "one", "title": "Active exploit", "kev_listed": True}
        with patch("serve_threatwatch.load_articles", return_value=[priority]), \
             patch("serve_threatwatch.load_clusters", return_value={"clusters": []}), \
             patch("serve_threatwatch.load_watchlist_data", return_value={}):
            status, headers, body = _get(test_server + "/api/v1/operations/summary")
        assert status == 200
        assert "application/json" in headers.get("Content-Type", "")
        payload = json.loads(body)
        assert payload["metrics"]["decision_queue"] == 1
        assert payload["priorities"][0]["id"] == "one"

    def test_operational_summary_endpoint_sanitizes_read_failures(self, test_server):
        with patch("serve_threatwatch.load_articles", side_effect=OSError("private path")):
            status, _, body = _get(test_server + "/api/v1/operations/summary")
        assert status == 500
        assert json.loads(body)["error"] == "Error building operational summary"

    def test_hunts_endpoint_returns_correlated_packages(self, test_server):
        payload = {"generated_at": "2026-10-08T00:00:00Z", "hunts": [{"id": "hunt-abc", "status": "qualified"}]}
        with patch("serve_threatwatch.load_hunts", return_value=payload):
            status, _, body = _get(test_server + "/api/v1/hunts")

        assert status == 200
        assert json.loads(body)["hunts"][0]["id"] == "hunt-abc"

    def test_hunt_detail_returns_one_package(self, test_server):
        payload = {"generated_at": "2026-10-08T00:00:00Z", "hunts": [{"id": "hunt-abc", "status": "qualified"}]}
        with patch("serve_threatwatch.load_hunts", return_value=payload):
            status, _, body = _get(test_server + "/api/v1/hunts/hunt-abc")

        assert status == 200
        assert json.loads(body)["id"] == "hunt-abc"

    def test_hunt_detail_rejects_invalid_or_missing_id(self, test_server):
        payload = {"hunts": []}
        with patch("serve_threatwatch.load_hunts", return_value=payload):
            invalid, _, _ = _get(test_server + "/api/v1/hunts/not%20valid")
            missing, _, _ = _get(test_server + "/api/v1/hunts/hunt-missing")

        assert invalid == 400
        assert missing == 404

    def test_ledger_endpoint_filters_public_records(self, test_server):
        payload = {
            "summary": {"total_records": 2},
            "records": [
                {"id": "threat-abc123", "entity_type": "cve", "entity_name": "CVE-2026-1000", "affected_products": ["Acme Gateway"], "decision": {"action": "patch"}, "state": {"activity": "active"}, "sources": [{"url": "https://example.test"}], "changes": [{"id": "private-history"}]},
                {"id": "threat-def456", "entity_type": "actor", "entity_name": "Qilin", "decision": {"action": "hunt"}, "state": {"activity": "active"}},
            ],
            "changes": [],
        }
        with patch("serve_threatwatch.load_ledger", return_value=payload):
            status, _, body = _get(test_server + "/api/v1/ledger?type=cve&action=patch&q=gateway")

        result = json.loads(body)
        assert status == 200
        assert result["total"] == 1
        assert result["records"][0]["id"] == "threat-abc123"
        assert "sources" not in result["records"][0]
        assert "changes" not in result["records"][0]
        assert result["filters"] == {"type": "cve", "action": "patch", "q": "gateway", "activity": ""}

    def test_ledger_endpoint_rejects_unknown_filters(self, test_server):
        with patch("serve_threatwatch.load_ledger", return_value={"records": []}):
            bad_type, _, _ = _get(test_server + "/api/v1/ledger?type=organization")
            bad_action, _, _ = _get(test_server + "/api/v1/ledger?action=block")
            bad_activity, _, _ = _get(test_server + "/api/v1/ledger?activity=deleted")

        assert (bad_type, bad_action, bad_activity) == (400, 400, 400)

    def test_ledger_changes_and_detail_are_available(self, test_server):
        payload = {
            "records": [{"id": "threat-abc123", "entity_name": "CVE-2026-1000"}],
            "changes": [{"id": "change-one", "record_id": "threat-abc123"}],
        }
        with patch("serve_threatwatch.load_ledger", return_value=payload):
            changes_status, _, changes_body = _get(test_server + "/api/v1/ledger/changes")
            detail_status, _, detail_body = _get(test_server + "/api/v1/ledger/threat-abc123")

        assert changes_status == 200
        assert json.loads(changes_body)["changes"][0]["id"] == "change-one"
        assert detail_status == 200
        assert json.loads(detail_body)["entity_name"] == "CVE-2026-1000"

    def test_ledger_changes_reports_total_before_limit(self, test_server):
        payload = {
            "records": [],
            "changes": [
                {"id": "change-one", "record_id": "threat-one"},
                {"id": "change-two", "record_id": "threat-two"},
            ],
        }
        with patch("serve_threatwatch.load_ledger", return_value=payload):
            status, _, body = _get(test_server + "/api/v1/ledger/changes?limit=1")

        result = json.loads(body)
        assert status == 200
        assert result["total"] == 2
        assert len(result["changes"]) == 1

    def test_ledger_detail_rejects_invalid_or_missing_id(self, test_server):
        with patch("serve_threatwatch.load_ledger", return_value={"records": []}):
            invalid, _, _ = _get(test_server + "/api/v1/ledger/not%20valid")
            missing, _, _ = _get(test_server + "/api/v1/ledger/threat-missing")

        assert invalid == 400
        assert missing == 404

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

    def test_etag_conditional_get_accepts_weak_proxy_tag(self, test_server):
        with patch("serve_threatwatch.render_page", return_value=b"<html>test</html>"):
            _, headers, _ = _get(test_server + "/")
            etag = headers.get("Etag") or headers.get("ETag")
            status, _, _ = _get(test_server + "/", headers={"If-None-Match": f"W/{etag}"})

        assert status == 304

    def test_etag_conditional_get_accepts_tag_list_and_wildcard(self, test_server):
        with patch("serve_threatwatch.render_page", return_value=b"<html>test</html>"):
            _, headers, _ = _get(test_server + "/")
            etag = headers.get("Etag") or headers.get("ETag")
            listed, _, _ = _get(test_server + "/", headers={"If-None-Match": f'"other", W/{etag}'})
            wildcard, _, _ = _get(test_server + "/", headers={"If-None-Match": "*"})

        assert listed == 304
        assert wildcard == 304

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


class TestSinceCursorLossless:
    """Paging /api/since with a small limit must deliver EVERY article exactly
    once when the client feeds next_cursor back — the old cursor jumped past
    unreturned items and lost them."""

    def test_full_walk_returns_every_article_once(self):
        articles = [
            {"title": f"a{i}", "hash": f"h{i}",
             "timestamp": f"2026-06-10T0{i}:00:00+00:00"}
            for i in range(7)
        ]
        server, base = _start_server()
        try:
            with patch.object(sw, "load_articles", return_value=articles):
                seen, cursor, hops = [], "2026-01-01T00:00:00+00:00", 0
                while hops < 20:
                    hops += 1
                    from urllib.parse import quote
                    status, _, body = _get(f"{base}/api/since?ts={quote(cursor)}&limit=2")
                    assert status == 200
                    data = json.loads(body)
                    if not data["articles"]:
                        break
                    seen.extend(a["title"] for a in data["articles"])
                    cursor = data["next_cursor"]
        finally:
            server.shutdown()
        assert sorted(seen) == sorted(a["title"] for a in articles)
        assert len(seen) == len(set(seen)), "no duplicates expected"

    def test_unencoded_plus_in_ts_tolerated(self):
        """next_cursor passed back without URL-encoding must still parse."""
        server, base = _start_server()
        try:
            with patch.object(sw, "load_articles", return_value=[]):
                # A literal "+" in the query (unencoded, as the documented
                # Logic App recipe sends it) is decoded to a space server-side.
                status, _, body = _get(
                    f"{base}/api/since?ts=2026-06-10T00:00:00+00:00&limit=5"
                )
        finally:
            server.shutdown()
        assert status == 200


class TestWatchlistGetAuth:
    """When WATCHLIST_TOKEN is configured, unauthenticated GETs must be
    rejected — this guard previously had zero regression coverage (only the
    token-unset open behaviour was tested)."""

    def test_get_requires_token_when_configured(self):
        server, base = _start_server()
        try:
            with patch.object(sw, "WATCHLIST_TOKEN", "sekrit-token"):
                status, _, _ = _get(f"{base}/api/watchlist")
                assert status == 401
                status2, _, body = _get(
                    f"{base}/api/watchlist",
                    headers={"Authorization": "Bearer sekrit-token"},
                )
                assert status2 == 200
                assert b"suggest_list" in body
        finally:
            server.shutdown()

    def test_wrong_token_rejected(self):
        server, base = _start_server()
        try:
            with patch.object(sw, "WATCHLIST_TOKEN", "sekrit-token"):
                status, _, _ = _get(
                    f"{base}/api/watchlist",
                    headers={"Authorization": "Bearer wrong"},
                )
        finally:
            server.shutdown()
        assert status == 401
