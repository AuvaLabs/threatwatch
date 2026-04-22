"""Tests for modules/feed_health.py — state machine and persistence."""
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

import modules.feed_health as fh


@pytest.fixture(autouse=True)
def isolated_health_file(tmp_path):
    """Redirect HEALTH_FILE to a temp path so tests don't touch the real state dir."""
    health_path = tmp_path / "feed_health.json"
    with patch.object(fh, "HEALTH_FILE", health_path):
        yield health_path


URL = "https://feeds.example.com/rss"


class TestLoadSaveHealth:
    def test_load_returns_empty_when_no_file(self, isolated_health_file):
        assert fh.load_health() == {}

    def test_save_and_load_roundtrip(self, isolated_health_file):
        data = {"https://example.com": {"status": "ok"}}
        fh.save_health(data)
        assert fh.load_health() == data

    def test_load_returns_empty_on_corrupt_file(self, isolated_health_file):
        isolated_health_file.write_text("not-json", encoding="utf-8")
        assert fh.load_health() == {}


class TestRecordFetch:
    def test_healthy_fetch_sets_ok(self):
        fh.record_fetch(URL, success=True, entry_count=5)
        data = fh.load_health()
        assert data[URL]["status"] == "ok"
        assert data[URL]["consecutive_errors"] == 0

    def test_quiet_feed_does_not_increment_errors(self):
        # Simulate a prior error
        fh.record_fetch(URL, success=False)
        before = fh.load_health()[URL]["consecutive_errors"]
        # Now quiet success
        fh.record_fetch(URL, success=True, entry_count=0)
        after = fh.load_health()[URL]["consecutive_errors"]
        assert after == before  # errors not reset and not incremented

    def test_failure_increments_errors(self):
        fh.record_fetch(URL, success=False)
        assert fh.load_health()[URL]["consecutive_errors"] == 1
        fh.record_fetch(URL, success=False)
        assert fh.load_health()[URL]["consecutive_errors"] == 2

    def test_status_ok_after_success(self):
        fh.record_fetch(URL, success=False)
        fh.record_fetch(URL, success=False)
        fh.record_fetch(URL, success=True, entry_count=3)
        assert fh.load_health()[URL]["status"] == "ok"
        assert fh.load_health()[URL]["consecutive_errors"] == 0

    def test_status_error_within_3_days(self):
        # first_error is now → < 3 days → "error"
        fh.record_fetch(URL, success=False)
        assert fh.load_health()[URL]["status"] == "error"

    def test_status_suspect_after_3_days(self):
        # Mock _days_since to return 4 days for the first_error timestamp
        with patch.object(fh, "_days_since", return_value=4.0):
            fh.record_fetch(URL, success=False)
        assert fh.load_health()[URL]["status"] == "suspect"

    def test_status_dead_after_7_days(self):
        with patch.object(fh, "_days_since", return_value=8.0):
            fh.record_fetch(URL, success=False)
        assert fh.load_health()[URL]["status"] == "dead"

    def test_stale_when_no_entries_in_30_days(self):
        # Set up a last_success that is 31 days ago
        old_ts = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
        data = {
            URL: {
                "url": URL,
                "consecutive_errors": 0,
                "first_error": None,
                "last_success": old_ts,
                "last_checked": old_ts,
                "status": "ok",
            }
        }
        fh.save_health(data)
        # Quiet fetch — HTTP 200, 0 entries
        fh.record_fetch(URL, success=True, entry_count=0)
        assert fh.load_health()[URL]["status"] == "stale"

    def test_quiet_feed_with_recent_success_stays_ok(self):
        recent_ts = datetime.now(timezone.utc).isoformat()
        data = {
            URL: {
                "url": URL,
                "consecutive_errors": 0,
                "first_error": None,
                "last_success": recent_ts,
                "last_checked": recent_ts,
                "status": "ok",
            }
        }
        fh.save_health(data)
        fh.record_fetch(URL, success=True, entry_count=0)
        assert fh.load_health()[URL]["status"] == "ok"


class TestGetReport:
    def test_categorises_by_status(self):
        fh.record_fetch("https://dead.example.com/feed", success=True, entry_count=5)
        data = fh.load_health()
        data["https://dead.example.com/feed"]["status"] = "dead"
        fh.save_health(data)
        fh.record_fetch(URL, success=True, entry_count=3)

        report = fh.get_report()
        assert any(e["url"] == "https://dead.example.com/feed" for e in report["dead"])
        assert any(e["url"] == URL for e in report["ok"])

    def test_empty_health_file_returns_empty_report(self):
        report = fh.get_report()
        assert report == {"ok": [], "error": [], "suspect": [], "dead": [], "stale": []}


class TestLogHealthSummary:
    def test_logs_all_ok(self, caplog):
        fh.record_fetch(URL, success=True, entry_count=1)
        import logging
        with caplog.at_level(logging.INFO, logger="root"):
            fh.log_health_summary()
        assert "all" in caplog.text and "ok" in caplog.text

    def test_logs_warning_on_dead(self, caplog):
        fh.record_fetch(URL, success=True, entry_count=5)
        data = fh.load_health()
        data[URL]["status"] = "dead"
        fh.save_health(data)
        import logging
        with caplog.at_level(logging.WARNING, logger="root"):
            fh.log_health_summary()
        assert "dead" in caplog.text.lower()


class TestSignalScore:
    def test_perfect_feed(self):
        entry = {
            "fetches_total": 100,
            "fetches_successful": 100,
            "entries_total": 2000,
            "status": "ok",
        }
        score = fh._signal_score(entry)
        assert score == 100.0

    def test_zero_fetches(self):
        entry = {"fetches_total": 0, "fetches_successful": 0, "entries_total": 0, "status": "ok"}
        assert fh._signal_score(entry) == 0.0

    def test_dead_feed_penalized(self):
        entry = {
            "fetches_total": 100,
            "fetches_successful": 100,
            "entries_total": 2000,
            "status": "dead",
        }
        score = fh._signal_score(entry)
        assert score < 20  # Heavy penalty

    def test_low_productivity(self):
        entry = {
            "fetches_total": 100,
            "fetches_successful": 100,
            "entries_total": 100,  # 1 entry per fetch = low productivity
            "status": "ok",
        }
        score = fh._signal_score(entry)
        assert score < 10  # Low productivity

    def test_partial_success_rate(self):
        entry = {
            "fetches_total": 100,
            "fetches_successful": 50,
            "entries_total": 1000,
            "status": "ok",
        }
        score = fh._signal_score(entry)
        assert 40 < score < 60


class TestSignalScores:
    def test_returns_sorted_list(self):
        fh.record_fetch("https://good.example.com/feed", success=True, entry_count=20)
        fh.record_fetch("https://bad.example.com/feed", success=False)
        result = fh.signal_scores()
        assert isinstance(result, list)
        assert len(result) >= 2
        # Should be sorted by score descending
        scores = [r["signal_score"] for r in result]
        assert scores == sorted(scores, reverse=True)

    def test_entry_has_expected_fields(self):
        fh.record_fetch(URL, success=True, entry_count=5)
        result = fh.signal_scores()
        entry = result[0]
        assert "url" in entry
        assert "status" in entry
        assert "signal_score" in entry
        assert "fetches_total" in entry


class TestGetHealthJson:
    """The API endpoint consumer — /api/feed-health."""

    def test_summary_counts_by_status(self):
        fh.record_fetch("https://ok1.example.com/feed", success=True, entry_count=10)
        fh.record_fetch("https://err1.example.com/feed", success=False)
        payload = fh.get_health_json()
        assert payload["total_tracked"] == 2
        assert payload["ok"] == 1
        assert payload["error"] == 1
        assert isinstance(payload["dead_feeds"], list)
        assert isinstance(payload["suspect_feeds"], list)

    def test_dead_feeds_include_last_success_trimmed(self):
        """Dead feed entries should include a trimmed last_success date
        (first 10 chars = YYYY-MM-DD)."""
        fh.record_fetch(URL, success=True, entry_count=5)
        data = fh.load_health()
        data[URL]["status"] = "dead"
        data[URL]["last_success"] = "2026-01-15T12:34:56+00:00"
        data[URL]["consecutive_errors"] = 10
        fh.save_health(data)
        payload = fh.get_health_json()
        assert payload["dead"] == 1
        assert payload["dead_feeds"][0]["last_success"] == "2026-01-15"
        assert payload["dead_feeds"][0]["errors"] == 10


class TestPrintReport:
    def test_prints_all_sections(self, capsys):
        """print_report is a manual CLI — just verify it runs and outputs
        the expected section headers without crashing."""
        fh.record_fetch("https://ok.example.com/feed", success=True, entry_count=10)
        fh.record_fetch("https://err.example.com/feed", success=False)
        # Force one into suspect so we hit the suspect section loop.
        data = fh.load_health()
        data["https://err.example.com/feed"]["status"] = "suspect"
        fh.save_health(data)
        fh.print_report()
        out = capsys.readouterr().out
        assert "FEED HEALTH REPORT" in out
        assert "Total tracked" in out
        assert "[SUSPECT]" in out

    def test_log_summary_lists_suspect_feeds(self, caplog):
        """Coverage for the suspect-feed logging branch in log_health_summary."""
        fh.record_fetch(URL, success=True, entry_count=5)
        data = fh.load_health()
        data[URL]["status"] = "suspect"
        fh.save_health(data)
        import logging
        with caplog.at_level(logging.WARNING, logger="root"):
            fh.log_health_summary()
        assert "SUSPECT" in caplog.text or "suspect" in caplog.text
