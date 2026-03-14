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
