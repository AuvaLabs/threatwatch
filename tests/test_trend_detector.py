import json
import pytest
from unittest.mock import patch
from datetime import datetime, timezone, timedelta

from modules.trend_detector import (
    update_trends,
    get_trends_report,
    _detect_spikes,
)


@pytest.fixture
def mock_trend_file(tmp_path, monkeypatch):
    trend_file = tmp_path / "trends.json"
    monkeypatch.setattr("modules.trend_detector.TREND_FILE", trend_file)
    return trend_file


class TestUpdateTrends:
    def test_creates_trend_data(self, mock_trend_file):
        articles = [
            {"title": "Ransomware hits hospital", "summary": "", "category": "Ransomware"},
            {"title": "Phishing campaign detected", "summary": "", "category": "Phishing"},
            {"title": "Ransomware group LockBit attacks", "summary": "", "category": "Ransomware"},
        ]
        result = update_trends(articles)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        assert today in result["daily_counts"]
        assert result["daily_counts"][today]["categories"]["Ransomware"] == 2
        assert result["daily_counts"][today]["categories"]["Phishing"] == 1

    def test_persists_to_file(self, mock_trend_file):
        articles = [{"title": "Test", "summary": "", "category": "Malware"}]
        update_trends(articles)
        assert mock_trend_file.exists()
        data = json.loads(mock_trend_file.read_text())
        assert "daily_counts" in data

    def test_accumulates_across_runs(self, mock_trend_file):
        articles1 = [{"title": "Ransomware hit", "summary": "", "category": "Ransomware"}]
        update_trends(articles1)

        articles2 = [{"title": "Ransomware hit 2", "summary": "", "category": "Ransomware"}]
        update_trends(articles2)

        data = json.loads(mock_trend_file.read_text())
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        assert data["daily_counts"][today]["categories"]["Ransomware"] == 2

    def test_tracks_keywords(self, mock_trend_file):
        articles = [
            {"title": "LockBit ransomware encrypts files", "summary": "", "category": "Ransomware"},
        ]
        result = update_trends(articles)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        assert result["daily_counts"][today]["keywords"].get("LockBit", 0) >= 1


class TestDetectSpikes:
    def test_detects_spike_above_threshold(self):
        # History: avg 2 ransomware/day, today: 10
        dates = [(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
                 for i in range(7, 0, -1)]
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        daily_counts = {}
        for d in dates:
            daily_counts[d] = {"categories": {"Ransomware": 2}, "keywords": {}}
        daily_counts[today] = {"categories": {"Ransomware": 10}, "keywords": {}}

        spikes = _detect_spikes(daily_counts, today)
        assert len(spikes) >= 1
        assert spikes[0]["keyword"] == "Ransomware"
        assert spikes[0]["spike_ratio"] == 5.0

    def test_no_spike_within_normal_range(self):
        dates = [(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
                 for i in range(7, 0, -1)]
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        daily_counts = {}
        for d in dates:
            daily_counts[d] = {"categories": {"Ransomware": 5}, "keywords": {}}
        daily_counts[today] = {"categories": {"Ransomware": 6}, "keywords": {}}

        spikes = _detect_spikes(daily_counts, today)
        assert len(spikes) == 0

    def test_needs_minimum_history(self):
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        daily_counts = {today: {"categories": {"Ransomware": 100}, "keywords": {}}}
        spikes = _detect_spikes(daily_counts, today)
        assert len(spikes) == 0  # Not enough history


class TestGetTrendsReport:
    def test_returns_no_data_when_empty(self, mock_trend_file):
        report = get_trends_report()
        assert report["status"] == "no_data"

    def test_returns_report_with_data(self, mock_trend_file):
        articles = [
            {"title": "Ransomware hits hospital", "summary": "", "category": "Ransomware"},
        ]
        update_trends(articles)
        report = get_trends_report()
        assert report["status"] == "ok"
        assert "categories_7d" in report
        assert "top_keywords_7d" in report
        assert "daily_totals" in report


class TestSpikeBranches:
    """Explicit coverage for detection branches — emergence, keyword spikes,
    and the below-threshold skip."""

    def test_keyword_spike_detected(self):
        dates = [(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
                 for i in range(7, 0, -1)]
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        daily_counts = {}
        for d in dates:
            daily_counts[d] = {"categories": {}, "keywords": {"LockBit": 2}}
        daily_counts[today] = {"categories": {}, "keywords": {"LockBit": 10}}
        spikes = _detect_spikes(daily_counts, today)
        assert any(s["type"] == "tracked_keyword" and s["keyword"] == "LockBit"
                   for s in spikes)

    def test_new_keyword_emergence(self):
        """A keyword with zero historical count but significant today count
        should be surfaced as 'new_emergence'."""
        dates = [(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
                 for i in range(7, 0, -1)]
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        daily_counts = {d: {"categories": {}, "keywords": {}} for d in dates}
        daily_counts[today] = {"categories": {}, "keywords": {"NovelMalware": 10}}
        spikes = _detect_spikes(daily_counts, today)
        assert any(s["type"] == "new_emergence" for s in spikes)

    def test_below_threshold_skipped(self):
        """Both category and keyword counts under _MIN_COUNT_FOR_SPIKE should
        NOT surface as spikes even with a huge ratio."""
        dates = [(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
                 for i in range(7, 0, -1)]
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        daily_counts = {d: {"categories": {"X": 0}, "keywords": {"Y": 0}} for d in dates}
        # Small today counts — below minimum to qualify as a spike.
        daily_counts[today] = {"categories": {"X": 1}, "keywords": {"Y": 1}}
        spikes = _detect_spikes(daily_counts, today)
        assert spikes == []


class TestUpdateTrendsLogging:
    def test_logs_spike_when_detected(self, mock_trend_file, caplog):
        """Seed historical data then feed a spike run — exercises the
        'TREND SPIKES detected' warning branch."""
        import logging
        trend_file = mock_trend_file
        dates = [(datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
                 for i in range(7, 0, -1)]
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        seed = {d: {"categories": {"Ransomware": 2}, "keywords": {}} for d in dates}
        trend_file.write_text(json.dumps({"daily_counts": seed}))
        # Current run adds 10 Ransomware articles — should spike.
        articles = [
            {"title": f"Ransomware article {i}", "summary": "", "category": "Ransomware"}
            for i in range(10)
        ]
        with caplog.at_level(logging.WARNING, logger="modules.trend_detector"):
            update_trends(articles)
        assert "SPIKES" in caplog.text.upper()


class TestLoadTrendsCorrupt:
    def test_corrupt_file_returns_default(self, mock_trend_file):
        """A corrupt trend file must not crash the pipeline — fall back to
        the empty default."""
        mock_trend_file.write_text("not valid json {{{")
        from modules.trend_detector import _load_trends
        data = _load_trends()
        assert data == {"daily_counts": {}, "generated_at": None}
