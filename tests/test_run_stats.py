"""Tests for modules/run_stats.py — RunStats data collection and persistence."""
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

import modules.run_stats as rs


@pytest.fixture(autouse=True)
def isolated_stats_file(tmp_path):
    stats_path = tmp_path / "stats.json"
    with patch.object(rs, "STATS_FILE", stats_path):
        yield stats_path


class TestLoadStats:
    def test_returns_empty_runs_when_no_file(self):
        assert rs._load_stats() == {"runs": []}

    def test_loads_existing_file(self, isolated_stats_file):
        data = {"runs": [{"started_at": "2026-01-01T00:00:00+00:00"}]}
        isolated_stats_file.write_text(json.dumps(data), encoding="utf-8")
        assert rs._load_stats() == data

    def test_returns_empty_on_corrupt_json(self, isolated_stats_file):
        isolated_stats_file.write_text("not json", encoding="utf-8")
        assert rs._load_stats() == {"runs": []}


class TestRunStatsInit:
    def test_initial_counters_are_zero(self):
        stats = rs.RunStats()
        assert stats.feeds_loaded == 0
        assert stats.articles_fetched == 0
        assert stats.cyber_articles == 0
        assert stats.budget_exceeded is False

    def test_started_at_is_set(self):
        stats = rs.RunStats()
        assert stats.started_at  # not empty/None


class TestRunStatsFinalize:
    def test_finalize_writes_stats_file(self, isolated_stats_file):
        stats = rs.RunStats()
        stats.articles_fetched = 10
        stats.cyber_articles = 5

        mock_ai = MagicMock()
        mock_ai.get_failure_stats.return_value = {}
        with patch("modules.run_stats.get_today_spend", return_value=0.01), \
             patch("modules.run_stats.get_total_spend", return_value=0.05), \
             patch.dict("sys.modules", {"modules.ai_engine": mock_ai}):
            stats.finalize()

        saved = json.loads(isolated_stats_file.read_text())
        assert len(saved["runs"]) == 1
        run = saved["runs"][0]
        assert run["articles_fetched"] == 10
        assert run["cyber_articles"] == 5
        assert "completed_at" in run

    def test_finalize_keeps_at_most_100_runs(self, isolated_stats_file):
        data = {"runs": [{"started_at": f"run-{i}"} for i in range(100)]}
        isolated_stats_file.write_text(json.dumps(data), encoding="utf-8")

        stats = rs.RunStats()
        mock_ai = MagicMock()
        mock_ai.get_failure_stats.return_value = {}
        with patch("modules.run_stats.get_today_spend", return_value=0.0), \
             patch("modules.run_stats.get_total_spend", return_value=0.0), \
             patch.dict("sys.modules", {"modules.ai_engine": mock_ai}):
            stats.finalize()

        saved = json.loads(isolated_stats_file.read_text())
        assert len(saved["runs"]) == 100  # still 100 (oldest dropped)

    def test_finalize_handles_missing_ai_engine(self, isolated_stats_file):
        stats = rs.RunStats()
        with patch("modules.run_stats.get_today_spend", return_value=0.0), \
             patch("modules.run_stats.get_total_spend", return_value=0.0), \
             patch.dict("sys.modules", {"modules.ai_engine": None}):
            stats.finalize()  # should not raise (try/except catches ImportError)

        assert isolated_stats_file.exists()
