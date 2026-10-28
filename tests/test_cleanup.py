"""Tests for scripts/cleanup.py — retention must never delete live outputs."""

import os
import json
import time
from unittest.mock import patch

from scripts import cleanup


def _age(path, days):
    old = time.time() - days * 86400
    os.utime(path, (old, old))


class TestCleanupOldOutputs:
    def test_live_files_survive_any_age(self, tmp_path):
        live = tmp_path / "daily_latest.json"
        live.write_text("[]")
        _age(live, cleanup.OUTPUT_RETENTION_DAYS + 100)
        with patch.object(cleanup, "OUTPUT_DIR", tmp_path):
            cleanup.cleanup_old_outputs()
        assert live.exists(), "live output file must never be age-deleted"

    def test_every_known_live_file_is_protected(self, tmp_path):
        for name in cleanup._LIVE_OUTPUT_FILES:
            f = tmp_path / name
            f.write_text("{}")
            _age(f, cleanup.OUTPUT_RETENTION_DAYS + 1)
        with patch.object(cleanup, "OUTPUT_DIR", tmp_path):
            cleanup.cleanup_old_outputs()
        survivors = {p.name for p in tmp_path.iterdir()}
        assert survivors == set(cleanup._LIVE_OUTPUT_FILES)

    def test_old_archive_snapshots_are_deleted(self, tmp_path):
        hourly = tmp_path / "hourly"
        hourly.mkdir()
        snap = hourly / "2025-01-01_00.json"
        snap.write_text("[]")
        _age(snap, cleanup.ARCHIVE_RETENTION_DAYS + 5)
        with patch.object(cleanup, "OUTPUT_DIR", tmp_path):
            cleanup.cleanup_old_outputs()
        assert not snap.exists()

    def test_recent_archive_snapshots_are_kept(self, tmp_path):
        hourly = tmp_path / "hourly"
        hourly.mkdir()
        snap = hourly / "recent.json"
        snap.write_text("[]")
        with patch.object(cleanup, "OUTPUT_DIR", tmp_path):
            cleanup.cleanup_old_outputs()
        assert snap.exists()


class TestCleanupNoiseArticles:
    def test_removes_only_confirmed_noise_from_live_corpus(self, tmp_path):
        output = tmp_path / "daily_latest.json"
        output.write_text(json.dumps([
            {"title": "Company launches new cybersecurity product solution"},
            {"title": "Attackers exploit Chrome zero-day in the wild"},
        ]))

        with patch.object(cleanup, "OUTPUT_DIR", tmp_path):
            assert cleanup.cleanup_noise_articles() == 1

        assert json.loads(output.read_text()) == [
            {"title": "Attackers exploit Chrome zero-day in the wild"},
        ]

    def test_invalid_live_corpus_is_left_unchanged(self, tmp_path):
        output = tmp_path / "hourly_latest.json"
        output.write_text("not-json")

        with patch.object(cleanup, "OUTPUT_DIR", tmp_path):
            assert cleanup.cleanup_noise_articles() == 0

        assert output.read_text() == "not-json"


class TestRepairKnownClassifications:
    def test_repairs_zero_day_that_was_labeled_as_breach(self, tmp_path):
        output = tmp_path / "daily_latest.json"
        output.write_text(json.dumps([{
            "title": "Attackers Exploit Leaked Zero-Day Flaws in PHP",
            "category": "Data Breach",
        }]))

        with patch.object(cleanup, "OUTPUT_DIR", tmp_path):
            assert cleanup.repair_known_classifications() == 1

        repaired = json.loads(output.read_text())
        assert repaired[0]["category"] == "Zero-Day Exploit"

    def test_does_not_reclassify_unrelated_breach(self, tmp_path):
        output = tmp_path / "hourly_latest.json"
        original = [{"title": "Hospital confirms data breach", "category": "Data Breach"}]
        output.write_text(json.dumps(original))

        with patch.object(cleanup, "OUTPUT_DIR", tmp_path):
            assert cleanup.repair_known_classifications() == 0

        assert json.loads(output.read_text()) == original
