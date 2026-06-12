"""Tests for scripts/cleanup.py — retention must never delete live outputs."""

import os
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
