"""Tests for the pull-based offsite backup verifier."""

from pathlib import Path

import pytest

from scripts.sync_offsite_backup import (
    _validate_remote_dir,
    build_status,
    select_latest_archive,
)


def test_select_latest_archive_uses_timestamped_backup_names():
    output = "\n".join([
        "tw_20261105_031500.tgz",
        "notes.txt",
        "tw_20261106_031500.tgz",
        "tw_bad.tgz",
    ])

    assert select_latest_archive(output) == "tw_20261106_031500.tgz"


def test_select_latest_archive_requires_a_valid_backup():
    with pytest.raises(RuntimeError, match="No timestamped ThreatWatch backup"):
        select_latest_archive("notes.txt\n")


@pytest.mark.parametrize("path", ["relative/path", "/tmp/path with spaces", "/tmp/path;touch-x"])
def test_remote_directory_rejects_unsafe_values(path):
    with pytest.raises(ValueError):
        _validate_remote_dir(path)


def test_build_status_records_independent_restore_proof():
    report = {
        "ok": True,
        "archive": "tw_20261106_031500.tgz",
        "sha256": "a" * 64,
        "verified_at": "2026-11-06T04:00:00+00:00",
        "sqlite_files": 2,
        "json_files": 20,
    }

    status = build_status(report, location="commandcenter")

    assert status == {
        "configured": True,
        "ok": True,
        "method": "pull-rsync",
        "location": "commandcenter",
        "archive": "tw_20261106_031500.tgz",
        "sha256": "a" * 64,
        "verified_at": "2026-11-06T04:00:00+00:00",
        "restore_verified": True,
        "sqlite_files": 2,
        "json_files": 20,
    }
