import io
import json
import sqlite3
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest


def _archive(tmp_path: Path, *, corrupt_json: bool = False) -> Path:
    source = tmp_path / "source"
    (source / "state").mkdir(parents=True)
    (source / "output").mkdir()
    with sqlite3.connect(source / "articles.db") as connection:
        connection.execute("CREATE TABLE articles (id INTEGER PRIMARY KEY, title TEXT)")
        connection.execute("INSERT INTO articles (title) VALUES (?)", ("Test report",))
    (source / "state" / "feed_health.json").write_text(
        json.dumps({"feed": {"status": "ok"}}), encoding="utf-8",
    )
    (source / "output" / "daily_latest.json").write_text(
        "{" if corrupt_json else json.dumps([{"title": "Test report"}]),
        encoding="utf-8",
    )
    archive = tmp_path / "tw_test.tgz"
    with tarfile.open(archive, "w:gz") as bundle:
        for path in sorted(source.rglob("*")):
            bundle.add(path, arcname=path.relative_to(source))
    return archive


def test_verify_archive_restores_and_checks_structured_data(tmp_path):
    from scripts.verify_backup import verify_archive

    report = verify_archive(_archive(tmp_path))

    assert report["ok"] is True
    assert report["sha256"]
    assert report["file_count"] >= 3
    assert report["sqlite_files"] == 1
    assert report["sqlite_rows"] == 1
    assert report["json_files"] == 2
    assert report["json_items"] == 2
    assert report["verified_at"].endswith("+00:00")


def test_verify_archive_rejects_corrupt_json(tmp_path):
    from scripts.verify_backup import BackupVerificationError, verify_archive

    with pytest.raises(BackupVerificationError, match="invalid JSON"):
        verify_archive(_archive(tmp_path, corrupt_json=True))


def test_verify_archive_rejects_path_traversal(tmp_path):
    from scripts.verify_backup import BackupVerificationError, verify_archive

    archive = tmp_path / "unsafe.tgz"
    with tarfile.open(archive, "w:gz") as bundle:
        member = tarfile.TarInfo("../outside.json")
        payload = b"{}"
        member.size = len(payload)
        bundle.addfile(member, io.BytesIO(payload))

    with pytest.raises(BackupVerificationError, match="unsafe archive member"):
        verify_archive(archive)


def test_verify_archive_enforces_checksum_sidecar(tmp_path):
    from scripts.verify_backup import BackupVerificationError, verify_archive

    archive = _archive(tmp_path)
    archive.with_suffix(archive.suffix + ".sha256").write_text(
        f"{'0' * 64}  {archive.name}\n", encoding="utf-8",
    )

    with pytest.raises(BackupVerificationError, match="checksum mismatch"):
        verify_archive(archive)


def test_verify_archive_rejects_missing_archive(tmp_path):
    from scripts.verify_backup import BackupVerificationError, verify_archive

    with pytest.raises(BackupVerificationError, match="not found"):
        verify_archive(tmp_path / "missing.tgz")


def test_verify_archive_rejects_archive_without_database(tmp_path):
    from scripts.verify_backup import BackupVerificationError, verify_archive

    archive = tmp_path / "no-database.tgz"
    with tarfile.open(archive, "w:gz") as bundle:
        member = tarfile.TarInfo("state/status.json")
        payload = b"{}"
        member.size = len(payload)
        bundle.addfile(member, io.BytesIO(payload))

    with pytest.raises(BackupVerificationError, match="no SQLite"):
        verify_archive(archive)


def test_verify_archive_rejects_invalid_database(tmp_path):
    from scripts.verify_backup import BackupVerificationError, verify_archive

    archive = tmp_path / "invalid-database.tgz"
    with tarfile.open(archive, "w:gz") as bundle:
        member = tarfile.TarInfo("articles.db")
        payload = b"not sqlite"
        member.size = len(payload)
        bundle.addfile(member, io.BytesIO(payload))

    with pytest.raises(BackupVerificationError, match="invalid SQLite"):
        verify_archive(archive)


def test_verify_archive_rejects_links_and_excessive_expansion():
    from scripts.verify_backup import (
        MAX_ARCHIVE_BYTES,
        BackupVerificationError,
        _safe_members,
    )

    link = tarfile.TarInfo("linked.db")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    with pytest.raises(BackupVerificationError, match="unsupported archive member"):
        _safe_members(type("Bundle", (), {"getmembers": lambda self: [link]})())

    huge = tarfile.TarInfo("huge.db")
    huge.size = MAX_ARCHIVE_BYTES + 1
    with pytest.raises(BackupVerificationError, match="expands beyond"):
        _safe_members(type("Bundle", (), {"getmembers": lambda self: [huge]})())


def test_cli_writes_machine_readable_report(tmp_path):
    archive = _archive(tmp_path)
    report = tmp_path / "report.json"

    result = subprocess.run(
        [sys.executable, "scripts/verify_backup.py", str(archive), "--output", str(report)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert json.loads(result.stdout)["ok"] is True
    assert json.loads(report.read_text(encoding="utf-8"))["ok"] is True


def test_cli_returns_failure_json(tmp_path):
    result = subprocess.run(
        [sys.executable, "scripts/verify_backup.py", str(tmp_path / "missing.tgz")],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert json.loads(result.stdout)["ok"] is False
