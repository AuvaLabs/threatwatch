#!/usr/bin/env python3
"""Restore a ThreatWatch backup in isolation and validate its contents."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

MAX_ARCHIVE_BYTES = 20 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 500_000


class BackupVerificationError(RuntimeError):
    """Raised when a backup cannot be safely restored and validated."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _expected_checksum(archive: Path) -> str | None:
    sidecar = Path(f"{archive}.sha256")
    if not sidecar.is_file():
        return None
    value = sidecar.read_text(encoding="utf-8").split()
    if not value or len(value[0]) != 64:
        raise BackupVerificationError("invalid checksum sidecar")
    return value[0].lower()


def _safe_members(bundle: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = bundle.getmembers()
    if not members:
        raise BackupVerificationError("backup archive is empty")
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise BackupVerificationError("backup has too many archive members")
    if sum(member.size for member in members) > MAX_ARCHIVE_BYTES:
        raise BackupVerificationError("backup expands beyond the safety limit")
    for member in members:
        name = PurePosixPath(member.name)
        if name.is_absolute() or ".." in name.parts:
            raise BackupVerificationError(f"unsafe archive member: {member.name}")
        if not (member.isfile() or member.isdir()):
            raise BackupVerificationError(f"unsupported archive member: {member.name}")
    return members


def _extract(bundle: tarfile.TarFile, members: list[tarfile.TarInfo], target: Path) -> None:
    for member in members:
        destination = target.joinpath(*PurePosixPath(member.name).parts)
        if member.isdir():
            destination.mkdir(parents=True, exist_ok=True)
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        source = bundle.extractfile(member)
        if source is None:
            raise BackupVerificationError(f"cannot read archive member: {member.name}")
        with source, destination.open("wb") as output:
            while chunk := source.read(1024 * 1024):
                output.write(chunk)


def _json_count(root: Path) -> tuple[int, int]:
    files = 0
    items = 0
    for path in root.rglob("*.json"):
        try:
            payload: Any = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            relative = path.relative_to(root)
            raise BackupVerificationError(f"invalid JSON in {relative}: {exc}") from exc
        files += 1
        if isinstance(payload, (dict, list)):
            items += len(payload)
        else:
            items += 1
    return files, items


def _sqlite_count(root: Path) -> tuple[int, int]:
    files = 0
    rows = 0
    database_paths = sorted({
        path
        for suffix in ("*.db", "*.sqlite", "*.sqlite3")
        for path in root.rglob(suffix)
    })
    for path in database_paths:
        try:
            with sqlite3.connect(path) as connection:
                result = connection.execute("PRAGMA integrity_check").fetchone()
                if result != ("ok",):
                    raise BackupVerificationError(
                        f"SQLite integrity check failed for {path.relative_to(root)}",
                    )
                tables = connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
                ).fetchall()
                for (table,) in tables:
                    escaped = str(table).replace('"', '""')
                    rows += connection.execute(f'SELECT COUNT(*) FROM "{escaped}"').fetchone()[0]
        except sqlite3.Error as exc:
            relative = path.relative_to(root)
            raise BackupVerificationError(f"invalid SQLite database {relative}: {exc}") from exc
        files += 1
    if not database_paths:
        raise BackupVerificationError("backup contains no SQLite database")
    return files, rows


def verify_archive(archive_path: str | Path) -> dict[str, Any]:
    """Extract and validate an archive, returning a machine-readable report."""
    archive = Path(archive_path).expanduser().resolve()
    if not archive.is_file():
        raise BackupVerificationError(f"backup archive not found: {archive}")

    actual_checksum = _sha256(archive)
    expected_checksum = _expected_checksum(archive)
    if expected_checksum is not None and expected_checksum != actual_checksum:
        raise BackupVerificationError("backup checksum mismatch")

    try:
        with tempfile.TemporaryDirectory(prefix="threatwatch-restore-") as temp_dir:
            target = Path(temp_dir)
            with tarfile.open(archive, "r:gz") as bundle:
                members = _safe_members(bundle)
                _extract(bundle, members, target)
            sqlite_files, sqlite_rows = _sqlite_count(target)
            json_files, json_items = _json_count(target)
    except (tarfile.TarError, OSError) as exc:
        raise BackupVerificationError(f"backup restore failed: {exc}") from exc

    return {
        "ok": True,
        "archive": archive.name,
        "sha256": actual_checksum,
        "file_count": sum(member.isfile() for member in members),
        "sqlite_files": sqlite_files,
        "sqlite_rows": sqlite_rows,
        "json_files": json_files,
        "json_items": json_items,
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", help="Path to a tw_*.tgz archive")
    parser.add_argument("--output", type=Path, help="Write the JSON report to this path")
    args = parser.parse_args()
    try:
        report = verify_archive(args.archive)
    except BackupVerificationError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    rendered = json.dumps(report, sort_keys=True)
    if args.output:
        args.output.write_text(f"{rendered}\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
