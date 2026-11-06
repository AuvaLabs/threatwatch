#!/usr/bin/env python3
"""Pull, restore-verify, and report the latest ThreatWatch backup offsite."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from modules.utils import write_json_atomic
from scripts.verify_backup import verify_archive

_ARCHIVE_RE = re.compile(r"^tw_\d{8}_\d{6}\.tgz$")
_SAFE_REMOTE_DIR_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")
_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9_.@-]+$")
_SAFE_CONTAINER_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def _validate_remote_dir(value: str) -> str:
    if not _SAFE_REMOTE_DIR_RE.fullmatch(value) or ".." in Path(value).parts:
        raise ValueError("source directory must be a safe absolute path")
    return value.rstrip("/") or "/"


def _validate_token(value: str, pattern: re.Pattern[str], label: str) -> str:
    if not pattern.fullmatch(value):
        raise ValueError(f"{label} contains unsupported characters")
    return value


def select_latest_archive(output: str) -> str:
    names = sorted({line.strip() for line in output.splitlines() if _ARCHIVE_RE.fullmatch(line.strip())})
    if not names:
        raise RuntimeError("No timestamped ThreatWatch backup found at the source")
    return names[-1]


def build_status(report: dict[str, Any], *, location: str) -> dict[str, Any]:
    if report.get("ok") is not True:
        raise ValueError("restore verification report is not successful")
    return {
        "configured": True,
        "ok": True,
        "method": "pull-rsync",
        "location": location,
        "archive": report.get("archive"),
        "sha256": report.get("sha256"),
        "verified_at": report.get("verified_at"),
        "restore_verified": True,
        "sqlite_files": report.get("sqlite_files"),
        "json_files": report.get("json_files"),
    }


def _run(command: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=True,
        input=input_text,
        capture_output=True,
        text=True,
    )


def _latest_remote_archive(host: str, source_dir: str) -> str:
    remote_command = shlex.join([
        "find",
        source_dir,
        "-maxdepth", "1",
        "-type", "f",
        "-name", "tw_*.tgz",
        "-printf", "%f\\n",
    ])
    result = _run(["ssh", host, remote_command])
    return select_latest_archive(result.stdout)


def _pull_files(host: str, source_dir: str, destination: Path, archive_name: str) -> Path:
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / archive_name
    checksum = Path(f"{archive}.sha256")
    remote_base = f"{host}:{source_dir}/"
    _run([
        "rsync", "-a", "--partial",
        f"{remote_base}{archive_name}",
        f"{remote_base}{archive_name}.sha256",
        f"{destination}/",
    ])
    if not archive.is_file() or not checksum.is_file():
        raise RuntimeError("Offsite transfer did not produce the archive and checksum")
    return archive


def _publish_status(host: str, container: str, status: dict[str, Any]) -> None:
    target = "/app/data/state/offsite_backup_status.json"
    code = (
        "import json,os,sys,tempfile; "
        "data=sys.stdin.read(); json.loads(data); "
        "os.makedirs(os.path.dirname(sys.argv[1]),exist_ok=True); "
        "fd,tmp=tempfile.mkstemp(dir=os.path.dirname(sys.argv[1])); "
        "f=os.fdopen(fd,'w'); f.write(data); f.flush(); os.fsync(f.fileno()); f.close(); "
        "os.replace(tmp,sys.argv[1])"
    )
    remote_command = shlex.join(["docker", "exec", "-i", container, "python3", "-c", code, target])
    _run(["ssh", host, remote_command], input_text=json.dumps(status, sort_keys=True) + "\n")


def sync_offsite_backup(
    *,
    source_host: str,
    source_dir: str,
    destination: Path,
    publish_host: str,
    publish_container: str,
    location: str,
) -> dict[str, Any]:
    host = _validate_token(source_host, _SAFE_HOST_RE, "source host")
    status_host = _validate_token(publish_host, _SAFE_HOST_RE, "publish host")
    container = _validate_token(publish_container, _SAFE_CONTAINER_RE, "publish container")
    safe_source_dir = _validate_remote_dir(source_dir)
    archive_name = _latest_remote_archive(host, safe_source_dir)
    archive = _pull_files(host, safe_source_dir, destination.resolve(), archive_name)
    report = verify_archive(archive)
    status = build_status(report, location=location)
    write_json_atomic(destination / "offsite_backup_status.json", status, ensure_ascii=False, indent=2)
    _publish_status(status_host, container, status)
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-host", required=True)
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--publish-host", required=True)
    parser.add_argument("--publish-container", default="threatwatch-pipeline")
    parser.add_argument("--location", default="offsite")
    args = parser.parse_args(argv)
    try:
        status = sync_offsite_backup(
            source_host=args.source_host,
            source_dir=args.source_dir,
            destination=args.destination,
            publish_host=args.publish_host,
            publish_container=args.publish_container,
            location=args.location,
        )
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    print(json.dumps(status, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
