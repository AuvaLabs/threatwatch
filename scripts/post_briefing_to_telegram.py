#!/usr/bin/env python3
"""Standalone Telegram briefing poster — for system-cron daily delivery.

Reads the latest briefing from disk and POSTs it to Telegram unconditionally
(no level gating, no cooldown). Pair with system cron for a guaranteed
once-a-day post regardless of threat level:

    # /etc/cron.d/threatwatch-telegram: post briefing at 08:00 UTC daily
    0 8 * * * deploy /usr/bin/docker exec threatwatch-pipeline \
        python scripts/post_briefing_to_telegram.py

Requires TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in the environment (or
in the .env that the project loads). Exits 0 on success, 1 on failure so
cron can flag delivery problems.
"""
from __future__ import annotations

import json
import argparse
import logging
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
os.chdir(BASE_DIR)
sys.path.insert(0, str(BASE_DIR))

from modules.logger_utils import setup_logger  # noqa: E402
from modules.briefing_generator import BRIEFING_PATH  # noqa: E402
from modules.command_brief import COMMAND_BRIEF_PATH  # noqa: E402
from modules.config import STATE_DIR  # noqa: E402
from modules.utils import write_json_atomic  # noqa: E402


def _record_status(ok: bool, level: object, reason: str) -> None:
    from datetime import datetime, timezone

    try:
        write_json_atomic(STATE_DIR / "telegram_daily_status.json", {
            "attempted_at": datetime.now(timezone.utc).isoformat(),
            "ok": ok,
            "level": str(level or "UNKNOWN"),
            "reason": reason,
        }, indent=2)
    except OSError:
        logging.getLogger("telegram-poster").warning("Could not persist delivery status")


def _load_briefing(log: logging.Logger, *, dry_run: bool) -> dict | None:
    briefing_path = (
        COMMAND_BRIEF_PATH if COMMAND_BRIEF_PATH.exists() else BRIEFING_PATH
    )
    if not briefing_path.exists():
        log.error("Briefing file not found: %s", briefing_path)
        if not dry_run:
            _record_status(False, None, "briefing_missing")
        return None
    try:
        briefing = json.loads(briefing_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.error("Could not load briefing: %s", exc)
        if not dry_run:
            _record_status(False, None, "briefing_invalid")
        return None
    if not isinstance(briefing, dict):
        log.error("Briefing must be a JSON object")
        if not dry_run:
            _record_status(False, None, "briefing_invalid_shape")
        return None
    return briefing


def main(*, dry_run: bool = False) -> int:
    setup_logger()
    log = logging.getLogger("telegram-poster")
    briefing = _load_briefing(log, dry_run=dry_run)
    if briefing is None:
        return 1

    from modules.telegram import (
        TELEGRAM_BOT_TOKEN,
        TELEGRAM_CHAT_ID,
        post_briefing_unconditional,
    )
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log.error("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must both be set")
        if not dry_run:
            _record_status(
                False, briefing.get("threat_level"), "configuration_missing"
            )
        return 1

    if dry_run:
        print(json.dumps({
            "ok": True,
            "dry_run": True,
            "level": briefing.get("threat_level", "UNKNOWN"),
            "destination_configured": True,
        }, separators=(",", ":")))
        return 0

    if post_briefing_unconditional(briefing):
        log.info("Briefing posted to Telegram (level=%s)", briefing.get("threat_level"))
        _record_status(True, briefing.get("threat_level"), "posted")
        return 0
    _record_status(False, briefing.get("threat_level"), "post_failed")
    log.error("Telegram post failed; see warnings above")
    return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    sys.exit(main(dry_run=args.dry_run))
