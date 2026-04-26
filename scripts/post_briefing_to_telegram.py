#!/usr/bin/env python3
"""Standalone Telegram briefing poster — for system-cron daily delivery.

Reads the latest briefing from disk and POSTs it to Telegram unconditionally
(no level gating, no cooldown). Pair with system cron for a guaranteed
once-a-day post regardless of threat level:

    # /etc/cron.d/threatwatch-telegram — post briefing at 08:00 UTC daily
    0 8 * * * deploy /home/deploy/threatwatch/scripts/post_briefing_to_telegram.py

Requires TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in the environment (or
in the .env that the project loads). Exits 0 on success, 1 on failure so
cron can flag delivery problems.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
os.chdir(BASE_DIR)
sys.path.insert(0, str(BASE_DIR))

from modules.logger_utils import setup_logger  # noqa: E402

_BRIEFING_PATH = BASE_DIR / "data" / "output" / "briefing.json"


def main() -> int:
    setup_logger()
    log = logging.getLogger("telegram-poster")

    if not _BRIEFING_PATH.exists():
        log.error("Briefing file not found: %s", _BRIEFING_PATH)
        return 1

    try:
        briefing = json.loads(_BRIEFING_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        log.error("Could not load briefing: %s", e)
        return 1

    from modules.telegram import (
        TELEGRAM_BOT_TOKEN,
        TELEGRAM_CHAT_ID,
        post_briefing_unconditional,
    )
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log.error("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must both be set")
        return 1

    if post_briefing_unconditional(briefing):
        log.info("Briefing posted to Telegram (level=%s)", briefing.get("threat_level"))
        return 0
    log.error("Telegram post failed — see warnings above")
    return 1


if __name__ == "__main__":
    sys.exit(main())
