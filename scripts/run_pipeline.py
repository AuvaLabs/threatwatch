#!/usr/bin/env python3
"""Pipeline scheduler with graceful SIGTERM handling.

Replaces the shell while-loop in docker-compose so that:
- SIGTERM stops the scheduler cleanly between runs
- Interval is configurable via PIPELINE_INTERVAL env var (default 600s)
- Daily cleanup runs every 144 cycles (~24h at default interval)
"""
import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# Scheduler heartbeat — touched on every loop tick so /api/health has a cheap
# liveness signal independent of how long an individual pipeline run takes.
# An individual run can take 3-4 hours because of LLM briefing work, which is
# much longer than the configured INTERVAL; using the last completed run as
# the freshness signal made healthy pipelines read as "stale".
_HEARTBEAT_PATH = Path("/app/data/state/scheduler_heartbeat.txt")


def _heartbeat() -> None:
    try:
        _HEARTBEAT_PATH.parent.mkdir(parents=True, exist_ok=True)
        _HEARTBEAT_PATH.write_text(str(time.time()))
    except OSError:
        pass  # non-fatal

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [scheduler] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

INTERVAL = int(os.environ.get("PIPELINE_INTERVAL", "600"))
CLEANUP_EVERY = int(os.environ.get("CLEANUP_EVERY", "144"))
# Run AI enrichment every Nth tick. Default: 3 ticks (30 min) between AI
# passes. Independent of the fetch pipeline so Groq rate limits don't drag
# feed ingestion. Set to 0 to disable out-of-band AI entirely (e.g. when
# AI_ENRICHMENT_INLINE=1 is preferred).
AI_ENRICHMENT_EVERY = int(os.environ.get("AI_ENRICHMENT_EVERY", "3"))

_shutdown = False


def _on_signal(sig, _frame):
    global _shutdown
    logging.info("Signal %s received — will stop after current sleep", sig)
    _shutdown = True


signal.signal(signal.SIGTERM, _on_signal)
signal.signal(signal.SIGINT, _on_signal)


def _run(script: str) -> int:
    logging.info("Running: python %s", script)
    result = subprocess.run([sys.executable, script])
    if result.returncode != 0:
        logging.warning("Script exited with code %d: %s", result.returncode, script)
    return result.returncode


def _interruptible_sleep(seconds: int) -> bool:
    """Sleep in 1-second ticks so SIGTERM is handled promptly.

    Returns True if the full sleep completed, False if interrupted.
    """
    for _ in range(seconds):
        if _shutdown:
            return False
        time.sleep(1)
    return True


def main() -> None:
    logging.info("ThreatWatch pipeline scheduler starting (interval=%ds)", INTERVAL)

    _heartbeat()
    _run("scripts/cleanup.py")
    _run("threatdigest_main.py")
    _heartbeat()

    run_count = 0
    while not _shutdown:
        logging.info("Sleeping %ds until next run…", INTERVAL)
        _heartbeat()
        if not _interruptible_sleep(INTERVAL):
            break

        if _shutdown:
            break

        run_count += 1
        logging.info("Pipeline run #%d starting", run_count)
        _heartbeat()
        _run("threatdigest_main.py")
        _heartbeat()

        # Out-of-band AI enrichment on its own cadence. Guards:
        # - AI_ENRICHMENT_EVERY=0 → disabled (falls back to inline via env)
        # - AI_ENRICHMENT_INLINE=1 → also skip out-of-band (belt + braces)
        if (
            AI_ENRICHMENT_EVERY > 0
            and run_count % AI_ENRICHMENT_EVERY == 0
            and os.environ.get("AI_ENRICHMENT_INLINE", "1") != "1"
        ):
            logging.info("AI enrichment run (every %d pipeline ticks)", AI_ENRICHMENT_EVERY)
            _run("scripts/run_ai_enrichment.py")
            _heartbeat()

        if run_count % CLEANUP_EVERY == 0:
            logging.info("Daily cleanup (every %d runs)", CLEANUP_EVERY)
            _run("scripts/cleanup.py")

    logging.info("Scheduler stopped cleanly")


if __name__ == "__main__":
    main()
