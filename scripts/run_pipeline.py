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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [scheduler] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

INTERVAL = int(os.environ.get("PIPELINE_INTERVAL", "600"))
CLEANUP_EVERY = int(os.environ.get("CLEANUP_EVERY", "144"))

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

    _run("scripts/cleanup.py")
    _run("threatdigest_main.py")

    run_count = 0
    while not _shutdown:
        logging.info("Sleeping %ds until next run…", INTERVAL)
        if not _interruptible_sleep(INTERVAL):
            break

        if _shutdown:
            break

        run_count += 1
        logging.info("Pipeline run #%d starting", run_count)
        _run("threatdigest_main.py")

        if run_count % CLEANUP_EVERY == 0:
            logging.info("Daily cleanup (every %d runs)", CLEANUP_EVERY)
            _run("scripts/cleanup.py")

    logging.info("Scheduler stopped cleanly")


if __name__ == "__main__":
    main()
