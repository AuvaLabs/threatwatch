"""
Freshness detection for the global Intel Brief. Reads briefing.json from
OUTPUT_DIR, computes age from the generated_at timestamp (falling back to file
mtime only when generated_at is absent or unparseable). Returns a structured
result indicating whether the briefing is stale. This module never raises —
all exceptions are caught internally and surfaced via the returned dict.
Provides self-healing flag-file helpers (write_stale_flag / clear_stale_flag)
that write to data/state/briefing_stale.flag; flag is created when stale,
deleted when fresh, requiring no manual cleanup.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from modules.config import OUTPUT_DIR

logger = logging.getLogger(__name__)


def check_briefing_freshness(max_age_hours: float = 3.0) -> dict:
    """Return a freshness dict for briefing.json.

    Keys: stale (bool), age_hours (float), generated_at (str | None), reason (str).
    Never raises.
    """
    briefing_path = OUTPUT_DIR / "briefing.json"

    try:
        stat = briefing_path.stat()
        mtime_epoch = stat.st_mtime
    except (FileNotFoundError, OSError) as exc:
        return {
            "stale": True,
            "age_hours": float("inf"),
            "generated_at": None,
            "reason": f"briefing.json not found or unreadable: {exc}",
        }

    # Attempt to parse generated_at from the JSON content.
    generated_at_str: str | None = None
    generated_at_epoch: float | None = None

    try:
        raw = briefing_path.read_text(encoding="utf-8")
        data = json.loads(raw)
        generated_at_str = data.get("generated_at")
        if generated_at_str:
            ts = generated_at_str
            if ts.endswith("Z"):
                ts = ts[:-1] + "+00:00"
            try:
                dt = datetime.fromisoformat(ts)
            except ValueError:
                dt = datetime.fromisoformat(ts.split(".")[0])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            generated_at_epoch = dt.timestamp()
    except json.JSONDecodeError as exc:
        logger.debug("briefing.json is not valid JSON: %s", exc)
        return {
            "stale": True,
            "age_hours": float("inf"),
            "generated_at": None,
            "reason": f"briefing.json is corrupt (JSON parse error): {exc}",
        }
    except (OSError, ValueError, Exception) as exc:
        logger.debug("Could not read/parse briefing.json: %s", exc)
        return {
            "stale": True,
            "age_hours": float("inf"),
            "generated_at": None,
            "reason": f"could not read or parse briefing.json: {exc}",
        }

    if generated_at_epoch is None:
        # generated_at field absent or unparseable — fall back to mtime.
        effective_epoch = mtime_epoch
    else:
        # generated_at is the authoritative signal for briefing content age.
        # It reflects when the LLM actually produced the brief, not filesystem
        # metadata. File mtime is ignored when generated_at is available: an
        # scp/docker cp race that preserves an old source mtime doesn't matter
        # because generated_at reflects the true generation time.
        effective_epoch = generated_at_epoch

    now_epoch = datetime.now(timezone.utc).timestamp()
    age_s = now_epoch - effective_epoch
    age_hours = age_s / 3600.0

    if age_hours > max_age_hours:
        return {
            "stale": True,
            "age_hours": age_hours,
            "generated_at": generated_at_str,
            "reason": (
                f"briefing is {age_hours:.2f}h old, threshold is {max_age_hours}h"
            ),
        }

    return {
        "stale": False,
        "age_hours": age_hours,
        "generated_at": generated_at_str,
        "reason": "ok",
    }


def write_stale_flag(result: dict) -> None:
    """Write briefing_stale.flag to data/state/. Swallows OSError."""
    flag_path = OUTPUT_DIR.parent / "state" / "briefing_stale.flag"
    try:
        flag_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "stale": result.get("stale"),
            "age_hours": result.get("age_hours"),
            "generated_at": result.get("generated_at"),
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "reason": result.get("reason"),
        }
        flag_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError as exc:
        logger.debug("Could not write stale flag: %s", exc)


def clear_stale_flag() -> None:
    """Delete briefing_stale.flag if present. Idempotent. Swallows errors."""
    flag_path = OUTPUT_DIR.parent / "state" / "briefing_stale.flag"
    try:
        flag_path.unlink()
    except (FileNotFoundError, OSError):
        pass
