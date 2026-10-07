"""Freshness status for analyst-facing generated intelligence artifacts."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from modules.config import OUTPUT_DIR


_ARTIFACTS = {
    "global_briefing": ("briefing.json", 3.0),
    "top_stories": ("top_stories.json", 3.0),
    "regional_na": ("briefing_na.json", 3.0),
    "regional_emea": ("briefing_emea.json", 3.0),
    "regional_apac": ("briefing_apac.json", 3.0),
}


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc)


def _artifact_status(path: Path, max_age_hours: float) -> dict[str, Any]:
    if not path.exists():
        return {"ok": False, "stale": True, "age_hours": None, "reason": "missing"}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"ok": False, "stale": True, "age_hours": None, "reason": "invalid"}
    generated_at = _parse_timestamp(data.get("generated_at"))
    if generated_at is None:
        return {"ok": False, "stale": True, "age_hours": None, "reason": "timestamp_missing"}
    age_hours = max(
        0.0,
        (datetime.now(timezone.utc) - generated_at).total_seconds() / 3600,
    )
    stale = age_hours > max_age_hours
    return {
        "ok": not stale,
        "stale": stale,
        "age_hours": round(age_hours, 2),
        "generated_at": generated_at.isoformat(),
        "reason": "stale" if stale else "fresh",
    }


def check_artifact_health(output_dir: Path = OUTPUT_DIR) -> dict[str, Any]:
    """Return freshness for every critical generated intelligence product."""
    configured = any((output_dir / filename).exists() for filename, _ in _ARTIFACTS.values())
    capabilities = {
        name: _artifact_status(output_dir / filename, max_age)
        for name, (filename, max_age) in _ARTIFACTS.items()
    }
    stale = [name for name, status in capabilities.items() if not status["ok"]]
    failing: list[str] = []
    state_path = output_dir.parent / "state" / "ai_health.json"
    try:
        run_status = json.loads(state_path.read_text(encoding="utf-8"))
        checked_at = _parse_timestamp(run_status.get("generated_at"))
        recent = checked_at and (
            datetime.now(timezone.utc) - checked_at
        ).total_seconds() <= 3 * 3600
        if recent:
            failing = [
                name for name, status in run_status.get("capabilities", {}).items()
                if not status.get("ok", False)
            ]
    except (OSError, json.JSONDecodeError, AttributeError):
        pass
    return {
        "configured": configured,
        "ok": configured and not stale and not failing,
        "stale_capabilities": stale,
        "failing_capabilities": failing,
        "capabilities": capabilities,
    }
