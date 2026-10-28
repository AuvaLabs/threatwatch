"""Persist authoritative Sol command editions and interim intelligence deltas."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from modules.config import OUTPUT_DIR
from modules.utils import write_json_atomic

logger = logging.getLogger(__name__)

COMMAND_BRIEF_PATH = OUTPUT_DIR / "command_brief.json"
INTELLIGENCE_DELTA_PATH = OUTPUT_DIR / "intelligence_delta.json"
COMMAND_BRIEF_HISTORY_DIR = OUTPUT_DIR / "command_briefs"
_SOL_PROVIDER = "modelservices/gpt-6.1-sol"


def _valid_sources(briefing: dict[str, Any]) -> list[dict[str, Any]]:
    sources = briefing.get("source_articles")
    if not isinstance(sources, list):
        return []
    return [
        source for source in sources
        if isinstance(source, dict) and str(source.get("link") or "").startswith(("https://", "http://"))
    ]


def _edition_id(generated_at: object) -> str | None:
    if not isinstance(generated_at, str):
        return None
    try:
        parsed = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _load_command_brief(path=COMMAND_BRIEF_PATH) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _write_command_brief(
    briefing: dict[str, Any], edition_id: str, command_path, delta_path, history_dir,
) -> None:
    command = {**briefing, "edition_type": "command_brief", "edition_id": edition_id}
    write_json_atomic(command_path, command, indent=2, ensure_ascii=False)
    history_path = history_dir / f"{edition_id}.json"
    write_json_atomic(history_path, command, indent=2, ensure_ascii=False)
    write_json_atomic(
        delta_path,
        {
            "schema_version": 1,
            "available": False,
            "reason": "command_brief_current",
            "command_edition_id": edition_id,
            "generated_at": briefing["generated_at"],
        },
        indent=2,
        ensure_ascii=False,
    )


def _write_delta(briefing: dict[str, Any], command: dict[str, Any], delta_path) -> None:
    command_links = {
        source.get("link") for source in _valid_sources(command)
    }
    new_indexes = [
        source.get("index") for source in _valid_sources(briefing)
        if source.get("link") not in command_links and isinstance(source.get("index"), int)
    ]
    delta = {
        **briefing,
        "schema_version": 1,
        "available": True,
        "edition_type": "intelligence_delta",
        "command_edition_id": command.get("edition_id"),
        "command_generated_at": command.get("generated_at"),
        "threat_level_changed": briefing.get("threat_level") != command.get("threat_level"),
        "new_source_indexes": new_indexes,
    }
    write_json_atomic(
        delta_path, delta, indent=2, ensure_ascii=False,
    )


def update_briefing_products(
    briefing: dict[str, Any], *, output_dir=None,
) -> str | None:
    """Update command or delta artifacts without replacing a prior Sol edition."""
    command_path = COMMAND_BRIEF_PATH if output_dir is None else output_dir / "command_brief.json"
    delta_path = INTELLIGENCE_DELTA_PATH if output_dir is None else output_dir / "intelligence_delta.json"
    history_dir = COMMAND_BRIEF_HISTORY_DIR if output_dir is None else output_dir / "command_briefs"
    edition_id = _edition_id(briefing.get("generated_at"))
    if not edition_id or not _valid_sources(briefing):
        logger.warning("Briefing product rejected: missing timestamp or valid sources")
        return None
    if briefing.get("provider") == _SOL_PROVIDER:
        _write_command_brief(
            briefing, edition_id, command_path, delta_path, history_dir,
        )
        return "command_brief"
    command = _load_command_brief(command_path)
    if command is None:
        return None
    _write_delta(briefing, command, delta_path)
    return "intelligence_delta"
