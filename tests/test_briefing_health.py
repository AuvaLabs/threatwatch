"""Offline tests for modules/briefing_health.py."""

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_briefing(tmp_path: Path, generated_at: datetime) -> Path:
    output_dir = tmp_path / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    briefing = output_dir / "briefing.json"
    briefing.write_text(
        json.dumps({"generated_at": generated_at.isoformat(), "threat_level": "MODERATE"}),
        encoding="utf-8",
    )
    return briefing


def _monkeypatch_output_dir(monkeypatch, tmp_path: Path):
    output_dir = tmp_path / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    import modules.briefing_health as bh
    monkeypatch.setattr(bh, "OUTPUT_DIR", output_dir)
    return output_dir


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

def test_fresh_file_fresh_timestamp_not_stale(tmp_path, monkeypatch):
    """File written 10 minutes ago with matching mtime — not stale."""
    output_dir = _monkeypatch_output_dir(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    gen_at = now - timedelta(minutes=10)
    briefing = output_dir / "briefing.json"
    briefing.write_text(
        json.dumps({"generated_at": gen_at.isoformat()}), encoding="utf-8"
    )

    from modules.briefing_health import check_briefing_freshness
    result = check_briefing_freshness(max_age_hours=3.0)

    assert result["stale"] is False
    assert result["age_hours"] < 0.5


def test_old_mtime_fresh_generated_at_not_stale(tmp_path, monkeypatch):
    """mtime is 5h ago but generated_at is 10 minutes ago — not stale (scp-race case)."""
    output_dir = _monkeypatch_output_dir(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    gen_at = now - timedelta(minutes=10)
    briefing = output_dir / "briefing.json"
    briefing.write_text(
        json.dumps({"generated_at": gen_at.isoformat()}), encoding="utf-8"
    )
    # Set mtime to 5 hours ago
    old_time = time.time() - 5 * 3600
    os.utime(briefing, (old_time, old_time))

    from modules.briefing_health import check_briefing_freshness
    result = check_briefing_freshness(max_age_hours=3.0)

    assert result["stale"] is False


def test_fresh_mtime_old_generated_at_stale(tmp_path, monkeypatch):
    """generated_at is 6h ago, mtime is just now — stale (generated_at wins)."""
    output_dir = _monkeypatch_output_dir(monkeypatch, tmp_path)
    now = datetime.now(timezone.utc)
    gen_at = now - timedelta(hours=6)
    briefing = output_dir / "briefing.json"
    briefing.write_text(
        json.dumps({"generated_at": gen_at.isoformat()}), encoding="utf-8"
    )
    # mtime is right now (default after write)

    from modules.briefing_health import check_briefing_freshness
    result = check_briefing_freshness(max_age_hours=3.0)

    assert result["stale"] is True
    assert result["age_hours"] >= 5


def test_missing_briefing_is_stale(tmp_path, monkeypatch):
    """No briefing.json — result is stale with reason mentioning missing/not found."""
    _monkeypatch_output_dir(monkeypatch, tmp_path)
    # Do NOT create briefing.json

    from modules.briefing_health import check_briefing_freshness
    result = check_briefing_freshness(max_age_hours=3.0)

    assert result["stale"] is True
    assert result["reason"] is not None
    reason_lower = result["reason"].lower()
    assert any(word in reason_lower for word in ("not found", "missing", "unreadable"))


def test_corrupt_briefing_is_stale_never_raises(tmp_path, monkeypatch):
    """Corrupt JSON in briefing.json — stale, no exception raised."""
    output_dir = _monkeypatch_output_dir(monkeypatch, tmp_path)
    briefing = output_dir / "briefing.json"
    briefing.write_text("{{{ not json }}}", encoding="utf-8")

    from modules.briefing_health import check_briefing_freshness
    # Must not raise
    result = check_briefing_freshness(max_age_hours=3.0)

    assert result["stale"] is True


def test_generated_at_with_z_suffix_parsed(tmp_path, monkeypatch):
    """Z-suffixed ISO timestamps (Anthropic-style) must be parsed correctly."""
    import modules.briefing_health as bh
    output_dir = _monkeypatch_output_dir(monkeypatch, tmp_path)
    briefing = output_dir / "briefing.json"
    # Recent — well within 3h threshold — but uses Z suffix instead of +00:00.
    briefing.write_text(
        json.dumps({"generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}),
        encoding="utf-8",
    )
    result = bh.check_briefing_freshness(max_age_hours=3.0)
    assert result["stale"] is False


def test_generated_at_without_tz_treated_as_utc(tmp_path, monkeypatch):
    """Legacy timestamps without a tz suffix must be assumed UTC, not local."""
    import modules.briefing_health as bh
    output_dir = _monkeypatch_output_dir(monkeypatch, tmp_path)
    briefing = output_dir / "briefing.json"
    # Naive ISO timestamp, no tz — must be assumed UTC.
    naive = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    briefing.write_text(
        json.dumps({"generated_at": naive}),
        encoding="utf-8",
    )
    result = bh.check_briefing_freshness(max_age_hours=3.0)
    assert result["stale"] is False


def test_missing_generated_at_falls_back_to_mtime(tmp_path, monkeypatch):
    """When generated_at is absent, freshness uses the file mtime."""
    import modules.briefing_health as bh
    output_dir = _monkeypatch_output_dir(monkeypatch, tmp_path)
    briefing = output_dir / "briefing.json"
    briefing.write_text(json.dumps({"threat_level": "MODERATE"}), encoding="utf-8")
    # File was just written — mtime is now.
    result = bh.check_briefing_freshness(max_age_hours=3.0)
    assert result["stale"] is False
    assert result["generated_at"] is None


def test_malformed_generated_at_uses_split_fallback(tmp_path, monkeypatch):
    """A generated_at value fromisoformat can't parse directly still succeeds
    via the split('.') fallback in the except ValueError branch."""
    import modules.briefing_health as bh
    output_dir = _monkeypatch_output_dir(monkeypatch, tmp_path)
    briefing = output_dir / "briefing.json"
    # Microseconds with a non-standard suffix that fromisoformat rejects on older pythons.
    # Use an unambiguous truncated format to exercise the fallback.
    now_naive = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")
    briefing.write_text(
        json.dumps({"generated_at": now_naive + ".weird-suffix"}),
        encoding="utf-8",
    )
    # Should not raise — fallback kicks in.
    result = bh.check_briefing_freshness(max_age_hours=3.0)
    assert "stale" in result


def test_write_stale_flag_swallows_oserror(tmp_path, monkeypatch):
    """Flag write failures must not propagate — the staleness check is a
    best-effort self-healing mechanism."""
    import modules.briefing_health as bh
    # Point at a read-only path that can't be created.
    fake_state = tmp_path / "output"
    fake_state.mkdir()
    monkeypatch.setattr(bh, "OUTPUT_DIR", fake_state)
    # Mock mkdir to raise OSError at write time.
    from unittest.mock import patch
    with patch("pathlib.Path.write_text", side_effect=OSError("read-only")):
        # Should not raise.
        bh.write_stale_flag({
            "stale": True, "age_hours": 5, "generated_at": None, "reason": "test"
        })


def test_flag_file_lifecycle(tmp_path, monkeypatch):
    """write_stale_flag creates flag with detected_at; clear_stale_flag removes it idempotently."""
    output_dir = _monkeypatch_output_dir(monkeypatch, tmp_path)
    import modules.briefing_health as bh

    flag_path = output_dir.parent / "state" / "briefing_stale.flag"

    stale_result = {
        "stale": True,
        "age_hours": 5.0,
        "generated_at": "2026-04-09T08:00:00+00:00",
        "reason": "briefing is 5.00h old, threshold is 3h",
    }

    bh.write_stale_flag(stale_result)
    assert flag_path.exists()

    flag_data = json.loads(flag_path.read_text(encoding="utf-8"))
    assert "detected_at" in flag_data
    assert flag_data["stale"] is True

    bh.clear_stale_flag()
    assert not flag_path.exists()

    # Second call on missing file must not raise
    bh.clear_stale_flag()
