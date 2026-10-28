"""Tests for the bounded Model Services subscription route."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from modules import model_services_quota as quota


def _configure(
    monkeypatch,
    tmp_path,
    *,
    luna_limit=24,
    luna_cooldown=3600,
    sol_limit=2,
    sol_cooldown=43200,
):
    monkeypatch.setattr(quota, "USAGE_FILE", tmp_path / "usage.json")
    monkeypatch.setattr(quota, "LOCK_FILE", tmp_path / "usage.lock")
    monkeypatch.setattr(quota, "MODEL_SERVICES_LUNA_DAILY_CALL_LIMIT", luna_limit)
    monkeypatch.setattr(
        quota, "MODEL_SERVICES_LUNA_CALLER_COOLDOWN_SECONDS", luna_cooldown,
    )
    monkeypatch.setattr(
        quota, "MODEL_SERVICES_LUNA_CALLERS", frozenset({"top_stories"}),
    )
    monkeypatch.setattr(quota, "MODEL_SERVICES_SOL_DAILY_CALL_LIMIT", sol_limit)
    monkeypatch.setattr(
        quota, "MODEL_SERVICES_SOL_CALLER_COOLDOWN_SECONDS", sol_cooldown,
    )
    monkeypatch.setattr(quota, "MODEL_SERVICES_SOL_CALLERS", frozenset({"briefing"}))
    monkeypatch.setattr(quota, "MODEL_SERVICES_SOL_SCHEDULE_HOURS_UTC", ())
    monkeypatch.setattr(quota, "MODEL_SERVICES_SOL_SCHEDULE_WINDOW_MINUTES", 180)


def test_claim_rejects_unapproved_caller(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)

    assert quota.claim("luna", "summaries") is False
    assert quota.claim("unknown", "top_stories") is False
    assert not quota.USAGE_FILE.exists()


def test_claim_enforces_per_caller_cooldown(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    now = datetime(2026, 10, 18, 8, 0, tzinfo=timezone.utc)

    assert quota.claim("sol", "briefing", now=now) is True
    assert quota.claim("sol", "briefing", now=now + timedelta(hours=6)) is False
    assert quota.claim("luna", "top_stories", now=now + timedelta(hours=1)) is True
    assert quota.claim("sol", "briefing", now=now + timedelta(hours=12)) is True


def test_claim_enforces_daily_limit(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, luna_limit=2, luna_cooldown=0)
    now = datetime(2026, 10, 18, 8, 0, tzinfo=timezone.utc)

    assert quota.claim("luna", "top_stories", now=now) is True
    assert quota.claim("luna", "top_stories", now=now) is True
    assert quota.claim("luna", "top_stories", now=now) is False
    assert quota.claim("sol", "briefing", now=now) is True


def test_claim_resets_on_next_utc_day(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, luna_limit=1, luna_cooldown=0)
    day_one = datetime(2026, 10, 18, 23, 59, tzinfo=timezone.utc)

    assert quota.claim("luna", "top_stories", now=day_one) is True
    assert quota.claim("luna", "top_stories", now=day_one) is False
    assert quota.claim(
        "luna", "top_stories", now=day_one + timedelta(minutes=2)
    ) is True


def test_claim_recovers_from_corrupt_state(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    quota.USAGE_FILE.write_text("not-json", encoding="utf-8")

    assert quota.claim("sol", "briefing") is True


def test_disabled_limit_rejects_calls(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, sol_limit=0)

    assert quota.claim("sol", "briefing") is False


def test_state_write_failure_fails_closed(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)

    with patch.object(quota, "write_json_atomic", side_effect=OSError("disk full")):
        assert quota.claim("sol", "briefing") is False


def test_sol_claims_once_per_configured_schedule_window(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, sol_cooldown=0)
    monkeypatch.setattr(quota, "MODEL_SERVICES_SOL_SCHEDULE_HOURS_UTC", (3, 15))
    monkeypatch.setattr(quota, "MODEL_SERVICES_SOL_SCHEDULE_WINDOW_MINUTES", 180)

    before = datetime(2026, 10, 18, 2, 59, tzinfo=timezone.utc)
    morning = datetime(2026, 10, 18, 3, 15, tzinfo=timezone.utc)
    evening = datetime(2026, 10, 18, 15, 5, tzinfo=timezone.utc)

    assert quota.claim("sol", "briefing", now=before) is False
    assert quota.claim("sol", "briefing", now=morning) is True
    assert quota.claim("sol", "briefing", now=morning + timedelta(hours=2)) is False
    assert quota.claim("sol", "briefing", now=evening) is True
    assert quota.claim("sol", "briefing", now=evening + timedelta(hours=2)) is False
