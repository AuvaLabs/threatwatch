"""Tests for the bounded Model Services subscription route."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from modules import model_services_quota as quota


def _configure(monkeypatch, tmp_path, *, limit=8, cooldown=21600):
    monkeypatch.setattr(quota, "USAGE_FILE", tmp_path / "usage.json")
    monkeypatch.setattr(quota, "LOCK_FILE", tmp_path / "usage.lock")
    monkeypatch.setattr(quota, "MODEL_SERVICES_DAILY_CALL_LIMIT", limit)
    monkeypatch.setattr(quota, "MODEL_SERVICES_CALLER_COOLDOWN_SECONDS", cooldown)
    monkeypatch.setattr(
        quota,
        "MODEL_SERVICES_CALLERS",
        frozenset({"briefing", "top_stories"}),
    )


def test_claim_rejects_unapproved_caller(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)

    assert quota.claim("summaries") is False
    assert not quota.USAGE_FILE.exists()


def test_claim_enforces_per_caller_cooldown(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    now = datetime(2026, 10, 18, 8, 0, tzinfo=timezone.utc)

    assert quota.claim("briefing", now=now) is True
    assert quota.claim("briefing", now=now + timedelta(hours=1)) is False
    assert quota.claim("top_stories", now=now + timedelta(hours=1)) is True
    assert quota.claim("briefing", now=now + timedelta(hours=6)) is True


def test_claim_enforces_daily_limit(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, limit=2, cooldown=0)
    now = datetime(2026, 10, 18, 8, 0, tzinfo=timezone.utc)

    assert quota.claim("briefing", now=now) is True
    assert quota.claim("top_stories", now=now) is True
    assert quota.claim("briefing", now=now) is False


def test_claim_resets_on_next_utc_day(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, limit=1, cooldown=0)
    day_one = datetime(2026, 10, 18, 23, 59, tzinfo=timezone.utc)

    assert quota.claim("briefing", now=day_one) is True
    assert quota.claim("top_stories", now=day_one) is False
    assert quota.claim("top_stories", now=day_one + timedelta(minutes=2)) is True


def test_claim_recovers_from_corrupt_state(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    quota.USAGE_FILE.write_text("not-json", encoding="utf-8")

    assert quota.claim("briefing") is True


def test_disabled_limit_rejects_calls(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path, limit=0)

    assert quota.claim("briefing") is False


def test_state_write_failure_fails_closed(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)

    with patch.object(quota, "write_json_atomic", side_effect=OSError("disk full")):
        assert quota.claim("briefing") is False
