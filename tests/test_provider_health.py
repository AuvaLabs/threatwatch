import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import modules.provider_health as provider_health


def test_success_clears_suspension_and_failure_details(tmp_path):
    health_file = tmp_path / "provider_health.json"
    with patch.object(provider_health, "PROVIDER_HEALTH_FILE", health_file):
        provider_health.record_failure(
            "ransomware.live",
            "tls_certificate_error",
            cooldown_seconds=3600,
        )
        provider_health.record_success("ransomware.live", item_count=4)

        entry = provider_health.get_provider_health()["providers"]["ransomware.live"]

    assert entry["status"] == "healthy"
    assert entry["item_count"] == 4
    assert entry["consecutive_failures"] == 0
    assert "retry_after" not in entry
    assert "error" not in entry


def test_failure_suspends_provider_until_retry_time(tmp_path):
    health_file = tmp_path / "provider_health.json"
    with patch.object(provider_health, "PROVIDER_HEALTH_FILE", health_file):
        provider_health.record_failure(
            "ransomware.live",
            "tls_certificate_error",
            cooldown_seconds=3600,
        )
        payload = provider_health.get_provider_health()

        assert provider_health.is_suspended("ransomware.live") is True

    assert payload["suspended"] == 1
    assert payload["providers"]["ransomware.live"]["error"] == "tls_certificate_error"


def test_expired_suspension_allows_probe(tmp_path):
    health_file = tmp_path / "provider_health.json"
    expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    health_file.write_text(json.dumps({
        "ransomware.live": {"status": "suspended", "retry_after": expired},
    }))

    with patch.object(provider_health, "PROVIDER_HEALTH_FILE", health_file):
        assert provider_health.is_suspended("ransomware.live") is False


def test_disabled_provider_is_reported_without_being_unhealthy(tmp_path):
    health_file = tmp_path / "provider_health.json"
    with patch.object(provider_health, "PROVIDER_HEALTH_FILE", health_file):
        provider_health.record_disabled("threatfox", "credential_not_configured")
        payload = provider_health.get_provider_health()

    assert payload["disabled"] == 1
    assert payload["degraded"] == 0
    assert payload["providers"]["threatfox"]["reason"] == "credential_not_configured"


def test_health_write_failure_never_breaks_ingestion(tmp_path):
    health_file = tmp_path / "provider_health.json"
    with patch.object(provider_health, "PROVIDER_HEALTH_FILE", health_file), \
         patch("pathlib.Path.write_text", side_effect=OSError("disk unavailable")):
        provider_health.record_success("nvd", item_count=3)

