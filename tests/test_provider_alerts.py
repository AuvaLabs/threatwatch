from unittest.mock import Mock

from modules.provider_alerts import (
    dispatch_current_provider_transitions,
    dispatch_provider_transitions,
    provider_transitions,
)


def _health(status, **fields):
    return {"providers": {"nvd": {"status": status, **fields}}}


def test_provider_transitions_reports_degradation_and_recovery():
    degraded = provider_transitions(
        _health("healthy"),
        _health("degraded", error="http_503", consecutive_failures=1),
    )
    recovered = provider_transitions(
        _health("suspended", error="http_503", consecutive_failures=3),
        _health("healthy", consecutive_failures=0),
    )

    assert degraded == [{
        "name": "nvd",
        "previous": "healthy",
        "current": "degraded",
        "error": "http_503",
        "consecutive_failures": 1,
    }]
    assert recovered[0]["current"] == "healthy"


def test_provider_transitions_ignores_unchanged_and_new_healthy_state():
    assert provider_transitions(_health("healthy"), _health("healthy")) == []
    assert provider_transitions({"providers": {}}, _health("healthy")) == []


def test_dispatch_provider_transitions_uses_private_ops_dispatcher():
    dispatcher = Mock(return_value=True)

    count = dispatch_provider_transitions(
        _health("degraded", error="timeout", consecutive_failures=2),
        _health("healthy", consecutive_failures=0),
        dispatcher=dispatcher,
    )

    assert count == 1
    dispatcher.assert_called_once_with(
        key="provider_nvd_healthy",
        subject="NVD provider recovered",
        detail="Provider returned to healthy operation.",
    )


def test_dispatch_current_provider_transitions_returns_new_baseline():
    dispatcher = Mock(return_value=True)
    after = {
        "providers": {
            "nvd": {"status": "healthy"},
            "threatfox": {
                "status": "degraded",
                "error": "http_429",
                "consecutive_failures": 1,
            },
        },
    }

    baseline, count = dispatch_current_provider_transitions(
        {"providers": {"nvd": {"status": "healthy"}}},
        dispatcher=dispatcher,
        health_loader=Mock(return_value=after),
    )

    assert baseline is after
    assert count == 1
    dispatcher.assert_called_once_with(
        key="provider_threatfox_degraded",
        subject="ThreatFox provider degraded",
        detail="Reason: http_429. Consecutive failed cycles: 1.",
    )
