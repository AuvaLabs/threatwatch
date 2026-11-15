"""Operator notifications for structured-provider health transitions."""

from collections.abc import Callable
from typing import Any


_KNOWN_STATES = frozenset({"healthy", "degraded", "suspended"})
_DISPLAY_NAMES = {
    "nvd": "NVD",
    "ransomware.live": "ransomware.live",
    "threatfox": "ThreatFox",
}


def provider_transitions(
    before: dict[str, Any],
    after: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return meaningful state changes without treating discovery as recovery."""
    previous = before.get("providers", {}) if isinstance(before, dict) else {}
    current = after.get("providers", {}) if isinstance(after, dict) else {}
    transitions: list[dict[str, Any]] = []
    for name, entry in current.items():
        if not isinstance(entry, dict):
            continue
        prior_entry = previous.get(name, {})
        prior_status = prior_entry.get("status") if isinstance(prior_entry, dict) else None
        status = entry.get("status")
        if status not in _KNOWN_STATES or status == prior_status:
            continue
        if prior_status is None and status == "healthy":
            continue
        transitions.append({
            "name": str(name),
            "previous": prior_status,
            "current": status,
            "error": entry.get("error"),
            "consecutive_failures": int(entry.get("consecutive_failures", 0)),
        })
    return transitions


def dispatch_provider_transitions(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    dispatcher: Callable[..., bool],
) -> int:
    """Send cooldown-deduplicated private alerts for provider transitions."""
    dispatched = 0
    for transition in provider_transitions(before, after):
        name = transition["name"]
        status = transition["current"]
        label = _DISPLAY_NAMES.get(name, name)
        if status == "healthy":
            subject = f"{label} provider recovered"
            detail = "Provider returned to healthy operation."
        else:
            subject = f"{label} provider {status}"
            error = transition.get("error") or "provider_error"
            failures = transition.get("consecutive_failures", 0)
            detail = f"Reason: {error}. Consecutive failed cycles: {failures}."
        if dispatcher(
            key=f"provider_{name}_{status}",
            subject=subject,
            detail=detail,
        ):
            dispatched += 1
    return dispatched


def dispatch_current_provider_transitions(
    before: dict[str, Any],
    *,
    dispatcher: Callable[..., bool],
    health_loader: Callable[[], dict[str, Any]],
) -> tuple[dict[str, Any], int]:
    """Load current health, alert on transitions, and return the new baseline."""
    after = health_loader()
    count = dispatch_provider_transitions(before, after, dispatcher=dispatcher)
    return after, count
