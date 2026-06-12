"""Webhook alert dispatcher.

Sends JSON POSTs to WEBHOOK_URL (if configured). Compatible with Slack /
Discord incoming webhooks and any generic JSON endpoint. Two alert
surfaces are supported:

1. High-confidence new articles — ``dispatch(articles)`` (legacy).
2. Intelligence briefing threat-level — ``dispatch_briefing_alert(briefing)``
   fires when the global briefing's threat_level is at or above
   ``WEBHOOK_BRIEFING_MIN_LEVEL`` (default ELEVATED). Deduplicated against
   a state file so the same level doesn't re-alert on every pipeline tick
   — only when the level changes or the last alert was more than
   ``WEBHOOK_BRIEFING_COOLDOWN_HOURS`` hours ago.

Configure via environment:
  WEBHOOK_URL                      — target URL (required to enable)
  WEBHOOK_MIN_CONF                 — article confidence threshold (default 80)
  WEBHOOK_BRIEFING_MIN_LEVEL       — ELEVATED | CRITICAL (default ELEVATED)
  WEBHOOK_BRIEFING_COOLDOWN_HOURS  — re-alert after N hours (default 6)
"""
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from modules.config import STATE_DIR
from modules.utils import write_json_atomic

WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")
WEBHOOK_MIN_CONF = int(os.environ.get("WEBHOOK_MIN_CONF", "80"))
WEBHOOK_BRIEFING_MIN_LEVEL = os.environ.get("WEBHOOK_BRIEFING_MIN_LEVEL", "ELEVATED").upper()
WEBHOOK_BRIEFING_COOLDOWN_HOURS = float(os.environ.get("WEBHOOK_BRIEFING_COOLDOWN_HOURS", "6"))

# Ordered threat-level severity (ascending). Used to decide whether an
# incoming briefing clears the alert threshold.
_LEVEL_RANK = {"LOW": 0, "GUARDED": 1, "MODERATE": 2, "ELEVATED": 3, "CRITICAL": 4}

_BRIEFING_STATE_PATH = STATE_DIR / "webhook_briefing_last_alert.json"

_session: requests.Session | None = None


def _get_session() -> requests.Session:
    global _session
    if _session is None:
        s = requests.Session()
        retry = Retry(total=2, backoff_factor=1, status_forcelist=[429, 500, 502, 503])
        s.mount("https://", HTTPAdapter(max_retries=retry))
        s.mount("http://", HTTPAdapter(max_retries=retry))
        _session = s
    return _session


def _is_slack_url(url: str) -> bool:
    return "hooks.slack.com" in url or "discord.com/api/webhooks" in url


def _format_slack(articles: list[dict]) -> dict:
    """Format payload for Slack/Discord incoming webhooks."""
    lines = []
    for a in articles[:5]:
        title = a.get("translated_title") or a.get("title", "")
        url = a.get("link", "")
        cat = a.get("category", "Cyber")
        conf = a.get("confidence", 0)
        lines.append(f"• [{cat}] <{url}|{title}> ({conf}%)")

    count = len(articles)
    header = f":rotating_light: *ThreatWatch — {count} new high-confidence threat{'s' if count > 1 else ''} detected*"
    text = header + "\n" + "\n".join(lines)
    if count > 5:
        text += f"\n_…and {count - 5} more. View full feed._"

    return {"text": text}


def _format_generic(articles: list[dict]) -> dict:
    """Format payload for generic JSON webhooks."""
    return {
        "source": "threatwatch",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alert_count": len(articles),
        "articles": [
            {
                "title": a.get("translated_title") or a.get("title", ""),
                "url": a.get("link", ""),
                "category": a.get("category", ""),
                "confidence": a.get("confidence", 0),
                "region": a.get("feed_region", "Global"),
                "summary": (a.get("summary") or "")[:300],
            }
            for a in articles[:10]
        ],
    }


def dispatch(articles: list[dict]) -> None:
    """Send webhook alert for high-confidence articles.

    No-op if WEBHOOK_URL is not set.
    Filters to articles meeting WEBHOOK_MIN_CONF threshold.
    """
    if not WEBHOOK_URL:
        return

    high_conf = [
        a for a in articles
        if a.get("is_cyber_attack") and (a.get("confidence") or 0) >= WEBHOOK_MIN_CONF
    ]
    if not high_conf:
        logger.debug("Webhook: no high-confidence articles to report")
        return

    payload = _format_slack(high_conf) if _is_slack_url(WEBHOOK_URL) else _format_generic(high_conf)

    try:
        resp = _get_session().post(
            WEBHOOK_URL,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        logger.info("Webhook dispatched: %d articles → %s (HTTP %d)",
                     len(high_conf), WEBHOOK_URL[:40] + "…", resp.status_code)
    except requests.RequestException as e:
        logger.warning("Webhook delivery failed: %s", e)


# ── Briefing threat-level alerts ─────────────────────────────────────────────


def _load_briefing_alert_state() -> dict:
    try:
        if _BRIEFING_STATE_PATH.exists():
            return json.loads(_BRIEFING_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _save_briefing_alert_state(state: dict) -> None:
    try:
        # Atomic: partial state reads back as {} and re-fires alerts.
        write_json_atomic(_BRIEFING_STATE_PATH, state)
    except OSError as e:
        logger.warning("Could not persist briefing alert state: %s", e)


def _should_alert_briefing(level: str, state: dict) -> bool:
    """Decide whether to fire a briefing alert given current level and state.

    Fires when:
    - level is at/above the configured minimum, AND
    - the level changed since the last alert OR the cooldown has lapsed.
    """
    current = _LEVEL_RANK.get((level or "").upper(), -1)
    minimum = _LEVEL_RANK.get(WEBHOOK_BRIEFING_MIN_LEVEL, _LEVEL_RANK["ELEVATED"])
    if current < minimum:
        return False

    last_level = (state.get("level") or "").upper()
    last_alerted_at = state.get("alerted_at")

    if last_level != (level or "").upper():
        return True  # level changed — always re-alert

    if not last_alerted_at:
        return True  # never alerted before

    try:
        ts = datetime.fromisoformat(str(last_alerted_at).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except ValueError:
        return True

    age_h = (datetime.now(timezone.utc) - ts).total_seconds() / 3600.0
    return age_h >= WEBHOOK_BRIEFING_COOLDOWN_HOURS


def _format_briefing_slack(briefing: dict) -> dict:
    level = (briefing.get("threat_level") or "UNKNOWN").upper()
    level_emoji = {
        "CRITICAL": ":fire:",
        "ELEVATED": ":rotating_light:",
        "MODERATE": ":warning:",
        "GUARDED": ":information_source:",
        "LOW": ":white_check_mark:",
    }.get(level, ":warning:")
    what = (briefing.get("what_happened") or "")[:500]
    actions = briefing.get("what_to_do") or []
    action_lines = []
    for a in actions[:3]:
        action = a.get("action") if isinstance(a, dict) else str(a)
        if action:
            action_lines.append(f"• {action[:140]}")

    text = f"{level_emoji} *ThreatWatch — Threat Level: {level}*\n{what}"
    if action_lines:
        text += "\n\n*Priority actions:*\n" + "\n".join(action_lines)
    return {"text": text}


def _format_briefing_generic(briefing: dict) -> dict:
    return {
        "source": "threatwatch",
        "alert_type": "briefing_threat_level",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "threat_level": briefing.get("threat_level"),
        "what_happened": briefing.get("what_happened"),
        "what_to_do": briefing.get("what_to_do"),
        "articles_analyzed": briefing.get("articles_analyzed"),
        "briefing_generated_at": briefing.get("generated_at"),
    }


def dispatch_briefing_alert(briefing: dict | None) -> bool:
    """Fire a webhook alert when the briefing threat_level clears the threshold.

    Returns True if an alert was actually dispatched, False otherwise. Safe
    to call with a ``None`` briefing or when ``WEBHOOK_URL`` is empty.
    """
    if not WEBHOOK_URL or not briefing:
        return False
    level = (briefing.get("threat_level") or "").upper()
    state = _load_briefing_alert_state()
    if not _should_alert_briefing(level, state):
        return False

    payload = (
        _format_briefing_slack(briefing)
        if _is_slack_url(WEBHOOK_URL)
        else _format_briefing_generic(briefing)
    )
    try:
        resp = _get_session().post(
            WEBHOOK_URL,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.warning("Briefing webhook delivery failed: %s", e)
        return False

    _save_briefing_alert_state({
        "level": level,
        "alerted_at": datetime.now(timezone.utc).isoformat(),
    })
    logger.info("Briefing webhook dispatched: threat_level=%s", level)
    return True
