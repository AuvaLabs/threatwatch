"""Telegram bot dispatcher for briefing alerts.

Posts the global intelligence briefing to a Telegram channel/chat via the
Bot API when the briefing's threat_level clears the configured minimum.
Mirrors the modules/webhook.py dedup pattern (level-change OR cooldown
lapsed) so the same level does not re-alert on every pipeline tick.

Configure via environment:
  TELEGRAM_BOT_TOKEN          — bot token from @BotFather (required to enable)
  TELEGRAM_CHAT_ID            — channel handle ("@my_channel") or numeric ID
  TELEGRAM_MIN_LEVEL          — ELEVATED | CRITICAL (default ELEVATED)
  TELEGRAM_COOLDOWN_HOURS     — re-alert after N hours (default 6)
  TELEGRAM_DASHBOARD_URL      — link surfaced in the message footer

The dispatcher is independent from the legacy WEBHOOK_* — both can fire
on the same briefing so an org can drive Slack and Telegram simultaneously.
"""
import json
import logging
import os
from datetime import datetime, timezone
from html import escape as _html_escape

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from modules.config import STATE_DIR

logger = logging.getLogger(__name__)

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
TELEGRAM_MIN_LEVEL = os.environ.get("TELEGRAM_MIN_LEVEL", "ELEVATED").upper()
TELEGRAM_COOLDOWN_HOURS = float(os.environ.get("TELEGRAM_COOLDOWN_HOURS", "6"))
TELEGRAM_DASHBOARD_URL = os.environ.get(
    "TELEGRAM_DASHBOARD_URL", "https://threatwatch.auvalabs.com"
)

# Telegram sendMessage caps at 4096 chars. We keep a comfortable safety
# margin since headline + actions + footer also consume budget.
_TELEGRAM_MAX_BODY = 4000
_WHAT_HAPPENED_BUDGET = 1800  # leaves room for headline + 3 actions + footer

_LEVEL_RANK = {"LOW": 0, "GUARDED": 1, "MODERATE": 2, "ELEVATED": 3, "CRITICAL": 4}
_LEVEL_EMOJI = {
    "CRITICAL": "🔥",
    "ELEVATED": "🚨",
    "MODERATE": "⚠️",
    "GUARDED": "ℹ️",
    "LOW": "✅",
}

_STATE_PATH = STATE_DIR / "telegram_briefing_last_alert.json"

_session: requests.Session | None = None


def _get_session() -> requests.Session:
    global _session
    if _session is None:
        s = requests.Session()
        retry = Retry(total=2, backoff_factor=1, status_forcelist=[429, 500, 502, 503])
        s.mount("https://", HTTPAdapter(max_retries=retry))
        _session = s
    return _session


def _load_state() -> dict:
    try:
        if _STATE_PATH.exists():
            return json.loads(_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _save_state(state: dict) -> None:
    try:
        _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _STATE_PATH.write_text(json.dumps(state), encoding="utf-8")
    except OSError as e:
        logger.warning("Could not persist telegram alert state: %s", e)


def _should_alert(level: str, state: dict) -> bool:
    """Fire when at/above the minimum AND (level changed OR cooldown lapsed)."""
    current = _LEVEL_RANK.get((level or "").upper(), -1)
    minimum = _LEVEL_RANK.get(TELEGRAM_MIN_LEVEL, _LEVEL_RANK["ELEVATED"])
    if current < minimum:
        return False

    last_level = (state.get("level") or "").upper()
    last_alerted_at = state.get("alerted_at")

    if last_level != (level or "").upper():
        return True

    if not last_alerted_at:
        return True

    try:
        ts = datetime.fromisoformat(str(last_alerted_at).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
    except ValueError:
        return True

    age_h = (datetime.now(timezone.utc) - ts).total_seconds() / 3600.0
    return age_h >= TELEGRAM_COOLDOWN_HOURS


def _truncate(text: str, limit: int) -> str:
    """Trim at a sentence/clause boundary near the limit; ellipsis fallback."""
    if not text or len(text) <= limit:
        return text or ""
    window = text[:limit]
    for sep in (". ", "; ", ", "):
        idx = window.rfind(sep)
        if idx >= int(limit * 0.6):
            return window[: idx + len(sep)].rstrip() + " …"
    return window.rstrip() + " …"


def format_briefing_html(briefing: dict) -> str:
    """Render a briefing as Telegram-compatible HTML.

    Telegram's HTML parse mode allows only a small whitelist of tags
    (<b>, <i>, <u>, <s>, <a>, <code>, <pre>) — every other tag must be
    escaped, and so must any '<' '>' '&' inside text.
    """
    level = (briefing.get("threat_level") or "UNKNOWN").upper()
    emoji = _LEVEL_EMOJI.get(level, "⚠️")
    headline = (briefing.get("headline") or "").strip()
    what_happened = _truncate(
        (briefing.get("what_happened") or "").strip(), _WHAT_HAPPENED_BUDGET
    )

    lines = [f"{emoji} <b>ThreatWatch — {_html_escape(level)}</b>"]
    if headline:
        lines.append(f"<b>{_html_escape(headline)}</b>")
    if what_happened:
        lines.append(_html_escape(what_happened))

    actions = briefing.get("what_to_do") or []
    action_lines = []
    for a in actions[:3]:
        text = a.get("action") if isinstance(a, dict) else str(a)
        if not text:
            continue
        action_lines.append(f"• {_html_escape(_truncate(text, 180))}")
    if action_lines:
        lines.append("<b>Priority actions</b>")
        lines.extend(action_lines)

    if TELEGRAM_DASHBOARD_URL:
        url = _html_escape(TELEGRAM_DASHBOARD_URL, quote=True)
        lines.append(f'<a href="{url}">Open dashboard →</a>')

    body = "\n\n".join(lines)
    if len(body) > _TELEGRAM_MAX_BODY:
        body = body[: _TELEGRAM_MAX_BODY - 3] + "…"
    return body


def _send(text: str) -> bool:
    """POST to sendMessage. Returns True on HTTP success."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    try:
        resp = _get_session().post(url, json=payload, timeout=10)
        resp.raise_for_status()
        return True
    except requests.RequestException as e:
        logger.warning("Telegram delivery failed: %s", e)
        return False


def dispatch_telegram_briefing(briefing: dict | None) -> bool:
    """Fire a Telegram alert for the briefing if it clears the threshold.

    Safe to call with a None briefing or when TELEGRAM_BOT_TOKEN /
    TELEGRAM_CHAT_ID are unset — both shortcircuit to False without
    raising. Independent dedup state from the webhook dispatcher.
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID or not briefing:
        return False
    level = (briefing.get("threat_level") or "").upper()
    state = _load_state()
    if not _should_alert(level, state):
        return False

    text = format_briefing_html(briefing)
    if not _send(text):
        return False

    _save_state({
        "level": level,
        "alerted_at": datetime.now(timezone.utc).isoformat(),
    })
    logger.info("Telegram briefing dispatched: threat_level=%s", level)
    return True


def post_briefing_unconditional(briefing: dict | None) -> bool:
    """Post the briefing now regardless of level / cooldown.

    For the standalone scripts/post_briefing_to_telegram.py daily cron
    flow — operators who want a guaranteed once-a-day post separate from
    the threshold-driven alert path.
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID or not briefing:
        return False
    return _send(format_briefing_html(briefing))
