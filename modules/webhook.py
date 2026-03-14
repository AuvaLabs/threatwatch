"""Webhook alert dispatcher.

Sends a JSON POST to WEBHOOK_URL (if configured) when new high-confidence
cybersecurity articles are found. Compatible with Slack incoming webhooks,
Discord webhooks, and any generic JSON endpoint.

Configure via environment:
  WEBHOOK_URL     — target URL (required to enable)
  WEBHOOK_MIN_CONF — minimum confidence score to alert on (default: 80)
"""
import json
import logging
import os
from datetime import datetime, timezone

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")
WEBHOOK_MIN_CONF = int(os.environ.get("WEBHOOK_MIN_CONF", "80"))

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
        logging.debug("Webhook: no high-confidence articles to report")
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
        logging.info("Webhook dispatched: %d articles → %s (HTTP %d)",
                     len(high_conf), WEBHOOK_URL[:40] + "…", resp.status_code)
    except requests.RequestException as e:
        logging.warning("Webhook delivery failed: %s", e)
