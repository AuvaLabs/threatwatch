"""Tests for modules/telegram.py — Telegram briefing dispatcher."""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
import requests

import modules.telegram as tg


_BRIEFING = {
    "threat_level": "ELEVATED",
    "headline": "CISA adds Cisco ASA zero-day to KEV after Volt Typhoon mass exploitation.",
    "what_happened": "Three notable incidents in the last 24 hours: a healthcare breach, a Cisco zero-day exploited in the wild, and a ransomware affiliate switching infrastructure.",
    "what_to_do": [
        {"action": "Patch Cisco ASA immediately if exposed", "sources": [1]},
        {"action": "Review healthcare partner access logs", "sources": [3]},
    ],
    "generated_at": "2026-04-26T10:00:00+00:00",
}


# ---------------------------------------------------------------------------
# _should_alert
# ---------------------------------------------------------------------------
class TestShouldAlert:
    def test_below_minimum_does_not_alert(self):
        with patch.object(tg, "TELEGRAM_MIN_LEVEL", "ELEVATED"):
            assert tg._should_alert("MODERATE", {}) is False
            assert tg._should_alert("LOW", {}) is False

    def test_first_time_at_threshold_alerts(self):
        with patch.object(tg, "TELEGRAM_MIN_LEVEL", "ELEVATED"):
            assert tg._should_alert("ELEVATED", {}) is True

    def test_level_change_alerts_even_within_cooldown(self):
        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        state = {"level": "ELEVATED", "alerted_at": recent}
        with patch.object(tg, "TELEGRAM_MIN_LEVEL", "ELEVATED"), \
             patch.object(tg, "TELEGRAM_COOLDOWN_HOURS", 6.0):
            assert tg._should_alert("CRITICAL", state) is True

    def test_same_level_within_cooldown_suppresses(self):
        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        state = {"level": "ELEVATED", "alerted_at": recent}
        with patch.object(tg, "TELEGRAM_MIN_LEVEL", "ELEVATED"), \
             patch.object(tg, "TELEGRAM_COOLDOWN_HOURS", 6.0):
            assert tg._should_alert("ELEVATED", state) is False

    def test_same_level_after_cooldown_alerts(self):
        old = (datetime.now(timezone.utc) - timedelta(hours=12)).isoformat()
        state = {"level": "ELEVATED", "alerted_at": old}
        with patch.object(tg, "TELEGRAM_MIN_LEVEL", "ELEVATED"), \
             patch.object(tg, "TELEGRAM_COOLDOWN_HOURS", 6.0):
            assert tg._should_alert("ELEVATED", state) is True

    def test_corrupted_timestamp_treated_as_alert(self):
        state = {"level": "ELEVATED", "alerted_at": "not-a-date"}
        with patch.object(tg, "TELEGRAM_MIN_LEVEL", "ELEVATED"):
            assert tg._should_alert("ELEVATED", state) is True


# ---------------------------------------------------------------------------
# format_briefing_html
# ---------------------------------------------------------------------------
class TestFormatBriefingHTML:
    def test_includes_level_and_headline_and_body(self):
        out = tg.format_briefing_html(_BRIEFING)
        assert "ELEVATED" in out
        assert "CISA adds Cisco ASA zero-day" in out
        assert "Patch Cisco ASA immediately" in out

    def test_escapes_html_in_user_supplied_text(self):
        evil = {**_BRIEFING, "headline": "Pwned <script>alert(1)</script>"}
        out = tg.format_briefing_html(evil)
        assert "<script>" not in out
        assert "&lt;script&gt;" in out

    def test_truncates_long_what_happened(self):
        long_text = "x. " * 1500  # ~4500 chars, well over the budget
        out = tg.format_briefing_html({**_BRIEFING, "what_happened": long_text})
        assert len(out) <= tg._TELEGRAM_MAX_BODY
        assert out.endswith("…") or "…" in out

    def test_dashboard_url_appears_when_set(self):
        with patch.object(tg, "TELEGRAM_DASHBOARD_URL", "https://example.test"):
            out = tg.format_briefing_html(_BRIEFING)
            assert 'href="https://example.test"' in out

    def test_dashboard_url_omitted_when_empty(self):
        with patch.object(tg, "TELEGRAM_DASHBOARD_URL", ""):
            out = tg.format_briefing_html(_BRIEFING)
            assert "href=" not in out

    def test_no_headline_still_renders(self):
        out = tg.format_briefing_html({**_BRIEFING, "headline": ""})
        assert "ELEVATED" in out
        assert "Three notable incidents" in out


# ---------------------------------------------------------------------------
# dispatch_telegram_briefing
# ---------------------------------------------------------------------------
class TestDispatchTelegramBriefing:
    def test_noop_when_no_token(self):
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", ""), \
             patch.object(tg, "TELEGRAM_CHAT_ID", "@x"), \
             patch.object(tg, "_get_session") as mock_sess:
            assert tg.dispatch_telegram_briefing(_BRIEFING) is False
            mock_sess.assert_not_called()

    def test_noop_when_no_chat_id(self):
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", "abc"), \
             patch.object(tg, "TELEGRAM_CHAT_ID", ""), \
             patch.object(tg, "_get_session") as mock_sess:
            assert tg.dispatch_telegram_briefing(_BRIEFING) is False
            mock_sess.assert_not_called()

    def test_noop_when_briefing_none(self):
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", "abc"), \
             patch.object(tg, "TELEGRAM_CHAT_ID", "@x"), \
             patch.object(tg, "_get_session") as mock_sess:
            assert tg.dispatch_telegram_briefing(None) is False
            mock_sess.assert_not_called()

    def test_below_threshold_does_not_post(self, tmp_path):
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", "abc"), \
             patch.object(tg, "TELEGRAM_CHAT_ID", "@x"), \
             patch.object(tg, "TELEGRAM_MIN_LEVEL", "CRITICAL"), \
             patch.object(tg, "_STATE_PATH", tmp_path / "state.json"), \
             patch("modules.telegram._get_session") as mock_sess:
            assert tg.dispatch_telegram_briefing(_BRIEFING) is False  # ELEVATED < CRITICAL
            mock_sess.assert_not_called()

    def test_full_dispatch_posts_and_persists_state(self, tmp_path):
        state_path = tmp_path / "state.json"
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", "abc"), \
             patch.object(tg, "TELEGRAM_CHAT_ID", "@x"), \
             patch.object(tg, "TELEGRAM_MIN_LEVEL", "ELEVATED"), \
             patch.object(tg, "_STATE_PATH", state_path), \
             patch("modules.telegram._get_session") as mock_sess:
            mock_resp = mock_sess.return_value.post.return_value
            mock_resp.raise_for_status.return_value = None
            assert tg.dispatch_telegram_briefing(_BRIEFING) is True

            # POST call inspection
            mock_sess.return_value.post.assert_called_once()
            call_args = mock_sess.return_value.post.call_args
            assert call_args.args[0].endswith("/sendMessage")
            payload = call_args.kwargs["json"]
            assert payload["chat_id"] == "@x"
            assert payload["parse_mode"] == "HTML"
            assert "ELEVATED" in payload["text"]

            # State persisted
            import json as _json
            saved = _json.loads(state_path.read_text())
            assert saved["level"] == "ELEVATED"
            assert "alerted_at" in saved

    def test_request_exception_returns_false_no_state_change(self, tmp_path):
        state_path = tmp_path / "state.json"
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", "abc"), \
             patch.object(tg, "TELEGRAM_CHAT_ID", "@x"), \
             patch.object(tg, "TELEGRAM_MIN_LEVEL", "ELEVATED"), \
             patch.object(tg, "_STATE_PATH", state_path), \
             patch("modules.telegram._get_session") as mock_sess:
            mock_sess.return_value.post.side_effect = requests.RequestException("boom")
            assert tg.dispatch_telegram_briefing(_BRIEFING) is False
            assert not state_path.exists()  # nothing persisted on failure


# ---------------------------------------------------------------------------
# dispatch_telegram_kev_alerts
# ---------------------------------------------------------------------------
def _kev_article(cve_id: str, date_added: str = "2026-04-25",
                 ransomware: str = "Unknown", title: str = "Article title",
                 vendor: str = "Cisco", product: str = "ASA"):
    """Build an article dict already enriched as if kev_enricher had run."""
    return {
        "title": title,
        "kev_listed": True,
        "kev_min_date_added": date_added,
        "kev_ransomware_use": ransomware,
        "kev_entries": [{
            "cve_id": cve_id,
            "date_added": date_added,
            "ransomware_use": ransomware,
            "vendor": vendor,
            "product": product,
            "name": f"{vendor} {product} vulnerability",
        }],
    }


class TestDispatchKEVAlerts:
    def test_noop_when_no_token(self):
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", ""), \
             patch.object(tg, "TELEGRAM_CHAT_ID", "@x"), \
             patch("modules.telegram._get_session") as mock_sess:
            assert tg.dispatch_telegram_kev_alerts([_kev_article("CVE-2026-1")]) == 0
            mock_sess.assert_not_called()

    def test_noop_when_no_chat(self):
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", "abc"), \
             patch.object(tg, "TELEGRAM_CHAT_ID", ""), \
             patch("modules.telegram._get_session") as mock_sess:
            assert tg.dispatch_telegram_kev_alerts([_kev_article("CVE-2026-1")]) == 0
            mock_sess.assert_not_called()

    def test_empty_or_no_kev_articles(self, tmp_path):
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", "abc"), \
             patch.object(tg, "TELEGRAM_CHAT_ID", "@x"), \
             patch.object(tg, "_KEV_STATE_PATH", tmp_path / "k.json"), \
             patch("modules.telegram._get_session") as mock_sess:
            assert tg.dispatch_telegram_kev_alerts([]) == 0
            assert tg.dispatch_telegram_kev_alerts([{"title": "no kev"}]) == 0
            mock_sess.assert_not_called()

    def test_fires_one_alert_per_new_cve(self, tmp_path):
        state_path = tmp_path / "k.json"
        articles = [_kev_article("CVE-2026-1"), _kev_article("CVE-2026-2")]
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", "abc"), \
             patch.object(tg, "TELEGRAM_CHAT_ID", "@x"), \
             patch.object(tg, "_KEV_STATE_PATH", state_path), \
             patch("modules.telegram._get_session") as mock_sess:
            mock_sess.return_value.post.return_value.raise_for_status.return_value = None
            sent = tg.dispatch_telegram_kev_alerts(articles)
            assert sent == 2
            assert mock_sess.return_value.post.call_count == 2
            import json as _json
            saved = _json.loads(state_path.read_text())
            assert "CVE-2026-1" in saved and "CVE-2026-2" in saved

    def test_dedup_collapses_multiple_articles_same_cve(self, tmp_path):
        articles = [
            _kev_article("CVE-2026-9", title="First write-up"),
            _kev_article("CVE-2026-9", title="Second write-up"),
            _kev_article("CVE-2026-9", title="Third write-up"),
        ]
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", "abc"), \
             patch.object(tg, "TELEGRAM_CHAT_ID", "@x"), \
             patch.object(tg, "_KEV_STATE_PATH", tmp_path / "k.json"), \
             patch("modules.telegram._get_session") as mock_sess:
            mock_sess.return_value.post.return_value.raise_for_status.return_value = None
            sent = tg.dispatch_telegram_kev_alerts(articles)
            assert sent == 1
            assert mock_sess.return_value.post.call_count == 1

    def test_already_alerted_cve_skipped_forever(self, tmp_path):
        state_path = tmp_path / "k.json"
        state_path.write_text('{"CVE-2026-1": "2026-01-01T00:00:00+00:00"}')
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", "abc"), \
             patch.object(tg, "TELEGRAM_CHAT_ID", "@x"), \
             patch.object(tg, "_KEV_STATE_PATH", state_path), \
             patch("modules.telegram._get_session") as mock_sess:
            sent = tg.dispatch_telegram_kev_alerts([_kev_article("CVE-2026-1")])
            assert sent == 0
            mock_sess.assert_not_called()  # nothing to send

    def test_per_batch_cap_truncates_flood(self, tmp_path):
        articles = [_kev_article(f"CVE-2026-{i}") for i in range(20)]
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", "abc"), \
             patch.object(tg, "TELEGRAM_CHAT_ID", "@x"), \
             patch.object(tg, "_KEV_STATE_PATH", tmp_path / "k.json"), \
             patch.object(tg, "_KEV_MAX_ALERTS_PER_BATCH", 5), \
             patch("modules.telegram._get_session") as mock_sess:
            mock_sess.return_value.post.return_value.raise_for_status.return_value = None
            sent = tg.dispatch_telegram_kev_alerts(articles)
            assert sent == 5

    def test_send_failure_stops_and_preserves_unstamped(self, tmp_path):
        state_path = tmp_path / "k.json"
        articles = [_kev_article("CVE-2026-1"), _kev_article("CVE-2026-2")]
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", "abc"), \
             patch.object(tg, "TELEGRAM_CHAT_ID", "@x"), \
             patch.object(tg, "_KEV_STATE_PATH", state_path), \
             patch("modules.telegram._get_session") as mock_sess:
            mock_sess.return_value.post.side_effect = requests.RequestException("boom")
            sent = tg.dispatch_telegram_kev_alerts(articles)
            assert sent == 0
            # Nothing persisted — un-alerted CVEs will retry next run
            assert not state_path.exists()

    def test_message_format_includes_cve_date_ransomware_link(self, tmp_path):
        article = _kev_article("CVE-2026-77", date_added="2026-04-25",
                               ransomware="Known", vendor="Acme",
                               product="VPN", title="Acme VPN actively exploited")
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", "abc"), \
             patch.object(tg, "TELEGRAM_CHAT_ID", "@x"), \
             patch.object(tg, "_KEV_STATE_PATH", tmp_path / "k.json"), \
             patch.object(tg, "TELEGRAM_DASHBOARD_URL", "https://example.test"), \
             patch("modules.telegram._get_session") as mock_sess:
            mock_sess.return_value.post.return_value.raise_for_status.return_value = None
            tg.dispatch_telegram_kev_alerts([article])
            payload = mock_sess.return_value.post.call_args.kwargs["json"]
            text = payload["text"]
            assert "CVE-2026-77" in text
            assert "2026-04-25" in text
            assert "ransomware" in text.lower()
            assert "Acme" in text
            # NVD link is the canonical CVE reference (not the JSON API endpoint)
            assert "https://nvd.nist.gov/vuln/detail/CVE-2026-77" in text
            assert "https://example.test" in text


# ---------------------------------------------------------------------------
# post_briefing_unconditional (used by the cron script)
# ---------------------------------------------------------------------------
class TestPostUnconditional:
    def test_noop_when_no_token(self):
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", ""), \
             patch.object(tg, "TELEGRAM_CHAT_ID", "@x"), \
             patch("modules.telegram._get_session") as mock_sess:
            assert tg.post_briefing_unconditional(_BRIEFING) is False
            mock_sess.assert_not_called()

    def test_posts_regardless_of_level_or_cooldown(self, tmp_path):
        # Even if the briefing is LOW and the cooldown would normally suppress,
        # the unconditional path posts anyway. State is NOT updated either —
        # the alert path's dedup must be unaffected.
        state_path = tmp_path / "state.json"
        original_state = '{"level": "ELEVATED", "alerted_at": "2026-04-26T00:00:00+00:00"}'
        state_path.write_text(original_state)
        with patch.object(tg, "TELEGRAM_BOT_TOKEN", "abc"), \
             patch.object(tg, "TELEGRAM_CHAT_ID", "@x"), \
             patch.object(tg, "_STATE_PATH", state_path), \
             patch("modules.telegram._get_session") as mock_sess:
            mock_sess.return_value.post.return_value.raise_for_status.return_value = None
            low_briefing = {**_BRIEFING, "threat_level": "LOW"}
            assert tg.post_briefing_unconditional(low_briefing) is True
            assert state_path.read_text() == original_state  # state untouched
