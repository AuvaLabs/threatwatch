"""Tests for modules/webhook.py — alert dispatch."""
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import requests

import modules.webhook as wh


CYBER_ARTICLE = {
    "title": "Ransomware Hits Hospital",
    "translated_title": "Ransomware Hits Hospital",
    "link": "https://example.com/article",
    "category": "Ransomware",
    "is_cyber_attack": True,
    "confidence": 95,
    "feed_region": "Global",
    "summary": "A major hospital was hit by ransomware.",
}

LOW_CONF_ARTICLE = {**CYBER_ARTICLE, "confidence": 40}
NON_CYBER_ARTICLE = {**CYBER_ARTICLE, "is_cyber_attack": False, "confidence": 95}


class TestDispatchNoOp:
    def test_no_webhook_url_is_noop(self):
        with patch.object(wh, "WEBHOOK_URL", ""):
            # Should not attempt any HTTP call
            with patch("modules.webhook._get_session") as mock_sess:
                wh.dispatch([CYBER_ARTICLE])
                mock_sess.assert_not_called()

    def test_no_high_conf_articles_is_noop(self):
        with patch.object(wh, "WEBHOOK_URL", "https://hooks.slack.com/test"), \
             patch.object(wh, "WEBHOOK_MIN_CONF", 80), \
             patch("modules.webhook._get_session") as mock_sess:
            wh.dispatch([LOW_CONF_ARTICLE])
            mock_sess.assert_not_called()

    def test_non_cyber_excluded(self):
        with patch.object(wh, "WEBHOOK_URL", "https://hooks.slack.com/test"), \
             patch("modules.webhook._get_session") as mock_sess:
            wh.dispatch([NON_CYBER_ARTICLE])
            mock_sess.assert_not_called()


class TestDispatchSlack:
    def test_posts_to_slack(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status.return_value = None

        mock_sess = MagicMock()
        mock_sess.post.return_value = mock_resp

        with patch.object(wh, "WEBHOOK_URL", "https://hooks.slack.com/test"), \
             patch.object(wh, "WEBHOOK_MIN_CONF", 80), \
             patch("modules.webhook._get_session", return_value=mock_sess):
            wh.dispatch([CYBER_ARTICLE])

        mock_sess.post.assert_called_once()
        payload = mock_sess.post.call_args[1]["json"]
        assert "text" in payload
        assert "Ransomware" in payload["text"] or "threat" in payload["text"].lower()

    def test_request_exception_does_not_raise(self):
        mock_sess = MagicMock()
        mock_sess.post.side_effect = requests.RequestException("timeout")

        with patch.object(wh, "WEBHOOK_URL", "https://hooks.slack.com/test"), \
             patch.object(wh, "WEBHOOK_MIN_CONF", 80), \
             patch("modules.webhook._get_session", return_value=mock_sess):
            wh.dispatch([CYBER_ARTICLE])  # must not raise


class TestDispatchGeneric:
    def test_generic_payload_has_articles(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_sess = MagicMock()
        mock_sess.post.return_value = mock_resp

        with patch.object(wh, "WEBHOOK_URL", "https://custom.webhook.example.com/notify"), \
             patch.object(wh, "WEBHOOK_MIN_CONF", 80), \
             patch("modules.webhook._get_session", return_value=mock_sess):
            wh.dispatch([CYBER_ARTICLE])

        payload = mock_sess.post.call_args[1]["json"]
        assert "articles" in payload
        assert payload["alert_count"] == 1
        assert payload["articles"][0]["title"] == CYBER_ARTICLE["translated_title"]


class TestFormatSlack:
    def test_formats_up_to_5_articles(self):
        articles = [CYBER_ARTICLE] * 7
        payload = wh._format_slack(articles)
        assert "text" in payload
        assert "…and 2 more" in payload["text"]

    def test_single_article_no_ellipsis(self):
        payload = wh._format_slack([CYBER_ARTICLE])
        assert "…and" not in payload["text"]


class TestGetSessionLazy:
    """_get_session caches a single Session instance across calls."""

    def setup_method(self):
        wh._session = None

    def test_returns_cached_session_on_second_call(self):
        s1 = wh._get_session()
        s2 = wh._get_session()
        assert s1 is s2

    def test_session_has_retry_adapter(self):
        s = wh._get_session()
        adapter = s.get_adapter("https://example.com")
        # Retry stays enabled here (unlike llm_client) — webhooks are one-shot
        # fire-and-forget so retry can't cascade into a runtime blowup.
        assert adapter.max_retries.total == 2


# ── Briefing threat-level alerts ─────────────────────────────────────────────

import modules.webhook  # used by patch targets inside tests


class TestShouldAlertBriefing:
    def test_below_minimum_does_not_alert(self, monkeypatch):
        monkeypatch.setattr(wh, "WEBHOOK_BRIEFING_MIN_LEVEL", "ELEVATED")
        # LOW/GUARDED/MODERATE all rank below ELEVATED.
        for lvl in ("LOW", "GUARDED", "MODERATE"):
            assert wh._should_alert_briefing(lvl, {}) is False

    def test_first_time_at_threshold_alerts(self, monkeypatch):
        monkeypatch.setattr(wh, "WEBHOOK_BRIEFING_MIN_LEVEL", "ELEVATED")
        assert wh._should_alert_briefing("ELEVATED", {}) is True
        assert wh._should_alert_briefing("CRITICAL", {}) is True

    def test_level_change_alerts(self, monkeypatch):
        monkeypatch.setattr(wh, "WEBHOOK_BRIEFING_MIN_LEVEL", "ELEVATED")
        state = {
            "level": "ELEVATED",
            "alerted_at": datetime.now(timezone.utc).isoformat(),
        }
        # Same level inside cooldown → no alert.
        assert wh._should_alert_briefing("ELEVATED", state) is False
        # Level escalates → always alert.
        assert wh._should_alert_briefing("CRITICAL", state) is True

    def test_cooldown_elapsed_alerts_same_level(self, monkeypatch):
        monkeypatch.setattr(wh, "WEBHOOK_BRIEFING_MIN_LEVEL", "ELEVATED")
        monkeypatch.setattr(wh, "WEBHOOK_BRIEFING_COOLDOWN_HOURS", 1.0)
        from datetime import timedelta
        old = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        state = {"level": "ELEVATED", "alerted_at": old}
        assert wh._should_alert_briefing("ELEVATED", state) is True

    def test_cooldown_still_active_suppresses(self, monkeypatch):
        monkeypatch.setattr(wh, "WEBHOOK_BRIEFING_MIN_LEVEL", "ELEVATED")
        monkeypatch.setattr(wh, "WEBHOOK_BRIEFING_COOLDOWN_HOURS", 6.0)
        from datetime import timedelta
        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        state = {"level": "ELEVATED", "alerted_at": recent}
        assert wh._should_alert_briefing("ELEVATED", state) is False


class TestDispatchBriefingAlert:
    @pytest.fixture(autouse=True)
    def _isolated_state(self, tmp_path, monkeypatch):
        monkeypatch.setattr(wh, "_BRIEFING_STATE_PATH", tmp_path / "last.json")
        yield

    def test_noop_when_no_url(self, monkeypatch):
        monkeypatch.setattr(wh, "WEBHOOK_URL", "")
        assert wh.dispatch_briefing_alert({"threat_level": "CRITICAL"}) is False

    def test_noop_when_briefing_none(self, monkeypatch):
        monkeypatch.setattr(wh, "WEBHOOK_URL", "https://example.com/webhook")
        assert wh.dispatch_briefing_alert(None) is False

    def test_slack_payload_shape(self, monkeypatch):
        monkeypatch.setattr(wh, "WEBHOOK_URL", "https://hooks.slack.com/services/xyz")
        monkeypatch.setattr(wh, "WEBHOOK_BRIEFING_MIN_LEVEL", "ELEVATED")
        captured = {}

        def fake_post(url, json=None, **kw):  # noqa: F811 — mirrors requests.post signature
            captured["url"] = url
            captured["body"] = json
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            return resp

        with patch.object(wh._get_session(), "post", side_effect=fake_post):
            fired = wh.dispatch_briefing_alert({
                "threat_level": "CRITICAL",
                "what_happened": "Active exploitation of CVE-2026-X in the wild.",
                "what_to_do": [{"action": "Patch immediately"}, {"action": "Monitor logs"}],
            })
        assert fired is True
        assert "text" in captured["body"]
        assert "CRITICAL" in captured["body"]["text"]
        assert "Patch immediately" in captured["body"]["text"]

    def test_generic_payload_shape(self, monkeypatch):
        monkeypatch.setattr(wh, "WEBHOOK_URL", "https://example.com/json-hook")
        monkeypatch.setattr(wh, "WEBHOOK_BRIEFING_MIN_LEVEL", "ELEVATED")
        captured = {}

        def fake_post(url, json=None, **kw):  # noqa: F811 — mirrors requests.post signature
            captured["body"] = json
            resp = MagicMock()
            resp.raise_for_status = MagicMock()
            return resp

        with patch.object(wh._get_session(), "post", side_effect=fake_post):
            wh.dispatch_briefing_alert({"threat_level": "CRITICAL", "what_happened": "X"})
        assert captured["body"]["alert_type"] == "briefing_threat_level"
        assert captured["body"]["threat_level"] == "CRITICAL"

    def test_state_persisted_on_success(self, monkeypatch, tmp_path):
        state_path = tmp_path / "state.json"
        monkeypatch.setattr(wh, "_BRIEFING_STATE_PATH", state_path)
        monkeypatch.setattr(wh, "WEBHOOK_URL", "https://example.com/hook")
        monkeypatch.setattr(wh, "WEBHOOK_BRIEFING_MIN_LEVEL", "ELEVATED")
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        with patch.object(wh._get_session(), "post", return_value=resp):
            wh.dispatch_briefing_alert({"threat_level": "CRITICAL"})
        import json as _json
        state = _json.loads(state_path.read_text())
        assert state["level"] == "CRITICAL"
        assert "alerted_at" in state

    def test_does_not_persist_on_failure(self, monkeypatch, tmp_path):
        state_path = tmp_path / "state.json"
        monkeypatch.setattr(wh, "_BRIEFING_STATE_PATH", state_path)
        monkeypatch.setattr(wh, "WEBHOOK_URL", "https://example.com/hook")
        monkeypatch.setattr(wh, "WEBHOOK_BRIEFING_MIN_LEVEL", "ELEVATED")
        with patch.object(wh._get_session(), "post",
                          side_effect=requests.RequestException("down")):
            fired = wh.dispatch_briefing_alert({"threat_level": "CRITICAL"})
        assert fired is False
        assert not state_path.exists()
