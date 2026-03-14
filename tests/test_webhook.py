"""Tests for modules/webhook.py — alert dispatch."""
import json
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
