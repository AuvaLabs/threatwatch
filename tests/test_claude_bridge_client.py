"""Tests for the Claude Bridge client in modules/llm_client.py.

The bridge is a host-local OpenAI-compatible shim that proxies to the
`claude` CLI using the user's Claude Max subscription. Single-shot policy
mirrors Featherless: any failure surfaces immediately so the briefing
caller can fall back to Groq instead of stacking subprocess timeouts.
"""
from unittest.mock import MagicMock, patch

import pytest
import requests

from modules import llm_client
from modules.llm_client import call_claude_bridge, claude_bridge_available


def _mock_response(status_code=200, json_body=None, text=""):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = text
    resp.json.return_value = json_body or {
        "choices": [{"message": {"content": "ok"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }

    def _raise_for_status():
        if status_code >= 400:
            err = requests.exceptions.HTTPError(f"{status_code} error")
            err.response = resp
            raise err

    resp.raise_for_status = _raise_for_status
    return resp


@pytest.fixture
def mock_session():
    with patch.object(llm_client, "_get_http_session") as mock_factory:
        session = MagicMock()
        mock_factory.return_value = session
        yield session


@pytest.fixture(autouse=True)
def bridge_configured(monkeypatch):
    """Default: bridge IS configured. Individual tests can blank the URL."""
    monkeypatch.setattr(llm_client, "CLAUDE_BRIDGE_URL", "http://localhost:8400/v1")
    monkeypatch.setattr(llm_client, "CLAUDE_BRIDGE_MODEL", "sonnet")
    monkeypatch.setattr(llm_client, "CLAUDE_BRIDGE_TIMEOUT", 300.0)


@pytest.fixture(autouse=True)
def silence_usage_writes():
    with patch("modules.groq_usage.record_usage"):
        yield


class TestClaudeBridgeAvailable:
    def test_true_when_url_set(self):
        assert claude_bridge_available() is True

    def test_false_when_url_blank(self, monkeypatch):
        monkeypatch.setattr(llm_client, "CLAUDE_BRIDGE_URL", "")
        assert claude_bridge_available() is False


class TestCallBridgeSuccessPath:
    def test_returns_content(self, mock_session):
        mock_session.post.return_value = _mock_response(
            json_body={"choices": [{"message": {"content": "  bridge says hi  "}}]}
        )
        result = call_claude_bridge("user", system_prompt="sys")
        assert result == "bridge says hi"

    def test_uses_bridge_url(self, mock_session):
        mock_session.post.return_value = _mock_response()
        call_claude_bridge("u", system_prompt="s")
        url = mock_session.post.call_args.args[0]
        assert url == "http://localhost:8400/v1/chat/completions"

    def test_no_authorization_header(self, mock_session):
        """Bridge auth is via ~/.claude on host; no Bearer token needed."""
        mock_session.post.return_value = _mock_response()
        call_claude_bridge("u", system_prompt="s")
        headers = mock_session.post.call_args.kwargs["headers"]
        assert "Authorization" not in headers

    def test_payload_uses_bridge_model_by_default(self, mock_session):
        mock_session.post.return_value = _mock_response()
        call_claude_bridge("u", system_prompt="s")
        payload = mock_session.post.call_args.kwargs["json"]
        assert payload["model"] == "sonnet"
        assert payload["messages"][0] == {"role": "system", "content": "s"}
        assert payload["messages"][1] == {"role": "user", "content": "u"}

    def test_explicit_model_override_wins(self, mock_session):
        mock_session.post.return_value = _mock_response()
        call_claude_bridge("u", system_prompt="s", model="opus")
        payload = mock_session.post.call_args.kwargs["json"]
        assert payload["model"] == "opus"

    def test_response_format_passed_through(self, mock_session):
        """Bridge ignores response_format but we pass it for symmetry."""
        mock_session.post.return_value = _mock_response()
        call_claude_bridge(
            "u", system_prompt="s",
            response_format={"type": "json_object"},
        )
        payload = mock_session.post.call_args.kwargs["json"]
        assert payload["response_format"] == {"type": "json_object"}


class TestCallBridgeNotConfigured:
    def test_raises_when_url_missing(self, monkeypatch):
        monkeypatch.setattr(llm_client, "CLAUDE_BRIDGE_URL", "")
        with pytest.raises(RuntimeError, match="not configured"):
            call_claude_bridge("u", system_prompt="s")


class TestCallBridge504:
    """Bridge returns 504 on subprocess timeout — surface immediately."""

    def test_504_raises_runtime_error_without_retry(self, mock_session):
        mock_session.post.return_value = _mock_response(status_code=504, text="claude -p timed out")
        with pytest.raises(RuntimeError, match="504"):
            call_claude_bridge("u", system_prompt="s")
        assert mock_session.post.call_count == 1


class TestCallBridge5xx:
    @pytest.mark.parametrize("status", [500, 502, 503])
    def test_5xx_raises_runtime_error_without_retry(self, mock_session, status):
        mock_session.post.return_value = _mock_response(status_code=status, text="oops")
        with pytest.raises(RuntimeError, match=str(status)):
            call_claude_bridge("u", system_prompt="s")
        assert mock_session.post.call_count == 1


class TestCallBridgeTransportErrors:
    def test_timeout_raises_runtime_error(self, mock_session):
        mock_session.post.side_effect = requests.exceptions.Timeout("read timed out")
        with pytest.raises(RuntimeError, match="timeout"):
            call_claude_bridge("u", system_prompt="s")

    def test_connection_error_raises_runtime_error(self, mock_session):
        mock_session.post.side_effect = requests.exceptions.ConnectionError("bridge down")
        with pytest.raises(RuntimeError, match="connection error"):
            call_claude_bridge("u", system_prompt="s")


class TestCallBridgeUsageRecording:
    """Usage tagged with claude_bridge: prefix so it's distinguishable from
    Groq and Featherless usage in shared groq_usage.json."""

    def test_caller_tagged_with_provider_prefix(self, mock_session):
        mock_session.post.return_value = _mock_response()
        with patch("modules.groq_usage.record_usage") as rec:
            call_claude_bridge("u", system_prompt="s", caller="briefing")
        rec.assert_called_once()
        kwargs = rec.call_args.kwargs
        assert kwargs.get("caller") == "claude_bridge:briefing"
