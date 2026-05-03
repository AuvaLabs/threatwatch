"""Tests for the Featherless.ai client in modules/llm_client.py.

Covers the single-shot policy (no retries on 429/5xx so caller can fall back
to Groq instead of queuing against other projects sharing the token), the
response_format graceful fallback for non-JSON-mode models like DeepSeek/GLM,
and configuration gating via FEATHERLESS_API_KEY.
"""
from unittest.mock import MagicMock, patch

import pytest
import requests

from modules import llm_client
from modules.llm_client import call_featherless, featherless_available


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
def featherless_configured(monkeypatch):
    """Default: Featherless IS configured. Individual tests can blank it."""
    monkeypatch.setattr(llm_client, "FEATHERLESS_API_KEY", "rc_testkey1234")
    monkeypatch.setattr(llm_client, "FEATHERLESS_BASE_URL", "https://api.featherless.ai/v1")
    monkeypatch.setattr(llm_client, "FEATHERLESS_MODEL", "deepseek-ai/DeepSeek-V3.2")


@pytest.fixture(autouse=True)
def silence_usage_writes():
    """record_usage writes to disk; isolate it so tests don't litter state files."""
    with patch("modules.groq_usage.record_usage"):
        yield


class TestFeatherlessAvailable:
    def test_true_when_key_set(self):
        assert featherless_available() is True

    def test_false_when_key_blank(self, monkeypatch):
        monkeypatch.setattr(llm_client, "FEATHERLESS_API_KEY", "")
        assert featherless_available() is False


class TestCallFeatherlessSuccessPath:
    def test_returns_content(self, mock_session):
        mock_session.post.return_value = _mock_response(
            json_body={
                "choices": [{"message": {"content": "  briefing JSON here  "}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        )
        result = call_featherless("user", system_prompt="sys")
        assert result == "briefing JSON here"

    def test_uses_featherless_base_url(self, mock_session):
        mock_session.post.return_value = _mock_response()
        call_featherless("u", system_prompt="s")
        url = mock_session.post.call_args.args[0]
        assert url == "https://api.featherless.ai/v1/chat/completions"

    def test_authorization_header_uses_featherless_key(self, mock_session):
        mock_session.post.return_value = _mock_response()
        call_featherless("u", system_prompt="s")
        headers = mock_session.post.call_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer rc_testkey1234"

    def test_payload_uses_featherless_model_by_default(self, mock_session):
        mock_session.post.return_value = _mock_response()
        call_featherless("u", system_prompt="s")
        payload = mock_session.post.call_args.kwargs["json"]
        assert payload["model"] == "deepseek-ai/DeepSeek-V3.2"
        assert payload["messages"][0] == {"role": "system", "content": "s"}
        assert payload["messages"][1] == {"role": "user", "content": "u"}

    def test_explicit_model_override_wins(self, mock_session):
        mock_session.post.return_value = _mock_response()
        call_featherless("u", system_prompt="s", model="kimi-k2")
        payload = mock_session.post.call_args.kwargs["json"]
        assert payload["model"] == "kimi-k2"


class TestCallFeatherlessNotConfigured:
    def test_raises_when_key_missing(self, monkeypatch):
        monkeypatch.setattr(llm_client, "FEATHERLESS_API_KEY", "")
        with pytest.raises(RuntimeError, match="not configured"):
            call_featherless("u", system_prompt="s")


class TestCallFeatherless429:
    """Concurrency contention: surface immediately, do NOT retry."""

    def test_429_raises_runtime_error_without_retry(self, mock_session):
        mock_session.post.return_value = _mock_response(status_code=429, text="busy")
        with pytest.raises(RuntimeError, match="429"):
            call_featherless("u", system_prompt="s")
        assert mock_session.post.call_count == 1


class TestCallFeatherless5xx:
    @pytest.mark.parametrize("status", [500, 502, 503, 504])
    def test_5xx_raises_runtime_error_without_retry(self, mock_session, status):
        mock_session.post.return_value = _mock_response(status_code=status, text="oops")
        with pytest.raises(RuntimeError, match=str(status)):
            call_featherless("u", system_prompt="s")
        assert mock_session.post.call_count == 1


class TestCallFeatherlessTransportErrors:
    def test_timeout_raises_runtime_error(self, mock_session):
        mock_session.post.side_effect = requests.exceptions.Timeout("read timed out")
        with pytest.raises(RuntimeError, match="timeout"):
            call_featherless("u", system_prompt="s")

    def test_connection_error_raises_runtime_error(self, mock_session):
        mock_session.post.side_effect = requests.exceptions.ConnectionError("tcp reset")
        with pytest.raises(RuntimeError, match="connection error"):
            call_featherless("u", system_prompt="s")


class TestCallFeatherlessResponseFormatFallback:
    """DeepSeek / GLM don't natively support response_format; we retry once
    without the field, mirroring the behavior of call_llm."""

    def test_response_format_included_when_passed(self, mock_session):
        mock_session.post.return_value = _mock_response()
        call_featherless(
            "u", system_prompt="s",
            response_format={"type": "json_object"},
        )
        payload = mock_session.post.call_args.kwargs["json"]
        assert payload["response_format"] == {"type": "json_object"}

    def test_400_response_format_unsupported_triggers_retry_without_field(self, mock_session):
        reject = _mock_response(
            status_code=400,
            text="response_format is not supported on this model",
        )
        success = _mock_response(
            json_body={
                "choices": [{"message": {"content": "fallback-ok"}}],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
            }
        )
        mock_session.post.side_effect = [reject, success]
        result = call_featherless(
            "u", system_prompt="s",
            response_format={"type": "json_object"},
        )
        assert result == "fallback-ok"
        assert mock_session.post.call_count == 2
        second_payload = mock_session.post.call_args_list[1].kwargs["json"]
        assert "response_format" not in second_payload

    def test_unrelated_400_does_not_retry(self, mock_session):
        bad = _mock_response(status_code=400, text="context length exceeded")
        mock_session.post.return_value = bad
        with pytest.raises(RuntimeError):
            call_featherless(
                "u", system_prompt="s",
                response_format={"type": "json_object"},
            )
        assert mock_session.post.call_count == 1


class TestCallFeatherlessUsageRecording:
    """Usage is tagged with featherless: prefix so it's distinguishable from
    Groq usage in the shared groq_usage.json file."""

    def test_caller_tagged_with_provider_prefix(self, mock_session):
        mock_session.post.return_value = _mock_response()
        with patch("modules.groq_usage.record_usage") as rec:
            call_featherless("u", system_prompt="s", caller="briefing")
        rec.assert_called_once()
        kwargs = rec.call_args.kwargs
        assert kwargs.get("caller") == "featherless:briefing"
