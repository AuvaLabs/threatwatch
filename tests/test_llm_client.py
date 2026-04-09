"""Tests for modules/llm_client.py — Groq/OpenAI-compatible client.

Covers the response_format opt-in and the graceful 400-fallback, plus the
regression lock that non-briefing callers (hybrid_classifier, actor_profiler,
incident_correlator) continue getting exactly the original payload when they
don't pass the new kwarg.
"""
import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from modules import llm_client
from modules.llm_client import call_llm, _response_format_unsupported


def _mock_response(status_code=200, json_body=None, text=""):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.text = text
    resp.json.return_value = json_body or {
        "choices": [{"message": {"content": "ok"}}]
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
    """Patch _get_http_session to return a mock whose .post we control."""
    with patch.object(llm_client, "_get_http_session") as mock_factory:
        session = MagicMock()
        mock_factory.return_value = session
        yield session


@pytest.fixture(autouse=True)
def single_key(monkeypatch):
    """Force single-key mode so attempts=1 and we don't churn through rotation."""
    monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["test-key"])
    monkeypatch.setattr(llm_client, "LLM_API_KEY", "test-key")
    monkeypatch.setattr(llm_client, "LLM_BASE_URL", "https://api.example.com/v1")
    monkeypatch.setattr(llm_client, "LLM_MODEL", "test-model")


class TestCallLLMDefaultBehavior:
    """Regression lock: callers that omit response_format get the original payload."""

    def test_default_payload_has_no_response_format(self, mock_session):
        mock_session.post.return_value = _mock_response()
        call_llm("hello", system_prompt="You are a bot.")
        assert mock_session.post.called
        payload = mock_session.post.call_args.kwargs["json"]
        assert "response_format" not in payload, (
            "Non-opted-in callers (hybrid_classifier, actor_profiler, "
            "incident_correlator) must NEVER have response_format in payload."
        )
        assert payload["model"] == "test-model"
        assert payload["max_tokens"] == 2000
        assert payload["temperature"] == 0.3
        assert payload["messages"][0]["role"] == "system"
        assert payload["messages"][1]["role"] == "user"

    def test_default_returns_content(self, mock_session):
        mock_session.post.return_value = _mock_response(
            json_body={"choices": [{"message": {"content": "  hello world  "}}]}
        )
        result = call_llm("x", system_prompt="y")
        assert result == "hello world"

    def test_custom_max_tokens_respected(self, mock_session):
        mock_session.post.return_value = _mock_response()
        call_llm("x", system_prompt="y", max_tokens=500)
        payload = mock_session.post.call_args.kwargs["json"]
        assert payload["max_tokens"] == 500
        assert "response_format" not in payload


class TestCallLLMResponseFormat:
    """Opt-in path used by briefing_generator._call_openai_compatible."""

    def test_response_format_included_when_passed(self, mock_session):
        mock_session.post.return_value = _mock_response()
        call_llm(
            "x",
            system_prompt="y",
            response_format={"type": "json_object"},
        )
        payload = mock_session.post.call_args.kwargs["json"]
        assert payload["response_format"] == {"type": "json_object"}

    def test_response_format_reaches_groq_on_first_attempt(self, mock_session):
        mock_session.post.return_value = _mock_response()
        call_llm("x", system_prompt="y", response_format={"type": "json_object"})
        # Exactly one POST, with the field present
        assert mock_session.post.call_count == 1
        payload = mock_session.post.call_args.kwargs["json"]
        assert "response_format" in payload


class TestResponseFormatFallback:
    """When Groq rejects response_format with 400, auto-retry once without it."""

    def test_400_with_response_format_in_body_triggers_retry(self, mock_session):
        # First call: 400 with body mentioning response_format.
        # Second call: 200 with content.
        reject = _mock_response(
            status_code=400,
            text="Error: response_format is not supported for this model",
        )
        success = _mock_response(
            json_body={"choices": [{"message": {"content": "fallback-ok"}}]}
        )
        mock_session.post.side_effect = [reject, success]

        result = call_llm(
            "x", system_prompt="y", response_format={"type": "json_object"}
        )
        assert result == "fallback-ok"
        assert mock_session.post.call_count == 2

        # Second call must omit response_format
        second_payload = mock_session.post.call_args_list[1].kwargs["json"]
        assert "response_format" not in second_payload
        # Messages and model preserved
        assert second_payload["model"] == "test-model"
        assert second_payload["messages"][1]["content"] == "x"

    def test_400_unrelated_message_does_not_retry(self, mock_session):
        # Unrelated 400 (e.g. prompt too long) must bubble up, not silently retry.
        bad = _mock_response(
            status_code=400,
            text="Error: context length exceeded",
        )
        mock_session.post.return_value = bad

        with pytest.raises(requests.exceptions.HTTPError):
            call_llm(
                "x", system_prompt="y", response_format={"type": "json_object"}
            )
        # Only one POST — no spurious retry
        assert mock_session.post.call_count == 1

    def test_fallback_only_fires_once(self, mock_session):
        # If the fallback call itself also 400s, we don't loop forever.
        reject1 = _mock_response(
            status_code=400,
            text="response_format not supported",
        )
        reject2 = _mock_response(status_code=400, text="response_format again")
        mock_session.post.side_effect = [reject1, reject2]

        with pytest.raises(requests.exceptions.HTTPError):
            call_llm(
                "x", system_prompt="y", response_format={"type": "json_object"}
            )
        assert mock_session.post.call_count == 2

    def test_no_fallback_without_response_format(self, mock_session):
        # A caller that didn't opt in shouldn't get any fallback behavior —
        # a 400 must propagate normally.
        bad = _mock_response(status_code=400, text="response_format not supported")
        mock_session.post.return_value = bad

        with pytest.raises(requests.exceptions.HTTPError):
            call_llm("x", system_prompt="y")
        assert mock_session.post.call_count == 1


class TestResponseFormatUnsupportedDetector:
    def test_detects_when_body_mentions_field(self):
        resp = _mock_response(status_code=400, text="invalid response_format value")
        assert _response_format_unsupported(resp) is True

    def test_detects_case_insensitive(self):
        resp = _mock_response(status_code=400, text="Response_Format is bad")
        assert _response_format_unsupported(resp) is True

    def test_ignores_non_400(self):
        resp = _mock_response(status_code=500, text="response_format error")
        assert _response_format_unsupported(resp) is False

    def test_ignores_400_without_keyword(self):
        resp = _mock_response(status_code=400, text="context too long")
        assert _response_format_unsupported(resp) is False


class TestRateLimitFallthrough:
    """Existing 429 behavior must be preserved when response_format is also set."""

    def test_429_still_rotates_keys(self, mock_session, monkeypatch):
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["k1", "k2", "k3"])
        rl = _mock_response(status_code=429, text="rate limited")
        ok = _mock_response(
            json_body={"choices": [{"message": {"content": "done"}}]}
        )
        mock_session.post.side_effect = [rl, rl, ok]

        result = call_llm(
            "x", system_prompt="y", response_format={"type": "json_object"}
        )
        assert result == "done"
        assert mock_session.post.call_count == 3
        # Every attempt included response_format (429 doesn't trigger fallback)
        for call in mock_session.post.call_args_list:
            assert call.kwargs["json"]["response_format"] == {"type": "json_object"}
