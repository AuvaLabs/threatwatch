"""Tests for modules/llm_client.py: OpenAI-compatible client.

Covers key rotation, failover, circuit breaker, and Kimi-specific payload
handling.
"""
import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from modules import llm_client
from modules.llm_client import (
    call_llm,
    _next_api_key, _advance_key, _get_http_session, is_available,
    reset_circuit,
)


@pytest.fixture(autouse=True)
def _reset_breaker():
    """Reset circuit breaker before each test so process-local state doesn't leak."""
    reset_circuit()
    yield
    reset_circuit()


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
    monkeypatch.setattr(llm_client, "FEATHERLESS_API_KEY", "")
    monkeypatch.setattr(llm_client, "FEATHERLESS_BASE_URL", "")
    monkeypatch.setattr(llm_client, "BRIEFING_FALLBACK_API_KEY", "")
    monkeypatch.setattr(llm_client, "BRIEFING_FALLBACK_BASE_URL", "")


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

    def test_response_format_reaches_provider_on_first_attempt(self, mock_session):
        mock_session.post.return_value = _mock_response()
        call_llm("x", system_prompt="y", response_format={"type": "json_object"})
        # Exactly one POST, with the field present
        assert mock_session.post.call_count == 1
        payload = mock_session.post.call_args.kwargs["json"]
        assert "response_format" in payload

    def test_unsupported_response_format_retries_without_field(self, mock_session):
        unsupported = _mock_response(
            status_code=400,
            text="response_format is not supported by this model",
        )
        ok = _mock_response(json_body={"choices": [{"message": {"content": "json"}}]})
        mock_session.post.side_effect = [unsupported, ok]

        result = call_llm(
            "x", system_prompt="y", response_format={"type": "json_object"}
        )

        assert result == "json"
        assert "response_format" in mock_session.post.call_args_list[0].kwargs["json"]
        assert "response_format" not in mock_session.post.call_args_list[1].kwargs["json"]


class TestProviderFailover:
    def test_primary_404_falls_back_to_secondary(self, mock_session, monkeypatch):
        monkeypatch.setattr(llm_client, "FEATHERLESS_API_KEY", "fallback-key")
        monkeypatch.setattr(llm_client, "FEATHERLESS_BASE_URL", "https://fallback.example/v1")
        monkeypatch.setattr(llm_client, "FEATHERLESS_MODEL", "fallback-model")
        primary_404 = _mock_response(status_code=404, text="model retired")
        fallback_ok = _mock_response(
            json_body={"choices": [{"message": {"content": "fallback result"}}]}
        )
        mock_session.post.side_effect = [primary_404, fallback_ok]

        result = call_llm("x", system_prompt="y", model="primary-task-model")

        assert result == "fallback result"
        calls = mock_session.post.call_args_list
        assert calls[0].args[0] == "https://api.example.com/v1/chat/completions"
        assert calls[0].kwargs["json"]["model"] == "primary-task-model"
        assert calls[1].args[0] == "https://fallback.example/v1/chat/completions"
        assert calls[1].kwargs["json"]["model"] == "fallback-model"
        assert llm_client.last_provider_label() == "featherless/fallback-model"

    def test_duplicate_provider_configuration_is_not_retried(self, mock_session, monkeypatch):
        monkeypatch.setattr(llm_client, "FEATHERLESS_API_KEY", "test-key")
        monkeypatch.setattr(llm_client, "FEATHERLESS_BASE_URL", "https://api.example.com/v1")
        monkeypatch.setattr(llm_client, "FEATHERLESS_MODEL", "test-model")
        mock_session.post.return_value = _mock_response(status_code=404, text="missing")

        with pytest.raises(RuntimeError):
            call_llm("x", system_prompt="y")

        assert mock_session.post.call_count == 1


class TestKimiEndpoint:
    """Kimi coding endpoint rejects temperature values other than 1 and
    emits reasoning tokens that count against max_tokens."""

    def test_temperature_omitted_for_kimi(self, mock_session, monkeypatch):
        monkeypatch.setattr(
            llm_client, "LLM_BASE_URL", "https://api.kimi.com/coding/v1"
        )
        mock_session.post.return_value = _mock_response()
        call_llm("x", system_prompt="y")
        payload = mock_session.post.call_args.kwargs["json"]
        assert "temperature" not in payload

    def test_temperature_kept_for_other_providers(self, mock_session, monkeypatch):
        monkeypatch.setattr(llm_client, "LLM_BASE_URL", "https://api.groq.com/openai/v1")
        mock_session.post.return_value = _mock_response()
        call_llm("x", system_prompt="y")
        payload = mock_session.post.call_args.kwargs["json"]
        assert payload["temperature"] == 0.3

    def test_small_max_tokens_floored_for_kimi(self, mock_session, monkeypatch):
        monkeypatch.setattr(
            llm_client, "LLM_BASE_URL", "https://api.kimi.com/coding/v1"
        )
        mock_session.post.return_value = _mock_response()
        call_llm("x", system_prompt="y", max_tokens=100)
        payload = mock_session.post.call_args.kwargs["json"]
        assert payload["max_tokens"] == llm_client._KIMI_MIN_MAX_TOKENS

    def test_large_max_tokens_unchanged_for_kimi(self, mock_session, monkeypatch):
        monkeypatch.setattr(
            llm_client, "LLM_BASE_URL", "https://api.kimi.com/coding/v1"
        )
        mock_session.post.return_value = _mock_response()
        call_llm("x", system_prompt="y", max_tokens=4000)
        payload = mock_session.post.call_args.kwargs["json"]
        assert payload["max_tokens"] == 4000

    def test_small_max_tokens_unchanged_for_other_providers(self, mock_session):
        mock_session.post.return_value = _mock_response()
        call_llm("x", system_prompt="y", max_tokens=100)
        payload = mock_session.post.call_args.kwargs["json"]
        assert payload["max_tokens"] == 100

    def test_default_timeout_longer_for_kimi(self, mock_session, monkeypatch):
        monkeypatch.setattr(
            llm_client, "LLM_BASE_URL", "https://api.kimi.com/coding/v1"
        )
        monkeypatch.delenv("LLM_TIMEOUT", raising=False)
        mock_session.post.return_value = _mock_response()
        call_llm("x", system_prompt="y")
        assert mock_session.post.call_args.kwargs["timeout"] == 120

    def test_default_timeout_30_for_other_providers(self, mock_session):
        mock_session.post.return_value = _mock_response()
        call_llm("x", system_prompt="y")
        assert mock_session.post.call_args.kwargs["timeout"] == 30

    def test_llm_timeout_env_overrides_default(self, mock_session, monkeypatch):
        monkeypatch.setenv("LLM_TIMEOUT", "45")
        mock_session.post.return_value = _mock_response()
        call_llm("x", system_prompt="y")
        assert mock_session.post.call_args.kwargs["timeout"] == 45


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
        # Every attempt included response_format
        for call in mock_session.post.call_args_list:
            assert call.kwargs["json"]["response_format"] == {"type": "json_object"}


class TestNextApiKey:
    def test_single_key(self, monkeypatch):
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["only-key"])
        monkeypatch.setattr(llm_client, "LLM_API_KEY", "only-key")
        assert _next_api_key() == "only-key"

    def test_rotates_multiple_keys(self, monkeypatch, tmp_path):
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["k1", "k2", "k3"])
        monkeypatch.setattr(llm_client, "LLM_API_KEY", "k1")
        monkeypatch.setattr(llm_client, "_key_index_path", tmp_path / ".idx")
        k1 = _next_api_key()
        k2 = _next_api_key()
        k3 = _next_api_key()
        assert {k1, k2, k3} == {"k1", "k2", "k3"}


class TestAdvanceKey:
    def test_advances_index(self, monkeypatch, tmp_path):
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["k1", "k2"])
        monkeypatch.setattr(llm_client, "_key_index_path", tmp_path / ".idx")
        (tmp_path / ".idx").write_text("0")
        _advance_key()
        assert (tmp_path / ".idx").read_text() == "1"


class TestGetHttpSession:
    def test_returns_plain_session(self):
        """urllib3 Retry was removed: it used to sleep for the full Retry-After
        header duration on 429/503, which turned a single load-shed into
        hours of blocked pipeline time. Retry is now handled by key rotation
        in the outer loop."""
        session = _get_http_session()
        assert isinstance(session, requests.Session)
        adapter = session.get_adapter("https://example.com")
        assert adapter.max_retries.total == 0


class TestIsAvailable:
    def test_true_with_key(self, monkeypatch):
        monkeypatch.setattr(llm_client, "LLM_API_KEY", "test-key")
        assert is_available() is True

    def test_false_without_key(self, monkeypatch):
        monkeypatch.setattr(llm_client, "LLM_API_KEY", "")
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", [])
        assert is_available() is False


class TestAllKeysExhausted:
    def test_raises_runtime_error(self, mock_session, monkeypatch):
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["k1"])
        rl = _mock_response(status_code=429, text="rate limited")
        mock_session.post.return_value = rl
        with pytest.raises(RuntimeError, match="exhausted"):
            call_llm("x", system_prompt="y")


class TestUpstream5xxFailover:
    """500/502/503/504 must rotate to next key without retry.

    Previously urllib3.Retry retried in-adapter and respected Retry-After on
    503s, which blocked the pipeline for hours during load-shed events.
    """

    def test_503_rotates_to_next_key(self, mock_session, monkeypatch):
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["k1", "k2"])
        fail = _mock_response(status_code=503, text="unavailable")
        ok = _mock_response(json_body={"choices": [{"message": {"content": "hi"}}]})
        mock_session.post.side_effect = [fail, ok]
        result = call_llm("x", system_prompt="y")
        assert result == "hi"
        assert mock_session.post.call_count == 2

    def test_500_rotates_to_next_key(self, mock_session, monkeypatch):
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["k1", "k2"])
        fail = _mock_response(status_code=500, text="internal error")
        ok = _mock_response()
        mock_session.post.side_effect = [fail, ok]
        call_llm("x", system_prompt="y")
        assert mock_session.post.call_count == 2


class TestTimeoutFailover:
    def test_timeout_rotates_to_next_key(self, mock_session, monkeypatch):
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["k1", "k2"])
        ok = _mock_response()
        mock_session.post.side_effect = [
            requests.exceptions.Timeout("read timed out"),
            ok,
        ]
        result = call_llm("x", system_prompt="y")
        assert result == "ok"
        assert mock_session.post.call_count == 2


class TestConnectionErrorFailover:
    def test_connection_error_rotates_to_next_key(self, mock_session, monkeypatch):
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["k1", "k2"])
        ok = _mock_response()
        mock_session.post.side_effect = [
            requests.exceptions.ConnectionError("tcp reset"),
            ok,
        ]
        result = call_llm("x", system_prompt="y")
        assert result == "ok"


class TestHTTPErrorRateLimitPath:
    """raise_for_status() → HTTPError with status 429 must rotate keys too.

    The earlier 429 check on resp.status_code handles the normal path, but
    resp.raise_for_status() turning a 429 into an HTTPError is a separate
    code path that also needs failover — regression lock.
    """

    def test_http_error_429_rotates(self, mock_session, monkeypatch):
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["k1", "k2"])
        # First response: status=200 but raise_for_status() raises with 429
        # response attached (simulates raise_for_status quirk).
        fail = MagicMock(spec=requests.Response)
        fail.status_code = 200
        fail.text = ""
        fail.json.return_value = {"choices": [{"message": {"content": "x"}}]}
        err = requests.exceptions.HTTPError("429 via raise")
        err429_resp = MagicMock(spec=requests.Response)
        err429_resp.status_code = 429
        err.response = err429_resp
        fail.raise_for_status = MagicMock(side_effect=err)

        ok = _mock_response()
        mock_session.post.side_effect = [fail, ok]
        result = call_llm("x", system_prompt="y")
        assert result == "ok"


class TestKeyRotationPersistence:
    """_next_api_key persists the index to disk; _advance_key bumps it."""

    def test_key_index_round_robin(self, tmp_path, monkeypatch):
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["k1", "k2", "k3"])
        monkeypatch.setattr(llm_client, "_key_index_path", tmp_path / ".idx")
        keys = [llm_client._next_api_key() for _ in range(7)]
        assert keys == ["k1", "k2", "k3", "k1", "k2", "k3", "k1"]

    def test_corrupt_index_resets_to_zero(self, tmp_path, monkeypatch):
        idx = tmp_path / ".idx"
        idx.write_text("not-a-number")
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["k1", "k2"])
        monkeypatch.setattr(llm_client, "_key_index_path", idx)
        # Should not raise; resets to 0 (returns k1).
        assert llm_client._next_api_key() == "k1"

    def test_advance_key_survives_corrupt_index(self, tmp_path, monkeypatch):
        idx = tmp_path / ".idx"
        idx.write_text("garbage")
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["k1", "k2"])
        monkeypatch.setattr(llm_client, "_key_index_path", idx)
        # Should not raise.
        llm_client._advance_key()


class TestCircuitBreaker:
    """Circuit breaker caps cascade failures within a single pipeline run."""

    def test_trips_after_threshold_consecutive_failures(self, mock_session, monkeypatch):
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["k1"])
        monkeypatch.setattr(llm_client, "_LLM_CIRCUIT_THRESHOLD", 2)
        mock_session.post.return_value = _mock_response(status_code=503, text="err")

        # First two failures should actually attempt the network call.
        with pytest.raises(RuntimeError):
            call_llm("x", system_prompt="y")
        with pytest.raises(RuntimeError):
            call_llm("x", system_prompt="y")

        calls_before = mock_session.post.call_count
        # Third call should short-circuit without hitting the network.
        with pytest.raises(RuntimeError, match="circuit breaker open"):
            call_llm("x", system_prompt="y")
        assert mock_session.post.call_count == calls_before

    def test_success_resets_consecutive_failures(self, mock_session, monkeypatch):
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["k1"])
        monkeypatch.setattr(llm_client, "_LLM_CIRCUIT_THRESHOLD", 2)
        fail = _mock_response(status_code=503, text="err")
        ok = _mock_response()
        # Fail once, succeed once, fail once — circuit should NOT trip since
        # failures are not consecutive.
        mock_session.post.side_effect = [fail, ok, fail]
        with pytest.raises(RuntimeError):
            call_llm("x", system_prompt="y")
        call_llm("x", system_prompt="y")  # success resets
        with pytest.raises(RuntimeError):
            call_llm("x", system_prompt="y")
        # Still only one consecutive failure; circuit not tripped.
        assert not llm_client._circuit_open()

    def test_reset_circuit_clears_state(self, mock_session, monkeypatch):
        monkeypatch.setattr(llm_client, "LLM_API_KEYS", ["k1"])
        monkeypatch.setattr(llm_client, "_LLM_CIRCUIT_THRESHOLD", 1)
        mock_session.post.return_value = _mock_response(status_code=503, text="err")
        with pytest.raises(RuntimeError):
            call_llm("x", system_prompt="y")
        assert llm_client._circuit_open()
        reset_circuit()
        assert not llm_client._circuit_open()
