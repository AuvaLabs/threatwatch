"""Tests for the Featherless-vs-Groq routing in briefing_generator._call_openai_compatible.

The global daily briefing prompt (~7-8K tokens) exceeds Groq free-tier 6K TPM,
so when Featherless is configured we route the briefing through it (32K ctx).
On any failure we fall back to Groq + the lighter BRIEFING_MODEL so the
feature degrades gracefully rather than going dark. Regional briefings and
top-stories continue to use Groq directly.
"""
from unittest.mock import patch

import pytest

from modules import briefing_generator


@pytest.fixture
def feather_on(monkeypatch):
    monkeypatch.setattr(briefing_generator, "_featherless_available", lambda: True)
    # Default: bridge OFF so existing tests stay focused on Featherless<->Groq.
    monkeypatch.setattr(briefing_generator, "_claude_bridge_available", lambda: False)


@pytest.fixture
def feather_off(monkeypatch):
    monkeypatch.setattr(briefing_generator, "_featherless_available", lambda: False)
    monkeypatch.setattr(briefing_generator, "_claude_bridge_available", lambda: False)


@pytest.fixture
def bridge_on(monkeypatch):
    """Bridge configured + Featherless not (or down). Use with feather_on/off."""
    monkeypatch.setattr(briefing_generator, "_claude_bridge_available", lambda: True)


class TestPreferFeatherlessTrue:
    def test_uses_featherless_when_configured(self, feather_on):
        with patch.object(briefing_generator, "_call_featherless", return_value="feather-out") as ff, \
             patch.object(briefing_generator, "_call_groq") as groq:
            result = briefing_generator._call_openai_compatible(
                "user content", caller="briefing",
                model="llama-3.1-8b-instant", max_tokens=1200,
                prefer_featherless=True,
            )
        assert result == "feather-out"
        ff.assert_called_once()
        groq.assert_not_called()

    def test_passes_featherless_model_not_briefing_model(self, feather_on, monkeypatch):
        """When routing to Featherless we override the Groq-tuned `model`
        kwarg with FEATHERLESS_MODEL — passing llama-3.1-8b-instant to
        Featherless would 404."""
        monkeypatch.setattr(briefing_generator, "FEATHERLESS_MODEL", "deepseek-v3.2")
        with patch.object(briefing_generator, "_call_featherless", return_value="ok") as ff, \
             patch.object(briefing_generator, "_call_groq"):
            briefing_generator._call_openai_compatible(
                "u", caller="briefing",
                model="llama-3.1-8b-instant",
                prefer_featherless=True,
            )
        kwargs = ff.call_args.kwargs
        assert kwargs["model"] == "deepseek-v3.2"

    def test_falls_back_to_groq_on_featherless_failure(self, feather_on):
        with patch.object(
            briefing_generator, "_call_featherless",
            side_effect=RuntimeError("Featherless 429 (concurrency exhausted)"),
        ) as ff, patch.object(
            briefing_generator, "_call_groq", return_value="groq-fallback",
        ) as groq:
            result = briefing_generator._call_openai_compatible(
                "u", caller="briefing",
                model="llama-3.1-8b-instant", max_tokens=1200,
                prefer_featherless=True,
            )
        assert result == "groq-fallback"
        ff.assert_called_once()
        groq.assert_called_once()
        assert groq.call_args.kwargs["model"] == "llama-3.1-8b-instant"

    def test_skips_featherless_when_unavailable(self, feather_off):
        with patch.object(briefing_generator, "_call_featherless") as ff, \
             patch.object(briefing_generator, "_call_groq", return_value="groq-only") as groq:
            result = briefing_generator._call_openai_compatible(
                "u", caller="briefing",
                model="llama-3.1-8b-instant",
                prefer_featherless=True,
            )
        assert result == "groq-only"
        ff.assert_not_called()
        groq.assert_called_once()


class TestPreferFeatherlessFalse:
    """Regional briefings, top stories, summaries: never touch Featherless."""

    def test_regional_call_stays_on_groq(self, feather_on):
        with patch.object(briefing_generator, "_call_featherless") as ff, \
             patch.object(briefing_generator, "_call_groq", return_value="ok") as groq:
            briefing_generator._call_openai_compatible(
                "u", caller="regional",
            )
        ff.assert_not_called()
        groq.assert_called_once()


class TestFeatherlessCallShape:
    def test_response_format_json_object_passed_to_featherless(self, feather_on):
        with patch.object(briefing_generator, "_call_featherless", return_value="ok") as ff, \
             patch.object(briefing_generator, "_call_groq"):
            briefing_generator._call_openai_compatible(
                "u", caller="briefing",
                prefer_featherless=True,
            )
        kwargs = ff.call_args.kwargs
        assert kwargs["response_format"] == {"type": "json_object"}
        assert kwargs["caller"] == "briefing"

    def test_groq_fallback_preserves_response_format(self, feather_on):
        """Even when Featherless fails, Groq fallback still gets JSON mode."""
        with patch.object(
            briefing_generator, "_call_featherless",
            side_effect=RuntimeError("transport"),
        ), patch.object(
            briefing_generator, "_call_groq", return_value="ok",
        ) as groq:
            briefing_generator._call_openai_compatible(
                "u", caller="briefing",
                model="llama-3.1-8b-instant",
                prefer_featherless=True,
            )
        kwargs = groq.call_args.kwargs
        assert kwargs["response_format"] == {"type": "json_object"}


class TestSplitMaxTokens:
    """Featherless's 32K ctx allows a richer briefing than Groq's 6K TPM.
    feather_max_tokens decouples the two so the Groq fallback still fits."""

    def test_feather_max_tokens_used_on_featherless_path(self, feather_on):
        with patch.object(briefing_generator, "_call_featherless", return_value="ok") as ff, \
             patch.object(briefing_generator, "_call_groq"):
            briefing_generator._call_openai_compatible(
                "u", caller="briefing",
                max_tokens=1200, feather_max_tokens=4000,
                prefer_featherless=True,
            )
        assert ff.call_args.kwargs["max_tokens"] == 4000

    def test_groq_fallback_uses_smaller_max_tokens(self, feather_on):
        """Critical: the Groq fallback must NOT receive 4000 — it would 429
        on free-tier TPM. Each provider keeps its own cap."""
        with patch.object(
            briefing_generator, "_call_featherless",
            side_effect=RuntimeError("feather down"),
        ), patch.object(
            briefing_generator, "_call_groq", return_value="ok",
        ) as groq:
            briefing_generator._call_openai_compatible(
                "u", caller="briefing",
                max_tokens=1200, feather_max_tokens=4000,
                prefer_featherless=True,
            )
        assert groq.call_args.kwargs["max_tokens"] == 1200

    def test_default_falls_back_to_max_tokens_when_feather_unset(self, feather_on):
        """If a caller doesn't opt in, Featherless gets the same cap as Groq —
        preserves prior behavior so existing call sites are unaffected."""
        with patch.object(briefing_generator, "_call_featherless", return_value="ok") as ff, \
             patch.object(briefing_generator, "_call_groq"):
            briefing_generator._call_openai_compatible(
                "u", caller="briefing",
                max_tokens=1500,  # no feather_max_tokens
                prefer_featherless=True,
            )
        assert ff.call_args.kwargs["max_tokens"] == 1500


class TestThreeTierCascade:
    """Briefing cascade: Featherless → Claude Bridge → Groq.
    Each tier is independent: gated by its own *_available() check;
    a failure on tier N tries tier N+1, never re-tries tier N.
    """

    def test_bridge_used_when_featherless_unavailable(self, feather_off, bridge_on):
        with patch.object(briefing_generator, "_call_featherless") as ff, \
             patch.object(briefing_generator, "_call_claude_bridge", return_value="bridge-ok") as br, \
             patch.object(briefing_generator, "_call_groq") as groq:
            result = briefing_generator._call_openai_compatible(
                "u", caller="briefing",
                model="llama-3.1-8b-instant",
                prefer_featherless=True,
            )
        assert result == "bridge-ok"
        ff.assert_not_called()
        br.assert_called_once()
        groq.assert_not_called()

    def test_bridge_used_when_featherless_fails(self, feather_on, bridge_on):
        with patch.object(
            briefing_generator, "_call_featherless",
            side_effect=RuntimeError("Featherless 429"),
        ) as ff, patch.object(
            briefing_generator, "_call_claude_bridge", return_value="bridge-ok",
        ) as br, patch.object(
            briefing_generator, "_call_groq",
        ) as groq:
            result = briefing_generator._call_openai_compatible(
                "u", caller="briefing",
                model="llama-3.1-8b-instant",
                prefer_featherless=True,
            )
        assert result == "bridge-ok"
        ff.assert_called_once()
        br.assert_called_once()
        groq.assert_not_called()

    def test_groq_used_when_both_premium_tiers_fail(self, feather_on, bridge_on):
        with patch.object(
            briefing_generator, "_call_featherless",
            side_effect=RuntimeError("Featherless 429"),
        ) as ff, patch.object(
            briefing_generator, "_call_claude_bridge",
            side_effect=RuntimeError("Bridge 504"),
        ) as br, patch.object(
            briefing_generator, "_call_groq", return_value="groq-final",
        ) as groq:
            result = briefing_generator._call_openai_compatible(
                "u", caller="briefing",
                model="llama-3.1-8b-instant", max_tokens=1200,
                feather_max_tokens=4000,
                prefer_featherless=True,
            )
        assert result == "groq-final"
        ff.assert_called_once()
        br.assert_called_once()
        groq.assert_called_once()
        # Groq fallback uses the small max_tokens (fits 6K TPM), not the 4000.
        assert groq.call_args.kwargs["max_tokens"] == 1200
        assert groq.call_args.kwargs["model"] == "llama-3.1-8b-instant"

    def test_bridge_skipped_when_prefer_featherless_false(self, feather_on, bridge_on):
        """Bridge is part of the briefing cascade only — regional/top-stories
        callers must never accidentally route through it."""
        with patch.object(briefing_generator, "_call_featherless") as ff, \
             patch.object(briefing_generator, "_call_claude_bridge") as br, \
             patch.object(briefing_generator, "_call_groq", return_value="ok") as groq:
            briefing_generator._call_openai_compatible(
                "u", caller="regional",
                # prefer_featherless defaults to False
            )
        ff.assert_not_called()
        br.assert_not_called()
        groq.assert_called_once()

    def test_bridge_receives_feather_max_tokens(self, feather_off, bridge_on):
        """The bridge ignores max_tokens internally but we still pass the
        Featherless-tier value (not the smaller Groq value) so the
        downstream prompt expects a richer reply."""
        with patch.object(briefing_generator, "_call_claude_bridge", return_value="ok") as br, \
             patch.object(briefing_generator, "_call_groq"):
            briefing_generator._call_openai_compatible(
                "u", caller="briefing",
                max_tokens=1200, feather_max_tokens=4000,
                prefer_featherless=True,
            )
        assert br.call_args.kwargs["max_tokens"] == 4000

    def test_bridge_uses_claude_bridge_model_not_groq_model(self, feather_off, bridge_on, monkeypatch):
        """When routing to Bridge we override the Groq-tuned `model`
        kwarg with CLAUDE_BRIDGE_MODEL — passing llama-3.1-8b-instant
        to Sonnet would 404."""
        monkeypatch.setattr(briefing_generator, "CLAUDE_BRIDGE_MODEL", "sonnet")
        with patch.object(briefing_generator, "_call_claude_bridge", return_value="ok") as br, \
             patch.object(briefing_generator, "_call_groq"):
            briefing_generator._call_openai_compatible(
                "u", caller="briefing",
                model="llama-3.1-8b-instant",
                prefer_featherless=True,
            )
        assert br.call_args.kwargs["model"] == "sonnet"
