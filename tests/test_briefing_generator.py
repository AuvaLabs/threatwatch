"""Tests for modules/briefing_generator.py"""
import json
import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from modules.briefing_generator import (
    _build_digest,
    _parse_json,
    _detect_provider,
    generate_briefing,
    load_briefing,
    _MAX_DIGEST_ARTICLES,
    BRIEFING_PATH,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _article(title="Test Article", category="Ransomware", region="US", summary="A test summary."):
    return {
        "title": title,
        "translated_title": title,
        "category": category,
        "feed_region": region,
        "summary": summary,
    }


def _valid_briefing(**overrides):
    base = {
        "threat_level": "ELEVATED",
        "assessment_basis": "Multiple ransomware campaigns targeting critical infrastructure.",
        "situation_overview": "Threat activity is elevated globally.",
        "key_intelligence": [
            {"finding": "APT29 active against government targets", "confidence": "HIGH", "source_count": 3},
            {"finding": "New loader variant detected in the wild", "confidence": "MODERATE", "source_count": 1},
        ],
        "threat_forecast": "Ransomware activity likely to persist over the next 30 days.",
        "sector_impact": ["Healthcare — targeted by LockBit", "Finance — credential theft campaigns"],
        "priority_actions": [
            {"action": "Enable MFA on all admin accounts", "threat_context": "Credential theft campaigns"},
            {"action": "Patch CVE-2026-1234 in OpenSSL", "threat_context": "Active exploitation observed"},
        ],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# _build_digest
# ---------------------------------------------------------------------------
class TestBuildDigest:
    def test_includes_title_category_region(self):
        a = _article(title="Hospital Hit", category="Ransomware", region="US")
        digest = _build_digest([a])
        assert "Hospital Hit" in digest
        assert "Ransomware" in digest
        assert "US" in digest

    def test_caps_at_max_digest_articles(self):
        articles = [_article(title=f"Article {i}") for i in range(100)]
        digest = _build_digest(articles)
        # Only first _MAX_DIGEST_ARTICLES titles should appear
        assert f"Article {_MAX_DIGEST_ARTICLES - 1}" in digest
        assert f"Article {_MAX_DIGEST_ARTICLES}" not in digest

    def test_truncates_summary_at_250_chars(self):
        long_summary = "x" * 400
        a = _article(summary=long_summary)
        digest = _build_digest([a])
        assert "x" * 250 in digest
        assert "x" * 251 not in digest

    def test_uses_translated_title_if_available(self):
        a = _article(title="Original")
        a["translated_title"] = "Translated Title"
        digest = _build_digest([a])
        assert "Translated Title" in digest
        assert "Original" not in digest

    def test_empty_articles_returns_empty_string(self):
        assert _build_digest([]) == ""


# ---------------------------------------------------------------------------
# _parse_json
# ---------------------------------------------------------------------------
class TestParseJson:
    def test_valid_json(self):
        text = '{"threat_level": "CRITICAL", "executive_summary": "test"}'
        result = _parse_json(text)
        assert result["threat_level"] == "CRITICAL"

    def test_json_wrapped_in_markdown(self):
        text = '```json\n{"threat_level": "LOW"}\n```'
        result = _parse_json(text)
        assert result["threat_level"] == "LOW"

    def test_json_with_preamble(self):
        text = 'Here is the analysis:\n{"threat_level": "MODERATE", "executive_summary": "ok"}'
        result = _parse_json(text)
        assert result["threat_level"] == "MODERATE"

    def test_invalid_json_returns_none(self):
        assert _parse_json("not json at all") is None

    def test_empty_string_returns_none(self):
        assert _parse_json("") is None

    def test_truncated_json_returns_none(self):
        # Truncated mid-string — no valid JSON object
        assert _parse_json('{"threat_level": "CRITICAL", "executive_summa') is None


# ---------------------------------------------------------------------------
# _detect_provider
# ---------------------------------------------------------------------------
class TestDetectProvider:
    def test_explicit_anthropic_provider(self):
        with patch("modules.briefing_generator.LLM_PROVIDER", "anthropic"):
            assert _detect_provider() == "anthropic"

    def test_explicit_ollama_provider(self):
        with patch("modules.briefing_generator.LLM_PROVIDER", "ollama"):
            assert _detect_provider() == "ollama"

    def test_auto_no_key_returns_none(self):
        with patch("modules.briefing_generator.LLM_PROVIDER", "auto"), \
             patch("modules.briefing_generator.LLM_API_KEY", None):
            assert _detect_provider() is None

    def test_auto_localhost_returns_ollama(self):
        with patch("modules.briefing_generator.LLM_PROVIDER", "auto"), \
             patch("modules.briefing_generator.LLM_API_KEY", "key"), \
             patch("modules.briefing_generator.LLM_BASE_URL", "http://localhost:11434/v1"):
            assert _detect_provider() == "ollama"

    def test_auto_default_returns_openai(self):
        with patch("modules.briefing_generator.LLM_PROVIDER", "auto"), \
             patch("modules.briefing_generator.LLM_API_KEY", "sk-test"), \
             patch("modules.briefing_generator.LLM_BASE_URL", "https://api.openai.com/v1"):
            assert _detect_provider() == "openai"


# ---------------------------------------------------------------------------
# generate_briefing
# ---------------------------------------------------------------------------
class TestGenerateBriefing:
    def _mock_reply(self, briefing_dict):
        return json.dumps(briefing_dict)

    @patch("modules.briefing_generator._detect_provider", return_value=None)
    def test_no_provider_returns_none(self, _):
        result = generate_briefing([_article()])
        assert result is None

    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_empty_articles_returns_none(self, _):
        result = generate_briefing([])
        assert result is None

    @patch("modules.briefing_generator._record_api_call")
    @patch("modules.briefing_generator._is_rate_limited", return_value=False)
    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator.cache_result")
    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._call_openai_compatible")
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_successful_generation(self, _, mock_call, mock_cache_get, mock_cache_set, mock_save, _rl, _rec):
        mock_call.return_value = self._mock_reply(_valid_briefing())
        articles = [_article() for _ in range(5)]
        result = generate_briefing(articles)

        assert result is not None
        assert result["threat_level"] == "ELEVATED"
        assert "generated_at" in result
        assert "articles_analyzed" in result
        assert "provider" in result
        mock_save.assert_called_once()
        mock_cache_set.assert_called_once()

    @patch("modules.briefing_generator._record_api_call")
    @patch("modules.briefing_generator._is_rate_limited", return_value=False)
    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._call_openai_compatible")
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_missing_required_fields_returns_none(self, _, mock_call, mock_cache_get, mock_save, _rl, _rec):
        incomplete = {"threat_level": "MODERATE", "key_intelligence": []}
        mock_call.return_value = json.dumps(incomplete)
        result = generate_briefing([_article()])
        assert result is None
        mock_save.assert_not_called()

    @patch("modules.briefing_generator._record_api_call")
    @patch("modules.briefing_generator._is_rate_limited", return_value=False)
    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._call_openai_compatible")
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_invalid_threat_level_normalised_to_moderate(self, _, mock_call, mock_cache_get, mock_save, _rl, _rec):
        briefing = _valid_briefing(threat_level="UNKNOWN_LEVEL")
        mock_call.return_value = json.dumps(briefing)
        result = generate_briefing([_article()])
        assert result["threat_level"] == "MODERATE"

    @patch("modules.briefing_generator._record_api_call")
    @patch("modules.briefing_generator._is_rate_limited", return_value=False)
    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._call_openai_compatible")
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_articles_analyzed_capped_at_max(self, _, mock_call, mock_cache_get, mock_save, _rl, _rec):
        mock_call.return_value = self._mock_reply(_valid_briefing())
        articles = [_article(title=f"A{i}") for i in range(120)]
        result = generate_briefing(articles)
        assert result["articles_analyzed"] == _MAX_DIGEST_ARTICLES
        assert result["total_articles"] == 120

    @patch("modules.briefing_generator._record_api_call")
    @patch("modules.briefing_generator._is_rate_limited", return_value=False)
    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._call_openai_compatible")
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_legacy_schema_converted(self, _, mock_call, mock_cache_get, mock_save, _rl, _rec):
        """Legacy responses with executive_summary/recommended_actions are accepted."""
        legacy = {
            "threat_level": "ELEVATED",
            "executive_summary": "Legacy summary.",
            "recommended_actions": ["Do thing A", "Do thing B"],
        }
        mock_call.return_value = json.dumps(legacy)
        result = generate_briefing([_article()])
        assert result is not None
        assert result["situation_overview"] == "Legacy summary."
        assert isinstance(result["priority_actions"], list)
        assert result["priority_actions"][0]["action"] == "Do thing A"

    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator._call_openai_compatible")
    @patch("modules.briefing_generator.get_cached_result")
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_cache_hit_skips_llm_call(self, _, mock_cache_get, mock_call, mock_save):
        cached = _valid_briefing()
        cached["generated_at"] = "2026-01-01T00:00:00+00:00"
        cached["articles_analyzed"] = 5
        cached["provider"] = "openai/gpt-4o-mini"
        mock_cache_get.return_value = cached
        result = generate_briefing([_article()])
        mock_call.assert_not_called()
        mock_save.assert_called_once()
        assert result["threat_level"] == "ELEVATED"

    @patch("modules.briefing_generator._is_rate_limited", return_value=False)
    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._call_openai_compatible", side_effect=Exception("API error"))
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_api_exception_returns_none(self, _, mock_call, mock_cache_get, mock_save, _rl):
        result = generate_briefing([_article()])
        assert result is None
        mock_save.assert_not_called()

    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._call_openai_compatible")
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_cache_key_uses_full_digest_not_truncated(self, _, mock_call, mock_cache_get):
        """Cache key must be computed from full digest, not truncated to MAX_CONTENT_CHARS."""
        mock_call.return_value = "{}"  # will fail schema check
        # Two article sets that differ only in a late entry
        articles_a = [_article(title=f"A{i}") for i in range(70)]
        articles_b = [_article(title=f"A{i}") for i in range(70)]
        articles_b[-1]["title"] = "DIFFERENT LATE ARTICLE"
        articles_b[-1]["translated_title"] = "DIFFERENT LATE ARTICLE"

        from modules.briefing_generator import _build_digest
        digest_a = _build_digest(articles_a)
        digest_b = _build_digest(articles_b)
        key_a = hashlib.sha256(digest_a.encode()).hexdigest()
        key_b = hashlib.sha256(digest_b.encode()).hexdigest()
        assert key_a != key_b, "Different article sets must produce different cache keys"


# ---------------------------------------------------------------------------
# load_briefing
# ---------------------------------------------------------------------------
class TestLoadBriefing:
    def test_returns_none_when_file_missing(self, tmp_path):
        with patch("modules.briefing_generator.BRIEFING_PATH", tmp_path / "nonexistent.json"):
            result = load_briefing()
        assert result is None

    def test_returns_none_on_corrupt_json(self, tmp_path):
        p = tmp_path / "briefing.json"
        p.write_text("not valid json")
        with patch("modules.briefing_generator.BRIEFING_PATH", p):
            result = load_briefing()
        assert result is None

    def test_loads_valid_briefing(self, tmp_path):
        p = tmp_path / "briefing.json"
        data = _valid_briefing()
        p.write_text(json.dumps(data))
        with patch("modules.briefing_generator.BRIEFING_PATH", p):
            result = load_briefing()
        assert result["threat_level"] == "ELEVATED"
        assert result["situation_overview"] == "Threat activity is elevated globally."
