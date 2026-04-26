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
    _normalise_headline,
    _read_prior_level,
    _stamp_previous_level,
    generate_briefing,
    load_briefing,
    _MAX_DIGEST_ARTICLES,
    _HEADLINE_SOFT_CAP,
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
# _normalise_headline
# ---------------------------------------------------------------------------
class TestNormaliseHeadline:
    def test_none_or_empty_returns_empty_string(self):
        assert _normalise_headline(None) == ""
        assert _normalise_headline("") == ""
        assert _normalise_headline("   ") == ""

    def test_short_headline_passes_through(self):
        text = "CISA adds Cisco ASA zero-day to KEV after Volt Typhoon mass exploitation."
        assert _normalise_headline(text) == text

    def test_strips_surrounding_whitespace(self):
        assert _normalise_headline("  Hello world.  ") == "Hello world."

    def test_under_soft_cap_untouched(self):
        text = "x" * _HEADLINE_SOFT_CAP
        assert _normalise_headline(text) == text

    def test_over_soft_cap_trims_at_clause_boundary(self):
        # 200 chars with a clear ", " boundary near the cap.
        prefix = "A" * 120
        text = f"{prefix}, then a tail that pushes us well past the cap and should be dropped entirely."
        result = _normalise_headline(text)
        assert result.endswith("…")
        assert len(result) <= _HEADLINE_SOFT_CAP + 1  # +1 for the ellipsis
        assert "," not in result.rstrip("…")  # clause boundary trimmed cleanly

    def test_over_cap_no_clause_falls_back_to_word_boundary(self):
        # No ", " or "; " or ". " inside the soft cap window — must word-wrap.
        text = ("supercalifragilistic " * 20).strip()  # ~420 chars, only spaces
        result = _normalise_headline(text)
        assert result.endswith("…")
        assert " " in result  # ended on a word boundary, not mid-word
        assert len(result) <= _HEADLINE_SOFT_CAP + 1


# ---------------------------------------------------------------------------
# _read_prior_level / _stamp_previous_level (escalation banner support)
# ---------------------------------------------------------------------------
class TestReadPriorLevel:
    def test_missing_file_returns_none_pair(self, tmp_path):
        assert _read_prior_level(tmp_path / "absent.json") == (None, None)

    def test_unreadable_json_returns_none_pair(self, tmp_path):
        path = tmp_path / "broken.json"
        path.write_text("not valid json {")
        assert _read_prior_level(path) == (None, None)

    def test_returns_level_and_generated_at(self, tmp_path):
        path = tmp_path / "briefing.json"
        path.write_text(json.dumps({
            "threat_level": "ELEVATED",
            "generated_at": "2026-04-26T10:00:00+00:00",
            "what_happened": "x",
        }))
        assert _read_prior_level(path) == ("ELEVATED", "2026-04-26T10:00:00+00:00")

    def test_missing_fields_return_none_in_tuple(self, tmp_path):
        path = tmp_path / "briefing.json"
        path.write_text(json.dumps({"what_happened": "x"}))
        assert _read_prior_level(path) == (None, None)


class TestStampPreviousLevel:
    def test_first_run_stamps_none(self, tmp_path):
        briefing = {"threat_level": "ELEVATED"}
        _stamp_previous_level(briefing, tmp_path / "absent.json")
        assert briefing["previous_threat_level"] is None
        assert briefing["previous_generated_at"] is None

    def test_subsequent_run_stamps_prior_level(self, tmp_path):
        path = tmp_path / "briefing.json"
        path.write_text(json.dumps({
            "threat_level": "MODERATE",
            "generated_at": "2026-04-25T08:00:00+00:00",
        }))
        briefing = {"threat_level": "ELEVATED"}
        _stamp_previous_level(briefing, path)
        assert briefing["previous_threat_level"] == "MODERATE"
        assert briefing["previous_generated_at"] == "2026-04-25T08:00:00+00:00"


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
        """Legacy responses with executive_summary/recommended_actions are accepted
        and translated into the current what_happened/what_to_do schema."""
        legacy = {
            "threat_level": "ELEVATED",
            "executive_summary": "Legacy summary.",
            "recommended_actions": ["Do thing A", "Do thing B"],
        }
        mock_call.return_value = self._mock_reply(legacy)
        result = generate_briefing([_article()])
        assert result is not None
        assert result["what_happened"] == "Legacy summary."
        assert isinstance(result["what_to_do"], list)
        assert result["what_to_do"][0]["action"] == "Do thing A"

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

    @patch("modules.briefing_generator._record_api_call")
    @patch("modules.briefing_generator._is_rate_limited", return_value=False)
    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator.cache_result")
    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._call_openai_compatible")
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_cache_key_changes_when_trailing_week_content_changes(
        self, _, mock_call, mock_cache_get, mock_cache_set, mock_save, _rl, _rec,
    ):
        """Cache key must account for 'earlier this week' articles so the
        briefing regenerates when older content rolls over, even if the
        last-24h set is identical between runs.
        """
        from datetime import datetime, timezone, timedelta

        now = datetime.now(timezone.utc)
        recent_ts = (now - timedelta(hours=2)).isoformat()
        old_ts_a = (now - timedelta(days=5)).isoformat()
        old_ts_b = (now - timedelta(days=5)).isoformat()

        # Same last-24h articles, different "earlier this week" articles
        def _fresh():
            a = _article(title="Breaking Incident Today")
            a["timestamp"] = recent_ts
            return a

        recent_shared = [_fresh() for _ in range(5)]

        old_a = _article(title="Week-Old Story A", category="Ransomware")
        old_a["timestamp"] = old_ts_a
        old_b = _article(title="Week-Old Story B", category="APT")
        old_b["timestamp"] = old_ts_b

        mock_call.return_value = json.dumps(_valid_briefing())

        generate_briefing(recent_shared + [old_a])
        key_a = mock_cache_set.call_args[0][0]

        mock_cache_set.reset_mock()
        generate_briefing(recent_shared + [old_b])
        key_b = mock_cache_set.call_args[0][0]

        assert key_a != key_b, (
            "Cache key must change when 'earlier this week' articles differ, "
            "otherwise the briefing will serve a stale week_in_review."
        )

    @patch("modules.briefing_generator._record_api_call")
    @patch("modules.briefing_generator._is_rate_limited", return_value=False)
    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator.cache_result")
    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._call_openai_compatible")
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_trailing_context_excludes_articles_in_current_briefing(
        self, _, mock_call, mock_cache_get, mock_cache_set, mock_save, _rl, _rec,
    ):
        """Day-2/3 articles pulled into briefing_articles as overflow must
        not also appear under 'EARLIER THIS WEEK'.
        """
        from datetime import datetime, timezone, timedelta

        now = datetime.now(timezone.utc)
        # Sparse last-24h -> day3 overflow gets promoted into briefing
        recent = _article(title="Today News")
        recent["timestamp"] = (now - timedelta(hours=2)).isoformat()

        day2 = _article(title="Two Day Old Story Promoted", category="Phishing")
        day2["timestamp"] = (now - timedelta(days=2)).isoformat()

        old = _article(title="Five Day Old Story", category="Ransomware")
        old["timestamp"] = (now - timedelta(days=5)).isoformat()

        mock_call.return_value = json.dumps(_valid_briefing())
        generate_briefing([recent, day2, old])

        sent_prompt = mock_call.call_args[0][0]
        # day2 title should appear once (as current incident), not duplicated
        # under the "earlier this week" notable incidents list
        earlier_section = sent_prompt.split("EARLIER THIS WEEK", 1)
        assert len(earlier_section) == 2, "trailing context should be rendered"
        trailing_block = earlier_section[1]
        assert "Two Day Old Story Promoted" not in trailing_block, (
            "articles already in the current briefing must not appear again "
            "under 'earlier this week'"
        )
        assert "Five Day Old Story" in trailing_block


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
