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
    _validate_cve_grounding,
    _strip_ungrounded_cves,
    _briefing_has_body,
    generate_briefing,
    load_briefing,
    _MAX_DIGEST_ARTICLES,
    _MAX_BRIEFING_ARTICLES,
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
            {"action": "Patch OpenSSL to the latest release", "threat_context": "Active exploitation observed"},
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

    def test_truncates_summary_at_digest_summary_chars(self):
        from modules.briefing_generator import _DIGEST_SUMMARY_CHARS
        long_summary = "x" * 400
        a = _article(summary=long_summary)
        digest = _build_digest([a])
        assert "x" * _DIGEST_SUMMARY_CHARS in digest
        assert "x" * (_DIGEST_SUMMARY_CHARS + 1) not in digest

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
        stamped = _stamp_previous_level(briefing, tmp_path / "absent.json")
        assert stamped["previous_threat_level"] is None
        assert stamped["previous_generated_at"] is None
        # Non-mutating: original briefing must be unchanged.
        assert "previous_threat_level" not in briefing

    def test_subsequent_run_stamps_prior_level(self, tmp_path):
        path = tmp_path / "briefing.json"
        path.write_text(json.dumps({
            "threat_level": "MODERATE",
            "generated_at": "2026-04-25T08:00:00+00:00",
        }))
        briefing = {"threat_level": "ELEVATED"}
        stamped = _stamp_previous_level(briefing, path)
        assert stamped["previous_threat_level"] == "MODERATE"
        assert stamped["previous_generated_at"] == "2026-04-25T08:00:00+00:00"
        # Non-mutating: the returned dict carries the stamps, original does not.
        assert "previous_threat_level" not in briefing


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
        assert result["articles_analyzed"] == _MAX_BRIEFING_ARTICLES
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
# Issue #3 — `provider` field + success log report the actual served tier
# (Featherless / Claude Bridge / Groq) instead of always echoing BRIEFING_MODEL.
# These tests exercise the real `_call_openai_compatible` code path and only
# mock the innermost tier callables, so the `_LAST_SERVED_TIER` sentinel
# actually gets set and read end-to-end.
# ---------------------------------------------------------------------------
class TestServedTierLogging:
    def setup_method(self):
        import modules.briefing_generator as _bg
        _bg._LAST_SERVED_TIER = None

    def teardown_method(self):
        import modules.briefing_generator as _bg
        _bg._LAST_SERVED_TIER = None

    @patch("modules.briefing_generator._record_api_call")
    @patch("modules.briefing_generator._is_rate_limited", return_value=False)
    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator.cache_result")
    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._featherless_available", return_value=True)
    @patch("modules.briefing_generator._call_featherless")
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_provider_reflects_featherless_when_featherless_serves(
        self, _, mock_feather, _ff_avail, _cache_get, _cache_set, _save, _rl, _rec,
    ):
        from modules.briefing_generator import FEATHERLESS_MODEL
        mock_feather.return_value = json.dumps(_valid_briefing())
        result = generate_briefing([_article() for _ in range(5)])
        assert result is not None
        assert result["provider"] == f"featherless/{FEATHERLESS_MODEL}"
        mock_feather.assert_called_once()

    @patch("modules.briefing_generator._record_api_call")
    @patch("modules.briefing_generator._is_rate_limited", return_value=False)
    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator.cache_result")
    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._call_claude_bridge")
    @patch("modules.briefing_generator._claude_bridge_available", return_value=True)
    @patch("modules.briefing_generator._call_featherless", side_effect=Exception("featherless 429"))
    @patch("modules.briefing_generator._featherless_available", return_value=True)
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_provider_reflects_claude_bridge_when_featherless_fails(
        self, _, _ff_avail, _ff_call, _cb_avail, mock_bridge,
        _cache_get, _cache_set, _save, _rl, _rec,
    ):
        from modules.briefing_generator import CLAUDE_BRIDGE_MODEL
        mock_bridge.return_value = json.dumps(_valid_briefing())
        result = generate_briefing([_article() for _ in range(5)])
        assert result is not None
        assert result["provider"] == f"claude_bridge/{CLAUDE_BRIDGE_MODEL}"
        mock_bridge.assert_called_once()

    @patch("modules.briefing_generator._record_api_call")
    @patch("modules.briefing_generator._is_rate_limited", return_value=False)
    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator.cache_result")
    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._call_groq")
    @patch("modules.briefing_generator._call_claude_bridge", side_effect=Exception("bridge down"))
    @patch("modules.briefing_generator._claude_bridge_available", return_value=True)
    @patch("modules.briefing_generator._call_featherless", side_effect=Exception("featherless 429"))
    @patch("modules.briefing_generator._featherless_available", return_value=True)
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_provider_reflects_groq_when_premium_tiers_fail(
        self, _, _ff_avail, _ff_call, _cb_avail, _cb_call, mock_groq,
        _cache_get, _cache_set, _save, _rl, _rec,
    ):
        from modules.briefing_generator import BRIEFING_MODEL
        mock_groq.return_value = json.dumps(_valid_briefing())
        result = generate_briefing([_article() for _ in range(5)])
        assert result is not None
        # Global briefing passes BRIEFING_MODEL into _call_openai_compatible
        # as the model kwarg, so the Groq tier reports that model.
        assert result["provider"] == f"groq/{BRIEFING_MODEL}"
        mock_groq.assert_called_once()

    @patch("modules.briefing_generator._record_api_call")
    @patch("modules.briefing_generator._is_rate_limited", return_value=False)
    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator.cache_result")
    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._call_groq")
    @patch("modules.briefing_generator._claude_bridge_available", return_value=False)
    @patch("modules.briefing_generator._featherless_available", return_value=False)
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_provider_reflects_groq_when_no_premium_tier_configured(
        self, _, _ff_avail, _cb_avail, mock_groq,
        _cache_get, _cache_set, _save, _rl, _rec,
    ):
        from modules.briefing_generator import BRIEFING_MODEL
        mock_groq.return_value = json.dumps(_valid_briefing())
        result = generate_briefing([_article() for _ in range(5)])
        assert result is not None
        assert result["provider"] == f"groq/{BRIEFING_MODEL}"
        mock_groq.assert_called_once()

    @patch("modules.briefing_generator._record_api_call")
    @patch("modules.briefing_generator._is_rate_limited", return_value=False)
    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator.cache_result")
    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._featherless_available", return_value=True)
    @patch("modules.briefing_generator._call_featherless")
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_success_log_line_includes_actual_served_tier(
        self, _, mock_feather, _ff_avail, _cache_get, _cache_set, _save, _rl, _rec, caplog,
    ):
        """Issue #3 fix: success log must say "via featherless/..." not the
        old misleading "via openai/llama-3.1-8b-instant" regardless of tier.
        """
        import logging
        from modules.briefing_generator import FEATHERLESS_MODEL
        mock_feather.return_value = json.dumps(_valid_briefing())
        with caplog.at_level(logging.INFO, logger="modules.briefing_generator"):
            generate_briefing([_article() for _ in range(5)])
        success_lines = [r.message for r in caplog.records
                         if "Intelligence briefing generated via" in r.message]
        assert success_lines, "expected one 'Intelligence briefing generated via' log line"
        assert f"via featherless/{FEATHERLESS_MODEL}" in success_lines[-1]
        # Belt-and-braces: the misleading legacy format must NOT appear.
        assert "via openai/" not in success_lines[-1]


# ---------------------------------------------------------------------------
# Tier-aware downgrade guard — Featherless (primary) is protected from being
# overwritten by Groq 8b fallback within BRIEFING_DOWNGRADE_GUARD_HOURS.
# ---------------------------------------------------------------------------
class TestTierRank:
    def test_featherless_is_rank_1(self):
        from modules.briefing_generator import _tier_rank
        assert _tier_rank("featherless/deepseek-ai/DeepSeek-V3.2") == 1

    def test_anthropic_is_rank_2(self):
        from modules.briefing_generator import _tier_rank
        assert _tier_rank("anthropic/claude-sonnet") == 2

    def test_claude_bridge_is_rank_2(self):
        from modules.briefing_generator import _tier_rank
        assert _tier_rank("claude_bridge/sonnet") == 2

    def test_groq_is_rank_3(self):
        from modules.briefing_generator import _tier_rank
        assert _tier_rank("groq/llama-3.1-8b-instant") == 3

    def test_legacy_openai_is_rank_3(self):
        from modules.briefing_generator import _tier_rank
        assert _tier_rank("openai/llama-3.1-8b-instant") == 3

    def test_none_is_rank_99(self):
        from modules.briefing_generator import _tier_rank
        assert _tier_rank(None) == 99

    def test_unknown_is_rank_99(self):
        from modules.briefing_generator import _tier_rank
        assert _tier_rank("mystery/whatever") == 99


class TestBriefingAgeHours:
    def test_missing_briefing_is_infinity(self):
        from modules.briefing_generator import _briefing_age_hours
        assert _briefing_age_hours(None) == float("inf")
        assert _briefing_age_hours({}) == float("inf")
        assert _briefing_age_hours({"generated_at": None}) == float("inf")

    def test_unparseable_is_infinity(self):
        from modules.briefing_generator import _briefing_age_hours
        assert _briefing_age_hours({"generated_at": "not a date"}) == float("inf")

    def test_recent_iso_returns_small_hours(self):
        from datetime import datetime, timezone, timedelta
        from modules.briefing_generator import _briefing_age_hours
        ts = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        h = _briefing_age_hours({"generated_at": ts})
        assert 1.9 < h < 2.1

    def test_z_suffix_iso_parses(self):
        from datetime import datetime, timezone, timedelta
        from modules.briefing_generator import _briefing_age_hours
        ts = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        h = _briefing_age_hours({"generated_at": ts})
        assert 0.9 < h < 1.1


class TestShouldSkipDowngrade:
    def _prior(self, provider, age_hours):
        from datetime import datetime, timezone, timedelta
        ts = (datetime.now(timezone.utc) - timedelta(hours=age_hours)).isoformat()
        return {"provider": provider, "generated_at": ts}

    def test_guard_disabled_never_skips(self):
        import modules.briefing_generator as bg
        prior = self._prior("featherless/deepseek-ai/DeepSeek-V3.2", 1)
        with patch.object(bg, "_BRIEFING_DOWNGRADE_GUARD_H", 0):
            assert bg._should_skip_downgrade(prior, "groq/llama-3.1-8b-instant") is False

    def test_no_prior_never_skips(self):
        import modules.briefing_generator as bg
        with patch.object(bg, "_BRIEFING_DOWNGRADE_GUARD_H", 4.0):
            assert bg._should_skip_downgrade(None, "groq/llama-3.1-8b-instant") is False
            assert bg._should_skip_downgrade({}, "groq/llama-3.1-8b-instant") is False

    def test_prior_without_provider_never_skips(self):
        import modules.briefing_generator as bg
        with patch.object(bg, "_BRIEFING_DOWNGRADE_GUARD_H", 4.0):
            assert bg._should_skip_downgrade({"generated_at": "2026-05-14T00:00:00+00:00"},
                                              "groq/llama-3.1-8b-instant") is False

    def test_same_tier_never_skips(self):
        import modules.briefing_generator as bg
        prior = self._prior("featherless/deepseek-ai/DeepSeek-V3.2", 1)
        with patch.object(bg, "_BRIEFING_DOWNGRADE_GUARD_H", 4.0):
            assert bg._should_skip_downgrade(prior, "featherless/deepseek-ai/DeepSeek-V3.2") is False

    def test_upgrade_never_skips(self):
        import modules.briefing_generator as bg
        prior = self._prior("groq/llama-3.1-8b-instant", 1)
        with patch.object(bg, "_BRIEFING_DOWNGRADE_GUARD_H", 4.0):
            assert bg._should_skip_downgrade(prior, "featherless/deepseek-ai/DeepSeek-V3.2") is False

    def test_downgrade_within_window_skips(self):
        """Featherless 1h old, new Groq → keep the Featherless one."""
        import modules.briefing_generator as bg
        prior = self._prior("featherless/deepseek-ai/DeepSeek-V3.2", 1)
        with patch.object(bg, "_BRIEFING_DOWNGRADE_GUARD_H", 4.0):
            assert bg._should_skip_downgrade(prior, "groq/llama-3.1-8b-instant") is True

    def test_downgrade_outside_window_overwrites(self):
        """Featherless 5h old (guard=4h), new Groq → save the new one."""
        import modules.briefing_generator as bg
        prior = self._prior("featherless/deepseek-ai/DeepSeek-V3.2", 5)
        with patch.object(bg, "_BRIEFING_DOWNGRADE_GUARD_H", 4.0):
            assert bg._should_skip_downgrade(prior, "groq/llama-3.1-8b-instant") is False

    def test_claude_bridge_protected_from_groq(self):
        """Tier 2 (Bridge) is still better than tier 3 (Groq) — guard fires."""
        import modules.briefing_generator as bg
        prior = self._prior("claude_bridge/sonnet", 1)
        with patch.object(bg, "_BRIEFING_DOWNGRADE_GUARD_H", 4.0):
            assert bg._should_skip_downgrade(prior, "groq/llama-3.1-8b-instant") is True

    def test_featherless_not_protected_from_claude_bridge(self):
        """A Bridge briefing is acceptable if Featherless is unreachable, but
        the guard treats Featherless > Bridge. So a fresh Featherless prior
        DOES skip a Bridge new briefing within the window. Documents intent."""
        import modules.briefing_generator as bg
        prior = self._prior("featherless/deepseek-ai/DeepSeek-V3.2", 1)
        with patch.object(bg, "_BRIEFING_DOWNGRADE_GUARD_H", 4.0):
            assert bg._should_skip_downgrade(prior, "claude_bridge/sonnet") is True


class TestDowngradeGuardEndToEnd:
    """Drive generate_briefing through the guard logic end-to-end."""
    def setup_method(self):
        import modules.briefing_generator as _bg
        _bg._LAST_SERVED_TIER = None

    def teardown_method(self):
        import modules.briefing_generator as _bg
        _bg._LAST_SERVED_TIER = None

    @patch("modules.briefing_generator._record_api_call")
    @patch("modules.briefing_generator._is_rate_limited", return_value=False)
    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator.cache_result")
    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._call_groq")
    @patch("modules.briefing_generator._call_claude_bridge", side_effect=Exception("bridge 502"))
    @patch("modules.briefing_generator._claude_bridge_available", return_value=True)
    @patch("modules.briefing_generator._call_featherless", side_effect=Exception("featherless 429"))
    @patch("modules.briefing_generator._featherless_available", return_value=True)
    @patch("modules.briefing_generator.load_briefing")
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_fresh_featherless_prior_blocks_groq_downgrade(
        self, _, mock_load_prior, _ff_avail, _ff_call, _cb_avail, _cb_call,
        mock_groq, _cache_get, _cache_set, mock_save, _rl, _rec,
    ):
        """When Featherless prior is 1h old and the new attempt falls through
        to Groq, _save_briefing must NOT be called and the prior is returned."""
        import modules.briefing_generator as bg
        from datetime import datetime, timezone, timedelta
        prior_ts = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        prior = {
            "threat_level": "ELEVATED",
            "what_happened": "Featherless-served briefing content.",
            "provider": "featherless/deepseek-ai/DeepSeek-V3.2",
            "generated_at": prior_ts,
        }
        mock_load_prior.return_value = prior
        mock_groq.return_value = json.dumps(_valid_briefing())
        with patch.object(bg, "_BRIEFING_DOWNGRADE_GUARD_H", 4.0):
            result = generate_briefing([_article() for _ in range(5)])
        assert result is not None
        # The prior briefing (Featherless) was returned, NOT the Groq one
        assert result["provider"] == "featherless/deepseek-ai/DeepSeek-V3.2"
        assert result["what_happened"] == "Featherless-served briefing content."
        # Critical: save was NOT called — the disk-state Featherless briefing is preserved
        mock_save.assert_not_called()

    @patch("modules.briefing_generator._record_api_call")
    @patch("modules.briefing_generator._is_rate_limited", return_value=False)
    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator.cache_result")
    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._call_groq")
    @patch("modules.briefing_generator._call_claude_bridge", side_effect=Exception("bridge 502"))
    @patch("modules.briefing_generator._claude_bridge_available", return_value=True)
    @patch("modules.briefing_generator._call_featherless", side_effect=Exception("featherless 429"))
    @patch("modules.briefing_generator._featherless_available", return_value=True)
    @patch("modules.briefing_generator.load_briefing")
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_stale_featherless_prior_allows_groq_overwrite(
        self, _, mock_load_prior, _ff_avail, _ff_call, _cb_avail, _cb_call,
        mock_groq, _cache_get, _cache_set, mock_save, _rl, _rec,
    ):
        """When Featherless prior is older than the guard window, the new Groq
        briefing overwrites — better stale Groq than really-stale Featherless."""
        import modules.briefing_generator as bg
        from datetime import datetime, timezone, timedelta
        prior_ts = (datetime.now(timezone.utc) - timedelta(hours=10)).isoformat()
        prior = {
            "provider": "featherless/deepseek-ai/DeepSeek-V3.2",
            "generated_at": prior_ts,
        }
        mock_load_prior.return_value = prior
        mock_groq.return_value = json.dumps(_valid_briefing())
        with patch.object(bg, "_BRIEFING_DOWNGRADE_GUARD_H", 4.0):
            result = generate_briefing([_article() for _ in range(5)])
        assert result is not None
        # The new Groq briefing was saved
        from modules.briefing_generator import BRIEFING_MODEL
        assert result["provider"] == f"groq/{BRIEFING_MODEL}"
        mock_save.assert_called_once()

    @patch("modules.briefing_generator._record_api_call")
    @patch("modules.briefing_generator._is_rate_limited", return_value=False)
    @patch("modules.briefing_generator._save_briefing")
    @patch("modules.briefing_generator.cache_result")
    @patch("modules.briefing_generator.get_cached_result", return_value=None)
    @patch("modules.briefing_generator._call_groq")
    @patch("modules.briefing_generator._claude_bridge_available", return_value=False)
    @patch("modules.briefing_generator._featherless_available", return_value=False)
    @patch("modules.briefing_generator.load_briefing", return_value=None)
    @patch("modules.briefing_generator._detect_provider", return_value="openai")
    def test_no_prior_saves_new_groq(
        self, _, _load_prior, _ff_avail, _cb_avail, mock_groq,
        _cache_get, _cache_set, mock_save, _rl, _rec,
    ):
        """First-run case: no prior on disk, Groq tier serves → save normally."""
        import modules.briefing_generator as bg
        mock_groq.return_value = json.dumps(_valid_briefing())
        with patch.object(bg, "_BRIEFING_DOWNGRADE_GUARD_H", 4.0):
            result = generate_briefing([_article() for _ in range(5)])
        assert result is not None
        mock_save.assert_called_once()


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


# ---------------------------------------------------------------------------
# _hoist_kev_listed — KEV-listed articles get extended tenure in what_happened
# ---------------------------------------------------------------------------
class TestHoistKevListed:
    """KEV-listed articles in days 2-3 get hoisted into the headline section
    when within the high-priority tenure window."""

    def _at(self, now, hours_ago):
        from datetime import timedelta
        return (now - timedelta(hours=hours_ago)).isoformat()

    def test_hoists_kev_within_tenure(self):
        from datetime import datetime, timezone
        from modules.briefing_generator import _hoist_kev_listed
        now = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)
        day1 = [{"title": "fresh", "timestamp": self._at(now, 12)}]
        day3 = [
            {"title": "kev30", "timestamp": self._at(now, 30), "kev_listed": True},
            {"title": "kev100", "timestamp": self._at(now, 100), "kev_listed": True},
            {"title": "non-kev30", "timestamp": self._at(now, 30)},
        ]
        new_day1, new_day3 = _hoist_kev_listed(day1, day3, max_age_hours=72, now=now)
        assert {a["title"] for a in new_day1} == {"fresh", "kev30"}
        assert {a["title"] for a in new_day3} == {"kev100", "non-kev30"}

    def test_no_hoist_when_outside_tenure(self):
        from datetime import datetime, timezone
        from modules.briefing_generator import _hoist_kev_listed
        now = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)
        day3 = [{"title": "kev100", "timestamp": self._at(now, 100), "kev_listed": True}]
        new_day1, new_day3 = _hoist_kev_listed([], day3, max_age_hours=72, now=now)
        assert new_day1 == []
        assert new_day3 == day3

    def test_empty_day3_is_noop(self):
        from modules.briefing_generator import _hoist_kev_listed
        new_day1, new_day3 = _hoist_kev_listed([{"title": "a"}], [], max_age_hours=72)
        assert new_day1 == [{"title": "a"}]
        assert new_day3 == []

    def test_invalid_timestamp_keeps_in_day3(self):
        from modules.briefing_generator import _hoist_kev_listed
        day3 = [{"title": "bad", "timestamp": "not-a-date", "kev_listed": True}]
        new_day1, new_day3 = _hoist_kev_listed([], day3, max_age_hours=72)
        # Defensive: don't hoist if we can't verify age.
        assert new_day1 == []
        assert new_day3 == day3

    def test_non_kev_articles_never_hoisted(self):
        from datetime import datetime, timezone
        from modules.briefing_generator import _hoist_kev_listed
        now = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)
        day3 = [{"title": "fresh-non-kev", "timestamp": self._at(now, 30)}]
        new_day1, new_day3 = _hoist_kev_listed([], day3, max_age_hours=72, now=now)
        assert new_day1 == []
        assert new_day3 == day3


class TestUngroundedCveSalvage:
    """The 2026-06 stale-briefing fix: strip hallucinated CVEs and publish a
    grounded briefing instead of wedging on stale content for days."""

    SOURCE = "Article [1]: CISA adds CVE-2026-10520 to the KEV catalog."

    def test_validate_flags_only_ungrounded(self):
        briefing = {
            "what_happened": "Active exploitation of CVE-2026-10520 and "
                             "CVE-2026-49975 reported.",
        }
        # CVE-2026-10520 is in SOURCE; CVE-2026-49975 is not.
        assert _validate_cve_grounding(briefing, self.SOURCE) == {"CVE-2026-49975"}

    def test_strip_removes_ungrounded_keeps_grounded(self):
        briefing = {
            "headline": "ShinyHunters exploits CVE-2026-49975 in PeopleSoft",
            "what_happened": "Attackers leverage CVE-2026-49975; CISA also "
                             "flagged CVE-2026-10520 in the KEV catalog.",
            "what_to_do": [{"action": "Patch CVE-2026-49975 immediately"}],
        }
        cleaned = _strip_ungrounded_cves(briefing, {"CVE-2026-49975"})
        # Ungrounded ID gone everywhere; grounded ID retained.
        assert "CVE-2026-49975" not in json.dumps(cleaned)
        assert "CVE-2026-10520" in cleaned["what_happened"]
        # Re-validation is now clean — deterministically grounded.
        assert _validate_cve_grounding(cleaned, self.SOURCE) == set()

    def test_strip_tidies_orphaned_punctuation(self):
        briefing = {"what_happened": "A flaw (CVE-2026-49975) was found."}
        cleaned = _strip_ungrounded_cves(briefing, {"CVE-2026-49975"})
        # No empty parens or doubled spaces left behind.
        assert "()" not in cleaned["what_happened"]
        assert "  " not in cleaned["what_happened"]
        assert "CVE-2026-49975" not in cleaned["what_happened"]

    def test_strip_is_case_insensitive(self):
        briefing = {"what_happened": "lower cve-2026-49975 cited."}
        cleaned = _strip_ungrounded_cves(briefing, {"CVE-2026-49975"})
        assert "2026-49975" not in cleaned["what_happened"]

    def test_strip_noop_when_nothing_ungrounded(self):
        briefing = {"what_happened": "All grounded here."}
        assert _strip_ungrounded_cves(briefing, set()) is briefing

    def test_has_body_true_for_real_narrative(self):
        assert _briefing_has_body({"what_happened": "x" * 80}) is True

    def test_has_body_false_for_stub(self):
        assert _briefing_has_body({"what_happened": "too short"}) is False
        assert _briefing_has_body({"what_happened": ""}) is False
        assert _briefing_has_body(None) is False
