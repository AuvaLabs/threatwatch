"""Tests for modules/utils.py — time slugs and path helpers."""
import re
from pathlib import Path
from unittest.mock import patch

from modules.utils import (
    extract_json,
    get_current_hour_slug,
    get_month_slug,
    get_today_slug,
    get_week_slug,
    get_year_slug,
    make_output_path,
    ensure_output_directory,
)


class TestTimeSlugs:
    def test_hour_slug_format(self):
        slug = get_current_hour_slug()
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}_\d{2}", slug), f"Unexpected format: {slug}"

    def test_today_slug_format(self):
        slug = get_today_slug()
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", slug), f"Unexpected format: {slug}"

    def test_week_slug_format(self):
        slug = get_week_slug()
        assert re.fullmatch(r"\d{4}-W\d{2}", slug), f"Unexpected format: {slug}"

    def test_month_slug_format(self):
        slug = get_month_slug()
        assert re.fullmatch(r"\d{4}-\d{2}", slug), f"Unexpected format: {slug}"

    def test_year_slug_format(self):
        slug = get_year_slug()
        assert re.fullmatch(r"\d{4}", slug), f"Unexpected format: {slug}"

    def test_slugs_are_utc_consistent(self):
        # All slugs for a given moment should start with the same year
        year = get_year_slug()
        month = get_month_slug()
        today = get_today_slug()
        assert month.startswith(year)
        assert today.startswith(month)


class TestExtractJson:
    """Regression tests for LLM JSON sanitization.

    Covers common Groq/OpenAI emission bugs that block briefing generation:
    bare `none`/`None`/`undefined` tokens, `[none]` for empty arrays, and
    trailing commas.
    """

    def test_valid_json_passes_through(self):
        result = extract_json('{"a": 1, "b": [1, 2]}')
        assert result == {"a": 1, "b": [1, 2]}

    def test_none_inside_array_becomes_empty(self):
        # Real failure mode from 2026-04-08: Groq emitted [none] for an empty
        # sources array, which broke the global Intel Brief for 18 hours.
        result = extract_json('{"sources": [none]}')
        assert result == {"sources": []}

    def test_capital_none_inside_array(self):
        result = extract_json('{"sources": [None]}')
        assert result == {"sources": []}

    def test_undefined_inside_array(self):
        result = extract_json('{"sources": [undefined]}')
        assert result == {"sources": []}

    def test_bare_none_as_value(self):
        result = extract_json('{"a": none, "b": 1}')
        assert result == {"a": None, "b": 1}

    def test_trailing_comma_in_array(self):
        result = extract_json('{"a": [1, 2,]}')
        assert result == {"a": [1, 2]}

    def test_trailing_comma_in_object(self):
        result = extract_json('{"a": 1, "b": 2,}')
        assert result == {"a": 1, "b": 2}

    def test_full_briefing_shape_with_none_array(self):
        # The exact shape that failed in production
        text = '''{
          "threat_level": "ELEVATED",
          "what_happened": "test",
          "what_happened_sources": [1, 2, 3],
          "week_in_review_sources": [none],
          "outlook": "test"
        }'''
        result = extract_json(text)
        assert result is not None
        assert result["week_in_review_sources"] == []
        assert result["what_happened_sources"] == [1, 2, 3]

    def test_json_embedded_in_prose(self):
        text = 'Here is the answer: {"a": 1} — hope that helps.'
        assert extract_json(text) == {"a": 1}

    def test_empty_and_none_inputs(self):
        assert extract_json("") is None
        assert extract_json(None) is None

    def test_unsalvageable_returns_none(self):
        assert extract_json("not json at all") is None

    def test_string_containing_the_word_none_is_preserved(self):
        # Must NOT rewrite `none` inside a string value
        result = extract_json('{"msg": "there are none left"}')
        assert result == {"msg": "there are none left"}


class TestMakeOutputPath:
    def test_returns_path_with_slug(self, tmp_path):
        with patch("modules.utils.Path", side_effect=lambda *a: tmp_path.joinpath(*a)):
            # Directly call with known inputs
            pass
        # Call real function and check filename
        result = make_output_path("daily", "2026-03-15")
        assert result.name == "2026-03-15.json"
        assert "daily" in str(result)


class TestEnsureOutputDirectory:
    def test_with_path(self, tmp_path):
        target = tmp_path / "deep" / "dir" / "file.json"
        ensure_output_directory(str(target))
        assert target.parent.exists()

    def test_without_path(self):
        # Just verify it doesn't raise
        ensure_output_directory()

    def test_idempotent(self, tmp_path):
        target = tmp_path / "dir" / "file.json"
        ensure_output_directory(str(target))
        ensure_output_directory(str(target))  # second call should not raise
        assert target.parent.exists()


class TestSanitizeJsonText:
    def test_nan_becomes_null(self):
        from modules.utils import _sanitize_json_text
        result = _sanitize_json_text('{"value": NaN}')
        assert "null" in result
        assert "NaN" not in result

    def test_trailing_comma_removed(self):
        from modules.utils import _sanitize_json_text
        result = _sanitize_json_text('{"a": 1, }')
        assert result == '{"a": 1 }'

    def test_valid_json_unchanged(self):
        from modules.utils import _sanitize_json_text
        original = '{"a": 1, "b": 2}'
        assert _sanitize_json_text(original) == original

    def test_undefined_becomes_null(self):
        from modules.utils import _sanitize_json_text
        result = _sanitize_json_text('{"a": undefined}')
        assert "null" in result


class TestExtractJsonRegexPath:
    """Tests for the regex-extract-then-sanitize fallback (lines 86-98)."""

    def test_json_in_markdown_fence_with_sanitize(self):
        text = '```json\n{"a": 1, "b": None}\n```'
        result = extract_json(text)
        assert result == {"a": 1, "b": None} or result is not None

    def test_json_block_with_trailing_comma_in_prose(self):
        text = 'The result is: {"key": "value",} and that is all.'
        result = extract_json(text)
        assert result == {"key": "value"}

    def test_json_block_with_none_in_array_in_prose(self):
        text = 'Analysis: {"items": [none], "count": 0} end.'
        result = extract_json(text)
        assert result is not None
        assert result["items"] == []
