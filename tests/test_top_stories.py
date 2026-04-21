"""Tests for modules/top_stories.py — AI-curated top stories."""

import json
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from pathlib import Path

# Import through briefing_generator to avoid circular import
# (briefing_generator re-exports top_stories symbols at module bottom)
from modules.briefing_generator import (
    _filter_for_briefing,
    generate_top_stories,
    load_top_stories,
    _save_top_stories,
)
import modules.top_stories as ts
from modules.top_stories import _split_by_age


def _make_article(title="Test Article", category="Ransomware", confidence=90,
                  darkweb=False, timestamp=None, **kwargs):
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    a = {
        "title": title,
        "category": category,
        "confidence": confidence,
        "timestamp": timestamp,
        "link": "https://example.com",
        "is_cyber_attack": True,
    }
    if darkweb:
        a["darkweb"] = True
    a.update(kwargs)
    return a


class TestFilterForBriefing:
    def test_excludes_darkweb(self):
        articles = [_make_article(darkweb=True), _make_article(title="Normal")]
        result = _filter_for_briefing(articles)
        assert len(result) == 1
        assert result[0]["title"] == "Normal"

    def test_excludes_isDarkweb(self):
        articles = [_make_article(isDarkweb=True), _make_article(title="Normal")]
        result = _filter_for_briefing(articles)
        assert len(result) == 1

    def test_excludes_noise(self):
        articles = [_make_article(category="Noise"), _make_article(title="Real")]
        result = _filter_for_briefing(articles)
        assert len(result) == 1
        assert result[0]["title"] == "Real"

    def test_excludes_zero_confidence(self):
        articles = [_make_article(confidence=0), _make_article(title="Good", confidence=80)]
        result = _filter_for_briefing(articles)
        assert len(result) == 1

    def test_deduplicates_by_title(self):
        articles = [
            _make_article(title="LockBit attack - BleepingComputer"),
            _make_article(title="LockBit attack - The Record"),
        ]
        result = _filter_for_briefing(articles)
        assert len(result) == 1

    def test_deduplicates_pipe_suffix(self):
        articles = [
            _make_article(title="Zero-day found | SecurityWeek"),
            _make_article(title="Zero-day found | Dark Reading"),
        ]
        result = _filter_for_briefing(articles)
        assert len(result) == 1

    def test_sorts_by_timestamp_descending(self):
        now = datetime.now(timezone.utc)
        old = _make_article(title="Old", timestamp=(now - timedelta(days=2)).isoformat())
        new = _make_article(title="New", timestamp=now.isoformat())
        result = _filter_for_briefing([old, new])
        assert result[0]["title"] == "New"
        assert result[1]["title"] == "Old"

    def test_normal_articles_pass_through(self):
        articles = [_make_article(title=f"Article {i}") for i in range(5)]
        result = _filter_for_briefing(articles)
        assert len(result) == 5


class TestSplitByAge:
    def test_last_24h_bucket(self):
        now = datetime.now(timezone.utc)
        articles = [_make_article(timestamp=(now - timedelta(hours=6)).isoformat())]
        day1, day3, older = _split_by_age(articles)
        assert len(day1) == 1
        assert len(day3) == 0
        assert len(older) == 0

    def test_days_2_3_bucket(self):
        now = datetime.now(timezone.utc)
        articles = [_make_article(timestamp=(now - timedelta(days=2)).isoformat())]
        day1, day3, older = _split_by_age(articles)
        assert len(day1) == 0
        assert len(day3) == 1

    def test_older_bucket(self):
        now = datetime.now(timezone.utc)
        articles = [_make_article(timestamp=(now - timedelta(days=5)).isoformat())]
        day1, day3, older = _split_by_age(articles)
        assert len(older) == 1

    def test_invalid_timestamp_goes_to_older(self):
        articles = [_make_article(timestamp="not-a-date")]
        day1, day3, older = _split_by_age(articles)
        assert len(older) == 1

    def test_missing_timestamp_goes_to_older(self):
        articles = [{"title": "No timestamp"}]
        day1, day3, older = _split_by_age(articles)
        assert len(older) == 1


class TestGenerateTopStories:
    def test_returns_none_when_no_provider(self):
        with patch.object(ts, "_detect_provider", return_value=None):
            assert generate_top_stories([_make_article()] * 20) is None

    def test_returns_none_when_anthropic_provider(self):
        with patch.object(ts, "_detect_provider", return_value="anthropic"):
            assert generate_top_stories([_make_article()] * 20) is None

    def test_returns_none_when_too_few_articles(self):
        with patch.object(ts, "_detect_provider", return_value="openai"):
            assert generate_top_stories([_make_article()] * 5) is None

    def test_returns_none_on_empty_articles(self):
        with patch.object(ts, "_detect_provider", return_value="openai"):
            assert generate_top_stories([]) is None

    def test_returns_cached_result(self, tmp_path):
        cached_data = {"stories": [{"headline": "Cached"}], "generated_at": "now"}
        articles = [_make_article(title=f"A{i}") for i in range(20)]
        with patch.object(ts, "_detect_provider", return_value="openai"), \
             patch.object(ts, "_build_digest", return_value="digest text"), \
             patch.object(ts, "_MAX_DIGEST_ARTICLES", 80), \
             patch.object(ts, "get_cached_result", return_value=cached_data), \
             patch.object(ts, "_save_top_stories"):
            result = generate_top_stories(articles)
        assert result == cached_data

    def test_rate_limited_returns_existing(self, tmp_path):
        existing = {"stories": [{"headline": "Existing"}]}
        last_call_path = tmp_path / ".top_stories_last_call"
        last_call_path.write_text(str(datetime.now(timezone.utc).timestamp()))
        top_stories_path = tmp_path / "top_stories.json"
        top_stories_path.write_text(json.dumps(existing))

        articles = [_make_article(title=f"A{i}") for i in range(20)]
        with patch.object(ts, "_detect_provider", return_value="openai"), \
             patch.object(ts, "_build_digest", return_value="digest text"), \
             patch.object(ts, "_MAX_DIGEST_ARTICLES", 80), \
             patch.object(ts, "get_cached_result", return_value=None), \
             patch.object(ts, "_LAST_TOP_STORIES_PATH", last_call_path), \
             patch.object(ts, "_TOP_STORIES_PATH", top_stories_path):
            result = generate_top_stories(articles)
        assert result == existing

    def test_successful_generation(self, tmp_path):
        llm_response = json.dumps({
            "top_stories": [{
                "article_index": 1,
                "headline": "Major breach",
                "summary": "Big company hacked",
                "significance": "CRITICAL",
                "category": "Data Breach",
            }]
        })
        articles = [_make_article(title=f"Article {i}", source_name="TestSource") for i in range(20)]
        last_call_path = tmp_path / ".top_stories_last_call"
        top_stories_path = tmp_path / "top_stories.json"

        with patch.object(ts, "_detect_provider", return_value="openai"), \
             patch.object(ts, "_build_digest", return_value="digest text"), \
             patch.object(ts, "_MAX_DIGEST_ARTICLES", 80), \
             patch.object(ts, "LLM_MODEL", "test-model"), \
             patch.object(ts, "get_cached_result", return_value=None), \
             patch.object(ts, "_call_openai_compatible", return_value=llm_response), \
             patch.object(ts, "_parse_json", return_value=json.loads(llm_response)), \
             patch.object(ts, "cache_result"), \
             patch.object(ts, "_LAST_TOP_STORIES_PATH", last_call_path), \
             patch.object(ts, "_TOP_STORIES_PATH", top_stories_path):
            result = generate_top_stories(articles)

        assert result is not None
        assert "stories" in result
        assert len(result["stories"]) == 1
        assert result["stories"][0]["headline"] == "Major breach"
        assert result["provider"] == "openai/test-model"

    def test_llm_failure_returns_none(self, tmp_path):
        articles = [_make_article(title=f"A{i}") for i in range(20)]
        last_call_path = tmp_path / ".nonexistent"

        with patch.object(ts, "_detect_provider", return_value="openai"), \
             patch.object(ts, "_build_digest", return_value="digest"), \
             patch.object(ts, "_MAX_DIGEST_ARTICLES", 80), \
             patch.object(ts, "get_cached_result", return_value=None), \
             patch.object(ts, "_call_openai_compatible", side_effect=Exception("API down")), \
             patch.object(ts, "_LAST_TOP_STORIES_PATH", last_call_path):
            result = generate_top_stories(articles)
        assert result is None

    def test_invalid_json_returns_none(self, tmp_path):
        articles = [_make_article(title=f"A{i}") for i in range(20)]
        last_call_path = tmp_path / ".nonexistent"

        with patch.object(ts, "_detect_provider", return_value="openai"), \
             patch.object(ts, "_build_digest", return_value="digest"), \
             patch.object(ts, "_MAX_DIGEST_ARTICLES", 80), \
             patch.object(ts, "get_cached_result", return_value=None), \
             patch.object(ts, "_call_openai_compatible", return_value="not json"), \
             patch.object(ts, "_parse_json", return_value=None), \
             patch.object(ts, "_LAST_TOP_STORIES_PATH", last_call_path):
            result = generate_top_stories(articles)
        assert result is None


class TestLoadSaveTopStories:
    def test_save_and_load_roundtrip(self, tmp_path):
        path = tmp_path / "top_stories.json"
        data = {"stories": [{"headline": "Test"}], "generated_at": "2026-01-01"}
        with patch.object(ts, "_TOP_STORIES_PATH", path):
            _save_top_stories(data)
            result = load_top_stories()
        assert result == data

    def test_load_returns_none_when_missing(self, tmp_path):
        path = tmp_path / "nonexistent.json"
        with patch.object(ts, "_TOP_STORIES_PATH", path):
            assert load_top_stories() is None

    def test_load_returns_none_on_corrupt_json(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{bad json")
        with patch.object(ts, "_TOP_STORIES_PATH", path):
            assert load_top_stories() is None
