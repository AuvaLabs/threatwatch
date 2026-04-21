"""Tests for modules/article_summariser.py — AI article summaries."""

import json
import pytest
from unittest.mock import patch, MagicMock

# Import via briefing_generator to avoid circular import
from modules.briefing_generator import summarize_articles


def _article(title="Test", summary="", is_cyber=True):
    return {"title": title, "summary": summary, "is_cyber_attack": is_cyber}


class TestSummarizeArticles:
    def test_returns_zero_without_provider(self):
        with patch("modules.article_summariser._detect_provider", return_value=None):
            assert summarize_articles([_article()]) == 0

    def test_returns_zero_for_anthropic(self):
        with patch("modules.article_summariser._detect_provider", return_value="anthropic"):
            assert summarize_articles([_article()]) == 0

    def test_returns_zero_when_all_have_summaries(self):
        with patch("modules.article_summariser._detect_provider", return_value="openai"):
            articles = [_article(summary="Already summarized")]
            assert summarize_articles(articles) == 0

    def test_returns_zero_for_non_cyber(self):
        with patch("modules.article_summariser._detect_provider", return_value="openai"):
            articles = [_article(is_cyber=False, summary="")]
            assert summarize_articles(articles) == 0

    def test_successful_summarization(self, tmp_path):
        articles = [_article(title="LockBit attack", summary="")]
        llm_response = json.dumps([
            {"index": 1, "what": "ransomware", "who": "hospital",
             "impact": "data stolen", "summary": "LockBit hit a hospital."}
        ])
        with patch("modules.article_summariser._detect_provider", return_value="openai"), \
             patch("modules.article_summariser.get_cached_result", return_value=None), \
             patch("modules.article_summariser._call_openai_compatible", return_value=llm_response), \
             patch("modules.article_summariser._parse_json", return_value=json.loads(llm_response)), \
             patch("modules.article_summariser.cache_result"):
            count = summarize_articles(articles)
        assert count == 1
        assert articles[0]["summary"] == "LockBit hit a hospital."
        assert articles[0]["intel_what"] == "ransomware"

    def test_cached_summaries_applied(self):
        articles = [_article(title="Test", summary="")]
        cached = [{"index": 1, "summary": "Cached summary", "what": "test"}]
        with patch("modules.article_summariser._detect_provider", return_value="openai"), \
             patch("modules.article_summariser.get_cached_result", return_value=cached):
            count = summarize_articles(articles)
        assert count == 1
        assert articles[0]["summary"] == "Cached summary"

    def test_llm_failure_continues(self):
        articles = [_article(summary="")]
        with patch("modules.article_summariser._detect_provider", return_value="openai"), \
             patch("modules.article_summariser.get_cached_result", return_value=None), \
             patch("modules.article_summariser._call_openai_compatible",
                   side_effect=Exception("API down")):
            count = summarize_articles(articles)
        assert count == 0

    def test_dict_response_unwrapped(self):
        articles = [_article(summary="")]
        dict_response = {"summaries": [{"index": 1, "summary": "From dict"}]}
        with patch("modules.article_summariser._detect_provider", return_value="openai"), \
             patch("modules.article_summariser.get_cached_result", return_value=None), \
             patch("modules.article_summariser._call_openai_compatible", return_value="{}"), \
             patch("modules.article_summariser._parse_json", return_value=dict_response), \
             patch("modules.article_summariser.cache_result"):
            count = summarize_articles(articles)
        assert count == 1
        assert articles[0]["summary"] == "From dict"

    def test_empty_articles(self):
        with patch("modules.article_summariser._detect_provider", return_value="openai"):
            assert summarize_articles([]) == 0
