"""Tests for modules/article_summariser.py — AI article summaries."""

import json
import pytest
from unittest.mock import patch

# Import via briefing_generator to avoid circular import
from modules.briefing_generator import summarize_articles


def _article(title="Test", summary="", is_cyber=True):
    return {"title": title, "summary": summary, "is_cyber_attack": is_cyber}


class TestSummarizeArticles:
    def test_returns_zero_without_provider(self):
        with patch("modules.article_summariser.is_available", return_value=False):
            assert summarize_articles([_article()]) == 0

    def test_returns_zero_when_all_have_summaries(self):
        with patch("modules.article_summariser.is_available", return_value=True):
            articles = [_article(summary="Already summarized")]
            assert summarize_articles(articles) == 0

    def test_returns_zero_for_non_cyber(self):
        with patch("modules.article_summariser.is_available", return_value=True):
            articles = [_article(is_cyber=False, summary="")]
            assert summarize_articles(articles) == 0

    def test_successful_summarization(self, tmp_path):
        articles = [_article(title="LockBit attack", summary="")]
        llm_response = json.dumps([
            {"index": 1, "what": "ransomware", "who": "hospital",
             "impact": "data stolen", "summary": "LockBit hit a hospital."}
        ])
        with patch("modules.article_summariser.is_available", return_value=True), \
             patch("modules.article_summariser.get_cached_result", return_value=None), \
             patch("modules.article_summariser.call_llm", return_value=llm_response), \
             patch("modules.article_summariser._parse_json", return_value=json.loads(llm_response)), \
             patch("modules.article_summariser.cache_result"):
            count = summarize_articles(articles)
        assert count == 1
        assert articles[0]["summary"] == "LockBit hit a hospital."
        assert articles[0]["intel_what"] == "ransomware"
        assert articles[0]["summary_method"] == "ai"

    def test_cached_summaries_applied(self):
        articles = [_article(title="Test", summary="")]
        cached = [{"index": 1, "summary": "Cached summary", "what": "test"}]
        with patch("modules.article_summariser.is_available", return_value=True), \
             patch("modules.article_summariser.get_cached_result", return_value=cached):
            count = summarize_articles(articles)
        assert count == 1
        assert articles[0]["summary"] == "Cached summary"

    def test_llm_failure_continues(self):
        articles = [_article(summary="")]
        with patch("modules.article_summariser.is_available", return_value=True), \
             patch("modules.article_summariser.get_cached_result", return_value=None), \
             patch("modules.article_summariser.call_llm", side_effect=Exception("API down")):
            count = summarize_articles(articles)
        assert count == 0

    def test_malformed_response_is_retried_once(self, monkeypatch):
        articles = [_article(summary="")]
        parsed = {
            "summaries": [{"index": 1, "summary": "Recovered summary"}]
        }
        monkeypatch.setattr("modules.article_summariser._SUMMARY_BATCH_DELAY_SECONDS", 0)
        with patch("modules.article_summariser.is_available", return_value=True), \
             patch("modules.article_summariser.get_cached_result", return_value=None), \
             patch("modules.article_summariser.call_llm", side_effect=["bad", "good"]) as call, \
             patch("modules.article_summariser._parse_json", side_effect=[None, parsed]), \
             patch("modules.article_summariser.cache_result"):
            count = summarize_articles(articles)

        assert count == 1
        assert articles[0]["summary"] == "Recovered summary"
        assert call.call_count == 2

    def test_dict_response_unwrapped(self):
        articles = [_article(summary="")]
        dict_response = {"summaries": [{"index": 1, "summary": "From dict"}]}
        with patch("modules.article_summariser.is_available", return_value=True), \
             patch("modules.article_summariser.get_cached_result", return_value=None), \
             patch("modules.article_summariser.call_llm", return_value="{}"), \
             patch("modules.article_summariser._parse_json", return_value=dict_response), \
             patch("modules.article_summariser.cache_result"):
            count = summarize_articles(articles)
        assert count == 1
        assert articles[0]["summary"] == "From dict"

    def test_uncached_batches_are_rate_limited(self, monkeypatch):
        articles = [_article(title=f"Article {index}") for index in range(20)]
        response = json.dumps([
            {"index": index, "summary": f"Summary {index}"}
            for index in range(1, 11)
        ])
        monkeypatch.setattr("modules.article_summariser._MAX_SUMMARIES_PER_RUN", 20)
        monkeypatch.setattr("modules.article_summariser._SUMMARY_BATCH_DELAY_SECONDS", 5.0)

        with patch("modules.article_summariser.is_available", return_value=True), \
             patch("modules.article_summariser.get_cached_result", return_value=None), \
             patch("modules.article_summariser.call_llm", return_value=response), \
             patch("modules.article_summariser._parse_json", return_value=json.loads(response)), \
             patch("modules.article_summariser.cache_result"), \
             patch("modules.article_summariser.time.sleep") as sleep:
            count = summarize_articles(articles)

        assert count == 20
        sleep.assert_called_once_with(5.0)

    def test_cached_batches_do_not_wait(self, monkeypatch):
        articles = [_article(title=f"Article {index}") for index in range(20)]
        cached = [
            {"index": index, "summary": f"Summary {index}"}
            for index in range(1, 11)
        ]
        monkeypatch.setattr("modules.article_summariser._MAX_SUMMARIES_PER_RUN", 20)
        monkeypatch.setattr("modules.article_summariser._SUMMARY_BATCH_DELAY_SECONDS", 5.0)

        with patch("modules.article_summariser.is_available", return_value=True), \
             patch("modules.article_summariser.get_cached_result", return_value=cached), \
             patch("modules.article_summariser.time.sleep") as sleep:
            count = summarize_articles(articles)

        assert count == 20
        sleep.assert_not_called()

    def test_empty_articles(self):
        with patch("modules.article_summariser.is_available", return_value=True):
            assert summarize_articles([]) == 0
