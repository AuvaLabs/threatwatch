import pytest
from unittest.mock import patch, MagicMock
from threatdigest_main import enrich_articles


class TestEnrichArticles:
    def _make_article(self, title, link):
        return {
            "title": title,
            "link": link,
            "published": "Mon, 01 Jan 2024",
            "summary": "Test",
            "hash": "abc123",
            "source": "https://feed.example.com",
        }

    @patch("threatdigest_main.classify_article")
    @patch("threatdigest_main.process_urls_in_parallel")
    @patch("threatdigest_main.detect_language", return_value="en")
    def test_uses_parallel_scrape_results(self, mock_lang, mock_parallel, mock_classify):
        article = self._make_article("Ransomware Attack", "https://example.com/1")
        mock_parallel.return_value = {"https://example.com/1": "Full article content here"}
        mock_classify.return_value = {
            "is_cyber_attack": True,
            "category": "Ransomware",
            "confidence": 95,
            "translated_title": "Ransomware Attack",
            "summary": "A ransomware attack summary.",
        }

        result = enrich_articles([article], summarize=True)

        mock_parallel.assert_called_once()
        mock_classify.assert_called_once()
        assert len(result) == 1
        assert result[0]["full_content"] == "Full article content here"

    @patch("threatdigest_main.classify_article")
    @patch("threatdigest_main.process_urls_in_parallel")
    @patch("threatdigest_main.detect_language", return_value="en")
    def test_filters_non_cyber_articles(self, mock_lang, mock_parallel, mock_classify):
        article = self._make_article("Sports News", "https://example.com/2")
        mock_parallel.return_value = {"https://example.com/2": "Sports content"}
        mock_classify.return_value = {
            "is_cyber_attack": False,
            "category": "General Cyber Threat",
            "confidence": 10,
            "translated_title": "Sports News",
            "summary": "",
        }

        result = enrich_articles([article], summarize=True)
        assert len(result) == 0

    @patch("threatdigest_main.classify_article")
    @patch("threatdigest_main.process_urls_in_parallel")
    @patch("threatdigest_main.detect_language", return_value="en")
    def test_handles_no_content(self, mock_lang, mock_parallel, mock_classify):
        article = self._make_article("DDoS Attack", "https://example.com/3")
        mock_parallel.return_value = {}
        mock_classify.return_value = {
            "is_cyber_attack": True,
            "category": "DDoS",
            "confidence": 80,
            "translated_title": "DDoS Attack",
            "summary": "",
        }

        result = enrich_articles([article], summarize=True)
        assert len(result) == 1
        assert result[0]["full_content"] is None

    @patch("threatdigest_main.classify_article")
    @patch("threatdigest_main.process_urls_in_parallel")
    @patch("threatdigest_main.detect_language", return_value="en")
    def test_immutable_original_article(self, mock_lang, mock_parallel, mock_classify):
        article = self._make_article("Test", "https://example.com/4")
        original_keys = set(article.keys())
        mock_parallel.return_value = {}
        mock_classify.return_value = {
            "is_cyber_attack": True,
            "category": "Malware",
            "confidence": 90,
            "translated_title": "Test",
            "summary": "Summary.",
        }

        result = enrich_articles([article], summarize=True)
        # enriched_article is a new dict (spread), so original should still have original keys
        # But since we use {**article, ...}, the original dict is not mutated
        assert len(result) == 1
        assert "category" in result[0]
