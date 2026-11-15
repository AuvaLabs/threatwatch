import pytest
from unittest.mock import patch, MagicMock
from threatdigest_main import enrich_articles
from modules.run_stats import RunStats


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
        mock_parallel.return_value = {}
        mock_classify.return_value = {
            "is_cyber_attack": True,
            "category": "Malware",
            "confidence": 90,
            "translated_title": "Test",
            "summary": "Summary.",
        }

        result = enrich_articles([article], summarize=True)
        assert len(result) == 1
        assert "category" in result[0]

    @patch("threatdigest_main.classify_article")
    @patch("threatdigest_main.process_urls_in_parallel")
    @patch("threatdigest_main.detect_language", return_value="en")
    def test_stats_tracking_scrape_counts(self, mock_lang, mock_parallel, mock_classify):
        """Verify scrape success/failure counts are tracked in stats."""
        articles = [
            self._make_article("A", "https://example.com/a"),
            self._make_article("B", "https://example.com/b"),
        ]
        mock_parallel.return_value = {
            "https://example.com/a": "content",
            "https://example.com/b": None,  # scrape failure
        }
        mock_classify.return_value = {
            "is_cyber_attack": True,
            "category": "Malware",
            "confidence": 90,
            "translated_title": "Test",
            "summary": "",
        }

        stats = RunStats()
        enrich_articles(articles, summarize=True, stats=stats)
        assert stats.scrape_successes == 1
        assert stats.scrape_failures == 1
        assert stats.scrape_skipped == 0
        assert stats.scrape_blocked == 0

    @patch("threatdigest_main.classify_article")
    @patch("threatdigest_main.process_urls_in_parallel")
    @patch("threatdigest_main.detect_language", return_value="en")
    def test_stats_use_detailed_scrape_outcomes(self, mock_lang, mock_parallel, mock_classify):
        from modules.article_scraper import ScrapeResults

        articles = [
            self._make_article("A", "https://example.com/a"),
            self._make_article("B", "https://vulners.com/b"),
            self._make_article("C", "https://unsafe.test/c"),
        ]
        mock_parallel.return_value = ScrapeResults(
            {
                "https://example.com/a": "content",
                "https://vulners.com/b": None,
                "https://unsafe.test/c": None,
            },
            outcomes={
                "https://example.com/a": "succeeded",
                "https://vulners.com/b": "skipped_protected",
                "https://unsafe.test/c": "blocked",
            },
        )
        mock_classify.return_value = {
            "is_cyber_attack": True,
            "category": "Malware",
            "confidence": 90,
            "translated_title": "Test",
            "summary": "",
        }

        stats = RunStats()
        enrich_articles(articles, summarize=True, stats=stats)

        assert stats.scrape_successes == 1
        assert stats.scrape_failures == 0
        assert stats.scrape_skipped == 1
        assert stats.scrape_blocked == 1

    @patch("threatdigest_main.classify_article")
    @patch("threatdigest_main.process_urls_in_parallel")
    @patch("threatdigest_main.detect_language", return_value="en")
    def test_stats_tracking_cache_hits(self, mock_lang, mock_parallel, mock_classify):
        """Verify cache hit/miss counts are tracked in stats."""
        article = self._make_article("Test", "https://example.com/5")
        mock_parallel.return_value = {}
        mock_classify.return_value = {
            "is_cyber_attack": True,
            "category": "Ransomware",
            "confidence": 95,
            "translated_title": "Test",
            "summary": "",
            "_cached": True,
        }

        stats = RunStats()
        enrich_articles([article], summarize=True, stats=stats)
        assert stats.cache_hits == 1
        assert stats.cache_misses == 0

    @patch("threatdigest_main.classify_article")
    @patch("threatdigest_main.process_urls_in_parallel")
    @patch("threatdigest_main.detect_language", return_value="en")
    def test_stats_tracking_cache_misses(self, mock_lang, mock_parallel, mock_classify):
        """Verify cache miss counts."""
        article = self._make_article("Test", "https://example.com/6")
        mock_parallel.return_value = {}
        mock_classify.return_value = {
            "is_cyber_attack": True,
            "category": "Ransomware",
            "confidence": 95,
            "translated_title": "Test",
            "summary": "",
        }

        stats = RunStats()
        enrich_articles([article], summarize=True, stats=stats)
        assert stats.cache_hits == 0
        assert stats.cache_misses == 1

    @patch("threatdigest_main.classify_article")
    @patch("threatdigest_main.process_urls_in_parallel")
    @patch("threatdigest_main.detect_language", return_value="en")
    def test_stats_tracking_ai_escalations(self, mock_lang, mock_parallel, mock_classify):
        """Verify AI escalation counts."""
        article = self._make_article("Test", "https://example.com/7")
        mock_parallel.return_value = {}
        mock_classify.return_value = {
            "is_cyber_attack": True,
            "category": "APT",
            "confidence": 99,
            "translated_title": "Test",
            "summary": "",
            "_ai_enhanced": True,
        }

        stats = RunStats()
        enrich_articles([article], summarize=True, stats=stats)
        assert stats.ai_escalations == 1

    @patch("threatdigest_main.classify_article")
    @patch("threatdigest_main.process_urls_in_parallel")
    @patch("threatdigest_main.detect_language", return_value="en")
    def test_stats_tracking_non_cyber_count(self, mock_lang, mock_parallel, mock_classify):
        """Verify non-cyber article counting."""
        article = self._make_article("Sports", "https://example.com/8")
        mock_parallel.return_value = {}
        mock_classify.return_value = {
            "is_cyber_attack": False,
            "category": "Unknown",
            "confidence": 10,
            "translated_title": "Sports",
            "summary": "",
        }

        stats = RunStats()
        enrich_articles([article], summarize=True, stats=stats)
        assert stats.non_cyber_articles == 1
        assert stats.cyber_articles == 0

    @patch("threatdigest_main.classify_article")
    @patch("threatdigest_main.process_urls_in_parallel")
    @patch("threatdigest_main.detect_language", return_value="en")
    @patch("threatdigest_main.log_article_summary")
    def test_logs_summary_when_summarize_enabled(self, mock_log, mock_lang, mock_parallel, mock_classify):
        """Verify article summaries are logged when summarize=True."""
        article = self._make_article("Attack", "https://example.com/9")
        mock_parallel.return_value = {}
        mock_classify.return_value = {
            "is_cyber_attack": True,
            "category": "Malware",
            "confidence": 90,
            "translated_title": "Attack",
            "summary": "Detailed summary here.",
        }

        enrich_articles([article], summarize=True)
        mock_log.assert_called_once_with("https://example.com/9", "Detailed summary here.")

    @patch("threatdigest_main.classify_article")
    @patch("threatdigest_main.process_urls_in_parallel")
    @patch("threatdigest_main.detect_language", return_value="en")
    def test_enriched_article_has_required_fields(self, mock_lang, mock_parallel, mock_classify):
        """Verify the enriched article dict has all expected fields."""
        article = self._make_article("Test Article", "https://example.com/10")
        mock_parallel.return_value = {"https://example.com/10": "Content"}
        mock_classify.return_value = {
            "is_cyber_attack": True,
            "category": "Phishing",
            "confidence": 85,
            "translated_title": "Test Article",
            "summary": "Summary.",
        }

        result = enrich_articles([article], summarize=True)
        assert len(result) == 1
        enriched = result[0]
        for field in ("translated_title", "language", "is_cyber_attack", "category",
                      "confidence", "full_content", "summary", "timestamp"):
            assert field in enriched, f"Missing field: {field}"
        assert enriched["language"] == "en"
        assert enriched["is_cyber_attack"] is True
