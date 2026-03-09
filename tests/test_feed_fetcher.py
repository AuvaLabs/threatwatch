import pytest
from unittest.mock import patch, MagicMock

from modules.feed_fetcher import fetch_articles


class TestFetchArticles:
    @patch("modules.feed_fetcher.resolve_original_url", side_effect=lambda x: x)
    @patch("modules.feed_fetcher.feedparser.parse")
    def test_returns_articles_from_feeds(self, mock_parse, mock_resolve):
        mock_entry = MagicMock()
        mock_entry.title = "Test Article"
        mock_entry.link = "https://example.com/article"
        mock_entry.get = lambda key, default="": {
            "published": "Mon, 01 Jan 2024",
            "summary": "Test summary",
        }.get(key, default)

        mock_parse.return_value = MagicMock(entries=[mock_entry])

        feeds = [{"url": "https://feed.example.com/rss"}]
        result = fetch_articles(feeds)

        assert len(result) == 1
        assert result[0]["title"] == "Test Article"
        assert "hash" in result[0]

    @patch("modules.feed_fetcher.resolve_original_url", side_effect=lambda x: x)
    @patch("modules.feed_fetcher.feedparser.parse")
    def test_no_global_state_accumulation(self, mock_parse, mock_resolve):
        mock_entry = MagicMock()
        mock_entry.title = "Article"
        mock_entry.link = "https://example.com/1"
        mock_entry.get = lambda key, default="": default

        mock_parse.return_value = MagicMock(entries=[mock_entry])

        feeds = [{"url": "https://feed.example.com/rss"}]

        result1 = fetch_articles(feeds)
        result2 = fetch_articles(feeds)

        assert len(result1) == 1
        assert len(result2) == 1

    @patch("modules.feed_fetcher.resolve_original_url", side_effect=lambda x: x)
    @patch("modules.feed_fetcher.feedparser.parse", side_effect=Exception("Network error"))
    def test_handles_feed_error(self, mock_parse, mock_resolve):
        feeds = [{"url": "https://broken.feed.com/rss"}]
        result = fetch_articles(feeds)
        assert result == []
