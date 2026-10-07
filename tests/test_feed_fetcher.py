import pytest
from unittest.mock import patch, MagicMock

from modules.feed_fetcher import fetch_articles


class TestFetchArticles:
    @patch("modules.feed_fetcher.resolve_original_url", side_effect=lambda x, **kw: x)
    @patch("modules.feed_fetcher.feedparser.parse")
    @patch("modules.feed_fetcher._get_session")
    def test_returns_articles_from_feeds(self, mock_get_session, mock_parse, mock_resolve):
        mock_http_resp = MagicMock()
        mock_http_resp.content = b""
        mock_get_session.return_value.get.return_value = mock_http_resp

        from datetime import datetime, timezone
        recent_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        mock_entry = MagicMock()
        mock_entry.title = "Test Article"
        mock_entry.link = "https://example.com/article"
        mock_entry.get = lambda key, default="": {
            "published": recent_date,
            "summary": "Test summary",
        }.get(key, default)

        mock_parse.return_value = MagicMock(entries=[mock_entry])

        feeds = [{"url": "https://feed.example.com/rss", "name": "Example Security"}]
        result = fetch_articles(feeds)

        assert len(result) == 1
        assert result[0]["title"] == "Test Article"
        assert "hash" in result[0]
        assert result[0]["source_name"] == "Example Security"

    @patch("modules.feed_fetcher.resolve_original_url", side_effect=lambda x, **kw: x)
    @patch("modules.feed_fetcher.feedparser.parse")
    @patch("modules.feed_fetcher._get_session")
    def test_rejects_implausible_future_article(self, mock_get_session, mock_parse, mock_resolve):
        from datetime import datetime, timedelta, timezone

        mock_http_resp = MagicMock()
        mock_http_resp.content = b""
        mock_get_session.return_value.get.return_value = mock_http_resp
        future_date = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        mock_entry = MagicMock()
        mock_entry.title = "Article from the future"
        mock_entry.link = "https://example.com/future"
        mock_entry.get = lambda key, default="": {
            "published": future_date,
            "summary": "Future item",
        }.get(key, default)
        mock_parse.return_value = MagicMock(entries=[mock_entry], bozo=False)

        result = fetch_articles([{"url": "https://feed.example.com/rss"}])

        assert result == []

    @patch("modules.feed_fetcher.resolve_original_url", side_effect=lambda x, **kw: x)
    @patch("modules.feed_fetcher.feedparser.parse")
    @patch("modules.feed_fetcher._get_session")
    def test_uses_entry_source_title_when_available(self, mock_get_session, mock_parse, mock_resolve):
        from datetime import datetime, timezone

        mock_http_resp = MagicMock()
        mock_http_resp.content = b""
        mock_get_session.return_value.get.return_value = mock_http_resp
        mock_entry = MagicMock()
        mock_entry.title = "Syndicated report"
        mock_entry.link = "https://news.google.com/articles/example"
        mock_entry.get = lambda key, default="": {
            "published": datetime.now(timezone.utc).isoformat(),
            "summary": "Report",
            "source": {"title": "Security Week"},
        }.get(key, default)
        mock_parse.return_value = MagicMock(entries=[mock_entry], bozo=False)

        result = fetch_articles([{"url": "https://news.google.com/rss/search?q=security"}])

        assert result[0]["source_name"] == "Security Week"

    @patch("modules.feed_fetcher.resolve_original_url", side_effect=lambda x, **kw: x)
    @patch("modules.feed_fetcher.feedparser.parse")
    @patch("modules.feed_fetcher._get_session")
    def test_no_global_state_accumulation(self, mock_get_session, mock_parse, mock_resolve):
        from datetime import datetime, timezone
        recent_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
        mock_http_resp = MagicMock()
        mock_http_resp.content = b""
        mock_get_session.return_value.get.return_value = mock_http_resp

        mock_entry = MagicMock()
        mock_entry.title = "Article"
        mock_entry.link = "https://example.com/1"
        mock_entry.get = lambda key, default="": {
            "published": recent_date,
            "summary": "",
        }.get(key, default)

        mock_parse.return_value = MagicMock(entries=[mock_entry])

        feeds = [{"url": "https://feed.example.com/rss"}]

        result1 = fetch_articles(feeds)
        result2 = fetch_articles(feeds)

        assert len(result1) == 1
        assert len(result2) == 1

    @patch("modules.feed_fetcher.resolve_original_url", side_effect=lambda x, **kw: x)
    @patch("modules.feed_fetcher.feedparser.parse", side_effect=Exception("Network error"))
    def test_handles_feed_error(self, mock_parse, mock_resolve):
        feeds = [{"url": "https://broken.feed.com/rss"}]
        result = fetch_articles(feeds)
        assert result == []
