import pytest
from unittest.mock import MagicMock, patch

from modules.article_scraper import extract_with_fallback, extract_with_trafilatura, process_urls_in_parallel


class TestExtractWithTrafilatura:
    def test_returns_content_when_trafilatura_extracts(self):
        long_text = "A" * 150
        with patch("modules.article_scraper.trafilatura.fetch_url", return_value="<html/>"), \
             patch("modules.article_scraper.trafilatura.extract", return_value=long_text):
            result = extract_with_trafilatura("https://example.com/article")
        assert result == long_text

    def test_returns_none_when_fetch_returns_nothing(self):
        with patch("modules.article_scraper.trafilatura.fetch_url", return_value=None):
            result = extract_with_trafilatura("https://example.com/article")
        assert result is None

    def test_returns_none_when_text_too_short(self):
        with patch("modules.article_scraper.trafilatura.fetch_url", return_value="<html/>"), \
             patch("modules.article_scraper.trafilatura.extract", return_value="short"):
            result = extract_with_trafilatura("https://example.com/article")
        assert result is None

    def test_returns_none_on_exception(self):
        with patch("modules.article_scraper.trafilatura.fetch_url", side_effect=RuntimeError("oops")):
            result = extract_with_trafilatura("https://example.com/article")
        assert result is None

    def test_blocks_unsafe_url(self):
        with patch("modules.article_scraper.is_safe_url", return_value=False):
            result = extract_with_trafilatura("http://192.168.1.1/")
        assert result is None


class TestExtractWithFallback:
    def test_returns_content_on_success(self):
        long_text = "This is a substantial paragraph of article content here, long enough to pass the one-hundred character minimum threshold check in the scraper module."
        mock_p = MagicMock()
        mock_p.get_text.return_value = long_text

        mock_soup = MagicMock()
        mock_soup.find.return_value = None  # no <article> tag — falls to soup root
        mock_soup.find_all.return_value = [mock_p]

        mock_resp = MagicMock()
        mock_resp.text = "<html><body></body></html>"
        mock_resp.raise_for_status.return_value = None

        with patch("modules.article_scraper._session") as mock_session, \
             patch("modules.article_scraper.BeautifulSoup", return_value=mock_soup):
            mock_session.get.return_value = mock_resp
            content = extract_with_fallback("https://example.com/article")

        assert content is not None
        assert "substantial paragraph" in content

    def test_returns_none_when_no_paragraphs(self):
        html = "<html><body><p>Hi</p></body></html>"
        mock_resp = MagicMock()
        mock_resp.text = html
        mock_resp.raise_for_status.return_value = None

        with patch("modules.article_scraper._session") as mock_session:
            mock_session.get.return_value = mock_resp
            content = extract_with_fallback("https://example.com/article")

        assert content is None

    def test_returns_none_on_request_exception(self):
        import requests
        with patch("modules.article_scraper._session") as mock_session:
            mock_session.get.side_effect = requests.RequestException("timeout")
            content = extract_with_fallback("https://example.com/article")

        assert content is None

    def test_strips_nav_and_footer(self):
        html = """<html><body>
            <nav>Navigation junk that should be removed</nav>
            <article>
                <p>Actual article content that is long enough to pass the filter threshold.</p>
            </article>
            <footer>Footer junk that should also be removed from output</footer>
        </body></html>"""
        mock_resp = MagicMock()
        mock_resp.text = html
        mock_resp.raise_for_status.return_value = None

        with patch("modules.article_scraper._session") as mock_session:
            mock_session.get.return_value = mock_resp
            content = extract_with_fallback("https://example.com/article")

        if content:
            assert "Navigation junk" not in content
            assert "Footer junk" not in content


class TestProcessUrlsInParallel:
    def test_returns_dict_keyed_by_url(self):
        with patch("modules.article_scraper.extract_article_content") as mock_extract:
            mock_extract.return_value = ("https://example.com/1", "article content here")
            results = process_urls_in_parallel(["https://example.com/1"])

        assert "https://example.com/1" in results

    def test_deduplicates_urls(self):
        calls = []
        def _fake_extract(url):
            calls.append(url)
            return url, "content"

        with patch("modules.article_scraper.extract_article_content", side_effect=_fake_extract):
            process_urls_in_parallel(["https://example.com/1", "https://example.com/1"])

        assert len(calls) == 1

    def test_handles_extraction_exception_gracefully(self):
        with patch("modules.article_scraper.extract_article_content") as mock_extract:
            mock_extract.side_effect = RuntimeError("network error")
            results = process_urls_in_parallel(["https://example.com/1"])

        assert results.get("https://example.com/1") is None

    def test_empty_url_list_returns_empty_dict(self):
        results = process_urls_in_parallel([])
        assert results == {}
