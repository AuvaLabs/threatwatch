import time
from unittest.mock import MagicMock, patch

import pytest

from modules.newsapi_fetcher import fetch_newsapi_articles, _normalize


class TestNormalize:
    def test_valid_article(self):
        raw = {
            "title": "Ransomware hits hospital network",
            "url": "https://example.com/article",
            "publishedAt": "2024-01-01T12:00:00Z",
            "description": "A ransomware attack disrupted operations.",
            "source": {"name": "SecurityWeek"},
        }
        result = _normalize(raw)
        assert result is not None
        assert result["title"] == "Ransomware hits hospital network"
        assert result["link"] == "https://example.com/article"
        assert result["summary"] == "A ransomware attack disrupted operations."
        assert result["source"] == "newsapi:SecurityWeek"
        assert "hash" in result
        assert result["feed_region"] == "Global"

    def test_removed_article_skipped(self):
        raw = {
            "title": "[Removed]",
            "url": "https://example.com/article",
            "publishedAt": "2024-01-01T12:00:00Z",
            "description": "",
            "source": {"name": "Unknown"},
        }
        assert _normalize(raw) is None

    def test_empty_title_skipped(self):
        raw = {"title": "", "url": "https://example.com/x", "publishedAt": "", "description": "", "source": {}}
        assert _normalize(raw) is None

    def test_non_clearnet_url_skipped(self):
        raw = {
            "title": "Article",
            "url": "http://example.onion/article",
            "publishedAt": "2024-01-01T00:00:00Z",
            "description": "",
            "source": {"name": "Onion"},
        }
        assert _normalize(raw) is None

    def test_hash_is_deterministic(self):
        raw = {
            "title": "Test",
            "url": "https://example.com/test",
            "publishedAt": "",
            "description": "",
            "source": {"name": "Test"},
        }
        r1 = _normalize(raw)
        r2 = _normalize(raw)
        assert r1["hash"] == r2["hash"]


class TestFetchNewsapiArticles:
    @patch("modules.newsapi_fetcher.os.getenv", return_value=None)
    def test_no_key_returns_empty(self, _):
        result = fetch_newsapi_articles()
        assert result == []

    @patch("modules.newsapi_fetcher._load_last_call", return_value=time.time())
    @patch("modules.newsapi_fetcher.os.getenv", return_value="test-key")
    def test_rate_limit_returns_empty(self, mock_env, mock_last):
        result = fetch_newsapi_articles()
        assert result == []

    @patch("modules.newsapi_fetcher._save_last_call")
    @patch("modules.newsapi_fetcher._load_last_call", return_value=0.0)
    @patch("modules.newsapi_fetcher.os.getenv", return_value="test-key")
    @patch("modules.newsapi_fetcher.requests.get")
    def test_successful_fetch(self, mock_get, mock_env, mock_last, mock_save):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "status": "ok",
            "articles": [
                {
                    "title": "Malware discovered in supply chain",
                    "url": "https://example.com/malware",
                    "publishedAt": "2024-01-01T10:00:00Z",
                    "description": "Researchers found malware.",
                    "source": {"name": "ThreatPost"},
                }
            ],
        }
        mock_get.return_value = mock_resp

        result = fetch_newsapi_articles()
        assert len(result) == 1
        assert result[0]["title"] == "Malware discovered in supply chain"
        mock_save.assert_called_once()

    @patch("modules.newsapi_fetcher._save_last_call")
    @patch("modules.newsapi_fetcher._load_last_call", return_value=0.0)
    @patch("modules.newsapi_fetcher.os.getenv", return_value="test-key")
    @patch("modules.newsapi_fetcher.requests.get")
    def test_non_ok_status_returns_empty(self, mock_get, mock_env, mock_last, mock_save):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {"status": "error", "message": "Invalid API key"}
        mock_get.return_value = mock_resp

        result = fetch_newsapi_articles()
        assert result == []
        mock_save.assert_not_called()

    @patch("modules.newsapi_fetcher._load_last_call", return_value=0.0)
    @patch("modules.newsapi_fetcher.os.getenv", return_value="test-key")
    @patch("modules.newsapi_fetcher.requests.get", side_effect=Exception("Network error"))
    def test_request_exception_returns_empty(self, mock_get, mock_env, mock_last):
        result = fetch_newsapi_articles()
        assert result == []

    @patch("modules.newsapi_fetcher._save_last_call")
    @patch("modules.newsapi_fetcher._load_last_call", return_value=0.0)
    @patch("modules.newsapi_fetcher.os.getenv", return_value="test-key")
    @patch("modules.newsapi_fetcher.requests.get")
    def test_removed_articles_filtered_out(self, mock_get, mock_env, mock_last, mock_save):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = {
            "status": "ok",
            "articles": [
                {
                    "title": "[Removed]",
                    "url": "https://example.com/removed",
                    "publishedAt": "2024-01-01T10:00:00Z",
                    "description": "",
                    "source": {"name": "Unknown"},
                }
            ],
        }
        mock_get.return_value = mock_resp

        result = fetch_newsapi_articles()
        assert result == []


class TestLastCallHelpers:
    """Persistence helpers for the rate-limit gate — silent failure is fine."""

    def test_load_last_call_returns_zero_when_no_file(self, tmp_path, monkeypatch):
        import modules.newsapi_fetcher as na
        monkeypatch.setattr(na, "_LAST_CALL_FILE", tmp_path / "nope.txt")
        assert na._load_last_call() == 0.0

    def test_load_last_call_roundtrip(self, tmp_path, monkeypatch):
        import modules.newsapi_fetcher as na
        p = tmp_path / "last.txt"
        monkeypatch.setattr(na, "_LAST_CALL_FILE", p)
        na._save_last_call(12345.0)
        assert na._load_last_call() == 12345.0

    def test_load_last_call_swallows_corrupt(self, tmp_path, monkeypatch):
        import modules.newsapi_fetcher as na
        p = tmp_path / "last.txt"
        p.write_text("not-a-float")
        monkeypatch.setattr(na, "_LAST_CALL_FILE", p)
        assert na._load_last_call() == 0.0

    def test_save_last_call_swallows_oserror(self, tmp_path, monkeypatch):
        """save failure must not crash the pipeline — just log a warning."""
        import modules.newsapi_fetcher as na
        monkeypatch.setattr(na, "_LAST_CALL_FILE", tmp_path / "locked.txt")
        with patch("pathlib.Path.write_text", side_effect=OSError("readonly")):
            na._save_last_call(1.0)  # should not raise
