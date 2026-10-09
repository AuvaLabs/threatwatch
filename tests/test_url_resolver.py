"""Tests for modules/url_resolver.py"""
import base64
import importlib
import importlib.util
import ipaddress
import socket
import sys
from unittest.mock import MagicMock, patch

import pytest

from modules.url_resolver import (
    decode_google_news_url,
    extract_canonical_from_html,
    extract_embedded_url,
    extract_url_from_gnews_summary,
    follow_redirects,
    is_clearnet_url,
    is_google_news_url,
    is_safe_url,
    resolve_original_url,
)
import modules.url_resolver as url_resolver_mod


def _load_real_beautifulsoup():
    """Load the real BeautifulSoup class bypassing the conftest bs4 mock."""
    mock = sys.modules.pop("bs4", None)
    try:
        import bs4 as real_bs4
        return real_bs4.BeautifulSoup
    finally:
        if mock is not None:
            sys.modules["bs4"] = mock


class TestGoogleNewsUrlClassification:
    def test_accepts_exact_google_news_host(self):
        assert is_google_news_url("https://news.google.com/rss/articles/id") is True

    @pytest.mark.parametrize("url", [
        "https://evil.test/?next=https://news.google.com/rss/articles/id",
        "https://news.google.com@evil.test/rss/articles/id",
        "https://news.google.com.evil.test/rss/articles/id",
        "not-a-url-with-news.google.com-inside",
    ])
    def test_rejects_google_news_substring_lookalikes(self, url):
        assert is_google_news_url(url) is False


class TestIsClearnetUrl:
    def test_valid_https(self):
        assert is_clearnet_url("https://example.com/article") is True

    def test_valid_http(self):
        assert is_clearnet_url("http://example.com/") is True

    def test_rejects_onion(self):
        assert is_clearnet_url("http://foobar.onion/path") is False

    def test_rejects_bare_onion_host(self):
        # host == "onion" without subdomain
        assert is_clearnet_url("http://onion/path") is False

    def test_rejects_i2p(self):
        assert is_clearnet_url("http://example.i2p/") is False

    def test_rejects_bare_i2p_host(self):
        assert is_clearnet_url("http://i2p/path") is False

    def test_rejects_ftp(self):
        assert is_clearnet_url("ftp://files.example.com/") is False

    def test_rejects_empty(self):
        assert is_clearnet_url("") is False

    def test_rejects_none(self):
        assert is_clearnet_url(None) is False  # type: ignore[arg-type]

    def test_rejects_non_string(self):
        assert is_clearnet_url(123) is False  # type: ignore[arg-type]

    def test_rejects_no_host(self):
        assert is_clearnet_url("https://") is False

    def test_exception_returns_false(self):
        # Passing a broken type that causes urlparse to fail
        with patch("modules.url_resolver.urlparse", side_effect=Exception("boom")):
            assert is_clearnet_url("https://example.com/") is False


class TestIsSafeUrl:
    def _mock_getaddrinfo(self, ip_str):
        """Return a getaddrinfo-shaped list for a given IP string."""
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip_str, 0))]

    def test_public_ip_is_safe(self):
        with patch("modules.url_resolver.socket.getaddrinfo",
                   return_value=self._mock_getaddrinfo("93.184.216.34")):
            assert is_safe_url("https://example.com/") is True

    def test_private_ip_is_blocked(self):
        with patch("modules.url_resolver.socket.getaddrinfo",
                   return_value=self._mock_getaddrinfo("192.168.1.1")):
            assert is_safe_url("https://internal.example.com/") is False

    def test_loopback_is_blocked(self):
        with patch("modules.url_resolver.socket.getaddrinfo",
                   return_value=self._mock_getaddrinfo("127.0.0.1")):
            assert is_safe_url("http://localhost/") is False

    def test_link_local_is_blocked(self):
        # 169.254.169.254 is the AWS metadata endpoint
        with patch("modules.url_resolver.socket.getaddrinfo",
                   return_value=self._mock_getaddrinfo("169.254.169.254")):
            assert is_safe_url("http://metadata.internal/latest/") is False

    def test_onion_fails_clearnet_check(self):
        assert is_safe_url("http://foobar.onion/") is False

    def test_dns_error_fails_closed(self):
        with patch("modules.url_resolver.socket.getaddrinfo",
                   side_effect=socket.gaierror("DNS failure")):
            assert is_safe_url("https://nonexistent.invalid/") is False

    def test_10_x_range_blocked(self):
        with patch("modules.url_resolver.socket.getaddrinfo",
                   return_value=self._mock_getaddrinfo("10.0.0.1")):
            assert is_safe_url("https://corp.internal/") is False

    def test_multicast_blocked(self):
        with patch("modules.url_resolver.socket.getaddrinfo",
                   return_value=self._mock_getaddrinfo("224.0.0.1")):
            assert is_safe_url("https://multicast.example.com/") is False

    def test_reserved_blocked(self):
        # 240.0.0.1 is in the reserved range
        with patch("modules.url_resolver.socket.getaddrinfo",
                   return_value=self._mock_getaddrinfo("240.0.0.1")):
            assert is_safe_url("https://reserved.example.com/") is False

    def test_empty_hostname_returns_false(self):
        # Cleared by is_clearnet_url before reaching DNS
        assert is_safe_url("https://") is False

    def test_logs_ssrf_warning(self, caplog):
        import logging
        with patch("modules.url_resolver.socket.getaddrinfo",
                   return_value=self._mock_getaddrinfo("10.0.0.1")):
            with caplog.at_level(logging.WARNING, logger="modules.url_resolver"):
                is_safe_url("https://internal.host.com/")
        assert any("SSRF blocked" in r.message for r in caplog.records)


class TestDecodeGoogleNewsUrl:
    def test_non_google_url_returns_none(self):
        assert decode_google_news_url("https://example.com/article") is None

    def test_google_news_without_articles_path_returns_none(self):
        assert decode_google_news_url("https://news.google.com/rss?hl=en") is None

    def test_valid_google_news_url_decoded(self):
        # Build a fake encoded payload that contains a real URL
        target = b"https://example.com/real-article"
        # Pad to simulate protobuf — the regex just grabs the first http URL it finds
        fake_proto = b"\x00\x01\x02" + target + b"\x00"
        encoded = base64.urlsafe_b64encode(fake_proto).rstrip(b"=").decode()
        gnews_url = f"https://news.google.com/rss/articles/{encoded}?hl=en-US"
        result = decode_google_news_url(gnews_url)
        assert result == "https://example.com/real-article"

    def test_malformed_encoded_part_returns_none(self):
        url = "https://news.google.com/rss/articles/!!!invalid!!!?hl=en"
        assert decode_google_news_url(url) is None

    def test_encoded_with_no_http_url_returns_none(self):
        # Valid base64 but no http URL embedded
        payload = b"\x00\x01\x02\x03\x04\x05"
        encoded = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
        url = f"https://news.google.com/rss/articles/{encoded}?hl=en"
        assert decode_google_news_url(url) is None


class TestExtractEmbeddedUrl:
    def test_extracts_url_param(self):
        url = "https://redirect.example.com/?url=https://target.example.com/article"
        assert extract_embedded_url(url) == "https://target.example.com/article"

    def test_returns_none_when_no_url_param(self):
        assert extract_embedded_url("https://example.com/path?q=1") is None


class TestExtractUrlFromGnewsSummary:
    """Tests for extract_url_from_gnews_summary.

    Note: conftest.py installs a stub bs4 mock (find_all returns []) when the
    real bs4 package hasn't been imported yet.  Tests that exercise the HTML
    parsing code-path must patch modules.url_resolver.BeautifulSoup with the
    real implementation so the function can actually find <a> tags.
    """

    @property
    def _real_bs(self):
        return _load_real_beautifulsoup()

    def test_returns_direct_article_url(self):
        summary = '<a href="https://article.example.com/path">Title</a>&nbsp;|&nbsp;Source'
        with patch("modules.url_resolver.BeautifulSoup", self._real_bs):
            result = extract_url_from_gnews_summary(summary)
        assert result == "https://article.example.com/path"

    def test_skips_google_news_links(self):
        summary = (
            '<a href="https://news.google.com/something">G</a> '
            '<a href="https://real.com/article">R</a>'
        )
        with patch("modules.url_resolver.BeautifulSoup", self._real_bs):
            result = extract_url_from_gnews_summary(summary)
        assert result == "https://real.com/article"

    def test_empty_summary_returns_none(self):
        assert extract_url_from_gnews_summary("") is None
        assert extract_url_from_gnews_summary(None) is None  # type: ignore[arg-type]

    def test_summary_without_http_returns_none(self):
        assert extract_url_from_gnews_summary("plain text with no links") is None

    def test_all_links_are_google_returns_none(self):
        summary = '<a href="https://news.google.com/a">A</a><a href="https://news.google.com/b">B</a>'
        with patch("modules.url_resolver.BeautifulSoup", self._real_bs):
            result = extract_url_from_gnews_summary(summary)
        assert result is None


class TestFollowRedirects:
    def _safe_mock(self, ip="93.184.216.34"):
        """Return a getaddrinfo mock for a public IP."""
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0))]

    def test_returns_none_for_unsafe_url(self):
        # Onion URL fails is_safe_url immediately
        result = follow_redirects("http://evil.onion/")
        assert result is None

    def test_follows_redirect_and_returns_location(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 301
        mock_resp.headers = {"Location": "https://final.example.com/article"}
        mock_resp.url = "https://example.com/"

        with patch("modules.url_resolver.socket.getaddrinfo", return_value=self._safe_mock()), \
             patch("modules.url_resolver.requests.head", return_value=mock_resp):
            result = follow_redirects("https://example.com/")
        assert result == "https://final.example.com/article"

    def test_returns_final_url_on_200(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.url = "https://final.example.com/page"

        with patch("modules.url_resolver.socket.getaddrinfo", return_value=self._safe_mock()), \
             patch("modules.url_resolver.requests.head", return_value=mock_resp):
            # final URL also needs to be safe
            with patch("modules.url_resolver.is_safe_url", side_effect=lambda u: True):
                result = follow_redirects("https://example.com/")
        assert result == "https://final.example.com/page"

    def test_returns_none_on_request_exception(self):
        import requests as req_lib
        with patch("modules.url_resolver.socket.getaddrinfo", return_value=self._safe_mock()), \
             patch("modules.url_resolver.requests.head",
                   side_effect=req_lib.RequestException("timeout")):
            result = follow_redirects("https://example.com/")
        assert result is None

    def test_logs_redirect_failure(self, caplog):
        import logging
        import requests as req_lib
        with patch("modules.url_resolver.socket.getaddrinfo", return_value=self._safe_mock()), \
             patch("modules.url_resolver.requests.head",
                   side_effect=req_lib.RequestException("connection error")):
            with caplog.at_level(logging.WARNING, logger="modules.url_resolver"):
                follow_redirects("https://example.com/")
        assert any("Redirect failed" in r.message for r in caplog.records)

    def test_final_url_unsafe_returns_none(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.url = "http://evil.onion/"

        call_count = {"n": 0}
        def side_effect(u):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return True  # first call (input URL)
            return False  # second call (final URL after redirect)

        with patch("modules.url_resolver.is_safe_url", side_effect=side_effect), \
             patch("modules.url_resolver.requests.head", return_value=mock_resp):
            result = follow_redirects("https://example.com/")
        assert result is None


class TestExtractCanonicalFromHtml:
    """Tests for extract_canonical_from_html.

    BeautifulSoup is patched with the real implementation where HTML parsing
    is exercised (conftest installs a stub that always returns find()=None).
    """

    def _safe_mock(self, ip="93.184.216.34"):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, 0))]

    @property
    def _real_bs(self):
        return _load_real_beautifulsoup()

    def test_returns_url_for_unsafe_input(self):
        # Unsafe URL falls back to original without HTTP call
        result = extract_canonical_from_html("http://evil.onion/")
        assert result == "http://evil.onion/"

    def test_returns_canonical_href_when_present(self):
        html = '<html><head><link rel="canonical" href="https://canonical.example.com/article"/></head></html>'
        mock_resp = MagicMock()
        mock_resp.text = html

        with patch("modules.url_resolver.socket.getaddrinfo", return_value=self._safe_mock()), \
             patch("modules.url_resolver.requests.get", return_value=mock_resp), \
             patch("modules.url_resolver.BeautifulSoup", self._real_bs):
            result = extract_canonical_from_html("https://example.com/")
        assert result == "https://canonical.example.com/article"

    def test_returns_original_when_no_canonical(self):
        html = "<html><head><title>No canonical</title></head></html>"
        mock_resp = MagicMock()
        mock_resp.text = html

        with patch("modules.url_resolver.socket.getaddrinfo", return_value=self._safe_mock()), \
             patch("modules.url_resolver.requests.get", return_value=mock_resp), \
             patch("modules.url_resolver.BeautifulSoup", self._real_bs):
            result = extract_canonical_from_html("https://example.com/path")
        assert result == "https://example.com/path"

    def test_returns_original_on_exception(self, caplog):
        import logging
        with patch("modules.url_resolver.socket.getaddrinfo", return_value=self._safe_mock()), \
             patch("modules.url_resolver.requests.get", side_effect=Exception("network error")):
            with caplog.at_level(logging.WARNING, logger="modules.url_resolver"):
                result = extract_canonical_from_html("https://example.com/")
        assert result == "https://example.com/"
        assert any("Failed to extract canonical" in r.message for r in caplog.records)


class TestResolveOriginalUrl:
    def test_google_news_decoded_locally(self):
        target = b"https://example.com/real-article"
        fake_proto = b"\x00\x01\x02" + target
        encoded = base64.urlsafe_b64encode(fake_proto).rstrip(b"=").decode()
        gnews_url = f"https://news.google.com/rss/articles/{encoded}"
        # Should decode without any HTTP call
        result = resolve_original_url(gnews_url)
        assert result == "https://example.com/real-article"

    def test_embedded_url_extracted(self):
        url = "https://redir.example.com/?url=https://article.example.com/"
        result = resolve_original_url(url)
        assert result == "https://article.example.com/"

    def test_returns_original_on_all_failures(self):
        plain_url = "https://example.com/article-" + "x" * 30  # unique to avoid cache hit
        with patch("modules.url_resolver.follow_redirects", return_value=None), \
             patch("modules.url_resolver.extract_canonical_from_html", return_value=None):
            result = resolve_original_url(plain_url)
        assert result == plain_url

    def test_cache_hit_returns_cached(self):
        # Prime the cache
        url_resolver_mod._CACHE.clear()
        url_resolver_mod._CACHE["https://cached.example.com/"] = "https://resolved.example.com/"
        result = resolve_original_url("https://cached.example.com/")
        assert result == "https://resolved.example.com/"
        url_resolver_mod._CACHE.clear()

    def test_gnews_with_summary_uses_summary_url(self):
        url_resolver_mod._CACHE.clear()
        summary = '<a href="https://article.example.com/from-summary">Title</a>'
        gnews_url = "https://news.google.com/rss/articles/ENCODED_PART?hl=en"
        result = resolve_original_url(gnews_url, summary=summary)
        assert result == "https://article.example.com/from-summary"
        url_resolver_mod._CACHE.clear()

    def test_google_url_with_no_decodable_content_kept_as_is(self):
        url_resolver_mod._CACHE.clear()
        # A google news URL with garbage encoding and no summary
        gnews_url = "https://news.google.com/rss/articles/NOTBASE64GARBAGE"
        result = resolve_original_url(gnews_url)
        assert result == gnews_url
        url_resolver_mod._CACHE.clear()

    def test_cache_eviction_on_max_size(self):
        url_resolver_mod._CACHE.clear()
        # Fill cache to max
        for i in range(url_resolver_mod._CACHE_MAX):
            url_resolver_mod._CACHE[f"https://example.com/article-{i}"] = f"https://resolved.com/{i}"
        assert len(url_resolver_mod._CACHE) == url_resolver_mod._CACHE_MAX

        # A new non-google URL with an embedded param triggers eviction
        new_url = "https://redir.example.com/?url=https://new-article.com/piece"
        result = resolve_original_url(new_url)
        assert result == "https://new-article.com/piece"
        # Cache should have evicted one old entry and added new
        assert len(url_resolver_mod._CACHE) == url_resolver_mod._CACHE_MAX
        url_resolver_mod._CACHE.clear()

    def test_follow_redirects_used_when_no_embedded(self):
        url_resolver_mod._CACHE.clear()
        plain_url = "https://shortlink.example.com/abc123unique"
        redirected = "https://final.example.com/real-article"
        with patch("modules.url_resolver.follow_redirects", return_value=redirected):
            result = resolve_original_url(plain_url)
        assert result == redirected
        url_resolver_mod._CACHE.clear()

    def test_canonical_used_when_redirect_same_as_input(self):
        url_resolver_mod._CACHE.clear()
        plain_url = "https://no-redirect.example.com/page-uniqueXYZ"
        with patch("modules.url_resolver.follow_redirects", return_value=plain_url), \
             patch("modules.url_resolver.extract_canonical_from_html",
                   return_value="https://canonical.example.com/page"):
            result = resolve_original_url(plain_url)
        assert result == "https://canonical.example.com/page"
        url_resolver_mod._CACHE.clear()
