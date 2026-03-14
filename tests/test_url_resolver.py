"""Tests for modules/url_resolver.py"""
import base64
import ipaddress
import socket
from unittest.mock import MagicMock, patch

import pytest

from modules.url_resolver import (
    decode_google_news_url,
    extract_embedded_url,
    is_clearnet_url,
    is_safe_url,
    resolve_original_url,
)


class TestIsClearnetUrl:
    def test_valid_https(self):
        assert is_clearnet_url("https://example.com/article") is True

    def test_valid_http(self):
        assert is_clearnet_url("http://example.com/") is True

    def test_rejects_onion(self):
        assert is_clearnet_url("http://foobar.onion/path") is False

    def test_rejects_i2p(self):
        assert is_clearnet_url("http://example.i2p/") is False

    def test_rejects_ftp(self):
        assert is_clearnet_url("ftp://files.example.com/") is False

    def test_rejects_empty(self):
        assert is_clearnet_url("") is False

    def test_rejects_none(self):
        assert is_clearnet_url(None) is False  # type: ignore[arg-type]

    def test_rejects_no_host(self):
        assert is_clearnet_url("https://") is False


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


class TestExtractEmbeddedUrl:
    def test_extracts_url_param(self):
        url = "https://redirect.example.com/?url=https://target.example.com/article"
        assert extract_embedded_url(url) == "https://target.example.com/article"

    def test_returns_none_when_no_url_param(self):
        assert extract_embedded_url("https://example.com/path?q=1") is None


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
