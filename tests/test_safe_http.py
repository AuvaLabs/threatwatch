"""Tests for modules/safe_http.py — SSRF guard."""

import socket
import pytest
from unittest.mock import patch, MagicMock

import modules.safe_http as safe_http
from modules.safe_http import _is_public_ip, install_ssrf_guard


class TestIsPublicIp:
    """Test the _is_public_ip helper."""

    # Public IPs
    def test_public_ipv4(self):
        assert _is_public_ip("8.8.8.8") is True

    def test_public_ipv4_cloudflare(self):
        assert _is_public_ip("1.1.1.1") is True

    def test_public_ipv6(self):
        assert _is_public_ip("2607:f8b0:4004:800::200e") is True

    # Private IPs
    def test_private_10(self):
        assert _is_public_ip("10.0.0.1") is False

    def test_private_172(self):
        assert _is_public_ip("172.16.0.1") is False

    def test_private_192(self):
        assert _is_public_ip("192.168.1.1") is False

    # Loopback
    def test_loopback_ipv4(self):
        assert _is_public_ip("127.0.0.1") is False

    def test_loopback_ipv6(self):
        assert _is_public_ip("::1") is False

    # Link-local (cloud IMDS)
    def test_link_local(self):
        assert _is_public_ip("169.254.169.254") is False

    def test_link_local_other(self):
        assert _is_public_ip("169.254.1.1") is False

    # Reserved / multicast / unspecified
    def test_reserved(self):
        assert _is_public_ip("240.0.0.1") is False

    def test_multicast(self):
        assert _is_public_ip("224.0.0.1") is False

    def test_unspecified(self):
        assert _is_public_ip("0.0.0.0") is False

    # Invalid input — fail closed
    def test_invalid_string(self):
        assert _is_public_ip("not-an-ip") is False

    def test_empty_string(self):
        assert _is_public_ip("") is False


class TestInstallSsrfGuard:
    """Test install_ssrf_guard with careful isolation."""

    @pytest.fixture(autouse=True)
    def _isolate(self):
        """Save and restore urllib3 create_connection and module state."""
        from urllib3.util import connection as urllib3_conn
        original_fn = urllib3_conn.create_connection
        original_installed = safe_http._installed
        safe_http._installed = False
        yield
        urllib3_conn.create_connection = original_fn
        safe_http._installed = original_installed

    def test_installs_guard(self):
        from urllib3.util import connection as urllib3_conn
        original = urllib3_conn.create_connection
        install_ssrf_guard()
        assert urllib3_conn.create_connection is not original
        assert safe_http._installed is True

    def test_idempotent(self):
        from urllib3.util import connection as urllib3_conn
        install_ssrf_guard()
        guarded = urllib3_conn.create_connection
        install_ssrf_guard()  # second call
        assert urllib3_conn.create_connection is guarded

    def test_blocks_private_ip(self):
        install_ssrf_guard()
        from urllib3.util import connection as urllib3_conn
        fake_info = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 80))]
        with patch("modules.safe_http.socket.getaddrinfo", return_value=fake_info):
            with pytest.raises(ConnectionRefusedError, match="non-public"):
                urllib3_conn.create_connection(("evil.com", 80))

    def test_blocks_link_local(self):
        install_ssrf_guard()
        from urllib3.util import connection as urllib3_conn
        fake_info = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", 80))]
        with patch("modules.safe_http.socket.getaddrinfo", return_value=fake_info):
            with pytest.raises(ConnectionRefusedError, match="non-public"):
                urllib3_conn.create_connection(("metadata.cloud", 80))

    def test_allows_public_ip(self):
        install_ssrf_guard()
        from urllib3.util import connection as urllib3_conn
        fake_info = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 443))]
        with patch("modules.safe_http.socket.getaddrinfo", return_value=fake_info), \
             patch.object(urllib3_conn, "_orig_create_connection", create=True) as mock_orig:
            # The guard calls through to the original on public IPs.
            # We saved the original in _isolate, so patch the underlying call.
            # Actually, the guard captures `original` in its closure. We need
            # to mock socket.getaddrinfo and let the original call fail naturally
            # (since we're not actually connecting). Let's just verify no
            # ConnectionRefusedError is raised — the underlying connect will
            # raise OSError which is fine.
            try:
                urllib3_conn.create_connection(("dns.google", 443))
            except ConnectionRefusedError:
                pytest.fail("SSRF guard should not block public IPs")
            except OSError:
                pass  # Expected — no actual server listening

    def test_dns_failure_falls_through(self):
        install_ssrf_guard()
        from urllib3.util import connection as urllib3_conn
        with patch("modules.safe_http.socket.getaddrinfo", side_effect=socket.gaierror("DNS failed")):
            # Should fall through to original create_connection, not raise
            # ConnectionRefusedError
            try:
                urllib3_conn.create_connection(("nonexistent.invalid", 80))
            except ConnectionRefusedError:
                pytest.fail("DNS failure should not trigger SSRF guard")
            except OSError:
                pass  # Expected — original connection fails normally

    def test_mixed_ips_one_private_blocks(self):
        """If any resolved IP is private, block the whole request."""
        install_ssrf_guard()
        from urllib3.util import connection as urllib3_conn
        fake_info = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 80)),
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 80)),
        ]
        with patch("modules.safe_http.socket.getaddrinfo", return_value=fake_info):
            with pytest.raises(ConnectionRefusedError, match="non-public"):
                urllib3_conn.create_connection(("evil.com", 80))

    def test_urllib3_not_importable(self):
        """When urllib3 is missing, logs warning and returns without error."""
        safe_http._installed = False
        with patch.dict("sys.modules", {"urllib3": None, "urllib3.util": None, "urllib3.util.connection": None}):
            # Force re-import failure
            with patch("builtins.__import__", side_effect=ImportError("no urllib3")):
                # Should not raise
                install_ssrf_guard()
                assert safe_http._installed is False


class TestAllowlist:
    """Allowlist for configured internal URLs (e.g. Claude Bridge)."""

    @pytest.fixture(autouse=True)
    def _isolate(self):
        from urllib3.util import connection as urllib3_conn
        original_fn = urllib3_conn.create_connection
        original_installed = safe_http._installed
        safe_http._installed = False
        yield
        urllib3_conn.create_connection = original_fn
        safe_http._installed = original_installed

    def test_allowlist_skips_check_for_configured_bridge(self, monkeypatch):
        monkeypatch.setenv("CLAUDE_BRIDGE_URL", "http://172.21.0.1:8400/v1")
        install_ssrf_guard()
        from urllib3.util import connection as urllib3_conn
        with patch("modules.safe_http.socket.getaddrinfo") as ga:
            try:
                urllib3_conn.create_connection(("172.21.0.1", 8400))
            except ConnectionRefusedError:
                pytest.fail("Allowlisted host should bypass SSRF guard")
            except OSError:
                pass
            # No ConnectionRefusedError = guard short-circuited correctly.

    def test_allowlist_does_not_leak_to_other_hosts(self, monkeypatch):
        monkeypatch.setenv("CLAUDE_BRIDGE_URL", "http://172.21.0.1:8400/v1")
        install_ssrf_guard()
        from urllib3.util import connection as urllib3_conn
        fake_info = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("172.21.0.1", 80))]
        with patch("modules.safe_http.socket.getaddrinfo", return_value=fake_info):
            with pytest.raises(ConnectionRefusedError, match="non-public"):
                urllib3_conn.create_connection(("evil.attacker.com", 80))

    def test_unset_bridge_url_leaves_allowlist_empty(self, monkeypatch):
        monkeypatch.delenv("CLAUDE_BRIDGE_URL", raising=False)
        install_ssrf_guard()
        from urllib3.util import connection as urllib3_conn
        fake_info = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("172.21.0.1", 80))]
        with patch("modules.safe_http.socket.getaddrinfo", return_value=fake_info):
            with pytest.raises(ConnectionRefusedError, match="non-public"):
                urllib3_conn.create_connection(("172.21.0.1", 8400))
