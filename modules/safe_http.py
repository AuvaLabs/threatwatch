"""Global SSRF guard for outbound HTTP/HTTPS.

`is_safe_url` in `url_resolver` resolves a hostname at VALIDATION time; the
actual socket connection happens later and re-resolves DNS. A hostile feed
operator can supply a domain that resolves to a public IP during the check and
flips to 169.254.169.254 (cloud IMDS) or 127.0.0.1 at connect time — classic
DNS-rebinding TOCTOU.

This module closes that gap by installing a `create_connection` hook on the
`urllib3` connection pool used by `requests`. Every outbound socket connection
re-resolves the hostname and rejects private/loopback/link-local/reserved
addresses at connect time, no matter what the pre-check said.

Usage:
    from modules.safe_http import install_ssrf_guard
    install_ssrf_guard()  # called once at process startup
"""
from __future__ import annotations

import ipaddress
import logging
import socket

logger = logging.getLogger(__name__)

_installed = False


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # Not a parseable IP (shouldn't happen here — getaddrinfo gave it to
        # us), so treat as unsafe to fail closed.
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_unspecified or ip.is_multicast
    )


def install_ssrf_guard() -> None:
    """Install a urllib3-level SSRF guard. Idempotent."""
    global _installed
    if _installed:
        return
    try:
        from urllib3.util import connection as urllib3_connection
    except ImportError:
        logger.warning("urllib3 not importable — SSRF guard not installed")
        return

    original = urllib3_connection.create_connection

    def guarded(address, *args, **kwargs):
        host, port = address
        # Re-resolve at connect time. Any IP in the getaddrinfo list that maps
        # to a blocked range poisons the whole attempt — we refuse to race
        # with happy-eyeballs / round-robin DNS.
        try:
            infos = socket.getaddrinfo(host, port)
        except socket.gaierror:
            # Let the underlying connection raise a normal DNS error.
            return original(address, *args, **kwargs)
        for info in infos:
            peer_ip = info[4][0]
            if not _is_public_ip(peer_ip):
                raise ConnectionRefusedError(
                    f"SSRF guard: {host} resolves to non-public {peer_ip}"
                )
        return original(address, *args, **kwargs)

    urllib3_connection.create_connection = guarded
    _installed = True
    logger.info("SSRF guard installed on urllib3 create_connection")
