# ==== Module Imports ====
import base64
import ipaddress
import logging
import re
import socket
import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

_CACHE: dict[str, str] = {}
_CACHE_MAX = 1000


def is_clearnet_url(url: str) -> bool:
    """Return True only if url is a regular clearnet http/https address.

    Rejects:
    - .onion domains (Tor hidden services)
    - .i2p domains (I2P network)
    - non-http/https schemes
    - empty or non-string values
    """
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        host = (parsed.hostname or "").lower()
        if host.endswith(".onion") or host == "onion":
            return False
        if host.endswith(".i2p") or host == "i2p":
            return False
        return bool(host)
    except Exception:
        return False


def is_safe_url(url: str) -> bool:
    """Return True only if url is safe to fetch — clearnet AND resolves to a
    public IP address.

    Blocks all SSRF targets:
    - RFC-1918 private ranges (10.x, 172.16-31.x, 192.168.x, 100.64.x)
    - Loopback (127.x, ::1)
    - Link-local (169.254.x — includes cloud metadata endpoint 169.254.169.254)
    - Reserved, unspecified, and multicast addresses

    Fails closed: returns False on any DNS or parsing error.
    """
    if not is_clearnet_url(url):
        return False
    try:
        hostname = urlparse(url).hostname or ""
        if not hostname:
            return False
        for addr_info in socket.getaddrinfo(hostname, None):
            ip_str = addr_info[4][0]
            ip = ipaddress.ip_address(ip_str)
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_unspecified or ip.is_multicast):
                logging.warning(f"SSRF blocked: {url} resolves to non-public IP {ip_str}")
                return False
    except Exception:
        return False
    return True


# ==== Google News URL Decoding ====
_GNEWS_URL_RE = re.compile(
    rb'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
)

def decode_google_news_url(url: str) -> str | None:
    """Decode a Google News RSS article link to the actual article URL.

    Google News RSS feeds wrap article links as base64-encoded protobuf:
      https://news.google.com/rss/articles/<encoded>?hl=...
    The encoded part contains the real URL embedded in protobuf bytes.
    Decoding is done locally — no HTTP request, no CAPTCHA risk.
    Returns the decoded URL, or None if the URL is not a Google News link
    or decoding fails.
    """
    if 'news.google.com' not in url or '/articles/' not in url:
        return None
    try:
        encoded = url.split('/articles/')[-1].split('?')[0]
        pad = (4 - len(encoded) % 4) % 4
        decoded = base64.urlsafe_b64decode(encoded + '=' * pad)
        match = _GNEWS_URL_RE.search(decoded)
        if match:
            return match.group(0).decode('utf-8')
    except Exception:
        pass
    return None


# ==== Embedded URL Extraction ====
def extract_embedded_url(url):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    return query.get('url', [None])[0]

# ==== Redirect Resolution via HEAD ====
def follow_redirects(url):
    if not is_safe_url(url):
        logging.debug(f"follow_redirects: blocked unsafe URL {url}")
        return None
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        if response.status_code in [301, 302] and 'Location' in response.headers:
            return response.headers['Location']
        final = response.url
        # Never return a Tor, I2P, or private-network address after redirect
        return final if is_safe_url(final) else None
    except requests.RequestException as e:
        logging.warning(f"Redirect failed for {url}: {e}")
        return None

# ==== Canonical URL Extraction from HTML ====
def extract_canonical_from_html(url):
    if not is_safe_url(url):
        logging.debug(f"extract_canonical: blocked unsafe URL {url}")
        return url
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        resp = requests.get(url, headers=headers, timeout=8)
        soup = BeautifulSoup(resp.text, 'html.parser')
        canonical = soup.find('link', rel='canonical')
        if canonical and canonical.get('href'):
            return canonical['href']
    except Exception as e:
        logging.warning(f"Failed to extract canonical URL from {url}: {e}")
    return url

# ==== Google News summary HTML extractor ====
def extract_url_from_gnews_summary(summary: str) -> str | None:
    """Extract the actual article URL from a Google News RSS entry summary.

    Google News RSS summaries contain HTML like:
      <a href="https://actual-article.com/path">Title</a>&nbsp;|&nbsp;Source
    Parsing this is zero-cost and works regardless of protobuf encoding changes.
    """
    if not summary or 'news.google.com' not in summary and 'http' not in summary:
        return None
    try:
        soup = BeautifulSoup(summary, 'html.parser')
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            if href.startswith('http') and 'news.google.com' not in href:
                return href
    except Exception:
        pass
    return None


# ==== Final URL Resolver ====
def resolve_original_url(url: str, summary: str = '') -> str:
    if url in _CACHE:
        return _CACHE[url]

    # 1. Try to extract from Google News summary HTML (zero-cost, no HTTP)
    if 'news.google.com' in url and summary:
        from_summary = extract_url_from_gnews_summary(summary)
        if from_summary and is_clearnet_url(from_summary):
            _CACHE[url] = from_summary
            return from_summary

    # 2. Try to decode the Google News protobuf URL locally (no HTTP)
    gnews_decoded = decode_google_news_url(url)
    if gnews_decoded and is_clearnet_url(gnews_decoded):
        _CACHE[url] = gnews_decoded
        return gnews_decoded

    # 3. Non-Google URLs: embedded param, redirect, or canonical HTML
    if 'news.google.com' not in url:
        embedded = extract_embedded_url(url)
        if embedded:
            result = embedded
        else:
            redirected = follow_redirects(url)
            if redirected and redirected != url:
                result = redirected
            else:
                result = extract_canonical_from_html(url) or url
        if len(_CACHE) >= _CACHE_MAX:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[url] = result
        return result

    # 4. Google URL with no decodable content — keep as-is (don't hit Google)
    _CACHE[url] = url
    return url
