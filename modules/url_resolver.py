# ==== Module Imports ====
import logging
import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup

_CACHE: dict[str, str] = {}
_CACHE_MAX = 1000

# ==== Embedded URL Extraction ====
def extract_embedded_url(url):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    return query.get('url', [None])[0]

# ==== Redirect Resolution via HEAD ====
def follow_redirects(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        if response.status_code in [301, 302] and 'Location' in response.headers:
            return response.headers['Location']
        return response.url
    except requests.RequestException as e:
        logging.warning(f"Redirect failed for {url}: {e}")
        return None

# ==== Canonical URL Extraction from HTML ====
def extract_canonical_from_html(url):
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

# ==== Final URL Resolver ====
def resolve_original_url(url):
    if url in _CACHE:
        return _CACHE[url]

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
