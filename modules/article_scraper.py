import time
import random
import logging
import requests
from newspaper import Article
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from modules.url_resolver import resolve_original_url
from modules.config import MAX_SCRAPER_THREADS

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


def _create_session():
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,
        pool_maxsize=20,
    )
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


_session = _create_session()


def _get_headers():
    return {"User-Agent": random.choice(USER_AGENTS)}


def extract_with_newspaper(url):
    try:
        article = Article(url)
        article.download()
        article.parse()
        text = article.text.strip()
        return text if len(text) > 100 else None
    except Exception as e:
        logging.warning(f"Newspaper3k failed for {url}: {e}")
        return None


def extract_with_fallback(url):
    try:
        response = _session.get(url, headers=_get_headers(), timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()

        article_tag = soup.find("article") or soup.find("main") or soup
        paragraphs = article_tag.find_all("p")
        content = " ".join(p.get_text(strip=True) for p in paragraphs if len(p.get_text(strip=True)) > 20)
        return content.strip() if len(content) > 100 else None
    except requests.RequestException as e:
        logging.warning(f"Fallback scraping failed for {url}: {e}")
        return None


def extract_article_content(raw_url):
    clean_url = resolve_original_url(raw_url)

    content = extract_with_newspaper(clean_url)
    if content:
        logging.info(f"Extracted {len(content)} chars from {clean_url}")
        return clean_url, content

    content = extract_with_fallback(clean_url)
    if content:
        logging.info(f"Extracted {len(content)} chars (fallback) from {clean_url}")
        return clean_url, content

    logging.warning(f"No content extracted from {clean_url}")
    return clean_url, None


def process_urls_in_parallel(url_list, max_threads=MAX_SCRAPER_THREADS):
    results = {}
    unique_urls = list(dict.fromkeys(url_list))

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_url = {
            executor.submit(extract_article_content, url): url
            for url in unique_urls
        }
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                clean_url, content = future.result()
                results[url] = content
                if clean_url != url:
                    results[clean_url] = content
            except Exception as exc:
                logging.error(f"Exception scraping {url}: {exc}")
                results[url] = None

    logging.info(
        f"Scraping complete: {sum(1 for v in results.values() if v)} of "
        f"{len(unique_urls)} articles extracted"
    )
    return results
