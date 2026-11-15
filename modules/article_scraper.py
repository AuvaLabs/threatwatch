import time
import random
import logging
import requests
import trafilatura
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from modules.url_resolver import is_google_news_url, resolve_original_url, is_safe_url
from modules.config import MAX_SCRAPER_THREADS

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


def _create_session() -> requests.Session:
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
_SKIP_FULL_TEXT_HOSTS = frozenset({"vulners.com"})
_OUTCOME_KEYS = (
    "succeeded",
    "failed",
    "blocked",
    "skipped_protected",
    "skipped_unresolved",
)


class ExtractionResult(tuple):
    """Backward-compatible two-tuple carrying a machine-readable outcome."""

    outcome: str

    def __new__(
        cls,
        clean_url: str,
        content: str | None,
        outcome: str,
    ) -> "ExtractionResult":
        instance = super().__new__(cls, (clean_url, content))
        instance.outcome = outcome
        return instance

    @property
    def clean_url(self) -> str:
        return self[0]

    @property
    def content(self) -> str | None:
        return self[1]


class ScrapeResults(dict[str, str | None]):
    """Content map with one explicit outcome for each requested URL."""

    def __init__(self, *args: Any, outcomes: dict[str, str] | None = None, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.outcomes = dict(outcomes or {})

    @property
    def outcome_counts(self) -> dict[str, int]:
        return {
            key: sum(outcome == key for outcome in self.outcomes.values())
            for key in _OUTCOME_KEYS
        }


def _get_headers() -> dict[str, str]:
    return {"User-Agent": random.choice(USER_AGENTS)}


def extract_with_trafilatura(url: str) -> str | None:
    if not is_safe_url(url):
        logger.debug(f"extract_with_trafilatura: blocked unsafe URL {url}")
        return None
    try:
        downloaded = trafilatura.fetch_url(url)
        if not downloaded:
            return None
        text = trafilatura.extract(downloaded, include_comments=False, include_tables=False)
        return text if text and len(text) > 100 else None
    except Exception as e:
        logger.warning(f"trafilatura failed for {url}: {e}")
        return None


def extract_with_fallback(url: str) -> str | None:
    if not is_safe_url(url):
        logger.debug(f"extract_with_fallback: blocked unsafe URL {url}")
        return None
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
        logger.warning(f"Fallback scraping failed for {url}: {e}")
        return None


def extract_article_content(raw_url: str) -> ExtractionResult:
    clean_url = resolve_original_url(raw_url)
    host = (urlparse(clean_url).hostname or "").lower()
    protected_source = any(
        host == candidate or host.endswith(f".{candidate}")
        for candidate in _SKIP_FULL_TEXT_HOSTS
    )
    if protected_source or is_google_news_url(clean_url):
        logger.debug("Skipping full-text extraction for %s", clean_url)
        outcome = "skipped_protected" if protected_source else "skipped_unresolved"
        return ExtractionResult(clean_url, None, outcome)

    if not is_safe_url(clean_url):
        logger.warning("Full-text extraction blocked for unsafe URL %s", clean_url)
        return ExtractionResult(clean_url, None, "blocked")

    content = extract_with_trafilatura(clean_url)
    if content:
        logger.info(f"Extracted {len(content)} chars from {clean_url}")
        return ExtractionResult(clean_url, content, "succeeded")

    content = extract_with_fallback(clean_url)
    if content:
        logger.info(f"Extracted {len(content)} chars (fallback) from {clean_url}")
        return ExtractionResult(clean_url, content, "succeeded")

    logger.warning(f"No content extracted from {clean_url}")
    return ExtractionResult(clean_url, None, "failed")


def _inferred_outcome(clean_url: str, content: str | None) -> str:
    if content:
        return "succeeded"
    host = (urlparse(clean_url).hostname or "").lower()
    if any(host == value or host.endswith(f".{value}") for value in _SKIP_FULL_TEXT_HOSTS):
        return "skipped_protected"
    if is_google_news_url(clean_url):
        return "skipped_unresolved"
    return "failed"


def process_urls_in_parallel(url_list: list[str], max_threads: int = MAX_SCRAPER_THREADS) -> ScrapeResults:
    results = ScrapeResults()
    unique_urls = list(dict.fromkeys(url_list))

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_url = {
            executor.submit(extract_article_content, url): url
            for url in unique_urls
        }
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                extracted = future.result()
                clean_url, content = extracted
                results[url] = content
                results.outcomes[url] = getattr(
                    extracted, "outcome", _inferred_outcome(clean_url, content)
                )
                if clean_url != url:
                    results[clean_url] = content
            except Exception as exc:
                logger.error(f"Exception scraping {url}: {exc}")
                results[url] = None
                results.outcomes[url] = "failed"

    counts = results.outcome_counts
    logger.info(
        "Scraping complete: %d succeeded, %d failed, %d blocked, %d skipped of %d URLs",
        counts["succeeded"],
        counts["failed"],
        counts["blocked"],
        counts["skipped_protected"] + counts["skipped_unresolved"],
        len(unique_urls),
    )
    return results
