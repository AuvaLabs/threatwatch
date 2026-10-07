from pathlib import Path

import yaml


CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "feeds_native.yaml"


def test_native_feed_urls_are_unique_and_current():
    feeds = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    urls = [feed["url"] for feed in feeds]
    retired = {
        "https://www.sentinelone.com/feed/",
        "https://www.mandiant.com/resources/blog/rss.xml",
        "https://threatconnect.com/blog/feed/",
        "https://www.cybereason.com/blog/rss.xml",
    }

    assert len(urls) == len(set(urls))
    assert retired.isdisjoint(urls)
    assert "https://research.intezer.com/index.xml" in urls
    assert "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml" in urls
    assert "https://www.volexity.com/feed/" in urls
