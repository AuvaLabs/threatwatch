import re
from pathlib import Path

import yaml


CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "feeds_native.yaml"


def _native_feeds_by_url():
    feeds = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    return {feed["url"]: feed for feed in feeds}


def test_native_feed_urls_are_unique_and_current():
    feeds = list(_native_feeds_by_url().values())
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


def test_primary_security_source_expansion_is_configured():
    feeds = _native_feeds_by_url()
    expected = {
        "https://www.morphisec.com/blog/topic/threat-research/feed/": (
            "Morphisec Threat Labs",
            "Global",
        ),
        "https://aws.amazon.com/security/security-bulletins/rss/feed/": (
            "AWS Security Bulletins",
            "Global",
        ),
        "https://www.microsoft.com/en-us/security/blog/feed/": (
            "Microsoft Security Blog",
            "Global",
        ),
        "https://aws.amazon.com/blogs/security/feed/": (
            "AWS Security Blog",
            "Global",
        ),
    }

    for url, (name, region) in expected.items():
        assert feeds[url]["name"] == name
        assert feeds[url]["category"] == "Native"
        assert feeds[url]["region"] == region


def test_cert_poland_keeps_its_configured_region():
    feeds = _native_feeds_by_url()

    assert feeds["https://www.cert.pl/en/feed"]["region"] == "Poland"


def test_disabled_feed_blocks_do_not_leave_active_metadata():
    contents = CONFIG_PATH.read_text(encoding="utf-8")
    active_metadata_after_disabled_url = re.compile(
        r"^# - url:.*\n(?:(?:#.*|\s*)\n)*  (?:name|category|region|user_agent):",
        re.MULTILINE,
    )

    assert active_metadata_after_disabled_url.search(contents) is None
