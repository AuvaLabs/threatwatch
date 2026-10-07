"""Corpus repair harness tests."""

from datetime import datetime, timedelta, timezone

from scripts.repair_corpus import repair_articles


def test_repair_normalizes_and_removes_future_and_duplicate_articles():
    now = datetime.now(timezone.utc).isoformat()
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    articles = [
        {"hash": "one", "title": "One", "link": "https://example.com/a",
         "source": "https://feeds.example.com/rss", "published": now},
        {"hash": "two", "title": "Duplicate", "link": "https://example.com/a",
         "source": "https://feeds.example.com/rss", "published": now},
        {"hash": "future", "title": "Future", "link": "https://example.com/future",
         "source": "https://feeds.example.com/rss", "published": future},
    ]

    repaired = repair_articles(articles)

    assert len(repaired) == 1
    assert repaired[0]["source_name"] == "Example"
    assert repaired[0]["canonical_url"] == "https://example.com/a"
