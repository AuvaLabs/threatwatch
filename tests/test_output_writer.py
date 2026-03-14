import json
import pytest
from datetime import datetime, timezone, timedelta

from modules.output_writer import _merge_articles
from modules.config import FEED_CUTOFF_DAYS


def _make_article(hash_val, days_ago=0):
    ts = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return {
        "hash": hash_val,
        "title": f"Article {hash_val}",
        "timestamp": ts.isoformat(),
    }


class TestMergeArticles:
    def test_new_articles_take_priority_in_ordering(self):
        existing = [_make_article("old", days_ago=1)]
        new = [_make_article("new")]
        merged = _merge_articles(existing, new)
        assert merged[0]["hash"] == "new"

    def test_deduplication_by_hash(self):
        existing = [_make_article("abc")]
        new = [_make_article("abc")]
        merged = _merge_articles(existing, new)
        assert len(merged) == 1

    def test_drops_articles_beyond_cutoff(self):
        old = _make_article("old", days_ago=FEED_CUTOFF_DAYS + 2)
        fresh = _make_article("fresh")
        merged = _merge_articles([old], [fresh])
        hashes = [a["hash"] for a in merged]
        assert "fresh" in hashes
        assert "old" not in hashes

    def test_keeps_articles_within_cutoff(self):
        recent = _make_article("recent", days_ago=FEED_CUTOFF_DAYS - 1)
        merged = _merge_articles([], [recent])
        assert len(merged) == 1

    def test_empty_inputs(self):
        assert _merge_articles([], []) == []

    def test_sorted_newest_first(self):
        a1 = _make_article("a1", days_ago=2)
        a2 = _make_article("a2", days_ago=0)
        merged = _merge_articles([a1], [a2])
        assert merged[0]["hash"] == "a2"

    def test_article_without_hash_is_excluded(self):
        # _merge_articles deduplicates by hash — articles without one are dropped
        article = {"title": "No hash", "timestamp": datetime.now(timezone.utc).isoformat()}
        merged = _merge_articles([], [article])
        assert len(merged) == 0

    def test_article_without_timestamp_is_kept(self):
        article = {"hash": "no-ts", "title": "No timestamp"}
        merged = _merge_articles([], [article])
        assert len(merged) == 1

    def test_no_duplicate_when_same_hash_in_both(self):
        article = _make_article("dup")
        merged = _merge_articles([article], [article])
        assert len(merged) == 1

    def test_preserves_all_fields(self):
        article = {
            "hash": "full",
            "title": "Full Article",
            "link": "https://example.com",
            "category": "Ransomware",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        merged = _merge_articles([], [article])
        assert merged[0]["category"] == "Ransomware"
        assert merged[0]["link"] == "https://example.com"
