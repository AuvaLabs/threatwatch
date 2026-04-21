"""Tests for modules/db.py — SQLite persistence layer."""

import json
import pytest
from unittest.mock import patch

import modules.db as db


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path):
    """Each test gets a fresh SQLite database."""
    test_db = tmp_path / "test.db"
    db._conn = None
    with patch.object(db, "DB_PATH", test_db):
        yield
    db.close()


class TestUpsertArticles:
    def test_inserts_article(self):
        articles = [{"hash": "abc123", "title": "Test", "timestamp": "2026-04-21T00:00:00Z"}]
        count = db.upsert_articles(articles)
        assert count == 1

    def test_skips_article_without_hash(self):
        articles = [{"title": "No hash", "timestamp": "2026-04-21T00:00:00Z"}]
        count = db.upsert_articles(articles)
        assert count == 0

    def test_upsert_replaces_on_duplicate_hash(self):
        articles = [{"hash": "abc", "title": "Version 1", "timestamp": "2026-04-21"}]
        db.upsert_articles(articles)
        articles = [{"hash": "abc", "title": "Version 2", "timestamp": "2026-04-21"}]
        db.upsert_articles(articles)
        loaded = db.load_articles_from_db()
        assert len(loaded) == 1
        assert loaded[0]["title"] == "Version 2"

    def test_multiple_articles(self):
        articles = [
            {"hash": f"h{i}", "title": f"Article {i}", "timestamp": "2026-04-21"}
            for i in range(5)
        ]
        assert db.upsert_articles(articles) == 5


class TestLoadArticles:
    def test_load_empty_db(self):
        assert db.load_articles_from_db() == []

    def test_load_returns_newest_first(self):
        articles = [
            {"hash": "old", "title": "Old", "timestamp": "2026-04-01T00:00:00Z"},
            {"hash": "new", "title": "New", "timestamp": "2026-04-21T00:00:00Z"},
        ]
        db.upsert_articles(articles)
        loaded = db.load_articles_from_db()
        assert loaded[0]["title"] == "New"

    def test_load_with_since_filter(self):
        articles = [
            {"hash": "old", "title": "Old", "timestamp": "2026-04-01T00:00:00Z"},
            {"hash": "new", "title": "New", "timestamp": "2026-04-21T00:00:00Z"},
        ]
        db.upsert_articles(articles)
        loaded = db.load_articles_from_db(since_iso="2026-04-10T00:00:00Z")
        assert len(loaded) == 1
        assert loaded[0]["title"] == "New"

    def test_load_with_limit(self):
        articles = [
            {"hash": f"h{i}", "title": f"A{i}", "timestamp": f"2026-04-{10+i:02d}"}
            for i in range(10)
        ]
        db.upsert_articles(articles)
        loaded = db.load_articles_from_db(limit=3)
        assert len(loaded) == 3


class TestPrune:
    def test_prune_older_than(self):
        articles = [
            {"hash": "old", "title": "Old", "timestamp": "2026-03-01T00:00:00Z"},
            {"hash": "new", "title": "New", "timestamp": "2026-04-21T00:00:00Z"},
        ]
        db.upsert_articles(articles)
        pruned = db.prune_older_than("2026-04-01T00:00:00Z")
        assert pruned == 1
        remaining = db.load_articles_from_db()
        assert len(remaining) == 1
        assert remaining[0]["title"] == "New"


class TestUpsertCampaign:
    def test_inserts_campaign(self):
        campaign = {
            "campaign_id": "uuid1",
            "entity_type": "actor",
            "entity_name": "LockBit",
            "status": "active",
        }
        db.upsert_campaign(campaign)
        assert db.count_campaigns() == 1

    def test_skips_campaign_without_id(self):
        db.upsert_campaign({"entity_name": "Test"})
        assert db.count_campaigns() == 0

    def test_replaces_on_duplicate(self):
        db.upsert_campaign({"campaign_id": "x", "entity_type": "actor",
                           "entity_name": "Test", "status": "active"})
        db.upsert_campaign({"campaign_id": "x", "entity_type": "actor",
                           "entity_name": "Test", "status": "dormant"})
        assert db.count_campaigns() == 1


class TestStats:
    def test_stats_empty_db(self):
        s = db.stats()
        assert s["article_count"] == 0
        assert s["campaign_count"] == 0
        assert s["db_bytes"] > 0

    def test_stats_with_data(self):
        db.upsert_articles([{"hash": "h1", "title": "T", "timestamp": "now"}])
        db.upsert_campaign({"campaign_id": "c1", "entity_type": "a",
                           "entity_name": "N", "status": "active"})
        s = db.stats()
        assert s["article_count"] == 1
        assert s["campaign_count"] == 1


class TestCountHelpers:
    def test_count_articles(self):
        assert db.count_articles() == 0
        db.upsert_articles([{"hash": "h1", "title": "T", "timestamp": "now"}])
        assert db.count_articles() == 1

    def test_count_campaigns(self):
        assert db.count_campaigns() == 0


class TestClose:
    def test_close_and_reopen(self):
        db.upsert_articles([{"hash": "h1", "title": "T", "timestamp": "now"}])
        db.close()
        assert db._conn is None
        # Should auto-reopen on next operation
        assert db.count_articles() == 1

    def test_close_idempotent(self):
        db.close()
        db.close()  # Should not raise
