"""Tests for the manual feed validation harness."""

from datetime import datetime, timedelta, timezone

from scripts.validate_feeds import publication_health


def test_publication_health_separates_feed_entries_from_collection_window():
    old = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    entries = [{"published": old}, {"published": "invalid"}]

    recent_count, latest_entry_at = publication_health(entries)

    assert recent_count == 0
    assert latest_entry_at == old


def test_publication_health_counts_recent_dated_entries():
    recent = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()

    recent_count, latest_entry_at = publication_health([{"published": recent}])

    assert recent_count == 1
    assert latest_entry_at == recent
