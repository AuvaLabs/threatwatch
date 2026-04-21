"""Tests for modules/campaign_tracker.py — campaign persistence."""

import json
import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import modules.campaign_tracker as ct
from modules.campaign_tracker import (
    load_campaigns, save_campaigns, record_clusters,
    get_campaign, list_campaigns,
    _cluster_key, _status_for_age,
)


class TestClusterKey:
    def test_composite_key(self):
        assert _cluster_key("actor", "LockBit") == "actor:LockBit"

    def test_cve_key(self):
        assert _cluster_key("cve", "CVE-2026-1234") == "cve:CVE-2026-1234"


class TestStatusForAge:
    def test_active(self):
        recent = datetime.now(timezone.utc) - timedelta(days=3)
        assert _status_for_age(recent) == "active"

    def test_dormant(self):
        old = datetime.now(timezone.utc) - timedelta(days=30)
        assert _status_for_age(old) == "dormant"

    def test_archived(self):
        ancient = datetime.now(timezone.utc) - timedelta(days=120)
        assert _status_for_age(ancient) == "archived"

    def test_none_returns_unknown(self):
        assert _status_for_age(None) == "unknown"

    def test_boundary_active(self):
        at_boundary = datetime.now(timezone.utc) - timedelta(days=14)
        assert _status_for_age(at_boundary) == "active"


class TestLoadSaveCampaigns:
    def test_load_returns_empty_when_missing(self, tmp_path):
        path = tmp_path / "campaigns.json"
        with patch.object(ct, "CAMPAIGNS_PATH", path):
            assert load_campaigns() == {}

    def test_load_returns_empty_on_corrupt(self, tmp_path):
        path = tmp_path / "campaigns.json"
        path.write_text("{bad")
        with patch.object(ct, "CAMPAIGNS_PATH", path):
            assert load_campaigns() == {}

    def test_save_and_load_roundtrip(self, tmp_path):
        path = tmp_path / "campaigns.json"
        data = {"id1": {"campaign_id": "id1", "entity_type": "actor", "entity_name": "Test"}}
        with patch.object(ct, "CAMPAIGNS_PATH", path):
            save_campaigns(data)
            result = load_campaigns()
        assert result == data

    def test_load_legacy_list_format(self, tmp_path):
        path = tmp_path / "campaigns.json"
        legacy = [{"campaign_id": "abc", "entity_type": "actor", "entity_name": "Test"}]
        path.write_text(json.dumps(legacy))
        with patch.object(ct, "CAMPAIGNS_PATH", path):
            result = load_campaigns()
        assert "abc" in result

    def test_save_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "deep" / "dir" / "campaigns.json"
        with patch.object(ct, "CAMPAIGNS_PATH", path):
            save_campaigns({"test": {}})
        assert path.exists()


class TestRecordClusters:
    def test_creates_new_campaign(self, tmp_path):
        path = tmp_path / "campaigns.json"
        with patch.object(ct, "CAMPAIGNS_PATH", path), \
             patch("modules.campaign_tracker.upsert_campaign", create=True, side_effect=Exception("no db")):
            clusters = [{"entity_type": "actor", "entity_name": "LockBit",
                        "first_seen": "2026-04-01T00:00:00+00:00",
                        "article_hashes": ["h1", "h2"], "article_count": 2}]
            mapping = record_clusters(clusters)
        assert "actor:LockBit" in mapping
        campaigns = load_campaigns() if path.exists() else {}
        # Verify campaign was persisted
        with patch.object(ct, "CAMPAIGNS_PATH", path):
            campaigns = load_campaigns()
        assert len(campaigns) == 1
        c = list(campaigns.values())[0]
        assert c["entity_name"] == "LockBit"
        assert c["status"] == "active"

    def test_updates_existing_campaign(self, tmp_path):
        path = tmp_path / "campaigns.json"
        existing = {
            "old-id": {
                "campaign_id": "old-id",
                "entity_type": "actor",
                "entity_name": "LockBit",
                "first_observed": "2026-01-01T00:00:00+00:00",
                "last_observed": "2026-03-01T00:00:00+00:00",
                "total_observed_articles": 5,
                "article_hashes": ["h1"],
                "status": "active",
                "created_at": "2026-01-01",
                "updated_at": "2026-03-01",
            }
        }
        path.write_text(json.dumps(existing))
        with patch.object(ct, "CAMPAIGNS_PATH", path), \
             patch("modules.campaign_tracker.upsert_campaign", create=True, side_effect=Exception("no db")):
            clusters = [{"entity_type": "actor", "entity_name": "LockBit",
                        "first_seen": "2026-04-01T00:00:00+00:00",
                        "article_hashes": ["h2", "h3"], "article_count": 2}]
            mapping = record_clusters(clusters)
        assert mapping["actor:LockBit"] == "old-id"
        with patch.object(ct, "CAMPAIGNS_PATH", path):
            updated = load_campaigns()
        c = updated["old-id"]
        assert c["first_observed"] == "2026-01-01T00:00:00+00:00"  # Never rolls forward
        assert "h2" in c["article_hashes"]

    def test_skips_clusters_without_entity(self, tmp_path):
        path = tmp_path / "campaigns.json"
        with patch.object(ct, "CAMPAIGNS_PATH", path), \
             patch("modules.campaign_tracker.upsert_campaign", create=True, side_effect=Exception("no db")):
            clusters = [{"entity_type": "", "entity_name": ""}]
            mapping = record_clusters(clusters)
        assert mapping == {}

    def test_dormant_campaigns_aged(self, tmp_path):
        path = tmp_path / "campaigns.json"
        old = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        existing = {
            "old-id": {
                "campaign_id": "old-id",
                "entity_type": "actor",
                "entity_name": "OldActor",
                "first_observed": old,
                "last_observed": old,
                "total_observed_articles": 1,
                "article_hashes": [],
                "status": "active",
            }
        }
        path.write_text(json.dumps(existing))
        with patch.object(ct, "CAMPAIGNS_PATH", path), \
             patch("modules.campaign_tracker.upsert_campaign", create=True, side_effect=Exception("no db")):
            # Record a different cluster — OldActor not in this batch
            mapping = record_clusters([{"entity_type": "actor", "entity_name": "NewActor",
                                       "article_hashes": ["x"], "article_count": 1}])
        with patch.object(ct, "CAMPAIGNS_PATH", path):
            campaigns = load_campaigns()
        assert campaigns["old-id"]["status"] == "dormant"


class TestGetAndListCampaigns:
    def test_get_campaign(self, tmp_path):
        path = tmp_path / "campaigns.json"
        data = {"id1": {"campaign_id": "id1", "entity_name": "Test"}}
        path.write_text(json.dumps(data))
        with patch.object(ct, "CAMPAIGNS_PATH", path):
            assert get_campaign("id1")["entity_name"] == "Test"
            assert get_campaign("nonexistent") is None

    def test_list_campaigns_all(self, tmp_path):
        path = tmp_path / "campaigns.json"
        data = {
            "a": {"campaign_id": "a", "status": "active", "updated_at": "2026-04-01"},
            "b": {"campaign_id": "b", "status": "dormant", "updated_at": "2026-03-01"},
        }
        path.write_text(json.dumps(data))
        with patch.object(ct, "CAMPAIGNS_PATH", path):
            result = list_campaigns()
        assert len(result) == 2
        assert result[0]["campaign_id"] == "a"  # Most recent first

    def test_list_campaigns_filtered(self, tmp_path):
        path = tmp_path / "campaigns.json"
        data = {
            "a": {"campaign_id": "a", "status": "active", "updated_at": "2026-04-01"},
            "b": {"campaign_id": "b", "status": "dormant", "updated_at": "2026-03-01"},
        }
        path.write_text(json.dumps(data))
        with patch.object(ct, "CAMPAIGNS_PATH", path):
            result = list_campaigns(status="active")
        assert len(result) == 1
        assert result[0]["status"] == "active"
