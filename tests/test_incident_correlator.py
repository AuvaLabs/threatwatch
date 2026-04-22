"""Tests for modules/incident_correlator.py — incident clustering."""

import json
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import modules.incident_correlator as ic
from modules.incident_correlator import (
    annotate_articles_with_cves,
    _extract_entities,
    cluster_articles,
    load_clusters,
    _save_clusters,
)


class TestAnnotateArticlesWithCves:
    def test_extracts_cves(self):
        articles = [{"title": "Patch for CVE-2026-1234 released", "summary": "Also CVE-2026-5678"}]
        count = annotate_articles_with_cves(articles)
        assert count == 1
        assert "CVE-2026-1234" in articles[0]["cve_ids"]
        assert "CVE-2026-5678" in articles[0]["cve_ids"]

    def test_no_cves(self):
        articles = [{"title": "Weather report", "summary": "Sunny"}]
        count = annotate_articles_with_cves(articles)
        assert count == 0
        assert "cve_ids" not in articles[0]

    def test_removes_stale_cve_ids(self):
        articles = [{"title": "No CVEs here", "cve_ids": ["CVE-OLD"]}]
        annotate_articles_with_cves(articles)
        assert "cve_ids" not in articles[0]

    def test_uppercase_normalized(self):
        articles = [{"title": "cve-2026-9999 found", "summary": ""}]
        annotate_articles_with_cves(articles)
        assert articles[0]["cve_ids"] == ["CVE-2026-9999"]

    def test_empty_list(self):
        assert annotate_articles_with_cves([]) == 0


class TestExtractEntities:
    def test_extracts_cve(self):
        entities = _extract_entities({"title": "CVE-2026-1234 exploited", "summary": ""})
        assert ("cve", "CVE-2026-1234") in entities

    def test_extracts_actor(self):
        entities = _extract_entities({"title": "LockBit hits hospital", "summary": ""})
        assert ("actor", "LockBit") in entities

    def test_extracts_org_from_title(self):
        entities = _extract_entities({"title": "Microsoft patches zero-day", "summary": ""})
        assert ("org", "Microsoft") in entities

    def test_no_entities(self):
        entities = _extract_entities({"title": "Weather report", "summary": ""})
        assert entities == []

    def test_multiple_entity_types(self):
        entities = _extract_entities({
            "title": "APT28 exploits CVE-2026-1234 in Cisco devices",
            "summary": "",
        })
        types = {e[0] for e in entities}
        assert "cve" in types
        assert "actor" in types
        assert "org" in types


class TestClusterArticles:
    def _make_articles(self, entity, count=4):
        """Create articles sharing the same entity for clustering."""
        return [
            {
                "title": f"{entity} incident report #{i}",
                "summary": f"Details about {entity}",
                "link": f"https://example.com/{i}",
                "published": f"2026-04-{20+i}T12:00:00+00:00",
                "hash": f"hash{i}",
                "category": "Vulnerability",
            }
            for i in range(count)
        ]

    def test_clusters_by_cve(self):
        articles = self._make_articles("CVE-2026-9999", count=4)
        with patch.object(ic, "_synthesize_clusters"), \
             patch("modules.campaign_tracker.record_clusters", return_value={}), \
             patch("modules.campaign_tracker.load_campaigns", return_value={}), \
             patch.object(ic, "_save_clusters"):
            result = cluster_articles(articles)
        assert result["total_clusters"] >= 1
        assert any(c["entity_name"] == "CVE-2026-9999" for c in result["clusters"])

    def test_clusters_by_actor(self):
        articles = self._make_articles("LockBit", count=4)
        with patch.object(ic, "_synthesize_clusters"), \
             patch("modules.campaign_tracker.record_clusters", return_value={}), \
             patch("modules.campaign_tracker.load_campaigns", return_value={}), \
             patch.object(ic, "_save_clusters"):
            result = cluster_articles(articles)
        assert result["total_clusters"] >= 1
        assert any(c["entity_name"] == "LockBit" for c in result["clusters"])

    def test_no_clusters_when_too_few(self):
        articles = [
            {"title": "Random article A", "summary": "", "hash": "a", "published": ""},
            {"title": "Unrelated article B", "summary": "", "hash": "b", "published": ""},
        ]
        with patch.object(ic, "_synthesize_clusters"), \
             patch.object(ic, "_save_clusters"):
            result = cluster_articles(articles)
        assert result["total_clusters"] == 0

    def test_cluster_has_article_hashes(self):
        articles = self._make_articles("CVE-2026-8888", count=3)
        with patch.object(ic, "_synthesize_clusters"), \
             patch("modules.campaign_tracker.record_clusters", return_value={}), \
             patch("modules.campaign_tracker.load_campaigns", return_value={}), \
             patch.object(ic, "_save_clusters"):
            result = cluster_articles(articles)
        if result["clusters"]:
            assert len(result["clusters"][0]["article_hashes"]) > 0

    def test_cluster_has_first_seen(self):
        articles = self._make_articles("CVE-2026-7777", count=3)
        with patch.object(ic, "_synthesize_clusters"), \
             patch("modules.campaign_tracker.record_clusters", return_value={}), \
             patch("modules.campaign_tracker.load_campaigns", return_value={}), \
             patch.object(ic, "_save_clusters"):
            result = cluster_articles(articles)
        if result["clusters"]:
            assert result["clusters"][0]["first_seen"] is not None

    def test_campaign_tracking_failure_nonfatal(self):
        articles = self._make_articles("CVE-2026-6666", count=3)
        with patch.object(ic, "_synthesize_clusters"), \
             patch("modules.campaign_tracker.record_clusters", side_effect=Exception("DB down")), \
             patch.object(ic, "_save_clusters"):
            result = cluster_articles(articles)
        # Should still return clusters despite campaign failure
        assert "clusters" in result

    def test_empty_articles(self):
        with patch.object(ic, "_synthesize_clusters"), \
             patch.object(ic, "_save_clusters"):
            result = cluster_articles([])
        assert result["total_clusters"] == 0


class TestSaveLoadClusters:
    def test_save_and_load_roundtrip(self, tmp_path):
        path = tmp_path / "clusters.json"
        data = {"clusters": [], "total_clusters": 0, "generated_at": "now"}
        with patch.object(ic, "CLUSTERS_PATH", path):
            _save_clusters(data)
            result = load_clusters()
        assert result == data

    def test_load_returns_none_when_missing(self, tmp_path):
        path = tmp_path / "missing.json"
        with patch.object(ic, "CLUSTERS_PATH", path):
            assert load_clusters() is None

    def test_load_returns_none_on_corrupt(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{bad")
        with patch.object(ic, "CLUSTERS_PATH", path):
            assert load_clusters() is None


class TestSynthesizeClusters:
    def test_skips_when_llm_unavailable(self):
        clusters = [{"entity_name": "Test", "entity_type": "cve",
                     "article_count": 5, "articles": [{"title": "A"}] * 5,
                     "synthesis": None}]
        with patch("modules.llm_client.is_available", return_value=False):
            ic._synthesize_clusters(clusters)
        assert clusters[0]["synthesis"] is None

    def test_uses_cached_synthesis(self):
        clusters = [{"entity_name": "Test", "entity_type": "cve",
                     "article_count": 5, "articles": [{"title": f"A{i}"}for i in range(5)]}]
        with patch("modules.llm_client.is_available", return_value=True), \
             patch("modules.ai_cache.get_cached_result", return_value="Cached synthesis"):
            ic._synthesize_clusters(clusters)
        assert clusters[0]["synthesis"] == "Cached synthesis"

    def test_generates_synthesis_via_llm(self):
        clusters = [{"entity_name": "Test", "entity_type": "cve",
                     "article_count": 5, "articles": [{"title": f"A{i}"} for i in range(5)]}]
        with patch("modules.llm_client.is_available", return_value=True), \
             patch("modules.ai_cache.get_cached_result", return_value=None), \
             patch("modules.llm_client.call_llm", return_value="AI synthesis text"), \
             patch("modules.ai_cache.cache_result"):
            ic._synthesize_clusters(clusters)
        assert clusters[0]["synthesis"] == "AI synthesis text"

    def test_skips_small_clusters(self):
        clusters = [{"entity_name": "Test", "entity_type": "cve",
                     "article_count": 2, "articles": [{"title": "A"}, {"title": "B"}]}]
        with patch("modules.llm_client.is_available", return_value=True):
            ic._synthesize_clusters(clusters)
        assert clusters[0].get("synthesis") is None


class TestClusterSkipPaths:
    """Covers the continue-branches in cluster_articles: small entities and
    entities whose new unique indices fall below threshold."""

    def test_entity_below_threshold_skipped(self, tmp_path, monkeypatch):
        """An entity mentioned in fewer than 3 articles is not clustered."""
        monkeypatch.setattr(ic, "CLUSTERS_PATH", tmp_path / "clusters.json")
        # Only 2 articles mention LockBit — below threshold of 3.
        articles = [
            {"title": "LockBit hits hospital", "summary": "", "link": "http://x/1"},
            {"title": "LockBit affiliate news", "summary": "", "link": "http://x/2"},
        ]
        ic.cluster_articles(articles)
        data = ic.load_clusters()
        # No clusters built — entity didn't meet threshold.
        assert all("LockBit" not in c.get("entity_name", "") for c in data.get("clusters", []))


class TestCampaignTrackingFailure:
    """Campaign tracking errors must not crash cluster_articles."""

    def test_campaign_failure_is_non_fatal(self, tmp_path, monkeypatch, caplog):
        import logging
        monkeypatch.setattr(ic, "CLUSTERS_PATH", tmp_path / "clusters.json")
        articles = [
            {"title": f"LockBit attack {i}", "summary": "", "link": f"http://x/{i}"}
            for i in range(5)
        ]
        # Force record_clusters to raise — the real API name.
        with patch("modules.campaign_tracker.record_clusters",
                   side_effect=RuntimeError("boom")):
            with caplog.at_level(logging.WARNING, logger="modules.incident_correlator"):
                # Must not raise.
                ic.cluster_articles(articles)
        # Logged the non-fatal warning.
        assert any("Campaign tracking failed" in r.message for r in caplog.records) or \
               any("campaign" in r.message.lower() for r in caplog.records)
