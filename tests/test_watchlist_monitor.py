"""Tests for modules/watchlist_monitor.py"""
import json
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.watchlist_monitor import (
    FLAT_VENDOR_LIST,
    VENDOR_SUGGEST_LIST,
    load_custom_watchlist,
    save_watchlist,
    tag_article_with_vendors,
    tag_articles_with_vendors,
    run_watchlist_monitor,
    _fetch_gnews,
)


# ── Suggest-list integrity ────────────────────────────────────────────────────

class TestVendorSuggestList:
    def test_has_multiple_categories(self):
        assert len(VENDOR_SUGGEST_LIST) >= 10

    def test_flat_list_not_empty(self):
        assert len(FLAT_VENDOR_LIST) >= 100

    def test_flat_list_no_duplicates(self):
        assert len(FLAT_VENDOR_LIST) == len(set(FLAT_VENDOR_LIST))

    def test_known_vendors_present(self):
        for vendor in ["CrowdStrike", "Cisco", "VMware", "Okta", "Intel", "Siemens"]:
            assert vendor in FLAT_VENDOR_LIST, f"{vendor} missing from suggest list"

    def test_all_categories_non_empty(self):
        for cat, vendors in VENDOR_SUGGEST_LIST.items():
            assert len(vendors) > 0, f"Category '{cat}' is empty"


# ── Article tagging ───────────────────────────────────────────────────────────

class TestTagArticleWithVendors:
    def _article(self, title="", summary=""):
        return {"title": title, "summary": summary, "hash": "abc"}

    def test_tags_known_vendor_in_title(self):
        art = self._article(title="CrowdStrike reports breach in customer data")
        result = tag_article_with_vendors(art)
        assert "CrowdStrike" in result["asset_tags"]

    def test_tags_multiple_vendors(self):
        art = self._article(title="Cisco and Fortinet both patched critical flaws")
        result = tag_article_with_vendors(art)
        tags = result["asset_tags"]
        assert "Cisco" in tags
        assert "Fortinet" in tags

    def test_no_tags_when_no_match(self):
        art = self._article(title="Weather update for the weekend")
        result = tag_article_with_vendors(art)
        assert "asset_tags" not in result

    def test_original_article_not_mutated(self):
        art = self._article(title="CrowdStrike incident")
        original_keys = set(art.keys())
        tag_article_with_vendors(art)
        assert set(art.keys()) == original_keys

    def test_case_insensitive_match(self):
        art = self._article(title="crowdstrike outage affects customers")
        result = tag_article_with_vendors(art)
        assert "CrowdStrike" in result.get("asset_tags", [])

    def test_tags_from_summary(self):
        art = self._article(title="Security incident reported", summary="VMware vCenter vulnerability exploited")
        result = tag_article_with_vendors(art)
        assert "VMware" in result["asset_tags"]

    def test_no_partial_word_match(self):
        # "AWS" should not match "COAWS" or "LAWSON"
        art = self._article(title="LAWSON software update released")
        result = tag_article_with_vendors(art)
        assert "AWS" not in result.get("asset_tags", [])

    def test_batch_tag_articles(self):
        articles = [
            self._article(title="CrowdStrike breach"),
            self._article(title="Weather report"),
            self._article(title="Cisco vuln patched"),
        ]
        results = tag_articles_with_vendors(articles)
        assert len(results) == 3
        assert "CrowdStrike" in results[0]["asset_tags"]
        assert "asset_tags" not in results[1]
        assert "Cisco" in results[2]["asset_tags"]


# ── Watchlist persistence ─────────────────────────────────────────────────────

class TestWatchlistPersistence:
    def test_load_returns_empty_when_missing(self, tmp_path):
        with patch("modules.watchlist_monitor.WATCHLIST_PATH", tmp_path / "watchlist.json"):
            result = load_custom_watchlist()
        assert result == {"brands": [], "assets": []}

    def test_save_and_load_roundtrip(self, tmp_path):
        wpath = tmp_path / "watchlist.json"
        with patch("modules.watchlist_monitor.WATCHLIST_PATH", wpath):
            save_watchlist(["AcmeCorp", "MyOrg"], ["CustomVendor"])
            result = load_custom_watchlist()
        assert result["brands"] == ["AcmeCorp", "MyOrg"]
        assert result["assets"] == ["CustomVendor"]

    def test_save_strips_empty_strings(self, tmp_path):
        wpath = tmp_path / "watchlist.json"
        with patch("modules.watchlist_monitor.WATCHLIST_PATH", wpath):
            save_watchlist(["Acme", "", "  "], ["Valid"])
            result = load_custom_watchlist()
        assert "" not in result["brands"]
        assert "Acme" in result["brands"]

    def test_load_handles_corrupt_json(self, tmp_path):
        wpath = tmp_path / "watchlist.json"
        wpath.write_text("not json")
        with patch("modules.watchlist_monitor.WATCHLIST_PATH", wpath):
            result = load_custom_watchlist()
        assert result == {"brands": [], "assets": []}

    def test_save_creates_parent_dirs(self, tmp_path):
        wpath = tmp_path / "nested" / "dir" / "watchlist.json"
        with patch("modules.watchlist_monitor.WATCHLIST_PATH", wpath):
            save_watchlist(["Brand"], [])
        assert wpath.exists()


# ── run_watchlist_monitor ─────────────────────────────────────────────────────

class TestRunWatchlistMonitor:
    def test_returns_empty_when_no_custom_keywords(self, tmp_path):
        wpath = tmp_path / "watchlist.json"
        with patch("modules.watchlist_monitor.WATCHLIST_PATH", wpath):
            result = run_watchlist_monitor()
        assert result == []

    def test_fetches_for_each_brand(self, tmp_path):
        wpath = tmp_path / "watchlist.json"
        wpath.write_text(json.dumps({"brands": ["AcmeCorp", "MyOrg"], "assets": []}))
        mock_articles = [{"title": "Test", "link": "https://example.com", "hash": "abc",
                          "published": "", "summary": "", "source": "watchlist:gnews"}]
        with patch("modules.watchlist_monitor.WATCHLIST_PATH", wpath), \
             patch("modules.watchlist_monitor._fetch_gnews", return_value=mock_articles) as mock_fetch, \
             patch("modules.watchlist_monitor.time.sleep"):
            result = run_watchlist_monitor()
        assert mock_fetch.call_count == 2
        assert all("brand_tags" in a for a in result)

    def test_fetches_for_each_asset(self, tmp_path):
        wpath = tmp_path / "watchlist.json"
        wpath.write_text(json.dumps({"brands": [], "assets": ["CustomTech"]}))
        mock_articles = [{"title": "Test", "link": "https://x.com", "hash": "xyz",
                          "published": "", "summary": "", "source": "watchlist:gnews"}]
        with patch("modules.watchlist_monitor.WATCHLIST_PATH", wpath), \
             patch("modules.watchlist_monitor._fetch_gnews", return_value=mock_articles) as mock_fetch, \
             patch("modules.watchlist_monitor.time.sleep"):
            result = run_watchlist_monitor()
        assert mock_fetch.call_count == 1
        assert result[0]["asset_tags"] == ["CustomTech"]
