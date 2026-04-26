import json
from unittest.mock import MagicMock, patch

import pytest

import modules.kev_enricher as kev_module
from modules.kev_enricher import (
    _extract_cve_ids,
    enrich_articles_with_kev,
    fetch_kev_catalog,
)


SAMPLE_CATALOG = {
    "CVE-2026-3844": {
        "cve_id": "CVE-2026-3844",
        "vendor": "Breeze Cache",
        "product": "Breeze Cache WordPress Plugin",
        "vulnerability_name": "Breeze Cache Unauthenticated File Upload",
        "date_added": "2026-04-25",
        "due_date": "2026-05-16",
        "required_action": "Apply mitigations or discontinue use.",
        "ransomware_use": "Known",
    },
    "CVE-2026-1111": {
        "cve_id": "CVE-2026-1111",
        "vendor": "Acme",
        "product": "Acme Router",
        "vulnerability_name": "Acme Router Auth Bypass",
        "date_added": "2026-04-10",
        "due_date": "2026-05-01",
        "required_action": "Patch.",
        "ransomware_use": "Unknown",
    },
}


class TestExtractCveIds:
    def test_extracts_from_title(self):
        article = {"title": "Active exploitation of CVE-2026-3844 reported"}
        assert _extract_cve_ids(article) == ["CVE-2026-3844"]

    def test_extracts_from_cve_id_field(self):
        article = {"title": "patch", "cve_id": "cve-2026-1111"}
        assert "CVE-2026-1111" in _extract_cve_ids(article)

    def test_extracts_from_cve_ids_list(self):
        article = {"title": "x", "cve_ids": ["CVE-2026-2222", "cve-2026-3333"]}
        cves = _extract_cve_ids(article)
        assert "CVE-2026-2222" in cves
        assert "CVE-2026-3333" in cves

    def test_dedupes_across_sources(self):
        article = {
            "title": "CVE-2026-3844 in the wild",
            "cve_id": "cve-2026-3844",
            "summary": "another mention of CVE-2026-3844",
        }
        assert _extract_cve_ids(article) == ["CVE-2026-3844"]

    def test_returns_empty_for_no_cves(self):
        assert _extract_cve_ids({"title": "Ransomware hits hospital"}) == []


class TestEnrichArticlesWithKev:
    def test_flags_kev_listed_article(self):
        articles = [{"title": "CVE-2026-3844 active", "id": "a1"}]
        result = enrich_articles_with_kev(articles, catalog=SAMPLE_CATALOG)
        assert result[0]["kev_listed"] is True
        assert result[0]["kev_min_date_added"] == "2026-04-25"
        assert result[0]["kev_ransomware_use"] == "Known"
        assert len(result[0]["kev_entries"]) == 1
        assert result[0]["kev_entries"][0]["vendor"] == "Breeze Cache"

    def test_does_not_touch_unflagged_article(self):
        articles = [{"title": "CVE-2099-9999 disclosed", "id": "a1"}]
        result = enrich_articles_with_kev(articles, catalog=SAMPLE_CATALOG)
        assert "kev_listed" not in result[0]

    def test_handles_article_with_no_cves(self):
        articles = [{"title": "Ransomware tactics evolving"}]
        result = enrich_articles_with_kev(articles, catalog=SAMPLE_CATALOG)
        assert "kev_listed" not in result[0]

    def test_picks_earliest_date_added_when_multiple_kev_cves(self):
        articles = [{"title": "Both CVE-2026-3844 and CVE-2026-1111 affect us"}]
        result = enrich_articles_with_kev(articles, catalog=SAMPLE_CATALOG)
        assert result[0]["kev_listed"] is True
        # 2026-04-10 is earlier than 2026-04-25 (lexicographic ISO sort works)
        assert result[0]["kev_min_date_added"] == "2026-04-10"
        assert len(result[0]["kev_entries"]) == 2

    def test_ransomware_use_is_known_if_any_matched_cve_is_known(self):
        articles = [{"title": "CVE-2026-3844 and CVE-2026-1111"}]
        result = enrich_articles_with_kev(articles, catalog=SAMPLE_CATALOG)
        assert result[0]["kev_ransomware_use"] == "Known"

    def test_empty_catalog_returns_articles_unchanged(self):
        articles = [{"title": "CVE-2026-3844"}]
        result = enrich_articles_with_kev(articles, catalog={})
        assert result == articles

    def test_preserves_immutability(self):
        original = {"title": "CVE-2026-3844", "id": "a1"}
        result = enrich_articles_with_kev([original], catalog=SAMPLE_CATALOG)
        assert "kev_listed" not in original  # original not mutated
        assert result[0]["kev_listed"] is True

    def test_preserves_article_order_and_count(self):
        articles = [
            {"title": "CVE-2026-3844 hit"},
            {"title": "Ransomware update"},
            {"title": "CVE-2026-1111 disclosed"},
        ]
        result = enrich_articles_with_kev(articles, catalog=SAMPLE_CATALOG)
        assert len(result) == 3
        assert result[0].get("kev_listed") is True
        assert "kev_listed" not in result[1]
        assert result[2].get("kev_listed") is True


class TestFetchKevCatalog:
    def _mock_response(self, payload):
        m = MagicMock()
        m.json.return_value = payload
        m.raise_for_status = MagicMock()
        return m

    def test_indexes_by_cve_id_uppercase(self, tmp_path, monkeypatch):
        monkeypatch.setattr(kev_module, "KEV_CACHE_PATH", tmp_path / "kev_catalog.json")
        feed = {
            "vulnerabilities": [
                {
                    "cveID": "cve-2026-3844",
                    "vendorProject": "Breeze Cache",
                    "product": "Breeze Cache",
                    "vulnerabilityName": "Auth bypass",
                    "dateAdded": "2026-04-25",
                    "dueDate": "2026-05-16",
                    "requiredAction": "Apply patch.",
                    "knownRansomwareCampaignUse": "Known",
                },
            ],
        }
        with patch.object(kev_module, "_get_session") as gs:
            gs.return_value.get.return_value = self._mock_response(feed)
            catalog = fetch_kev_catalog(force_refresh=True)
        assert "CVE-2026-3844" in catalog
        assert catalog["CVE-2026-3844"]["vendor"] == "Breeze Cache"
        assert catalog["CVE-2026-3844"]["ransomware_use"] == "Known"

    def test_skips_entries_with_no_cve_id(self, tmp_path, monkeypatch):
        monkeypatch.setattr(kev_module, "KEV_CACHE_PATH", tmp_path / "kev_catalog.json")
        feed = {"vulnerabilities": [{"vendorProject": "x"}, {"cveID": "CVE-2026-1"}]}
        with patch.object(kev_module, "_get_session") as gs:
            gs.return_value.get.return_value = self._mock_response(feed)
            catalog = fetch_kev_catalog(force_refresh=True)
        assert len(catalog) == 1
        assert "CVE-2026-1" in catalog

    def test_falls_back_to_cache_on_network_error(self, tmp_path, monkeypatch):
        cache_path = tmp_path / "kev_catalog.json"
        monkeypatch.setattr(kev_module, "KEV_CACHE_PATH", cache_path)
        cached = {"CVE-2024-1234": {"cve_id": "CVE-2024-1234", "vendor": "x"}}
        cache_path.write_text(json.dumps(cached))

        with patch.object(kev_module, "_get_session") as gs:
            gs.return_value.get.side_effect = RuntimeError("network down")
            catalog = fetch_kev_catalog(force_refresh=True)
        assert catalog == cached

    def test_returns_empty_when_no_cache_and_network_fails(self, tmp_path, monkeypatch):
        monkeypatch.setattr(kev_module, "KEV_CACHE_PATH", tmp_path / "missing.json")
        with patch.object(kev_module, "_get_session") as gs:
            gs.return_value.get.side_effect = RuntimeError("network down")
            catalog = fetch_kev_catalog(force_refresh=True)
        assert catalog == {}

    def test_uses_fresh_cache_without_network_call(self, tmp_path, monkeypatch):
        cache_path = tmp_path / "kev_catalog.json"
        monkeypatch.setattr(kev_module, "KEV_CACHE_PATH", cache_path)
        cache_path.write_text(json.dumps({"CVE-2024-1": {"cve_id": "CVE-2024-1"}}))

        with patch.object(kev_module, "_get_session") as gs:
            catalog = fetch_kev_catalog(force_refresh=False)
        gs.assert_not_called()
        assert "CVE-2024-1" in catalog
