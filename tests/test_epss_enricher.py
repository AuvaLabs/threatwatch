import pytest
from unittest.mock import patch, MagicMock

import modules.epss_enricher as epss
from modules.epss_enricher import (
    enrich_articles_with_epss,
    _extract_cve_ids,
    _epss_risk_label,
    _fetch_epss_batch,
    _get_session,
)


class TestExtractCveIds:
    def test_extracts_from_title(self):
        article = {"title": "Critical CVE-2026-12345 exploit in the wild"}
        assert _extract_cve_ids(article) == ["CVE-2026-12345"]

    def test_extracts_from_cve_id_field(self):
        article = {"title": "Some article", "cve_id": "CVE-2026-99999"}
        assert "CVE-2026-99999" in _extract_cve_ids(article)

    def test_extracts_multiple_cves(self):
        article = {"title": "CVE-2026-1111 and CVE-2026-2222 patched"}
        cves = _extract_cve_ids(article)
        assert len(cves) == 2
        assert "CVE-2026-1111" in cves
        assert "CVE-2026-2222" in cves

    def test_extracts_from_summary(self):
        article = {"title": "Patch available", "summary": "Fixes CVE-2026-54321"}
        assert "CVE-2026-54321" in _extract_cve_ids(article)

    def test_returns_empty_for_no_cves(self):
        article = {"title": "Ransomware attack on hospital"}
        assert _extract_cve_ids(article) == []


class TestEpssRiskLabel:
    def test_very_high(self):
        assert _epss_risk_label(0.6) == "VERY HIGH"

    def test_high(self):
        assert _epss_risk_label(0.15) == "HIGH"

    def test_moderate(self):
        assert _epss_risk_label(0.05) == "MODERATE"

    def test_low(self):
        assert _epss_risk_label(0.005) == "LOW"


class TestEnrichArticlesWithEpss:
    @patch("modules.epss_enricher._fetch_epss_batch")
    def test_enriches_articles_with_cves(self, mock_fetch):
        mock_fetch.return_value = {
            "CVE-2026-12345": {"epss_score": 0.85, "epss_percentile": 0.99},
        }
        articles = [
            {"title": "CVE-2026-12345 actively exploited", "summary": ""},
        ]
        result = enrich_articles_with_epss(articles)
        assert len(result) == 1
        assert result[0]["epss_max_score"] == 0.85
        assert result[0]["epss_risk"] == "VERY HIGH"
        assert len(result[0]["epss_scores"]) == 1

    @patch("modules.epss_enricher._fetch_epss_batch")
    def test_skips_articles_without_cves(self, mock_fetch):
        mock_fetch.return_value = {}
        articles = [{"title": "Ransomware hits hospital", "summary": ""}]
        result = enrich_articles_with_epss(articles)
        assert "epss_scores" not in result[0]

    @patch("modules.epss_enricher._fetch_epss_batch")
    def test_handles_multiple_cves_per_article(self, mock_fetch):
        mock_fetch.return_value = {
            "CVE-2026-1111": {"epss_score": 0.3, "epss_percentile": 0.8},
            "CVE-2026-2222": {"epss_score": 0.9, "epss_percentile": 0.99},
        }
        articles = [
            {"title": "CVE-2026-1111 and CVE-2026-2222 found", "summary": ""},
        ]
        result = enrich_articles_with_epss(articles)
        assert result[0]["epss_max_score"] == 0.9
        assert len(result[0]["epss_scores"]) == 2


class TestGetSession:
    def test_creates_session(self):
        epss._SESSION = None
        try:
            s = _get_session()
            assert s is not None
            assert "ThreatWatch" in s.headers.get("User-Agent", "")
        finally:
            epss._SESSION = None

    def test_reuses_session(self):
        epss._SESSION = None
        try:
            s1 = _get_session()
            s2 = _get_session()
            assert s1 is s2
        finally:
            epss._SESSION = None


class TestFetchEpssBatch:
    def test_empty_input(self):
        assert _fetch_epss_batch([]) == {}

    def test_successful_fetch(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": [{"cve": "CVE-2026-1234", "epss": "0.85", "percentile": "0.99"}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_session = MagicMock()
        mock_session.get.return_value = mock_resp
        epss._SESSION = mock_session
        try:
            result = _fetch_epss_batch(["CVE-2026-1234"])
        finally:
            epss._SESSION = None
        assert "CVE-2026-1234" in result
        assert result["CVE-2026-1234"]["epss_score"] == 0.85

    def test_api_error_returns_partial(self):
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("timeout")
        epss._SESSION = mock_session
        try:
            result = _fetch_epss_batch(["CVE-2026-1234"])
        finally:
            epss._SESSION = None
        assert result == {}

    def test_batches_large_input(self):
        """Over 100 CVEs should trigger multiple API calls."""
        cves = [f"CVE-2026-{i:04d}" for i in range(150)]
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": []}
        mock_resp.raise_for_status = MagicMock()
        mock_session = MagicMock()
        mock_session.get.return_value = mock_resp
        epss._SESSION = mock_session
        try:
            _fetch_epss_batch(cves)
            assert mock_session.get.call_count == 2  # 100 + 50
        finally:
            epss._SESSION = None


class TestEnrichArticlesEdgeCases:
    @patch("modules.epss_enricher._fetch_epss_batch")
    def test_cve_not_in_epss_data_passes_through(self, mock_fetch):
        mock_fetch.return_value = {}  # No EPSS data for this CVE
        articles = [{"title": "CVE-2026-9999 found", "summary": ""}]
        result = enrich_articles_with_epss(articles)
        assert "epss_scores" not in result[0]

    @patch("modules.epss_enricher._fetch_epss_batch")
    def test_mixed_articles_with_and_without_cves(self, mock_fetch):
        mock_fetch.return_value = {
            "CVE-2026-1111": {"epss_score": 0.5, "epss_percentile": 0.95},
        }
        articles = [
            {"title": "CVE-2026-1111 exploited", "summary": ""},
            {"title": "No CVE here", "summary": "General news"},
        ]
        result = enrich_articles_with_epss(articles)
        assert "epss_scores" in result[0]
        assert "epss_scores" not in result[1]
