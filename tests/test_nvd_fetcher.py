import json
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

import modules.nvd_fetcher as nvd
from modules.nvd_fetcher import (
    fetch_nvd_cves, _cvss_score, _severity_label,
    _load_state, _save_state, _should_fetch, _get_session,
)


class TestCvssScore:
    def test_extracts_v31_score(self):
        vuln = {
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N"}
                }]
            }
        }
        score, vector = _cvss_score(vuln)
        assert score == 9.8
        assert "CVSS:3.1" in vector

    def test_falls_back_to_v30(self):
        vuln = {
            "metrics": {
                "cvssMetricV30": [{
                    "cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.0/AV:N"}
                }]
            }
        }
        score, _ = _cvss_score(vuln)
        assert score == 7.5

    def test_falls_back_to_v2(self):
        vuln = {
            "metrics": {
                "cvssMetricV2": [{
                    "cvssData": {"baseScore": 10.0, "vectorString": "AV:N/AC:L"}
                }]
            }
        }
        score, _ = _cvss_score(vuln)
        assert score == 10.0

    def test_returns_zero_for_empty_metrics(self):
        score, vector = _cvss_score({"metrics": {}})
        assert score == 0.0
        assert vector == ""


class TestSeverityLabel:
    def test_critical(self):
        assert _severity_label(9.5) == "CRITICAL"

    def test_high(self):
        assert _severity_label(7.5) == "HIGH"

    def test_medium(self):
        assert _severity_label(5.0) == "MEDIUM"

    def test_low(self):
        assert _severity_label(2.0) == "LOW"


class TestFetchNvdCves:
    @patch("modules.nvd_fetcher._should_fetch", return_value=True)
    @patch("modules.nvd_fetcher._save_state")
    @patch("modules.nvd_fetcher._get_session")
    def test_fetches_and_parses_cves(self, mock_session, mock_save, mock_should):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-12345",
                    "published": "2026-04-01T12:00:00Z",
                    "descriptions": [{"lang": "en", "value": "Remote code execution in FooBar"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L"}
                        }]
                    },
                    "configurations": [],
                    "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                    "references": [{"url": "https://example.com/advisory"}],
                }
            }]
        }
        mock_session.return_value.get.return_value = mock_resp

        articles = fetch_nvd_cves()
        assert len(articles) == 1
        assert articles[0]["cve_id"] == "CVE-2026-12345"
        assert articles[0]["cvss_score"] == 9.8
        assert articles[0]["cvss_severity"] == "CRITICAL"
        assert articles[0]["source"] == "nvd:cve"
        assert "CWE-79" in articles[0]["cwe_ids"]

    @patch("modules.nvd_fetcher._should_fetch", return_value=False)
    def test_respects_rate_limit(self, mock_should):
        articles = fetch_nvd_cves()
        assert articles == []

    @patch("modules.nvd_fetcher._should_fetch", return_value=True)
    @patch("modules.nvd_fetcher._get_session")
    def test_handles_api_error_gracefully(self, mock_session, mock_should):
        mock_session.return_value.get.side_effect = Exception("Connection refused")
        articles = fetch_nvd_cves()
        assert articles == []

    @patch("modules.nvd_fetcher._should_fetch", return_value=True)
    @patch("modules.nvd_fetcher._save_state")
    @patch("modules.nvd_fetcher._get_session")
    def test_filters_below_min_cvss(self, mock_session, mock_save, mock_should):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2026-99999",
                    "published": "2026-04-01T12:00:00Z",
                    "descriptions": [{"lang": "en", "value": "Low severity issue"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 3.0, "vectorString": "CVSS:3.1/AV:L"}
                        }]
                    },
                    "configurations": [],
                    "weaknesses": [],
                    "references": [],
                }
            }]
        }
        mock_session.return_value.get.return_value = mock_resp
        articles = fetch_nvd_cves()
        assert len(articles) == 0  # Below _MIN_CVSS_SCORE


class TestStateManagement:
    def test_load_returns_empty_when_missing(self, tmp_path):
        path = tmp_path / "state" / "nvd_last_fetch.json"
        with patch.object(nvd, "NVD_STATE_FILE", path):
            assert _load_state() == {}

    def test_load_returns_empty_on_corrupt(self, tmp_path):
        path = tmp_path / "nvd_last_fetch.json"
        path.write_text("{bad json")
        with patch.object(nvd, "NVD_STATE_FILE", path):
            assert _load_state() == {}

    def test_save_and_load_roundtrip(self, tmp_path):
        path = tmp_path / "nvd_last_fetch.json"
        state = {"last_fetch_utc": "2026-04-21T12:00:00+00:00"}
        with patch.object(nvd, "NVD_STATE_FILE", path):
            _save_state(state)
            assert _load_state() == state

    def test_save_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "deep" / "dir" / "state.json"
        with patch.object(nvd, "NVD_STATE_FILE", path):
            _save_state({"test": True})
        assert path.exists()


class TestShouldFetch:
    def test_true_when_no_state(self, tmp_path):
        path = tmp_path / "missing.json"
        with patch.object(nvd, "NVD_STATE_FILE", path):
            assert _should_fetch() is True

    def test_true_when_old(self, tmp_path):
        path = tmp_path / "state.json"
        old_time = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
        path.write_text(json.dumps({"last_fetch_utc": old_time}))
        with patch.object(nvd, "NVD_STATE_FILE", path):
            assert _should_fetch() is True

    def test_false_when_recent(self, tmp_path):
        path = tmp_path / "state.json"
        recent = datetime.now(timezone.utc).isoformat()
        path.write_text(json.dumps({"last_fetch_utc": recent}))
        with patch.object(nvd, "NVD_STATE_FILE", path):
            assert _should_fetch() is False

    def test_true_on_corrupt_state(self, tmp_path):
        path = tmp_path / "state.json"
        path.write_text(json.dumps({"last_fetch_utc": "not-a-date"}))
        with patch.object(nvd, "NVD_STATE_FILE", path):
            assert _should_fetch() is True


class TestGetSession:
    def test_returns_session(self):
        nvd._SESSION = None
        try:
            s = _get_session()
            assert s is not None
            assert "ThreatWatch" in s.headers.get("User-Agent", "")
        finally:
            nvd._SESSION = None

    def test_session_reused(self):
        nvd._SESSION = None
        try:
            s1 = _get_session()
            s2 = _get_session()
            assert s1 is s2
        finally:
            nvd._SESSION = None
