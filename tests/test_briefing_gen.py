"""Tests for modules/briefing_generator.py — AI briefing orchestration."""

import json
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from pathlib import Path

# Import through the module's own namespace to avoid circular issues
from modules import briefing_generator as bg


def _article(title="Test", category="Ransomware", confidence=90, region="US",
             timestamp=None, darkweb=False, **kw):
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    a = {"title": title, "category": category, "confidence": confidence,
         "feed_region": region, "timestamp": timestamp, "link": "https://example.com",
         "is_cyber_attack": True, "published": timestamp[:16]}
    if darkweb:
        a["darkweb"] = True
    a.update(kw)
    return a


class TestDetectProvider:
    def test_explicit_provider(self):
        with patch.object(bg, "LLM_PROVIDER", "anthropic"):
            assert bg._detect_provider() == "anthropic"

    def test_no_api_key_returns_none(self):
        with patch.object(bg, "LLM_PROVIDER", "auto"), \
             patch.object(bg, "LLM_API_KEY", ""):
            assert bg._detect_provider() is None

    def test_anthropic_url_detected(self):
        with patch.object(bg, "LLM_PROVIDER", "auto"), \
             patch.object(bg, "LLM_API_KEY", "key"), \
             patch.object(bg, "LLM_BASE_URL", "https://api.anthropic.com/v1"):
            assert bg._detect_provider() == "anthropic"

    def test_ollama_localhost_detected(self):
        with patch.object(bg, "LLM_PROVIDER", "auto"), \
             patch.object(bg, "LLM_API_KEY", "key"), \
             patch.object(bg, "LLM_BASE_URL", "http://localhost:11434/v1"):
            assert bg._detect_provider() == "ollama"

    def test_defaults_to_openai(self):
        with patch.object(bg, "LLM_PROVIDER", "auto"), \
             patch.object(bg, "LLM_API_KEY", "key"), \
             patch.object(bg, "LLM_BASE_URL", "https://api.groq.com/openai/v1"):
            assert bg._detect_provider() == "openai"


class TestBuildDigest:
    def test_basic_digest(self):
        articles = [_article(title="LockBit attack", category="Ransomware")]
        result = bg._build_digest(articles)
        assert "[1]" in result
        assert "LockBit attack" in result
        assert "[Ransomware]" in result

    def test_includes_source_metadata(self):
        articles = [_article(source_name="BleepingComputer")]
        result = bg._build_digest(articles)
        assert "BleepingComputer" in result

    def test_includes_cve_enrichment(self):
        articles = [_article(cve_id="CVE-2026-1234", cvss_score=9.8)]
        result = bg._build_digest(articles)
        assert "CVE-2026-1234" in result
        assert "9.8" in result

    def test_includes_epss(self):
        articles = [_article(epss_max_score=0.95, epss_risk="VERY HIGH")]
        result = bg._build_digest(articles)
        assert "EPSS" in result
        assert "VERY HIGH" in result

    def test_includes_attack_tactics(self):
        articles = [_article(attack_tactics=["Initial Access", "Execution"])]
        result = bg._build_digest(articles)
        assert "ATT&CK" in result

    def test_caps_at_max_articles(self):
        articles = [_article(title=f"A{i}") for i in range(100)]
        result = bg._build_digest(articles)
        assert f"[{bg._MAX_DIGEST_ARTICLES}]" in result
        assert f"[{bg._MAX_DIGEST_ARTICLES + 1}]" not in result


class TestBuildTrendContext:
    def test_returns_empty_when_no_file(self, tmp_path):
        with patch.object(bg, "OUTPUT_DIR", tmp_path / "output"):
            assert bg._build_trend_context() == ""

    def test_returns_empty_when_no_spikes(self, tmp_path):
        state_dir = tmp_path / "state"
        state_dir.mkdir(parents=True)
        (state_dir / "trends.json").write_text(json.dumps({"spikes": []}))
        with patch.object(bg, "OUTPUT_DIR", tmp_path / "output"):
            # _build_trend_context looks at OUTPUT_DIR.parent / "state"
            (tmp_path / "output").mkdir(exist_ok=True)
            with patch.object(bg, "OUTPUT_DIR", tmp_path / "output"):
                assert bg._build_trend_context() == ""

    def test_formats_spikes(self, tmp_path):
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        state_dir = tmp_path / "state"
        state_dir.mkdir()
        (state_dir / "trends.json").write_text(json.dumps({
            "spikes": [{"keyword": "Ransomware", "current_count": 20,
                        "average": 5.0, "ratio": 4.0}]
        }))
        with patch.object(bg, "OUTPUT_DIR", output_dir):
            result = bg._build_trend_context()
        assert "Ransomware" in result
        assert "4.0x" in result


class TestBuildVulnContext:
    def test_no_cves_returns_empty(self):
        articles = [_article()]
        assert bg._build_vuln_context(articles) == ""

    def test_formats_cve_data(self):
        articles = [_article(cve_id="CVE-2026-1234", cvss_score=9.8,
                            epss_max_score=0.85, epss_risk="VERY HIGH",
                            cvss_severity="CRITICAL")]
        result = bg._build_vuln_context(articles)
        assert "CVE-2026-1234" in result
        assert "CVSS 9.8" in result
        assert "CRITICAL" in result

    def test_sorted_by_epss_then_cvss(self):
        articles = [
            _article(cve_id="CVE-LOW", cvss_score=5.0, epss_max_score=0.01),
            _article(cve_id="CVE-HIGH", cvss_score=9.8, epss_max_score=0.95),
        ]
        result = bg._build_vuln_context(articles)
        assert result.index("CVE-HIGH") < result.index("CVE-LOW")


class TestComputeReportingWindow:
    def test_no_dates(self):
        assert bg._compute_reporting_window([_article(published="")]) == "Last 7 days"

    def test_single_date(self):
        assert bg._compute_reporting_window(
            [_article(published="2026-04-21T12:00:00")]
        ) == "Last 24 hours"

    def test_multiple_dates(self):
        articles = [
            _article(published="2026-04-21T12:00:00"),
            _article(published="2026-04-18T12:00:00"),
        ]
        result = bg._compute_reporting_window(articles)
        assert "Last" in result
        assert "2026-04-18" in result


class TestIsRateLimited:
    def test_not_limited_when_no_file(self, tmp_path):
        path = tmp_path / ".briefing_last_call"
        with patch.object(bg, "_LAST_API_CALL_PATH", path):
            assert bg._is_rate_limited() is False

    def test_limited_when_recent(self, tmp_path):
        path = tmp_path / ".briefing_last_call"
        path.write_text(str(datetime.now(timezone.utc).timestamp()))
        with patch.object(bg, "_LAST_API_CALL_PATH", path):
            assert bg._is_rate_limited() is True

    def test_not_limited_when_old(self, tmp_path):
        path = tmp_path / ".briefing_last_call"
        old = datetime.now(timezone.utc).timestamp() - 7200  # 2 hours ago
        path.write_text(str(old))
        with patch.object(bg, "_LAST_API_CALL_PATH", path):
            assert bg._is_rate_limited() is False

    def test_not_limited_on_corrupt(self, tmp_path):
        path = tmp_path / ".briefing_last_call"
        path.write_text("not-a-number")
        with patch.object(bg, "_LAST_API_CALL_PATH", path):
            assert bg._is_rate_limited() is False


class TestRecordApiCall:
    def test_records_timestamp(self, tmp_path):
        path = tmp_path / ".briefing_last_call"
        with patch.object(bg, "_LAST_API_CALL_PATH", path):
            bg._record_api_call()
        assert path.exists()
        ts = float(path.read_text())
        assert ts > 0


class TestGenerateBriefing:
    def _articles(self, n=30):
        now = datetime.now(timezone.utc)
        return [_article(title=f"Article {i}",
                        timestamp=(now - timedelta(hours=i)).isoformat())
                for i in range(n)]

    def test_no_provider_returns_none(self):
        with patch.object(bg, "_detect_provider", return_value=None):
            assert bg.generate_briefing(self._articles()) is None

    def test_empty_articles_returns_none(self):
        with patch.object(bg, "_detect_provider", return_value="openai"):
            assert bg.generate_briefing([]) is None

    def test_cached_result_returned(self, tmp_path):
        cached = {"threat_level": "MODERATE", "what_happened": "cached"}
        with patch.object(bg, "_detect_provider", return_value="openai"), \
             patch.object(bg, "get_cached_result", return_value=cached), \
             patch.object(bg, "_save_briefing"), \
             patch.object(bg, "BRIEFING_PATH", tmp_path / "briefing.json"):
            result = bg.generate_briefing(self._articles())
        assert result == cached

    def test_rate_limited_serves_existing(self, tmp_path):
        existing = {"threat_level": "ELEVATED", "what_happened": "old"}
        with patch.object(bg, "_detect_provider", return_value="openai"), \
             patch.object(bg, "get_cached_result", return_value=None), \
             patch.object(bg, "_is_rate_limited", return_value=True), \
             patch.object(bg, "load_briefing", return_value=existing):
            result = bg.generate_briefing(self._articles())
        assert result == existing

    def test_successful_generation(self, tmp_path):
        llm_reply = json.dumps({
            "threat_level": "ELEVATED",
            "what_happened": "LockBit hit hospitals.",
            "what_to_do": ["Patch systems"],
            "outlook": "More attacks expected.",
        })
        with patch.object(bg, "_detect_provider", return_value="openai"), \
             patch.object(bg, "get_cached_result", return_value=None), \
             patch.object(bg, "_is_rate_limited", return_value=False), \
             patch.object(bg, "_call_openai_compatible", return_value=llm_reply), \
             patch.object(bg, "_parse_json", return_value=json.loads(llm_reply)), \
             patch.object(bg, "_record_api_call"), \
             patch.object(bg, "cache_result"), \
             patch.object(bg, "_save_briefing"), \
             patch.object(bg, "LLM_MODEL", "test-model"), \
             patch.object(bg, "_build_trend_context", return_value=""), \
             patch.object(bg, "_build_vuln_context", return_value=""):
            result = bg.generate_briefing(self._articles())
        assert result is not None
        assert result["threat_level"] == "ELEVATED"
        assert "source_articles" in result
        assert result["provider"] == "openai/test-model"

    def test_legacy_field_mapping(self, tmp_path):
        """Legacy LLM responses with old field names should be normalized."""
        llm_reply = json.dumps({
            "threat_level": "MODERATE",
            "situation_overview": "Legacy overview.",
            "priority_actions": ["Action 1"],
            "threat_forecast": "Forecast.",
        })
        with patch.object(bg, "_detect_provider", return_value="openai"), \
             patch.object(bg, "get_cached_result", return_value=None), \
             patch.object(bg, "_is_rate_limited", return_value=False), \
             patch.object(bg, "_call_openai_compatible", return_value=llm_reply), \
             patch.object(bg, "_parse_json", return_value=json.loads(llm_reply)), \
             patch.object(bg, "_record_api_call"), \
             patch.object(bg, "cache_result"), \
             patch.object(bg, "_save_briefing"), \
             patch.object(bg, "LLM_MODEL", "test"), \
             patch.object(bg, "_build_trend_context", return_value=""), \
             patch.object(bg, "_build_vuln_context", return_value=""):
            result = bg.generate_briefing(self._articles())
        assert result["what_happened"] == "Legacy overview."
        assert result["outlook"] == "Forecast."

    def test_invalid_threat_level_normalized(self, tmp_path):
        llm_reply = json.dumps({
            "threat_level": "BANANA",
            "what_happened": "Test.",
        })
        with patch.object(bg, "_detect_provider", return_value="openai"), \
             patch.object(bg, "get_cached_result", return_value=None), \
             patch.object(bg, "_is_rate_limited", return_value=False), \
             patch.object(bg, "_call_openai_compatible", return_value=llm_reply), \
             patch.object(bg, "_parse_json", return_value=json.loads(llm_reply)), \
             patch.object(bg, "_record_api_call"), \
             patch.object(bg, "cache_result"), \
             patch.object(bg, "_save_briefing"), \
             patch.object(bg, "LLM_MODEL", "test"), \
             patch.object(bg, "_build_trend_context", return_value=""), \
             patch.object(bg, "_build_vuln_context", return_value=""):
            result = bg.generate_briefing(self._articles())
        assert result["threat_level"] == "MODERATE"

    def test_llm_failure_returns_none(self):
        with patch.object(bg, "_detect_provider", return_value="openai"), \
             patch.object(bg, "get_cached_result", return_value=None), \
             patch.object(bg, "_is_rate_limited", return_value=False), \
             patch.object(bg, "_call_openai_compatible", side_effect=Exception("API down")), \
             patch.object(bg, "_build_trend_context", return_value=""), \
             patch.object(bg, "_build_vuln_context", return_value=""):
            result = bg.generate_briefing(self._articles())
        assert result is None

    def test_parse_failure_returns_none(self):
        with patch.object(bg, "_detect_provider", return_value="openai"), \
             patch.object(bg, "get_cached_result", return_value=None), \
             patch.object(bg, "_is_rate_limited", return_value=False), \
             patch.object(bg, "_call_openai_compatible", return_value="not json"), \
             patch.object(bg, "_parse_json", return_value=None), \
             patch.object(bg, "_build_trend_context", return_value=""), \
             patch.object(bg, "_build_vuln_context", return_value=""):
            result = bg.generate_briefing(self._articles())
        assert result is None


class TestGenerateRegionalDigests:
    def _articles(self, region="US", n=20):
        now = datetime.now(timezone.utc)
        return [_article(title=f"Art {i}", region=region,
                        timestamp=(now - timedelta(hours=i)).isoformat())
                for i in range(n)]

    def test_no_provider_returns_empty(self):
        with patch.object(bg, "_detect_provider", return_value=None):
            assert bg.generate_regional_briefings(self._articles()) == {}

    def test_generates_for_region(self, tmp_path):
        llm_reply = json.dumps({
            "threat_level": "MODERATE",
            "what_happened": "NA digest.",
        })
        articles = self._articles("US", 20)
        with patch.object(bg, "_detect_provider", return_value="openai"), \
             patch.object(bg, "get_cached_result", return_value=None), \
             patch.object(bg, "_call_openai_compatible", return_value=llm_reply), \
             patch.object(bg, "_parse_json", return_value=json.loads(llm_reply)), \
             patch.object(bg, "cache_result"), \
             patch.object(bg, "LLM_MODEL", "test"), \
             patch.object(bg, "_save_regional_briefing"), \
             patch.object(bg, "_regional_rate_limit_path",
                         side_effect=lambda k: tmp_path / f".rate_{k}"), \
             patch.object(bg, "_regional_briefing_path",
                         side_effect=lambda k: tmp_path / f"brief_{k}.json"):
            result = bg.generate_regional_briefings(articles)
        assert "na" in result
        assert result["na"]["what_happened"] == "NA digest."

    def test_skips_region_with_too_few_articles(self, tmp_path):
        articles = self._articles("US", 2)  # Only 2 — below threshold of 5
        with patch.object(bg, "_detect_provider", return_value="openai"), \
             patch.object(bg, "_regional_rate_limit_path",
                         side_effect=lambda k: tmp_path / f".rate_{k}"), \
             patch.object(bg, "_regional_briefing_path",
                         side_effect=lambda k: tmp_path / f"brief_{k}.json"):
            result = bg.generate_regional_briefings(articles)
        # Should get empty or missing "na" since not enough articles
        # (EMEA/APAC also empty)
        assert result == {} or all(v is None for v in result.values())

    def test_rate_limited_serves_existing(self, tmp_path):
        rate_path = tmp_path / ".rate_na"
        rate_path.write_text(str(datetime.now(timezone.utc).timestamp()))
        brief_path = tmp_path / "brief_na.json"
        existing = {"threat_level": "LOW", "what_happened": "old"}
        brief_path.write_text(json.dumps(existing))
        articles = self._articles("US", 20)
        with patch.object(bg, "_detect_provider", return_value="openai"), \
             patch.object(bg, "_regional_rate_limit_path",
                         side_effect=lambda k: tmp_path / f".rate_{k}"), \
             patch.object(bg, "_regional_briefing_path",
                         side_effect=lambda k: tmp_path / f"brief_{k}.json"):
            result = bg.generate_regional_briefings(articles)
        assert result.get("na", {}).get("what_happened") == "old"


class TestSaveLoadBriefing:
    def test_save_and_load_roundtrip(self, tmp_path):
        path = tmp_path / "briefing.json"
        data = {"threat_level": "MODERATE", "what_happened": "Test"}
        with patch.object(bg, "BRIEFING_PATH", path):
            bg._save_briefing(data)
            result = bg.load_briefing()
        assert result == data

    def test_load_returns_none_when_missing(self, tmp_path):
        with patch.object(bg, "BRIEFING_PATH", tmp_path / "missing.json"):
            assert bg.load_briefing() is None

    def test_load_returns_none_on_corrupt(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{bad")
        with patch.object(bg, "BRIEFING_PATH", path):
            assert bg.load_briefing() is None


class TestCallOpenaiCompatible:
    def test_delegates_to_llm_client(self):
        with patch.object(bg, "_call_groq", return_value="response") as mock:
            result = bg._call_openai_compatible("test prompt")
        assert result == "response"
        mock.assert_called_once()
