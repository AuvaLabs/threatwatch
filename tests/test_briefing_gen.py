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
        # Cache hit re-stamps generated_at so the staleness alarm stays accurate
        # across runs even when the digest is unchanged.
        assert result["threat_level"] == "MODERATE"
        assert result["what_happened"] == "cached"
        assert "generated_at" in result

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
        # Reset the served-tier sentinel — _call_openai_compatible is mocked
        # here so the production-path setter never fires; without this reset,
        # state from sibling test files (e.g. test_briefing_featherless_routing)
        # bleeds in and the provider field reflects the prior test's tier.
        with patch.object(bg, "_detect_provider", return_value="openai"), \
             patch.object(bg, "get_cached_result", return_value=None), \
             patch.object(bg, "_is_rate_limited", return_value=False), \
             patch.object(bg, "_call_openai_compatible", return_value=llm_reply), \
             patch.object(bg, "_parse_json", return_value=json.loads(llm_reply)), \
             patch.object(bg, "_record_api_call"), \
             patch.object(bg, "cache_result"), \
             patch.object(bg, "_save_briefing"), \
             patch.object(bg, "BRIEFING_MODEL", "test-model"), \
             patch.object(bg, "_LAST_SERVED_TIER", None), \
             patch.object(bg, "_build_trend_context", return_value=""), \
             patch.object(bg, "_build_vuln_context", return_value=""):
            result = bg.generate_briefing(self._articles())
        assert result is not None
        assert result["threat_level"] == "ELEVATED"
        assert "source_articles" in result
        assert result["provider"] == "openai/test-model"

    def test_generated_at_stamped_after_llm_call(self, tmp_path):
        """generated_at must be stamped AFTER the LLM call returns, not before.

        Groq free-tier calls can block for many minutes; stamping at function
        entry produces a timestamp hours older than the actual save, tripping
        the staleness alarm the moment the briefing hits disk.
        """
        from datetime import datetime, timezone, timedelta
        llm_reply = json.dumps({
            "threat_level": "MODERATE",
            "what_happened": "Test incident.",
        })
        # Simulate a slow LLM call by advancing time during the call.
        call_start = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        call_end = call_start + timedelta(minutes=107)
        # First now() call (function entry) sees call_start; every later call
        # sees call_end. A finite two-tick iterator broke whenever production
        # code added a now() call — the StopIteration was swallowed and the
        # briefing silently returned None.
        ticks = iter([call_start])

        def clock():
            return next(ticks, call_end)

        def _slow_call(*_a, **_k):
            # Patch datetime.now inside briefing_generator to advance on call.
            return llm_reply

        with patch.object(bg, "_detect_provider", return_value="openai"), \
             patch.object(bg, "get_cached_result", return_value=None), \
             patch.object(bg, "_is_rate_limited", return_value=False), \
             patch.object(bg, "_call_openai_compatible", side_effect=_slow_call), \
             patch.object(bg, "_parse_json", return_value=json.loads(llm_reply)), \
             patch.object(bg, "_record_api_call"), \
             patch.object(bg, "cache_result"), \
             patch.object(bg, "_save_briefing"), \
             patch.object(bg, "LLM_MODEL", "m"), \
             patch.object(bg, "_build_trend_context", return_value=""), \
             patch.object(bg, "_build_vuln_context", return_value=""), \
             patch("modules.briefing_generator.datetime") as mock_dt:
            mock_dt.now.side_effect = lambda tz=None: clock()
            mock_dt.side_effect = lambda *a, **k: datetime(*a, **k)
            result = bg.generate_briefing(self._articles())
        # generated_at must reflect the post-call time, not the pre-call time.
        assert result["generated_at"] == call_end.isoformat()

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
        # _save_briefing stamps previous_* fields read from any prior on-disk
        # briefing; first run has no prior so both stamp as None.
        assert result == {**data, "previous_threat_level": None, "previous_generated_at": None}

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


class TestRegionalBriefingPersistence:
    """Cover the regional briefing load/save helpers — low-value code but
    not tested and eating coverage percentage."""

    def test_save_and_load_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bg, "OUTPUT_DIR", tmp_path)
        briefing = {"region": "na", "what_happened": "Test", "generated_at": "2026-01-01"}
        bg._save_regional_briefing("na", briefing)
        loaded = bg.load_regional_briefing("na")
        # _save_regional_briefing stamps previous_* fields read from any prior
        # on-disk regional briefing; first run has no prior so both stamp as None.
        assert loaded == {**briefing, "previous_threat_level": None, "previous_generated_at": None}

    def test_load_returns_none_when_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bg, "OUTPUT_DIR", tmp_path / "empty")
        assert bg.load_regional_briefing("na") is None

    def test_load_returns_none_when_corrupt(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bg, "OUTPUT_DIR", tmp_path)
        path = bg._regional_briefing_path("na")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not json {{{")
        assert bg.load_regional_briefing("na") is None

    def test_load_all_regional_briefings_returns_by_key(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bg, "OUTPUT_DIR", tmp_path)
        bg._save_regional_briefing("na", {"region": "na"})
        bg._save_regional_briefing("emea", {"region": "emea"})
        result = bg.load_all_regional_briefings()
        assert "na" in result and "emea" in result
        assert result["na"]["region"] == "na"

    def test_load_all_skips_missing(self, tmp_path, monkeypatch):
        """Missing regional files don't break aggregation."""
        monkeypatch.setattr(bg, "OUTPUT_DIR", tmp_path / "empty")
        # No files written — should return empty dict.
        assert bg.load_all_regional_briefings() == {}


class TestCveGrounding:
    """Block hallucinated CVE IDs from leaking into briefings.

    Regression: the model echoed a CVE ID that only existed in the prompt's
    style examples, surfacing as a false CRITICAL alert on Telegram. The
    guard rejects any briefing citing a CVE that isn't in the article digest.
    """

    def test_no_cves_means_grounded(self):
        briefing = {"what_happened": "Generic ransomware activity continues.",
                    "headline": "Quiet day."}
        assert bg._validate_cve_grounding(briefing, "BEGIN INCIDENT DATA\n...\nEND") == set()

    def test_cited_cve_present_in_source_passes(self):
        briefing = {"what_happened": "CVE-2025-1111 actively exploited."}
        source = "[1] CVE-2025-1111 affects Cisco devices"
        assert bg._validate_cve_grounding(briefing, source) == set()

    def test_cited_cve_absent_from_source_is_flagged(self):
        # Mirrors the production incident: model echoed CVE-2026-1234 from the
        # prompt's example clause, with no such CVE anywhere in the digest.
        briefing = {"what_happened": "CVE-2026-1234 added to KEV."}
        source = "[1] LockBit attack on hospital\n[2] APT41 campaign"
        assert bg._validate_cve_grounding(briefing, source) == {"CVE-2026-1234"}

    def test_grounding_checks_all_text_fields(self):
        briefing = {
            "headline": "Quiet day.",
            "what_happened": "Generic activity.",
            "outlook": "CVE-2099-9999 may emerge.",
            "what_to_do": [{"action": "Patch CVE-2099-1111", "threat": "x"}],
        }
        ungrounded = bg._validate_cve_grounding(briefing, "no CVEs in source")
        assert ungrounded == {"CVE-2099-9999", "CVE-2099-1111"}

    def test_case_insensitive_match(self):
        briefing = {"what_happened": "cve-2025-2222 is bad."}
        source = "Article mentions CVE-2025-2222 in the body"
        assert bg._validate_cve_grounding(briefing, source) == set()

    def test_extract_cited_handles_malformed_what_to_do(self):
        # Legacy/edge-case shapes must not crash the validator.
        briefing = {"what_to_do": ["bare string", None, {"action": None}]}
        assert bg._extract_cited_cve_ids(briefing) == set()

    def test_generation_rejects_ungrounded_cve_and_serves_stale(self, tmp_path):
        """End-to-end: a fabricated CVE in the LLM reply must NOT be saved.

        The pipeline serves the prior on-disk briefing instead.
        """
        existing = {"threat_level": "MODERATE", "what_happened": "yesterday's news"}
        llm_reply = json.dumps({
            "threat_level": "CRITICAL",
            "what_happened": "CVE-2026-1234 added to KEV — critical exploitation.",
            "headline": "CVE-2026-1234 actively exploited.",
        })
        articles = [_article(title="Ransomware roundup",
                             timestamp=datetime.now(timezone.utc).isoformat())
                    for _ in range(20)]
        with patch.object(bg, "_detect_provider", return_value="openai"), \
             patch.object(bg, "get_cached_result", return_value=None), \
             patch.object(bg, "_is_rate_limited", return_value=False), \
             patch.object(bg, "_call_openai_compatible", return_value=llm_reply), \
             patch.object(bg, "_parse_json", return_value=json.loads(llm_reply)), \
             patch.object(bg, "_record_api_call"), \
             patch.object(bg, "cache_result"), \
             patch.object(bg, "_save_briefing") as save_mock, \
             patch.object(bg, "load_briefing", return_value=existing), \
             patch.object(bg, "BRIEFING_MODEL", "test-model"), \
             patch.object(bg, "_build_trend_context", return_value=""), \
             patch.object(bg, "_build_vuln_context", return_value=""):
            result = bg.generate_briefing(articles)
        # Stale briefing served, fabricated brief never reached disk.
        assert result == existing
        save_mock.assert_not_called()


class TestProperNounExtraction:
    """Underlies the headline narrative-coupling guard."""

    def test_extracts_capitalized_proper_nouns(self):
        nouns = bg._extract_proper_nouns(
            "Vimeo confirms Anodot breach; ShinyHunters claim credit."
        )
        assert "Vimeo" in nouns
        assert "Anodot" in nouns
        assert "ShinyHunters" in nouns

    def test_drops_security_jargon(self):
        nouns = bg._extract_proper_nouns(
            "Multiple Vulnerabilities Exploited Today By Hackers; CVE released."
        )
        # All of these should be stop-worded — none are entity-identifying.
        assert nouns == set()

    def test_handles_punctuation_and_hyphens(self):
        nouns = bg._extract_proper_nouns("Cisco-IOS issue affects ASA appliances.")
        assert "Cisco-IOS" in nouns
        assert "ASA" in nouns

    def test_empty_text(self):
        assert bg._extract_proper_nouns("") == set()
        assert bg._extract_proper_nouns(None) == set()


class TestHeadlineGrounding:
    """Block headlines that fuse entities from unrelated source articles.

    Regression: a briefing's headline read 'Vimeo confirms Anodot breach
    exposed user data, attackers exploited vulnerability CVE-2026-41205'.
    Vimeo/Anodot were one source article; CVE-2026-41205 (Mako template)
    was a different unrelated article. The guard must catch this.
    """

    def _articles(self):
        return [
            {"title": "Video service Vimeo confirms Anodot breach exposed user data",
             "summary": "Vimeo disclosed a breach via partner Anodot."},
            {"title": "CVE-2026-41205: HIGH (7.5) — Mako template library path traversal",
             "summary": "Mako prior to 1.3.11 vulnerable to path traversal."},
        ]

    def test_grounded_headline_passes(self):
        briefing = {
            "headline": "Vimeo confirms Anodot breach exposed user data.",
            "headline_source": 1,
        }
        assert bg._validate_headline_grounding(briefing, self._articles()) is None

    def test_conflated_entities_rejected(self):
        # The exact production failure: CVE from article 2, victim from article 1.
        briefing = {
            "headline": "Vimeo confirms Anodot breach, attackers exploited CVE-2026-41205.",
            "headline_source": 1,  # Vimeo article — but cites Mako CVE
        }
        reason = bg._validate_headline_grounding(briefing, self._articles())
        assert reason is not None
        assert "CVE-2026-41205" in reason

    def test_proper_noun_not_in_source_rejected(self):
        # Headline names a victim that isn't in the linked article.
        briefing = {
            "headline": "Cisco zero-day exploited in Vimeo breach.",
            "headline_source": 2,  # Mako article — names neither Cisco nor Vimeo
        }
        reason = bg._validate_headline_grounding(briefing, self._articles())
        assert reason is not None

    def test_missing_headline_source_rejected(self):
        briefing = {"headline": "Vimeo confirms Anodot breach."}
        reason = bg._validate_headline_grounding(briefing, self._articles())
        assert reason is not None
        assert "headline_source" in reason

    def test_invalid_headline_source_index(self):
        briefing = {"headline": "Anything.", "headline_source": 99}
        reason = bg._validate_headline_grounding(briefing, self._articles())
        assert reason is not None

    def test_empty_headline_passes(self):
        # Empty headline = frontend fallback will distill from what_happened.
        briefing = {"headline": "", "headline_source": 1}
        assert bg._validate_headline_grounding(briefing, self._articles()) is None

    def test_string_typed_index_accepted(self):
        # LLMs sometimes return "1" instead of 1. Tolerate it.
        briefing = {
            "headline": "Vimeo confirms Anodot breach exposed user data.",
            "headline_source": "1",
        }
        assert bg._validate_headline_grounding(briefing, self._articles()) is None
