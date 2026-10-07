"""Tests for hybrid_classifier — keyword-first, AI-escalation logic."""

import pytest
from unittest.mock import patch

from modules.hybrid_classifier import classify_article, _should_escalate, _classify_via_llm


class TestShouldEscalate:
    """Test the escalation decision logic."""

    def test_no_escalation_without_api_key(self):
        with patch("modules.llm_client.LLM_API_KEY", ""):
            result = {"is_cyber_attack": True, "category": "General Cyber Threat", "confidence": 50}
            assert _should_escalate(result) is False

    def test_no_escalation_for_non_cyber(self):
        with patch("modules.llm_client.LLM_API_KEY", "sk-test"):
            result = {"is_cyber_attack": False, "category": "Noise", "confidence": 0}
            assert _should_escalate(result) is False

    def test_escalates_general_cyber_threat(self):
        with patch("modules.llm_client.LLM_API_KEY", "sk-test"):
            result = {"is_cyber_attack": True, "category": "General Cyber Threat", "confidence": 60}
            assert _should_escalate(result) is True

    def test_escalates_low_confidence(self):
        with patch("modules.llm_client.LLM_API_KEY", "sk-test"):
            result = {"is_cyber_attack": True, "category": "Ransomware", "confidence": 55}
            assert _should_escalate(result) is True

    def test_no_escalation_high_confidence(self):
        with patch("modules.llm_client.LLM_API_KEY", "sk-test"):
            result = {"is_cyber_attack": True, "category": "Ransomware", "confidence": 92}
            assert _should_escalate(result) is False


class TestClassifyViaLlm:
    """Test the shared-LLM classification helper."""

    def test_cache_hit_returns_cached(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        cached = {"is_cyber_attack": True, "category": "Ransomware", "confidence": 90}
        with patch("modules.hybrid_classifier.get_cached_result", return_value=cached):
            result = _classify_via_llm("LockBit attack")
        assert result["_cached"] is True
        assert result["category"] == "Ransomware"

    def test_llm_call_parses_json(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        llm_reply = '{"is_cyber_attack": true, "category": "Malware", "confidence": 88}'
        with patch("modules.hybrid_classifier.get_cached_result", return_value=None), \
             patch("modules.llm_client.call_llm", return_value=llm_reply), \
             patch("modules.hybrid_classifier.cache_result"):
            result = _classify_via_llm("Suspicious malware", "Article content here")
        assert result["category"] == "Malware"

    def test_bad_response_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        with patch("modules.hybrid_classifier.get_cached_result", return_value=None), \
             patch("modules.llm_client.call_llm", return_value="not json"):
            result = _classify_via_llm("Test")
        assert result is None


class TestHybridClassifier:
    """Test the hybrid classify_article function."""

    def test_keyword_only_without_api_key(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr("modules.llm_client.LLM_API_KEY", "")

        result = classify_article("LockBit ransomware hits hospital")
        assert result["is_cyber_attack"] is True
        assert result["category"] == "Ransomware"
        assert "_ai_enhanced" not in result

    def test_high_confidence_skips_ai(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr("modules.llm_client.LLM_API_KEY", "sk-test")

        with patch("modules.hybrid_classifier.keyword_classify") as mock_kw:
            mock_kw.return_value = {
                "is_cyber_attack": True,
                "category": "Ransomware",
                "confidence": 92,
                "translated_title": "LockBit ransomware hits hospital",
                "summary": "Test summary",
            }
            result = classify_article("LockBit ransomware hits hospital")
            assert result["category"] == "Ransomware"
            assert "_ai_enhanced" not in result

    def test_low_confidence_escalates_to_ai(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr("modules.llm_client.LLM_API_KEY", "sk-test")
        import modules.hybrid_classifier as hc
        hc._escalation_count = 0

        with patch("modules.hybrid_classifier.keyword_classify") as mock_kw, \
             patch("modules.hybrid_classifier._classify_via_llm") as mock_llm:
            mock_kw.return_value = {
                "is_cyber_attack": True,
                "category": "General Cyber Threat",
                "confidence": 60,
                "translated_title": "Suspicious activity detected",
                "summary": "",
            }
            mock_llm.return_value = {
                "is_cyber_attack": True,
                "category": "Malware",
                "confidence": 88,
                "translated_title": "Suspicious activity detected",
                "summary": "AI-generated summary here.",
            }
            result = classify_article("Suspicious activity detected")
            assert result["category"] == "Malware"
            assert result["confidence"] == 88
            assert result["_ai_enhanced"] is True
            assert result["_keyword_category"] == "General Cyber Threat"
            mock_llm.assert_called_once()

    def test_ai_failure_falls_back_to_keyword(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr("modules.llm_client.LLM_API_KEY", "sk-test")

        with patch("modules.hybrid_classifier.keyword_classify") as mock_kw, \
             patch("modules.hybrid_classifier._classify_via_llm") as mock_llm:
            mock_kw.return_value = {
                "is_cyber_attack": True,
                "category": "General Cyber Threat",
                "confidence": 60,
                "translated_title": "Some article",
                "summary": "",
            }
            mock_llm.return_value = None
            result = classify_article("Some article")
            # Falls back to keyword result
            assert result["category"] == "General Cyber Threat"
            assert result["confidence"] == 60
            assert "_ai_enhanced" not in result
            assert result["_ai_failed"] is True

    def test_ai_exception_falls_back_to_keyword(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr("modules.llm_client.LLM_API_KEY", "sk-test")

        with patch("modules.hybrid_classifier.keyword_classify") as mock_kw, \
             patch("modules.hybrid_classifier._classify_via_llm", side_effect=Exception("API down")):
            mock_kw.return_value = {
                "is_cyber_attack": True,
                "category": "General Cyber Threat",
                "confidence": 60,
                "translated_title": "Exception test",
                "summary": "",
            }
            result = classify_article("Exception test")
            assert result["confidence"] == 60
            assert "_ai_enhanced" not in result
            assert result["_ai_failed"] is True

    def test_noise_articles_never_escalate(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr("modules.llm_client.LLM_API_KEY", "sk-test")

        result = classify_article("Cybersecurity jobs available right now")
        assert result["is_cyber_attack"] is False
        assert "_ai_enhanced" not in result


class TestCacheKeyVersioning:
    def test_prompt_change_busts_cache(self, tmp_path):
        """A cached LLM verdict must not survive a prompt rewrite."""
        import modules.hybrid_classifier as hc
        from unittest.mock import patch
        import modules.ai_cache as ac
        captured = []
        with patch.object(ac, "CACHE_DIR", tmp_path), \
             patch.object(hc, "get_cached_result", side_effect=lambda k: captured.append(k) or None), \
             patch("modules.llm_client.call_llm", return_value='{"is_cyber_attack": true, "category": "Ransomware", "confidence": 90}'), \
             patch.object(hc, "cache_result"):
            hc._classify_via_llm("LockBit hits hospital")
            with patch.object(hc, "SYSTEM_PROMPT", "completely different prompt"):
                hc._classify_via_llm("LockBit hits hospital")
        assert len(captured) == 2
        assert captured[0] != captured[1], "cache key must change when the prompt changes"
