"""Tests for hybrid_classifier — keyword-first, AI-escalation logic."""

import pytest
from unittest.mock import patch, MagicMock

from modules.hybrid_classifier import classify_article, _should_escalate


class TestShouldEscalate:
    """Test the escalation decision logic."""

    def test_no_escalation_without_api_key(self):
        with patch("modules.hybrid_classifier.ANTHROPIC_API_KEY", None), \
             patch("modules.llm_client.LLM_API_KEY", ""):
            result = {"is_cyber_attack": True, "category": "General Cyber Threat", "confidence": 50}
            assert _should_escalate(result) is False

    def test_no_escalation_for_non_cyber(self):
        with patch("modules.hybrid_classifier.ANTHROPIC_API_KEY", "sk-test"):
            result = {"is_cyber_attack": False, "category": "Noise", "confidence": 0}
            assert _should_escalate(result) is False

    def test_escalates_general_cyber_threat(self):
        with patch("modules.hybrid_classifier.ANTHROPIC_API_KEY", "sk-test"):
            result = {"is_cyber_attack": True, "category": "General Cyber Threat", "confidence": 60}
            assert _should_escalate(result) is True

    def test_escalates_low_confidence(self):
        with patch("modules.hybrid_classifier.ANTHROPIC_API_KEY", "sk-test"):
            result = {"is_cyber_attack": True, "category": "Ransomware", "confidence": 55}
            assert _should_escalate(result) is True

    def test_no_escalation_high_confidence(self):
        with patch("modules.hybrid_classifier.ANTHROPIC_API_KEY", "sk-test"):
            result = {"is_cyber_attack": True, "category": "Ransomware", "confidence": 92}
            assert _should_escalate(result) is False


class TestHybridClassifier:
    """Test the hybrid classify_article function."""

    def test_keyword_only_without_api_key(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr("modules.hybrid_classifier.ANTHROPIC_API_KEY", None)

        result = classify_article("LockBit ransomware hits hospital")
        assert result["is_cyber_attack"] is True
        assert result["category"] == "Ransomware"
        assert "_ai_enhanced" not in result

    def test_high_confidence_skips_ai(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr("modules.hybrid_classifier.ANTHROPIC_API_KEY", "sk-test")

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
        monkeypatch.setattr("modules.hybrid_classifier.ANTHROPIC_API_KEY", "sk-test")

        with patch("modules.hybrid_classifier.keyword_classify") as mock_kw, \
             patch("modules.llm_client.LLM_API_KEY", ""):
            mock_kw.return_value = {
                "is_cyber_attack": True,
                "category": "General Cyber Threat",
                "confidence": 60,
                "translated_title": "Suspicious activity detected",
                "summary": "",
            }
            with patch("modules.ai_engine.analyze_article") as mock_ai:
                mock_ai.return_value = {
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
                mock_ai.assert_called_once()

    def test_ai_failure_falls_back_to_keyword(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr("modules.hybrid_classifier.ANTHROPIC_API_KEY", "sk-test")

        with patch("modules.hybrid_classifier.keyword_classify") as mock_kw, \
             patch("modules.llm_client.LLM_API_KEY", ""):
            mock_kw.return_value = {
                "is_cyber_attack": True,
                "category": "General Cyber Threat",
                "confidence": 60,
                "translated_title": "Some article",
                "summary": "",
            }
            with patch("modules.ai_engine.analyze_article") as mock_ai:
                mock_ai.return_value = {
                    "is_cyber_attack": False,
                    "category": "General Cyber Threat",
                    "confidence": 0,
                    "translated_title": "Some article",
                    "summary": "",
                    "ai_analysis_failed": True,
                }
                result = classify_article("Some article")
                # Falls back to keyword result
                assert result["category"] == "General Cyber Threat"
                assert result["confidence"] == 60
                assert "_ai_enhanced" not in result

    def test_budget_skip_falls_back_to_keyword(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr("modules.hybrid_classifier.ANTHROPIC_API_KEY", "sk-test")

        with patch("modules.hybrid_classifier.keyword_classify") as mock_kw, \
             patch("modules.llm_client.LLM_API_KEY", ""):
            mock_kw.return_value = {
                "is_cyber_attack": True,
                "category": "General Cyber Threat",
                "confidence": 60,
                "translated_title": "Budget test",
                "summary": "",
            }
            with patch("modules.ai_engine.analyze_article") as mock_ai:
                mock_ai.return_value = {
                    "is_cyber_attack": False,
                    "category": "General Cyber Threat",
                    "confidence": 0,
                    "translated_title": "Budget test",
                    "summary": "",
                    "_budget_skipped": True,
                }
                result = classify_article("Budget test")
                assert result["confidence"] == 60
                assert "_ai_enhanced" not in result

    def test_ai_exception_falls_back_to_keyword(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr("modules.hybrid_classifier.ANTHROPIC_API_KEY", "sk-test")

        with patch("modules.hybrid_classifier.keyword_classify") as mock_kw, \
             patch("modules.llm_client.LLM_API_KEY", ""):
            mock_kw.return_value = {
                "is_cyber_attack": True,
                "category": "General Cyber Threat",
                "confidence": 60,
                "translated_title": "Exception test",
                "summary": "",
            }
            with patch("modules.ai_engine.analyze_article", side_effect=Exception("API down")):
                result = classify_article("Exception test")
                assert result["confidence"] == 60
                assert "_ai_enhanced" not in result

    def test_noise_articles_never_escalate(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr("modules.hybrid_classifier.ANTHROPIC_API_KEY", "sk-test")

        result = classify_article("Cybersecurity jobs available right now")
        assert result["is_cyber_attack"] is False
        assert "_ai_enhanced" not in result
