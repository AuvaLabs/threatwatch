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

    def test_groq_escalation_success(self, tmp_path, monkeypatch):
        """Test the Groq escalation path (lines 111-127)."""
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr("modules.hybrid_classifier.ANTHROPIC_API_KEY", None)
        import modules.hybrid_classifier as hc
        hc._escalation_count = 0

        with patch("modules.hybrid_classifier.keyword_classify") as mock_kw, \
             patch("modules.llm_client.LLM_API_KEY", "groq-key"), \
             patch("modules.hybrid_classifier._classify_via_groq") as mock_groq:
            mock_kw.return_value = {
                "is_cyber_attack": True,
                "category": "General Cyber Threat",
                "confidence": 60,
            }
            mock_groq.return_value = {
                "is_cyber_attack": True,
                "category": "Malware",
                "confidence": 85,
            }
            result = classify_article("Suspicious activity")
            assert result["category"] == "Malware"
            assert result["_ai_enhanced"] is True
            mock_groq.assert_called_once()

    def test_groq_cached_result_no_count_increment(self, tmp_path, monkeypatch):
        """Cached Groq results don't increment escalation count."""
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr("modules.hybrid_classifier.ANTHROPIC_API_KEY", None)
        import modules.hybrid_classifier as hc
        hc._escalation_count = 0

        with patch("modules.hybrid_classifier.keyword_classify") as mock_kw, \
             patch("modules.llm_client.LLM_API_KEY", "groq-key"), \
             patch("modules.hybrid_classifier._classify_via_groq") as mock_groq:
            mock_kw.return_value = {
                "is_cyber_attack": True,
                "category": "General Cyber Threat",
                "confidence": 50,
            }
            mock_groq.return_value = {
                "is_cyber_attack": True,
                "category": "Phishing Campaign",
                "confidence": 90,
                "_cached": True,
            }
            classify_article("Test")
            assert hc._escalation_count == 0

    def test_groq_returns_none_falls_to_anthropic(self, tmp_path, monkeypatch):
        """When Groq returns None, falls through to Anthropic if available."""
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr("modules.hybrid_classifier.ANTHROPIC_API_KEY", "sk-test")

        with patch("modules.hybrid_classifier.keyword_classify") as mock_kw, \
             patch("modules.llm_client.LLM_API_KEY", "groq-key"), \
             patch("modules.hybrid_classifier._classify_via_groq", return_value=None), \
             patch("modules.ai_engine.analyze_article") as mock_ai:
            mock_kw.return_value = {
                "is_cyber_attack": True,
                "category": "General Cyber Threat",
                "confidence": 55,
            }
            mock_ai.return_value = {
                "is_cyber_attack": True,
                "category": "Data Breach",
                "confidence": 80,
            }
            result = classify_article("Test breach")
            assert result["category"] == "Data Breach"
            mock_ai.assert_called_once()

    def test_classify_via_groq_with_cache(self, tmp_path, monkeypatch):
        """Test _classify_via_groq cache hit path."""
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        from modules.hybrid_classifier import _classify_via_groq
        cached = {"is_cyber_attack": True, "category": "Ransomware", "confidence": 90}
        with patch("modules.hybrid_classifier.get_cached_result", return_value=cached):
            result = _classify_via_groq("LockBit attack")
        assert result["_cached"] is True
        assert result["category"] == "Ransomware"

    def test_classify_via_groq_llm_call(self, tmp_path, monkeypatch):
        """Test _classify_via_groq LLM call path."""
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        from modules.hybrid_classifier import _classify_via_groq
        llm_reply = '{"is_cyber_attack": true, "category": "Malware", "confidence": 88}'
        with patch("modules.hybrid_classifier.get_cached_result", return_value=None), \
             patch("modules.llm_client.call_llm", return_value=llm_reply), \
             patch("modules.hybrid_classifier.cache_result"):
            result = _classify_via_groq("Suspicious malware", "Article content here")
        assert result["category"] == "Malware"

    def test_classify_via_groq_bad_response(self, tmp_path, monkeypatch):
        """LLM returns unparseable response → None."""
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        from modules.hybrid_classifier import _classify_via_groq
        with patch("modules.hybrid_classifier.get_cached_result", return_value=None), \
             patch("modules.llm_client.call_llm", return_value="not json"):
            result = _classify_via_groq("Test")
        assert result is None

    def test_noise_articles_never_escalate(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr("modules.hybrid_classifier.ANTHROPIC_API_KEY", "sk-test")

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
            hc._classify_via_groq("LockBit hits hospital")
            with patch.object(hc, "SYSTEM_PROMPT", "completely different prompt"):
                hc._classify_via_groq("LockBit hits hospital")
        assert len(captured) == 2
        assert captured[0] != captured[1], "cache key must change when the prompt changes"
