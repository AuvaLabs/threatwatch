import json
import pytest
from unittest.mock import patch, MagicMock

from modules.ai_engine import _extract_json, analyze_article, SAFE_DEFAULT


class TestExtractJson:
    def test_valid_json(self):
        result = _extract_json('{"is_cyber_attack": true, "category": "Malware"}')
        assert result["is_cyber_attack"] is True

    def test_json_with_surrounding_text(self):
        text = 'Here is the result: {"is_cyber_attack": false, "category": "None"} end'
        result = _extract_json(text)
        assert result is not None
        assert result["is_cyber_attack"] is False

    def test_invalid_json(self):
        assert _extract_json("not json at all") is None

    def test_empty_string(self):
        assert _extract_json("") is None


class TestAnalyzeArticle:
    @patch("modules.ai_engine._get_client")
    def test_successful_analysis(self, mock_get_client):
        mock_response = MagicMock()
        mock_response.content = [MagicMock()]
        mock_response.content[0].text = json.dumps({
            "is_cyber_attack": True,
            "category": "Ransomware",
            "confidence": 95,
            "translated_title": "Test Title",
            "summary": "A ransomware attack occurred.",
        })
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response
        mock_get_client.return_value = mock_client

        result = analyze_article("Test Title", "Some content")
        assert result["is_cyber_attack"] is True
        assert result["category"] == "Ransomware"
        assert result["confidence"] == 95

    @patch("modules.ai_engine._get_client")
    def test_malformed_json_returns_safe_default(self, mock_get_client):
        mock_response = MagicMock()
        mock_response.content = [MagicMock()]
        mock_response.content[0].text = "I cannot parse this as JSON properly {broken"
        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_response
        mock_get_client.return_value = mock_client

        result = analyze_article("Test Title")
        assert result["is_cyber_attack"] is False
        assert result["translated_title"] == "Test Title"

    @patch("modules.ai_engine._get_client")
    def test_api_error_returns_safe_default(self, mock_get_client):
        import anthropic
        mock_client = MagicMock()
        mock_client.messages.create.side_effect = anthropic.APIError(
            message="rate limited",
            request=MagicMock(),
            body=None,
        )
        mock_get_client.return_value = mock_client

        result = analyze_article("Test Title")
        assert result["is_cyber_attack"] is False
        assert result["translated_title"] == "Test Title"

    @patch("modules.ai_engine.get_cached_result")
    def test_cache_hit_skips_api(self, mock_cache):
        cached = {
            "is_cyber_attack": True,
            "category": "DDoS",
            "confidence": 88,
            "translated_title": "Cached Title",
            "summary": "Cached summary.",
        }
        mock_cache.return_value = cached

        result = analyze_article("Some Title", "Some content")
        assert result == cached
