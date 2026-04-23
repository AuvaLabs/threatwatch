"""Tests for the LLM fallback path in modules/attack_tagger.py.

The pure-regex path is covered by test_attack_tagger.py. This file
focuses on the optional ``LLM_ATTACK_FALLBACK`` tier that escalates
under-tagged incident articles to the LLM.
"""

import json
from unittest.mock import patch

import pytest

import modules.attack_tagger as at


def _incident(title="Mysterious attack on AcmeBank", content="Attackers deployed novel TTPs beyond regex reach."):
    return {
        "hash": "hx",
        "title": title,
        "summary": "Incident summary text.",
        "full_content": content,
        "is_cyber_attack": True,
    }


class TestParseLLMTechniques:
    def test_valid_json_parsed(self):
        raw = json.dumps({
            "techniques": [
                {"technique_id": "T1566", "technique_name": "Phishing", "tactic": "Initial Access"},
                {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution"},
            ]
        })
        out = at._parse_llm_techniques(raw)
        assert len(out) == 2
        assert out[0]["technique_id"] == "T1566"
        assert out[1]["source"] == "llm"

    def test_invalid_ids_filtered(self):
        raw = json.dumps({
            "techniques": [
                {"technique_id": "BOGUS", "technique_name": "Fake", "tactic": "None"},
                {"technique_id": "T9999", "technique_name": "Real-shape", "tactic": "Test"},
            ]
        })
        out = at._parse_llm_techniques(raw)
        ids = [t["technique_id"] for t in out]
        assert "BOGUS" not in ids
        assert "T9999" in ids

    def test_dedup_by_id(self):
        raw = json.dumps({
            "techniques": [
                {"technique_id": "T1566", "technique_name": "Phishing", "tactic": "IA"},
                {"technique_id": "T1566", "technique_name": "Phishing", "tactic": "IA"},
            ]
        })
        assert len(at._parse_llm_techniques(raw)) == 1

    def test_empty_on_invalid_json(self):
        assert at._parse_llm_techniques("garbage") == []

    def test_truncates_to_five(self):
        raw = json.dumps({
            "techniques": [
                {"technique_id": f"T{1000+i}", "technique_name": f"N{i}", "tactic": "T"}
                for i in range(8)
            ]
        })
        assert len(at._parse_llm_techniques(raw)) == 5


class TestShouldEscalate:
    def test_disabled_when_flag_off(self):
        with patch.object(at, "_LLM_FALLBACK_ENABLED", False):
            assert at._should_escalate_to_llm(_incident()) is False

    def test_enabled_with_no_regex_hits(self):
        article = {**_incident(), "attack_techniques": []}
        with patch.object(at, "_LLM_FALLBACK_ENABLED", True):
            assert at._should_escalate_to_llm(article) is True

    def test_skipped_when_enough_regex_hits(self):
        article = {
            **_incident(),
            "attack_techniques": [
                {"technique_id": "T1566", "technique_name": "Phishing", "tactic": "IA"},
                {"technique_id": "T1486", "technique_name": "Ransomware", "tactic": "Impact"},
            ],
        }
        with patch.object(at, "_LLM_FALLBACK_ENABLED", True), \
             patch.object(at, "_LLM_FALLBACK_MIN_TECHNIQUES", 2):
            assert at._should_escalate_to_llm(article) is False

    def test_non_incident_skipped(self):
        article = {**_incident(), "is_cyber_attack": False}
        with patch.object(at, "_LLM_FALLBACK_ENABLED", True):
            assert at._should_escalate_to_llm(article) is False


class TestLLMMerge:
    def test_merge_preserves_regex_results(self):
        regex_hit = {"technique_id": "T1566", "technique_name": "Phishing", "tactic": "IA"}
        llm_hit = {"technique_id": "T1059", "technique_name": "CLI", "tactic": "Execution"}
        merged = at._merge_techniques([regex_hit], [llm_hit])
        ids = [t["technique_id"] for t in merged]
        assert ids == ["T1566", "T1059"]

    def test_merge_dedups_by_id(self):
        dup = {"technique_id": "T1566", "technique_name": "Phishing", "tactic": "IA"}
        merged = at._merge_techniques([dup], [dup])
        assert len(merged) == 1


class TestLLMFallbackIntegration:
    def test_llm_called_with_correct_caller(self):
        articles = [_incident()]
        llm_raw = json.dumps({
            "techniques": [
                {"technique_id": "T1566", "technique_name": "Phishing", "tactic": "Initial Access"},
            ]
        })
        with patch.object(at, "_LLM_FALLBACK_ENABLED", True), \
             patch.object(at, "get_cached_result", return_value=None), \
             patch.object(at, "cache_result"), \
             patch("modules.llm_client.call_llm", return_value=llm_raw) as llm:
            tagged = at.tag_articles_with_attack(articles)
        assert llm.call_args.kwargs["caller"] == "attack_llm"
        assert any(
            t["technique_id"] == "T1566"
            for t in tagged[0].get("attack_techniques", [])
        )

    def test_budget_cap_limits_llm_calls(self):
        articles = [_incident() for _ in range(5)]
        # Different hashes so cache keys differ
        for i, a in enumerate(articles):
            a["hash"] = f"h{i}"
        llm_raw = json.dumps({
            "techniques": [{"technique_id": "T1566", "technique_name": "Phishing", "tactic": "IA"}]
        })
        with patch.object(at, "_LLM_FALLBACK_ENABLED", True), \
             patch.object(at, "_LLM_FALLBACK_MAX_CALLS", 2), \
             patch.object(at, "get_cached_result", return_value=None), \
             patch.object(at, "cache_result"), \
             patch("modules.llm_client.call_llm", return_value=llm_raw) as llm:
            at.tag_articles_with_attack(articles)
        assert llm.call_count == 2

    def test_llm_disabled_by_default(self):
        articles = [_incident()]
        with patch.object(at, "_LLM_FALLBACK_ENABLED", False), \
             patch("modules.llm_client.call_llm") as llm:
            at.tag_articles_with_attack(articles)
        llm.assert_not_called()
