"""Tests for modules/actor_profiler.py — threat actor profiles."""

import json
import pytest
from unittest.mock import patch, MagicMock

import modules.actor_profiler as ap
from modules.actor_profiler import (
    extract_actors_from_articles,
    generate_profiles,
    load_profiles,
    _load_profiles,
    _save_profiles,
)


class TestExtractActors:
    def test_finds_known_actor(self):
        articles = [{"title": "LockBit ransomware hits hospital", "summary": ""}]
        result = extract_actors_from_articles(articles)
        assert "LockBit" in result
        assert result["LockBit"]["type"] == "Ransomware"
        assert result["LockBit"]["count"] == 1

    def test_counts_multiple_mentions(self):
        articles = [
            {"title": "LockBit hits hospital", "summary": ""},
            {"title": "LockBit targets school", "summary": ""},
        ]
        result = extract_actors_from_articles(articles)
        assert result["LockBit"]["count"] == 2

    def test_multiple_actors(self):
        articles = [{"title": "APT28 and Lazarus found in same campaign", "summary": ""}]
        result = extract_actors_from_articles(articles)
        assert "APT28" in result
        assert "Lazarus Group" in result

    def test_no_actors(self):
        articles = [{"title": "Weather is nice", "summary": ""}]
        assert extract_actors_from_articles(articles) == {}

    def test_empty_articles(self):
        assert extract_actors_from_articles([]) == {}

    def test_matches_in_summary(self):
        articles = [{"title": "New threat found", "summary": "Volt Typhoon compromised routers"}]
        result = extract_actors_from_articles(articles)
        assert "Volt Typhoon" in result


class TestLoadSaveProfiles:
    def test_load_empty_when_missing(self, tmp_path):
        path = tmp_path / "profiles.json"
        with patch.object(ap, "PROFILES_PATH", path):
            assert _load_profiles() == {}

    def test_load_empty_on_corrupt(self, tmp_path):
        path = tmp_path / "profiles.json"
        path.write_text("{bad")
        with patch.object(ap, "PROFILES_PATH", path):
            assert _load_profiles() == {}

    def test_save_and_load_roundtrip(self, tmp_path):
        path = tmp_path / "profiles.json"
        data = {"LockBit": {"name": "LockBit", "type": "Ransomware"}}
        with patch.object(ap, "PROFILES_PATH", path):
            _save_profiles(data)
            assert _load_profiles() == data


class TestGenerateProfiles:
    def test_no_actors_returns_existing(self, tmp_path):
        profiles_path = tmp_path / "state" / "profiles.json"
        output_path = tmp_path / "output" / "actor_profiles.json"
        with patch.object(ap, "PROFILES_PATH", profiles_path), \
             patch.object(ap, "OUTPUT_DIR", tmp_path / "output"):
            result = generate_profiles([{"title": "Weather report", "summary": ""}])
        assert result == {}

    def test_skips_below_min_articles(self, tmp_path):
        profiles_path = tmp_path / "state" / "profiles.json"
        output_path = tmp_path / "output" / "actor_profiles.json"
        # Only 1 article mentioning LockBit — below _MIN_ARTICLES_FOR_PROFILE (2)
        articles = [{"title": "LockBit hits target", "summary": ""}]
        with patch.object(ap, "PROFILES_PATH", profiles_path), \
             patch.object(ap, "OUTPUT_DIR", tmp_path / "output"):
            result = generate_profiles(articles)
        assert "LockBit" not in result

    def test_generates_new_profile_via_llm(self, tmp_path):
        profiles_path = tmp_path / "state" / "profiles.json"
        output_path = tmp_path / "output"
        articles = [
            {"title": "LockBit hits hospital", "summary": ""},
            {"title": "LockBit targets school", "summary": ""},
        ]
        mock_profile = {"name": "LockBit", "type": "Ransomware-as-a-Service",
                        "origin": "Criminal", "description": "Test profile"}
        with patch.object(ap, "PROFILES_PATH", profiles_path), \
             patch.object(ap, "OUTPUT_DIR", output_path), \
             patch("modules.actor_profiler._generate_single_profile", return_value=mock_profile):
            result = generate_profiles(articles)
        assert "LockBit" in result
        assert result["LockBit"]["name"] == "LockBit"

    def test_updates_existing_profile_count(self, tmp_path):
        profiles_path = tmp_path / "state" / "profiles.json"
        output_path = tmp_path / "output"
        existing = {"LockBit": {"name": "LockBit", "current_article_count": 1}}
        profiles_path.parent.mkdir(parents=True, exist_ok=True)
        profiles_path.write_text(json.dumps(existing))
        articles = [
            {"title": "LockBit hits target A", "summary": ""},
            {"title": "LockBit hits target B", "summary": ""},
            {"title": "LockBit hits target C", "summary": ""},
        ]
        with patch.object(ap, "PROFILES_PATH", profiles_path), \
             patch.object(ap, "OUTPUT_DIR", output_path):
            result = generate_profiles(articles)
        assert result["LockBit"]["current_article_count"] == 3

    def test_llm_failure_returns_none_profile(self, tmp_path):
        profiles_path = tmp_path / "state" / "profiles.json"
        output_path = tmp_path / "output"
        articles = [
            {"title": "LockBit A", "summary": ""},
            {"title": "LockBit B", "summary": ""},
        ]
        with patch.object(ap, "PROFILES_PATH", profiles_path), \
             patch.object(ap, "OUTPUT_DIR", output_path), \
             patch("modules.actor_profiler._generate_single_profile", return_value=None):
            result = generate_profiles(articles)
        assert "LockBit" not in result


class TestLoadProfilesPublic:
    def test_loads_from_output_dir(self, tmp_path):
        output_path = tmp_path / "actor_profiles.json"
        data = {"APT28": {"name": "APT28"}}
        output_path.write_text(json.dumps(data))
        with patch.object(ap, "OUTPUT_DIR", tmp_path):
            result = load_profiles()
        assert "APT28" in result

    def test_falls_back_to_state(self, tmp_path):
        state_path = tmp_path / "state" / "profiles.json"
        state_path.parent.mkdir(parents=True, exist_ok=True)
        state_path.write_text(json.dumps({"LockBit": {"name": "LockBit"}}))
        with patch.object(ap, "OUTPUT_DIR", tmp_path / "empty"), \
             patch.object(ap, "PROFILES_PATH", state_path):
            result = load_profiles()
        assert "LockBit" in result


class TestObservedTTPs:
    """Actor profiles surface the top ATT&CK techniques/tactics observed
    in articles mentioning the actor, grounding LLM narratives in data."""

    def test_techniques_aggregated_per_actor(self):
        articles = [
            {
                "title": "LockBit hit hospital",
                "summary": "",
                "attack_techniques": [
                    {"id": "T1566", "name": "Phishing"},
                    {"id": "T1486", "name": "Data Encrypted for Impact"},
                ],
                "attack_tactics": ["Initial Access", "Impact"],
            },
            {
                "title": "LockBit affiliate breaches firm",
                "summary": "",
                "attack_techniques": [{"id": "T1566", "name": "Phishing"}],
                "attack_tactics": ["Initial Access"],
            },
        ]
        actors = extract_actors_from_articles(articles)
        assert actors["LockBit"]["techniques"]["T1566"] == 2
        assert actors["LockBit"]["techniques"]["T1486"] == 1
        assert actors["LockBit"]["tactics"]["Initial Access"] == 2

    def test_technique_string_ids_also_counted(self):
        """Older cached articles may have plain string IDs — shouldn't break."""
        articles = [
            {"title": "LockBit a", "summary": "", "attack_techniques": ["T1566"]},
            {"title": "LockBit b", "summary": "", "attack_techniques": ["T1566"]},
        ]
        actors = extract_actors_from_articles(articles)
        assert actors["LockBit"]["techniques"]["T1566"] == 2

    def test_new_profile_gets_observed_ttps_stamped(self, tmp_path):
        profiles_path = tmp_path / "state" / "profiles.json"
        output_path = tmp_path / "output"
        articles = [
            {
                "title": "LockBit a", "summary": "",
                "attack_techniques": [{"id": "T1486"}],
                "attack_tactics": ["Impact"],
            },
            {
                "title": "LockBit b", "summary": "",
                "attack_techniques": [{"id": "T1486"}],
                "attack_tactics": ["Impact"],
            },
        ]
        mock_profile = {
            "name": "LockBit",
            "origin": "Russia",
            "type": "Ransomware-as-a-Service",
            "description": "Test",
        }
        with patch.object(ap, "PROFILES_PATH", profiles_path), \
             patch.object(ap, "OUTPUT_DIR", output_path), \
             patch("modules.actor_profiler._generate_single_profile", return_value=mock_profile):
            result = generate_profiles(articles)
        assert result["LockBit"]["observed_techniques"] == [{"id": "T1486", "count": 2}]
        assert result["LockBit"]["observed_tactics"] == [{"name": "Impact", "count": 2}]

    def test_single_profile_returns_none_when_llm_unavailable(self):
        """_generate_single_profile bails cleanly when no API key is set."""
        with patch("modules.llm_client.is_available", return_value=False):
            result = ap._generate_single_profile(
                "LockBit", {"type": "Ransomware-as-a-Service", "origin": "Russia"}
            )
        assert result is None

    def test_single_profile_returns_none_on_llm_exception(self):
        """LLM call raising must be swallowed and return None so the caller
        can skip this actor and continue with the rest."""
        with patch("modules.llm_client.is_available", return_value=True), \
             patch("modules.llm_client.call_llm", side_effect=RuntimeError("429")):
            result = ap._generate_single_profile(
                "LockBit", {"type": "RaaS", "origin": "Russia"}
            )
        assert result is None

    def test_single_profile_returns_none_on_missing_name_field(self):
        """LLM reply that parses to JSON but lacks 'name' is rejected."""
        with patch("modules.llm_client.is_available", return_value=True), \
             patch("modules.llm_client.call_llm", return_value='{"origin":"Russia"}'), \
             patch("modules.utils.extract_json", return_value={"origin": "Russia"}):
            result = ap._generate_single_profile(
                "LockBit", {"type": "RaaS", "origin": "Russia"}
            )
        assert result is None

    def test_max_new_profiles_per_run_enforced(self, tmp_path, monkeypatch):
        """Only _MAX_NEW_PROFILES_PER_RUN fresh profiles generated per run."""
        profiles_path = tmp_path / "state" / "profiles.json"
        output_path = tmp_path / "output"
        monkeypatch.setattr(ap, "_MAX_NEW_PROFILES_PER_RUN", 1)
        # Two different actors both above the threshold.
        articles = [
            {"title": "LockBit a", "summary": ""},
            {"title": "LockBit b", "summary": ""},
            {"title": "BlackCat a", "summary": ""},
            {"title": "BlackCat b", "summary": ""},
        ]
        gen_calls = []

        def fake_gen(name, meta):
            gen_calls.append(name)
            return {"name": name}

        with patch.object(ap, "PROFILES_PATH", profiles_path), \
             patch.object(ap, "OUTPUT_DIR", output_path), \
             patch("modules.actor_profiler._generate_single_profile", side_effect=fake_gen):
            result = generate_profiles(articles)
        assert len(gen_calls) == 1  # stopped after 1
        # One profile got created; the other actor did not.
        assert len([k for k in result if k in ("LockBit", "BlackCat")]) == 1

    def test_existing_profile_observed_ttps_refreshed(self, tmp_path):
        """Existing profiles must pick up current observations every run so
        the evidence base reflects this week's reporting, not last week's."""
        profiles_path = tmp_path / "state" / "profiles.json"
        output_path = tmp_path / "output"
        # Seed with a profile that has stale observed data.
        existing = {
            "LockBit": {
                "name": "LockBit",
                "observed_techniques": [{"id": "T9999", "count": 99}],
                "observed_tactics": [{"name": "Old", "count": 99}],
            }
        }
        profiles_path.parent.mkdir(parents=True, exist_ok=True)
        profiles_path.write_text(json.dumps(existing))
        articles = [
            {
                "title": "LockBit a", "summary": "",
                "attack_techniques": [{"id": "T1566"}],
                "attack_tactics": ["Initial Access"],
            },
            {
                "title": "LockBit b", "summary": "",
                "attack_techniques": [{"id": "T1566"}],
                "attack_tactics": ["Initial Access"],
            },
        ]
        with patch.object(ap, "PROFILES_PATH", profiles_path), \
             patch.object(ap, "OUTPUT_DIR", output_path):
            result = generate_profiles(articles)
        assert result["LockBit"]["observed_techniques"] == [{"id": "T1566", "count": 2}]
        assert result["LockBit"]["observed_tactics"] == [{"name": "Initial Access", "count": 2}]
