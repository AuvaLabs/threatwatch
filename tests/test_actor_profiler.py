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
