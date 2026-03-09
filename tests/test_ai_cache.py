import json
import pytest
from datetime import datetime, timezone, timedelta

from modules.ai_cache import get_cached_result, cache_result, clear_old_cache


class TestAiCache:
    def test_cache_miss(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        assert get_cached_result("nonexistent") is None

    def test_cache_roundtrip(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        data = {"is_cyber_attack": True, "category": "Malware"}
        cache_result("abc123", data)
        result = get_cached_result("abc123")
        assert result == data

    def test_corrupt_cache_returns_none(self, tmp_path, monkeypatch):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", cache_dir)

        corrupt_file = cache_dir / "corrupt.json"
        corrupt_file.write_text("not valid json{{{")
        assert get_cached_result("corrupt") is None

    def test_clear_old_cache(self, tmp_path, monkeypatch):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", cache_dir)

        old_entry = {
            "result": {"test": True},
            "cached_at": (datetime.now(timezone.utc) - timedelta(days=60)).isoformat(),
        }
        old_file = cache_dir / "old_hash.json"
        old_file.write_text(json.dumps(old_entry))

        new_entry = {
            "result": {"test": True},
            "cached_at": datetime.now(timezone.utc).isoformat(),
        }
        new_file = cache_dir / "new_hash.json"
        new_file.write_text(json.dumps(new_entry))

        clear_old_cache(max_age_days=30)
        assert not old_file.exists()
        assert new_file.exists()
