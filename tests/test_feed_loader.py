import pytest
from modules.feed_loader import load_feeds_from_files


class TestLoadFeeds:
    def test_loads_yaml_list(self, tmp_path):
        feed_file = tmp_path / "feeds.yaml"
        feed_file.write_text(
            "- url: https://example.com/rss\n  category: Test\n  region: Global\n"
        )
        result = load_feeds_from_files([str(feed_file)])
        assert len(result) == 1
        assert result[0]["url"] == "https://example.com/rss"

    def test_handles_missing_file(self, tmp_path):
        result = load_feeds_from_files([str(tmp_path / "nonexistent.yaml")])
        assert result == []

    def test_loads_multiple_files(self, tmp_path):
        f1 = tmp_path / "a.yaml"
        f2 = tmp_path / "b.yaml"
        f1.write_text("- url: https://a.com/rss\n  category: A\n")
        f2.write_text("- url: https://b.com/rss\n  category: B\n")

        result = load_feeds_from_files([str(f1), str(f2)])
        assert len(result) == 2
