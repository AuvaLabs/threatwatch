import pytest
from modules.deduplicator import normalize_title, deduplicate_articles


class TestNormalizeTitle:
    def test_lowercase_and_strip(self):
        assert normalize_title("  HELLO WORLD  ") == "hello world"

    def test_strips_punctuation(self):
        assert normalize_title("Hello, World!") == "hello world"

    def test_strips_breaking_prefix(self):
        assert normalize_title("Breaking: Major breach found") == "major breach found"

    def test_strips_update_prefix(self):
        assert normalize_title("Update: Patch released") == "patch released"

    def test_collapses_whitespace(self):
        assert normalize_title("too   many   spaces") == "too many spaces"

    def test_empty_string(self):
        assert normalize_title("") == ""


class TestDeduplicateArticles:
    def _make_article(self, title, link="https://example.com", source="test"):
        return {"title": title, "link": link, "source": source}

    def test_removes_exact_title_duplicates(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "modules.deduplicator.SEEN_HASHES_FILE", tmp_path / "hashes.txt"
        )
        monkeypatch.setattr(
            "modules.deduplicator.SEEN_TITLES_FILE", tmp_path / "titles.txt"
        )

        articles = [
            self._make_article("Big Breach at Corp", "https://a.com"),
            self._make_article("Big Breach at Corp", "https://b.com"),
        ]
        result = deduplicate_articles(articles)
        assert len(result) == 1

    def test_removes_fuzzy_duplicates(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "modules.deduplicator.SEEN_HASHES_FILE", tmp_path / "hashes.txt"
        )
        monkeypatch.setattr(
            "modules.deduplicator.SEEN_TITLES_FILE", tmp_path / "titles.txt"
        )

        articles = [
            self._make_article("Major ransomware attack hits hospital chain", "https://a.com"),
            self._make_article("Major ransomware attack hits hospital chain network", "https://b.com"),
        ]
        result = deduplicate_articles(articles)
        assert len(result) == 1
        assert "related_articles" in result[0]

    def test_keeps_different_articles(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "modules.deduplicator.SEEN_HASHES_FILE", tmp_path / "hashes.txt"
        )
        monkeypatch.setattr(
            "modules.deduplicator.SEEN_TITLES_FILE", tmp_path / "titles.txt"
        )

        articles = [
            self._make_article("Ransomware hits hospital", "https://a.com"),
            self._make_article("Phishing targets banks", "https://b.com"),
        ]
        result = deduplicate_articles(articles)
        assert len(result) == 2

    def test_persists_hashes(self, tmp_path, monkeypatch):
        hashes_file = tmp_path / "hashes.txt"
        monkeypatch.setattr("modules.deduplicator.SEEN_HASHES_FILE", hashes_file)
        monkeypatch.setattr(
            "modules.deduplicator.SEEN_TITLES_FILE", tmp_path / "titles.txt"
        )

        articles = [self._make_article("Test Article", "https://a.com")]
        deduplicate_articles(articles)
        assert hashes_file.exists()
        assert len(hashes_file.read_text().strip().split("\n")) >= 1
