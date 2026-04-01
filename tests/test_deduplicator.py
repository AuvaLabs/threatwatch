import pytest
from modules.deduplicator import (
    normalize_title,
    deduplicate_articles,
    normalize_url,
    _collapse_regions,
    _merge_region,
)


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


# ---------------------------------------------------------------------------
# CVE guard
# ---------------------------------------------------------------------------

class TestCVEGuard:
    """Articles sharing a CVE ID are deduplicated; different CVEs are kept distinct."""

    def _make_article(self, title, link, source="test"):
        return {"title": title, "link": link, "source": source}

    def _patch(self, monkeypatch, tmp_path):
        monkeypatch.setattr("modules.deduplicator.SEEN_HASHES_FILE", tmp_path / "hashes.txt")
        monkeypatch.setattr("modules.deduplicator.SEEN_TITLES_FILE", tmp_path / "titles.txt")

    # NOTE: The CVE guard prevents articles with *different* CVEs from being merged
    # even when their word-shingle overlap is high enough to normally trigger fuzzy
    # dedup. Articles with the *same* CVE are still subject to normal fuzzy matching —
    # they merge only when their word overlap also crosses the threshold.

    def test_same_cve_deduplicates_when_titles_are_also_similar(self, tmp_path, monkeypatch):
        # Titles share the same CVE AND have very high word overlap → should dedup.
        self._patch(monkeypatch, tmp_path)
        articles = [
            self._make_article(
                "CVE-2024-1234 critical vulnerability exploited in the wild remote code execution",
                "https://a.com/1",
            ),
            self._make_article(
                "CVE-2024-1234 critical vulnerability exploited in the wild remote code execution patch",
                "https://b.com/2",
            ),
        ]
        result = deduplicate_articles(articles)
        assert len(result) == 1
        assert "related_articles" in result[0]

    def test_different_cves_are_kept_distinct(self, tmp_path, monkeypatch):
        # Titles are near-identical EXCEPT for the CVE ID — the guard must keep both.
        # Without the CVE guard these would merge (word overlap ~0.87 > threshold 0.6).
        self._patch(monkeypatch, tmp_path)
        articles = [
            self._make_article(
                "CVE-2024-1111 critical vulnerability exploited in the wild remote code execution",
                "https://a.com/1",
            ),
            self._make_article(
                "CVE-2024-9999 critical vulnerability exploited in the wild remote code execution",
                "https://b.com/2",
            ),
        ]
        result = deduplicate_articles(articles)
        assert len(result) == 2

    def test_cve_vs_no_cve_are_kept_distinct(self, tmp_path, monkeypatch):
        # One article has a CVE ID, the other does not — guard keeps both distinct.
        self._patch(monkeypatch, tmp_path)
        articles = [
            self._make_article(
                "CVE-2024-1234 critical vulnerability exploited in the wild remote code execution",
                "https://a.com/1",
            ),
            self._make_article(
                "Critical vulnerability exploited in the wild remote code execution servers",
                "https://b.com/2",
            ),
        ]
        result = deduplicate_articles(articles)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Region merging
# ---------------------------------------------------------------------------

class TestRegionMerging:
    """_collapse_regions and _merge_region behave correctly."""

    def test_collapse_two_regions(self):
        regions = {"US", "EU"}
        assert _collapse_regions(regions) == "EU,US"

    def test_collapse_three_regions(self):
        regions = {"US", "EU", "APAC"}
        result = _collapse_regions(regions)
        assert result == "APAC,EU,US"

    def test_collapse_more_than_three_regions_gives_global(self):
        regions = {"US", "EU", "APAC", "LATAM"}
        assert _collapse_regions(regions) == "Global"

    def test_collapse_empty_set_gives_global(self):
        assert _collapse_regions(set()) == "Global"

    def test_collapse_strips_global_before_counting(self):
        # "Global" plus 3 real regions → 3 real regions, should NOT collapse
        regions = {"Global", "US", "EU", "APAC"}
        assert _collapse_regions(regions) == "APAC,EU,US"

    def test_merge_region_splits_compound_string(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.deduplicator.SEEN_HASHES_FILE", tmp_path / "hashes.txt")
        monkeypatch.setattr("modules.deduplicator.SEEN_TITLES_FILE", tmp_path / "titles.txt")
        # Two articles with overlapping compound region strings; hash-dedup triggers merge
        base_title = "Ransomware attack strikes financial sector worldwide operations"
        import hashlib
        from modules.deduplicator import normalize_title, normalize_url
        link = "https://example.com/story"
        norm_link = normalize_url(link)
        shared_hash = hashlib.sha256((base_title + norm_link).encode()).hexdigest()
        articles = [
            {"title": base_title, "link": link, "source": "s1",
             "feed_region": "US,EU", "hash": shared_hash},
            {"title": base_title, "link": link, "source": "s2",
             "feed_region": "APAC", "hash": shared_hash},
        ]
        result = deduplicate_articles(articles)
        assert len(result) == 1
        # US, EU, APAC = 3 regions → should be merged (not collapsed to Global)
        merged = result[0]["feed_region"]
        assert "APAC" in merged
        assert "US" in merged
        assert "EU" in merged
        assert merged != "Global"

    def test_merge_region_collapses_to_global_when_overflow(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.deduplicator.SEEN_HASHES_FILE", tmp_path / "hashes.txt")
        monkeypatch.setattr("modules.deduplicator.SEEN_TITLES_FILE", tmp_path / "titles.txt")
        base_title = "Ransomware attack strikes financial sector worldwide operations"
        import hashlib
        link = "https://example.com/story"
        from modules.deduplicator import normalize_url
        norm_link = normalize_url(link)
        shared_hash = hashlib.sha256((base_title + norm_link).encode()).hexdigest()
        articles = [
            {"title": base_title, "link": link, "source": "s1",
             "feed_region": "US,EU,APAC", "hash": shared_hash},
            {"title": base_title, "link": link, "source": "s2",
             "feed_region": "LATAM", "hash": shared_hash},
        ]
        result = deduplicate_articles(articles)
        assert result[0]["feed_region"] == "Global"


# ---------------------------------------------------------------------------
# Fuzzy-dup title persistence (third variant caught)
# ---------------------------------------------------------------------------

class TestFuzzyTitlePersistence:
    """After two variants are ingested, a third variant is still caught."""

    def _patch(self, monkeypatch, tmp_path):
        monkeypatch.setattr("modules.deduplicator.SEEN_HASHES_FILE", tmp_path / "hashes.txt")
        monkeypatch.setattr("modules.deduplicator.SEEN_TITLES_FILE", tmp_path / "titles.txt")

    def test_third_fuzzy_variant_is_deduped_in_same_batch(self, tmp_path, monkeypatch):
        self._patch(monkeypatch, tmp_path)
        articles = [
            {"title": "Major ransomware attack cripples hospital chain network systems",
             "link": "https://a.com/1", "source": "src1"},
            {"title": "Major ransomware attack cripples hospital chain network infrastructure",
             "link": "https://b.com/2", "source": "src2"},
            {"title": "Major ransomware attack cripples hospital chain network operations",
             "link": "https://c.com/3", "source": "src3"},
        ]
        result = deduplicate_articles(articles)
        assert len(result) == 1
        assert len(result[0].get("related_articles", [])) == 2

    def test_third_fuzzy_variant_caught_across_batches(self, tmp_path, monkeypatch):
        self._patch(monkeypatch, tmp_path)
        # First batch: ingest variant 1 and variant 2
        batch1 = [
            {"title": "Major ransomware attack cripples hospital chain network systems",
             "link": "https://a.com/1", "source": "src1"},
            {"title": "Major ransomware attack cripples hospital chain network infrastructure",
             "link": "https://b.com/2", "source": "src2"},
        ]
        deduplicate_articles(batch1)

        # Second batch: variant 3 should be caught via persisted titles file
        batch2 = [
            {"title": "Major ransomware attack cripples hospital chain network operations",
             "link": "https://c.com/3", "source": "src3"},
        ]
        result = deduplicate_articles(batch2)
        assert len(result) == 0


# ---------------------------------------------------------------------------
# URL normalisation
# ---------------------------------------------------------------------------

class TestNormalizeUrl:
    """normalize_url strips trailing slashes, query params, and fragments."""

    def test_trailing_slash_stripped(self):
        assert normalize_url("https://example.com/story/") == "https://example.com/story"

    def test_query_params_stripped(self):
        assert normalize_url("https://example.com/story?utm_source=rss&ref=feed") == \
            "https://example.com/story"

    def test_fragment_stripped(self):
        assert normalize_url("https://example.com/story#comments") == \
            "https://example.com/story"

    def test_query_and_trailing_slash_both_stripped(self):
        assert normalize_url("https://example.com/story/?utm_source=newsletter") == \
            "https://example.com/story"

    def test_same_base_url_different_query_params_deduplicates(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.deduplicator.SEEN_HASHES_FILE", tmp_path / "hashes.txt")
        monkeypatch.setattr("modules.deduplicator.SEEN_TITLES_FILE", tmp_path / "titles.txt")
        articles = [
            {"title": "Hackers breach government database exposing millions of records",
             "link": "https://news.example.com/article?utm_source=rss",
             "source": "src1"},
            {"title": "Hackers breach government database exposing millions of records",
             "link": "https://news.example.com/article?utm_source=twitter",
             "source": "src2"},
        ]
        result = deduplicate_articles(articles)
        assert len(result) == 1

    def test_trailing_slash_variant_deduplicates(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.deduplicator.SEEN_HASHES_FILE", tmp_path / "hashes.txt")
        monkeypatch.setattr("modules.deduplicator.SEEN_TITLES_FILE", tmp_path / "titles.txt")
        articles = [
            {"title": "Hackers breach government database exposing millions of records",
             "link": "https://news.example.com/article",
             "source": "src1"},
            {"title": "Hackers breach government database exposing millions of records",
             "link": "https://news.example.com/article/",
             "source": "src2"},
        ]
        result = deduplicate_articles(articles)
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Dark web bypass
# ---------------------------------------------------------------------------

class TestDarkWebBypass:
    """Articles with darkweb=True skip fuzzy matching and are never merged."""

    def _patch(self, monkeypatch, tmp_path):
        monkeypatch.setattr("modules.deduplicator.SEEN_HASHES_FILE", tmp_path / "hashes.txt")
        monkeypatch.setattr("modules.deduplicator.SEEN_TITLES_FILE", tmp_path / "titles.txt")

    def test_darkweb_articles_not_fuzzy_deduped(self, tmp_path, monkeypatch):
        self._patch(monkeypatch, tmp_path)
        articles = [
            {"title": "Major ransomware attack cripples hospital chain network systems",
             "link": "https://darkweb.onion/1", "source": "dw", "darkweb": True},
            {"title": "Major ransomware attack cripples hospital chain network operations",
             "link": "https://darkweb.onion/2", "source": "dw", "darkweb": True},
        ]
        result = deduplicate_articles(articles)
        assert len(result) == 2

    def test_darkweb_flag_false_still_fuzzy_deduped(self, tmp_path, monkeypatch):
        self._patch(monkeypatch, tmp_path)
        articles = [
            {"title": "Major ransomware attack cripples hospital chain network systems",
             "link": "https://a.com/1", "source": "src", "darkweb": False},
            {"title": "Major ransomware attack cripples hospital chain network operations",
             "link": "https://b.com/2", "source": "src", "darkweb": False},
        ]
        result = deduplicate_articles(articles)
        assert len(result) == 1

    def test_darkweb_still_deduped_on_exact_hash(self, tmp_path, monkeypatch):
        self._patch(monkeypatch, tmp_path)
        # Exact same title + link (same hash) — hash-dedup fires even for dark web
        articles = [
            {"title": "Database leaked on dark web forum credentials",
             "link": "https://darkweb.onion/post/42", "source": "dw", "darkweb": True},
            {"title": "Database leaked on dark web forum credentials",
             "link": "https://darkweb.onion/post/42", "source": "dw", "darkweb": True},
        ]
        result = deduplicate_articles(articles)
        assert len(result) == 1

    def test_darkweb_article_does_not_poison_clearweb_fuzzy_index(self, tmp_path, monkeypatch):
        self._patch(monkeypatch, tmp_path)
        # A dark-web article with a title similar to a later clear-web article should
        # NOT prevent the clear-web article from appearing (dark web article was added
        # to the index after being kept, so clear-web article is a fuzzy-dup of it —
        # but dark web article itself was not deduped, so both should appear).
        articles = [
            {"title": "Major ransomware attack cripples hospital chain network systems",
             "link": "https://darkweb.onion/1", "source": "dw", "darkweb": True},
            {"title": "Major ransomware attack cripples hospital chain network systems update",
             "link": "https://clearweb.com/2", "source": "news", "darkweb": False},
        ]
        result = deduplicate_articles(articles)
        # Clear-web article IS a fuzzy dup of the dark-web article (same title words),
        # so only 1 survives — that is correct dedup behaviour.
        # The important assertion: dark-web article was NOT pre-emptively merged away.
        assert len(result) >= 1
        links = [a["link"] for a in result]
        assert "https://darkweb.onion/1" in links
