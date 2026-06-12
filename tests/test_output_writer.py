import json
import pytest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree

from modules.output_writer import _merge_articles
from modules.config import FEED_CUTOFF_DAYS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_article(hash_val, days_ago=0, **extra):
    ts = datetime.now(timezone.utc) - timedelta(days=days_ago)
    article = {
        "hash": hash_val,
        "title": f"Article {hash_val}",
        "timestamp": ts.isoformat(),
    }
    article.update(extra)
    return article


# ---------------------------------------------------------------------------
# _merge_articles (existing tests kept + extended)
# ---------------------------------------------------------------------------

class TestMergeArticles:
    def test_new_articles_take_priority_in_ordering(self):
        existing = [_make_article("old", days_ago=1)]
        new = [_make_article("new")]
        merged = _merge_articles(existing, new)
        assert merged[0]["hash"] == "new"

    def test_deduplication_by_hash(self):
        existing = [_make_article("abc")]
        new = [_make_article("abc")]
        merged = _merge_articles(existing, new)
        assert len(merged) == 1

    def test_drops_articles_beyond_cutoff(self):
        old = _make_article("old", days_ago=FEED_CUTOFF_DAYS + 2)
        fresh = _make_article("fresh")
        merged = _merge_articles([old], [fresh])
        hashes = [a["hash"] for a in merged]
        assert "fresh" in hashes
        assert "old" not in hashes

    def test_keeps_articles_within_cutoff(self):
        recent = _make_article("recent", days_ago=FEED_CUTOFF_DAYS - 1)
        merged = _merge_articles([], [recent])
        assert len(merged) == 1

    def test_empty_inputs(self):
        assert _merge_articles([], []) == []

    def test_sorted_newest_first(self):
        a1 = _make_article("a1", days_ago=2)
        a2 = _make_article("a2", days_ago=0)
        merged = _merge_articles([a1], [a2])
        assert merged[0]["hash"] == "a2"

    def test_article_without_hash_is_excluded(self):
        article = {"title": "No hash", "timestamp": datetime.now(timezone.utc).isoformat()}
        merged = _merge_articles([], [article])
        assert len(merged) == 0

    def test_article_without_timestamp_is_kept(self):
        article = {"hash": "no-ts", "title": "No timestamp"}
        merged = _merge_articles([], [article])
        assert len(merged) == 1

    def test_no_duplicate_when_same_hash_in_both(self):
        article = _make_article("dup")
        merged = _merge_articles([article], [article])
        assert len(merged) == 1

    def test_preserves_all_fields(self):
        article = {
            "hash": "full",
            "title": "Full Article",
            "link": "https://example.com",
            "category": "Ransomware",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        merged = _merge_articles([], [article])
        assert merged[0]["category"] == "Ransomware"
        assert merged[0]["link"] == "https://example.com"

    def test_multiple_new_articles_all_kept(self):
        new = [_make_article(f"h{i}") for i in range(5)]
        merged = _merge_articles([], new)
        assert len(merged) == 5

    def test_existing_only_added_when_no_new(self):
        existing = [_make_article("ex1"), _make_article("ex2")]
        merged = _merge_articles(existing, [])
        assert len(merged) == 2

    def test_article_at_exact_cutoff_boundary_is_kept(self):
        # Article at exactly (cutoff - 1) hours should survive
        ts = datetime.now(timezone.utc) - timedelta(days=FEED_CUTOFF_DAYS - 1)
        article = {"hash": "boundary", "title": "Boundary", "timestamp": ts.isoformat()}
        merged = _merge_articles([], [article])
        assert len(merged) == 1

    def test_invalid_timestamp_article_is_kept(self):
        article = {"hash": "badts", "title": "Bad TS", "timestamp": "not-a-date"}
        merged = _merge_articles([], [article])
        assert len(merged) == 1


# ---------------------------------------------------------------------------
# _write_json
# ---------------------------------------------------------------------------

class TestWriteJson:
    def test_basic_write_creates_file(self, tmp_path):
        from modules.output_writer import _write_json
        target = tmp_path / "out" / "data.json"
        data = [{"hash": "abc", "title": "Test"}]
        _write_json(data, target)
        assert target.exists()

    def test_written_content_is_valid_json(self, tmp_path):
        from modules.output_writer import _write_json
        target = tmp_path / "data.json"
        data = [{"hash": "x", "title": "Hello"}]
        _write_json(data, target)
        loaded = json.loads(target.read_text(encoding="utf-8"))
        assert loaded == data

    def test_creates_missing_parent_directories(self, tmp_path):
        from modules.output_writer import _write_json
        target = tmp_path / "a" / "b" / "c" / "file.json"
        _write_json([], target)
        assert target.exists()

    def test_unicode_content_preserved(self, tmp_path):
        from modules.output_writer import _write_json
        target = tmp_path / "unicode.json"
        data = [{"hash": "u1", "title": "Атака на сервер"}]
        _write_json(data, target)
        loaded = json.loads(target.read_text(encoding="utf-8"))
        assert loaded[0]["title"] == "Атака на сервер"

    def test_overwrites_existing_file(self, tmp_path):
        from modules.output_writer import _write_json
        target = tmp_path / "overwrite.json"
        _write_json([{"hash": "old"}], target)
        _write_json([{"hash": "new"}], target)
        loaded = json.loads(target.read_text(encoding="utf-8"))
        assert len(loaded) == 1
        assert loaded[0]["hash"] == "new"

    def test_empty_list_writes_empty_array(self, tmp_path):
        from modules.output_writer import _write_json
        target = tmp_path / "empty.json"
        _write_json([], target)
        loaded = json.loads(target.read_text(encoding="utf-8"))
        assert loaded == []


# ---------------------------------------------------------------------------
# _load_existing
# ---------------------------------------------------------------------------

class TestLoadExisting:
    def test_missing_file_returns_empty_list(self, tmp_path):
        from modules.output_writer import _load_existing
        result = _load_existing(tmp_path / "nonexistent.json")
        assert result == []

    def test_corrupt_json_returns_empty_list(self, tmp_path):
        from modules.output_writer import _load_existing
        bad_file = tmp_path / "corrupt.json"
        bad_file.write_text("{ not valid json !!!", encoding="utf-8")
        result = _load_existing(bad_file)
        assert result == []

    def test_valid_file_returns_list(self, tmp_path):
        from modules.output_writer import _load_existing
        valid_file = tmp_path / "valid.json"
        data = [{"hash": "h1", "title": "Article 1"}]
        valid_file.write_text(json.dumps(data), encoding="utf-8")
        result = _load_existing(valid_file)
        assert result == data

    def test_json_object_instead_of_list_returns_empty(self, tmp_path):
        from modules.output_writer import _load_existing
        obj_file = tmp_path / "object.json"
        obj_file.write_text(json.dumps({"key": "value"}), encoding="utf-8")
        result = _load_existing(obj_file)
        assert result == []

    def test_empty_list_json_returns_empty_list(self, tmp_path):
        from modules.output_writer import _load_existing
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("[]", encoding="utf-8")
        result = _load_existing(empty_file)
        assert result == []

    def test_valid_file_preserves_all_fields(self, tmp_path):
        from modules.output_writer import _load_existing
        valid_file = tmp_path / "full.json"
        data = [{"hash": "h1", "title": "T", "link": "https://example.com", "category": "Malware"}]
        valid_file.write_text(json.dumps(data), encoding="utf-8")
        result = _load_existing(valid_file)
        assert result[0]["category"] == "Malware"


# ---------------------------------------------------------------------------
# _parse_pub_date
# ---------------------------------------------------------------------------

class TestParsePubDate:
    def test_rfc2822_format(self):
        from modules.output_writer import _parse_pub_date
        result = _parse_pub_date("Thu, 20 Mar 2026 12:00:00 +0000")
        assert result.year == 2026
        assert result.month == 3
        assert result.day == 20

    def test_iso8601_with_timezone(self):
        from modules.output_writer import _parse_pub_date
        result = _parse_pub_date("2026-03-20T12:00:00+00:00")
        assert result.year == 2026
        assert result.tzinfo is not None

    def test_iso8601_without_timezone_gets_utc(self):
        from modules.output_writer import _parse_pub_date
        result = _parse_pub_date("2026-03-20T12:00:00")
        assert result.tzinfo is not None

    def test_datetime_string_with_space(self):
        from modules.output_writer import _parse_pub_date
        result = _parse_pub_date("2026-03-20 12:00:00")
        assert result.year == 2026
        assert result.tzinfo is not None

    def test_date_only_string(self):
        from modules.output_writer import _parse_pub_date
        result = _parse_pub_date("2026-03-20")
        assert result.year == 2026
        assert result.tzinfo is not None

    def test_datetime_with_microseconds(self):
        from modules.output_writer import _parse_pub_date
        result = _parse_pub_date("2026-03-20 12:00:00.123456")
        assert result.year == 2026
        assert result.tzinfo is not None

    def test_invalid_string_falls_back_to_now(self):
        from modules.output_writer import _parse_pub_date
        before = datetime.now(timezone.utc)
        result = _parse_pub_date("not-a-date-at-all")
        after = datetime.now(timezone.utc)
        assert before <= result <= after

    def test_empty_string_falls_back_to_now(self):
        from modules.output_writer import _parse_pub_date
        before = datetime.now(timezone.utc)
        result = _parse_pub_date("")
        after = datetime.now(timezone.utc)
        assert before <= result <= after

    def test_returns_datetime_object(self):
        from modules.output_writer import _parse_pub_date
        result = _parse_pub_date("2026-03-20T09:00:00Z")
        assert isinstance(result, datetime)


# ---------------------------------------------------------------------------
# write_hourly_output
# ---------------------------------------------------------------------------

class TestWriteHourlyOutput:
    def test_creates_timestamped_file(self, tmp_path):
        import modules.output_writer as ow
        hourly_dir = tmp_path / "hourly"
        static_file = tmp_path / "hourly_latest.json"
        articles = [_make_article("h1")]

        with patch.object(ow, "HOURLY_DIR", hourly_dir), \
             patch.object(ow, "STATIC_HOURLY", static_file):
            ow.write_hourly_output(articles)

        files = list(hourly_dir.iterdir())
        assert len(files) == 1
        assert files[0].suffix == ".json"

    def test_creates_static_latest_file(self, tmp_path):
        import modules.output_writer as ow
        hourly_dir = tmp_path / "hourly"
        static_file = tmp_path / "hourly_latest.json"
        articles = [_make_article("h1")]

        with patch.object(ow, "HOURLY_DIR", hourly_dir), \
             patch.object(ow, "STATIC_HOURLY", static_file):
            ow.write_hourly_output(articles)

        assert static_file.exists()

    def test_timestamped_file_contains_articles(self, tmp_path):
        import modules.output_writer as ow
        hourly_dir = tmp_path / "hourly"
        static_file = tmp_path / "hourly_latest.json"
        articles = [_make_article("h1"), _make_article("h2")]

        with patch.object(ow, "HOURLY_DIR", hourly_dir), \
             patch.object(ow, "STATIC_HOURLY", static_file):
            ow.write_hourly_output(articles)

        written = json.loads(list(hourly_dir.iterdir())[0].read_text())
        assert len(written) == 2

    def test_merges_with_existing_static_file(self, tmp_path):
        import modules.output_writer as ow
        hourly_dir = tmp_path / "hourly"
        static_file = tmp_path / "hourly_latest.json"

        # Pre-populate the static file with one article
        existing = [_make_article("existing")]
        static_file.write_text(json.dumps(existing), encoding="utf-8")

        new_articles = [_make_article("new-one")]

        with patch.object(ow, "HOURLY_DIR", hourly_dir), \
             patch.object(ow, "STATIC_HOURLY", static_file):
            ow.write_hourly_output(new_articles)

        merged = json.loads(static_file.read_text())
        hashes = {a["hash"] for a in merged}
        assert "existing" in hashes
        assert "new-one" in hashes

    def test_deduplicates_in_static_file(self, tmp_path):
        import modules.output_writer as ow
        hourly_dir = tmp_path / "hourly"
        static_file = tmp_path / "hourly_latest.json"

        article = _make_article("dup")
        static_file.write_text(json.dumps([article]), encoding="utf-8")

        with patch.object(ow, "HOURLY_DIR", hourly_dir), \
             patch.object(ow, "STATIC_HOURLY", static_file):
            ow.write_hourly_output([article])

        merged = json.loads(static_file.read_text())
        assert len(merged) == 1


# ---------------------------------------------------------------------------
# write_daily_output
# ---------------------------------------------------------------------------

class TestWriteDailyOutput:
    def test_creates_date_named_file(self, tmp_path):
        import modules.output_writer as ow
        daily_dir = tmp_path / "daily"
        static_file = tmp_path / "daily_latest.json"
        articles = [_make_article("d1")]

        with patch.object(ow, "DAILY_DIR", daily_dir), \
             patch.object(ow, "STATIC_DAILY", static_file):
            ow.write_daily_output(articles)

        files = list(daily_dir.iterdir())
        assert len(files) == 1
        # File name should be YYYY-MM-DD.json
        assert files[0].stem.count("-") == 2

    def test_creates_static_daily_file(self, tmp_path):
        import modules.output_writer as ow
        daily_dir = tmp_path / "daily"
        static_file = tmp_path / "daily_latest.json"

        with patch.object(ow, "DAILY_DIR", daily_dir), \
             patch.object(ow, "STATIC_DAILY", static_file):
            ow.write_daily_output([_make_article("d1")])

        assert static_file.exists()

    def test_daily_file_contains_all_articles(self, tmp_path):
        import modules.output_writer as ow
        daily_dir = tmp_path / "daily"
        static_file = tmp_path / "daily_latest.json"
        articles = [_make_article(f"d{i}") for i in range(3)]

        with patch.object(ow, "DAILY_DIR", daily_dir), \
             patch.object(ow, "STATIC_DAILY", static_file):
            ow.write_daily_output(articles)

        written = json.loads(list(daily_dir.iterdir())[0].read_text())
        assert len(written) == 3

    def test_merges_with_existing_static_daily(self, tmp_path):
        import modules.output_writer as ow
        daily_dir = tmp_path / "daily"
        static_file = tmp_path / "daily_latest.json"

        existing = [_make_article("day-old")]
        static_file.write_text(json.dumps(existing), encoding="utf-8")

        with patch.object(ow, "DAILY_DIR", daily_dir), \
             patch.object(ow, "STATIC_DAILY", static_file):
            ow.write_daily_output([_make_article("day-new")])

        merged = json.loads(static_file.read_text())
        hashes = {a["hash"] for a in merged}
        assert "day-old" in hashes
        assert "day-new" in hashes

    def test_empty_articles_still_creates_files(self, tmp_path):
        import modules.output_writer as ow
        daily_dir = tmp_path / "daily"
        static_file = tmp_path / "daily_latest.json"

        with patch.object(ow, "DAILY_DIR", daily_dir), \
             patch.object(ow, "STATIC_DAILY", static_file):
            ow.write_daily_output([])

        assert static_file.exists()
        assert list(daily_dir.iterdir())


# ---------------------------------------------------------------------------
# write_rss_output
# ---------------------------------------------------------------------------

class TestWriteRssOutput:
    def _run_rss(self, tmp_path, articles):
        import modules.output_writer as ow
        rss_path = tmp_path / "rss_cyberattacks.xml"
        with patch.object(ow, "RSS_PATH", rss_path):
            ow.write_rss_output(articles)
        return rss_path

    def test_creates_rss_file(self, tmp_path):
        rss_path = self._run_rss(tmp_path, [])
        assert rss_path.exists()

    def test_rss_is_valid_xml(self, tmp_path):
        articles = [
            {
                "title": "Test Attack",
                "link": "https://example.com/attack",
                "summary": "Some summary.",
                "published": "2026-03-20T12:00:00+00:00",
                "category": "Ransomware",
            }
        ]
        rss_path = self._run_rss(tmp_path, articles)
        # Should not raise
        tree = ElementTree.parse(str(rss_path))
        assert tree is not None

    def test_rss_contains_channel_element(self, tmp_path):
        rss_path = self._run_rss(tmp_path, [])
        tree = ElementTree.parse(str(rss_path))
        root = tree.getroot()
        assert root.tag == "rss"
        channel = root.find("channel")
        assert channel is not None

    def test_rss_item_has_guid_equal_to_link(self, tmp_path):
        link = "https://example.com/article-1"
        articles = [
            {
                "title": "GUID Test",
                "link": link,
                "summary": "Summary.",
                "published": "2026-03-20T12:00:00+00:00",
            }
        ]
        rss_path = self._run_rss(tmp_path, articles)
        tree = ElementTree.parse(str(rss_path))
        root = tree.getroot()
        item = root.find("channel/item")
        guid = item.find("guid")
        assert guid is not None
        assert guid.text == link

    def test_rss_item_has_category(self, tmp_path):
        articles = [
            {
                "title": "Cat Test",
                "link": "https://example.com/cat",
                "summary": "Summary.",
                "published": "2026-03-20T12:00:00+00:00",
                "category": "Malware",
            }
        ]
        rss_path = self._run_rss(tmp_path, articles)
        tree = ElementTree.parse(str(rss_path))
        root = tree.getroot()
        item = root.find("channel/item")
        category = item.find("category")
        assert category is not None
        assert category.text == "Malware"

    def test_rss_item_title_present(self, tmp_path):
        articles = [
            {
                "title": "Big Breach",
                "link": "https://example.com/breach",
                "summary": "Details here.",
                "published": "2026-03-20T12:00:00+00:00",
            }
        ]
        rss_path = self._run_rss(tmp_path, articles)
        tree = ElementTree.parse(str(rss_path))
        root = tree.getroot()
        item = root.find("channel/item")
        title = item.find("title")
        assert title is not None
        assert title.text == "Big Breach"

    def test_rss_multiple_articles(self, tmp_path):
        articles = [
            {
                "title": f"Article {i}",
                "link": f"https://example.com/{i}",
                "summary": "Summary.",
                "published": "2026-03-20T12:00:00+00:00",
            }
            for i in range(3)
        ]
        rss_path = self._run_rss(tmp_path, articles)
        tree = ElementTree.parse(str(rss_path))
        root = tree.getroot()
        items = root.findall("channel/item")
        assert len(items) == 3

    def test_rss_no_category_field_omits_category_element(self, tmp_path):
        articles = [
            {
                "title": "No Cat",
                "link": "https://example.com/nocat",
                "summary": "Summary.",
                "published": "2026-03-20T12:00:00+00:00",
                # no "category" key
            }
        ]
        rss_path = self._run_rss(tmp_path, articles)
        tree = ElementTree.parse(str(rss_path))
        root = tree.getroot()
        item = root.find("channel/item")
        category = item.find("category")
        assert category is None

    def test_rss_fallback_title_for_missing_title(self, tmp_path):
        articles = [
            {
                "link": "https://example.com/notitle",
                "summary": "Summary.",
                "published": "2026-03-20T12:00:00+00:00",
            }
        ]
        rss_path = self._run_rss(tmp_path, articles)
        tree = ElementTree.parse(str(rss_path))
        root = tree.getroot()
        item = root.find("channel/item")
        title = item.find("title")
        assert title.text == "No Title"

    def test_rss_fallback_summary_for_missing_summary(self, tmp_path):
        articles = [
            {
                "title": "No Summary",
                "link": "https://example.com/nosummary",
                "published": "2026-03-20T12:00:00+00:00",
            }
        ]
        rss_path = self._run_rss(tmp_path, articles)
        tree = ElementTree.parse(str(rss_path))
        root = tree.getroot()
        item = root.find("channel/item")
        desc = item.find("description")
        assert desc is not None
        assert "No summary available" in desc.text

    def test_rss_with_invalid_pub_date_still_creates_file(self, tmp_path):
        articles = [
            {
                "title": "Bad Date",
                "link": "https://example.com/baddate",
                "summary": "Summary.",
                "published": "not-a-real-date",
            }
        ]
        rss_path = self._run_rss(tmp_path, articles)
        assert rss_path.exists()


# ---------------------------------------------------------------------------
# Time-integrity policy (Phase 3 overhaul): publication date is authoritative
# ---------------------------------------------------------------------------

class TestMergeTimeIntegrity:
    def test_sorted_by_published_not_ingestion_time(self):
        """An old article re-enriched today (fresh timestamp) must NOT outrank
        genuinely newer news."""
        now = datetime.now(timezone.utc)
        old_news_reenriched = {
            "hash": "old-news",
            "title": "Old incident",
            "published": (now - timedelta(days=5)).isoformat(),
            "ingested_at": now.isoformat(),
            "timestamp": now.isoformat(),
        }
        fresh_news = {
            "hash": "fresh-news",
            "title": "Fresh incident",
            "published": (now - timedelta(hours=1)).isoformat(),
            "ingested_at": (now - timedelta(hours=1)).isoformat(),
            "timestamp": (now - timedelta(hours=1)).isoformat(),
        }
        merged = _merge_articles([old_news_reenriched], [fresh_news])
        assert [a["hash"] for a in merged] == ["fresh-news", "old-news"]

    def test_cutoff_judges_by_published_when_available(self):
        """Stale published date drops the article even if it was ingested
        five minutes ago."""
        now = datetime.now(timezone.utc)
        stale = {
            "hash": "stale",
            "title": "Stale event",
            "published": (now - timedelta(days=FEED_CUTOFF_DAYS + 3)).isoformat(),
            "ingested_at": now.isoformat(),
            "timestamp": now.isoformat(),
        }
        assert _merge_articles([], [stale]) == []

    def test_corrupt_published_falls_back_to_ingestion_not_dropped(self):
        """A fresh article whose feed shipped garbage in `published` must be
        kept (judged by ingestion time), not silently discarded."""
        now = datetime.now(timezone.utc)
        corrupt = {
            "hash": "corrupt-date",
            "title": "Fresh event, bad date",
            "published": "not-a-date",
            "ingested_at": now.isoformat(),
            "timestamp": now.isoformat(),
        }
        merged = _merge_articles([], [corrupt])
        assert [a["hash"] for a in merged] == ["corrupt-date"]

    def test_no_parseable_dates_at_all_is_kept(self):
        merged = _merge_articles([], [{"hash": "undated", "title": "Undated"}])
        assert [a["hash"] for a in merged] == ["undated"]


class TestRssPubDateHonesty:
    def test_unparseable_published_uses_ingestion_time_not_now(self, tmp_path):
        """RSS pubDate for a corrupt-date article must be the (stable)
        ingestion time, not the moment the feed file was regenerated."""
        from modules import output_writer as ow
        ingested = datetime.now(timezone.utc) - timedelta(days=2)
        articles = [{
            "hash": "x",
            "title": "Corrupt date article",
            "link": "https://example.test/a",
            "published": "garbage",
            "ingested_at": ingested.isoformat(),
        }]
        with patch.object(ow, "RSS_PATH", tmp_path / "rss.xml"):
            ow.write_rss_output(articles)
            tree = ElementTree.parse(tmp_path / "rss.xml")
        pub = tree.find(".//item/pubDate").text
        from email.utils import parsedate_to_datetime
        assert abs((parsedate_to_datetime(pub) - ingested).total_seconds()) < 2
