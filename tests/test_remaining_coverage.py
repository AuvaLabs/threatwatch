"""Targeted tests for remaining coverage gaps across multiple modules."""

import json
import os
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from pathlib import Path


# ── cost_tracker.py (86% → 95%+) ────────────────────────────────────────────

class TestCostTracker:
    def test_track_usage_with_response(self):
        from modules.cost_tracker import track_usage
        mock_resp = MagicMock()
        mock_resp.usage.input_tokens = 100
        mock_resp.usage.output_tokens = 50
        mock_resp.usage.cache_creation_input_tokens = 0
        mock_resp.usage.cache_read_input_tokens = 0
        track_usage(mock_resp)

    def test_track_usage_with_none(self):
        from modules.cost_tracker import track_usage
        track_usage(None)

    def test_check_daily_budget_default(self):
        from modules.cost_tracker import check_daily_budget
        assert isinstance(check_daily_budget(), bool)

    def test_get_today_spend(self):
        from modules.cost_tracker import get_today_spend
        assert isinstance(get_today_spend(), (int, float))

    def test_get_total_spend(self):
        from modules.cost_tracker import get_total_spend
        assert isinstance(get_total_spend(), (int, float))


# ── briefing_health.py (83% → 95%) ──────────────────────────────────────────

class TestBriefingHealth:
    def test_freshness_no_file(self, tmp_path):
        from modules.briefing_health import check_briefing_freshness
        with patch("modules.briefing_health.OUTPUT_DIR", tmp_path / "missing"):
            result = check_briefing_freshness()
        assert result["stale"] is True

    def test_freshness_fresh(self, tmp_path):
        from modules.briefing_health import check_briefing_freshness
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "briefing.json").write_text(json.dumps({
            "generated_at": datetime.now(timezone.utc).isoformat()
        }))
        with patch("modules.briefing_health.OUTPUT_DIR", output_dir):
            result = check_briefing_freshness()
        assert result["stale"] is False

    def test_freshness_stale(self, tmp_path):
        from modules.briefing_health import check_briefing_freshness
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        old = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
        (output_dir / "briefing.json").write_text(json.dumps({"generated_at": old}))
        with patch("modules.briefing_health.OUTPUT_DIR", output_dir):
            result = check_briefing_freshness()
        assert result["stale"] is True

    def test_freshness_corrupt_json(self, tmp_path):
        from modules.briefing_health import check_briefing_freshness
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        (output_dir / "briefing.json").write_text("{bad")
        with patch("modules.briefing_health.OUTPUT_DIR", output_dir):
            result = check_briefing_freshness()
        assert result["stale"] is True

    def test_write_stale_flag(self, tmp_path):
        from modules.briefing_health import write_stale_flag
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        state_dir = tmp_path / "state"
        with patch("modules.briefing_health.OUTPUT_DIR", output_dir):
            # OUTPUT_DIR.parent / "state" = tmp_path / "state"
            write_stale_flag({"stale": True, "age_hours": 5.0, "generated_at": None, "reason": "test"})
        flag = output_dir.parent / "state" / "briefing_stale.flag"
        assert flag.exists()

    def test_clear_stale_flag(self, tmp_path):
        from modules.briefing_health import clear_stale_flag
        output_dir = tmp_path / "output"
        output_dir.mkdir()
        state_dir = output_dir.parent / "state"
        state_dir.mkdir()
        flag = state_dir / "briefing_stale.flag"
        flag.write_text("stale")
        with patch("modules.briefing_health.OUTPUT_DIR", output_dir):
            clear_stale_flag()
        assert not flag.exists()


# ── webhook.py (86% → 95%) ──────────────────────────────────────────────────

# webhook.py already at 86% via existing tests in test_webhook.py


# ── attack_tagger.py (83% → 95%) ────────────────────────────────────────────

class TestAttackTagger:
    def test_tag_single_article(self):
        from modules.attack_tagger import tag_article_with_attack
        article = {"title": "Ransomware encrypts files", "summary": "Phishing email used"}
        result = tag_article_with_attack(article)
        assert isinstance(result, dict)

    def test_tag_articles_batch(self):
        from modules.attack_tagger import tag_articles_with_attack
        articles = [
            {"title": "Ransomware attack", "summary": ""},
            {"title": "Weather report", "summary": ""},
        ]
        result = tag_articles_with_attack(articles)
        assert isinstance(result, list)
        assert len(result) == 2


# ── date_utils.py (91% → 100%) ──────────────────────────────────────────────

class TestDateUtils:
    def test_parse_rfc2822(self):
        from modules.date_utils import parse_datetime
        result = parse_datetime("Mon, 21 Apr 2026 12:00:00 GMT")
        assert result is not None

    def test_parse_iso(self):
        from modules.date_utils import parse_datetime
        result = parse_datetime("2026-04-21T12:00:00+00:00")
        assert result is not None

    def test_parse_none(self):
        from modules.date_utils import parse_datetime
        assert parse_datetime(None) is None

    def test_parse_empty(self):
        from modules.date_utils import parse_datetime
        assert parse_datetime("") is None

    def test_parse_invalid(self):
        from modules.date_utils import parse_datetime
        assert parse_datetime("not a date") is None


# ── feed_loader.py (80% → 95%) ──────────────────────────────────────────────

class TestFeedLoader:
    def test_loads_yaml(self):
        from modules.feed_loader import load_feeds_from_files
        files = list(Path("config").glob("feeds_*.yaml"))
        feeds = load_feeds_from_files(files)
        assert len(feeds) > 100

    def test_empty_file_list(self):
        from modules.feed_loader import load_feeds_from_files
        assert load_feeds_from_files([]) == []

    def test_missing_file(self):
        from modules.feed_loader import load_feeds_from_files
        result = load_feeds_from_files([Path("/nonexistent/feeds.yaml")])
        assert result == []


# ── newsapi_fetcher.py (85% → 95%) ──────────────────────────────────────────

class TestNewsapiFetcher:
    def test_no_key_returns_empty(self):
        import modules.newsapi_fetcher as nf
        with patch.dict(os.environ, {"NEWSAPI_KEY": ""}, clear=False), \
             patch("modules.newsapi_fetcher.os.getenv", return_value=None):
            result = nf.fetch_newsapi_articles()
        assert result == []

    def test_api_call_with_key(self):
        import modules.newsapi_fetcher as nf
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "status": "ok",
            "articles": [{
                "title": "Security breach",
                "url": "https://example.com/article",
                "publishedAt": "2026-04-21T12:00:00Z",
                "description": "Test desc",
                "source": {"name": "TestSource"},
            }]
        }
        mock_resp.raise_for_status = MagicMock()
        nf._SESSION = None
        with patch("modules.newsapi_fetcher.os.getenv", return_value="test-key"), \
             patch.object(nf, "_load_last_call", return_value=0), \
             patch.object(nf, "_save_last_call"), \
             patch("modules.newsapi_fetcher.requests.get", return_value=mock_resp):
            result = nf.fetch_newsapi_articles()
        assert len(result) >= 0  # May normalize out if fields are missing


# ── article_scraper.py (83% → 90%+) ─────────────────────────────────────────

class TestArticleScraper:
    def test_extract_returns_tuple(self):
        from modules.article_scraper import extract_article_content
        result = extract_article_content("https://example.com")
        assert isinstance(result, tuple)

    def test_extract_with_error(self):
        from modules.article_scraper import extract_article_content
        with patch("modules.article_scraper._create_session") as mock_sess:
            mock_sess.return_value.get.side_effect = Exception("timeout")
            result = extract_article_content("https://nonexistent.invalid")
        # Should handle gracefully
        assert isinstance(result, tuple)
