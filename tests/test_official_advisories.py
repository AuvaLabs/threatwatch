from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from modules.feed_fetcher import fetch_articles
from modules.official_advisories import split_and_publish_advisories


def _entry(title, link, updated, published=None):
    return {"title": title, "link": link, "updated": updated, "published": published}


def _feed(entries):
    from feedparser import FeedParserDict

    return FeedParserDict(entries=[FeedParserDict(e) for e in entries], bozo=False)


def test_official_dates_and_highest_revision_stay_out_of_news(tmp_path):
    link = "https://cert.example/advisory"
    now = datetime.now(timezone.utc)
    stamp = (now - timedelta(hours=1)).isoformat()
    published = (now - timedelta(days=2)).isoformat()
    same_page = "https://cert.example/weekly"
    entries = [
        _entry("SSA-10 V1.9", link, stamp, published),
        _entry("SSA-10 V1.10", link, stamp),
        _entry("Weekly item one", same_page + "#one", stamp),
        _entry("Weekly item two", same_page + "#two", stamp),
        _entry("No date", link + "/missing", None),
        _entry("Future date", link + "/future", (now + timedelta(days=1)).isoformat()),
        _entry("Unsafe link", "javascript:alert(1)", stamp),
    ]
    configs = [{"url": "https://cert.example/feed", "name": "ProductCERT", "official_advisory": True}]
    with patch("modules.feed_fetcher._get_session", return_value=Mock()), \
         patch("modules.feed_fetcher.feedparser.parse", return_value=_feed(entries)), \
         patch("modules.feed_fetcher.record_fetch") as health:
        items = fetch_articles(configs)
    path = tmp_path / "advisories.json"
    items.append({"title": "News"})
    assert split_and_publish_advisories(items, configs, path=path, now=now) == [{"title": "News"}]
    import json

    advisories = json.loads(path.read_text())["advisories"]
    assert len(advisories) == 3
    assert {a["url"] for a in advisories} == {link, same_page + "#one", same_page + "#two"}
    winner = next(a for a in advisories if a["url"] == link)
    assert winner["title"] == "SSA-10 V1.10"
    assert winner["published_at"] == published
    assert winner["updated_at"] == stamp
    assert health.call_args.kwargs["entry_count"] == 3


def test_cached_advisories_survive_empty_fetch_but_expire(tmp_path):
    import json

    now = datetime.now(timezone.utc)
    feed = "https://cert.example/feed"
    path = tmp_path / "advisories.json"
    configs = [{"url": feed, "official_advisory": True}]
    record = {
        "record_type": "official_advisory", "id": "advisory",
        "title": "Advisory", "url": "https://cert.example/a", "source_url": feed,
        "published_at": None, "updated_at": now.isoformat(),
    }
    split_and_publish_advisories([record], configs, path=path, now=now)
    split_and_publish_advisories([], configs, path=path, now=now + timedelta(hours=1))
    assert len(json.loads(path.read_text())["advisories"]) == 1
    split_and_publish_advisories([], configs, path=path, now=now + timedelta(days=8))
    assert json.loads(path.read_text())["advisories"] == []
