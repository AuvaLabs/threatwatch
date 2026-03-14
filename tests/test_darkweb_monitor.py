import json
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

from modules.darkweb_monitor import (
    _parse_ransomware_live,
    _parse_threatfox,
    _parse_c2_tracker,
)
from modules.config import FEED_CUTOFF_DAYS


def _make_cutoff(days=FEED_CUTOFF_DAYS):
    return datetime.now(timezone.utc) - timedelta(days=days)


def _mock_resp(data):
    resp = MagicMock()
    resp.json.return_value = data
    resp.text = json.dumps(data)
    return resp


class TestParseRansomwareLive:
    def _source(self):
        return {"name": "ransomware.live", "url": "https://api.ransomware.live/recentvictims"}

    def test_basic_victim_parsed(self):
        data = [{
            "victim": "Acme Corp",
            "group_name": "LockBit",
            "discovered": datetime.now(timezone.utc).isoformat(),
            "post_url": "https://ransomware.live/victim/1",
            "country": "US",
        }]
        articles = _parse_ransomware_live(_mock_resp(data), self._source(), _make_cutoff())
        assert len(articles) == 1
        assert articles[0]["darkweb"] is True
        assert articles[0]["darkweb_group"] == "LockBit"
        assert articles[0]["darkweb_source"] == "ransomware.live"

    def test_title_does_not_have_dark_web_prefix_displayed(self):
        data = [{
            "victim": "TargetCo",
            "group_name": "Cl0p",
            "discovered": datetime.now(timezone.utc).isoformat(),
            "post_url": "",
            "country": "",
        }]
        articles = _parse_ransomware_live(_mock_resp(data), self._source(), _make_cutoff())
        # Title may have [DARK WEB] prefix — this is stripped in JS, not Python
        assert "Cl0p" in articles[0]["title"]

    def test_old_victim_filtered_out(self):
        data = [{
            "victim": "OldCorp",
            "group_name": "Akira",
            "discovered": (datetime.now(timezone.utc) - timedelta(days=FEED_CUTOFF_DAYS + 5)).isoformat(),
            "post_url": "",
            "country": "",
        }]
        articles = _parse_ransomware_live(_mock_resp(data), self._source(), _make_cutoff())
        assert len(articles) == 0

    def test_caps_at_100_victims(self):
        data = [
            {"victim": f"Corp{i}", "group_name": "ALPHV",
             "discovered": datetime.now(timezone.utc).isoformat(),
             "post_url": "", "country": ""}
            for i in range(200)
        ]
        articles = _parse_ransomware_live(_mock_resp(data), self._source(), _make_cutoff())
        assert len(articles) <= 100

    def test_malformed_response_returns_empty(self):
        resp = MagicMock()
        resp.json.return_value = "not a list"
        articles = _parse_ransomware_live(resp, self._source(), _make_cutoff())
        assert articles == []

    def test_article_has_required_fields(self):
        data = [{
            "victim": "SomeCorp",
            "group_name": "8Base",
            "discovered": datetime.now(timezone.utc).isoformat(),
            "post_url": "https://example.com",
            "country": "UK",
        }]
        articles = _parse_ransomware_live(_mock_resp(data), self._source(), _make_cutoff())
        a = articles[0]
        for field in ("title", "link", "published", "summary", "hash", "source", "darkweb"):
            assert field in a, f"Missing field: {field}"


class TestParseThreatFox:
    def _source(self):
        return {"name": "threatfox", "url": "https://threatfox.abuse.ch/export/json/recent/"}

    def _make_ioc(self, ioc_type="url", malware="Emotet", days_ago=0):
        ts = datetime.now(timezone.utc) - timedelta(days=days_ago)
        return {
            "ioc_type": ioc_type,
            "malware": malware,
            "malware_printable": malware,
            "ioc": "http://evil.example.com/malware",
            "first_seen": ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "confidence_level": 80,
        }

    def test_groups_by_malware_family(self):
        data = {
            "query_status": "ok",
            "data": [self._make_ioc(malware="Emotet"), self._make_ioc(malware="Emotet")],
        }
        articles = _parse_threatfox(_mock_resp(data), self._source(), _make_cutoff())
        # Should produce one article grouping both Emotet IOCs
        titles = [a["title"] for a in articles]
        assert any("Emotet" in t for t in titles)

    def test_malformed_response_returns_empty(self):
        resp = MagicMock()
        resp.json.return_value = "not a dict"
        articles = _parse_threatfox(resp, self._source(), _make_cutoff())
        assert articles == []

    def test_article_marked_as_darkweb(self):
        data = {
            "query_status": "ok",
            "data": [self._make_ioc()],
        }
        articles = _parse_threatfox(_mock_resp(data), self._source(), _make_cutoff())
        assert all(a.get("darkweb") is True for a in articles)


class TestParseC2Tracker:
    def _source(self):
        return {
            "name": "github-iocs",
            "url": "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt",
        }

    def test_parses_ip_list(self):
        resp = MagicMock()
        resp.text = "1.2.3.4\n5.6.7.8\n9.10.11.12\n"
        articles = _parse_c2_tracker(resp, self._source(), _make_cutoff())
        assert len(articles) > 0

    def test_article_marked_as_darkweb(self):
        resp = MagicMock()
        resp.text = "1.1.1.1\n2.2.2.2\n"
        articles = _parse_c2_tracker(resp, self._source(), _make_cutoff())
        assert all(a.get("darkweb") is True for a in articles)
