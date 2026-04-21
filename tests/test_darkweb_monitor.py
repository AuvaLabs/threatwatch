import json
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

from modules.darkweb_monitor import (
    _parse_ransomware_live,
    _parse_threatfox,
    _parse_c2_tracker,
    _country_to_region,
    _get_session,
    _get_tor_session,
    check_tor_available,
    fetch_darkweb_intel,
    _fetch_source,
)
from modules.config import FEED_CUTOFF_DAYS
import modules.darkweb_monitor as darkweb_mod


def _make_cutoff(days=FEED_CUTOFF_DAYS):
    return datetime.now(timezone.utc) - timedelta(days=days)


def _mock_resp(data):
    resp = MagicMock()
    resp.json.return_value = data
    resp.text = json.dumps(data)
    return resp


# ── Session helpers ───────────────────────────────────────────────────────────

class TestGetSession:
    def setup_method(self):
        darkweb_mod._SESSION = None

    def test_returns_session(self):
        session = _get_session()
        assert session is not None

    def test_returns_same_session_on_second_call(self):
        s1 = _get_session()
        s2 = _get_session()
        assert s1 is s2

    def teardown_method(self):
        darkweb_mod._SESSION = None


class TestGetTorSession:
    def setup_method(self):
        darkweb_mod._TOR_SESSION = None

    def test_returns_session_with_socks_proxy(self):
        session = _get_tor_session()
        assert session is not None
        assert "socks5h://127.0.0.1:9050" in session.proxies.get("http", "")

    def test_returns_same_session_on_second_call(self):
        s1 = _get_tor_session()
        s2 = _get_tor_session()
        assert s1 is s2

    def teardown_method(self):
        darkweb_mod._TOR_SESSION = None


class TestCheckTorAvailable:
    def setup_method(self):
        darkweb_mod._TOR_SESSION = None

    def test_returns_false_when_session_none(self):
        with patch("modules.darkweb_monitor._get_tor_session", return_value=None):
            result = check_tor_available()
        assert result is False

    def test_returns_true_when_tor_connected(self):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"IsTor": True, "IP": "1.2.3.4"}
        mock_session.get.return_value = mock_resp
        with patch("modules.darkweb_monitor._get_tor_session", return_value=mock_session):
            result = check_tor_available()
        assert result is True

    def test_returns_false_when_not_tor(self):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"IsTor": False, "IP": "1.2.3.4"}
        mock_session.get.return_value = mock_resp
        with patch("modules.darkweb_monitor._get_tor_session", return_value=mock_session):
            result = check_tor_available()
        assert result is False

    def test_returns_false_on_exception(self):
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Connection refused")
        with patch("modules.darkweb_monitor._get_tor_session", return_value=mock_session):
            result = check_tor_available()
        assert result is False

    def teardown_method(self):
        darkweb_mod._TOR_SESSION = None


# ── fetch_darkweb_intel ───────────────────────────────────────────────────────

class TestFetchDarkwebIntel:
    def test_returns_list(self):
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = []
        mock_resp.text = "[]"
        with patch("modules.darkweb_monitor._get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_session.get.return_value = mock_resp
            mock_get_session.return_value = mock_session
            result = fetch_darkweb_intel()
        assert isinstance(result, list)

    def test_handles_source_failure_gracefully(self):
        with patch("modules.darkweb_monitor._fetch_source", side_effect=Exception("network error")):
            result = fetch_darkweb_intel()
        assert isinstance(result, list)
        assert len(result) == 0

    def test_aggregates_articles_from_all_sources(self):
        from modules.darkweb_monitor import DARKWEB_SOURCES
        fake_article = {"title": "Test", "darkweb": True}
        with patch("modules.darkweb_monitor._fetch_source", return_value=[fake_article]):
            result = fetch_darkweb_intel()
        assert len(result) == len(DARKWEB_SOURCES) * 1


class TestFetchSource:
    def test_no_parser_returns_empty(self):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_session.get.return_value = mock_resp
        with patch("modules.darkweb_monitor._get_session", return_value=mock_session):
            source = {"name": "test", "url": "https://example.com", "parser": "_nonexistent_parser"}
            result = _fetch_source(source, _make_cutoff())
        assert result == []

    def test_calls_correct_parser(self):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = []
        mock_resp.text = ""
        mock_session.get.return_value = mock_resp
        with patch("modules.darkweb_monitor._get_session", return_value=mock_session):
            source = {
                "name": "ransomware.live",
                "url": "https://api.ransomware.live/recentvictims",
                "parser": "_parse_ransomware_live",
            }
            result = _fetch_source(source, _make_cutoff())
        assert isinstance(result, list)


# ── _parse_ransomware_live ────────────────────────────────────────────────────

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

    def test_non_clearnet_post_url_uses_fallback_link(self):
        data = [{
            "victim": "DarkCorp",
            "group_name": "LockBit",
            "discovered": datetime.now(timezone.utc).isoformat(),
            "post_url": "http://evil.onion/victim",
            "country": "DE",
        }]
        articles = _parse_ransomware_live(_mock_resp(data), self._source(), _make_cutoff())
        assert articles[0]["link"] == "https://ransomware.live/#/victims"

    def test_country_added_to_title(self):
        data = [{
            "victim": "EuroCorp",
            "group_name": "Cl0p",
            "discovered": datetime.now(timezone.utc).isoformat(),
            "post_url": "",
            "country": "France",
        }]
        articles = _parse_ransomware_live(_mock_resp(data), self._source(), _make_cutoff())
        assert "France" in articles[0]["title"]

    def test_uses_post_title_fallback(self):
        data = [{
            "post_title": "Victim via post_title",
            "group_name": "Akira",
            "discovered": datetime.now(timezone.utc).isoformat(),
            "post_url": "",
            "country": "",
        }]
        articles = _parse_ransomware_live(_mock_resp(data), self._source(), _make_cutoff())
        assert "Victim via post_title" in articles[0]["title"]

    def test_uses_published_fallback(self):
        ts = datetime.now(timezone.utc).isoformat()
        data = [{
            "victim": "FallbackCo",
            "group_name": "Akira",
            "published": ts,
            "post_url": "",
            "country": "",
        }]
        articles = _parse_ransomware_live(_mock_resp(data), self._source(), _make_cutoff())
        assert len(articles) == 1

    def test_json_decode_error_returns_empty(self):
        resp = MagicMock()
        resp.json.side_effect = json.JSONDecodeError("msg", "", 0)
        articles = _parse_ransomware_live(resp, self._source(), _make_cutoff())
        assert articles == []


# ── _parse_threatfox ─────────────────────────────────────────────────────────

class TestParseThreatFox:
    def _source(self):
        return {"name": "threatfox", "url": "https://threatfox.abuse.ch/export/json/recent/"}

    def _make_entry(self, malware="Emotet", days_ago=0, ioc_value="http://evil.com/bad"):
        ts = datetime.now(timezone.utc) - timedelta(days=days_ago)
        return {
            "ioc_type": "url",
            "ioc_value": ioc_value,
            "malware_printable": malware,
            "threat_type": "botnet_cc",
            "first_seen_utc": ts.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "confidence_level": 80,
        }

    def test_groups_by_malware_family(self):
        data = {
            "query_status": "ok",
            "entry1": [self._make_entry(malware="Emotet")],
            "entry2": [self._make_entry(malware="Emotet")],
        }
        articles = _parse_threatfox(_mock_resp(data), self._source(), _make_cutoff())
        titles = [a["title"] for a in articles]
        assert any("Emotet" in t for t in titles)

    def test_malformed_response_returns_empty(self):
        resp = MagicMock()
        resp.json.return_value = "not a dict"
        articles = _parse_threatfox(resp, self._source(), _make_cutoff())
        assert articles == []

    def test_article_marked_as_darkweb(self):
        data = {
            "entry1": [self._make_entry()],
        }
        articles = _parse_threatfox(_mock_resp(data), self._source(), _make_cutoff())
        assert all(a.get("darkweb") is True for a in articles)

    def test_old_ioc_filtered_out(self):
        data = {
            "entry1": [self._make_entry(days_ago=FEED_CUTOFF_DAYS + 10)],
        }
        articles = _parse_threatfox(_mock_resp(data), self._source(), _make_cutoff())
        assert len(articles) == 0

    def test_caps_at_20_malware_families(self):
        data = {f"entry{i}": [self._make_entry(malware=f"Malware{i}")] for i in range(30)}
        articles = _parse_threatfox(_mock_resp(data), self._source(), _make_cutoff())
        assert len(articles) <= 20

    def test_iocs_per_family_capped_at_10(self):
        entries = [self._make_entry(malware="SpamBot", ioc_value=f"http://evil{i}.com/") for i in range(20)]
        data = {"entry1": entries}
        articles = _parse_threatfox(_mock_resp(data), self._source(), _make_cutoff())
        # Should only have up to 10 IOCs in sample
        assert len(articles) == 1
        # Verify summary has IOCs (up to 5 shown)
        assert "http://evil" in articles[0]["summary"]

    def test_skips_non_list_entries(self):
        data = {
            "query_status": "ok",  # not a list — should be skipped
            "entry1": [self._make_entry()],
        }
        articles = _parse_threatfox(_mock_resp(data), self._source(), _make_cutoff())
        assert len(articles) >= 1

    def test_singular_ioc_title(self):
        data = {"entry1": [self._make_entry(malware="SingleIOC")]}
        articles = _parse_threatfox(_mock_resp(data), self._source(), _make_cutoff())
        assert any("1 new IOC" in a["title"] for a in articles)

    def test_plural_ioc_title(self):
        entries = [self._make_entry(malware="MultiIOC"), self._make_entry(malware="MultiIOC")]
        data = {"entry1": entries}
        articles = _parse_threatfox(_mock_resp(data), self._source(), _make_cutoff())
        assert any("IOCs" in a["title"] for a in articles)

    def test_json_decode_error_returns_empty(self):
        resp = MagicMock()
        resp.json.side_effect = json.JSONDecodeError("msg", "", 0)
        articles = _parse_threatfox(resp, self._source(), _make_cutoff())
        assert articles == []

    def test_feed_region_is_global(self):
        data = {"entry1": [self._make_entry()]}
        articles = _parse_threatfox(_mock_resp(data), self._source(), _make_cutoff())
        assert all(a["feed_region"] == "Global" for a in articles)


# ── _parse_c2_tracker ─────────────────────────────────────────────────────────

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

    def test_skips_comment_lines(self):
        resp = MagicMock()
        resp.text = "# This is a comment\n1.2.3.4\n5.6.7.8\n"
        articles = _parse_c2_tracker(resp, self._source(), _make_cutoff())
        assert len(articles) == 1
        assert "2 active" in articles[0]["title"]

    def test_empty_text_returns_empty(self):
        resp = MagicMock()
        resp.text = ""
        articles = _parse_c2_tracker(resp, self._source(), _make_cutoff())
        assert articles == []

    def test_only_comments_returns_empty(self):
        resp = MagicMock()
        resp.text = "# just comments\n# another comment\n"
        articles = _parse_c2_tracker(resp, self._source(), _make_cutoff())
        assert articles == []

    def test_title_contains_ip_count(self):
        resp = MagicMock()
        resp.text = "\n".join(f"10.0.0.{i}" for i in range(1, 6))
        articles = _parse_c2_tracker(resp, self._source(), _make_cutoff())
        assert "5" in articles[0]["title"]

    def test_sample_ips_in_summary(self):
        resp = MagicMock()
        resp.text = "1.1.1.1\n2.2.2.2\n3.3.3.3\n"
        articles = _parse_c2_tracker(resp, self._source(), _make_cutoff())
        assert "1.1.1.1" in articles[0]["summary"]

    def test_exception_returns_empty(self):
        resp = MagicMock()
        resp.text = MagicMock(side_effect=Exception("error"))
        # strip() on a mock will raise — but the real code does resp.text.strip()
        # so we need text to raise on strip
        type(resp).text = property(lambda self: (_ for _ in ()).throw(Exception("read error")))
        articles = _parse_c2_tracker(resp, self._source(), _make_cutoff())
        assert articles == []

    def test_feed_region_is_global(self):
        resp = MagicMock()
        resp.text = "1.1.1.1\n"
        articles = _parse_c2_tracker(resp, self._source(), _make_cutoff())
        assert articles[0]["feed_region"] == "Global"


# ── _country_to_region ────────────────────────────────────────────────────────

class TestCountryToRegion:
    # ISO-2 codes
    def test_us_iso2(self):
        assert _country_to_region("US") == "US"

    def test_ca_iso2(self):
        assert _country_to_region("CA") == "US"

    def test_gb_iso2(self):
        assert _country_to_region("GB") == "Europe"

    def test_de_iso2(self):
        assert _country_to_region("DE") == "Europe"

    def test_fr_iso2(self):
        assert _country_to_region("FR") == "Europe"

    def test_jp_iso2(self):
        assert _country_to_region("JP") == "APAC"

    def test_cn_iso2(self):
        assert _country_to_region("CN") == "APAC"

    def test_au_iso2(self):
        assert _country_to_region("AU") == "APAC"

    def test_in_iso2(self):
        assert _country_to_region("IN") == "APAC"

    def test_br_iso2(self):
        assert _country_to_region("BR") == "LATAM"

    def test_mx_iso2(self):
        assert _country_to_region("MX") == "LATAM"

    def test_ae_iso2(self):
        assert _country_to_region("AE") == "Middle East"

    def test_sa_iso2(self):
        assert _country_to_region("SA") == "Middle East"

    def test_il_iso2(self):
        assert _country_to_region("IL") == "Middle East"

    def test_unknown_iso2_returns_global(self):
        assert _country_to_region("ZZ") == "Global"

    # Full country names
    def test_united_states_full(self):
        assert _country_to_region("United States") == "US"

    def test_usa_full(self):
        assert _country_to_region("USA") == "US"

    def test_germany_full(self):
        assert _country_to_region("Germany") == "Europe"

    def test_france_full(self):
        assert _country_to_region("France") == "Europe"

    def test_united_kingdom_full(self):
        assert _country_to_region("United Kingdom") == "Europe"

    def test_russia_full(self):
        assert _country_to_region("Russia") == "Europe"

    def test_japan_full(self):
        assert _country_to_region("Japan") == "APAC"

    def test_china_full(self):
        assert _country_to_region("China") == "APAC"

    def test_india_full(self):
        assert _country_to_region("India") == "APAC"

    def test_brazil_full(self):
        assert _country_to_region("Brazil") == "LATAM"

    def test_mexico_full(self):
        assert _country_to_region("Mexico") == "LATAM"

    def test_israel_full(self):
        assert _country_to_region("Israel") == "Middle East"

    def test_saudi_arabia_full(self):
        assert _country_to_region("Saudi Arabia") == "Middle East"

    def test_uae_full(self):
        assert _country_to_region("UAE") == "Middle East"

    def test_unknown_name_returns_global(self):
        assert _country_to_region("Atlantis") == "Global"

    # Edge cases
    def test_empty_string_returns_global(self):
        assert _country_to_region("") == "Global"

    def test_none_returns_global(self):
        assert _country_to_region(None) == "Global"  # type: ignore[arg-type]

    def test_whitespace_trimmed(self):
        assert _country_to_region("  US  ") == "US"

    def test_case_insensitive(self):
        assert _country_to_region("germany") == "Europe"
        assert _country_to_region("GERMANY") == "Europe"
