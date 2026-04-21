"""Tests for modules/ioc_extractor.py — IOC extraction."""

import pytest
from modules.ioc_extractor import (
    refang, extract_iocs, has_any_iocs, annotate_articles_with_iocs,
)


class TestRefang:
    def test_defanged_dot(self):
        assert refang("192.168[.]1[.]1") == "192.168.1.1"

    def test_hxxp(self):
        assert refang("hxxp://evil.com") == "http://evil.com"

    def test_hxxps(self):
        assert refang("hxxps://evil.com") == "https://evil.com"

    def test_at_symbol(self):
        assert refang("user[at]evil.com") == "user@evil.com"

    def test_empty_string(self):
        assert refang("") == ""

    def test_none(self):
        assert refang(None) is None

    def test_no_defang(self):
        assert refang("normal text") == "normal text"


class TestExtractIocs:
    def test_ipv4_public(self):
        iocs = extract_iocs("C2 server at 185.220.101.50 was active")
        assert "185.220.101.50" in iocs["ipv4"]

    def test_ipv4_private_excluded(self):
        iocs = extract_iocs("Internal: 192.168.1.1")
        assert iocs["ipv4"] == []

    def test_ipv4_placeholder_excluded(self):
        iocs = extract_iocs("Example: 1.2.3.4")
        assert iocs["ipv4"] == []

    def test_ipv4_defanged(self):
        iocs = extract_iocs("C2: 185[.]220[.]101[.]50 active")
        assert "185.220.101.50" in iocs["ipv4"]

    def test_sha256(self):
        h = "a" * 64
        iocs = extract_iocs(f"Hash: {h}")
        assert h in iocs["sha256"]

    def test_sha1(self):
        h = "b" * 40
        iocs = extract_iocs(f"SHA1: {h}")
        assert h in iocs["sha1"]

    def test_md5(self):
        h = "c" * 32
        iocs = extract_iocs(f"MD5: {h}")
        assert h in iocs["md5"]

    def test_url(self):
        iocs = extract_iocs("Download from https://evil.example.com/payload.exe")
        assert any("evil.example.com" in u for u in iocs["urls"])

    def test_hxxps_url(self):
        iocs = extract_iocs("C2: hxxps://evil.example.com/c2")
        assert any("evil.example.com" in u for u in iocs["urls"])

    def test_email(self):
        iocs = extract_iocs("Contact: attacker@evil.com for ransom")
        assert "attacker@evil.com" in iocs["emails"]

    def test_domain(self):
        iocs = extract_iocs("Resolves to malware-c2.xyz")
        assert "malware-c2.xyz" in iocs["domains"]

    def test_benign_domain_excluded(self):
        iocs = extract_iocs("Read more at bleepingcomputer.com")
        assert "bleepingcomputer.com" not in iocs["domains"]

    def test_empty_input(self):
        iocs = extract_iocs(None)
        assert all(v == [] for v in iocs.values())

    def test_empty_string(self):
        iocs = extract_iocs("")
        assert all(v == [] for v in iocs.values())

    def test_stable_keys(self):
        iocs = extract_iocs("no indicators here")
        expected_keys = {"ipv4", "ipv6", "domains", "urls", "sha256", "sha1", "md5", "emails"}
        assert set(iocs.keys()) == expected_keys


class TestHasAnyIocs:
    def test_true_with_ip(self):
        assert has_any_iocs({"ipv4": ["8.8.8.8"], "domains": [], "urls": [],
                             "sha256": [], "sha1": [], "md5": [], "emails": [], "ipv6": []})

    def test_false_when_empty(self):
        assert not has_any_iocs({"ipv4": [], "domains": [], "urls": [],
                                  "sha256": [], "sha1": [], "md5": [], "emails": [], "ipv6": []})


class TestAnnotateArticlesWithIocs:
    def test_annotates_article_with_iocs(self):
        articles = [{"title": "C2 at 185.220.101.50", "summary": "Active server"}]
        count = annotate_articles_with_iocs(articles)
        assert count == 1
        assert "iocs" in articles[0]
        assert "185.220.101.50" in articles[0]["iocs"]["ipv4"]

    def test_no_iocs_no_key(self):
        articles = [{"title": "Weather report", "summary": "Sunny"}]
        count = annotate_articles_with_iocs(articles)
        assert count == 0
        assert "iocs" not in articles[0]

    def test_removes_stale_key(self):
        articles = [{"title": "No indicators", "iocs": {"ipv4": ["old"]}}]
        annotate_articles_with_iocs(articles)
        assert "iocs" not in articles[0]

    def test_empty_list(self):
        assert annotate_articles_with_iocs([]) == 0
