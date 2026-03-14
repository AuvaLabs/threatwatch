"""Tests for modules/stix_output.py — STIX 2.1 bundle generation."""
import json
import pytest
from modules.stix_output import (
    _article_to_report,
    _ioc_to_indicator,
    build_stix_bundle,
    build_stix_bytes,
    _deterministic_id,
)

SAMPLE_ARTICLE = {
    "title": "Critical Vulnerability in OpenSSL Patched",
    "translated_title": "Critical Vulnerability in OpenSSL Patched",
    "link": "https://example.com/openssl-vuln",
    "summary": "Researchers discovered a critical RCE in OpenSSL 3.x.",
    "published": "2026-03-14T10:00:00+00:00",
    "category": "Vulnerability Disclosure",
    "feed_region": "Global",
    "source_name": "SecurityNews",
}

SAMPLE_IOC = {
    "title": "Cobalt Strike beacon",
    "iocValue": "1.2.3.4",
    "iocType": "ip:port",
    "malwareFamily": "CobaltStrike",
    "published": "2026-03-14T10:00:00+00:00",
}


class TestDeterministicId:
    def test_stable_across_calls(self):
        id1 = _deterministic_id("report", "https://example.com/article")
        id2 = _deterministic_id("report", "https://example.com/article")
        assert id1 == id2

    def test_different_seeds_give_different_ids(self):
        id1 = _deterministic_id("report", "https://example.com/a")
        id2 = _deterministic_id("report", "https://example.com/b")
        assert id1 != id2

    def test_prefix_is_correct(self):
        stix_id = _deterministic_id("indicator", "some-seed")
        assert stix_id.startswith("indicator--")


class TestArticleToReport:
    def test_returns_stix_report(self):
        report = _article_to_report(SAMPLE_ARTICLE)
        assert report["type"] == "report"
        assert report["spec_version"] == "2.1"

    def test_name_from_translated_title(self):
        report = _article_to_report(SAMPLE_ARTICLE)
        assert report["name"] == SAMPLE_ARTICLE["translated_title"]

    def test_external_reference_contains_url(self):
        report = _article_to_report(SAMPLE_ARTICLE)
        refs = report.get("external_references", [])
        assert any(r["url"] == SAMPLE_ARTICLE["link"] for r in refs)

    def test_handles_missing_published(self):
        article = {**SAMPLE_ARTICLE}
        del article["published"]
        report = _article_to_report(article)
        assert "published" in report

    def test_labels_contain_category(self):
        report = _article_to_report(SAMPLE_ARTICLE)
        assert "vulnerability-disclosure" in report.get("labels", [])


class TestIocToIndicator:
    def test_ip_port_produces_pattern(self):
        indicator = _ioc_to_indicator(SAMPLE_IOC)
        assert indicator is not None
        assert "1.2.3.4" in indicator["pattern"]
        assert indicator["type"] == "indicator"

    def test_domain_ioc(self):
        ioc = {**SAMPLE_IOC, "iocType": "domain", "iocValue": "malicious.example.com"}
        indicator = _ioc_to_indicator(ioc)
        assert indicator is not None
        assert "malicious.example.com" in indicator["pattern"]

    def test_md5_hash_ioc(self):
        ioc = {**SAMPLE_IOC, "iocType": "md5_hash", "iocValue": "a" * 32}
        indicator = _ioc_to_indicator(ioc)
        assert indicator is not None
        assert "MD5" in indicator["pattern"]

    def test_unknown_ioc_type_returns_none(self):
        ioc = {**SAMPLE_IOC, "iocType": "unknown_type"}
        assert _ioc_to_indicator(ioc) is None


class TestBuildStixBundle:
    def test_bundle_type(self):
        bundle = build_stix_bundle([SAMPLE_ARTICLE])
        assert bundle["type"] == "bundle"

    def test_contains_identity_object(self):
        bundle = build_stix_bundle([])
        types = [o["type"] for o in bundle["objects"]]
        assert "identity" in types

    def test_contains_report_for_article(self):
        bundle = build_stix_bundle([SAMPLE_ARTICLE])
        types = [o["type"] for o in bundle["objects"]]
        assert "report" in types

    def test_contains_indicator_for_ioc(self):
        bundle = build_stix_bundle([], [SAMPLE_IOC])
        types = [o["type"] for o in bundle["objects"]]
        assert "indicator" in types

    def test_empty_inputs(self):
        bundle = build_stix_bundle([], [])
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) == 1  # only identity


class TestBuildStixBytes:
    def test_returns_valid_json_bytes(self):
        raw = build_stix_bytes([SAMPLE_ARTICLE])
        parsed = json.loads(raw)
        assert parsed["type"] == "bundle"

    def test_utf8_encoded(self):
        raw = build_stix_bytes([SAMPLE_ARTICLE])
        assert isinstance(raw, bytes)
