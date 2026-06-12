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


class TestArticleConfidence:
    def test_confidence_mapped_to_report(self):
        article = {**SAMPLE_ARTICLE, "confidence": 85}
        report = _article_to_report(article)
        assert report["confidence"] == 85

    def test_confidence_clamped_to_100(self):
        article = {**SAMPLE_ARTICLE, "confidence": 150}
        report = _article_to_report(article)
        assert report["confidence"] == 100

    def test_confidence_absent_when_not_in_article(self):
        report = _article_to_report(SAMPLE_ARTICLE)
        assert "confidence" not in report


class TestProvenance:
    """`indicator indicates identity` was semantically invalid STIX (the spec
    defines indicates for indicator→malware/campaign/actor); provenance is
    now carried by created_by_ref, which every validator accepts."""

    def test_no_invalid_indicates_relationships(self):
        bundle = build_stix_bundle([SAMPLE_ARTICLE], [SAMPLE_IOC])
        types = [o["type"] for o in bundle["objects"]]
        assert "relationship" not in types

    def test_indicator_carries_created_by_ref(self):
        bundle = build_stix_bundle([], [SAMPLE_IOC])
        identity = next(o for o in bundle["objects"] if o["type"] == "identity")
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 1
        assert indicators[0]["created_by_ref"] == identity["id"]

    def test_report_carries_created_by_ref(self):
        bundle = build_stix_bundle([SAMPLE_ARTICLE], [])
        identity = next(o for o in bundle["objects"] if o["type"] == "identity")
        report = next(o for o in bundle["objects"] if o["type"] == "report")
        assert report["created_by_ref"] == identity["id"]

    def test_report_object_refs_include_indicators(self):
        bundle = build_stix_bundle([SAMPLE_ARTICLE], [SAMPLE_IOC])
        reports = [o for o in bundle["objects"] if o["type"] == "report"]
        indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
        assert len(reports) == 1
        assert len(indicators) == 1
        assert indicators[0]["id"] in reports[0]["object_refs"]


class TestBuildStixBytes:
    def test_returns_valid_json_bytes(self):
        raw = build_stix_bytes([SAMPLE_ARTICLE])
        parsed = json.loads(raw)
        assert parsed["type"] == "bundle"

    def test_utf8_encoded(self):
        raw = build_stix_bytes([SAMPLE_ARTICLE])
        assert isinstance(raw, bytes)


_STIX_ID_RE_TEXT = r"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"


class TestStixSpecCompliance:
    def test_every_object_id_is_uuid_form(self):
        """Validators reject the whole bundle on a single malformed id —
        the old identity id 'identity--threatwatch-system' did exactly that."""
        import re
        id_re = re.compile(_STIX_ID_RE_TEXT)
        bundle = build_stix_bundle([SAMPLE_ARTICLE], [SAMPLE_IOC])
        bad = [o["id"] for o in bundle["objects"] if not id_re.match(o["id"])]
        assert bad == []
        import re as _re
        assert _re.match(r"^bundle--[0-9a-f-]{36}$", bundle["id"])

    def test_bundle_id_stable_for_same_content(self):
        """TAXII clients dedup on bundle id; same articles => same id."""
        b1 = build_stix_bundle([SAMPLE_ARTICLE], [SAMPLE_IOC])
        b2 = build_stix_bundle([SAMPLE_ARTICLE], [SAMPLE_IOC])
        assert b1["id"] == b2["id"]

    def test_bundle_id_changes_when_content_changes(self):
        b1 = build_stix_bundle([SAMPLE_ARTICLE], [])
        other = {**SAMPLE_ARTICLE, "title": "Different incident",
                 "link": "https://example.test/other"}
        b2 = build_stix_bundle([other], [])
        assert b1["id"] != b2["id"]
