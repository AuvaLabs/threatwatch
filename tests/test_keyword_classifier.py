"""Tests for keyword_classifier — classification accuracy and noise filtering."""

import pytest
from modules.keyword_classifier import classify_article


class TestCyberRelevance:
    """Articles should be correctly identified as cyber-related or not."""

    @pytest.mark.parametrize("title,expected_cyber", [
        ("LockBit ransomware claims attack on major hospital chain", True),
        ("APT29 deploys new backdoor in diplomatic phishing campaign", True),
        ("Microsoft Patch Tuesday fixes 60 vulnerabilities", True),
        ("Critical RCE vulnerability found in Apache Struts CVE-2024-1234", True),
        ("New Linux Rootkits Leverage eBPF and io_uring For Stealth", True),
        ("Cisco Drops 48 New Firewall Vulnerabilities, 2 Critical", True),
        ("Iran-linked hackers target Israeli organizations, wipe data", True),
        ("New botnet targets IoT devices worldwide", True),
        ("CISA delays cyber incident reporting town halls", True),
        ("Children Council of San Francisco Data Breach Investigation", True),
        # Non-cyber
        ("Best restaurants in New York for 2026", False),
        ("Stock market reaches all-time high", False),
        ("New iPhone release date announced", False),
    ])
    def test_cyber_relevance(self, title, expected_cyber, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        result = classify_article(title)
        assert result["is_cyber_attack"] == expected_cyber, (
            f"'{title}' should be cyber={expected_cyber}, "
            f"got cyber={result['is_cyber_attack']}, cat={result['category']}"
        )


class TestClassificationRules:
    """Articles should be classified into the correct threat category."""

    @pytest.mark.parametrize("title,expected_category", [
        ("LockBit ransomware claims attack on hospital", "Ransomware"),
        ("APT29 deploys backdoor in phishing campaign", "Nation-State Attack"),
        ("Volt Typhoon targets US critical infrastructure", "Nation-State Attack"),
        ("New zero-day exploit found in Chrome browser", "Zero-Day Exploit"),
        ("Major data breach exposes 10 million records", "Data Breach"),
        ("Microsoft Patch Tuesday fixes 60 vulnerabilities", "Patch/Security Update"),
        ("Critical RCE vulnerability CVE-2024-1234 found", "Vulnerability Disclosure"),
        ("Supply chain attack compromises npm packages", "Supply Chain Attack"),
        ("DDoS attack takes down major website", "DDoS"),
        ("New phishing campaign targets bank customers", "Phishing"),
        ("Emotet malware returns with new evasion techniques", "Malware"),
        ("New rootkit leverages eBPF for stealth", "Malware"),
        ("Crypto exchange hacked for $100 million", "Cryptocurrency/Blockchain Theft"),
        ("AWS S3 bucket exposed millions of records", "Cloud Security Incident"),
        ("SCADA systems targeted in power grid attack", "Critical Infrastructure Attack"),
    ])
    def test_category_classification(self, title, expected_category, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        result = classify_article(title)
        assert result["is_cyber_attack"] is True
        assert result["category"] == expected_category, (
            f"'{title}' should be '{expected_category}', got '{result['category']}'"
        )


class TestRuleMatchAsCyberSignal:
    """Articles matching classification rules should be cyber-relevant
    even without broad keyword matches."""

    @pytest.mark.parametrize("title", [
        "Volt Typhoon targets US critical infrastructure in ongoing campaign",
        "Lazarus Group deploys new tooling against defense contractors",
        "Salt Typhoon infiltrates telecom networks across Asia",
    ])
    def test_apt_names_detected_without_broad_keywords(self, title, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        result = classify_article(title)
        assert result["is_cyber_attack"] is True
        assert result["category"] == "Nation-State Attack"


class TestNoiseFiltering:
    """Non-threat-intel articles should be filtered out."""

    @pytest.mark.parametrize("title", [
        # Job listings
        "Cybersecurity jobs available right now: March 2026",
        "Cybersecurity hiring trends show talent shortage crisis",
        # Career / workforce diversity
        "Two percent of women say cybersecurity is a welcoming career",
        "Turning expertise into opportunity for women in cybersecurity",
        "Women in Cybersecurity Say the Industry Needs Change",
        # Vendor funding
        "Armadin secures $189.9 million to counter AI-driven cyber threats",
        "Escape lands $18 million funding to scale AI-driven security",
        # Event marketing
        "Preparing for the Quantum Era: Post-Quantum Cryptography Webinar for Security Leaders",
        # Celebrity / entertainment
        "CM apologises to Mammootty for cyber attack on his X account",
        # M&A / business
        "Cybersecurity M&A Roundup: 42 Deals Announced in February 2026",
        "Is Cybersecurity the Dark Horse for Venture Investors?",
        # Insurance / advice
        "10 Tips to Lower Your Cyber Insurance Premium",
        # Networking events
        "Tewkesbury Borough Business Voice announces cyber security themed networking breakfast",
        "Video: The top cybersecurity talent under one roof",
        # Non-cyber social/political
        "Indonesia to ban children under 16 from social media",
        "Qatar arrests 313 people for sharing Iran attack videos",
        "House panel marks up kids digital safety act amid Democrat backlash",
    ])
    def test_noise_articles_filtered(self, title, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        result = classify_article(title)
        assert result["is_cyber_attack"] is False, (
            f"'{title}' should be filtered as noise, "
            f"got cyber={result['is_cyber_attack']}, cat={result['category']}"
        )


class TestNoFalsePositives:
    """Real threat intel should NOT be filtered by noise patterns."""

    @pytest.mark.parametrize("title", [
        "After Operation Epic Fury Iran May Turn to Cyberwar - Clearance Jobs",
        "Cisco NX-OS Software Link Layer Discovery Protocol Denial of Service Vulnerability",
        "Children Council of San Francisco Data Breach Investigation",
        "CISA delays cyber incident reporting town halls amid shutdown",
        "Poor WA gov M365 security led to $71k theft and children's data breached",
        "Iran-linked hackers target Israeli organizations, wipe data in cyberattacks",
    ])
    def test_real_threat_intel_not_filtered(self, title, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        result = classify_article(title)
        assert result["is_cyber_attack"] is True, (
            f"'{title}' is real threat intel but was filtered: "
            f"cat={result['category']}"
        )


class TestSummaryExtraction:
    """Content should be summarized in the result."""

    def test_summary_from_content(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        content = (
            "A major ransomware attack hit several hospitals. "
            "Patient data was encrypted. "
            "The attackers demanded $5 million in Bitcoin."
        )
        result = classify_article("Ransomware hits hospitals", content)
        assert result["summary"] != ""
        assert "ransomware" in result["summary"].lower()

    def test_summary_truncated(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        content = "A major cyber attack occurred. " * 100
        result = classify_article("Major cyber attack", content)
        assert len(result["summary"]) <= 500

    def test_no_content_empty_summary(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        result = classify_article("Ransomware hits hospitals")
        assert result["summary"] == ""


class TestCaching:
    """Results should be cached and returned on subsequent calls."""

    def test_cached_result_returned(self, tmp_path, monkeypatch):
        monkeypatch.setattr("modules.ai_cache.CACHE_DIR", tmp_path / "cache")
        r1 = classify_article("LockBit ransomware hits bank")
        r2 = classify_article("LockBit ransomware hits bank")
        assert r2.get("_cached") is True
        assert r1["category"] == r2["category"]
