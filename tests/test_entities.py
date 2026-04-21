"""Tests for modules/entities.py — shared entity patterns."""

from modules.entities import CVE_RE, ACTOR_PATTERNS


class TestCveRegex:
    def test_matches_standard_cve(self):
        assert CVE_RE.search("CVE-2026-12345")

    def test_matches_long_id(self):
        assert CVE_RE.search("CVE-2026-123456")

    def test_case_insensitive(self):
        assert CVE_RE.search("cve-2026-12345")

    def test_no_match_short_id(self):
        assert not CVE_RE.search("CVE-2026-12")

    def test_extracts_from_text(self):
        matches = CVE_RE.findall("Found CVE-2026-1234 and CVE-2025-5678 in report")
        assert len(matches) == 2


class TestActorPatterns:
    def test_apt28_fancy_bear(self):
        for text in ["APT28", "Fancy Bear", "Forest Blizzard"]:
            matches = [(name, atype) for rx, name, atype, _ in ACTOR_PATTERNS if rx.search(text)]
            assert any(name == "APT28" for name, _ in matches), f"Failed to match: {text}"

    def test_lockbit(self):
        matches = [(name, atype) for rx, name, atype, _ in ACTOR_PATTERNS if rx.search("LockBit 3.0")]
        assert any(name == "LockBit" for name, _ in matches)

    def test_volt_typhoon(self):
        matches = [(name, atype) for rx, name, atype, _ in ACTOR_PATTERNS if rx.search("Volt Typhoon")]
        assert any(name == "Volt Typhoon" for name, _ in matches)

    def test_lazarus(self):
        matches = [(name, origin) for rx, name, _, origin in ACTOR_PATTERNS if rx.search("Lazarus Group")]
        assert any(origin == "North Korea" for _, origin in matches)

    def test_no_false_positive_on_generic_text(self):
        matches = [name for rx, name, _, _ in ACTOR_PATTERNS if rx.search("The weather is nice")]
        assert len(matches) == 0
