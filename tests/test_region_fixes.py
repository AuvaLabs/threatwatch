"""Tests for region accuracy fixes:
- ISO-2 country code mapping in darkweb_monitor._country_to_region
- Multi-region collapsing in deduplicator._collapse_regions
- Content-based region inference in region_inferrer
"""
import pytest

from modules.darkweb_monitor import _country_to_region
from modules.deduplicator import _collapse_regions
from modules.region_inferrer import infer_article_region, infer_articles_regions


# ---------------------------------------------------------------------------
# _country_to_region — ISO-2 codes
# ---------------------------------------------------------------------------
class TestCountryToRegion:
    def test_iso2_us(self):
        assert _country_to_region("US") == "US"

    def test_iso2_germany(self):
        assert _country_to_region("DE") == "Europe"

    def test_iso2_france(self):
        assert _country_to_region("FR") == "Europe"

    def test_iso2_uk(self):
        assert _country_to_region("GB") == "Europe"

    def test_iso2_australia(self):
        assert _country_to_region("AU") == "APAC"

    def test_iso2_japan(self):
        assert _country_to_region("JP") == "APAC"

    def test_iso2_india(self):
        assert _country_to_region("IN") == "APAC"

    def test_iso2_singapore(self):
        assert _country_to_region("SG") == "APAC"

    def test_iso2_brazil(self):
        assert _country_to_region("BR") == "LATAM"

    def test_iso2_mexico(self):
        assert _country_to_region("MX") == "LATAM"

    def test_iso2_uae(self):
        assert _country_to_region("AE") == "Middle East"

    def test_iso2_israel(self):
        assert _country_to_region("IL") == "Middle East"

    def test_iso2_ukraine(self):
        assert _country_to_region("UA") == "Europe"

    def test_iso2_italy(self):
        assert _country_to_region("IT") == "Europe"

    def test_iso2_spain(self):
        assert _country_to_region("ES") == "Europe"

    def test_iso2_poland(self):
        assert _country_to_region("PL") == "Europe"

    def test_iso2_south_korea(self):
        assert _country_to_region("KR") == "APAC"

    def test_iso2_canada(self):
        assert _country_to_region("CA") == "US"

    def test_full_name_germany(self):
        assert _country_to_region("Germany") == "Europe"

    def test_full_name_united_states(self):
        assert _country_to_region("United States") == "US"

    def test_empty_returns_global(self):
        assert _country_to_region("") == "Global"
        assert _country_to_region(None) == "Global"

    def test_unknown_returns_global(self):
        assert _country_to_region("XZ") == "Global"
        assert _country_to_region("Andorra") == "Global"

    def test_case_insensitive_iso2(self):
        assert _country_to_region("de") == "Europe"
        assert _country_to_region("De") == "Europe"


# ---------------------------------------------------------------------------
# _collapse_regions — multi-region collapsing
# ---------------------------------------------------------------------------
class TestCollapseRegions:
    def test_single_region_kept(self):
        assert _collapse_regions({"US"}) == "US"

    def test_two_regions_kept(self):
        result = _collapse_regions({"US", "Europe"})
        assert "US" in result and "Europe" in result

    def test_three_regions_collapse_to_global(self):
        # 3 regions exceeds max 2 threshold — collapses to Global
        assert _collapse_regions({"US", "Europe", "APAC"}) == "Global"

    def test_four_regions_collapse_to_global(self):
        assert _collapse_regions({"US", "Europe", "APAC", "LATAM"}) == "Global"

    def test_five_regions_collapse_to_global(self):
        assert _collapse_regions({"US", "UK", "France", "Germany", "Canada"}) == "Global"

    def test_global_discarded_in_merge(self):
        result = _collapse_regions({"US", "Global"})
        assert result == "US"

    def test_only_global_returns_global(self):
        assert _collapse_regions({"Global"}) == "Global"

    def test_empty_returns_global(self):
        assert _collapse_regions(set()) == "Global"


# ---------------------------------------------------------------------------
# infer_article_region — content-based inference
# ---------------------------------------------------------------------------
class TestInferArticleRegion:
    def _article(self, title, summary="", region="US", source="google"):
        return {
            "title": title,
            "summary": summary,
            "feed_region": region,
            "source": source,
        }

    def test_german_company_in_title_corrects_us_region(self):
        a = self._article("Akira ransomware hits Porsche Zentrum Fulda in Germany")
        result = infer_article_region(a)
        assert result["feed_region"] == "Europe"

    def test_uk_attack_corrects_us_region(self):
        a = self._article("British Hospital suffers major data breach")
        result = infer_article_region(a)
        assert result["feed_region"] == "Europe"

    def test_japan_title_corrects_us_region(self):
        a = self._article("Japanese automaker hit by supply chain attack")
        result = infer_article_region(a)
        assert result["feed_region"] == "APAC"

    def test_australia_title_corrects_region(self):
        a = self._article("Australian government agency breached by APT group")
        result = infer_article_region(a)
        assert result["feed_region"] == "APAC"

    def test_brazil_title_corrects_region(self):
        a = self._article("Brazilian bank hit by DDoS attack")
        result = infer_article_region(a)
        assert result["feed_region"] == "LATAM"

    def test_us_article_keeps_us_region(self):
        a = self._article("US Treasury Department warns of cyber threats", region="US")
        result = infer_article_region(a)
        assert result["feed_region"] == "US"

    def test_global_article_inferred_from_title(self):
        a = self._article("Sandworm targets Ukrainian infrastructure", region="Global")
        result = infer_article_region(a)
        assert result["feed_region"] == "Europe"

    def test_global_article_no_match_stays_global(self):
        a = self._article("New ransomware variant detected in the wild", region="Global")
        result = infer_article_region(a)
        assert result["feed_region"] == "Global"

    def test_darkweb_articles_not_overridden(self):
        a = {
            "title": "akira ransomware: new victim 'Porsche Zentrum Fulda' (DE)",
            "summary": "",
            "feed_region": "Europe",
            "source": "darkweb:ransomware.live",
            "darkweb": True,
        }
        result = infer_article_region(a)
        assert result["feed_region"] == "Europe"

    def test_middle_east_inferred(self):
        a = self._article("Iranian hackers breach Israeli defence contractor", region="US")
        result = infer_article_region(a)
        # Iran and Israel both map to Middle East
        assert result["feed_region"] == "Middle East"

    def test_batch_inference(self):
        articles = [
            self._article("German hospital pays ransom after cyberattack"),
            self._article("New vulnerability in Apache server", region="Global"),
        ]
        results = infer_articles_regions(articles)
        assert results[0]["feed_region"] == "Europe"
        assert results[1]["feed_region"] == "Global"

    # ── attacker-origin disambiguation (lines 118-143) ───────────────────

    def test_chinese_hackers_attack_american_returns_us(self):
        """Attacker-origin: Chinese (APAC) + American (US) → target is US."""
        a = self._article("Chinese hackers target American government agencies")
        result = infer_article_region(a)
        assert result["feed_region"] == "US"

    def test_north_korean_apt_hits_british(self):
        """Attacker-origin: North Korean (APAC) + British (Europe) → Europe."""
        a = self._article("North Korean APT37 hits British banks")
        result = infer_article_region(a)
        assert result["feed_region"] == "Europe"

    def test_iranian_breach_american(self):
        """Attacker-origin: Iranian (Middle East) + American (US) → US."""
        a = self._article("Iranian-linked hackers breach American defense contractor")
        result = infer_article_region(a)
        assert result["feed_region"] == "US"

    def test_russian_sandworm_attacks_ukraine(self):
        """Both Russia and Ukraine map to Europe — single region."""
        a = self._article("Russian Sandworm attacks Ukrainian power grid")
        result = infer_article_region(a)
        assert result["feed_region"] == "Europe"

    def test_both_attacker_origins_returns_global(self):
        """Two attacker-origin regions with no non-attacker target → Global."""
        a = self._article("Chinese and Iranian cyber groups collaborate on Australian targets")
        result = infer_article_region(a)
        # Chinese=APAC, Iranian=Middle East, Australian=APAC. Attacker origins={APAC, Middle East}.
        # targets = {APAC} - {APAC, Middle East} = {} → Global
        assert result["feed_region"] == "Global"

    def test_generic_attacker_heuristic(self):
        """Generic fallback: APAC is generic attacker-region, LATAM is target."""
        a = self._article("Cyberattack from Japanese group targets Brazilian companies")
        result = infer_article_region(a)
        assert result["feed_region"] == "LATAM"

    def test_multiple_regions_no_attacker_returns_global(self):
        """Multiple regions, no attacker pattern → Global fallback."""
        a = self._article("Cyberattack affects companies in Germany and Japan")
        result = infer_article_region(a)
        assert result["feed_region"] == "Global"

    # ── summary-only inference (lines 147-153) ───────────────────────────

    def test_summary_single_country_inferred(self):
        a = self._article("Major breach reported", summary="The French ministry confirmed the incident")
        result = infer_article_region(a)
        assert result["feed_region"] == "Europe"

    def test_summary_multiple_countries_no_override(self):
        a = self._article("Major breach reported", summary="Attacks in Germany and Japan confirmed", region="Global")
        result = infer_article_region(a)
        assert result["feed_region"] == "Global"
