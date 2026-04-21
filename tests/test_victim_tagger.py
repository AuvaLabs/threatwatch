"""Tests for modules/victim_tagger.py — sector taxonomy tagging."""

import pytest

from modules.victim_tagger import tag_sectors, annotate_articles_with_sectors


class TestTagSectors:
    """Test the tag_sectors(title, summary) function."""

    # ── per-sector positive matches ──────────────────────────────────────────

    def test_healthcare_hospital(self):
        assert "Healthcare" in tag_sectors("Ransomware hits hospital network", None)

    def test_healthcare_hipaa(self):
        assert "Healthcare" in tag_sectors("HIPAA breach reported", None)

    def test_healthcare_patient_data(self):
        assert "Healthcare" in tag_sectors("Hackers steal patient data", None)

    def test_healthcare_nhs(self):
        assert "Healthcare" in tag_sectors("NHS trust hit by cyberattack", None)

    def test_healthcare_pharmaceutical(self):
        assert "Healthcare" in tag_sectors("Pharmaceutical firm breached", None)

    def test_finance_bank(self):
        assert "Finance" in tag_sectors("Major bank suffers data breach", None)

    def test_finance_crypto(self):
        assert "Finance" in tag_sectors("Cryptocurrency exchange hacked", None)

    def test_finance_fintech(self):
        assert "Finance" in tag_sectors("Fintech startup leaks customer records", None)

    def test_finance_wall_street(self):
        assert "Finance" in tag_sectors("Wall Street firm targeted", None)

    def test_government_fbi(self):
        assert "Government" in tag_sectors("FBI warns of new threat", None)

    def test_government_pentagon(self):
        assert "Government" in tag_sectors("Pentagon contractor breached", None)

    def test_government_ministry(self):
        assert "Government" in tag_sectors("Ministry of Defense hacked", None)

    def test_government_military(self):
        assert "Government" in tag_sectors("Military systems compromised", None)

    def test_government_embassy(self):
        assert "Government" in tag_sectors("Diplomatic embassy targeted", None)

    def test_education_university(self):
        assert "Education" in tag_sectors("University hit by ransomware", None)

    def test_education_school_district(self):
        assert "Education" in tag_sectors("School district data breach", None)

    def test_education_k12(self):
        assert "Education" in tag_sectors("K-12 systems targeted by hackers", None)

    def test_energy_power_grid(self):
        assert "Energy" in tag_sectors("Power grid attack detected", None)

    def test_energy_pipeline(self):
        assert "Energy" in tag_sectors("Pipeline operator hit by ransomware", None)

    def test_energy_nuclear(self):
        assert "Energy" in tag_sectors("Nuclear plant cybersecurity incident", None)

    def test_energy_company(self):
        assert "Energy" in tag_sectors("Energy company breached", None)

    def test_technology_tech_giant(self):
        assert "Technology" in tag_sectors("Tech giant faces data breach", None)

    def test_technology_saas(self):
        assert "Technology" in tag_sectors("SaaS provider compromised", None)

    def test_technology_microsoft(self):
        assert "Technology" in tag_sectors("Microsoft patches zero-day", None)

    def test_technology_cisco(self):
        assert "Technology" in tag_sectors("Cisco vulnerability exploited", None)

    def test_telecom_isp(self):
        assert "Telecom" in tag_sectors("ISP suffers major outage", None)

    def test_telecom_att(self):
        assert "Telecom" in tag_sectors("AT&T data breach affects millions", None)

    def test_telecom_mobile_carrier(self):
        assert "Telecom" in tag_sectors("Mobile carrier hacked", None)

    def test_retail_retailer(self):
        assert "Retail" in tag_sectors("Major retailer suffers breach", None)

    def test_retail_ecommerce(self):
        assert "Retail" in tag_sectors("E-commerce platform hacked", None)

    def test_retail_walmart(self):
        assert "Retail" in tag_sectors("Walmart POS system compromised", None)

    def test_manufacturing_factory(self):
        assert "Manufacturing" in tag_sectors("Factory systems hit by ransomware", None)

    def test_manufacturing_automaker(self):
        assert "Manufacturing" in tag_sectors("Automaker production halted", None)

    def test_manufacturing_supply_chain(self):
        assert "Manufacturing" in tag_sectors("Supply chain attack impacts firms", None)

    def test_transportation_airline(self):
        assert "Transportation" in tag_sectors("Airline booking system breached", None)

    def test_transportation_port(self):
        assert "Transportation" in tag_sectors("Port authority hit by cyberattack", None)

    def test_transportation_maersk(self):
        assert "Transportation" in tag_sectors("Maersk suffers NotPetya attack", None)

    def test_media_news_outlet(self):
        assert "Media" in tag_sectors("News outlet hacked", None)

    def test_media_broadcaster(self):
        assert "Media" in tag_sectors("Broadcaster hit by DDoS", None)

    def test_media_gaming(self):
        assert "Media" in tag_sectors("Gaming company data leak", None)

    def test_legal_law_firm(self):
        assert "Legal" in tag_sectors("Law firm client data exposed", None)

    def test_legal_deloitte(self):
        assert "Legal" in tag_sectors("Deloitte breach confirmed", None)

    def test_critical_infra_scada(self):
        assert "Critical Infrastructure" in tag_sectors("SCADA systems targeted", None)

    def test_critical_infra_water(self):
        assert "Critical Infrastructure" in tag_sectors("Water treatment plant hacked", None)

    def test_critical_infra_ics(self):
        assert "Critical Infrastructure" in tag_sectors("ICS vulnerabilities discovered", None)

    def test_hospitality_hotel(self):
        assert "Hospitality" in tag_sectors("Hotel chain suffers data breach", None)

    def test_hospitality_mgm(self):
        assert "Hospitality" in tag_sectors("MGM Resorts cyberattack", None)

    def test_hospitality_caesars(self):
        assert "Hospitality" in tag_sectors("Caesars pays ransom", None)

    # ── multi-sector matching ────────────────────────────────────────────────

    def test_multi_sector_healthcare_and_finance(self):
        sectors = tag_sectors("Hospital billing system breach exposes banking data", None)
        assert "Healthcare" in sectors
        assert "Finance" in sectors

    def test_multi_sector_energy_and_critical_infra(self):
        sectors = tag_sectors("Power plant SCADA system compromised", None)
        assert "Energy" in sectors
        assert "Critical Infrastructure" in sectors

    # ── negative / edge cases ────────────────────────────────────────────────

    def test_empty_inputs(self):
        assert tag_sectors(None, None) == []
        assert tag_sectors("", "") == []
        assert tag_sectors("", None) == []
        assert tag_sectors(None, "") == []

    def test_generic_text_no_match(self):
        assert tag_sectors("The weather is nice today", None) == []

    def test_generic_cyber_no_sector(self):
        assert tag_sectors("New zero-day vulnerability discovered", None) == []

    def test_summary_only_match(self):
        sectors = tag_sectors("Breach reported", "The hospital confirmed the incident")
        assert "Healthcare" in sectors

    def test_case_insensitive(self):
        assert "Healthcare" in tag_sectors("HOSPITAL NETWORK BREACHED", None)

    def test_deterministic_order(self):
        """Sector order follows _SECTOR_PATTERNS declaration order."""
        sectors = tag_sectors("Hospital bank power grid attack", None)
        assert sectors.index("Healthcare") < sectors.index("Finance")
        assert sectors.index("Finance") < sectors.index("Energy")


class TestAnnotateArticlesWithSectors:
    """Test annotate_articles_with_sectors(articles)."""

    def test_tags_matching_article(self):
        articles = [{"title": "Hospital breached", "summary": "Patient data stolen"}]
        count = annotate_articles_with_sectors(articles)
        assert count == 1
        assert "Healthcare" in articles[0]["victim_sectors"]

    def test_no_match_no_key(self):
        articles = [{"title": "Weather report", "summary": "Sunny today"}]
        count = annotate_articles_with_sectors(articles)
        assert count == 0
        assert "victim_sectors" not in articles[0]

    def test_removes_stale_key_on_no_match(self):
        articles = [{"title": "Weather report", "victim_sectors": ["Healthcare"]}]
        annotate_articles_with_sectors(articles)
        assert "victim_sectors" not in articles[0]

    def test_darkweb_title_only(self):
        """Darkweb articles should match on title only, not summary."""
        articles = [{
            "title": "qilin ransomware: new victim 'Acme Corp'",
            "summary": "Healthcare Finance Government Education",
            "darkweb": True,
        }]
        annotate_articles_with_sectors(articles)
        # Summary sectors should NOT be picked up for darkweb
        assert "Healthcare" not in articles[0].get("victim_sectors", [])

    def test_darkweb_isDarkweb_flag(self):
        """isDarkweb flag also triggers title-only matching."""
        articles = [{
            "title": "lockbit: new victim 'City Hospital'",
            "summary": "bank factory airline hotel",
            "isDarkweb": True,
        }]
        annotate_articles_with_sectors(articles)
        assert "Healthcare" in articles[0].get("victim_sectors", [])
        # Summary sectors should not be picked up
        assert "Finance" not in articles[0].get("victim_sectors", [])

    def test_non_darkweb_uses_summary_and_content(self):
        articles = [{
            "title": "New breach reported",
            "summary": "The hospital confirmed",
            "full_content": "Banking records also exposed",
        }]
        annotate_articles_with_sectors(articles)
        assert "Healthcare" in articles[0]["victim_sectors"]
        assert "Finance" in articles[0]["victim_sectors"]

    def test_returns_hit_count(self):
        articles = [
            {"title": "Hospital breached"},
            {"title": "Weather report"},
            {"title": "Bank hacked"},
        ]
        count = annotate_articles_with_sectors(articles)
        assert count == 2

    def test_empty_list(self):
        assert annotate_articles_with_sectors([]) == 0
