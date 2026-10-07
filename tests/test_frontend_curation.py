"""Regression checks for the briefing-first news feed curation."""

from pathlib import Path


HTML = (Path(__file__).parent.parent / "threatwatch.html").read_text(encoding="utf-8")


def test_machine_vulnerability_sources_are_identified():
    assert "function isBulkVulnerabilityArticle(article)" in HTML
    assert "source === 'nvd:cve'" in HTML
    assert "source === 'https://vulners.com/rss.xml'" in HTML


def test_default_news_view_hides_non_kev_machine_records():
    assert "_isDefaultNewsView(filter)" in HTML
    assert "item.isBulkVulnerability && !item.kevListed" in HTML
    assert "CVEs in Exploits" in HTML


def test_exploits_tab_still_includes_vulnerability_cards():
    assert "filter === 'exploits'" in HTML
    assert "item.cssType === 'vuln'" in HTML
