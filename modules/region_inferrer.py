"""Content-based region inference for news articles.

Scans article title and summary for geographic mentions to assign a more
accurate feed_region than the feed's locale (which only reflects where the
feed is hosted, not where the incident occurred).

Conservative approach: only overrides when a clear country/city mention is
found in the title. Summary is used only to confirm.

Does NOT run on darkweb articles (ransomware.live already provides country).
"""

import re

# ---------------------------------------------------------------------------
# Region map: keyword → normalized region label
# ---------------------------------------------------------------------------
# Each entry is (pattern, region). Patterns are tried in order; first match wins.
# Patterns with word-boundary anchors avoid false matches (e.g. "Iran" in "Ukraine").

_COUNTRY_PATTERNS = [
    # North America — U.S. needs special handling: word boundary doesn't work
    # after trailing period, so we use a lookahead instead
    (re.compile(r"(?:^|\s|,)(U\.S\.A?\.?|USA|United States|American|America)(?:\s|,|$|')", re.I), "US"),
    (re.compile(r"\b(FBI|CISA|NSA|Pentagon|Homeland Security)\b"), "US"),
    (re.compile(r"\bCanadian?\b", re.I), "US"),           # group with US for region purposes

    # UK / British Isles
    (re.compile(r"\b(UK|United Kingdom|Britain|British|England|Scotland|Wales|Northern Ireland)\b", re.I), "Europe"),

    # Europe (country names, adjectives, city demonyms, EU institutions)
    (re.compile(
        r"\b(European\s+Commission|European\s+Union|\bEU\b"
        r"|Germany|German|Deutschland|France|French|Italy|Italian|Spain|Spanish"
        r"|Netherlands|Dutch|Poland|Polish|Sweden|Swedish|Norway|Norwegian"
        r"|Finland|Finnish|Denmark|Danish|Switzerland|Swiss|Austria|Austrian"
        r"|Belgium|Belgian|Ireland|Irish|Portugal|Portuguese|Czech|Romania|Romanian"
        r"|Hungary|Hungarian|Greece|Greek|Bulgaria|Bulgarian|Croatia|Croatian"
        r"|Slovakia|Slovak|Slovenia|Slovenian|Serbia|Serbian|Ukraine|Ukrainian"
        r"|Russia|Russian|Belarus|Belarusian|Estonia|Estonian|Latvia|Latvian"
        r"|Lithuania|Lithuanian|Luxembourg|Cyprus|Malta|Albania|Albanian"
        r"|North Macedonia|Moldova|Moldova|Kosovo)\b",
        re.I,
    ), "Europe"),

    # Africa (map to Europe for now — same EMEA region display)
    (re.compile(
        r"\b(South Africa|South African|Nigeria|Nigerian|Kenya|Kenyan"
        r"|Ethiopia|Ethiopian|Ghana|Ghanaian|Egypt|Egyptian|Morocco|Moroccan"
        r"|Tunisia|Tunisian|Algeria|Algerian|Libya|Libyan)\b",
        re.I,
    ), "Europe"),

    # Middle East
    (re.compile(
        r"\b(UAE|United Arab Emirates|Emirati|Saudi Arabia|Saudi|Israel|Israeli"
        r"|Iran|Iranian|Turkey|Turkish|Egypt|Egyptian|Qatar|Qatari|Kuwait|Kuwaiti"
        r"|Bahrain|Bahraini|Jordan|Jordanian|Iraq|Iraqi|Lebanon|Lebanese"
        r"|Oman|Omani|Syria|Syrian|Yemen|Yemeni|Palestine|Palestinian)\b",
        re.I,
    ), "Middle East"),

    # APAC
    (re.compile(
        r"\b(Japan|Japanese|Australia|Australian|India|Indian|Singapore|Singaporean"
        r"|South Korea|Korean|China|Chinese|Taiwan|Taiwanese|Indonesia|Indonesian"
        r"|Malaysia|Malaysian|Thailand|Thai|Vietnam|Vietnamese|Philippines|Filipino"
        r"|New Zealand|Hong Kong|Pakistan|Pakistani|Bangladesh|Bangladeshi"
        r"|Sri Lanka|Myanmar|Cambodia|Nepal)\b",
        re.I,
    ), "APAC"),

    # LATAM
    (re.compile(
        r"\b(Brazil|Brazilian|Argentina|Argentine|Colombia|Colombian|Chile|Chilean"
        r"|Peru|Peruvian|Mexico|Mexican|Ecuador|Ecuadorian|Venezuela|Venezuelan"
        r"|Paraguay|Uruguayan|Bolivia|Bolivian|Costa Rica|Panama|Guatemala"
        r"|Honduras|El Salvador|Nicaragua|Dominican Republic|Cuba|Puerto Rico)\b",
        re.I,
    ), "LATAM"),
]

# Global sources whose feed_region should be trusted as-is (already correct)
_TRUST_FEED_SOURCES = {
    "darkweb:ransomware.live",
    "darkweb:threatfox",
    "darkweb:c2-tracker",
}

# Google News feed region labels — these are feed locales, NOT incident locations.
# We should attempt to infer a better region for articles from these feeds.
_LOCALE_REGIONS = {"US", "UK", "France", "Germany", "Japan", "South Korea",
                   "Brazil", "Australia", "India", "Canada", "Singapore", "UAE",
                   "Italy", "Spain", "Netherlands", "Mexico", "Poland", "Turkey",
                   "LATAM", "Southeast Asia", "Middle East", "South Africa",
                   "Saudi Arabia", "China", "Ukraine", "Argentina"}


def _infer_from_text(title: str, summary: str) -> str | None:
    """Return inferred region from title (with summary as tiebreaker), or None."""
    # Collect ALL region matches from title
    title_regions = set()
    for pattern, region in _COUNTRY_PATTERNS:
        if pattern.search(title):
            title_regions.add(region)

    if len(title_regions) == 1:
        return title_regions.pop()

    if len(title_regions) > 1:
        # Multiple regions mentioned in title — prefer the target region.
        # Heuristic: if one region is a known "attacker origin" (Middle East for
        # Iran, APAC for China/North Korea, Europe for Russia) and the other is
        # the likely target, prefer the target.
        attacker_regions = {"Middle East", "APAC", "Europe"}
        targets = title_regions - attacker_regions
        if len(targets) == 1:
            return targets.pop()
        # Can't disambiguate — return Global
        return "Global"

    # Summary match is weaker — only use if it's a clear single-country mention
    # (don't infer from summaries that mention many countries)
    if summary:
        found = set()
        for pattern, region in _COUNTRY_PATTERNS:
            if pattern.search(summary):
                found.add(region)
        if len(found) == 1:
            return found.pop()

    return None


def infer_article_region(article: dict) -> dict:
    """Return article with a refined feed_region based on content inference.

    Rules:
    1. darkweb articles with known sources are trusted — no override.
    2. For all others: try to infer from title+summary.
       - If the article already has a specific non-locale region (Europe, APAC,
         Middle East, LATAM, US) and inference agrees or finds nothing — keep it.
       - If the current region is a feed locale AND inference finds a different
         region → override with the inferred region.
       - If no inference is possible → keep the current region.
    """
    source = article.get("source", "")
    if source in _TRUST_FEED_SOURCES or article.get("darkweb"):
        return article

    current_region = article.get("feed_region", "Global")
    # Already Global — inference can only improve it
    # Locale region — inference may correct it

    title = article.get("title") or article.get("translated_title") or ""
    summary = article.get("summary") or ""

    inferred = _infer_from_text(title, summary)
    if not inferred:
        return article

    # If current region is a locale-based tag or a broad regional label,
    # prefer the inferred content-based region
    _OVERRIDABLE = _LOCALE_REGIONS | {"Europe", "APAC", "Middle East", "LATAM", "MENA", "Global"}
    if current_region in _OVERRIDABLE:
        article = {**article, "feed_region": inferred}

    return article


def infer_articles_regions(articles: list[dict]) -> list[dict]:
    """Batch version of infer_article_region."""
    return [infer_article_region(a) for a in articles]
