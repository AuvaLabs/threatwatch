from pathlib import Path

import yaml


CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "feeds_native.yaml"
CONFIG_DIR = CONFIG_PATH.parent


def _native_feeds_by_url():
    feeds = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    return {feed["url"]: feed for feed in feeds}


def _feed_urls(filename):
    feeds = yaml.safe_load((CONFIG_DIR / filename).read_text(encoding="utf-8"))
    return {feed["url"] for feed in feeds}


def _feeds_by_url(filename):
    feeds = yaml.safe_load((CONFIG_DIR / filename).read_text(encoding="utf-8"))
    return {feed["url"]: feed for feed in feeds}


def test_native_feed_urls_are_unique_and_current():
    feeds = list(_native_feeds_by_url().values())
    urls = [feed["url"] for feed in feeds]
    retired = {
        "https://www.sentinelone.com/feed/",
        "https://www.mandiant.com/resources/blog/rss.xml",
        "https://threatconnect.com/blog/feed/",
        "https://www.cybereason.com/blog/rss.xml",
    }

    assert len(urls) == len(set(urls))
    assert retired.isdisjoint(urls)
    assert "https://research.intezer.com/index.xml" not in urls
    assert "https://www.imperva.com/blog/feed/" not in urls
    assert "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf" not in urls
    assert "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml" in urls
    assert "https://www.volexity.com/feed/" in urls
    assert "https://www.varonis.com/blog/rss.xml" not in urls
    assert "https://feeds.feedburner.com/TrendMicroResearch" not in urls


def test_low_cadence_authoritative_feeds_have_explicit_freshness_policy():
    feeds = _native_feeds_by_url()

    trend = feeds["https://newsroom.trendmicro.com/cyberthreat?pagetemplate=rss"]
    cert_ua = feeds["https://cert.gov.ua/api/articles/rss"]
    cert_eu = feeds["https://cert.europa.eu/publications/threat-intelligence-rss"]
    volexity = feeds["https://www.volexity.com/feed/"]

    assert trend["name"] == "Trend Micro Cyberthreat News"
    assert trend["stale_after_days"] == 45
    assert cert_ua["name"] == "CERT-UA"
    assert cert_ua["stale_after_days"] == 90
    assert cert_eu["stale_after_days"] == 45
    assert volexity["name"] == "Volexity"
    assert volexity["stale_after_days"] == 45


def test_problematic_feed_endpoints_and_searches_are_replaced():
    native = _feed_urls("feeds_native.yaml")
    google = _feed_urls("feeds_google.yaml")
    bing = _feed_urls("feeds_bing.yaml")

    assert "https://orca.security/resources/blog/feed/" not in native
    assert "https://orca.security/feed/?output=1" not in native
    retired_orca_search = (
        "https://news.google.com/rss/search?q=site%3Aorca.security+cloud+security"
        "&hl=en-US&gl=US&ceid=US:en"
    )
    current_orca_search = (
        "https://news.google.com/rss/search?q=site%3Aorca.security%2Fresources%2Fblog+"
        "%28vulnerability+OR+research+OR+threat%29+when%3A90d"
        "&hl=en-US&gl=US&ceid=US:en"
    )
    assert retired_orca_search not in google
    assert current_orca_search in google
    assert _feeds_by_url("feeds_google.yaml")[current_orca_search]["stale_after_days"] == 45

    retired_databreaches = "https://databreaches.net/feed/"
    databreaches_discovery = (
        "https://news.google.com/rss/search?q=site%3Adatabreaches.net+"
        "%28breach+OR+ransomware+OR+leak%29+when%3A30d"
        "&hl=en-US&gl=US&ceid=US:en"
    )
    assert retired_databreaches not in native
    assert databreaches_discovery in google
    assert _feeds_by_url("feeds_google.yaml")[databreaches_discovery]["name"] == (
        "DataBreaches.Net"
    )

    retired_africa = (
        "https://news.google.com/rss/search?q=cyber+attack+Africa+South+Africa+"
        "Nigeria+Kenya&hl=en&gl=ZA&ceid=ZA:en"
    )
    current_africa = (
        "https://news.google.com/rss/search?q=%28cyberattack+OR+%22cyber+attack%22+"
        "OR+ransomware+OR+%22data+breach%22%29+%28%22South+Africa%22+OR+Nigeria+"
        "OR+Kenya+OR+Ghana%29+when%3A30d&hl=en-ZA&gl=ZA&ceid=ZA:en"
    )
    assert retired_africa not in google
    assert current_africa in google

    retired_latam = (
        "https://news.google.com/rss/search?q=data+breach+Latin+America"
        "&hl=en&gl=US&ceid=US:en"
    )
    current_latam = (
        "https://news.google.com/rss/search?q=%28ciberataque+OR+ransomware+OR+"
        "%22filtraci%C3%B3n+de+datos%22%29+%28M%C3%A9xico+OR+Brasil+OR+Argentina+"
        "OR+Colombia+OR+Chile%29+when%3A30d&hl=es-419&gl=MX&ceid=MX:es-419"
    )
    retired_mena = (
        "https://www.bing.com/news/search?q=cyber+attack+Middle+East+"
        "Saudi+Arabia+UAE+Qatar&format=rss"
    )
    current_mena = (
        "https://news.google.com/rss/search?q=%28cyberattack+OR+ransomware+OR+"
        "%22data+breach%22%29+%28UAE+OR+%22Saudi+Arabia%22+OR+Qatar+OR+Bahrain+"
        "OR+Oman+OR+Kuwait%29+when%3A30d&hl=en-AE&gl=AE&ceid=AE:en"
    )
    assert retired_latam not in google
    assert current_latam in google
    assert retired_mena not in bing
    assert current_mena in google

    ahnlab_url = "https://asec.ahnlab.com/en/feed/"
    assert ahnlab_url in native
    assert _feeds_by_url("feeds_native.yaml")[ahnlab_url]["user_agent"].startswith("ThreatWatch/")

    retired_google = {
        "https://news.google.com/rss/search?q=APT+threat+actor+campaign&hl=en-US&gl=US&ceid=US:en",
        "https://news.google.com/rss/search?q=Scattered+Spider+UNC3944+cybercrime&hl=en-US&gl=US&ceid=US:en",
        "https://news.google.com/rss/search?q=%28%22Scattered+Spider%22+OR+UNC3944%29&hl=en-US&gl=US&ceid=US:en",
        "https://news.google.com/rss/search?q=Hunters+International+Qilin+INC+Ransom+ransomware&hl=en-US&gl=US&ceid=US:en",
        "https://news.google.com/rss/search?q=cyber+attack+Middle+East&hl=en-AE&gl=AE&ceid=AE:en",
        "https://news.google.com/rss/search?q=cyber+attack+China+Taiwan&hl=en&gl=US&ceid=US:en",
        "https://news.google.com/rss/search?q=ataque+cibern%C3%A9tico+Argentina+Colombia+Chile&hl=es&gl=AR&ceid=AR:es",
    }
    assert retired_google.isdisjoint(google)
    assert "https://news.google.com/rss/search?q=%28APT+OR+%22threat+actor%22%29+cybersecurity&hl=en-US&gl=US&ceid=US:en" in google
    assert (
        "https://news.google.com/rss/search?q=%28%22Scattered+Spider%22+OR+UNC3944+OR+%22Muddled+Libra%22+OR+%22Octo+Tempest%22%29+when%3A30d"
        "&hl=en-US&gl=US&ceid=US:en"
    ) in google
    assert "https://www.bing.com/news/search?q=cybersecurity+Latin+America&format=rss" in bing


def test_primary_security_source_expansion_is_configured():
    feeds = _native_feeds_by_url()
    expected = {
        "https://aws.amazon.com/security/security-bulletins/rss/feed/": (
            "AWS Security Bulletins",
            "Global",
        ),
        "https://www.microsoft.com/en-us/security/blog/feed/": (
            "Microsoft Security Blog",
            "Global",
        ),
        "https://aws.amazon.com/blogs/security/feed/": (
            "AWS Security Blog",
            "Global",
        ),
    }

    for url, (name, region) in expected.items():
        assert feeds[url]["name"] == name
        assert feeds[url]["category"] == "Native"
        assert feeds[url]["region"] == region

    assert "https://www.morphisec.com/blog/topic/threat-research/feed/" not in feeds


def test_cert_poland_keeps_its_configured_region():
    feeds = _native_feeds_by_url()

    assert feeds["https://www.cert.pl/en/feed"]["region"] == "Poland"


def test_disabled_feed_blocks_do_not_leave_active_metadata():
    contents = CONFIG_PATH.read_text(encoding="utf-8")
    active_keys = {"name", "category", "region", "user_agent"}
    disabled_url = None

    for line_number, line in enumerate(contents.splitlines(), 1):
        if line.startswith("# - url:"):
            disabled_url = line.removeprefix("# - url:").strip()
            continue
        if line.startswith("- url:"):
            disabled_url = None
            continue
        if disabled_url is None or not line.startswith("  "):
            continue
        key = line.strip().partition(":")[0]
        assert key not in active_keys, (
            f"disabled feed {disabled_url} has active {key} metadata "
            f"at line {line_number}"
        )
