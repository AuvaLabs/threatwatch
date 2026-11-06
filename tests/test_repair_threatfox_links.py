from scripts.repair_threatfox_links import repair_links


def test_repairs_matching_threatfox_link_without_mutating_input():
    original = {
        "hash": "same-hash",
        "source": "darkweb:threatfox",
        "link": "https://threatfox.abuse.ch/browse/malware/quasar-rat/",
    }
    fresh = {
        "hash": "same-hash",
        "source": "darkweb:threatfox",
        "link": "https://threatfox.abuse.ch/browse/malware/win.quasar_rat/",
    }

    repaired, count = repair_links([original], [fresh])

    assert count == 1
    assert repaired[0]["link"].endswith("/win.quasar_rat/")
    assert original["link"].endswith("/quasar-rat/")


def test_ignores_unrelated_or_untrusted_replacements():
    articles = [
        {"hash": "news", "source": "rss", "link": "https://example.com/story"},
        {
            "hash": "threatfox",
            "source": "darkweb:threatfox",
            "link": "https://threatfox.abuse.ch/browse/",
        },
    ]
    fresh = [
        {
            "hash": "news",
            "source": "darkweb:threatfox",
            "link": "https://threatfox.abuse.ch/browse/malware/win.test/",
        },
        {
            "hash": "threatfox",
            "source": "darkweb:threatfox",
            "link": "https://attacker.example/malware/win.test/",
        },
    ]

    repaired, count = repair_links(articles, fresh)

    assert count == 0
    assert repaired == articles
