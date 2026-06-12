"""IOC (Indicators of Compromise) extraction from article text.

Pulls IPs, domains, URLs, file hashes, and email addresses out of article
title + summary + scraped body so the dashboard can surface them per-article
and so analysts can pivot by indicator.

Non-goals:
- Validation beyond format (e.g., we don't WHOIS-check domains or verify
  hashes against a corpus).
- Enrichment (VirusTotal, PassiveDNS, etc.) — handled separately if ever.

False-positive controls:
- Domains require a TLD from a conservative allowlist so version strings
  (`1.2.3.4`, `v2.0.1`) and file extensions (`report.pdf`) are not mistaken
  for indicators.
- IPs are filtered to public/routable space and reject obvious non-IOC ranges
  (0.0.0.0, 255.255.255.255, broadcast, multicast, private — using the same
  _is_public helper as our SSRF guard so definitions stay consistent).
- "Defanged" notation (`1.2.3[.]4`, `example[.]com`, `hxxp://`, `hxxps://`)
  is re-fanged before matching so CTI reports written in the typical
  defanged style still yield real IOCs.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Iterable

# ── refang ────────────────────────────────────────────────────────────────────
# The standard CTI defang conventions seen across reports and feeds.
_REFANG_PATTERNS: tuple[tuple[str, str], ...] = (
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[:]", ":"),
    ("[/]", "/"),
    ("hxxp://", "http://"),
    ("hxxps://", "https://"),
    ("hXXp://", "http://"),
    ("hXXps://", "https://"),
    ("[at]", "@"),
    ("[@]", "@"),
)


def refang(text: str) -> str:
    """Undo common IOC defanging so the regexes below can match naturally."""
    if not text:
        return text
    for pat, repl in _REFANG_PATTERNS:
        if pat in text:
            text = text.replace(pat, repl)
    return text


# ── regexes ───────────────────────────────────────────────────────────────────
_IPV4_RE = re.compile(
    r"(?<![\d.])"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\."
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\."
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\."
    r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)"
    r"(?![\d.])"
)

# Rough IPv6 — global unicast 2xxx: prefix is what we actually care about for
# IOCs; fe80::/loopback are filtered out anyway by _is_public. The regex is
# intentionally loose; we validate with ipaddress.ip_address() after matching.
_IPV6_RE = re.compile(r"\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b")

_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE   = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE    = re.compile(r"\b[a-fA-F0-9]{32}\b")

_URL_RE = re.compile(
    r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",
    re.IGNORECASE,
)

_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# Domain regex kept conservative: require a TLD from a small, widely-cited
# allowlist so version numbers and filenames don't pollute results. Additional
# TLDs can be added as patterns emerge in intel.
_DOMAIN_TLD_ALLOWLIST = {
    "com", "net", "org", "io", "co", "dev", "app", "info", "biz", "gov",
    "mil", "edu", "int", "us", "uk", "de", "fr", "it", "es", "nl", "ru",
    "cn", "jp", "kr", "in", "br", "ca", "au", "mx", "ar", "ch", "se",
    "no", "fi", "dk", "ie", "pl", "cz", "ua", "ro", "gr", "tr", "sa",
    "ae", "za", "ng", "ke", "eg", "il", "sg", "hk", "tw", "th", "vn",
    "id", "my", "ph", "pk", "bd", "pt", "be", "at", "hu", "sk", "cl",
    "pe", "ve", "nz", "tech", "xyz", "site", "online", "club", "top",
    "cloud", "ai", "dev", "shop", "store", "digital", "io", "me", "cc",
    "tv", "fm", "gg", "pw", "ws", "la", "so", "to", "sh", "sc",
}
_DOMAIN_RE = re.compile(
    r"\b"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:[A-Za-z]{2,24})"
    r"\b"
)

# Common-word false positives (seen in feed titles). Blocked explicitly
# because they tokenise into plausible "domain" shapes but are never IOCs.
_DOMAIN_BLOCKLIST = frozenset({
    "e.g", "i.e", "etc.", "vs.", "fig.",
})

# Legitimate sites that routinely appear in article bodies as source citations,
# vendor-advisory links, or brand mentions — not indicators of compromise.
# Curated from the live distribution: the top 20 extracted domains during the
# post-deploy validation pass were almost entirely news / vendor / social
# media sites, which drowned out the real C2 / phishing domains.
_BENIGN_DOMAINS = frozenset({
    # News and security media
    "cyberpress.org", "thehackernews.com", "bleepingcomputer.com",
    "darkreading.com", "securityweek.com", "scmagazine.com", "scworld.com",
    "csoonline.com", "techradar.com", "hothardware.com", "socradar.io",
    "cybersecuritynews.com", "infosecurity-magazine.com", "helpnetsecurity.com",
    "theregister.com", "the420.in", "marketscreener.com", "01net.com",
    "wired.com", "ars-technica.com", "arstechnica.com", "cnet.com",
    "reuters.com", "bloomberg.com", "ft.com", "nytimes.com", "wsj.com",
    "gbhackers.com", "pymnts.com", "mezha.net", "openpr.com", "vietnam.vn",
    "vulncheck.com", "vuldb.com", "cpuid.com", "shutterstock.com",
    "wordfence.com", "autodesk.com", "appstreaming.autodesk.com",
    # Advisory / NVD / government
    "nvd.nist.gov", "nist.gov", "cve.mitre.org", "cisa.gov", "ncsc.gov.uk",
    "advisory.splunk.com", "helpx.adobe.com", "support.microsoft.com",
    "msrc.microsoft.com", "cert.gov.ua", "cert-fr.cossi.fr", "cert.pl",
    "first.org", "attack.mitre.org", "sans.org", "sans.edu",
    "plugins.trac.wordpress.org", "wordpress.org",
    # Dark-web trackers used as sources by the pipeline itself
    "ransomware.live", "ransomwatch.net", "threatfox.abuse.ch",
    "abuse.ch", "malware-traffic-analysis.net", "databreaches.net",
    # Social and code hosting
    "x.com", "twitter.com", "t.me", "linkedin.com", "facebook.com",
    "github.com", "sourceforge.net", "onworks.net",
    # Ubiquitous vendor brands that appear as mentions, not IOCs
    "microsoft.com", "google.com", "apple.com", "amazon.com", "aws.amazon.com",
    "cloudflare.com", "akamai.com", "booking.com", "airbnb.com",
    "wordpress.com", "medium.com", "youtube.com", "youtu.be", "reddit.com",
})

# Placeholder IPs that show up in docs, examples, and version strings far
# more often than as real indicators. Kept intentionally tiny: we don't
# blocklist 1.1.1.1 / 8.8.8.8 because malware DOES occasionally exfil through
# public resolvers and blocking them here would lose real IOCs.
_IP_PLACEHOLDERS = frozenset({
    "1.2.3.4",  # RFC 5737 test net — but also the canonical "version number"
    "4.3.2.1",
    "0.0.0.0",
    "255.255.255.255",
})

# Trailing punctuation that commonly leaks into URL regex matches — we strip
# it because end-of-sentence dots etc. are not part of the URL.
_URL_TRAILING_STRIP = ".,;:!?)>}]\"'"


# ── helpers ───────────────────────────────────────────────────────────────────
def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_unspecified or ip.is_multicast
    )


def _extract_domains(text: str) -> set[str]:
    out: set[str] = set()
    for m in _DOMAIN_RE.finditer(text):
        d = m.group(0).lower()
        if d in _DOMAIN_BLOCKLIST:
            continue
        tld = d.rsplit(".", 1)[-1]
        if tld not in _DOMAIN_TLD_ALLOWLIST:
            continue
        # Drop emails (already extracted separately; the domain-side of an
        # email is not an IOC on its own in this pipeline).
        if _EMAIL_RE.search(d):
            continue
        # Skip benign news / vendor / aggregator domains so the extracted
        # IOC list is dominated by real malicious indicators rather than
        # source citations. An eTLD+1 check catches subdomains too
        # (help.adobe.com -> adobe.com match).
        etld1 = ".".join(d.split(".")[-2:])
        if d in _BENIGN_DOMAINS or etld1 in _BENIGN_DOMAINS:
            continue
        out.add(d)
    return out


# 32/40-hex strings are ambiguous: git commit IDs, compact UUIDs, tracking
# tokens. Only treat them as malware hashes when the surrounding text talks
# about hashes/samples/IOCs — a SHA256 (64 hex) is specific enough on its own.
_HASH_CONTEXT_RE = re.compile(
    r"(?:\bmd5\b|\bsha-?1\b|\bsha-?256\b|\bhash(?:es)?\b|\bchecksum\b|"
    r"\bsample\b|\bioc\b|\bindicator)",
    re.IGNORECASE,
)


def _extract_hashes(text: str) -> tuple[set[str], set[str], set[str]]:
    sha256 = {m.group(0).lower() for m in _SHA256_RE.finditer(text)}
    has_hash_context = bool(_HASH_CONTEXT_RE.search(text))
    sha1 = (
        {m.group(0).lower() for m in _SHA1_RE.finditer(text)}
        if has_hash_context else set()
    )
    md5 = (
        {m.group(0).lower() for m in _MD5_RE.finditer(text)}
        if has_hash_context else set()
    )
    # SHA256 hex strings also match the SHA1/MD5 regexes (40/32 hex is a prefix
    # of 64 hex); subtract so each hash is counted once under its correct type.
    sha1 -= {h[:40] for h in sha256}
    md5 -= {h[:32] for h in sha256}
    md5 -= {h[:32] for h in sha1}
    return sha256, sha1, md5


# ── public API ────────────────────────────────────────────────────────────────
def extract_iocs(text: str | None) -> dict[str, list[str]]:
    """Return the set of IOCs found in `text`, grouped by type.

    The returned dict has stable keys (empty lists instead of missing keys)
    so frontend code can iterate without `.get(..., [])`.
    """
    empty = {"ipv4": [], "ipv6": [], "domains": [], "urls": [],
             "sha256": [], "sha1": [], "md5": [], "emails": []}
    if not text:
        return empty

    t = refang(text)

    ipv4 = sorted({
        m.group(0) for m in _IPV4_RE.finditer(t)
        if _is_public_ip(m.group(0)) and m.group(0) not in _IP_PLACEHOLDERS
    })
    ipv6 = sorted({m.group(0) for m in _IPV6_RE.finditer(t)
                   if _is_public_ip(m.group(0))})
    urls = sorted({m.group(0).rstrip(_URL_TRAILING_STRIP) for m in _URL_RE.finditer(t)})
    emails = sorted({m.group(0).lower() for m in _EMAIL_RE.finditer(t)})
    domains = sorted(_extract_domains(t))
    sha256, sha1, md5 = _extract_hashes(t)

    return {
        "ipv4":    ipv4,
        "ipv6":    ipv6,
        "domains": domains,
        "urls":    urls,
        "sha256":  sorted(sha256),
        "sha1":    sorted(sha1),
        "md5":     sorted(md5),
        "emails":  emails,
    }


def has_any_iocs(iocs: dict) -> bool:
    return any(iocs.get(k) for k in ("ipv4", "ipv6", "domains", "urls",
                                      "sha256", "sha1", "md5", "emails"))


def annotate_articles_with_iocs(articles: Iterable[dict]) -> int:
    """Extract IOCs from each article's title+summary+full_content in place.

    Writes the `iocs` key when at least one indicator was found; otherwise
    leaves the article unchanged (avoiding empty-dict bloat on the SSR wire).
    Returns the number of articles annotated.
    """
    hits = 0
    for a in articles:
        text = " ".join(filter(None, [
            a.get("title"), a.get("summary"), a.get("full_content"),
        ]))
        iocs = extract_iocs(text)
        if has_any_iocs(iocs):
            a["iocs"] = iocs
            hits += 1
        elif "iocs" in a:
            del a["iocs"]
    return hits
