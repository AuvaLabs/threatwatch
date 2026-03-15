"""Watchlist Monitor — brand and technology/asset keyword monitoring.

Two modes:
  Hosted:      tag_articles_with_vendors() annotates articles at ingest time
               with which suggest-list vendors they mention. Frontend filters
               by user's localStorage selection — no extra HTTP requests.

  Self-hosted: additionally reads data/state/watchlist.json for custom brand/
               asset keywords and runs targeted Google News RSS searches.
               Requires WATCHLIST_WRITE_ENABLED=true in env.
"""

import hashlib
import json
import logging
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

import requests

from modules.config import FEED_CUTOFF_DAYS, STATE_DIR

log = logging.getLogger(__name__)

# ── Comprehensive vendor / technology suggest-list ───────────────────────────
# Organised by category. This is the canonical list used by both the backend
# tagger and the frontend checkbox UI. Keep entries unique across categories.

VENDOR_SUGGEST_LIST: dict[str, list[str]] = {
    "Endpoint Security": [
        "CrowdStrike", "SentinelOne", "Carbon Black", "Cybereason",
        "Trend Micro", "Symantec", "McAfee", "ESET", "Sophos",
        "Malwarebytes", "Huntress", "ThreatLocker", "Darktrace",
        "Cylance", "Webroot", "Bitdefender", "Kaspersky", "Trellix",
        "Microsoft Defender", "Cortex XDR",
    ],
    "Network Security": [
        "Palo Alto Networks", "Fortinet", "Check Point", "SonicWall",
        "Barracuda", "Zscaler", "Cisco", "Juniper Networks", "F5",
        "Citrix", "Ivanti", "Aruba Networks", "Zyxel", "WatchGuard",
        "Netscout", "Infoblox", "Stormshield", "Cradlepoint",
        "Radware", "Cloudflare Gateway",
    ],
    "Identity & Access": [
        "Okta", "CyberArk", "BeyondTrust", "Ping Identity", "OneLogin",
        "SailPoint", "Saviynt", "Duo Security", "RSA Security",
        "Thales", "ForgeRock", "Microsoft Entra", "Delinea",
        "HashiCorp Vault", "JumpCloud",
    ],
    "Cloud Platforms": [
        "AWS", "Microsoft Azure", "Google Cloud", "Oracle Cloud",
        "IBM Cloud", "Alibaba Cloud", "Cloudflare", "Akamai",
        "Fastly", "DigitalOcean", "Rackspace", "Linode",
        "Hetzner", "OVHcloud", "Vultr",
    ],
    "Enterprise Software": [
        "Microsoft", "SAP", "Oracle", "Salesforce", "ServiceNow",
        "Workday", "Adobe", "Atlassian", "VMware", "IBM",
        "Zoom", "Slack", "Progress Software", "OpenText",
        "Broadcom", "Ivanti", "Zoho", "HCL Software",
    ],
    "Email & Collaboration": [
        "Microsoft Exchange", "Office 365", "Google Workspace",
        "Proofpoint", "Mimecast", "Zimbra", "Sendgrid",
        "Postfix", "Exim", "Roundcube", "IceWarp",
    ],
    "DevOps & Developer Tools": [
        "GitHub", "GitLab", "JetBrains", "Docker", "Kubernetes",
        "Terraform", "HashiCorp", "Jenkins", "Ansible",
        "JFrog", "Nexus Repository", "CircleCI", "TeamCity",
        "ArgoCD", "Helm",
    ],
    "Database & Data": [
        "Oracle Database", "Microsoft SQL Server", "MySQL", "PostgreSQL",
        "MongoDB", "Redis", "Elasticsearch", "Snowflake",
        "Databricks", "Cassandra", "CouchDB", "InfluxDB",
        "MariaDB", "SQLite",
    ],
    "Supply Chain (Known Incidents)": [
        "SolarWinds", "Kaseya", "3CX", "MOVEit", "Log4j",
        "XZ Utils", "PyPI", "npm", "RubyGems", "Codecov",
        "Polyfill", "MiMedx",
    ],
    "Hardware & Chips": [
        "Intel", "AMD", "NVIDIA", "Qualcomm", "Broadcom",
        "Dell", "HP", "Lenovo", "Supermicro", "ASUS",
        "Marvell", "Arm", "MediaTek", "Samsung", "Seagate",
        "Western Digital",
    ],
    "Industrial / OT / ICS": [
        "Siemens", "Schneider Electric", "Rockwell Automation",
        "Honeywell", "GE Digital", "ABB", "Emerson",
        "Yokogawa", "AVEVA", "Inductive Automation",
        "Beckhoff", "Mitsubishi Electric",
    ],
    "Storage & Backup": [
        "Veeam", "Commvault", "NetApp", "Pure Storage",
        "Rubrik", "Cohesity", "Veritas", "Acronis",
        "Zerto", "Druva", "MSP360",
    ],
    "IoT & Physical Security": [
        "Hikvision", "Dahua", "Axis Communications", "D-Link",
        "TP-Link", "Netgear", "Ubiquiti", "Wyze", "Reolink",
        "Hanwha", "Bosch Security", "Genetec",
    ],
    "CDN & DNS": [
        "Cloudflare", "Akamai", "Verisign", "Infoblox",
        "BlueCat", "NS1", "Neustar", "Dyn",
    ],
    "Telecom": [
        "Ericsson", "Nokia", "Huawei", "T-Mobile", "AT&T",
        "Vodafone", "Verizon", "BT Group", "Orange",
        "Deutsche Telekom", "NTT", "Lumen Technologies",
    ],
    "Financial Technology": [
        "Stripe", "PayPal", "Block", "Visa", "Mastercard",
        "Swift", "Finastra", "Temenos", "NCR",
        "Fiserv", "Jack Henry", "Verifone",
    ],
    "Security Operations": [
        "Splunk", "IBM QRadar", "Microsoft Sentinel", "Elastic SIEM",
        "LogRhythm", "Exabeam", "Securonix", "Chronicle",
        "Recorded Future", "ThreatConnect", "Anomali",
    ],
    "Vulnerability Management": [
        "Tenable", "Qualys", "Rapid7", "Vulcan Cyber",
        "Wiz", "Orca Security", "Lacework", "Snyk",
        "Checkmarx", "Veracode",
    ],
}

# Flat list for iteration (deduped by insertion order)
_seen: set[str] = set()
FLAT_VENDOR_LIST: list[str] = []
for _cat_vendors in VENDOR_SUGGEST_LIST.values():
    for _v in _cat_vendors:
        if _v not in _seen:
            _seen.add(_v)
            FLAT_VENDOR_LIST.append(_v)

# Precompile regex patterns — word-boundary aware, case-insensitive
# Longer entries compiled first so "Microsoft Exchange" matches before "Microsoft"
_SORTED_VENDORS = sorted(FLAT_VENDOR_LIST, key=len, reverse=True)
_VENDOR_PATTERNS: dict[str, re.Pattern] = {
    vendor: re.compile(
        r'(?<![A-Za-z0-9])' + re.escape(vendor) + r'(?![A-Za-z0-9])',
        re.IGNORECASE,
    )
    for vendor in _SORTED_VENDORS
}

WATCHLIST_PATH = STATE_DIR / "watchlist.json"
_GNEWS_RSS = (
    "https://news.google.com/rss/search"
    "?q={query}&hl=en-US&gl=US&ceid=US:en"
)
_REQUEST_DELAY = 2.0  # seconds between Google News requests


# ── Article tagging ───────────────────────────────────────────────────────────

def tag_article_with_vendors(article: dict[str, Any]) -> dict[str, Any]:
    """Scan article text for vendor mentions. Returns article copy with asset_tags."""
    text = " ".join(filter(None, [
        article.get("title", ""),
        article.get("translated_title", ""),
        article.get("summary", ""),
    ]))
    matched = [v for v, pat in _VENDOR_PATTERNS.items() if pat.search(text)]
    if not matched:
        return article
    return {**article, "asset_tags": matched}


def tag_articles_with_vendors(articles: list[dict]) -> list[dict]:
    """Batch-tag a list of articles. Called at end of ingest pipeline."""
    return [tag_article_with_vendors(a) for a in articles]


# ── Watchlist persistence ─────────────────────────────────────────────────────

def load_custom_watchlist() -> dict[str, list[str]]:
    """Load custom brand/asset keywords from watchlist.json."""
    if not WATCHLIST_PATH.exists():
        return {"brands": [], "assets": []}
    try:
        with open(WATCHLIST_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return {
            "brands": [str(k).strip() for k in data.get("brands", []) if str(k).strip()],
            "assets": [str(k).strip() for k in data.get("assets", []) if str(k).strip()],
        }
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Failed to load watchlist: %s", exc)
        return {"brands": [], "assets": []}


def save_watchlist(brands: list[str], assets: list[str]) -> None:
    """Persist custom watchlist to STATE_DIR/watchlist.json."""
    WATCHLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "brands": [b.strip() for b in brands if b.strip()],
        "assets": [a.strip() for a in assets if a.strip()],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(WATCHLIST_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    log.info("Watchlist saved: %d brands, %d assets", len(payload["brands"]), len(payload["assets"]))


# ── Google News RSS fetcher (self-hosted only) ────────────────────────────────

def _fetch_gnews(query: str, cutoff: datetime) -> list[dict]:
    """Fetch Google News RSS for a search query. Returns raw article dicts."""
    url = _GNEWS_RSS.format(query=requests.utils.quote(query))
    articles = []
    try:
        resp = requests.get(
            url, timeout=12,
            headers={"User-Agent": "ThreatWatch/1.0 (security research aggregator)"},
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.content)
        channel = root.find("channel")
        if channel is None:
            return []
        for item in channel.findall("item"):
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            pub_date = (item.findtext("pubDate") or "").strip()
            description = (item.findtext("description") or "").strip()

            pub_dt = _parse_rss_date(pub_date)
            if pub_dt and pub_dt < cutoff:
                continue

            article_hash = hashlib.sha256((title + link).encode()).hexdigest()
            articles.append({
                "title": title,
                "link": link,
                "published": pub_date,
                "summary": description,
                "hash": article_hash,
                "source": "watchlist:gnews",
            })
    except Exception as exc:
        log.warning("Google News RSS failed for '%s': %s", query, exc)
    return articles


def _parse_rss_date(date_str: str) -> datetime | None:
    if not date_str:
        return None
    try:
        return parsedate_to_datetime(date_str)
    except Exception:
        return None


def run_watchlist_monitor() -> list[dict]:
    """Fetch Google News RSS for custom brand/asset keywords (self-hosted only).

    Reads data/state/watchlist.json. Returns articles tagged with brand_tags
    or asset_tags for each matched custom keyword.
    """
    watchlist = load_custom_watchlist()
    brands = watchlist.get("brands", [])
    assets = watchlist.get("assets", [])

    if not brands and not assets:
        log.debug("Watchlist monitor: no custom keywords, skipping")
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=FEED_CUTOFF_DAYS)
    all_articles: list[dict] = []

    for brand in brands:
        query = f'"{brand}" cybersecurity OR breach OR hack OR attack OR vulnerability'
        fetched = _fetch_gnews(query, cutoff)
        for a in fetched:
            a["brand_tags"] = [brand]
            a["source"] = f"watchlist:brand:{brand}"
        all_articles.extend(fetched)
        log.info("Brand watch '%s': %d articles", brand, len(fetched))
        time.sleep(_REQUEST_DELAY)

    for asset in assets:
        query = f'"{asset}" vulnerability OR CVE OR exploit OR breach OR attack'
        fetched = _fetch_gnews(query, cutoff)
        for a in fetched:
            a["asset_tags"] = [asset]
            a["source"] = f"watchlist:asset:{asset}"
        all_articles.extend(fetched)
        log.info("Asset watch '%s': %d articles", asset, len(fetched))
        time.sleep(_REQUEST_DELAY)

    log.info("Watchlist monitor: %d total custom articles", len(all_articles))
    return all_articles
