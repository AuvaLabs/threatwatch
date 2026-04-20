"""Incident correlator: groups related articles about the same event.

Uses zero-cost entity extraction (CVE IDs, threat actors, organization names)
to cluster articles. Optionally generates AI synthesis for large clusters.
"""

import hashlib
import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from modules.config import OUTPUT_DIR, STATE_DIR

logger = logging.getLogger(__name__)

CLUSTERS_PATH = OUTPUT_DIR / "clusters.json"

# Entity extraction patterns
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Major organization names for clustering (avoid overly generic names)
_ORG_PATTERNS = [
    (re.compile(r"\b(Microsoft|Google|Apple|Amazon|Meta|Facebook)\b"), None),
    (re.compile(r"\b(Cisco|Fortinet|Palo Alto|CrowdStrike|SentinelOne)\b"), None),
    (re.compile(r"\b(Ivanti|VMware|Citrix|F5|SonicWall|Juniper)\b"), None),
    (re.compile(r"\b(Oracle|SAP|Salesforce|Adobe|Atlassian)\b"), None),
    (re.compile(r"\b(FBI|CISA|NSA|Europol|Interpol|NCSC)\b"), None),
    (re.compile(r"\b(NHS|MOVEit|SolarWinds|Log4j|Exchange)\b"), None),
]

# Threat actor patterns (Python versions of the frontend ACTOR_PATTERNS)
_ACTOR_PATTERNS = [
    # Nation-State: Russia
    (re.compile(r"\bAPT28\b|Fancy\s*Bear|Forest\s*Blizzard", re.I), "APT28", "Nation-State", "Russia"),
    (re.compile(r"\bAPT29\b|Cozy\s*Bear|Midnight\s*Blizzard|Nobelium", re.I), "APT29", "Nation-State", "Russia"),
    (re.compile(r"Sandworm|Seashell\s*Blizzard", re.I), "Sandworm", "Nation-State", "Russia"),
    (re.compile(r"Gamaredon|Shuckworm", re.I), "Gamaredon", "Nation-State", "Russia"),
    (re.compile(r"\bTurla\b|Venomous\s*Bear", re.I), "Turla", "Nation-State", "Russia"),
    # Nation-State: China
    (re.compile(r"\bAPT41\b|Winnti|Double\s*Dragon", re.I), "APT41", "Nation-State", "China"),
    (re.compile(r"Volt\s*Typhoon", re.I), "Volt Typhoon", "Nation-State", "China"),
    (re.compile(r"Salt\s*Typhoon", re.I), "Salt Typhoon", "Nation-State", "China"),
    (re.compile(r"Mustang\s*Panda", re.I), "Mustang Panda", "Nation-State", "China"),
    (re.compile(r"Silk\s*Typhoon|Hafnium", re.I), "Silk Typhoon", "Nation-State", "China"),
    # Nation-State: North Korea
    (re.compile(r"Lazarus|Hidden\s*Cobra", re.I), "Lazarus Group", "Nation-State", "North Korea"),
    (re.compile(r"Kimsuky|Emerald\s*Sleet", re.I), "Kimsuky", "Nation-State", "North Korea"),
    (re.compile(r"BlueNoroff|Sapphire\s*Sleet", re.I), "BlueNoroff", "Nation-State", "North Korea"),
    # Nation-State: Iran
    (re.compile(r"MuddyWater|Mango\s*Sandstorm", re.I), "MuddyWater", "Nation-State", "Iran"),
    (re.compile(r"Charming\s*Kitten|APT35|Mint\s*Sandstorm", re.I), "Charming Kitten", "Nation-State", "Iran"),
    (re.compile(r"CyberAv3ngers", re.I), "CyberAv3ngers", "Nation-State", "Iran"),
    (re.compile(r"\bHandala\b", re.I), "Handala", "Nation-State", "Iran"),
    # Ransomware
    (re.compile(r"LockBit", re.I), "LockBit", "Ransomware", "Criminal"),
    (re.compile(r"BlackCat|ALPHV", re.I), "BlackCat/ALPHV", "Ransomware", "Criminal"),
    (re.compile(r"\bCl0p\b|Clop", re.I), "Cl0p", "Ransomware", "Criminal"),
    (re.compile(r"\bAkira\b", re.I), "Akira", "Ransomware", "Criminal"),
    (re.compile(r"Black\s*Basta", re.I), "Black Basta", "Ransomware", "Criminal"),
    (re.compile(r"RansomHub", re.I), "RansomHub", "Ransomware", "Criminal"),
    (re.compile(r"\bQilin\b", re.I), "Qilin", "Ransomware", "Criminal"),
    (re.compile(r"Scattered\s*Spider|UNC3944", re.I), "Scattered Spider", "Cybercrime", "Unknown"),
    (re.compile(r"ShinyHunters", re.I), "ShinyHunters", "Cybercrime", "Unknown"),
]


def _parse_published(raw: str | None) -> datetime | None:
    """Best-effort parse of `published` which may be RFC822 or ISO8601."""
    if not raw:
        return None
    dt: datetime | None = None
    # Try ISO8601 first (cheap; matches "2026-04-14T18:17:35.100")
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        dt = None
    # Fall back to RFC822 (e.g. "Fri, 17 Apr 2026 11:30:00 GMT")
    if dt is None:
        try:
            dt = parsedate_to_datetime(raw)
        except (ValueError, TypeError):
            dt = None
    if dt and dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _extract_entities(article: dict) -> list[tuple[str, str]]:
    """Extract clustering entities from an article. Returns [(type, entity_name)]."""
    title = article.get("title", "")
    summary = article.get("summary", "") or ""
    text = title + " " + summary
    entities = []

    # CVE IDs — strongest clustering signal
    for m in _CVE_RE.finditer(text):
        entities.append(("cve", m.group(0).upper()))

    # Threat actors
    for pat, name, actor_type, origin in _ACTOR_PATTERNS:
        if pat.search(text):
            entities.append(("actor", name))

    # Organizations (only from title — too noisy in body)
    for pat, _ in _ORG_PATTERNS:
        m = pat.search(title)
        if m:
            entities.append(("org", m.group(1)))

    return entities


def cluster_articles(articles: list[dict[str, Any]]) -> dict[str, Any]:
    """Group related articles by shared entities.

    Returns cluster data with optional AI synthesis for 3+ article clusters.
    """
    # Build entity → article indices mapping
    entity_to_indices = defaultdict(set)
    article_entities = []

    for i, article in enumerate(articles):
        entities = _extract_entities(article)
        article_entities.append(entities)
        for entity in entities:
            entity_to_indices[entity].add(i)

    # Build clusters: groups of 3+ articles sharing an entity
    clusters = []
    seen_indices = set()

    # Sort by cluster size descending — largest clusters first
    sorted_entities = sorted(
        entity_to_indices.items(),
        key=lambda x: len(x[1]),
        reverse=True,
    )

    for (entity_type, entity_name), indices in sorted_entities:
        if len(indices) < 3:
            continue

        # Skip articles already assigned to a larger cluster
        new_indices = indices - seen_indices
        if len(new_indices) < 2:
            continue

        cluster_indices = sorted(indices)  # Include all related
        seen_indices.update(cluster_indices)

        cluster_articles_data = []
        for idx in cluster_indices[:10]:  # Cap at 10 per cluster (preview only)
            a = articles[idx]
            cluster_articles_data.append({
                "title": a.get("title", ""),
                "link": a.get("link", ""),
                "source_name": a.get("source_name", ""),
                "published": a.get("published", ""),
                "category": a.get("category", ""),
                "summary": (a.get("summary") or "")[:200],
            })

        # Full member list (by hash) + earliest publish date — used by the
        # frontend to render "Story first seen N days ago" on every related
        # article card, so recurring coverage of the same CVE does not look
        # like distinct 24h stories.
        article_hashes = []
        first_seen_dt: datetime | None = None
        for idx in cluster_indices:
            a = articles[idx]
            h = a.get("hash")
            if h:
                article_hashes.append(h)
            dt = _parse_published(a.get("published"))
            if dt and (first_seen_dt is None or dt < first_seen_dt):
                first_seen_dt = dt

        clusters.append({
            "entity_type": entity_type,
            "entity_name": entity_name,
            "article_count": len(indices),
            "articles": cluster_articles_data,
            "article_hashes": article_hashes,
            "first_seen": first_seen_dt.isoformat() if first_seen_dt else None,
            "synthesis": None,  # Filled by AI if available
        })

    # AI synthesis for top clusters (limit token usage)
    _synthesize_clusters(clusters[:8])

    # Persist every cluster (not just top 15) so the frontend can annotate
    # all related articles. Display surfaces still slice to their own caps.
    cluster_data = {
        "clusters": clusters,
        "total_clusters": len(clusters),
        "articles_clustered": len(seen_indices),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    _save_clusters(cluster_data)
    if clusters:
        logger.info(
            f"Incident correlator: {len(clusters)} clusters found, "
            f"{len(seen_indices)} articles grouped."
        )
    return cluster_data


def _synthesize_clusters(clusters: list[dict]) -> None:
    """Generate AI synthesis for large clusters."""
    try:
        from modules.llm_client import call_llm, is_available
        from modules.ai_cache import get_cached_result, cache_result

        if not is_available():
            return

        for cluster in clusters:
            if cluster["article_count"] < 3:
                continue

            titles = [a["title"] for a in cluster["articles"][:8]]
            digest = "\n".join(f"- {t}" for t in titles)
            cache_key = "cluster_" + hashlib.sha256(digest.encode()).hexdigest()

            cached = get_cached_result(cache_key)
            if cached is not None:
                cluster["synthesis"] = cached
                continue

            try:
                reply = call_llm(
                    user_content=f"Entity: {cluster['entity_name']} ({cluster['entity_type']})\n\nRelated articles:\n{digest}",
                    system_prompt=(
                        "You are a CTI analyst. In 2 sentences, synthesize these related "
                        "incidents into a single intelligence finding. What pattern, campaign, "
                        "or story do they collectively represent? Be specific and factual."
                    ),
                    max_tokens=150,
                )
                cluster["synthesis"] = reply.strip()
                cache_result(cache_key, reply.strip())
            except Exception as e:
                logger.debug(f"Cluster synthesis failed: {e}")

    except ImportError:
        pass


def _save_clusters(data: dict) -> None:
    CLUSTERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CLUSTERS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)


def load_clusters() -> dict | None:
    if not CLUSTERS_PATH.exists():
        return None
    try:
        with open(CLUSTERS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None
