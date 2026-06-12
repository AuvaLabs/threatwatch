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

# Entity patterns now live in modules.entities. Private-alias re-exports let
# external callers (tests, other modules) keep their existing imports.
from modules.entities import ACTOR_PATTERNS as _ACTOR_PATTERNS
from modules.entities import CVE_RE as _CVE_RE

# Major organization names for clustering (avoid overly generic names)
_ORG_PATTERNS = [
    (re.compile(r"\b(Microsoft|Google|Apple|Amazon|Meta|Facebook)\b"), None),
    (re.compile(r"\b(Cisco|Fortinet|Palo Alto|CrowdStrike|SentinelOne)\b"), None),
    (re.compile(r"\b(Ivanti|VMware|Citrix|F5|SonicWall|Juniper)\b"), None),
    (re.compile(r"\b(Oracle|SAP|Salesforce|Adobe|Atlassian)\b"), None),
    (re.compile(r"\b(FBI|CISA|NSA|Europol|Interpol|NCSC)\b"), None),
    (re.compile(r"\b(NHS|MOVEit|SolarWinds|Log4j|Exchange)\b"), None),
]

def _parse_published(raw: str | None) -> datetime | None:
    """Thin wrapper over date_utils.parse_datetime — call-site stability only."""
    from modules.date_utils import parse_datetime
    return parse_datetime(raw)


def annotate_articles_with_cves(articles: list[dict]) -> int:
    """Extract CVE IDs from title+summary and write them onto each article.

    Runs before output write so `cve_ids` is persisted on every article, not
    just computed ephemerally during clustering. Returns the number of articles
    that gained at least one CVE ID. Safe to call multiple times — overwrites
    any existing `cve_ids` field with the freshly extracted set.
    """
    hits = 0
    for a in articles:
        text = (a.get("title") or "") + " " + (a.get("summary") or "")
        cves = sorted({m.group(0).upper() for m in _CVE_RE.finditer(text)})
        if cves:
            a["cve_ids"] = cves
            hits += 1
        elif "cve_ids" in a:
            # Stale value from a previous enrichment — keep data self-consistent
            del a["cve_ids"]
    return hits


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

        # Sort members by published date ascending BEFORE the 10-article cap
        # so the earliest-reporting outlet is always in the preview and its
        # first entry is the "first reported by" winner. Articles without a
        # parseable date sink to the bottom (parse_datetime returns None, and
        # None compares as larger in the fallback key).
        sorted_members = sorted(
            cluster_indices,
            key=lambda i: _parse_published(articles[i].get("published"))
                          or datetime(9999, 12, 31, tzinfo=timezone.utc),
        )
        cluster_articles_data = []
        for idx in sorted_members[:10]:  # Cap at 10 per cluster (preview only)
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

    # Campaign persistence — annotate each cluster with a stable campaign_id
    # and an ever-earliest first_observed that survives across pipeline runs.
    # The cluster's own `first_seen` only reflects articles inside the rolling
    # 7-day window, so a long-running threat like Volt Typhoon would otherwise
    # look freshly-born every Monday after older coverage ages out.
    try:
        from modules.campaign_tracker import record_clusters, load_campaigns
        campaign_map = record_clusters(clusters)
        campaigns_by_id = load_campaigns()
        for cluster in clusters:
            key = f"{cluster.get('entity_type')}:{cluster.get('entity_name')}"
            cid = campaign_map.get(key)
            if not cid:
                continue
            campaign = campaigns_by_id.get(cid) or {}
            cluster["campaign_id"] = cid
            cluster["first_observed"] = campaign.get("first_observed") or cluster.get("first_seen")
            cluster["campaign_status"] = campaign.get("status") or "active"
            cluster["total_observed_articles"] = campaign.get(
                "total_observed_articles", cluster.get("article_count", 0),
            )
    except Exception as exc:
        logger.warning(f"Campaign tracking failed (non-fatal): {exc}")

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


_SYNTH_PROMPT = (
    "You are a CTI analyst. In 2 sentences, synthesize these related "
    "incidents into a single intelligence finding. What pattern, campaign, "
    "or story do they collectively represent? Be specific and factual. "
    "Only reference CVE IDs, threat actors, and organisations that appear "
    "in the provided article titles."
)

_SYNTH_MAX_CHARS = 500
_SYNTH_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _validate_synthesis(reply: str, source_digest: str) -> str | None:
    """Ground-check an LLM cluster synthesis before it reaches the UI.

    Rejects (returns None) when the synthesis cites a CVE ID that does not
    appear in the source article titles — the same hallucination guard the
    main briefing applies. Truncates runaway replies to _SYNTH_MAX_CHARS.
    """
    text = (reply or "").strip()
    if not text:
        return None
    cited = {m.upper() for m in _SYNTH_CVE_RE.findall(text)}
    grounded = {m.upper() for m in _SYNTH_CVE_RE.findall(source_digest)}
    if cited - grounded:
        logger.warning(
            "Cluster synthesis rejected — ungrounded CVE IDs %s",
            sorted(cited - grounded),
        )
        return None
    if len(text) > _SYNTH_MAX_CHARS:
        text = text[:_SYNTH_MAX_CHARS].rsplit(" ", 1)[0] + "…"
    return text


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
            # Prompt-versioned key: changing _SYNTH_PROMPT invalidates old
            # (possibly hallucinated) syntheses instead of serving them forever.
            prompt_salt = hashlib.sha256(_SYNTH_PROMPT.encode()).hexdigest()[:12]
            cache_key = "cluster_" + hashlib.sha256(
                (prompt_salt + ":" + digest).encode()
            ).hexdigest()

            cached = get_cached_result(cache_key)
            if cached is not None:
                cluster["synthesis"] = cached
                continue

            try:
                reply = call_llm(
                    user_content=f"Entity: {cluster['entity_name']} ({cluster['entity_type']})\n\nRelated articles:\n{digest}",
                    system_prompt=_SYNTH_PROMPT,
                    max_tokens=150,
                    caller="cluster_synth",
                )
                synthesis = _validate_synthesis(reply, digest)
                if synthesis is None:
                    # Reject rather than serve ungrounded analysis; the UI
                    # falls back to listing the member articles.
                    continue
                cluster["synthesis"] = synthesis
                cache_result(cache_key, synthesis)
            except Exception as e:
                logger.debug(f"Cluster synthesis failed: {e}")

    except ImportError:
        pass


def _save_clusters(data: dict) -> None:
    from modules.utils import write_json_atomic
    write_json_atomic(CLUSTERS_PATH, data, ensure_ascii=False)


def load_clusters() -> dict | None:
    if not CLUSTERS_PATH.exists():
        return None
    try:
        with open(CLUSTERS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return None
