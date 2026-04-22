"""Threat actor profiler: generates and caches AI profiles for known actors.

When a threat actor appears in articles, generates a brief profile covering
origin, targets, TTPs, and recent activity. Profiles are cached permanently
in state/actor_profiles.json — near-zero ongoing token cost.

On top of the LLM-generated profile, each entry is enriched with **observed**
MITRE ATT&CK techniques and tactics aggregated from the article corpus.
`signature_ttps` is what the LLM describes; `observed_techniques` /
`observed_tactics` are data-driven counts from the articles that actually
mention the actor — grounding the profile in observable evidence so analysts
can see which TTPs are backed by current reporting.
"""

import json
import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from modules.config import STATE_DIR, OUTPUT_DIR
from modules.entities import ACTOR_PATTERNS as _ACTOR_PATTERNS

logger = logging.getLogger(__name__)

PROFILES_PATH = STATE_DIR / "actor_profiles.json"

# Only profile actors that appear in 2+ articles (avoid noise)
_MIN_ARTICLES_FOR_PROFILE = 2
# Max new profiles per pipeline run (controls token budget)
_MAX_NEW_PROFILES_PER_RUN = 5
# How many top techniques/tactics to surface on each profile
_TOP_TECHNIQUES_PER_ACTOR = 8
_TOP_TACTICS_PER_ACTOR = 6

_PROFILE_PROMPT = """You are a cyber threat intelligence analyst. Generate a brief threat actor profile.

Return ONLY valid JSON (no markdown, no explanation):
{
  "name": "<canonical name>",
  "aliases": ["<known aliases>"],
  "origin": "<country/region of attribution>",
  "type": "<APT|Ransomware-as-a-Service|Cybercrime|Hacktivist|Unknown>",
  "active_since": "<year or 'Unknown'>",
  "target_sectors": ["<top 3 targeted sectors>"],
  "target_regions": ["<top 3 targeted regions>"],
  "signature_ttps": ["<3-4 key TTPs or techniques>"],
  "description": "<3-4 sentence profile: who they are, what they do, notable campaigns>"
}"""


def _load_profiles() -> dict[str, Any]:
    """Load existing profiles from disk."""
    if not PROFILES_PATH.exists():
        return {}
    try:
        with open(PROFILES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}


def _save_profiles(profiles: dict[str, Any]) -> None:
    """Save profiles to disk."""
    PROFILES_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(PROFILES_PATH, "w", encoding="utf-8") as f:
        json.dump(profiles, f, ensure_ascii=False, indent=2)


def extract_actors_from_articles(articles: list[dict]) -> dict[str, dict]:
    """Scan articles for known threat actors.

    Returns {actor_name: {type, origin, count, techniques: Counter, tactics: Counter}}.
    ``techniques`` / ``tactics`` count occurrences of each ATT&CK technique
    ID / tactic name across the articles that mention this actor, so
    downstream code can surface the most-observed TTPs on the profile.
    """
    actor_counts: dict[str, dict] = {}
    for article in articles:
        text = (article.get("title", "") + " " + (article.get("summary") or ""))
        techniques = article.get("attack_techniques") or []
        tactics = article.get("attack_tactics") or []
        for pat, name, actor_type, origin in _ACTOR_PATTERNS:
            if pat.search(text):
                entry = actor_counts.get(name)
                if entry is None:
                    entry = {
                        "type": actor_type,
                        "origin": origin,
                        "count": 0,
                        "techniques": Counter(),
                        "tactics": Counter(),
                    }
                    actor_counts[name] = entry
                entry["count"] += 1
                # attack_tagger emits {"technique_id": "T1566",
                # "technique_name": "...", "tactic": "..."} dicts. Also
                # accept plain string IDs and the simpler {"id": "..."}
                # shape for forward-compat and test ergonomics.
                for t in techniques:
                    if isinstance(t, dict):
                        tid = t.get("technique_id") or t.get("id")
                        if tid:
                            entry["techniques"][tid] += 1
                    elif isinstance(t, str):
                        entry["techniques"][t] += 1
                for tac in tactics:
                    if isinstance(tac, str) and tac:
                        entry["tactics"][tac] += 1
    return actor_counts


def generate_profiles(articles: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate profiles for actors found in articles that don't have one yet.

    Returns the full profiles dict. Modifies state/actor_profiles.json.
    """
    actor_counts = extract_actors_from_articles(articles)
    if not actor_counts:
        return _load_profiles()

    profiles = _load_profiles()
    new_count = 0

    # Sort by article count descending — profile most-mentioned actors first
    sorted_actors = sorted(
        actor_counts.items(),
        key=lambda x: x[1]["count"],
        reverse=True,
    )

    for actor_name, meta in sorted_actors:
        if meta["count"] < _MIN_ARTICLES_FOR_PROFILE:
            continue

        observed = _top_observed_ttps(meta)

        if actor_name in profiles:
            # Update the article count and observed TTPs for existing
            # profiles on every run — the LLM-generated description doesn't
            # change but the evidence base keeps current.
            profiles[actor_name]["current_article_count"] = meta["count"]
            profiles[actor_name].update(observed)
            continue
        if new_count >= _MAX_NEW_PROFILES_PER_RUN:
            break

        profile = _generate_single_profile(actor_name, meta)
        if profile:
            profile["generated_at"] = datetime.now(timezone.utc).isoformat()
            profile["current_article_count"] = meta["count"]
            profile.update(observed)
            profiles[actor_name] = profile
            new_count += 1
            logger.info(f"Generated profile for {actor_name}")

    if new_count > 0 or profiles:
        _save_profiles(profiles)
        logger.info(
            f"Actor profiler: {new_count} new profiles generated, "
            f"{len(profiles)} total profiles."
        )

    # Also save to output dir for API serving
    output_path = OUTPUT_DIR / "actor_profiles.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(profiles, f, ensure_ascii=False)

    return profiles


def _top_observed_ttps(meta: dict) -> dict[str, list[dict] | list[str]]:
    """Return the top-N ATT&CK techniques and tactics for an actor.

    Shape matches what the frontend expects:
    - observed_techniques: list of {"id": "T1566", "count": 3}
    - observed_tactics: list of {"name": "Initial Access", "count": 3}
    """
    techniques = meta.get("techniques")
    tactics = meta.get("tactics")
    top_techniques = []
    top_tactics = []
    if isinstance(techniques, Counter):
        top_techniques = [
            {"id": tid, "count": c}
            for tid, c in techniques.most_common(_TOP_TECHNIQUES_PER_ACTOR)
        ]
    if isinstance(tactics, Counter):
        top_tactics = [
            {"name": name, "count": c}
            for name, c in tactics.most_common(_TOP_TACTICS_PER_ACTOR)
        ]
    return {
        "observed_techniques": top_techniques,
        "observed_tactics": top_tactics,
    }


def _generate_single_profile(actor_name: str, meta: dict) -> dict | None:
    """Generate a single actor profile via LLM."""
    try:
        from modules.llm_client import call_llm, is_available
        from modules.utils import extract_json

        if not is_available():
            return None

        reply = call_llm(
            user_content=f"Threat actor: {actor_name}\nType: {meta['type']}\nAttribution: {meta['origin']}",
            system_prompt=_PROFILE_PROMPT,
            max_tokens=400,
        )
        profile = extract_json(reply)
        if profile and "name" in profile:
            return profile
        return None

    except Exception as e:
        logger.warning(f"Profile generation failed for {actor_name}: {e}")
        return None


def load_profiles() -> dict[str, Any]:
    """Load profiles from the output directory (for API serving)."""
    output_path = OUTPUT_DIR / "actor_profiles.json"
    if not output_path.exists():
        return _load_profiles()
    try:
        with open(output_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return {}
