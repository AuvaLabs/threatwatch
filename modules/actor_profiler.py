"""Threat actor profiler: generates and caches AI profiles for known actors.

When a threat actor appears in articles, generates a brief profile covering
origin, targets, TTPs, and recent activity. Profiles are cached permanently
in state/actor_profiles.json — near-zero ongoing token cost.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

from modules.config import STATE_DIR, OUTPUT_DIR
from modules.incident_correlator import _ACTOR_PATTERNS

logger = logging.getLogger(__name__)

PROFILES_PATH = STATE_DIR / "actor_profiles.json"

# Only profile actors that appear in 2+ articles (avoid noise)
_MIN_ARTICLES_FOR_PROFILE = 2
# Max new profiles per pipeline run (controls token budget)
_MAX_NEW_PROFILES_PER_RUN = 5

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
    """Scan articles for known threat actors. Returns {actor_name: {type, origin, count}}."""
    actor_counts = {}
    for article in articles:
        text = (article.get("title", "") + " " + (article.get("summary") or ""))
        for pat, name, actor_type, origin in _ACTOR_PATTERNS:
            if pat.search(text):
                if name not in actor_counts:
                    actor_counts[name] = {
                        "type": actor_type,
                        "origin": origin,
                        "count": 0,
                    }
                actor_counts[name]["count"] += 1
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
        if actor_name in profiles:
            # Update the article count for existing profiles
            profiles[actor_name]["current_article_count"] = meta["count"]
            continue
        if new_count >= _MAX_NEW_PROFILES_PER_RUN:
            break

        profile = _generate_single_profile(actor_name, meta)
        if profile:
            profile["generated_at"] = datetime.now(timezone.utc).isoformat()
            profile["current_article_count"] = meta["count"]
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
