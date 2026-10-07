"""AI per-article summariser.

Runs over articles that lack a `summary` field and generates a structured
what/who/impact/summary triple via the LLM. Extracted from
`briefing_generator.py` to keep that file under the 800-line cap.
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import Any

from modules.ai_cache import get_cached_result, cache_result
from modules.llm_client import call_llm, is_available
from modules.utils import extract_json as _parse_json

logger = logging.getLogger(__name__)


# --- AI Article Summaries: batch-summarize articles missing summaries ---

_SUMMARY_BATCH_SIZE = 10  # articles per LLM call
# Was 30/run which only covered ~2% of the ~1600 articles/run backlog, leaving
# >50% of the corpus without summaries. Groq's free tier accommodates higher
# throughput; batches of 10 keep token usage per call predictable.
_MAX_SUMMARIES_PER_RUN = int(os.environ.get("MAX_SUMMARIES_PER_RUN", "150"))
try:
    _SUMMARY_BATCH_DELAY_SECONDS = max(
        0.0, float(os.environ.get("SUMMARY_BATCH_DELAY_SECONDS", "5"))
    )
except ValueError:
    logger.warning("Invalid SUMMARY_BATCH_DELAY_SECONDS; using 5 seconds")
    _SUMMARY_BATCH_DELAY_SECONDS = 5.0

_SUMMARY_PROMPT = """You are a cyber threat intelligence analyst. For each article, extract key intelligence details in a structured format.

Rules:
- GROUNDING (CRITICAL): Use ONLY identifiers (actor names, CVE IDs, organizations, products, numbers) that appear in the article's title or content snippet below. Tokens shown in angle-bracket form (<ACTOR>, <VICTIM>, <COUNT>) in these instructions are schema placeholders, not data — never echo them or fabricate similar-looking values. If a field is unknown from the content, use null — do not invent.
- Keep each field concise (under 80 chars per field)
- "what": the incident or event in generic terms (e.g. "ransomware attack", "data breach", "vulnerability disclosed")
- "who": affected organization, threat actor, or both — extracted verbatim from the content. Style template: "<ACTOR> targeted <VICTIM>". Use null if neither is named.
- "impact": the consequence or scale, extracted verbatim. Style template: "<COUNT> records exposed" or "systems offline for <N> days". Use null if no impact figure is in the content.
- "summary": 1 sentence combining the above into a readable intelligence summary, citing only entities present in the content
- For CVE/vulnerability articles, include product and severity in "what"
- Return ONLY valid JSON array — no markdown, no explanation

Input format: numbered articles with title and content snippet.
Output format:
[
  {"index": 1, "what": "...", "who": "...", "impact": "...", "summary": "..."},
  {"index": 2, "what": "...", "who": "...", "impact": "...", "summary": "..."}
]"""


def summarize_articles(articles: list[dict[str, Any]]) -> int:
    """Generate AI summaries for articles that lack them.

    Modifies articles in-place. Returns count of summaries generated.
    Uses batched calls to minimize token usage.
    """
    if not is_available():
        return 0

    # Find articles missing summaries
    needs_summary = [
        (i, a) for i, a in enumerate(articles)
        if not a.get("summary") and a.get("is_cyber_attack")
        and a.get("title")
    ]

    if not needs_summary:
        return 0

    # Cap to prevent budget overrun
    needs_summary = needs_summary[:_MAX_SUMMARIES_PER_RUN]
    total_generated = 0
    network_batches = 0

    # Process in batches
    for batch_start in range(0, len(needs_summary), _SUMMARY_BATCH_SIZE):
        batch = needs_summary[batch_start:batch_start + _SUMMARY_BATCH_SIZE]

        # Build batch prompt
        lines = []
        for batch_idx, (_, article) in enumerate(batch, 1):
            title = article.get("translated_title") or article.get("title", "")
            content = (article.get("full_content") or "")[:500]
            lines.append(f"[{batch_idx}] {title}")
            if content:
                lines.append(f"    {content}")

        user_content = "\n".join(lines)
        cache_key = "summaries_" + hashlib.sha256(user_content.encode()).hexdigest()

        cached = get_cached_result(cache_key)
        if cached is not None:
            summaries = cached
        else:
            try:
                if network_batches > 0 and _SUMMARY_BATCH_DELAY_SECONDS > 0:
                    time.sleep(_SUMMARY_BATCH_DELAY_SECONDS)
                network_batches += 1
                reply = call_llm(
                    user_content,
                    system_prompt=_SUMMARY_PROMPT,
                    max_tokens=800,
                    response_format={"type": "json_object"},
                    caller="summaries",
                )
                summaries = _parse_json(reply)
                if summaries is None:
                    continue
                # Handle both list and dict-with-list responses
                if isinstance(summaries, dict):
                    summaries = summaries.get("summaries", [])
                cache_result(cache_key, summaries)
            except Exception as e:
                logger.warning(f"Summary batch failed: {e}")
                continue

        # Apply summaries back to articles
        if isinstance(summaries, list):
            for item in summaries:
                batch_idx = item.get("index", 0) - 1
                summary_text = item.get("summary", "")
                if 0 <= batch_idx < len(batch) and summary_text:
                    orig_idx = batch[batch_idx][0]
                    articles[orig_idx]["summary"] = summary_text
                    articles[orig_idx]["summary_method"] = "ai"
                    articles[orig_idx]["summary_generated"] = True
                    # Store structured intel fields if available
                    if item.get("what"):
                        articles[orig_idx]["intel_what"] = item["what"]
                    if item.get("who"):
                        articles[orig_idx]["intel_who"] = item["who"]
                    if item.get("impact"):
                        articles[orig_idx]["intel_impact"] = item["impact"]
                    total_generated += 1

    if total_generated > 0:
        logger.info(f"AI summaries generated: {total_generated} articles enriched.")
    return total_generated
