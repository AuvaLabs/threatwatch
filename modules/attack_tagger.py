"""MITRE ATT&CK technique tagger.

Maps articles to ATT&CK techniques using keyword-based pattern matching.
Zero cost by default — runs entirely locally with compiled regex patterns.

Optional LLM fallback (``LLM_ATTACK_FALLBACK=true``): articles whose regex
pass yields fewer than ``LLM_ATTACK_FALLBACK_MIN`` techniques (default 2)
AND that are flagged as cyber incidents are escalated to the LLM to catch
novel TTP phrasings that hand-tuned regex misses. Cached by article hash.

Each article gets a list of matched ATT&CK technique IDs with names,
grouped by tactic. This transforms news articles into structured
threat intelligence with TTP context.
"""

import hashlib
import json
import logging
import os
import re
from typing import Any

from modules.ai_cache import cache_result, get_cached_result

logger = logging.getLogger(__name__)

_LLM_FALLBACK_ENABLED = os.environ.get("LLM_ATTACK_FALLBACK", "").lower() in {"1", "true", "yes"}
_LLM_FALLBACK_MIN_TECHNIQUES = int(os.environ.get("LLM_ATTACK_FALLBACK_MIN", "2"))
_LLM_FALLBACK_MAX_CALLS = int(os.environ.get("LLM_ATTACK_FALLBACK_MAX_CALLS", "100"))
_LLM_CALLER = "attack_llm"

_LLM_SYSTEM_PROMPT = (
    "You tag cybersecurity news articles with MITRE ATT&CK techniques. "
    "Respond with ONLY a JSON object of the form "
    '{"techniques": [{"technique_id": "T1566", "technique_name": "Phishing", '
    '"tactic": "Initial Access"}]}. '
    "Use canonical MITRE ATT&CK technique IDs (Txxxx or Txxxx.yyy). "
    "Include up to 5 techniques; if no technique is clearly supported by the "
    'text, return {"techniques": []}. Do not invent IDs.'
)

# ATT&CK technique patterns: (technique_id, technique_name, tactic, regex_pattern)
# Covers the most commonly referenced techniques in threat reporting.
_TECHNIQUE_PATTERNS = [
    # Initial Access
    ("T1566", "Phishing", "Initial Access",
     re.compile(r"phishing|spearphish|email\s+lure|credential\s+harvest|fake\s+login|smishing|vishing", re.I)),
    ("T1566.001", "Spearphishing Attachment", "Initial Access",
     re.compile(r"spearphish.*attach|malicious\s+(attachment|document|pdf|docx|xlsx)", re.I)),
    ("T1566.002", "Spearphishing Link", "Initial Access",
     re.compile(r"spearphish.*link|phishing\s+link|malicious\s+url|lookalike\s+domain", re.I)),
    ("T1190", "Exploit Public-Facing Application", "Initial Access",
     re.compile(r"exploit.*public.facing|web\s+shell|rce\s+in\s+.{0,30}(server|appliance|gateway)", re.I)),
    ("T1133", "External Remote Services", "Initial Access",
     re.compile(r"vpn\s+(exploit|compromise|vulnerability)|rdp\s+(brute|exposed|attack)", re.I)),
    ("T1195", "Supply Chain Compromise", "Initial Access",
     re.compile(r"supply[\s-]chain\s+(attack|compromise)|dependency\s+confusion|trojanized\s+update", re.I)),
    ("T1078", "Valid Accounts", "Initial Access",
     re.compile(r"stolen\s+credentials|credential\s+stuffing|compromised\s+accounts?|valid\s+accounts", re.I)),

    # Execution
    ("T1059", "Command and Scripting Interpreter", "Execution",
     re.compile(r"powershell\s+(attack|malicious|payload)|malicious\s+(script|macro|vba|python)", re.I)),
    ("T1204", "User Execution", "Execution",
     re.compile(r"social\s+engineering\s+attack|trick.*(open|click|execute)|lure.*execute", re.I)),

    # Persistence
    ("T1547", "Boot or Logon Autostart Execution", "Persistence",
     re.compile(r"registry\s+persistence|autostart|startup\s+folder\s+malware|boot\s+persistence", re.I)),
    ("T1053", "Scheduled Task/Job", "Persistence",
     re.compile(r"scheduled\s+task\s+persistence|cron\s+job\s+malware|at\s+job\s+persistence", re.I)),

    # Privilege Escalation
    ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation",
     re.compile(r"privilege\s+escalation|local\s+privilege|kernel\s+exploit|root\s+exploit|elevation\s+of\s+privilege", re.I)),

    # Defense Evasion
    ("T1027", "Obfuscated Files or Information", "Defense Evasion",
     re.compile(r"obfuscated|packed\s+malware|encrypted\s+payload|code\s+obfuscation|packing\s+technique", re.I)),
    ("T1562", "Impair Defenses", "Defense Evasion",
     re.compile(r"disable.*antivirus|bypass.*edr|edr\s+evasion|tamper.*security|impair\s+defenses", re.I)),
    ("T1070", "Indicator Removal", "Defense Evasion",
     re.compile(r"clear\s+event\s+logs|delete.*evidence|anti.forensic|indicator\s+removal", re.I)),

    # Credential Access
    ("T1003", "OS Credential Dumping", "Credential Access",
     re.compile(r"credential\s+dump|mimikatz|lsass\s+dump|ntds\.dit|password\s+hash\s+dump", re.I)),
    ("T1110", "Brute Force", "Credential Access",
     re.compile(r"brute\s+force\s+attack|password\s+spray|credential\s+stuffing", re.I)),
    ("T1539", "Steal Web Session Cookie", "Credential Access",
     re.compile(r"session\s+(hijack|steal|token\s+theft)|cookie\s+theft|steal.*session", re.I)),

    # Lateral Movement
    ("T1021", "Remote Services", "Lateral Movement",
     re.compile(r"lateral\s+movement|rdp\s+lateral|psexec|smb\s+lateral|wmi\s+lateral", re.I)),

    # Collection
    ("T1005", "Data from Local System", "Collection",
     re.compile(r"data\s+exfiltration|steal.*data|harvest.*(file|data|document)", re.I)),
    ("T1119", "Automated Collection", "Collection",
     re.compile(r"automated\s+collection|mass\s+data\s+collection|bulk\s+harvest", re.I)),

    # Command and Control
    ("T1071", "Application Layer Protocol", "Command and Control",
     re.compile(r"\bc2\b.*server|command\s+and\s+control|cobalt\s*strike|beacon|c2\s+(channel|traffic|infrastructure)", re.I)),
    ("T1573", "Encrypted Channel", "Command and Control",
     re.compile(r"encrypted\s+c2|https\s+c2|dns\s+tunnel|covert\s+channel", re.I)),
    ("T1105", "Ingress Tool Transfer", "Command and Control",
     re.compile(r"download.*payload|stage[dr]?\s+payload|tool\s+transfer|drop.*second.stage", re.I)),

    # Exfiltration
    ("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
     re.compile(r"exfiltrat.*c2|data\s+exfiltration|stolen\s+data.*upload|exfiltrate.*server", re.I)),
    ("T1567", "Exfiltration Over Web Service", "Exfiltration",
     re.compile(r"exfiltrat.*(cloud|telegram|discord|pastebin|google\s+drive)", re.I)),

    # Impact
    ("T1486", "Data Encrypted for Impact", "Impact",
     re.compile(r"ransomware|encrypted\s+files|ransom\s+demand|file\s+encryption\s+attack", re.I)),
    ("T1489", "Service Stop", "Impact",
     re.compile(r"wiper\s+malware|destructive\s+malware|kill\s+switch|service\s+disruption\s+attack", re.I)),
    ("T1498", "Network Denial of Service", "Impact",
     re.compile(r"\bddos\b|denial\s+of\s+service|volumetric\s+attack|flood\s+attack", re.I)),
    ("T1531", "Account Access Removal", "Impact",
     re.compile(r"account\s+lockout\s+attack|mass\s+password\s+reset|access\s+removal", re.I)),

    # Resource Development
    ("T1588", "Obtain Capabilities", "Resource Development",
     re.compile(r"exploit\s+kit|malware.as.a.service|raas|stealer.as.a.service", re.I)),
    ("T1583", "Acquire Infrastructure", "Resource Development",
     re.compile(r"bulletproof\s+hosting|malicious\s+infrastructure|c2\s+infrastructure\s+setup", re.I)),
]


def tag_article_with_attack(article: dict) -> dict:
    """Tag a single article with matching ATT&CK techniques.

    Scans title, summary, and full_content for technique patterns.
    Returns article with added 'attack_techniques' and 'attack_tactics' fields.
    """
    text = " ".join(filter(None, [
        article.get("title", ""),
        article.get("summary", ""),
        article.get("translated_title", ""),
        (article.get("full_content", "") or "")[:2000],
    ]))

    if not text:
        return article

    matched = []
    seen_ids = set()

    for tech_id, tech_name, tactic, pattern in _TECHNIQUE_PATTERNS:
        if tech_id not in seen_ids and pattern.search(text):
            matched.append({
                "technique_id": tech_id,
                "technique_name": tech_name,
                "tactic": tactic,
            })
            seen_ids.add(tech_id)
            # Also add parent technique if this is a sub-technique
            parent_id = tech_id.split(".")[0]
            if parent_id != tech_id and parent_id not in seen_ids:
                parent = next(
                    (t for t in _TECHNIQUE_PATTERNS if t[0] == parent_id),
                    None,
                )
                if parent:
                    matched.append({
                        "technique_id": parent[0],
                        "technique_name": parent[1],
                        "tactic": parent[2],
                    })
                    seen_ids.add(parent[0])

    if not matched:
        return article

    # Group by tactic for structured output
    tactics = sorted(set(m["tactic"] for m in matched))

    return {
        **article,
        "attack_techniques": matched,
        "attack_tactics": tactics,
    }


_VALID_TECH_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _article_cache_key(article: dict) -> str:
    raw = article.get("hash") or article.get("link") or article.get("title") or ""
    return "attack_llm:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _build_llm_prompt(article: dict) -> str:
    title = article.get("title", "") or ""
    summary = article.get("summary", "") or ""
    body = (article.get("full_content", "") or "")[:2000]
    return f"Title: {title}\n\nSummary: {summary}\n\nBody: {body}"


def _parse_llm_techniques(raw: str) -> list[dict]:
    """Parse LLM JSON response into a list of technique dicts.

    Defensively handles malformed output (missing fields, unknown IDs).
    Returns at most 5 entries.
    """
    if not raw:
        return []
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return []
    items = obj.get("techniques") if isinstance(obj, dict) else None
    if not isinstance(items, list):
        return []
    cleaned: list[dict] = []
    seen: set[str] = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        tid = str(item.get("technique_id") or "").strip().upper()
        if not _VALID_TECH_ID.match(tid) or tid in seen:
            continue
        tname = str(item.get("technique_name") or "").strip() or tid
        tactic = str(item.get("tactic") or "").strip() or "Unknown"
        cleaned.append({
            "technique_id": tid,
            "technique_name": tname,
            "tactic": tactic,
            "source": "llm",
        })
        seen.add(tid)
        if len(cleaned) >= 5:
            break
    return cleaned


def _llm_tag_article(article: dict) -> list[dict]:
    """Call the LLM to propose ATT&CK techniques. Cache-first.

    Returns a list of technique dicts; empty list on failure (callers
    must treat missing LLM output as non-fatal — the regex matches
    always stand on their own).
    """
    cache_key = _article_cache_key(article)
    cached = get_cached_result(cache_key)
    if isinstance(cached, list):
        return cached

    try:
        from modules.llm_client import call_llm
        raw = call_llm(
            user_content=_build_llm_prompt(article),
            system_prompt=_LLM_SYSTEM_PROMPT,
            max_tokens=600,
            response_format={"type": "json_object"},
            caller=_LLM_CALLER,
        )
    except Exception as exc:
        logger.debug("attack_tagger LLM fallback failed: %s", exc)
        return []

    techniques = _parse_llm_techniques(raw)
    cache_result(cache_key, techniques)
    return techniques


def _should_escalate_to_llm(article: dict) -> bool:
    """Decide whether an article deserves the LLM fallback pass."""
    if not _LLM_FALLBACK_ENABLED:
        return False
    if not article.get("is_cyber_attack"):
        return False
    existing = article.get("attack_techniques") or []
    return len(existing) < _LLM_FALLBACK_MIN_TECHNIQUES


def _merge_techniques(base: list[dict], extra: list[dict]) -> list[dict]:
    seen = {t.get("technique_id") for t in base if t.get("technique_id")}
    merged = list(base)
    for t in extra:
        tid = t.get("technique_id")
        if tid and tid not in seen:
            merged.append(t)
            seen.add(tid)
    return merged


def tag_articles_with_attack(articles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Batch version — tag all articles with ATT&CK techniques.

    Runs the regex pass on every article, then (if enabled) escalates
    under-tagged incident articles to the LLM. Budget-capped via
    ``LLM_ATTACK_FALLBACK_MAX_CALLS`` to protect daily token budget.
    """
    tagged = [tag_article_with_attack(a) for a in articles]
    tagged_count = sum(1 for a in tagged if a.get("attack_techniques"))

    if not _LLM_FALLBACK_ENABLED:
        logger.info(
            f"ATT&CK: tagged {tagged_count}/{len(articles)} articles with "
            f"MITRE ATT&CK techniques"
        )
        return tagged

    llm_calls = 0
    llm_hits = 0
    for i, article in enumerate(tagged):
        if not _should_escalate_to_llm(article):
            continue
        cached = get_cached_result(_article_cache_key(article))
        if isinstance(cached, list):
            if cached:
                tagged[i] = {
                    **article,
                    "attack_techniques": _merge_techniques(article.get("attack_techniques") or [], cached),
                    "attack_tactics": sorted({
                        *(article.get("attack_tactics") or []),
                        *[t.get("tactic") for t in cached if t.get("tactic")],
                    }),
                }
                llm_hits += 1
            continue
        if llm_calls >= _LLM_FALLBACK_MAX_CALLS:
            continue
        proposed = _llm_tag_article(article)
        llm_calls += 1
        if proposed:
            tagged[i] = {
                **article,
                "attack_techniques": _merge_techniques(article.get("attack_techniques") or [], proposed),
                "attack_tactics": sorted({
                    *(article.get("attack_tactics") or []),
                    *[t.get("tactic") for t in proposed if t.get("tactic")],
                }),
            }
            llm_hits += 1

    final_count = sum(1 for a in tagged if a.get("attack_techniques"))
    logger.info(
        f"ATT&CK: tagged {final_count}/{len(articles)} articles "
        f"(regex {tagged_count}, +{final_count - tagged_count} via LLM; "
        f"{llm_calls} LLM calls, {llm_hits} with usable output)"
    )
    return tagged
