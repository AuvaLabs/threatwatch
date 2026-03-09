"""Zero-cost keyword-based article classifier.

Replaces the AI engine for classification, using regex patterns
to determine if an article is cybersecurity-related and categorize it.
No API calls — runs entirely locally.
"""

import re
import logging
import hashlib

from modules.ai_cache import get_cached_result, cache_result
from modules.config import MAX_CONTENT_CHARS

# Priority-ordered classification rules (first match wins)
_RULES = [
    {
        "category": "Zero-Day Exploit",
        "re": re.compile(
            r"zero.?day|0day|0-day|actively\s+exploited|in\s+the\s+wild"
            r"|no\s+patch\s+available|unpatched\s+vuln",
            re.IGNORECASE,
        ),
        "confidence": 90,
    },
    {
        "category": "Ransomware",
        "re": re.compile(
            r"ransomware|encrypted\s+files|ransom\s+demand|lockbit|blackcat"
            r"|cl0p|clop|akira\s+ransom|play\s+ransomware|alphv|rhysida"
            r"|medusa\s+ransom|black\s*basta|royal\s+ransom|hive\s+ransom"
            r"|conti\s+ransom|ransomhub|bianlian",
            re.IGNORECASE,
        ),
        "confidence": 92,
    },
    {
        "category": "Nation-State Attack",
        "re": re.compile(
            r"\bapt\d{1,3}\b|nation.?state|state.?sponsored|cyber\s*espionage"
            r"|lazarus|volt\s*typhoon|salt\s*typhoon|sandworm|fancy\s*bear"
            r"|cozy\s*bear|midnight\s*blizzard|charming\s*kitten|muddywater"
            r"|kimsuky|hidden\s*cobra|apt28|apt29|apt41|winnti|turla"
            r"|gamaredon|star\s*blizzard",
            re.IGNORECASE,
        ),
        "confidence": 88,
    },
    {
        "category": "Cyber Espionage",
        "re": re.compile(
            r"cyber\s*espionage|espionage\s+campaign|spying|intelligence\s+gathering"
            r"|surveillance\s+malware|state\s+actor",
            re.IGNORECASE,
        ),
        "confidence": 85,
    },
    {
        "category": "Critical Infrastructure Attack",
        "re": re.compile(
            r"critical\s+infrastructure|power\s+grid|water\s+treatment"
            r"|pipeline\s+attack|energy\s+sector\s+attack|nuclear\s+facility"
            r"|dam\s+attack|electrical\s+grid",
            re.IGNORECASE,
        ),
        "confidence": 88,
    },
    {
        "category": "Supply Chain Attack",
        "re": re.compile(
            r"supply\s*chain\s*(attack|compromise)|third.party\s+breach"
            r"|software\s+update.*compromis|dependency\s+confusion"
            r"|npm\s+package\s+malicious|pypi\s+malicious|github\s+action\s+compromis",
            re.IGNORECASE,
        ),
        "confidence": 87,
    },
    {
        "category": "Data Breach",
        "re": re.compile(
            r"data\s+breach|breached|data\s+leak|leaked|exposed\s+data"
            r"|stolen\s+data|data\s+dump|database\s+exposed|records\s+stolen"
            r"|credentials\s+leaked|personal\s+data\s+exposed"
            r"|million\s+records|account.*compromis",
            re.IGNORECASE,
        ),
        "confidence": 88,
    },
    {
        "category": "Malware",
        "re": re.compile(
            r"\bmalware\b|trojan|backdoor|\brat\b|stealer|infostealer"
            r"|loader|dropper|\bbotnet\b|\bworm\b|emotet|qakbot|trickbot"
            r"|cobalt\s*strike|sliver\s+c2|redline\s+stealer|raccoon"
            r"|bumblebee|icedid|lumma\s*stealer|vidar|amadey",
            re.IGNORECASE,
        ),
        "confidence": 87,
    },
    {
        "category": "Cryptocurrency/Blockchain Theft",
        "re": re.compile(
            r"crypto\s*(theft|hack|heist|stolen)|bitcoin\s+stolen"
            r"|blockchain\s+hack|defi\s+exploit|exchange\s+hack"
            r"|wallet\s+drain|nft\s+scam|rug\s+pull|bridge\s+exploit",
            re.IGNORECASE,
        ),
        "confidence": 85,
    },
    {
        "category": "Cloud Security Incident",
        "re": re.compile(
            r"cloud\s+breach|aws\s+(breach|exposed|misconfigur)"
            r"|azure\s+(breach|incident|vuln)|gcp\s+breach"
            r"|s3\s+bucket\s+exposed|container\s+escape|kubernetes\s+vuln",
            re.IGNORECASE,
        ),
        "confidence": 82,
    },
    {
        "category": "IoT/OT Security",
        "re": re.compile(
            r"\bics\b.*attack|\bscada\b|operational\s+technology"
            r"|\bot\s+security\b|\bot\s+attack\b|industrial\s+control"
            r"|plc\s+attack|smart\s+device\s+hack|iot\s+(attack|vuln|hack)",
            re.IGNORECASE,
        ),
        "confidence": 82,
    },
    {
        "category": "Account Takeover",
        "re": re.compile(
            r"account\s+takeover|credential\s+stuffing|brute\s+force\s+attack"
            r"|password\s+spray|sim\s+swap|mfa\s+bypass",
            re.IGNORECASE,
        ),
        "confidence": 80,
    },
    {
        "category": "Insider Threat",
        "re": re.compile(
            r"insider\s+threat|rogue\s+employee|disgruntled\s+worker"
            r"|employee\s+stole|internal\s+breach",
            re.IGNORECASE,
        ),
        "confidence": 78,
    },
    {
        "category": "DDoS",
        "re": re.compile(
            r"\bddos\b|denial\s+of\s+service|flood\s+attack"
            r"|bandwidth\s+attack|layer\s+7\s+attack|volumetric\s+attack",
            re.IGNORECASE,
        ),
        "confidence": 85,
    },
    {
        "category": "Phishing",
        "re": re.compile(
            r"phishing|spearphish|credential\s+harvest|fake\s+login"
            r"|lookalike\s+domain|email\s+lure|smishing|vishing"
            r"|social\s+engineering\s+attack|business\s+email\s+compromise|\bbec\b",
            re.IGNORECASE,
        ),
        "confidence": 85,
    },
    {
        "category": "Hacktivism",
        "re": re.compile(
            r"hacktivist|hacktivism|\banonymous\b.*hack|defacement"
            r"|politically\s+motivated\s+attack|cyber\s+protest",
            re.IGNORECASE,
        ),
        "confidence": 78,
    },
    {
        "category": "Disinformation/Influence Operation",
        "re": re.compile(
            r"disinformation|influence\s+operation|fake\s+news\s+campaign"
            r"|propaganda\s+cyber|troll\s+farm|information\s+warfare"
            r"|deepfake\s+attack",
            re.IGNORECASE,
        ),
        "confidence": 75,
    },
    {
        "category": "Vulnerability Disclosure",
        "re": re.compile(
            r"cve-\d{4}|cvss\s+\d|vulnerability\s+discover"
            r"|vulnerability\s+disclos|\brce\b|remote\s+code\s+execution"
            r"|privilege\s+escalation|sql\s+injection|xss\s+vuln"
            r"|buffer\s+overflow|authentication\s+bypass",
            re.IGNORECASE,
        ),
        "confidence": 85,
    },
    {
        "category": "Patch/Security Update",
        "re": re.compile(
            r"patch\s+tuesday|security\s+patch|security\s+update"
            r"|hotfix|firmware\s+update|emergency\s+patch|out-of-band\s+patch"
            r"|security\s+advisory|critical\s+update",
            re.IGNORECASE,
        ),
        "confidence": 82,
    },
    {
        "category": "Security Policy/Regulation",
        "re": re.compile(
            r"cybersecurity\s+(regulation|law|policy|legislation|mandate|directive)"
            r"|gdpr\s+fine|sec\s+cyber|nist\s+framework|cyber\s+resilience\s+act"
            r"|executive\s+order.*cyber|cisa\s+directive",
            re.IGNORECASE,
        ),
        "confidence": 75,
    },
    {
        "category": "Threat Intelligence Report",
        "re": re.compile(
            r"threat\s+(report|landscape|brief|intelligence|research|analysis)"
            r"|security\s+report|cyber\s+threat\s+trend|annual\s+report.*cyber"
            r"|state\s+of\s+.*security|forecast.*cyber",
            re.IGNORECASE,
        ),
        "confidence": 72,
    },
]

# Broad cybersecurity relevance check
_CYBER_KEYWORDS = re.compile(
    r"cyber|hack|breach|malware|ransomware|phishing|vulnerability|exploit"
    r"|ddos|botnet|trojan|apt\d|zero.day|cve-|security\s+incident"
    r"|data\s+leak|threat\s+actor|attack|infosec|cisa|ncsc"
    r"|patch\s+tuesday|critical\s+vuln|backdoor|credential"
    r"|authentication|encryption|firewall|endpoint\s+security"
    r"|soc\s+|siem|penetration\s+test|bug\s+bounty|dark\s+web",
    re.IGNORECASE,
)


def classify_article(title, content=None, source_language="en"):
    """Classify an article using keyword patterns. Zero API cost.

    Returns same dict structure as ai_engine.analyze_article for compatibility.
    """
    cache_key = _compute_hash(title + (content or ""))

    cached = get_cached_result(cache_key)
    if cached is not None:
        cached["_cached"] = True
        return cached

    text = title + " " + (content or "")

    # Check if cybersecurity-related
    is_cyber = bool(_CYBER_KEYWORDS.search(text))

    if not is_cyber:
        result = {
            "is_cyber_attack": False,
            "category": "General Cyber Threat",
            "confidence": 0,
            "translated_title": title,
            "summary": "",
        }
        cache_result(cache_key, result)
        return result

    # Classify by first matching rule
    category = "General Cyber Threat"
    confidence = 60

    for rule in _RULES:
        if rule["re"].search(text):
            category = rule["category"]
            confidence = rule["confidence"]
            break

    # Use RSS summary as the article summary (free, no AI needed)
    summary = ""
    if content:
        # Take first 3 sentences from content as summary
        sentences = re.split(r'(?<=[.!?])\s+', content.strip())
        summary = " ".join(sentences[:3])
        if len(summary) > 500:
            summary = summary[:497] + "..."

    result = {
        "is_cyber_attack": True,
        "category": category,
        "confidence": confidence,
        "translated_title": title,
        "summary": summary,
    }

    cache_result(cache_key, result)
    return result


def _compute_hash(text):
    return hashlib.sha256(text[:MAX_CONTENT_CHARS].encode()).hexdigest()
