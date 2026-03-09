import os
import sys
import logging
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"

SITE_DOMAIN = os.getenv("SITE_DOMAIN", "threatdigest.cyberonehq.com")
SITE_URL = f"https://{SITE_DOMAIN}"

BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
STATE_DIR = DATA_DIR / "state"
OUTPUT_DIR = DATA_DIR / "output"
LOG_DIR = DATA_DIR / "logs"

CATEGORIES = [
    "Ransomware",
    "Phishing",
    "DDoS",
    "Data Breach",
    "Malware",
    "Insider Threat",
    "Zero-Day Exploit",
    "Nation-State Attack",
    "Supply Chain Attack",
    "Vulnerability Disclosure",
    "Cyber Espionage",
    "Hacktivism",
    "Account Takeover",
    "Critical Infrastructure Attack",
    "Cloud Security Incident",
    "IoT/OT Security",
    "Cryptocurrency/Blockchain Theft",
    "Disinformation/Influence Operation",
    "Security Policy/Regulation",
    "Patch/Security Update",
    "Threat Intelligence Report",
    "General Cyber Threat",
]

SYSTEM_PROMPT = (
    "You are a cybersecurity analyst. You will receive a news headline and optionally "
    "the article content. Your job is to:\n"
    "1. Determine if it is related to cybersecurity. This includes: cyberattacks, "
    "security incidents, data breaches, vulnerability disclosures, security patches, "
    "threat intelligence reports, security policy/regulation, critical infrastructure "
    "threats, hacktivism, and any cybersecurity-relevant news. Set is_cyber_attack=true "
    "for ALL cybersecurity-related content, not just active attacks.\n"
    "2. Classify it into one of these categories:\n"
    f"   {CATEGORIES}\n"
    "3. If the title is not in English, translate it to English.\n"
    "4. If article content is provided, write a 3-4 sentence summary focusing on "
    "the security incident, impact, and threat context.\n\n"
    "Respond ONLY with valid JSON (no markdown, no explanation):\n"
    '{"is_cyber_attack": true/false, "category": "<category>", "confidence": 0-100, '
    '"translated_title": "<english title>", "summary": "<summary or empty string>"}'
)

MAX_CONTENT_CHARS = 4000
MAX_SCRAPER_THREADS = 8
FUZZY_DEDUP_THRESHOLD = 0.6  # word-shingle overlap (equivalent to ~0.85 SequenceMatcher)
MAX_SEEN_TITLES = 10000
MAX_SEEN_HASHES = 50000

FEED_CUTOFF_DAYS = int(os.getenv("FEED_CUTOFF_DAYS", "7"))
DAILY_BUDGET_USD = float(os.getenv("DAILY_BUDGET_USD", "2.00"))


def validate_config():
    if not ANTHROPIC_API_KEY:
        logging.info(
            "ANTHROPIC_API_KEY not set — using keyword classifier (zero cost)."
        )
