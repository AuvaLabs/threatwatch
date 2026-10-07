import os
import sys
import logging
from pathlib import Path
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

load_dotenv()

# Provider-agnostic LLM config for AI features.
# Supports any OpenAI-compatible API. Kimi is the default/recommended provider.
_KIMI_API_KEY = os.getenv("KIMI_API_KEY")
LLM_API_KEY = os.getenv("LLM_API_KEY") or _KIMI_API_KEY or os.getenv("OPENAI_API_KEY")

# Default to the Kimi coding endpoint when a Kimi key is present; otherwise
# keep the legacy Groq default for operators who explicitly set OPENAI_API_KEY.
_default_base_url = (
    "https://api.kimi.com/coding/v1"
    if _KIMI_API_KEY else "https://api.groq.com/openai/v1"
)
LLM_BASE_URL = os.getenv("LLM_BASE_URL", _default_base_url)

# Kimi coding endpoint only accepts temperature=1, so the client omits the
# field for that base URL. Default the model to Kimi's coding model when the
# configured endpoint is Kimi; otherwise keep the legacy Groq default.
_default_model = (
    "kimi-for-coding"
    if "api.kimi.com/coding/v1" in LLM_BASE_URL else "llama-3.3-70b-versatile"
)
LLM_MODEL = os.getenv("LLM_MODEL", _default_model)

# We only use OpenAI-compatible endpoints now.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai")

# Multiple API keys for round-robin rotation (comma-separated in env).
LLM_API_KEYS = [
    k.strip() for k in os.getenv("LLM_API_KEYS", "").split(",") if k.strip()
] or ([LLM_API_KEY] if LLM_API_KEY else [])

# Briefing and top-stories models default to the global LLM model so a single
# provider switch (e.g. to Kimi) propagates everywhere.
BRIEFING_MODEL = os.getenv("BRIEFING_MODEL", LLM_MODEL)
TOP_STORIES_MODEL = os.getenv("TOP_STORIES_MODEL", LLM_MODEL)

# Optional independent OpenAI-compatible fallbacks. Historical variable names
# are retained so existing VPS configuration keeps working while routing is
# now shared by every AI capability, not just the global briefing.
FEATHERLESS_API_KEY = os.getenv("FEATHERLESS_API_KEY", "")
FEATHERLESS_BASE_URL = os.getenv("FEATHERLESS_BASE_URL", "")
FEATHERLESS_MODEL = os.getenv("FEATHERLESS_MODEL", "")
FEATHERLESS_TIMEOUT = float(os.getenv("FEATHERLESS_TIMEOUT", "60"))
BRIEFING_FALLBACK_API_KEY = os.getenv("BRIEFING_FALLBACK_API_KEY", "")
BRIEFING_FALLBACK_BASE_URL = os.getenv("BRIEFING_FALLBACK_BASE_URL", "")
BRIEFING_FALLBACK_MODEL = os.getenv("BRIEFING_FALLBACK_MODEL", "")
BRIEFING_FALLBACK_TIMEOUT = float(os.getenv("BRIEFING_FALLBACK_TIMEOUT", "60"))

SITE_DOMAIN = os.getenv("SITE_DOMAIN", "threatwatch.auvalabs.com")
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
    "Threat Research & Analysis",
    "Detection & Response",
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
MAX_SCRAPER_THREADS = int(os.environ.get("MAX_SCRAPER_THREADS", "16"))
# Parallel feed fetchers. 164 feeds / 16 workers ≈ 10 feeds per worker;
# each worker holds one connection pool so raising this stays polite to
# individual domains. Old default (8) was the dominant bottleneck when
# a few slow feeds serialised the tail of the run.
MAX_FEED_FETCH_THREADS = int(os.environ.get("MAX_FEED_FETCH_THREADS", "16"))
FUZZY_DEDUP_THRESHOLD = 0.55  # word-shingle overlap (lowered from 0.6 to catch more near-dupes)
MAX_SEEN_TITLES = 10000
MAX_SEEN_HASHES = 50000

FEED_CUTOFF_DAYS = int(os.getenv("FEED_CUTOFF_DAYS", "7"))
MAX_FUTURE_MINUTES = int(os.getenv("MAX_FUTURE_MINUTES", "15"))
DAILY_BUDGET_USD = float(os.getenv("DAILY_BUDGET_USD", "2.00"))


def validate_config():
    if LLM_API_KEY:
        logger.info(
            f"LLM configured: AI features enabled ({LLM_PROVIDER}/{LLM_MODEL} via "
            f"{LLM_BASE_URL.split('@')[-1]})."
        )
    else:
        logger.info("No LLM API key: AI features disabled (zero cost).")
