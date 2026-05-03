import os
import sys
import logging
from pathlib import Path
from dotenv import load_dotenv

logger = logging.getLogger(__name__)

load_dotenv()

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"

# Provider-agnostic LLM config for AI briefing
# Supports any OpenAI-compatible API (OpenAI, Groq, Together, Ollama, Mistral, DeepSeek, etc.)
# Falls back to Anthropic SDK if LLM_PROVIDER=anthropic
LLM_API_KEY = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or ANTHROPIC_API_KEY
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "llama-3.3-70b-versatile")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "auto")  # auto, openai, anthropic, ollama

# The global daily briefing prompt (~7-8K tokens with 80 articles + enrichment)
# exceeds Groq free-tier TPM for 70B (~6K/min), causing every call to 429.
# Default the briefing to the lighter 8B model which has higher TPM headroom.
BRIEFING_MODEL = os.getenv("BRIEFING_MODEL", "llama-3.1-8b-instant")

# Multiple API keys for round-robin rotation (comma-separated in env)
# Doubles the free-tier budget: 2 keys x 500K tokens/day = 1M tokens/day
LLM_API_KEYS = [
    k.strip() for k in os.getenv("LLM_API_KEYS", "").split(",") if k.strip()
] or ([LLM_API_KEY] if LLM_API_KEY else [])

# Featherless.ai — paid OpenAI-compatible provider used ONLY for the daily
# global briefing. Groq free-tier 6K TPM rejects the ~7-8K briefing prompt;
# Featherless gives 32K context. The token is shared across multiple projects
# (effective platform-wide concurrency ≈ 1 for cost-4 models like
# deepseek-v3.2/kimi-k2/glm46), so we use it sparingly and fall back to
# Groq+8B on any failure rather than retrying.
FEATHERLESS_API_KEY = os.getenv("FEATHERLESS_API_KEY", "").strip()
FEATHERLESS_BASE_URL = os.getenv(
    "FEATHERLESS_BASE_URL", "https://api.featherless.ai/v1"
).rstrip("/")
FEATHERLESS_MODEL = os.getenv("FEATHERLESS_MODEL", "deepseek-v3.2")

# Claude Bridge — host-local OpenAI-compatible shim that routes requests
# through the `claude` CLI using the user's Claude Max subscription. Used
# as the 2nd-tier fallback for the daily briefing (Featherless → Bridge
# → Groq+8B). No per-token cost, but rate-limited by the shared Max
# session and ignores `max_tokens` / `response_format` (CLI doesn't
# expose them). Operated by RedBlue's claude-bridge service on this host;
# leave URL blank to disable.
CLAUDE_BRIDGE_URL = os.getenv("CLAUDE_BRIDGE_URL", "").strip().rstrip("/")
CLAUDE_BRIDGE_MODEL = os.getenv("CLAUDE_BRIDGE_MODEL", "sonnet")
CLAUDE_BRIDGE_TIMEOUT = float(os.getenv("CLAUDE_BRIDGE_TIMEOUT", "300"))

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
DAILY_BUDGET_USD = float(os.getenv("DAILY_BUDGET_USD", "2.00"))


def validate_config():
    if not ANTHROPIC_API_KEY:
        logger.info(
            "ANTHROPIC_API_KEY not set — keyword classifier only (zero cost)."
        )
    else:
        logger.info(
            "ANTHROPIC_API_KEY set — hybrid mode (keyword + AI escalation)."
        )
    if LLM_API_KEY:
        logger.info(
            f"LLM configured — AI briefing enabled ({LLM_PROVIDER}/{LLM_MODEL} via {LLM_BASE_URL.split('@')[-1]})."
        )
    else:
        logger.info("No LLM API key — AI briefing disabled (zero cost).")
    if FEATHERLESS_API_KEY:
        logger.info(
            f"Featherless configured — global briefing will prefer "
            f"{FEATHERLESS_MODEL} (32K ctx); Groq+{BRIEFING_MODEL} fallback."
        )
    if CLAUDE_BRIDGE_URL:
        logger.info(
            f"Claude Bridge configured at {CLAUDE_BRIDGE_URL} "
            f"({CLAUDE_BRIDGE_MODEL}); 2nd-tier briefing fallback."
        )
