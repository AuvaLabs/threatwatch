#!/usr/bin/env python3
"""Free-LLM provider test harness for ThreatWatch.

Probes any OpenAI-compatible provider with the EXACT call shape production
uses (POST {base}/chat/completions, Bearer auth, response_format json_object,
with a graceful retry-without-response_format on a 400 that mentions it — the
same fallback modules/llm_client.py performs). Scores each candidate on the two
real ThreatWatch workloads:

  1. classify  — small, high-volume article escalation (short JSON out)
  2. briefing  — large-context JSON generation (the daily intel brief)

Providers are declared in PROVIDERS below. Each reads its key from an env var
so no secret is ever committed. Run:

    LLM7_KEY= GROQ_API_KEY=... CEREBRAS_API_KEY=... \
        python3 scripts/test_free_llms.py

Only providers whose key env is set (or that need no key) are tested. Output is
a ranked table: OK/FAIL, JSON-valid, response_format support, latency, tokens.
Nothing here writes to production config — it only reports what works so the
operator can wire the winners into .env.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

# A provider is (name, base_url, model, api_key_env, needs_key).
# api_key_env="" + needs_key=False => open provider (no auth).
PROVIDERS = [
    ("llm7-deepseek",  "https://api.llm7.io/v1",              "deepseek-v4-flash",              "LLM7_KEY",       False),
    ("llm7-mistral",   "https://api.llm7.io/v1",              "codestral-latest",              "LLM7_KEY",       False),
    ("groq-70b",       "https://api.groq.com/openai/v1",      "llama-3.3-70b-versatile",       "GROQ_API_KEY",   True),
    ("groq-gptoss",    "https://api.groq.com/openai/v1",      "openai/gpt-oss-120b",           "GROQ_API_KEY",   True),
    ("cerebras-gptoss","https://api.cerebras.ai/v1",          "gpt-oss-120b",                  "CEREBRAS_API_KEY", True),
    ("sambanova-ds",   "https://api.sambanova.ai/v1",         "DeepSeek-V3.1",                 "SAMBANOVA_API_KEY", True),
    ("openrouter-70b", "https://openrouter.ai/api/v1",        "meta-llama/llama-3.3-70b-instruct:free", "OPENROUTER_API_KEY", True),
    ("nvidia-nemotron","https://integrate.api.nvidia.com/v1", "nvidia/llama-3.1-nemotron-70b-instruct", "NVIDIA_API_KEY", True),
    ("gemini-flash",   "https://generativelanguage.googleapis.com/v1beta/openai", "gemini-2.5-flash", "GEMINI_API_KEY", True),
    ("mistral-small",  "https://api.mistral.ai/v1",           "mistral-small-latest",          "MISTRAL_API_KEY", True),
]

CLASSIFY_SYS = "You are a cyber-threat classifier. Reply ONLY with a JSON object."
CLASSIFY_USER = (
    'Classify this headline. Return JSON with keys "is_cyber" (bool), '
    '"severity" (one of low/medium/high/critical), "topic" (short string).\n\n'
    'Headline: "Critical RCE in Fortinet FortiOS SSL-VPN actively exploited, CVE-2026-12345"'
)
# ~large briefing-shaped prompt to exercise context/TPM handling.
BRIEFING_SYS = (
    "You are a senior threat-intelligence analyst. Produce a concise daily "
    "intelligence brief as a JSON object with keys: headline (string), "
    "what_happened (string, >=80 chars), threat_level (low/medium/high/critical), "
    "what_to_do (array of {action, threat})."
)
BRIEFING_USER = (
    "Incident data (cite only what appears here):\n"
    + "\n".join(
        f"[{i}] {t}"
        for i, t in enumerate(
            [
                "Akira ransomware breached a US healthcare provider via an unpatched VPN.",
                "A supply-chain compromise in a popular npm package exfiltrated tokens.",
                "CISA added CVE-2026-9999 (Ivanti) to the KEV catalog; active exploitation.",
                "ShinyHunters leaked 2M records from a breached SaaS CRM.",
                "A new Qilin affiliate is targeting manufacturing OT networks.",
            ] * 8, 1
        )
    )
    + "\n\nWrite the brief now. Cite sources as [N]."
)


def _post(base: str, model: str, key: str, sys_p: str, user_p: str,
          max_tokens: int, use_rf: bool, timeout: float = 60.0):
    url = f"{base.rstrip('/')}/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": sys_p},
            {"role": "user", "content": user_p},
        ],
        "temperature": 0.3,
        "max_tokens": max_tokens,
    }
    if use_rf:
        payload["response_format"] = {"type": "json_object"}
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = json.loads(r.read().decode())
        dt = time.time() - t0
        content = body["choices"][0]["message"]["content"]
        usage = body.get("usage", {})
        return {"ok": True, "latency": dt, "content": content,
                "tokens": usage.get("total_tokens"), "rf": use_rf}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()[:200]
        # Retry once without response_format if that's what tripped a 400.
        if use_rf and e.code == 400 and "response_format" in err_body:
            return _post(base, model, key, sys_p, user_p, max_tokens, False, timeout)
        return {"ok": False, "latency": time.time() - t0,
                "error": f"HTTP {e.code}: {err_body}", "rf": use_rf}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "latency": time.time() - t0, "error": str(e)[:200], "rf": use_rf}


def _json_valid(text: str) -> bool:
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.split("```", 2)[1].removeprefix("json").strip() if "```" in text else text
    try:
        json.loads(text)
        return True
    except Exception:
        # tolerate leading prose then a JSON object
        i, j = text.find("{"), text.rfind("}")
        if i >= 0 and j > i:
            try:
                json.loads(text[i:j + 1])
                return True
            except Exception:
                return False
        return False


def main() -> int:
    print(f"{'provider':<18} {'classify':<26} {'briefing':<26}")
    print("-" * 72)
    results = []
    for name, base, model, key_env, needs_key in PROVIDERS:
        key = os.environ.get(key_env, "").strip()
        if needs_key and not key:
            print(f"{name:<18} {'(no key: '+key_env+')':<26}")
            continue
        c = _post(base, model, key, CLASSIFY_SYS, CLASSIFY_USER, 200, True)
        b = _post(base, model, key, BRIEFING_SYS, BRIEFING_USER, 1200, True)

        def cell(r):
            if not r["ok"]:
                return f"FAIL {r['error'][:20]}"
            jv = "json" if _json_valid(r.get("content", "")) else "TEXT"
            rf = "rf" if r.get("rf") else "no-rf"
            return f"OK {r['latency']:.1f}s {jv} {rf} {r.get('tokens') or '?'}t"

        print(f"{name:<18} {cell(c):<26} {cell(b):<26}")
        results.append((name, c, b))
    print("-" * 72)
    good = [n for n, c, b in results if c["ok"] and b["ok"]
            and _json_valid(c.get("content", "")) and _json_valid(b.get("content", ""))]
    print(f"Fully working (both workloads, valid JSON): {good or 'none'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
