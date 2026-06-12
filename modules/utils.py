import json
import re
from datetime import datetime, timezone
from pathlib import Path
import os
import logging

# Time slugs
def get_current_hour_slug():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d_%H")

def get_today_slug():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")

def get_week_slug(dt=None):
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime("%Y-W%U")  # Week number of the year

def get_month_slug(dt=None):
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime("%Y-%m")

def get_year_slug(dt=None):
    dt = dt or datetime.now(timezone.utc)
    return dt.strftime("%Y")

# Output path generator
def make_output_path(category, slug):
    base = Path("data") / "output" / category
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{slug}.json"

# Generic directory creator
def ensure_output_directory(path=None):
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    else:
        Path("data/output").mkdir(parents=True, exist_ok=True)


_JSON_SANITIZE_PATTERNS = [
    # `[none]` / `[ None ]` / `[undefined]` → `[]` (LLMs emit these for "empty" arrays)
    (re.compile(r"\[\s*(?:none|None|NONE|null|undefined|NaN)\s*\]"), "[]"),
    # Bare `none` / `None` / `undefined` / `NaN` used as a value after `:` or `,` → `null`
    (re.compile(r"(?<=[:\[,])(\s*)(?:none|None|NONE|undefined|NaN)(\s*)(?=[,\]}])"), r"\1null\2"),
    # Trailing commas before `]` or `}` (another common LLM slip)
    (re.compile(r",(\s*[}\]])"), r"\1"),
]


def _sanitize_json_text(text: str) -> str:
    """Apply targeted fixes for common LLM JSON-emission bugs.

    Handles tokens like `none`, `None`, `undefined`, `NaN` and trailing commas.
    Only operates on non-string positions via simple regex — not a full JSON
    parser, so it is best-effort. Returns the sanitized text; if the text was
    already valid JSON it is returned unchanged.
    """
    out = text
    for pat, repl in _JSON_SANITIZE_PATTERNS:
        out = pat.sub(repl, out)
    return out


def extract_json(text):
    """Extract a JSON object from text that may contain markdown fences or prose.

    Tries json.loads first, then falls back to sanitization and regex extraction.
    Used by ai_engine and briefing_generator to parse LLM responses.
    """
    if not text:
        return None
    # 1. Direct parse
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        pass
    # 2. Sanitize common LLM JSON bugs and retry
    sanitized = _sanitize_json_text(text)
    if sanitized != text:
        try:
            return json.loads(sanitized)
        except json.JSONDecodeError:
            pass
    # 3. Regex-extract the first {...} block and try both raw and sanitized
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        block = match.group()
        try:
            return json.loads(block)
        except json.JSONDecodeError:
            pass
        block_sanitized = _sanitize_json_text(block)
        if block_sanitized != block:
            try:
                return json.loads(block_sanitized)
            except json.JSONDecodeError:
                pass
    return None



def write_json_atomic(path, obj, *, indent=None, ensure_ascii=False):
    """Write JSON via temp file + atomic rename.

    Readers (the dashboard server polls these files every request) must never
    observe a partially-written file. os.replace() is atomic on POSIX when
    source and target share a filesystem, which holds because the temp file
    lives next to the target.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=indent, ensure_ascii=ensure_ascii)
    os.replace(tmp, path)
