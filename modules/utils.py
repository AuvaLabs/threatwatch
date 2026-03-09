from datetime import datetime
from pathlib import Path
import os
import logging

# Time slugs
def get_current_hour_slug():
    return datetime.utcnow().strftime("%Y-%m-%d_%H")

def get_today_slug():
    return datetime.utcnow().strftime("%Y-%m-%d")

def get_week_slug(dt=None):
    dt = dt or datetime.utcnow()
    return dt.strftime("%Y-W%U")  # Week number of the year

def get_month_slug(dt=None):
    dt = dt or datetime.utcnow()
    return dt.strftime("%Y-%m")

def get_year_slug(dt=None):
    dt = dt or datetime.utcnow()
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

