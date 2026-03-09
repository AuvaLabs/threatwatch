# ==== Module Imports ====
import os
import json
import logging
from datetime import datetime
from pathlib import Path

# ==== Centralized Log Setup ====
def setup_logger():
    log_dir = Path("data/logs")
    log_dir.mkdir(parents=True, exist_ok=True)

    log_file = log_dir / f"run_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.log"

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s | %(levelname)s | %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    logging.info("Logger initialized.")
    return log_file


# ==== Summary Audit Logger ====
def log_article_summary(article_link, summary_text):
    try:
        summary_dir = Path("data/logs/summaries")
        summary_dir.mkdir(parents=True, exist_ok=True)
        summary_file = summary_dir / f"summary_{datetime.utcnow().date()}.jsonl"

        entry = {
            "url": article_link,
            "summary": summary_text,
            "timestamp": datetime.utcnow().isoformat()
        }

        with open(summary_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

        logging.info(f"Summary logged for {article_link}.")

    except Exception as e:
        logging.error(f"Failed to log summary for {article_link}: {e}")
