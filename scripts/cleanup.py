import logging
from datetime import datetime
from pathlib import Path

from modules.config import STATE_DIR, OUTPUT_DIR, MAX_SEEN_HASHES

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s"
)

RETENTION_DAYS = 365


def cleanup_seen_hashes():
    hashes_file = STATE_DIR / "seen_hashes.txt"
    if not hashes_file.exists():
        logging.warning("Hash file does not exist.")
        return

    with open(hashes_file, "r") as f:
        hashes = [line.strip() for line in f if line.strip()]

    original_count = len(hashes)
    if original_count <= MAX_SEEN_HASHES:
        logging.info(f"Hash file has {original_count} entries, within limit.")
        return

    trimmed = hashes[-MAX_SEEN_HASHES:]
    with open(hashes_file, "w") as f:
        for h in trimmed:
            f.write(f"{h}\n")

    logging.info(
        f"Trimmed hashes from {original_count} to {len(trimmed)} entries."
    )


def cleanup_old_outputs():
    now = datetime.now()
    deleted_count = 0
    for file in OUTPUT_DIR.rglob("*.json"):
        if file.is_file():
            mtime = datetime.fromtimestamp(file.stat().st_mtime)
            if (now - mtime).days > RETENTION_DAYS:
                try:
                    file.unlink()
                    deleted_count += 1
                    logging.info(f"Deleted old file: {file}")
                except Exception as e:
                    logging.error(f"Error deleting {file}: {e}")

    logging.info(f"Deleted {deleted_count} old output files.")


def cleanup_seen_titles():
    titles_file = STATE_DIR / "seen_titles.txt"
    if not titles_file.exists():
        return

    with open(titles_file, "r", encoding="utf-8") as f:
        titles = [line.strip() for line in f if line.strip()]

    from modules.config import MAX_SEEN_TITLES

    if len(titles) <= MAX_SEEN_TITLES:
        return

    trimmed = titles[-MAX_SEEN_TITLES:]
    with open(titles_file, "w", encoding="utf-8") as f:
        for t in trimmed:
            f.write(f"{t}\n")

    logging.info(f"Trimmed titles from {len(titles)} to {len(trimmed)} entries.")


def main():
    logging.info("=== Running cleanup script ===")
    cleanup_seen_hashes()
    cleanup_seen_titles()
    cleanup_old_outputs()
    logging.info("=== Cleanup completed ===")


if __name__ == "__main__":
    main()
