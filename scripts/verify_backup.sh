#!/usr/bin/env bash
# Restore a backup into an isolated temporary directory and validate its data.
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 /path/to/tw_YYYYMMDD_HHMMSS.tgz [--output report.json]" >&2
  exit 2
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$SCRIPT_DIR/verify_backup.py" "$@"
