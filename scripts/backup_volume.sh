#!/bin/bash
# Nightly backup of the named Docker volume that holds all ThreatWatch state
# (articles, feed_health, seen_hashes, AI cache, cost tracker). The volume is
# otherwise opaque to host tooling — a `docker compose down -v` wipes it with
# no warning. Run this from cron on the VPS host, NOT inside a container.
#
# Keeps the last N backups (default 7). Safe to run concurrently with the
# pipeline: tar reads a consistent filesystem snapshot via Docker's overlay.
set -euo pipefail

VOLUME="${TW_VOLUME:-threatwatch_threatwatch-data}"
BACKUP_DIR="${TW_BACKUP_DIR:-$HOME/backups/threatwatch}"
KEEP="${TW_BACKUP_KEEP:-7}"

mkdir -p "$BACKUP_DIR"
STAMP="$(date +%Y%m%d_%H%M%S)"
OUT="$BACKUP_DIR/tw_${STAMP}.tgz"

sudo docker run --rm \
  -v "${VOLUME}:/data:ro" \
  -v "${BACKUP_DIR}:/backup" \
  alpine \
  tar czf "/backup/tw_${STAMP}.tgz" -C /data .

# The tar ran as root inside the container, so the host-side file is root-owned.
# Hand ownership back so the rotation (and any manual cleanup) works without sudo.
sudo chown "$(id -u):$(id -g)" "$OUT"

# Rotate: keep newest KEEP, delete the rest
ls -1t "$BACKUP_DIR"/tw_*.tgz 2>/dev/null | tail -n "+$((KEEP + 1))" | xargs -r rm -f

SIZE=$(du -h "$OUT" | awk '{print $1}')
echo "[$(date -u +%FT%TZ)] backup ok: $OUT ($SIZE), retaining last $KEEP"
