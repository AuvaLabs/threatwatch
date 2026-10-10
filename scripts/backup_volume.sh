#!/usr/bin/env bash
# Create and restore-verify a consistent backup of the ThreatWatch data volume.
set -euo pipefail

VOLUME="${TW_VOLUME:-threatwatch_threatwatch-data}"
WRITER_CONTAINER="${TW_WRITER_CONTAINER:-threatwatch-pipeline}"
BACKUP_DIR="${TW_BACKUP_DIR:-$HOME/backups/threatwatch}"
KEEP="${TW_BACKUP_KEEP:-7}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if ! [[ "$KEEP" =~ ^[1-9][0-9]*$ ]]; then
  echo "TW_BACKUP_KEEP must be a positive integer" >&2
  exit 2
fi
if [ -z "$BACKUP_DIR" ] || [ "$BACKUP_DIR" = "/" ]; then
  echo "Refusing unsafe backup directory" >&2
  exit 2
fi

if [ "$(id -u)" -eq 0 ]; then
  DOCKER=(docker)
else
  DOCKER=(sudo docker)
fi

mkdir -p "$BACKUP_DIR"
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/threatwatch-backup.XXXXXX")
STAMP=$(date -u +%Y%m%d_%H%M%S)
ARCHIVE_NAME="tw_${STAMP}.tgz"
OUT="$BACKUP_DIR/$ARCHIVE_NAME"
CHECKSUM="$OUT.sha256"
VERIFY_REPORT="$WORK_DIR/verification.json"
STATUS_REPORT="$WORK_DIR/backup_status.json"
WRITER_PAUSED=false

resume_writer() {
  if $WRITER_PAUSED; then
    "${DOCKER[@]}" unpause "$WRITER_CONTAINER" >/dev/null
    WRITER_PAUSED=false
  fi
}

cleanup() {
  resume_writer
  rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

writer_running=$("${DOCKER[@]}" inspect \
  --format '{{if .State.Running}}{{if .State.Paused}}paused{{else}}running{{end}}{{else}}stopped{{end}}' \
  "$WRITER_CONTAINER" 2>/dev/null || printf 'missing')
if [ "$writer_running" = "running" ]; then
  # docker pause freezes SQLite and its WAL at one filesystem instant.
  "${DOCKER[@]}" pause "$WRITER_CONTAINER" >/dev/null
  WRITER_PAUSED=true
elif [ "$writer_running" != "paused" ]; then
  echo "Writer container is not running: $WRITER_CONTAINER" >&2
  exit 1
fi

"${DOCKER[@]}" run --rm \
  -v "${VOLUME}:/data:ro" \
  -v "${BACKUP_DIR}:/backup" \
  alpine \
  tar czf "/backup/$ARCHIVE_NAME" -C /data .
resume_writer

if [ ! -s "$OUT" ]; then
  echo "Backup archive was not created: $OUT" >&2
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  sudo chown "$(id -u):$(id -g)" "$OUT"
fi
(
  cd "$BACKUP_DIR"
  sha256sum "$ARCHIVE_NAME" > "$ARCHIVE_NAME.sha256"
)
if ! bash "$SCRIPT_DIR/verify_backup.sh" "$OUT" --output "$VERIFY_REPORT"; then
  rm -f -- "$OUT" "$CHECKSUM"
  exit 1
fi

OFFSITE_CONFIGURED=false
OFFSITE_OK_JSON=null
OFFSITE_FAILED=false
OFFSITE_METHODS=()

record_offsite_failure() {
  OFFSITE_FAILED=true
  echo "[$(date -u +%FT%TZ)] offsite $1 FAILED: $2" >&2
}

if [ -n "${TW_OFFSITE_RCLONE:-}" ]; then
  OFFSITE_CONFIGURED=true
  OFFSITE_METHODS+=(rclone)
  if ! command -v rclone >/dev/null 2>&1; then
    record_offsite_failure rclone "command not found"
  elif rclone copy "$OUT" "$TW_OFFSITE_RCLONE" 2>"$WORK_DIR/rclone.err"; then
    rclone copy "$CHECKSUM" "$TW_OFFSITE_RCLONE" 2>>"$WORK_DIR/rclone.err" || \
      record_offsite_failure rclone "checksum upload failed"
  else
    record_offsite_failure rclone "$(tr '\n' ' ' <"$WORK_DIR/rclone.err")"
  fi
fi

if [ -n "${TW_OFFSITE_SCP:-}" ]; then
  OFFSITE_CONFIGURED=true
  OFFSITE_METHODS+=(scp)
  if ! command -v scp >/dev/null 2>&1; then
    record_offsite_failure scp "command not found"
  elif ! scp -q -o StrictHostKeyChecking=accept-new \
    "$OUT" "$CHECKSUM" "$TW_OFFSITE_SCP" 2>"$WORK_DIR/scp.err"; then
    record_offsite_failure scp "$(tr '\n' ' ' <"$WORK_DIR/scp.err")"
  fi
fi

if [ -n "${TW_OFFSITE_RSYNC:-}" ]; then
  OFFSITE_CONFIGURED=true
  OFFSITE_METHODS+=(rsync)
  if ! command -v rsync >/dev/null 2>&1; then
    record_offsite_failure rsync "command not found"
  elif ! rsync -aq --delete-after -e "ssh -o StrictHostKeyChecking=accept-new" \
    "$BACKUP_DIR/" "$TW_OFFSITE_RSYNC/" 2>"$WORK_DIR/rsync.err"; then
    record_offsite_failure rsync "$(tr '\n' ' ' <"$WORK_DIR/rsync.err")"
  fi
fi

if $OFFSITE_CONFIGURED; then
  OFFSITE_OK_JSON=true
  $OFFSITE_FAILED && OFFSITE_OK_JSON=false
fi
METHODS_CSV=$(IFS=,; printf '%s' "${OFFSITE_METHODS[*]:-}")
COMPLETED_AT=$(date -u +%FT%TZ)
python3 - "$VERIFY_REPORT" "$STATUS_REPORT" "$COMPLETED_AT" \
  "$OFFSITE_CONFIGURED" "$OFFSITE_OK_JSON" "$METHODS_CSV" <<'PY'
import json
import sys

source, target, completed_at, configured, offsite_ok, methods = sys.argv[1:]
report = json.loads(open(source, encoding="utf-8").read())
report["completed_at"] = completed_at
report["offsite"] = {
    "configured": configured == "true",
    "ok": None if offsite_ok == "null" else offsite_ok == "true",
    "methods": [method for method in methods.split(",") if method],
}
with open(target, "w", encoding="utf-8") as output:
    json.dump(report, output, sort_keys=True)
    output.write("\n")
PY

"${DOCKER[@]}" run --rm \
  -v "${VOLUME}:/data" \
  -v "${WORK_DIR}:/status:ro" \
  alpine sh -c \
  'mkdir -p /data/state && cp /status/backup_status.json /data/state/.backup_status.json.tmp && chmod 0644 /data/state/.backup_status.json.tmp && mv /data/state/.backup_status.json.tmp /data/state/backup_status.json'

mapfile -t archives < <(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'tw_*.tgz' -printf '%T@ %p\n' | sort -nr | cut -d' ' -f2-)
if [ "${#archives[@]}" -gt "$KEEP" ]; then
  for old_archive in "${archives[@]:$KEEP}"; do
    rm -f -- "$old_archive" "$old_archive.sha256"
  done
fi

SIZE=$(du -h "$OUT" | awk '{print $1}')
echo "[$COMPLETED_AT] backup and restore verification ok: $OUT ($SIZE)"
if $OFFSITE_FAILED; then
  exit 1
fi
