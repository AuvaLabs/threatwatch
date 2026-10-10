#!/usr/bin/env bash
# Build and release the current clean ThreatWatch checkout with rollback gates.
set -Eeuo pipefail

REBUILD=true
HEALTH_URL="${TW_HEALTH_URL:-http://127.0.0.1:8098/api/v1/health}"
HEALTH_TIMEOUT="${TW_HEALTH_TIMEOUT:-180}"
MAX_ARTICLE_LOSS_PERCENT="${TW_MAX_ARTICLE_LOSS_PERCENT:-5}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
DEPLOY_STARTED=false
TEMP_DIR=""

usage() {
  echo "Usage: $0 [--no-rebuild]" >&2
}

for arg in "$@"; do
  case "$arg" in
    --no-rebuild) REBUILD=false ;;
    *) usage; exit 2 ;;
  esac
done

if ! [[ "$HEALTH_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
  echo "TW_HEALTH_TIMEOUT must be a positive integer" >&2
  exit 2
fi
if ! [[ "$MAX_ARTICLE_LOSS_PERCENT" =~ ^[0-9]+$ ]] || [ "$MAX_ARTICLE_LOSS_PERCENT" -gt 100 ]; then
  echo "TW_MAX_ARTICLE_LOSS_PERCENT must be an integer from 0 to 100" >&2
  exit 2
fi

if [ "$(id -u)" -eq 0 ]; then
  DOCKER=(docker)
else
  DOCKER=(sudo docker)
fi
COMPOSE=("${DOCKER[@]}" compose)

cd "$REPO_DIR"
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "Refusing to deploy a checkout with tracked changes" >&2
  exit 1
fi

EXPECTED_SHA=$(git rev-parse HEAD)
BUILD_TIME=$(date -u +%FT%TZ)
TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/threatwatch-deploy.XXXXXX")
PRE_HEALTH="$TEMP_DIR/pre-health.json"
POST_HEALTH="$TEMP_DIR/post-health.json"

cleanup() {
  [ -z "$TEMP_DIR" ] || rm -rf -- "$TEMP_DIR"
}

capture_current_images() {
  PIPELINE_IMAGE_ID=$("${COMPOSE[@]}" images -q pipeline)
  SERVER_IMAGE_ID=$("${COMPOSE[@]}" images -q server)
  PIPELINE_IMAGE_NAME=$("${DOCKER[@]}" inspect --format '{{.Config.Image}}' threatwatch-pipeline)
  SERVER_IMAGE_NAME=$("${DOCKER[@]}" inspect --format '{{.Config.Image}}' threatwatch-server)
  if [ -z "$PIPELINE_IMAGE_ID" ] || [ -z "$SERVER_IMAGE_ID" ]; then
    echo "Cannot identify the current release images" >&2
    exit 1
  fi
}

rollback() {
  echo "[deploy] health gate failed, restoring previous images" >&2
  "${DOCKER[@]}" image tag "$PIPELINE_IMAGE_ID" "$PIPELINE_IMAGE_NAME"
  "${DOCKER[@]}" image tag "$SERVER_IMAGE_ID" "$SERVER_IMAGE_NAME"
  "${COMPOSE[@]}" up -d --no-deps --force-recreate pipeline server
  echo "[deploy] rollback completed" >&2
}

on_error() {
  status=$?
  trap - ERR
  if $DEPLOY_STARTED; then
    rollback
  fi
  cleanup
  exit "$status"
}
trap on_error ERR
trap cleanup EXIT

echo "[deploy] release $EXPECTED_SHA"
curl -fsS "$HEALTH_URL" > "$PRE_HEALTH"
python3 - "$PRE_HEALTH" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
if payload.get("status") != "ok":
    raise SystemExit(f"pre-deploy health is {payload.get('status')!r}")
if not isinstance(payload.get("articles_total"), int):
    raise SystemExit("pre-deploy health has no article count")
PY

echo "[deploy] creating verified backup"
bash "$SCRIPT_DIR/backup_volume.sh"

capture_current_images
if $REBUILD; then
  echo "[deploy] building release images"
  "${COMPOSE[@]}" build \
    --build-arg "TW_BUILD_SHA=$EXPECTED_SHA" \
    --build-arg "TW_BUILD_TIME=$BUILD_TIME" \
    pipeline server
fi

echo "[deploy] starting release"
DEPLOY_STARTED=true
"${COMPOSE[@]}" up -d --no-deps pipeline server

deadline=$((SECONDS + HEALTH_TIMEOUT))
while [ "$SECONDS" -lt "$deadline" ]; do
  if curl -fsS "$HEALTH_URL" > "$POST_HEALTH" 2>/dev/null && \
    python3 - "$PRE_HEALTH" "$POST_HEALTH" "$EXPECTED_SHA" "$MAX_ARTICLE_LOSS_PERCENT" <<'PY'
import json
import sys

before = json.load(open(sys.argv[1], encoding="utf-8"))
after = json.load(open(sys.argv[2], encoding="utf-8"))
expected_sha = sys.argv[3]
max_loss = int(sys.argv[4])
if after.get("status") != "ok":
    raise SystemExit(1)
if after.get("deployment", {}).get("sha") != expected_sha:
    raise SystemExit(1)
before_count = before["articles_total"]
after_count = after.get("articles_total")
minimum = before_count * (100 - max_loss) / 100
if not isinstance(after_count, int) or after_count < minimum:
    raise SystemExit(1)
if after.get("backup", {}).get("ok") is not True:
    raise SystemExit(1)
PY
  then
    break
  fi
  sleep 5
done

if [ ! -s "$POST_HEALTH" ] || ! python3 - "$POST_HEALTH" "$EXPECTED_SHA" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
valid = payload.get("status") == "ok" and payload.get("deployment", {}).get("sha") == sys.argv[2]
raise SystemExit(0 if valid else 1)
PY
then
  echo "Release did not pass its health gate within ${HEALTH_TIMEOUT}s" >&2
  false
fi

API_ROOT=${HEALTH_URL%/health}
for route in openapi.json operations/summary hunts ledger sources; do
  curl -fsS "$API_ROOT/$route" >/dev/null
done
curl -fsS "${API_ROOT%/api/v1}/" >/dev/null

"${COMPOSE[@]}" ps
DEPLOY_STARTED=false
echo "[deploy] release verified: $EXPECTED_SHA"
