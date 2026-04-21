#!/usr/bin/env bash
# Deploy ThreatWatch from the current git working directory.
# Run from ~/threatwatch/ on the VPS after `git pull origin main`.
# Usage: bash scripts/deploy.sh [--no-rebuild]
set -euo pipefail

COMPOSE="sudo docker compose"
REBUILD=true

for arg in "$@"; do
  [[ "$arg" == "--no-rebuild" ]] && REBUILD=false
done

echo "[deploy] git status:"
git log --oneline -3

if $REBUILD; then
  echo "[deploy] building images..."
  $COMPOSE build
fi

echo "[deploy] starting containers..."
$COMPOSE up -d

echo "[deploy] waiting 8s for server to start..."
sleep 8

echo "[deploy] health check:"
curl -s http://localhost:8098/api/health | python3 -c "
import json, sys
d = json.load(sys.stdin)
print('  status:', d.get('status'))
print('  briefing_stale:', d.get('briefing_stale'))
print('  articles_total:', d.get('articles_total'))
print('  feed_health:', d.get('feed_health'))
" || true

echo "[deploy] done."
