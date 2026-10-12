#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Switch the dev stack's frontend between two ways of running:
#
#   prod  A pre-built production server. Navigation between pages is instant and refreshes are fast, because nothing is
#         compiled in the browser's path. After you change frontend code you rebuild (about 2-4 minutes).
#   dev   `next dev`. Every page is compiled the FIRST time you open it (slow, and each restart starts cold), but code
#         changes show up immediately. Only worth it while you are actively editing the UI.
#
# Usage:  bash deploy/scripts/frontend-mode.sh <prod|dev|status> [install-dir]
#
# Safe by design: if the build fails (for example a type error), the previous setting is restored and the previous
# frontend container keeps running, so you are never left without a frontend.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

MODE="${1:-status}"
TARGET_DIR="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
DOCKER="${DOCKER_BIN:-docker}"
CF="${COMPOSE_FILE:-docker-compose.dev.yml}"
BASE="${BASE_URL:-http://localhost}"
ENVF="$TARGET_DIR/deploy/docker/.env"
COMPOSE="$DOCKER compose -f $TARGET_DIR/deploy/docker/$CF"

if [[ -t 1 ]]; then G=$'\033[0;32m'; Y=$'\033[1;33m'; R=$'\033[0;31m'; N=$'\033[0m'; else G=; Y=; R=; N=; fi
ok()   { echo "${G}✓${N} $*"; }
warn() { echo "${Y}!${N} $*"; }
die()  { echo "${R}✗${N} $*" >&2; exit 1; }

[[ "$MODE" == prod || "$MODE" == dev || "$MODE" == status ]] || die "Usage: $0 <prod|dev|status> [install-dir]"
[[ -f "$ENVF" ]] || die "No $ENVF — run the installer first."

get_target() { local v; v=$(grep -E '^FRONTEND_TARGET=' "$ENVF" | tail -1 | cut -d= -f2- | tr -d '"'"'"'[:space:]'); echo "${v:-dev}"; }
set_target() {
  if grep -qE '^FRONTEND_TARGET=' "$ENVF"; then sed -i "s|^FRONTEND_TARGET=.*|FRONTEND_TARGET=$1|" "$ENVF"
  else printf '\nFRONTEND_TARGET=%s\n' "$1" >> "$ENVF"; fi
}
label() { [[ "$1" == runner ]] && echo "prod (pre-built production server)" || echo "dev (next dev, compiles each page on first visit)"; }

if [[ "$MODE" == status ]]; then
  cur=$(get_target); echo "Configured frontend mode: $(label "$cur")"
  ne=$($COMPOSE exec -T frontend printenv NODE_ENV 2>/dev/null | tr -d '\r')
  [[ -n "$ne" ]] && echo "Running container NODE_ENV: $ne" || warn "frontend container is not running"
  exit 0
fi

want=dev; [[ "$MODE" == prod ]] && want=runner
prev=$(get_target)
echo "Switching the frontend from: $(label "$prev")"
echo "                         to: $(label "$want")"
[[ "$want" == runner ]] && echo "Building the production frontend (a few minutes; the current frontend keeps running meanwhile)…"

set_target "$want"
if ! $COMPOSE up -d --build frontend; then
  set_target "$prev"
  echo
  die "The build FAILED, so nothing was changed: FRONTEND_TARGET is back to '$prev' and your previous frontend is still running. Send me the build error above and I will fix it."
fi
$COMPOSE restart nginx >/dev/null 2>&1 || warn "could not restart nginx (run: $COMPOSE restart nginx)"

echo "Waiting for the frontend to answer…"
code=000
for _ in $(seq 1 "${FM_WAIT_TRIES:-60}"); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$BASE/login" 2>/dev/null)
  [[ "$code" == 200 ]] && break
  sleep "${FM_WAIT_SLEEP:-3}"
done
[[ "$code" == 200 ]] || die "The frontend did not answer 200 on $BASE/login (last code $code). Check: $COMPOSE logs --tail=50 frontend"
ok "Frontend is up in $(label "$want") mode"
for i in 1 2 3; do printf '   /login try %s: %ss\n' "$i" "$(curl -s -o /dev/null -w '%{time_total}' --max-time 30 "$BASE/login" 2>/dev/null)"; done
[[ "$want" == runner ]] && echo "After you change frontend code, run this script with 'prod' again to rebuild; use 'dev' to go back to hot-reload."
exit 0
