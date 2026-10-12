#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# recover-env.sh — fix "password authentication failed for user socis_admin".
#
# Cause: the Postgres password is baked into its data volume the first time the
# database starts. If deploy/docker/.env later changes (e.g. an installer re-run
# regenerated it), the backend sends a different password and cannot start.
#
# What this does (no data is deleted):
#   1. Tests the DB_PASSWORD from the current .env and from every saved backup
#      (.env.backup.*) against the RUNNING Postgres container.
#   2. If the current one already works -> reports that the cause is elsewhere.
#   3. If a saved one works -> restores it (current file kept as .env.broken.*).
#   4. If none works -> sets the Postgres password to the current .env value
#      through Postgres's local socket (keeps all data), and tells you what that
#      means for encrypted settings.
#   5. Re-creates backend/worker/mcp_all and waits for the backend to answer.
#
# Usage: bash recover-env.sh [REPO_ROOT]     (COMPOSE_FILE=docker-compose.prod.yml for prod)
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
COMPOSE_DIR="$ROOT/deploy/docker"
CF="${COMPOSE_FILE:-docker-compose.dev.yml}"
DOCKER="${DOCKER:-docker}"
PG="${PG_CONTAINER:-socis_postgres}"
BACKEND="${BACKEND_CONTAINER:-socis_backend}"
DB_USER="${DB_USER:-socis_admin}"; DB_NAME="${DB_NAME:-socis_ai_pt}"
CURRENT="$COMPOSE_DIR/.env"

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; N='\033[0m'
say(){ echo -e "$*"; }; ok(){ say "  ${G}✓${N} $*"; }; bad(){ say "  ${R}✗${N} $*"; }; note(){ say "  ${Y}!${N} $*"; }

getv() {   # getv FILE KEY  -> value without surrounding quotes
  [[ -f "$1" ]] || return 0
  local v; v="$(grep -m1 "^$2=" "$1" | cut -d= -f2-)"
  v="${v#\'}"; v="${v%\'}"; v="${v#\"}"; v="${v%\"}"; printf '%s' "$v"
}
db_ok() {  # does Postgres accept this password?
  # Connect over the container's NETWORK address. 127.0.0.1 is "trust" in the official image (ANY password
  # passes), so a loopback test proves nothing — that mistake made an earlier version accept every file.
  "$DOCKER" exec -e PGPASSWORD="$1" "$PG" sh -c 'psql -h "$(hostname -i | cut -d" " -f1)" -U "$0" -d "$1" -tAc "select 1"' "$DB_USER" "$DB_NAME" >/dev/null 2>&1
}
dc() { "$DOCKER" compose -f "$COMPOSE_DIR/$CF" "$@"; }
ensure_key() { grep -q "^$1=" "$CURRENT" 2>/dev/null || { echo "$1=$2" >> "$CURRENT"; note "added missing setting $1"; }; }
rand_hex() { openssl rand -hex "$1" 2>/dev/null || python3 -c "import secrets;print(secrets.token_hex($1))"; }

# The DB password the RUNNING backend container was created with. Containers read .env only when
# they are created, so a container made while .env was wrong keeps crash-looping after .env is fixed.
container_db_pw() {
  "$DOCKER" inspect "$BACKEND" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
    | grep -m1 '^DATABASE_URL=' | sed -E 's#^DATABASE_URL=[^:]+://[^:]+:([^@]*)@.*#\1#'
}

wait_backend() {
  local i
  for i in $(seq 1 "${WAIT_TRIES:-45}"); do
    dc exec -T backend curl -sf -o /dev/null http://localhost:8000/health >/dev/null 2>&1 && return 0
    sleep "${WAIT_SLEEP:-2}"
  done
  return 1
}
recreate() {
  say "\n${B}Re-creating backend / worker / mcp_all ...${N}"
  dc up -d --force-recreate backend worker mcp_all >/dev/null 2>&1 || bad "docker compose up reported an error (continuing)"
  dc restart nginx >/dev/null 2>&1 || true
  if wait_backend; then ok "backend is answering on :8000"; return 0; fi
  bad "backend still not answering — relevant log lines:"
  dc logs --tail=300 backend 2>/dev/null | grep -iE "error|traceback|exception|importerror|critical|password" | tail -8 | sed 's/^/      /'
  return 1
}

say "${B}SOCIS-AI-PT env recovery${N}  ($COMPOSE_DIR, $CF)"
command -v "$DOCKER" >/dev/null 2>&1 || { bad "docker not found"; exit 2; }
if ! "$DOCKER" ps --format '{{.Names}}' 2>/dev/null | grep -qx "$PG"; then
  note "$PG is not running — starting it"; "$DOCKER" start "$PG" >/dev/null 2>&1 || { bad "cannot start $PG (is the stack installed?)"; exit 2; }
  for _ in $(seq 1 30); do "$DOCKER" exec "$PG" pg_isready -U "$DB_USER" >/dev/null 2>&1 && break; sleep 2; done
fi

# Sanity probe: a wrong password must be rejected, or testing candidates would prove nothing.
if db_ok "__wrong_password_probe_$$__"; then
  bad "this Postgres accepts ANY password over the network (trust auth) — candidate testing would prove nothing"
  exit 2
fi

# ── 1. candidates: current first, then backups newest-first ────────────────
mapfile -t BACKUPS < <(ls -1t "$COMPOSE_DIR"/.env.backup.* "$ROOT"/.env.backup.* "$ROOT/.env" 2>/dev/null | awk '!seen[$0]++')
CANDS=("$CURRENT" "${BACKUPS[@]}")

say "\n${B}Testing each saved .env against the running database${N}"
WORKING=""
for f in "${CANDS[@]}"; do
  [[ -f "$f" ]] || continue
  pw="$(getv "$f" DB_PASSWORD)"; src="set in file"
  [[ -z "$pw" ]] && { pw="socis_secure_pass"; src="not set → compose default"; }
  when="$(date -r "$f" '+%Y-%m-%d %H:%M' 2>/dev/null || echo '?')"
  if db_ok "$pw"; then ok "$f  [$when]  DB password accepted ($src)"; [[ -z "$WORKING" ]] && WORKING="$f"
  else bad "$f  [$when]  DB password rejected ($src)"; fi
done

# ── 2. the current .env matches the database ─────────────────────────────────
if [[ "$WORKING" == "$CURRENT" ]]; then
  say "\n${G}${B}The current .env matches the database.${N}"
  epw="$(getv "$CURRENT" DB_PASSWORD)"; epw="${epw:-socis_secure_pass}"
  cpw="$(container_db_pw)"
  if [[ -z "$cpw" ]]; then
    note "could not read the backend container's environment"
  elif [[ "$cpw" != "$epw" ]]; then
    bad "the running backend container was created with a DIFFERENT (older) DB password"
    say "    Containers read .env only when they are created, so it keeps retrying with the old value."
  else
    ok "the backend container uses the same password as .env"
  fi
  # Recreating re-reads .env and resets the container's logs, so anything printed below is current.
  recreate; rc=$?
  (( rc != 0 )) && say "\n${Y}Still failing with a correct password — the lines above come from the NEW container.${N}"
  exit $rc
fi

# ── 3. restore a saved .env that matches ───────────────────────────────────
if [[ -n "$WORKING" ]]; then
  TS="$(date +%s)"
  [[ -f "$CURRENT" ]] && cp "$CURRENT" "$COMPOSE_DIR/.env.broken.$TS" && note "current file kept as .env.broken.$TS"
  cp "$WORKING" "$CURRENT"; chmod 600 "$CURRENT"
  ok "restored $WORKING → deploy/docker/.env"
  ensure_key MCP_AUTH_TOKEN "$(rand_hex 32)"
  ensure_key GRAFANA_ADMIN_PASSWORD "$(rand_hex 16)"
  ensure_key MSF_PASSWORD "$(rand_hex 16)"
  recreate; exit $?
fi

# ── 4. nothing matches: align Postgres to the current .env (data is kept) ───
say "\n${Y}${B}No saved .env matches the database.${N} Aligning the database password to the current .env (data is kept)."
PW="$(getv "$CURRENT" DB_PASSWORD)"; PW="${PW:-socis_secure_pass}"
if "$DOCKER" exec -i "$PG" psql -U "$DB_USER" -d "$DB_NAME" -v "pw=$PW" -tA >/dev/null 2>&1 <<'SQL'
ALTER USER socis_admin WITH PASSWORD :'pw';
SQL
then
  if db_ok "$PW"; then ok "Postgres password now matches deploy/docker/.env"; else bad "password change did not take effect"; exit 1; fi
else
  bad "could not change the password through the local socket."
  say "    Manual options: restore the original .env from where you saved it, or (ONLY if the data is disposable)"
  say "    remove the database volume so Postgres re-initialises: ${B}docker compose -f $CF down && docker volume rm \$(docker volume ls -q | grep postgres)${N}"
  exit 1
fi
ensure_key MCP_AUTH_TOKEN "$(rand_hex 32)"
note "ENCRYPTION_KEY in the current .env may differ from the one used when your data was created."
note "If so, previously stored secrets (LLM API keys, SSO secrets, MFA) cannot be decrypted — re-enter them in the UI."
recreate; exit $?
