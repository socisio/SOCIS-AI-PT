#!/usr/bin/env bash
# prod-preflight.sh — validate the PRODUCTION artifacts WITHOUT installing anything.
# Safe to run on a dev box: nothing is started, no ports are bound.
#   1. dev/prod compose parity guard
#   2. Docker parses docker-compose.prod.yml (with dummy secrets)
#   3. nginx parses nginx.prod.conf with a throwaway certificate
#   4. install-prod.sh / lib scripts pass bash syntax checks
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; N='\033[0m'; rc=0
ok(){ echo -e "  ${G}✓${N} $*"; }; no(){ echo -e "  ${R}✗${N} $*"; rc=1; }; sk(){ echo -e "  ${Y}·${N} $*"; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

echo "1) dev/prod parity"
out="$(python3 "$ROOT/deploy/scripts/lib/compose_parity.py" "$ROOT/deploy/docker/docker-compose.dev.yml" "$ROOT/deploy/docker/docker-compose.prod.yml" 2>&1)"; c=$?
(( c == 0 )) && ok "$out" || { (( c == 2 )) && sk "skipped ($out) — apt install python3-yaml" || no "$out"; }

echo "2) docker compose parses docker-compose.prod.yml"
if command -v docker >/dev/null 2>&1; then
  cat > "$TMP/env" <<ENV
DOMAIN=preflight.example.com
DB_PASSWORD=x
REDIS_PASSWORD=x
SECRET_KEY=x
JWT_SECRET_KEY=x
ENCRYPTION_KEY=x
ADMIN_PASSWORD=x
MCP_AUTH_TOKEN=x
MSF_PASSWORD=x
MINIO_ACCESS_KEY=x
MINIO_SECRET_KEY=x
GRAFANA_ADMIN_PASSWORD=x
SOCIS_HOME=$TMP/home
ENV
  if err="$(docker compose --env-file "$TMP/env" -f "$ROOT/deploy/docker/docker-compose.prod.yml" config -q 2>&1)"; then ok "compose file is valid (all required variables resolved)"
  else no "compose rejected: $(echo "$err" | head -3)"; fi
else sk "docker not installed"; fi

echo "3) nginx parses nginx.prod.conf (throwaway certificate)"
if command -v docker >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1; then
  mkdir -p "$TMP/ssl"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$TMP/ssl/privkey.pem" -out "$TMP/ssl/fullchain.pem" -subj "/CN=preflight" >/dev/null 2>&1
  if err="$(docker run --rm -v "$ROOT/deploy/nginx/nginx.prod.conf:/etc/nginx/nginx.conf:ro" -v "$TMP/ssl:/etc/nginx/ssl:ro" \
        --add-host backend:127.0.0.1 --add-host frontend:127.0.0.1 nginx:alpine nginx -t 2>&1)"; then ok "nginx: configuration test is successful"
  else no "nginx rejected the config: $(echo "$err" | tail -3)"; fi
else sk "docker/openssl not available"; fi

echo "3b) nginx parses the DEV nginx.conf (so a bad edit cannot take the dev stack down)"
if command -v docker >/dev/null 2>&1; then
  if err="$(docker run --rm -v "$ROOT/deploy/nginx/nginx.conf:/etc/nginx/nginx.conf:ro" \
        --add-host backend:127.0.0.1 --add-host frontend:127.0.0.1 nginx:alpine nginx -t 2>&1)"; then ok "nginx: dev configuration test is successful"
  else no "nginx rejected the DEV config: $(echo "$err" | tail -3)"; fi
else sk "docker not available"; fi

echo "4) undefined names (would crash on import/run — compile checks cannot see these)"
out="$(python3 "$ROOT/deploy/scripts/lib/undefined_names.py" "$ROOT/backend/app" "$ROOT/mcp-servers" 2>&1)"; c=$?
(( c == 0 )) && ok "$(echo "$out" | tail -1)" || no "$out"

echo "5) shell syntax"
for f in install.sh install-prod.sh install-dev.sh verify.sh recover-env.sh lib/tls.sh lib/autosize.sh pin-images.sh; do
  bash -n "$ROOT/deploy/scripts/$f" 2>/dev/null && ok "$f" || no "$f has a syntax error"; done

echo; (( rc == 0 )) && echo -e "${G}Preflight passed — production artifacts are valid.${N}" || echo -e "${R}Preflight FAILED — see above.${N}"
exit $rc
