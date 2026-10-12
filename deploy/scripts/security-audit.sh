#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# security-audit.sh — dependency CVE audit for SOCIS-AI-PT (verifies finding H-6).
#
# Runs pip-audit (backend) and npm audit (frontend) against what is ACTUALLY
# deployed in the running containers, and summarizes findings by severity. Use
# it after dependency bumps and before a production deployment.
#
# Usage:
#   bash security-audit.sh [TARGET]
#     TARGET  repo path (default /opt/socis.io/SOCIS-AI-PT)
#
# Exit codes:
#   0  no HIGH/CRITICAL vulnerabilities
#   1  HIGH/CRITICAL vulnerabilities found (review output)
#   2  could not run an audit (tool/container unavailable)
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

TARGET="${1:-/opt/socis.io/SOCIS-AI-PT}"
# Prefer the dev compose; override with COMPOSE_FILE=docker-compose.prod.yml.
_CF="${COMPOSE_FILE:-docker-compose.dev.yml}"
COMPOSE="docker compose -f ${TARGET}/deploy/docker/${_CF}"

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; N='\033[0m'
hdr(){ echo -e "\n${C}${B}=== $* ===${N}"; }
ok(){ echo -e "  ${G}✓${N} $*"; }
no(){ echo -e "  ${R}✗${N} $*"; }
wn(){ echo -e "  ${Y}!${N} $*"; }

RC=0

echo -e "${B}SOCIS-AI-PT dependency audit${N}  (compose: ${_CF})"

# ─── Backend: pip-audit ──────────────────────────────────────
hdr "Backend (Python) — pip-audit"
if ! $COMPOSE ps backend 2>/dev/null | grep -q backend; then
  wn "backend container not running — skipping pip-audit"
  RC=2
else
  # Install pip-audit on the fly inside the container (no image change), then
  # audit the live installed packages.
  AUDIT=$($COMPOSE exec -T backend sh -c '
    pip install --quiet --disable-pip-version-check pip-audit >/dev/null 2>&1
    pip-audit --progress-spinner off 2>/dev/null
  ' 2>/dev/null)
  # Fallback: audit the requirements file from the HOST if the container was
  # offline (needs pip-audit + network on the host instead).
  if [[ -z "$AUDIT" ]] && command -v pip-audit >/dev/null 2>&1; then
    wn "container pip-audit unavailable — auditing requirements.txt from host"
    AUDIT=$(pip-audit -r "$TARGET/backend/requirements.txt" --progress-spinner off 2>/dev/null)
  fi
  if [[ -z "$AUDIT" ]]; then
    wn "pip-audit produced no output (no network in container, and no host pip-audit)"
    wn "Run on a networked host:  pip install pip-audit && pip-audit -r backend/requirements.txt"
    RC=2
  else
    # pip-audit prints "No known vulnerabilities found" when clean.
    if echo "$AUDIT" | grep -qi "No known vulnerabilities found"; then
      ok "No known vulnerabilities in backend dependencies"
    else
      echo "$AUDIT" | sed 's/^/    /'
      # Count affected packages (rough): lines that look like "name version ...".
      VULN_COUNT=$(echo "$AUDIT" | grep -cE "^[a-zA-Z0-9._-]+\s+[0-9]" || true)
      no "pip-audit reported vulnerabilities (${VULN_COUNT} line(s)) — review above"
      RC=1
    fi
    # Explicit re-check of the finding-H-6 packages.
    hdr "H-6 targeted packages (expect patched versions)"
    $COMPOSE exec -T backend sh -c 'pip show jinja2 python-jose aiohttp 2>/dev/null | grep -E "^(Name|Version):"' \
      | paste - - | sed 's/^/    /'
  fi
fi

# ─── Frontend: npm audit ─────────────────────────────────────
hdr "Frontend (Node) — npm audit"
if ! $COMPOSE ps frontend 2>/dev/null | grep -q frontend; then
  wn "frontend container not running — skipping npm audit"
  [[ $RC -eq 0 ]] && RC=2
else
  NPM=$($COMPOSE exec -T frontend sh -c 'cd /app 2>/dev/null || cd /frontend 2>/dev/null; npm audit --omit=dev 2>/dev/null' 2>/dev/null)
  if [[ -z "$NPM" ]]; then
    # Try a JSON summary as a fallback.
    NPM=$($COMPOSE exec -T frontend sh -c 'cd /app 2>/dev/null || cd /frontend 2>/dev/null; npm audit 2>/dev/null' 2>/dev/null)
  fi
  if [[ -z "$NPM" ]]; then
    wn "npm audit produced no output (no lockfile in container, or offline)"
    [[ $RC -eq 0 ]] && RC=2
  else
    echo "$NPM" | tail -20 | sed 's/^/    /'
    if echo "$NPM" | grep -qiE "found 0 vulnerabilities"; then
      ok "No known vulnerabilities in frontend dependencies"
    elif echo "$NPM" | grep -qiE "high|critical"; then
      no "npm audit reports high/critical vulnerabilities — review above"
      RC=1
    else
      wn "npm audit reports low/moderate vulnerabilities — review above"
    fi
  fi
fi

# ─── Summary ─────────────────────────────────────────────────
hdr "Summary"
case $RC in
  0) echo -e "  ${G}${B}No HIGH/CRITICAL dependency vulnerabilities. H-6 verified.${N}" ;;
  1) echo -e "  ${R}${B}HIGH/CRITICAL vulnerabilities found — review and bump the affected packages.${N}" ;;
  2) echo -e "  ${Y}${B}Audit incomplete (a tool/container was unavailable or offline).${N}"
     echo -e "  ${Y}Run on a host with container network access, or audit the lockfiles directly:${N}"
     echo -e "     pip-audit -r backend/requirements.txt    # needs: pip install pip-audit"
     echo -e "     cd frontend && npm audit" ;;
esac
exit $RC
