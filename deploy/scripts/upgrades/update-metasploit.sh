#!/usr/bin/env bash
# =============================================================================
# SOCIS-AI-PT — Metasploit Community Edition Live Updater
# Updates the Metasploit Framework inside the running metasploit_rpc container
# using msfupdate (the official Rapid7 update mechanism) — no rebuild needed.
#
# Usage:
#   ./deploy/scripts/update-metasploit.sh [OPTIONS]
#
# Options:
#   --container NAME   Target container name (default: socis_metasploit_rpc)
#   --dry-run          Show what would run without making changes
#   --no-color         Disable colored output
#   -h, --help         Show this help
#
# Notes:
#   - Uses the free Metasploit Community Edition (metasploitframework/metasploit-framework)
#   - msfupdate pulls the latest modules, exploits, and payloads from Rapid7
#   - The msfrpcd RPC daemon is automatically restarted after update
#   - Metasploit data (loot, sessions, creds) in the /root/.msf4 volume is untouched
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
CONTAINER="socis_metasploit_rpc"
DRY_RUN=false
NO_COLOR=false

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --container) CONTAINER="$2"; shift 2 ;;
    --dry-run)   DRY_RUN=true; shift ;;
    --no-color)  NO_COLOR=true; shift ;;
    -h|--help)
      awk '/^# ==/{if(++n==2)exit; next} n==1{sub(/^# ?/,""); print}' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ── Colors ────────────────────────────────────────────────────────────────────
if [[ "$NO_COLOR" == false ]] && [[ -t 1 ]]; then
  C_RESET='\033[0m'; C_BOLD='\033[1m'; C_CYAN='\033[0;36m'
  C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m'; C_RED='\033[0;31m'
else
  C_RESET=''; C_BOLD=''; C_CYAN=''; C_GREEN=''; C_YELLOW=''; C_RED=''
fi

log()  { echo -e "${C_CYAN}[INFO]${C_RESET}  $*"; }
ok()   { echo -e "${C_GREEN}[OK]${C_RESET}    $*"; }
warn() { echo -e "${C_YELLOW}[WARN]${C_RESET}  $*"; }
fail() { echo -e "${C_RED}[FAIL]${C_RESET}  $*" >&2; }
sep()  { echo -e "${C_CYAN}────────────────────────────────────────────────────────${C_RESET}"; }

cexec() {
  if [[ "$DRY_RUN" == true ]]; then
    echo -e "${C_YELLOW}[DRY-RUN]${C_RESET} docker exec ${CONTAINER} $*"
    return 0
  fi
  docker exec "${CONTAINER}" "$@"
}

# ── Pre-flight ────────────────────────────────────────────────────────────────
sep
echo -e "${C_BOLD}SOCIS-AI-PT Metasploit Updater${C_RESET}  ($(date '+%Y-%m-%d %H:%M:%S'))"
sep

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
  fail "Container '${CONTAINER}' is not running."
  fail "Start it:  docker compose -f deploy/docker/docker-compose.yml up -d metasploit_rpc"
  exit 1
fi
log "Container: ${C_BOLD}${CONTAINER}${C_RESET}"
[[ "$DRY_RUN" == true ]] && warn "Dry-run mode — no changes will be made."

# ── 1. Show current version ───────────────────────────────────────────────────
sep
log "Current Metasploit version:"
cexec bash -c 'msfconsole -q -x "version; exit" 2>/dev/null | grep -i "metasploit" | head -3 || echo "  (version check skipped — msfconsole not in PATH)"'

# ── 2. Run msfupdate ──────────────────────────────────────────────────────────
sep
log "Running ${C_BOLD}msfupdate${C_RESET} (Rapid7 official updater)…"
log "This downloads the latest modules, exploits, payloads, and auxiliary scripts."
log "The RPC daemon continues running during the update."
echo ""

cexec bash -c '
  set -e
  # msfupdate is at /usr/bin/msfupdate on the official Rapid7 Docker image.
  # It calls apt-get / git pull internally — no network restrictions needed.
  if command -v msfupdate >/dev/null 2>&1; then
    msfupdate
  elif [[ -f /usr/local/bin/msfupdate ]]; then
    /usr/local/bin/msfupdate
  else
    # Fallback: git pull on the embedded MSF source tree
    MSF_HOME=$(find /usr/share /opt -maxdepth 2 -name "msfrpcd" 2>/dev/null | head -1 | xargs dirname || true)
    if [[ -n "$MSF_HOME" && -d "$MSF_HOME/.git" ]]; then
      echo "[metasploit] git pull on $MSF_HOME"
      cd "$MSF_HOME" && git pull --ff-only
    else
      echo "[metasploit] WARNING: msfupdate not found and no git repo detected."
      echo "             The base Docker image handles updates — use: docker pull metasploitframework/metasploit-framework:latest"
      exit 1
    fi
  fi
'

ok "msfupdate completed"

# ── 3. Update Ruby gems used by Metasploit ────────────────────────────────────
sep
log "Updating Metasploit Ruby gems…"
cexec bash -c '
  if command -v bundle >/dev/null 2>&1; then
    MSF_GEMFILE=$(find /usr/share /opt -name "Gemfile" -path "*/metasploit*" 2>/dev/null | head -1 || true)
    if [[ -n "$MSF_GEMFILE" ]]; then
      cd "$(dirname "$MSF_GEMFILE")"
      bundle update --quiet 2>&1 | tail -5
      echo "[gems] updated"
    else
      echo "[gems] Gemfile not found — skipping"
    fi
  else
    echo "[gems] bundler not available — skipping"
  fi
'

# ── 4. Refresh Metasploit DB (modules cache) ──────────────────────────────────
sep
log "Refreshing Metasploit module cache…"
cexec bash -c '
  if command -v msfconsole >/dev/null 2>&1; then
    msfconsole -q -x "db_rebuild_cache; exit" 2>/dev/null | tail -5 || true
  else
    echo "[cache] msfconsole not available — cache refresh skipped"
  fi
' || warn "Module cache refresh skipped (non-critical)"

# ── 5. Restart the msfrpcd RPC daemon ────────────────────────────────────────
sep
log "Restarting ${C_BOLD}msfrpcd${C_RESET} RPC daemon to load updated modules…"

cexec bash -c '
  # Gracefully kill the existing msfrpcd process
  if pgrep -x msfrpcd >/dev/null 2>&1; then
    echo "[rpc] stopping msfrpcd..."
    pkill -TERM msfrpcd || true
    sleep 5
  fi

  # Re-read environment (password, port, SSL) from running env
  MSF_PASSWORD="${MSF_PASSWORD:-msf_secure_default_2024}"
  MSF_PORT="${MSF_PORT:-55553}"

  echo "[rpc] starting msfrpcd on port $MSF_PORT..."

  # The official image ships msfrpcd in the working directory
  cd "${MSF_ROOT:-/usr/share/metasploit-framework}" 2>/dev/null \
    || cd "$(dirname "$(command -v msfrpcd 2>/dev/null || find /usr/share /opt -name msfrpcd 2>/dev/null | head -1)")" 2>/dev/null \
    || cd "$HOME"

  ./msfrpcd -P "$MSF_PASSWORD" -S -a 0.0.0.0 -p "$MSF_PORT" -n &
  sleep 3
  if pgrep -x msfrpcd >/dev/null 2>&1; then
    echo "[rpc] msfrpcd started successfully"
  else
    echo "[rpc] WARNING: msfrpcd may have failed to start — check container logs"
    exit 1
  fi
'

ok "msfrpcd restarted with updated modules"

# ── 6. Show new version ───────────────────────────────────────────────────────
sep
log "Updated Metasploit version:"
sleep 2
cexec bash -c 'msfconsole -q -x "version; exit" 2>/dev/null | grep -i "metasploit" | head -3 || echo "  (run: docker exec '"${CONTAINER}"' msfconsole -q -x \"version; exit\")"'

sep
ok "Metasploit update complete — no rebuild required."
echo ""
log "To verify the RPC is live:"
echo "    docker exec ${CONTAINER} ps aux | grep msfrpcd"
echo ""
log "To check MCP connectivity:"
echo "    curl http://localhost:8104/health"
sep
