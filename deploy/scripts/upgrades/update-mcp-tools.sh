#!/usr/bin/env bash
# =============================================================================
# SOCIS-AI-PT — MCP Tools Live Updater
# Updates all binary tools inside the running mcp_all container WITHOUT
# requiring a Docker image rebuild or container restart.
#
# Usage:
#   ./deploy/scripts/update-mcp-tools.sh [OPTIONS]
#
# Options:
#   --container NAME   Target container name (default: socis_mcp_all)
#   --tool TOOL        Update only one tool (nuclei|ffuf|gobuster|sqlmap|
#                      nikto|masscan|wpscan|nmap|wordlists|pip|cve-lite|all)
#   --dry-run          Print what would be updated without making changes
#   --no-color         Disable colored output
#   -h, --help         Show this help
#
# Examples:
#   ./deploy/scripts/update-mcp-tools.sh
#   ./deploy/scripts/update-mcp-tools.sh --tool nuclei
#   ./deploy/scripts/update-mcp-tools.sh --tool ffuf --tool gobuster
#   ./deploy/scripts/update-mcp-tools.sh --dry-run
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
CONTAINER="socis_mcp_all"
TOOLS_REQUESTED=()
DRY_RUN=false
NO_COLOR=false

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --container) CONTAINER="$2"; shift 2 ;;
    --tool)      TOOLS_REQUESTED+=("$2"); shift 2 ;;
    --dry-run)   DRY_RUN=true; shift ;;
    --no-color)  NO_COLOR=true; shift ;;
    -h|--help)
      awk '/^# ==/{if(++n==2)exit; next} n==1{sub(/^# ?/,""); print}' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# Default: update all tools
if [[ ${#TOOLS_REQUESTED[@]} -eq 0 ]]; then
  TOOLS_REQUESTED=(all)
fi

# ── Colors ────────────────────────────────────────────────────────────────────
if [[ "$NO_COLOR" == false ]] && [[ -t 1 ]]; then
  C_RESET='\033[0m'; C_BOLD='\033[1m'; C_CYAN='\033[0;36m'
  C_GREEN='\033[0;32m'; C_YELLOW='\033[0;33m'; C_RED='\033[0;31m'
  C_BLUE='\033[0;34m'
else
  C_RESET=''; C_BOLD=''; C_CYAN=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_BLUE=''
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
log()  { echo -e "${C_CYAN}[INFO]${C_RESET}  $*"; }
ok()   { echo -e "${C_GREEN}[OK]${C_RESET}    $*"; }
warn() { echo -e "${C_YELLOW}[WARN]${C_RESET}  $*"; }
fail() { echo -e "${C_RED}[FAIL]${C_RESET}  $*" >&2; }
sep()  { echo -e "${C_BLUE}────────────────────────────────────────────────────────${C_RESET}"; }

STARTED=$(date '+%Y-%m-%d %H:%M:%S')
RESULTS=()   # "TOOL:status:detail"

record() { RESULTS+=("$1:$2:$3"); }

# Run a command inside the container (or just print it in dry-run mode)
cexec() {
  if [[ "$DRY_RUN" == true ]]; then
    echo -e "${C_YELLOW}[DRY-RUN]${C_RESET} docker exec ${CONTAINER} $*"
    return 0
  fi
  docker exec "${CONTAINER}" "$@"
}

# ── Pre-flight ────────────────────────────────────────────────────────────────
sep
echo -e "${C_BOLD}SOCIS-AI-PT MCP Tools Updater${C_RESET}  (started: $STARTED)"
sep

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}$"; then
  fail "Container '${CONTAINER}' is not running."
  fail "Start it first:  docker compose -f deploy/docker/docker-compose.yml up -d mcp_all"
  exit 1
fi
log "Container: ${C_BOLD}${CONTAINER}${C_RESET}"
[[ "$DRY_RUN" == true ]] && warn "Dry-run mode — no changes will be made."

# Resolve which tools to run
should_update() {
  local tool="$1"
  for t in "${TOOLS_REQUESTED[@]}"; do
    [[ "$t" == "all" || "$t" == "$tool" ]] && return 0
  done
  return 1
}

# ── Tool: nuclei ──────────────────────────────────────────────────────────────
update_nuclei() {
  log "Updating ${C_BOLD}Nuclei${C_RESET} (ProjectDiscovery)…"
  local before after

  before=$(cexec nuclei -version 2>&1 | grep -oP 'v[\d.]+' | head -1 || echo "unknown")

  cexec bash -c '
    set -e
    VER=$(curl -sf https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
          | grep "\"tag_name\"" | cut -d"\"" -f4)
    [[ -z "$VER" ]] && { echo "Could not fetch nuclei version"; exit 1; }
    wget -q "https://github.com/projectdiscovery/nuclei/releases/download/${VER}/nuclei_${VER#v}_linux_amd64.zip" \
         -O /tmp/nuclei.zip
    unzip -oq /tmp/nuclei.zip nuclei -d /usr/local/bin/
    chmod +x /usr/local/bin/nuclei
    rm -f /tmp/nuclei.zip
    echo "[nuclei] installed: $VER"
  '

  # Update nuclei templates separately (safe, fast)
  cexec bash -c 'nuclei -update-templates -silent 2>&1 | tail -3 || true'

  after=$(cexec nuclei -version 2>&1 | grep -oP 'v[\d.]+' | head -1 || echo "unknown")
  ok "Nuclei: ${before} → ${after}"
  record "nuclei" "ok" "${before}→${after}"
}

# ── Tool: ffuf ────────────────────────────────────────────────────────────────
update_ffuf() {
  log "Updating ${C_BOLD}ffuf${C_RESET}…"
  local before after

  before=$(cexec ffuf -V 2>&1 | grep -oP 'v[\d.]+' | head -1 || echo "unknown")

  cexec bash -c '
    set -e
    VER=$(curl -sf https://api.github.com/repos/ffuf/ffuf/releases/latest \
          | grep "\"tag_name\"" | cut -d"\"" -f4)
    [[ -z "$VER" ]] && { echo "Could not fetch ffuf version"; exit 1; }
    wget -q "https://github.com/ffuf/ffuf/releases/download/${VER}/ffuf_${VER#v}_linux_amd64.tar.gz" \
         -O /tmp/ffuf.tar.gz
    tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf
    chmod +x /usr/local/bin/ffuf
    rm -f /tmp/ffuf.tar.gz
    echo "[ffuf] installed: $VER"
  '

  after=$(cexec ffuf -V 2>&1 | grep -oP 'v[\d.]+' | head -1 || echo "unknown")
  ok "ffuf: ${before} → ${after}"
  record "ffuf" "ok" "${before}→${after}"
}

# ── Tool: gobuster ────────────────────────────────────────────────────────────
update_gobuster() {
  log "Updating ${C_BOLD}Gobuster${C_RESET}…"
  local before after

  before=$(cexec gobuster version 2>&1 | grep -oP '[\d.]+' | head -1 || echo "unknown")

  cexec bash -c '
    set -e
    VER=$(curl -sf https://api.github.com/repos/OJ/gobuster/releases/latest \
          | grep "\"tag_name\"" | cut -d"\"" -f4)
    [[ -z "$VER" ]] && { echo "Could not fetch gobuster version"; exit 1; }
    wget -q "https://github.com/OJ/gobuster/releases/download/${VER}/gobuster_Linux_x86_64.tar.gz" \
         -O /tmp/gobuster.tar.gz
    tar -xzf /tmp/gobuster.tar.gz -C /usr/local/bin/ gobuster
    chmod +x /usr/local/bin/gobuster
    rm -f /tmp/gobuster.tar.gz
    echo "[gobuster] installed: $VER"
  '

  after=$(cexec gobuster version 2>&1 | grep -oP '[\d.]+' | head -1 || echo "unknown")
  ok "Gobuster: ${before} → ${after}"
  record "gobuster" "ok" "${before}→${after}"
}

# ── Tool: sqlmap ──────────────────────────────────────────────────────────────
update_sqlmap() {
  log "Updating ${C_BOLD}SQLMap${C_RESET} (pip)…"
  local before after

  before=$(cexec python3 -c "import sqlmap; print(sqlmap.__version__)" 2>/dev/null || echo "unknown")
  cexec pip install --quiet --no-cache-dir --upgrade sqlmap
  after=$(cexec python3 -c "import sqlmap; print(sqlmap.__version__)" 2>/dev/null || echo "unknown")
  ok "SQLMap: ${before} → ${after}"
  record "sqlmap" "ok" "${before}→${after}"
}

# ── Tool: nikto ───────────────────────────────────────────────────────────────
update_nikto() {
  log "Updating ${C_BOLD}Nikto${C_RESET} (git pull)…"
  local before after

  before=$(cexec nikto -Version 2>&1 | grep -oP '[\d.]+' | head -1 || echo "unknown")
  cexec bash -c 'cd /opt/nikto && git pull --ff-only --quiet 2>&1 | tail -2'
  after=$(cexec nikto -Version 2>&1 | grep -oP '[\d.]+' | head -1 || echo "unknown")
  ok "Nikto: ${before} → ${after}"
  record "nikto" "ok" "${before}→${after}"
}

# ── Tool: masscan ─────────────────────────────────────────────────────────────
update_masscan() {
  log "Updating ${C_BOLD}Masscan${C_RESET} (git pull + rebuild)…"
  local before after

  before=$(cexec masscan --version 2>&1 | grep -oP '[\d.-]+' | head -1 || echo "unknown")

  cexec bash -c '
    set -e
    # Masscan is built from source — git pull and recompile
    if [[ -d /opt/masscan ]]; then
      cd /opt/masscan && git pull --ff-only --quiet
    else
      git clone --depth 1 https://github.com/robertdavidgraham/masscan.git /opt/masscan
    fi
    make -C /opt/masscan -j"$(nproc)" --quiet
    cp /opt/masscan/bin/masscan /usr/local/bin/masscan
    chmod +x /usr/local/bin/masscan
    echo "[masscan] rebuilt from source"
  '

  after=$(cexec masscan --version 2>&1 | grep -oP '[\d.-]+' | head -1 || echo "unknown")
  ok "Masscan: ${before} → ${after}"
  record "masscan" "ok" "${before}→${after}"
}

# ── Tool: wpscan ──────────────────────────────────────────────────────────────
update_wpscan() {
  log "Updating ${C_BOLD}WPScan${C_RESET} (gem update)…"
  local before after

  before=$(cexec wpscan --version 2>&1 | grep -oP '[\d.]+' | head -1 || echo "unknown")
  cexec gem update wpscan --no-document --quiet 2>&1 | tail -3 || true
  after=$(cexec wpscan --version 2>&1 | grep -oP '[\d.]+' | head -1 || echo "unknown")
  ok "WPScan: ${before} → ${after}"
  record "wpscan" "ok" "${before}→${after}"

  # Also update the WPScan vulnerability database
  log "  Refreshing WPScan vulnerability database…"
  cexec wpscan --update --quiet 2>&1 | tail -2 || true
}

# ── Tool: nmap ────────────────────────────────────────────────────────────────
update_nmap() {
  log "Updating ${C_BOLD}Nmap${C_RESET} (apt)…"
  local before after

  before=$(cexec nmap --version 2>&1 | grep -oP '[\d.]+' | head -1 || echo "unknown")
  cexec bash -c 'apt-get update -qq && apt-get install -y --no-install-recommends nmap -qq 2>&1 | tail -2'
  after=$(cexec nmap --version 2>&1 | grep -oP '[\d.]+' | head -1 || echo "unknown")
  ok "Nmap: ${before} → ${after}"
  record "nmap" "ok" "${before}→${after}"
}

# ── Tool: wordlists ───────────────────────────────────────────────────────────
update_wordlists() {
  log "Refreshing ${C_BOLD}SecLists wordlists${C_RESET}…"

  cexec bash -c '
    set -e
    BASE="https://raw.githubusercontent.com/danielmiessler/SecLists/master"
    WL=/usr/share/wordlists
    mkdir -p "$WL"
    wget -q "$BASE/Discovery/Web-Content/common.txt"           -O "$WL/common.txt"
    wget -q "$BASE/Discovery/Web-Content/big.txt"              -O "$WL/big.txt"
    wget -q "$BASE/Discovery/DNS/subdomains-top1million-5000.txt" -O "$WL/subdomains.txt"
    wget -q "$BASE/Discovery/Web-Content/burp-parameter-names.txt" -O "$WL/parameters.txt"
    wget -q "$BASE/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt" -O "$WL/passwords.txt"
    wget -q "$BASE/Usernames/top-usernames-shortlist.txt"      -O "$WL/usernames.txt"
    echo "[wordlists] refreshed $(ls $WL/*.txt | wc -l) files"
  '

  ok "Wordlists: refreshed"
  record "wordlists" "ok" "refreshed"
}

# ── Tool: pip (Python MCP server requirements) ────────────────────────────────
update_pip() {
  log "Updating ${C_BOLD}Python MCP requirements${C_RESET} (pip)…"
  cexec pip install --quiet --no-cache-dir --upgrade -r /app/requirements.txt
  ok "Python packages: updated"
  record "pip" "ok" "requirements upgraded"
}

# ── Tool: cve-lite ────────────────────────────────────────────────────────────
update_cve_lite() {
  log "Updating ${C_BOLD}cve-lite-cli${C_RESET} (npm)…"
  local before after

  before=$(cexec cve-lite --version 2>&1 | grep -oP '[\d.]+' | head -1 || echo "unknown")
  cexec npm install -g --quiet cve-lite-cli 2>&1 | tail -2 || true
  after=$(cexec cve-lite --version 2>&1 | grep -oP '[\d.]+' | head -1 || echo "unknown")
  ok "cve-lite-cli: ${before} → ${after}"
  record "cve-lite" "ok" "${before}→${after}"
}

update_ad() {
  log "Updating ${C_BOLD}Active Directory tools${C_RESET} (NetExec / Impacket / kerbrute)…"
  local before after
  before=$(cexec nxc --version 2>&1 | head -1 || echo "unknown")

  # NetExec + Impacket via pip (official PyPI). Pinned-floor update: refresh to latest stable.
  cexec bash -c 'pip install --no-cache-dir --upgrade netexec impacket 2>&1 | tail -3 || true'

  # kerbrute: refresh to the latest official release binary.
  cexec bash -c '
    VER=$(curl -sf https://api.github.com/repos/ropnop/kerbrute/releases/latest \
          | grep "\"tag_name\"" | cut -d"\"" -f4)
    [[ -z "$VER" ]] && { echo "[kerbrute] could not fetch version; keeping current"; exit 0; }
    wget -q "https://github.com/ropnop/kerbrute/releases/download/${VER}/kerbrute_linux_amd64" \
         -O /usr/local/bin/kerbrute && chmod +x /usr/local/bin/kerbrute
    echo "[kerbrute] installed: $VER"
  '

  after=$(cexec nxc --version 2>&1 | head -1 || echo "unknown")
  ok "AD tools: ${before} → ${after}"
  record "ad" "ok" "${before}→${after}"
}

# ── Dispatch ──────────────────────────────────────────────────────────────────
update_trivy() {
  log "Updating ${C_BOLD}Trivy${C_RESET} vulnerability database…"
  local before after
  before=$(cexec trivy --version 2>&1 | head -1 || echo "unknown")
  # Trivy's CVE database is the part that actually goes stale day to day; refresh it explicitly.
  cexec trivy image --download-db-only --quiet 2>&1 | tail -3 || true
  after=$(cexec trivy --version 2>&1 | head -1 || echo "unknown")
  ok "Trivy: ${before} → ${after} (vulnerability DB refreshed)"
  record "trivy" "ok" "DB refreshed"
}

TOOL_FUNCTIONS=(nuclei ffuf gobuster sqlmap nikto masscan wpscan nmap wordlists pip cve-lite ad trivy)

for tool in "${TOOL_FUNCTIONS[@]}"; do
  # Map cve-lite to function name
  fn="update_${tool//-/_}"
  if should_update "$tool"; then
    sep
    if ! $fn 2>&1; then
      fail "${tool}: update failed — container may be missing a dependency"
      record "$tool" "FAIL" "see output above"
    fi
  fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
sep
echo -e "${C_BOLD}Update Summary${C_RESET}"
sep
for r in "${RESULTS[@]}"; do
  IFS=':' read -r tool status detail <<< "$r"
  if [[ "$status" == "ok" ]]; then
    echo -e "  ${C_GREEN}✓${C_RESET} ${C_BOLD}${tool}${C_RESET}  ${detail}"
  else
    echo -e "  ${C_RED}✗${C_RESET} ${C_BOLD}${tool}${C_RESET}  ${detail}"
  fi
done
sep
echo "Completed: $(date '+%Y-%m-%d %H:%M:%S')"

# Exit with failure if any tool failed
for r in "${RESULTS[@]}"; do
  IFS=':' read -r _ status _ <<< "$r"
  [[ "$status" == "FAIL" ]] && exit 1
done
exit 0
