#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# SOCIS-AI-PT — Advanced Installer v2.2
# Fully automated — containers are up and running on completion.
#
# Supports: Ubuntu 22.04/24.04 | Debian 12+ | RHEL 8/9 | Rocky 8/9
#
# Usage:
#   bash install-dev.sh [OPTIONS]
#
# Options:
#   --domain <domain>     Platform domain (default: socis.local)
#   --install-dir <path>  Override install directory (default: ~/.local/share/socis)
#   --email <email>       Admin contact email
#   --standalone          Deploy without MCP servers (backend only)
#   --skip-docker         Skip Docker installation (use existing install)
#   --rebuild             Rebuild containers only (after code changes)
#   --regenerate-env      Overwrite an existing deploy/docker/.env (ONLY for a brand-new database)
#   --unattended          Unattended mode (no prompts)
#   -h, --help            Show this help
#
# Examples:
#   # Development setup — fully automated, all containers started
#   bash install-dev.sh
#
#
#   # Rebuild containers after code changes
#   bash install-dev.sh --rebuild
#
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ─── Script Meta ─────────────────────────────────────────────────────
INSTALLER_VERSION="2.2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# ─── Rebuild flag (resolved after arg parsing) ───────────────────────────────
REBUILD_ONLY=false

# ─── Colors & Logging ────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; DIM='\033[2m'; BOLD='\033[1m'; RESET='\033[0m'

# ─── Banner ──────────────────────────────────────────────────────────
clear
echo -e "${CYAN}"
cat << 'BANNER'

 ▄█████ ▄████▄ ▄█████ ██ ▄█████   ▄████▄ ██   █████▄ ▄▄▄▄▄ ▄▄  ▄▄ ▄▄▄▄▄▄ ▄▄▄▄   ▄▄▄ ▄▄▄▄▄▄ ▄▄  ▄▄▄  ▄▄  ▄▄   ▄▄▄▄▄▄ ▄▄▄▄▄  ▄▄▄▄ ▄▄▄▄▄▄ ▄▄ ▄▄  ▄▄  ▄▄▄▄
 ▀▀▀▄▄▄ ██  ██ ██     ██ ▀▀▀▄▄▄   ██▄▄██ ██   ██▄▄█▀ ██▄▄  ███▄██   ██   ██▄█▄ ██▀██  ██   ██ ██▀██ ███▄██     ██   ██▄▄  ███▄▄   ██   ██ ███▄██ ██ ▄▄
 █████▀ ▀████▀ ▀█████ ██ █████▀   ██  ██ ██   ██     ██▄▄▄ ██ ▀██   ██   ██ ██ ██▀██  ██   ██ ▀███▀ ██ ▀██     ██   ██▄▄▄ ▄▄██▀   ██   ██ ██ ▀██ ▀███▀

                          Advanced Installer v2.2 — Fully Automated • All Containers Up

BANNER
echo -e "${RESET}"

# ─── Log File ─────────────────────────────────────────────────────
LOGFILE="/tmp/socis-install-$(date +%s).log"
touch "$LOGFILE"

# ─── Logging Functions ────────────────────────────────────────────
_log()    { local lvl="$1"; shift; echo -e "${lvl}$*${RESET}" | tee -a "$LOGFILE"; }
info()    { _log "  ${CYAN}[INFO]${RESET}    " "$*"; }
success() { _log "  ${GREEN}[ OK ]${RESET}    " "$*"; }
warn()    { _log "  ${YELLOW}[WARN]${RESET}    " "$*"; }
fail()    {
    _log "\n  ${RED}[FAIL]${RESET}    " "$*"
    echo -e "\n  ${DIM}Logs saved to: ${LOGFILE}${RESET}\n"
    exit 1
}
step()    { echo ""; _log "${BOLD}${CYAN} ► PHASE $* ${RESET}"; }

# ─── Defaults ─────────────────────────────────────────────────────
DEPLOYMENT_MODE="development"  # always development — use install-prod.sh for production
DOMAIN="socis.local"
ADMIN_EMAIL=""
USE_LETSENCRYPT=false
STANDALONE=false
SKIP_DOCKER=false
NO_MONITORING=false
REGENERATE_ENV=false
UNATTENDED=false
INSTALL_DIR_OVERRIDE=""

# ─── Parse Arguments ──────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)           DOMAIN="$2"; shift 2 ;;
        --install-dir)      INSTALL_DIR_OVERRIDE="$2"; shift 2 ;;
        --email)            ADMIN_EMAIL="$2"; shift 2 ;;
        --standalone)       STANDALONE=true; shift ;;
        --skip-docker)      SKIP_DOCKER=true; shift ;;
        --no-monitoring)    NO_MONITORING=true; shift ;;
        --regenerate-env)   REGENERATE_ENV=true; shift ;;
        --rebuild)        REBUILD_ONLY=true; shift ;;
        --unattended)       UNATTENDED=true; shift ;;
        -h|--help)
            head -35 "$0" | tail -32
            exit 0
            ;;
        *)
            warn "Unknown option: $1"
            shift
            ;;
    esac
done

# ─── Deferred Rebuild (runs after arg parsing) ──────────────────────────────
if [[ "$REBUILD_ONLY" == true ]]; then
    echo ""
    echo "🔄 Rebuilding SOCIS-AI-PT containers (development mode)..."
    cd "${REPO_ROOT}/deploy/docker"
    # Monitoring is built into docker-compose.dev.yml — nothing extra to add.
    COMPOSE_ARGS=( -f docker-compose.dev.yml )
    docker compose "${COMPOSE_ARGS[@]}" build --pull 2>&1 | grep -v "^#"
    docker compose "${COMPOSE_ARGS[@]}" up -d
    # nginx caches upstream IPs at startup; recreated containers get new IPs -> 502.
    docker compose "${COMPOSE_ARGS[@]}" restart nginx >/dev/null 2>&1 || true
    echo ""
    echo "✅ Rebuild complete! Services restarted with latest code."
    exit 0
fi

# ─── Resolve INSTALL_DIR ──────────────────────────────────────────
# Explicit --install-dir wins; otherwise use per-user default (no root needed).
if [[ -n "$INSTALL_DIR_OVERRIDE" ]]; then
    INSTALL_DIR="$INSTALL_DIR_OVERRIDE"
else
    INSTALL_DIR="${HOME}/.local/share/socis"
fi

DATA_DIR="${INSTALL_DIR}/data"

# ─── OS Detection ─────────────────────────────────────────────────
if [[ ! -f /etc/os-release ]]; then
    fail "Cannot detect OS. /etc/os-release not found."
fi

source /etc/os-release
OS_ID="${ID}"
OS_VERSION="${VERSION_ID%%.*}"

info "Detected: ${PRETTY_NAME}"
info "Installation Mode: ${DEPLOYMENT_MODE^^}"
info "Install Directory: ${INSTALL_DIR}"
info "Log File: ${LOGFILE}"

# ─── Confirm Deployment ──────────────────────────────────────────
if [[ "$UNATTENDED" != true ]]; then
    echo ""
    echo -e "  ${YELLOW}DEPLOYMENT CONFIGURATION:${RESET}"
    echo -e "    Domain: ${DOMAIN}"
    echo -e "    Mode: ${DEPLOYMENT_MODE^^}"
    echo -e "    Location: ${INSTALL_DIR}"
    [[ "$STANDALONE" == true ]] && echo -e "    Profile: Standalone (backend only)"
    echo ""
    read -rp "  Proceed with ${DEPLOYMENT_MODE} deployment? [Y/n] " confirm
    case "${confirm,,}" in
        n|no) echo -e "\n  ${YELLOW}Aborted.${RESET}\n"; exit 0 ;;
    esac
fi

# ═════════════════════════════════════════════════════════════════════
# PHASE 1 — Pre-Flight Checks
# ═════════════════════════════════════════════════════════════════════
step "1/9 — System Validation"

info "Checking system requirements..."

# Check git
if ! command -v git &>/dev/null; then
    fail "Git is required but not installed. Please install git and retry."
fi
success "Git available"

# Check curl
if ! command -v curl &>/dev/null; then
    fail "curl is required but not installed."
fi
success "curl available"

# Check openssl (needed for secret generation)
if ! command -v openssl &>/dev/null; then
    fail "openssl is required but not installed."
fi
success "openssl available"

# Check Python
if command -v python3 &>/dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    success "Python ${PYTHON_VERSION} detected"
else
    fail "Python 3.9+ is required but not found."
fi

# ═════════════════════════════════════════════════════════════════════
# PHASE 2 — Repository Setup
# ═════════════════════════════════════════════════════════════════════
step "2/9 — Repository Preparation"

info "Repository root: ${REPO_ROOT}"

# Verify structure
[[ ! -d "$REPO_ROOT/backend" ]]       && fail "Missing backend/ directory in repository"
[[ ! -d "$REPO_ROOT/frontend" ]]      && fail "Missing frontend/ directory in repository"
[[ ! -d "$REPO_ROOT/deploy/docker" ]] && fail "Missing deploy/docker/ directory in repository"

success "Repository structure validated"

# ═════════════════════════════════════════════════════════════════════
# PHASE 3 — Docker Preparation (if not skipped)
# ═════════════════════════════════════════════════════════════════════
if [[ "$SKIP_DOCKER" != true ]]; then
    step "3/9 — Docker Engine Setup"
    
    if command -v docker &>/dev/null; then
        success "Docker already installed: $(docker --version)"
    else
        info "Docker not found — installing Docker CE..."
        case "$OS_ID" in
            ubuntu|debian)
                apt-get update -qq
                apt-get install -y -qq ca-certificates curl gnupg
                install -m 0755 -d /etc/apt/keyrings
                curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" \
                    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
                chmod a+r /etc/apt/keyrings/docker.gpg
                echo \
                  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
                  https://download.docker.com/linux/${OS_ID} \
                  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
                  | tee /etc/apt/sources.list.d/docker.list > /dev/null
                apt-get update -qq
                apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
                systemctl enable --now docker
                ;;
            rhel|rocky|centos|almalinux)
                dnf config-manager --add-repo \
                    https://download.docker.com/linux/centos/docker-ce.repo 2>/dev/null || \
                    yum-config-manager --add-repo \
                    https://download.docker.com/linux/centos/docker-ce.repo
                dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
                systemctl enable --now docker
                ;;
            *)
                fail "Unsupported OS: ${OS_ID}. Install Docker manually and re-run with --skip-docker."
                ;;
        esac
        success "Docker CE installed"
    fi

    # Add current user to docker group so they can run docker without sudo (dev mode)
    if [[ "$DEPLOYMENT_MODE" == "development" && $EUID -ne 0 ]]; then
        if ! groups 2>/dev/null | grep -q docker; then
            usermod -aG docker "$USER" 2>/dev/null && \
                warn "Added $USER to docker group — you may need to log out/in for this to take effect" || \
                warn "Could not add $USER to docker group — prefix docker commands with sudo if needed"
        fi
    fi

    # Resolve and verify Docker binary
    DOCKER_BIN="$(command -v docker)"
    "$DOCKER_BIN" compose version &>/dev/null || fail "Docker Compose plugin is not available."
    success "Docker Compose ready: $("$DOCKER_BIN" compose version --short 2>/dev/null || echo 'ok')"
else
    step "3/9 — Docker Setup (Skipped)"
    DOCKER_BIN="$(command -v docker 2>/dev/null || echo docker)"
    info "Using existing Docker at: ${DOCKER_BIN}"
fi

# ═════════════════════════════════════════════════════════════════════
# PHASE 4 — Installation Directory Setup
# ═════════════════════════════════════════════════════════════════════
step "4/9 — Directory Preparation"

info "Creating directories under: ${INSTALL_DIR}"
mkdir -p "$INSTALL_DIR"/{data,logs,uploads,reports}
success "Development directories created"

# Dev secrets — hard-coded defaults, safe for local use only
SECRET_KEY="dev-secret-change-in-production"
JWT_SECRET="dev-jwt-secret-change-in-production"
DB_PASSWORD="devpassword"
REDIS_PASSWORD="devpassword"
MINIO_SECRET="dev-minio-secret"
ADMIN_PASSWORD="Admin123!"

# Generate Fernet-compatible encryption key (URL-safe base64 of 32 random bytes)
ENCRYPTION_KEY=$(python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())" 2>/dev/null \
    || openssl rand -base64 32 | tr '+/' '-_' | tr -d '='  | head -c 43)
info "Encryption key generated"

# Grafana admin password (auto-generated so monitoring works with no manual step)
GRAFANA_ADMIN_PASSWORD=$(openssl rand -hex 16 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(16))")

# Shared secret between the backend and the MCP tool servers. Without it every MCP
# tool call (all scans / AI tools) is rejected with 401.
MCP_AUTH_TOKEN=$(openssl rand -hex 32 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(32))")

# ═════════════════════════════════════════════════════════════════════
# PHASE 5 — .env Configuration
# ═════════════════════════════════════════════════════════════════════
step "5/9 — Configuration File Generation"

# deploy/docker/.env is the file docker compose actually reads. Once a database exists it holds
# values that MUST stay stable: the Postgres password is baked into the data volume at first start,
# and ENCRYPTION_KEY protects stored secrets. Regenerating them on a re-run locked the backend out
# of its own database ("password authentication failed for user socis_admin"). So an existing file
# is KEPT and only missing keys are added. Use --regenerate-env for a brand-new database.
KEEP_EXISTING_ENV=false
[[ -f "${REPO_ROOT}/deploy/docker/.env" && "$REGENERATE_ENV" != true ]] && KEEP_EXISTING_ENV=true

if [[ "$KEEP_EXISTING_ENV" == true ]]; then
    ENV_FILE="${REPO_ROOT}/deploy/docker/.env"
    cp "$ENV_FILE" "${ENV_FILE}.backup.$(date +%s)" && chmod 600 "${ENV_FILE}".backup.* 2>/dev/null || true
    info "Existing deploy/docker/.env found — KEEPING it (database password, encryption key and URLs unchanged)"
    info "A backup was saved next to it. Pass --regenerate-env only for a brand-new database."
    # A key that exists but is BLANK counts as missing (a blank ADMIN_PASSWORD= left the admin password unreadable).
    _ensure_env_key() {
        grep -q "^$1=." "$ENV_FILE" && return 0
        if grep -q "^$1=\$" "$ENV_FILE"; then sed -i "s|^$1=\$|$1=$2|" "$ENV_FILE"; else echo "$1=$2" >> "$ENV_FILE"; fi
        info "Set missing/blank setting: $1"
    }
    _ensure_env_key MCP_AUTH_TOKEN "${MCP_AUTH_TOKEN}"
    _ensure_env_key GRAFANA_ADMIN_PASSWORD "${GRAFANA_ADMIN_PASSWORD}"
    _ensure_env_key MSF_PASSWORD "${MSF_PASSWORD:-msf_secure_default_2024}"
    _ensure_env_key ENCRYPTION_KEY "${ENCRYPTION_KEY}"
    _ensure_env_key ADMIN_PASSWORD "${ADMIN_PASSWORD}"
    # Show the REAL admin password in the final summary, not the installer's default.
    _kept_pw="$(grep -m1 '^ADMIN_PASSWORD=' "$ENV_FILE" | cut -d= -f2- | tr -d "'\"")"
    [[ -n "$_kept_pw" ]] && ADMIN_PASSWORD="$_kept_pw"
    success "Configuration kept: $ENV_FILE"
else
ENV_FILE="$REPO_ROOT/.env"
if [[ -f "$ENV_FILE" ]]; then
    warn "Existing .env found, creating backup"
    cp "$ENV_FILE" "${ENV_FILE}.backup.$(date +%s)"
fi

info "Generating .env configuration..."

cat > "$ENV_FILE" << EOF
# ═════════════════════════════════════════════════════════════════════
# SOCIS-AI-PT Configuration
# Generated: $(date)
# Mode: ${DEPLOYMENT_MODE}
# ═════════════════════════════════════════════════════════════════════

# ─── Application ──────────────────────────────────────────────────
APP_NAME=SOCIS-AI-PT
APP_VERSION=1.0.0
DEPLOYMENT_MODE=${DEPLOYMENT_MODE}
DEBUG=$([[ "$DEPLOYMENT_MODE" == "development" ]] && echo "true" || echo "false")

# ─── Domain & Security ────────────────────────────────────────────
DOMAIN=${DOMAIN}
SECRET_KEY=${SECRET_KEY}
JWT_SECRET_KEY=${JWT_SECRET}
JWT_ALGORITHM=HS256
ALLOWED_ORIGINS=["http://localhost:3000","http://localhost:8000","https://${DOMAIN}"]

# ─── Database (PostgreSQL) ────────────────────────────────────────
DATABASE_URL=postgresql+asyncpg://socis_admin:${DB_PASSWORD}@postgres:5432/socis_ai_pt
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=10
DB_PASSWORD=${DB_PASSWORD}

# ─── Redis ────────────────────────────────────────────────────────
REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0
REDIS_PASSWORD=${REDIS_PASSWORD}

# ─── MinIO / S3 Storage ──────────────────────────────────────────
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=socis-minio
MINIO_SECRET_KEY=${MINIO_SECRET}
MINIO_BUCKET=socis-reports
MINIO_SECURE=false

# ─── Ollama (EXTERNAL server) — bundled container removed ─────────
# Point at an external Ollama host to use it (default LLM), or leave blank and
# use an API provider (OPENAI_API_KEY / ANTHROPIC_API_KEY / ...).
OLLAMA_REMOTE_URL=${OLLAMA_REMOTE_URL:-}
OLLAMA_REMOTE_MODEL=socis-pentest
OLLAMA_TIMEOUT=600

# ─── MCP Servers ──────────────────────────────────────────────────
MCP_NMAP_ENABLED=true
MCP_NUCLEI_ENABLED=true
MCP_CVE_ENABLED=true
MCP_OSINT_ENABLED=true
MCP_METASPLOIT_ENABLED=true
MCP_WAF_DETECTION_ENABLED=$([[ "$STANDALONE" != true ]] && echo "true" || echo "false")

# ─── Metasploit RPC ───────────────────────────────────────────────────────
MSF_HOST=metasploit_rpc
MSF_PORT=55553
MSF_PASSWORD=${MSF_PASSWORD:-msf_secure_default_2024}
MSF_SSL=false

# ─── Admin User ─────────────────────────────────────────────
ADMIN_PASSWORD=${ADMIN_PASSWORD}

# ─── Report Generation ────────────────────────────────────────────
REPORT_BRAND_NAME=SOCIS-AI-PT
REPORT_BRAND_TAGLINE=AI-Powered Penetration Testing Platform
REPORT_BRAND_COLOR=#0ff0fc
REPORT_OUTPUT_DIR=./reports

# ─── Rate Limiting ────────────────────────────────────────────────
RATE_LIMIT_ENABLED=false
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW_SECONDS=60

# ─── Encryption ───────────────────────────────────────────────────
ENCRYPTION_KEY=${ENCRYPTION_KEY}

# ─── Monitoring (observability #9 — auto-configured) ──────────────
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}
GRAFANA_ANONYMOUS=false
PROM_RETENTION=15d

# ─── MCP shared secret (backend <-> tool servers) ─────────────────
MCP_AUTH_TOKEN=${MCP_AUTH_TOKEN}
EOF

# ─── Auto-sized resource limits (portable across hardware) ────────
# Detect this host's CPU/RAM and write proportional docker-compose limits so
# the stack self-sizes on any machine instead of using fixed numbers.
if [[ -f "${SCRIPT_DIR}/lib/autosize.sh" ]]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/lib/autosize.sh"
    {
        echo ""
        autosize_env_block
    } >> "$ENV_FILE"
    success "Resource limits auto-sized for this host ($(nproc 2>/dev/null || echo '?') cores)"
else
    warn "autosize.sh not found — using compose default resource limits"
fi

success "Configuration generated: $ENV_FILE"
fi   # KEEP_EXISTING_ENV

# ═════════════════════════════════════════════════════════════════════
# PHASE 6 — Start Docker Services
# ═════════════════════════════════════════════════════════════════════
step "6/9 — Starting Docker Services"

COMPOSE_DIR="${REPO_ROOT}/deploy/docker"
COMPOSE_FILE="${COMPOSE_DIR}/docker-compose.dev.yml"
[[ ! -f "$COMPOSE_FILE" ]] && fail "Docker Compose file not found: ${COMPOSE_FILE}"
COMPOSE_ARGS=( -f "$COMPOSE_FILE" )
COMPOSE_FILE_ARGS="-f docker-compose.dev.yml"
# Monitoring (Prometheus + Grafana + exporters) is built into the dev compose
# file and starts automatically — nothing extra to add.


# Run Ollama on a separate host and set OLLAMA_REMOTE_URL, or use an API provider.
:

# Sync .env into the compose directory — docker compose reads it from CWD
if [[ "$ENV_FILE" -ef "${COMPOSE_DIR}/.env" ]]; then
    info "Environment already in place: ${COMPOSE_DIR}/.env"
else
    if [[ -f "${COMPOSE_DIR}/.env" ]]; then
        cp "${COMPOSE_DIR}/.env" "${COMPOSE_DIR}/.env.backup.$(date +%s)"
        warn "Previous deploy/docker/.env backed up (.env.backup.*)"
    fi
    cp "$ENV_FILE" "${COMPOSE_DIR}/.env"
    info "Environment synced to: ${COMPOSE_DIR}/.env"
fi
chmod 600 "${COMPOSE_DIR}/.env" 2>/dev/null || true

# Stop any leftover containers from a previous run
info "Removing any previous containers..."
(cd "$COMPOSE_DIR" && "$DOCKER_BIN" compose "${COMPOSE_ARGS[@]}" down --remove-orphans 2>/dev/null || true)

# Build images and start all services (platform + MCP servers)
info "Building Docker images and starting all containers..."
info "This may take 15-25 minutes on first run — do not interrupt"
echo ""

if ! (cd "$COMPOSE_DIR" && "$DOCKER_BIN" compose "${COMPOSE_ARGS[@]}" up -d --build 2>&1 | tee -a "$LOGFILE"); then
    echo ""
    fail "Docker Compose failed. Review the log: ${LOGFILE}"
fi

echo ""
success "All containers started (platform + MCP servers + monitoring)"

# ═════════════════════════════════════════════════════════════════════
# PHASE 7 — Wait for Services to be Healthy
# ═════════════════════════════════════════════════════════════════════
step "7/9 — Waiting for Services to be Healthy"

# Poll an HTTP endpoint until it responds or timeout expires
wait_http() {
    local label="$1"
    local url="$2"
    local max_secs="${3:-180}"
    local interval=5
    local elapsed=0
    while [[ $elapsed -lt $max_secs ]]; do
        if curl -sf "$url" -o /dev/null 2>/dev/null; then
            echo ""
            success "${label} is ready"
            return 0
        fi
        printf "\r  %-22s waiting... %3ds / %ds" "$label" "$elapsed" "$max_secs"
        sleep $interval
        elapsed=$((elapsed + interval))
    done
    echo ""
    warn "${label} did not respond within ${max_secs}s — it may still be initialising"
    return 1
}

wait_http "Backend API"  "http://localhost:8000/health" 240 || true
wait_http "Frontend"     "http://localhost:3000"               180 || true

# Print live container status
echo ""
info "Container status:"
(cd "$COMPOSE_DIR" && "$DOCKER_BIN" compose "${COMPOSE_ARGS[@]}" ps) 2>/dev/null | tee -a "$LOGFILE" || true

# ═════════════════════════════════════════════════════════════════════
# PHASE 8 — Ollama Model Setup
# ═════════════════════════════════════════════════════════════════════
# The bundled Ollama container was removed. Build custom socis-* models only if
# an EXTERNAL Ollama server is configured (OLLAMA_REMOTE_URL); otherwise skip and
# rely on an API provider.
if [[ -n "${OLLAMA_REMOTE_URL:-}" ]]; then
    step "8/9 — Ollama Model Setup (external)"
    info "Building custom models on external Ollama: ${OLLAMA_REMOTE_URL}"
    OLLAMA_HOST="${OLLAMA_REMOTE_URL}" \
    MODELFILE_DIR="${REPO_ROOT}/backend/modelfiles" \
    bash "${SCRIPT_DIR}/setup-models.sh" || warn "Model setup finished with warnings — check log"
else
    step "8/9 — Ollama Model Setup (skipped)"
    if [[ -z "${OLLAMA_REMOTE_URL:-}" ]]; then
        info "No external Ollama (OLLAMA_REMOTE_URL) set — skipping model build."
        info "Set OLLAMA_REMOTE_URL and run: bash deploy/scripts/setup-models.sh"
    else
        info "Skip flag set — models not built."
    fi
fi

# ═════════════════════════════════════════════════════════════════════
# PHASE 9 — Deployment Complete
# ═════════════════════════════════════════════════════════════════════
step "9/9 — Deployment Complete"

# Final health probe
BACKEND_STATUS="${RED}not responding${RESET}"
FRONTEND_STATUS="${RED}not responding${RESET}"
curl -sf "http://localhost:8000/health" -o /dev/null 2>/dev/null && \
    BACKEND_STATUS="${GREEN}running${RESET}"
curl -sf "http://localhost:3000" -o /dev/null 2>/dev/null && \
    FRONTEND_STATUS="${GREEN}running${RESET}"

echo ""
echo -e "${BOLD}${GREEN}✓ INSTALLATION COMPLETE — SOCIS-AI-PT IS RUNNING${RESET}"
echo ""
echo -e "  ${CYAN}Mode:${RESET}           ${DEPLOYMENT_MODE^^}"
echo -e "  ${CYAN}Repository:${RESET}     ${REPO_ROOT}"
echo -e "  ${CYAN}Config (.env):${RESET}  ${ENV_FILE}"
echo -e "  ${CYAN}Compose dir:${RESET}    ${COMPOSE_DIR}"
echo -e "  ${CYAN}Install log:${RESET}    ${LOGFILE}"
echo ""
echo -e "${BOLD}${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}${YELLOW}🔐 ADMIN CREDENTIALS — SAVE THESE IMMEDIATELY!${RESET}"
echo -e "${BOLD}${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${CYAN}Username:${RESET}    admin"
    echo -e "  ${CYAN}Password:${RESET}  ${ADMIN_PASSWORD}"
echo -e "${YELLOW}  ⚠️  IMPORTANT: Change password after first login!${RESET}"
echo -e "${BOLD}${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""
echo -e "${BOLD}SERVICE STATUS:${RESET}"
echo -e "  Backend API  → http://localhost:8000   [${BACKEND_STATUS}]"
echo -e "  Frontend     → http://localhost:3000   [${FRONTEND_STATUS}]"
if [[ -n "${OLLAMA_REMOTE_URL:-}" ]]; then
    echo -e "  Ollama (ext) → ${OLLAMA_REMOTE_URL}"
else
    echo -e "  LLM          → API provider (set OLLAMA_REMOTE_URL for external Ollama)"
fi
echo -e "  Postgres     → localhost:5432          [internal]"
echo -e "  Redis        → localhost:6379          [internal]"
echo -e "  MinIO UI     → http://localhost:9001"
echo ""
echo -e "${BOLD}MCP SERVERS:${RESET}"
echo -e "  CVE/NVD MCP       → http://localhost:8100"
echo -e "  NMAP MCP          → http://localhost:8101"
echo -e "  Nuclei MCP        → http://localhost:8102"
echo -e "  OSINT MCP         → http://localhost:8103"
echo -e "  Metasploit MCP    → http://localhost:8104"
echo -e "  Burp Suite MCP    → http://localhost:8105"
echo -e "  OWASP ZAP MCP     → http://localhost:8106"
echo -e "  WAF Detection MCP → http://localhost:8107"
echo -e "  Metasploit RPC    → localhost:55553        [RPC daemon]"
echo ""
echo -e "${BOLD}MANAGE SERVICES:${RESET}"
echo -e "  Start:    cd ${COMPOSE_DIR} && ${DOCKER_BIN} compose ${COMPOSE_FILE_ARGS} up -d"
echo -e "  Stop:     cd ${COMPOSE_DIR} && ${DOCKER_BIN} compose ${COMPOSE_FILE_ARGS} down"
echo -e "  Rebuild:  cd ${COMPOSE_DIR} && ${DOCKER_BIN} compose ${COMPOSE_FILE_ARGS} up -d --build"
echo -e "  Logs:     cd ${COMPOSE_DIR} && ${DOCKER_BIN} compose ${COMPOSE_FILE_ARGS} logs -f"
echo -e "  Status:   cd ${COMPOSE_DIR} && ${DOCKER_BIN} compose ${COMPOSE_FILE_ARGS} ps"
echo ""
echo -e "${DIM}Full install log: ${LOGFILE}${RESET}"
echo ""
success "SOCIS-AI-PT is ready!"
echo ""
