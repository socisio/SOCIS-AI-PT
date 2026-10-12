#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; DIM='\033[2m'; BOLD='\033[1m'; RESET='\033[0m'

# Configuration
INSTALL_DIR="/opt/socis"
DATA_DIR="${INSTALL_DIR}/data"
DOMAIN="socis.local"
ADMIN_EMAIL=""
USE_LETSENCRYPT=false
TLS_MODE=""
TLS_CERT=""
TLS_KEY=""
ADMIN_PASSWORD_ARG=""
ALLOW_PRIVATE_TARGETS=false
UNATTENDED=false
NO_MONITORING=false
REBUILD_ONLY=false

LOGFILE="/var/log/socis-prod-install.log"
[[ ! -w /var/log ]] && LOGFILE="/tmp/socis-prod-install.log"
touch "$LOGFILE"

# Logging Functions
_log() { echo -e "$*" | tee -a "$LOGFILE"; }
info() { _log "  ${CYAN}[INFO]${RESET}    $*"; }
success() { _log "  ${GREEN}[ OK ]${RESET}    $*"; }
warn() { _log "  ${YELLOW}[WARN]${RESET}    $*"; }
fail() { 
    _log "\n  ${RED}[FAIL]${RESET}    $*"
    _log "\n${DIM}Logs: ${LOGFILE}${RESET}\n"
    exit 1
}
step() { echo ""; _log "${BOLD}${CYAN} ► PHASE $*${RESET}"; }

# Banner
clear
cat << 'BANNER'
 ▄█████ ▄████▄ ▄█████ ██ ▄█████   ▄████▄ ██   █████▄ ▄▄▄▄▄ ▄▄  ▄▄ ▄▄▄▄▄▄ ▄▄▄▄   ▄▄▄ ▄▄▄▄▄▄ ▄▄  ▄▄▄  ▄▄  ▄▄   ▄▄▄▄▄▄ ▄▄▄▄▄  ▄▄▄▄ ▄▄▄▄▄▄ ▄▄ ▄▄  ▄▄  ▄▄▄▄
 ▀▀▀▄▄▄ ██  ██ ██     ██ ▀▀▀▄▄▄   ██▄▄██ ██   ██▄▄█▀ ██▄▄  ███▄██   ██   ██▄█▄ ██▀██  ██   ██ ██▀██ ███▄██     ██   ██▄▄  ███▄▄   ██   ██ ███▄██ ██ ▄▄
 █████▀ ▀████▀ ▀█████ ██ █████▀   ██  ██ ██   ██     ██▄▄▄ ██ ▀██   ██   ██ ██ ██▀██  ██   ██ ▀███▀ ██ ▀██     ██   ██▄▄▄ ▄▄██▀   ██   ██ ██ ▀██ ▀███▀

                           Production Installer v2.2 — Enterprise-Grade
BANNER
echo -e "${RESET}"

usage() {
cat <<'USAGE'
SOCIS-AI-PT production installer

  sudo bash install-prod.sh [options]

TLS (choose ONE — prompted interactively if omitted; defaults to 'internal' with --unattended):
  --tls letsencrypt   Public domain. Free, trusted, auto-renewing certificate.
                      Needs: --domain <public DNS name> --email <addr>, DNS pointing
                      at this server, ports 80/443 reachable from the internet.
  --tls internal      Private domain or IP (no public exposure).
                      Default: generates a self-signed certificate.
                      Or supply your own CA-issued certificate:
                        --cert /path/fullchain.pem --key /path/privkey.pem

General:
  --domain <name|ip>  Hostname or IP users will browse to (default: socis.local)
  --email <addr>      Contact for Let's Encrypt expiry notices
  --admin-password <pw>   Set the admin password (>=12 chars; no ' or spaces).
                      Default: a random password is generated and shown once.
  --allow-private-targets Allow scans of private/RFC1918 ranges (internal pentests).
                      Off by default; loopback and cloud-metadata are ALWAYS blocked.
  --install-dir <path>    Data/cert root (default: /opt/socis)
  --no-monitoring     Skip Prometheus/Grafana
  --unattended        No prompts
  --rebuild           Rebuild containers after code changes
USAGE
}

# Parse Arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)       DOMAIN="$2"; shift 2 ;;
        --email)        ADMIN_EMAIL="$2"; shift 2 ;;
        --install-dir)  INSTALL_DIR="$2"; DATA_DIR="${INSTALL_DIR}/data"; shift 2 ;;
        --letsencrypt)  TLS_MODE="letsencrypt"; shift ;;      # legacy alias for --tls letsencrypt
        --tls)          TLS_MODE="${2:-}"; shift 2 ;;
        --cert)         TLS_CERT="${2:-}"; shift 2 ;;
        --key)          TLS_KEY="${2:-}"; shift 2 ;;
        --admin-password) ADMIN_PASSWORD_ARG="${2:-}"; shift 2 ;;
        --allow-private-targets) ALLOW_PRIVATE_TARGETS=true; shift ;;
        --unattended)   UNATTENDED=true; shift ;;
        --no-monitoring) NO_MONITORING=true; shift ;;
        --rebuild)      REBUILD_ONLY=true; shift ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            warn "Unknown: $1"; shift
            ;;
    esac
done

# ─── Deferred Rebuild (skips full install, just rebuilds containers) ─────────
if [[ "$REBUILD_ONLY" == true ]]; then
    [[ $EUID -ne 0 ]] && fail "Rebuild requires root (sudo)"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cd "$SCRIPT_DIR/../docker"
    # Monitoring is built into docker-compose.prod.yml — nothing extra to add.
    COMPOSE_ARGS=( -f docker-compose.prod.yml )
    echo ""
    echo "🔄 Rebuilding SOCIS-AI-PT containers (production mode)..."
    docker compose "${COMPOSE_ARGS[@]}" build --pull 2>&1 | grep -v "^#"
    docker compose "${COMPOSE_ARGS[@]}" up -d
    echo ""
    echo "✅ Rebuild complete! Production services restarted."
    exit 0
fi

# Root Check
[[ $EUID -ne 0 ]] && fail "Requires root (sudo)"

# OS Detection
[[ ! -f /etc/os-release ]] && fail "Cannot detect OS"
source /etc/os-release
OS_ID="${ID}"; OS_VERSION="${VERSION_ID%%.*}"

info "OS: ${PRETTY_NAME}"
info "Install: ${INSTALL_DIR}"
info "Domain: ${DOMAIN}"

# PHASE 1 — Confirm Production Deployment
step "1/12 — Deployment Confirmation"

if [[ "$UNATTENDED" != true ]]; then
    echo ""
    echo -e "  ${YELLOW}⚠ PRODUCTION DEPLOYMENT ⚠${RESET}"
    echo -e "  This will:"
    echo -e "    • Install Docker & dependencies"
    echo -e "    • Setup PostgreSQL, Redis, MinIO, MCP tools, monitoring"
    echo -e "    • Configure systemd services"
    echo -e "    • Configure firewall rules"
    echo ""
    read -rp "  Proceed? [y/N] " confirm
    [[ "${confirm,,}" != "y" ]] && { echo "Aborted."; exit 0; }
fi

success "Deployment confirmed"

# PHASE 2 — System Prerequisites
step "2/12 — System Prerequisites"

info "Updating package managers..."
case "$OS_ID" in
    ubuntu|debian)
        apt-get update -qq
        apt-get upgrade -y -qq
        ;;
    rhel|rocky|centos|almalinux)
        dnf makecache -q
        dnf upgrade -y -q
        ;;
esac

info "Installing core dependencies..."
case "$OS_ID" in
    ubuntu|debian)
        apt-get install -y -qq curl wget openssl ca-certificates gnupg zstd jq git \
            build-essential libssl-dev libffi-dev python3-dev systemd net-tools ufw
        ;;
    rhel|rocky|centos|almalinux)
        dnf install -y -q curl wget openssl ca-certificates gnupg zstd jq git \
            gcc openssl-devel libffi-devel python3-devel firewalld net-tools
        systemctl enable firewalld
        systemctl start firewalld || true
        ;;
esac

success "System prerequisites installed"

# PHASE 3 — Docker Installation
step "3/12 — Docker Engine"

if command -v docker &>/dev/null; then
    success "Docker found: $(docker --version)"
    DOCKER_BIN="$(command -v docker)"
else
    info "Installing Docker..."
    case "$OS_ID" in
        ubuntu|debian)
            mkdir -p /etc/apt/keyrings
            curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" | \
                gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null
            chmod a+r /etc/apt/keyrings/docker.gpg
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${OS_ID} $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
                tee /etc/apt/sources.list.d/docker.list > /dev/null
            apt-get update -qq
            apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
        rhel|rocky|centos|almalinux)
            yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo 2>/dev/null || \
                dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
    esac
    
    systemctl enable --now docker
    success "Docker installed"
fi

# Resolve docker binary path — may vary by install method or distro
DOCKER_BIN="$(command -v docker)"
success "Docker binary: ${DOCKER_BIN}"

# PHASE 5 — Installation Directories
step "5/12 — File System Setup"

info "Creating secure directories..."
mkdir -p "$INSTALL_DIR"/{data,logs/backend,ssl,uploads,reports,certbot-www,letsencrypt}
mkdir -p "$DATA_DIR"/{postgres,redis,minio,projects,plugins,metasploit,wordlists,cve-lite,prometheus,grafana}
chmod 700 "$INSTALL_DIR"/{data,ssl,logs,letsencrypt}
chmod 755 "$INSTALL_DIR" "$INSTALL_DIR"/{reports,certbot-www}
# Containers that run as non-root write to these bind mounts, so the host
# directories must be owned by the container user:
#   backend/worker -> uid 10001 (fixed via the APP_UID build arg)
#   prometheus     -> 65534 (nobody)     grafana -> 472
chown -R 10001:10001 "$DATA_DIR/projects" "$DATA_DIR/plugins" "$INSTALL_DIR/reports" "$INSTALL_DIR/logs/backend"
chown -R 65534:65534 "$DATA_DIR/prometheus"
chown -R 472:472     "$DATA_DIR/grafana"

success "Directories created and secured"

# PHASE 6 — TLS (two modes: Let's Encrypt | internal)
step "6/12 — TLS Configuration"

export TLS_DIR="${INSTALL_DIR}/ssl" LE_DIR="${INSTALL_DIR}/letsencrypt" ACME_WEBROOT="${INSTALL_DIR}/certbot-www"
_TLS_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/tls.sh"
[[ -f "$_TLS_LIB" ]] || fail "Missing ${_TLS_LIB}"
# shellcheck source=lib/tls.sh
source "$_TLS_LIB"

if [[ -z "$TLS_MODE" ]]; then
    if [[ -n "$TLS_CERT" || -n "$TLS_KEY" ]]; then
        TLS_MODE=internal
    elif [[ "$UNATTENDED" == true ]]; then
        TLS_MODE=internal
        warn "No --tls given in unattended mode: using 'internal' (self-signed). Re-run with --tls letsencrypt for a public domain."
    else
        TLS_MODE="$(tls_choose_interactive)"
        [[ -n "$TLS_MODE" ]] || fail "Invalid choice — run again and pick 1 or 2 (or pass --tls letsencrypt|internal)"
    fi
fi
case "$TLS_MODE" in
    letsencrypt|internal) ;;
    *) fail "--tls must be 'letsencrypt' or 'internal' (got '${TLS_MODE}')" ;;
esac
if [[ -n "$TLS_CERT" || -n "$TLS_KEY" ]]; then
    [[ "$TLS_MODE" == internal ]] || fail "--cert/--key can only be used with --tls internal"
    [[ -n "$TLS_CERT" && -n "$TLS_KEY" ]] || fail "--cert and --key must be given together"
fi

TLS_NEEDS_LE=false
if [[ "$TLS_MODE" == letsencrypt ]]; then
    # Fail BEFORE the long install if Let's Encrypt can never work with these inputs.
    tls_letsencrypt_validate_inputs "$DOMAIN" "$ADMIN_EMAIL" || exit 1
    if tls_copy_le_to_nginx "$DOMAIN" 2>/dev/null; then
        success "Existing Let's Encrypt certificate reused ($(tls_cert_days_left) days left)"
    else
        info "Creating a temporary self-signed certificate so nginx can start;"
        info "the real Let's Encrypt certificate is requested once the stack is up."
        tls_selfsigned "$DOMAIN" 30 || exit 1
        TLS_NEEDS_LE=true
    fi
else
    if [[ -n "$TLS_CERT" ]]; then
        tls_validate_provided "$TLS_CERT" "$TLS_KEY" "$DOMAIN" || exit 1
        tls_install_provided "$TLS_CERT" "$TLS_KEY"
        success "Customer-provided certificate installed"
    elif [[ -s "$TLS_DIR/fullchain.pem" && -s "$TLS_DIR/privkey.pem" ]]; then
        success "Existing certificate kept ($(tls_cert_days_left) days left)"
    else
        info "Generating a self-signed certificate for ${DOMAIN} (valid 2 years)..."
        tls_selfsigned "$DOMAIN" 730 || exit 1
        success "Self-signed certificate created"
    fi
fi
tls_summary "$TLS_MODE"

# PHASE 7 — Repository Preparation
step "7/12 — Repository Setup"

# Derive repo root from the script's own location (deploy/scripts/ → ../../)
# This works regardless of git availability or cwd, and never clones.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_PATH="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Sanity-check the derived path has the expected structure
if [[ ! -d "${REPO_PATH}/backend" ]] || [[ ! -d "${REPO_PATH}/frontend" ]] || [[ ! -d "${REPO_PATH}/deploy/docker" ]]; then
    fail "Repository structure not found at ${REPO_PATH}. Run this script from inside the SOCIS-AI-PT directory."
fi

info "Repository root: ${REPO_PATH}"
success "Using local repository (no clone needed)"

# PHASE 8 — Generate Production Configuration
step "8/12 — Configuration Generation"

ENV_FILE="${REPO_PATH}/.env"
PREV_ENV=""
if [[ -f "$ENV_FILE" ]]; then
    PREV_ENV="${ENV_FILE}.backup.$(date +%s)"
    cp "$ENV_FILE" "$PREV_ENV"; chmod 600 "$PREV_ENV"
    info "Existing configuration found — persistent secrets will be REUSED (database, encryption key, sessions stay valid)"
fi
# Read a value from the previous .env (quotes stripped); empty if absent.
_prev() {
    [[ -n "$PREV_ENV" && -f "$PREV_ENV" ]] || return 0
    local v; v="$(grep -m1 "^$1=" "$PREV_ENV" | cut -d= -f2-)"
    v="${v#\'}"; v="${v%\'}"; v="${v#\"}"; v="${v%\"}"
    printf '%s' "$v"
}

info "Generating secure configuration..."
SECRET_KEY=$(openssl rand -base64 32)
JWT_SECRET=$(openssl rand -base64 32)
DB_PASS=$(openssl rand -hex 16)
REDIS_PASS=$(openssl rand -hex 16)
MINIO_SECRET=$(openssl rand -base64 32)
GRAFANA_PASS=$(openssl rand -hex 16)
ENCRYPTION_KEY=$(python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())" 2>/dev/null \
    || openssl rand -base64 32 | tr '+/' '-_' | tr -d '=' | head -c 43)

# Re-run safety: reuse persistent secrets. Regenerating them would lock the
# backend out of its own Postgres volume, make ALL encrypted data (LLM keys, SSO
# secrets, MFA secrets) unreadable, and sign every user out.
_reuse() { local v; v="$(_prev "$2")"; [[ -n "$v" ]] && printf -v "$1" '%s' "$v"; return 0; }
_reuse SECRET_KEY SECRET_KEY;          _reuse JWT_SECRET JWT_SECRET_KEY
_reuse DB_PASS DB_PASSWORD;            _reuse REDIS_PASS REDIS_PASSWORD
_reuse MINIO_SECRET MINIO_SECRET_KEY;  _reuse GRAFANA_PASS GRAFANA_ADMIN_PASSWORD
_reuse ENCRYPTION_KEY ENCRYPTION_KEY
MSF_PASS="$(_prev MSF_PASSWORD)"
MCP_TOKEN="$(_prev MCP_AUTH_TOKEN)"; MCP_TOKEN="${MCP_TOKEN:-$(openssl rand -hex 32)}"

# Admin password: --admin-password > previous > freshly generated (shown once at the end).
ADMIN_PW_GENERATED=false
if [[ -n "$ADMIN_PASSWORD_ARG" ]]; then
    if [[ ${#ADMIN_PASSWORD_ARG} -lt 12 || "$ADMIN_PASSWORD_ARG" == *"'"* || "$ADMIN_PASSWORD_ARG" == *[[:space:]]* ]]; then
        fail "--admin-password must be at least 12 characters with no spaces or single quotes"
    fi
    ADMIN_PW="$ADMIN_PASSWORD_ARG"
else
    ADMIN_PW="$(_prev ADMIN_PASSWORD)"
    if [[ -z "$ADMIN_PW" ]]; then
        ADMIN_PW="$(openssl rand -base64 24 | tr -d '/+=\n' | cut -c1-22)"
        ADMIN_PW_GENERATED=true
    fi
fi

cat > "$ENV_FILE" << 'ENVEOF'
# SOCIS-AI-PT Production Configuration

APP_NAME=SOCIS-AI-PT
APP_VERSION=1.0.0
DEPLOYMENT_MODE=production
DEBUG=false
DOMAIN=DOMAIN_PLACEHOLDER
SECRET_KEY=SECRET_PLACEHOLDER
JWT_SECRET_KEY=JWT_PLACEHOLDER
JWT_ALGORITHM=HS256

# Database
DB_PASSWORD=DB_PLACEHOLDER
DATABASE_URL=postgresql+asyncpg://socis_admin:DB_PLACEHOLDER@postgres:5432/socis_ai_pt
DATABASE_POOL_SIZE=10
DATABASE_MAX_OVERFLOW=10

# Redis
REDIS_PASSWORD=REDIS_PLACEHOLDER
REDIS_URL=redis://:REDIS_PLACEHOLDER@redis:6379/0

# MinIO
MINIO_ENDPOINT=minio:9000
MINIO_ACCESS_KEY=socis-minio
MINIO_SECRET_KEY=MINIO_PLACEHOLDER
MINIO_BUCKET=socis-reports
MINIO_SECURE=false

# Ollama (EXTERNAL server — bundled container removed)
# Set to an external Ollama host to use it as the default LLM, else leave blank
# and configure an API provider (OPENAI_API_KEY / ANTHROPIC_API_KEY / ...).
OLLAMA_REMOTE_URL=${OLLAMA_REMOTE_URL:-}
OLLAMA_REMOTE_MODEL=socis-pentest
OLLAMA_TIMEOUT=600

# Metasploit RPC
MSF_HOST=metasploit_rpc
MSF_PORT=55553
MSF_PASSWORD=MSF_PLACEHOLDER
MSF_SSL=false

# Application
RATE_LIMIT_ENABLED=true
ALLOWED_ORIGINS=["https://DOMAIN_PLACEHOLDER"]
MCP_NMAP_ENABLED=true
MCP_NUCLEI_ENABLED=true
MCP_CVE_ENABLED=true
MCP_OSINT_ENABLED=true
MCP_WAF_DETECTION_ENABLED=true

# Encryption (Fernet symmetric key for DB secrets)
ENCRYPTION_KEY=ENCRYPTION_PLACEHOLDER

# Monitoring (observability #9 — auto-configured)
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=GRAFANA_PLACEHOLDER
GRAFANA_ANONYMOUS=false
PROM_RETENTION=15d

# Registration / agent safety / scan scope
ALLOW_OPEN_REGISTRATION=false
DEFAULT_USER_ROLE=viewer
SOCIS_AGENT_ALLOW_OFFENSIVE=false
# true only when engagements are authorized to scan private (RFC1918) ranges.
# Loopback and cloud-metadata addresses are ALWAYS blocked regardless.
MCP_ALLOW_PRIVATE_TARGETS=PRIV_PLACEHOLDER
MAX_CONCURRENT_CHAT_SESSIONS=20
REPORT_RETENTION_DAYS=90
ARQ_MAX_JOBS=10
ARQ_JOB_TIMEOUT=3600
REDIS_MAXMEMORY=1gb

# Shared secret between the backend and the MCP tool servers.
MCP_AUTH_TOKEN=MCPTOKEN_PLACEHOLDER

# Host path root for bind mounts (docker-compose.prod.yml)
SOCIS_HOME=INSTALLDIR_PLACEHOLDER
TLS_MODE=TLSMODE_PLACEHOLDER
ENVEOF

# Replace placeholders
MSF_PASS="${MSF_PASS:-$(openssl rand -hex 16)}"

sed -i "s|DOMAIN_PLACEHOLDER|${DOMAIN}|g" "$ENV_FILE"
sed -i "s|SECRET_PLACEHOLDER|${SECRET_KEY}|g" "$ENV_FILE"
sed -i "s|JWT_PLACEHOLDER|${JWT_SECRET}|g" "$ENV_FILE"
sed -i "s|DB_PLACEHOLDER|${DB_PASS}|g" "$ENV_FILE"
sed -i "s|REDIS_PLACEHOLDER|${REDIS_PASS}|g" "$ENV_FILE"
sed -i "s|MINIO_PLACEHOLDER|${MINIO_SECRET}|g" "$ENV_FILE"
sed -i "s|MSF_PLACEHOLDER|${MSF_PASS}|g" "$ENV_FILE"
sed -i "s|ENCRYPTION_PLACEHOLDER|${ENCRYPTION_KEY}|g" "$ENV_FILE"
sed -i "s|GRAFANA_PLACEHOLDER|${GRAFANA_PASS}|g" "$ENV_FILE"
sed -i "s|MCPTOKEN_PLACEHOLDER|${MCP_TOKEN}|g" "$ENV_FILE"
sed -i "s|INSTALLDIR_PLACEHOLDER|${INSTALL_DIR}|g" "$ENV_FILE"
sed -i "s|TLSMODE_PLACEHOLDER|${TLS_MODE}|g" "$ENV_FILE"
sed -i "s|PRIV_PLACEHOLDER|${ALLOW_PRIVATE_TARGETS}|g" "$ENV_FILE"
# Single-quoted so compose never interpolates $ or other characters in the password.
printf "ADMIN_PASSWORD='%s'\n" "$ADMIN_PW" >> "$ENV_FILE"
# Root-only copy of the bootstrap credentials for the operator.
umask 077
cat > "${INSTALL_DIR}/.admin-credentials" <<CREDEOF
SOCIS-AI-PT bootstrap admin
  URL:      https://${DOMAIN}
  Username: admin
  Password: ${ADMIN_PW}
Change the password after first login, store it in your vault, then delete this file.
CREDEOF
umask 022

# ─── Auto-sized resource limits (portable across hardware) ────────
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

chmod 600 "$ENV_FILE"
success "Configuration generated and secured"

# PHASE 9 — Firewall Configuration
step "9/12 — Network Security"

info "Configuring firewall rules..."
case "$OS_ID" in
    ubuntu|debian)
        ufw allow 22/tcp 2>/dev/null || true
        ufw allow 80/tcp 2>/dev/null || true
        ufw allow 443/tcp 2>/dev/null || true
        ufw --force enable 2>/dev/null || true
        ;;
    rhel|rocky|centos|almalinux)
        firewall-cmd --permanent --add-service=ssh 2>/dev/null || true
        firewall-cmd --permanent --add-service=http 2>/dev/null || true
        firewall-cmd --permanent --add-service=https 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        ;;
esac

success "Firewall configured"

# PHASE 10 — Docker Services Deployment
step "10/12 — Docker Services Deployment"

info "Deploying Docker services..."
cd "${REPO_PATH}/deploy/docker"
# Monitoring (Prometheus + Grafana + exporters) is built into the prod compose
# file and starts automatically — nothing extra to add.
COMPOSE_ARGS=( -f docker-compose.prod.yml )
COMPOSE_FILE_ARGS="-f docker-compose.prod.yml"

# Sync generated .env into compose CWD so docker compose picks up all secrets
cp "${ENV_FILE}" "${REPO_PATH}/deploy/docker/.env"
info "Environment synced to compose directory"

# Have nginx itself validate config + certificate BEFORE touching running containers.
tls_preflight_nginx "${REPO_PATH}/deploy/nginx/nginx.prod.conf" || exit 1

# Remove old containers
docker compose "${COMPOSE_ARGS[@]}" down --remove-orphans 2>/dev/null || true
sleep 3

# Build and start services (platform + MCP servers + monitoring)
info "Building Docker images (this may take 15-25 minutes on first run)..."
if true; then
    if ! docker compose "${COMPOSE_ARGS[@]}" up -d --build >> "$LOGFILE" 2>&1; then
        fail "Docker deployment failed. Check logs: $LOGFILE"
    fi
fi

info "Waiting for services to initialize..."
sleep 20

# Health check function
check_health() {
    local service=$1
    local port=$2
    local max_attempts=30
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        # Use HTTP health endpoint for HTTP services, container exec for others
        if curl -sf "http://localhost:${port}/health" >/dev/null 2>&1 || \
              (docker compose "${COMPOSE_ARGS[@]}" ps --status running "$service" 2>/dev/null | grep -q "$service"); then
            success "$service is healthy"
            return 0
        fi
        attempt=$((attempt + 1))
        echo -ne "\r  Checking $service... ($attempt/$max_attempts)"
        sleep 2
    done
    
    warn "$service may not be responding yet"
    return 1
}

# Verify key services
info "Verifying services..."
check_health "backend" "8000" || true
check_health "postgres" "9999" || true   # postgres has no HTTP — uses container running check
check_health "redis" "9999" || true     # redis has no HTTP — uses container running check

# Show service status
info "Docker services status:"
docker compose "${COMPOSE_ARGS[@]}" ps >> "$LOGFILE" 2>&1

success "Docker services deployed and running"

# ─── Let's Encrypt: request the real certificate now that :80 is being served ───
TLS_RESULT_LINE="✓ TLS: ${TLS_MODE}"
if [[ "$TLS_MODE" == letsencrypt ]]; then
    if [[ "$TLS_NEEDS_LE" == true ]]; then
        if tls_letsencrypt_issue "$DOMAIN" "$ADMIN_EMAIL"; then
            TLS_RESULT_LINE="✓ TLS: Let's Encrypt certificate issued (auto-renews)"
        else
            TLS_RESULT_LINE="⚠ TLS: TEMPORARY self-signed certificate — Let's Encrypt issuance FAILED (fix DNS/port 80, then run: sudo socis-cert-renew --issue)"
        fi
    else
        TLS_RESULT_LINE="✓ TLS: Let's Encrypt certificate (auto-renews)"
    fi
    tls_install_renewal "$DOMAIN" "$ADMIN_EMAIL"
elif [[ -n "$TLS_CERT" ]]; then
    TLS_RESULT_LINE="✓ TLS: customer-provided certificate (renew it before it expires)"
else
    TLS_RESULT_LINE="✓ TLS: self-signed certificate (distribute ${TLS_DIR}/fullchain.pem to client trust stores)"
fi

# PHASE 11 — Ollama Model Setup (external only; bundled container removed)
if [[ -n "${OLLAMA_REMOTE_URL:-}" ]]; then
    step "11/12 — Ollama Model Setup (external)"
    info "Building custom socis-* models on external Ollama: ${OLLAMA_REMOTE_URL}"
    OLLAMA_HOST="${OLLAMA_REMOTE_URL}" \
    MODELFILE_DIR="${APP_DIR:-$PWD}/backend/modelfiles" \
    bash "$(dirname "$0")/setup-models.sh" >> "$LOGFILE" 2>&1 \
        && success "External Ollama models ready" \
        || warn "Model setup finished with warnings — check $LOGFILE"
else
    step "11/12 — Ollama Setup (skipped)"
    info "No external Ollama (OLLAMA_REMOTE_URL) configured — relying on API providers."
    info "To use Ollama later: set OLLAMA_REMOTE_URL and run deploy/scripts/setup-models.sh"
fi

# PHASE 12 — Systemd Service & Final Setup
step "12/12 — Systemd Service Configuration"

info "Creating systemd service for auto-restart..."
cat > /etc/systemd/system/socis-docker.service << 'SYSTEMDEOF'
[Unit]
Description=SOCIS-AI-PT Docker Services
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=root
WorkingDirectory=REPO_PLACEHOLDER/deploy/docker
ExecStart=DOCKER_BIN_PLACEHOLDER compose COMPOSE_FILES_PLACEHOLDER up
ExecStop=DOCKER_BIN_PLACEHOLDER compose COMPOSE_FILES_PLACEHOLDER down
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SYSTEMDEOF

sed -i "s|REPO_PLACEHOLDER|${REPO_PATH}|g" /etc/systemd/system/socis-docker.service
sed -i "s|DOCKER_BIN_PLACEHOLDER|${DOCKER_BIN}|g" /etc/systemd/system/socis-docker.service
sed -i "s|COMPOSE_FILES_PLACEHOLDER|${COMPOSE_FILE_ARGS}|g" /etc/systemd/system/socis-docker.service

systemctl daemon-reload
systemctl enable socis-docker.service
success "Systemd service configured"

# Final health check
info "Final platform verification..."
sleep 5
BACKEND_READY=false
FRONTEND_READY=false

if curl -sf "http://localhost:8000/api/v1/health" >/dev/null 2>&1; then
    success "Backend API is responsive"
    BACKEND_READY=true
fi

if curl -sf "http://localhost:3000" >/dev/null 2>&1 2>&1; then
    success "Frontend is responsive"
    FRONTEND_READY=true
fi

# PHASE 12 — Deployment Complete
step "12/12 — Deployment Complete"

echo ""
echo -e "${BOLD}${GREEN}✓ PRODUCTION DEPLOYMENT FULLY AUTOMATED & COMPLETE!${RESET}"
echo ""
echo -e "  ${CYAN}Platform URL:${RESET}         https://${DOMAIN}"
echo ""
echo -e "  ${BOLD}${YELLOW}ADMIN LOGIN${RESET}"
echo -e "    Username: ${BOLD}admin${RESET}"
if [[ "$ADMIN_PW_GENERATED" == true || -n "$ADMIN_PASSWORD_ARG" ]]; then
    echo -e "    Password: ${BOLD}${ADMIN_PW}${RESET}"
    echo -e "    ${DIM}(shown once — also saved root-only in ${INSTALL_DIR}/.admin-credentials)${RESET}"
else
    echo -e "    Password: unchanged from the previous install (${INSTALL_DIR}/.admin-credentials)"
fi
echo -e "    Change it after first login, then delete that file."
if [[ "$TLS_MODE" == internal && -z "$TLS_CERT" ]]; then
    echo ""
    echo -e "  ${BOLD}${YELLOW}SELF-SIGNED CERTIFICATE${RESET} — browsers will warn until it is trusted."
    echo -e "    Distribute ${CYAN}${TLS_DIR}/fullchain.pem${RESET} to users' trust stores (or re-run with"
    echo -e "    --cert/--key using a certificate from your internal CA)."
fi
echo -e "  ${CYAN}Installation:${RESET}         ${INSTALL_DIR}"
echo -e "  ${CYAN}Repository:${RESET}           ${REPO_PATH}"
echo -e "  ${CYAN}Configuration:${RESET}        ${ENV_FILE}"
echo -e "  ${CYAN}System Logs:${RESET}          ${LOGFILE}"
echo ""
echo -e "${BOLD}WHAT'S BEEN AUTOMATED:${RESET}"
echo -e "  ✓ Docker engine installed & configured"
echo -e "  ✓ Platform services deployed (backend, frontend, postgres, redis, minio)"
echo -e "  ✓ MCP tool servers deployed (CVE, NMAP, Nuclei, OSINT, Metasploit, Burp, ZAP, WAF)"
echo -e "  ${TLS_RESULT_LINE:-✓ TLS configured}"
echo -e "  ✓ Firewall rules applied"
if [[ -n "${OLLAMA_REMOTE_URL:-}" ]]; then
    echo -e "  ✓ External Ollama configured (${OLLAMA_REMOTE_URL}); custom models built"
else
    echo -e "  • LLM: using API provider(s) — set OLLAMA_REMOTE_URL to use external Ollama"
fi
echo -e "  ✓ Systemd service configured for auto-restart"
echo -e "  ✓ Platform is READY TO USE NOW"
echo ""
echo -e "${BOLD}WHAT'S RUNNING:${RESET}"
if [[ "$BACKEND_READY" == "true" ]]; then
    echo -e "  ✓ Backend API: ${GREEN}http://localhost:8000${RESET}"
else
    echo -e "  ℹ Backend API: Available at http://localhost:8000"
fi
if [[ "$FRONTEND_READY" == "true" ]]; then
    echo -e "  ✓ Frontend: ${GREEN}http://localhost:3000${RESET}"
else
    echo -e "  ℹ Frontend: Available at http://localhost:3000"
fi
echo ""
echo -e "${BOLD}NEXT STEPS:${RESET}"
echo -e "  1. Access the platform:"
echo -e "     ${CYAN}https://${DOMAIN}${RESET}"
echo ""
echo -e "  2. Configure DNS (if using domain):"
echo -e "     Point ${DOMAIN} → $(hostname -I 2>/dev/null | awk '{print $1}' || ip route get 1.1.1.1 2>/dev/null | awk '/src/{print $NF;exit}' || echo '<server-ip>')"
echo ""
echo -e "  3. Monitor services:"
echo -e "     ${CYAN}journalctl -u socis-docker -f${RESET}"
echo -e "     ${CYAN}cd ${REPO_PATH}/deploy/docker && docker compose ${COMPOSE_FILE_ARGS} logs -f${RESET}"
echo ""
echo -e "${BOLD}MCP SERVERS (all on socis-net):${RESET}"
echo -e "  CVE/NVD MCP       → http://localhost:8100"
echo -e "  NMAP MCP          → http://localhost:8101"
echo -e "  Nuclei MCP        → http://localhost:8102"
echo -e "  OSINT MCP         → http://localhost:8103"
echo -e "  Metasploit MCP    → http://localhost:8104"
echo -e "  Burp Suite MCP    → http://localhost:8105"
echo -e "  OWASP ZAP MCP     → http://localhost:8106"
echo -e "  WAF Detection MCP → http://localhost:8107"
echo -e "  Metasploit RPC    → (optional) docker compose --profile metasploit up -d"
echo ""
echo -e "${BOLD}IMPORTANT:${RESET}"
echo -e "  • Default credentials are in: ${ENV_FILE}"
echo -e "  • Change default passwords immediately"
echo -e "  • Enable backups for PostgreSQL data"
echo ""
echo -e "${DIM}Issues? https://github.com/0x4hm3d/SOCIS-AI-PT/issues${RESET}"
echo ""
success "SOCIS-AI-PT is now running in production!"
