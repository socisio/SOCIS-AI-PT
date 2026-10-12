#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ─── Colors & Logging ────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; DIM='\033[2m'; BOLD='\033[1m'; RESET='\033[0m'

# ─── Banner ──────────────────────────────────────────────────────────
clear
cat << 'BANNER'
 ▄█████ ▄████▄ ▄█████ ██ ▄█████   ▄████▄ ██   █████▄ ▄▄▄▄▄ ▄▄  ▄▄ ▄▄▄▄▄▄ ▄▄▄▄   ▄▄▄ ▄▄▄▄▄▄ ▄▄  ▄▄▄  ▄▄  ▄▄   ▄▄▄▄▄▄ ▄▄▄▄▄  ▄▄▄▄ ▄▄▄▄▄▄ ▄▄ ▄▄  ▄▄  ▄▄▄▄
 ▀▀▀▄▄▄ ██  ██ ██     ██ ▀▀▀▄▄▄   ██▄▄██ ██   ██▄▄█▀ ██▄▄  ███▄██   ██   ██▄█▄ ██▀██  ██   ██ ██▀██ ███▄██     ██   ██▄▄  ███▄▄   ██   ██ ███▄██ ██ ▄▄
 █████▀ ▀████▀ ▀█████ ██ █████▀   ██  ██ ██   ██     ██▄▄▄ ██ ▀██   ██   ██ ██ ██▀██  ██   ██ ▀███▀ ██ ▀██     ██   ██▄▄▄ ▄▄██▀   ██   ██ ██ ▀██ ▀███▀

                          SOCIS-AI-PT Installer v2.2 — Smart Deployment
BANNER
echo -e "${RESET}"

# ─── Logging ─────────────────────────────────────────────────────────
info()    { echo -e "  ${CYAN}[INFO]${RESET}    $*"; }
success() { echo -e "  ${GREEN}[ OK ]${RESET}    $*"; }
warn()    { echo -e "  ${YELLOW}[WARN]${RESET}    $*"; }
fail()    { echo -e "\n  ${RED}[FAIL]${RESET}    $*\n"; exit 1; }

# ─── Defaults ─────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOYMENT_MODE="interactive"
DOMAIN_ARG=""
EMAIL_ARG=""
INSTALL_DIR_ARG=""
LETSENCRYPT_ARG=""
TLS_ARG=""
CERT_ARG=""
KEY_ARG=""
ADMINPW_ARG=""
PRIVATE_ARG=""
SKIP_DOCKER_ARG=""
NO_MONITORING_ARG=""
UNATTENDED_ARG=""
REBUILD_ONLY=false

# ─── Parse Arguments ──────────────────────────────────────────────────
show_help() {
    cat << 'HELP'
Usage: sudo bash install.sh [OPTIONS]

Installation Modes:
  --dev                 Development mode (local setup, no Docker required)
  --prod                Production mode (enterprise deployment)
  --interactive         Interactive mode (default) - choose during setup

Options (Production):
  --domain <domain>     Platform domain (default: socis.local)
  --email <email>       Admin email for SSL certificates
  --install-dir <path>  Installation directory (default: /opt/socis)
  --tls <mode>          TLS mode: letsencrypt (public domain) | internal (private domain/IP)
  --letsencrypt         Alias for --tls letsencrypt
  --cert <file> --key <file>   Your own CA-issued certificate (with --tls internal)
  --admin-password <pw> Set the admin password (default: generated, shown once)
  --allow-private-targets  Permit scans of private/RFC1918 ranges
  --unattended          Skip all prompts

Options (Development):
  --skip-docker         Skip Docker installation

Common:
  --no-monitoring       Install without the Prometheus/Grafana stack
  -h, --help            Show this help message
  --rebuild            Rebuild containers after code changes

Examples:
  # Interactive mode (recommended)
  bash install.sh

  # Development setup
  bash install.sh --dev

  # Rebuild after changes
  bash install.sh --rebuild

  # Production with Let's Encrypt
  sudo bash install.sh --prod --domain socis.company.com --email admin@company.com --tls letsencrypt

  # Production unattended
  sudo bash install.sh --prod --unattended --domain socis.company.com

HELP
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dev)              DEPLOYMENT_MODE="development"; shift ;;
        --prod)             DEPLOYMENT_MODE="production"; shift ;;
        --interactive)      DEPLOYMENT_MODE="interactive"; shift ;;
        --domain)           DOMAIN_ARG="$2"; shift 2 ;;
        --email)            EMAIL_ARG="$2"; shift 2 ;;
        --install-dir)      INSTALL_DIR_ARG="$2"; shift 2 ;;
        --letsencrypt)      LETSENCRYPT_ARG="--letsencrypt"; shift ;;
        --tls)              TLS_ARG="${2:-}"; shift 2 ;;
        --cert)             CERT_ARG="${2:-}"; shift 2 ;;
        --key)              KEY_ARG="${2:-}"; shift 2 ;;
        --admin-password)   ADMINPW_ARG="${2:-}"; shift 2 ;;
        --allow-private-targets) PRIVATE_ARG="--allow-private-targets"; shift ;;
        --skip-docker)      SKIP_DOCKER_ARG="--skip-docker"; shift ;;
        --no-monitoring)    NO_MONITORING_ARG="--no-monitoring"; shift ;;
        --unattended)       UNATTENDED_ARG="--unattended"; shift ;;
        --rebuild)         
            REBUILD_ONLY=true; shift ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            warn "Unknown option: $1"
            shift
            ;;
    esac
done

# ─── Rebuild (deferred — mode is now known) ───────────────────────────────────
# Must come AFTER all args are parsed so --dev --rebuild works correctly.
if [[ "$REBUILD_ONLY" == true ]]; then
    if [[ "$DEPLOYMENT_MODE" == "development" || "$DEPLOYMENT_MODE" == "interactive" ]]; then
        echo "🔄 Rebuilding in development mode..."
        exec bash "$SCRIPT_DIR/install-dev.sh" --rebuild
    else
        echo "🔄 Rebuilding in production mode..."
        cd "$SCRIPT_DIR/../docker"
        docker compose -f docker-compose.prod.yml down 2>/dev/null || true
        docker compose -f docker-compose.prod.yml up -d --build
        echo "✅ Rebuild complete!"
        exit 0
    fi
fi

# ─── OS Detection ─────────────────────────────────────────────────────
if [[ ! -f /etc/os-release ]]; then
    fail "Cannot detect operating system"
fi

source /etc/os-release
info "Detected: ${PRETTY_NAME}"

# ─── Interactive Mode ─────────────────────────────────────────────────
if [[ "$DEPLOYMENT_MODE" == "interactive" ]]; then
    echo ""
    echo -e "  ${BOLD}${CYAN}Select Deployment Mode:${RESET}"
    echo -e "    ${GREEN}1)${RESET} Development (local, no root required)"
    echo -e "    ${GREEN}2)${RESET} Production (enterprise, requires root)"
    echo ""
    read -rp "  Choose [1 or 2]: " choice
    
    case "$choice" in
        1) DEPLOYMENT_MODE="development" ;;
        2) DEPLOYMENT_MODE="production" ;;
        *) fail "Invalid choice" ;;
    esac
fi

# ─── Check Root Requirements ──────────────────────────────────────────
if [[ "$DEPLOYMENT_MODE" == "production" && $EUID -ne 0 ]]; then
    fail "Production mode requires root (sudo). Run: sudo bash $0 --prod ..."
fi

# ─── Execute Appropriate Installer ────────────────────────────────────
if [[ "$DEPLOYMENT_MODE" == "development" ]]; then
    echo ""
    info "Launching Development Installer  →  docker-compose.dev.yml"
    sleep 1

    exec bash "$SCRIPT_DIR/install-dev.sh" \
        ${SKIP_DOCKER_ARG:-} \
        ${NO_MONITORING_ARG:-} \
        ${UNATTENDED_ARG:-}

elif [[ "$DEPLOYMENT_MODE" == "production" ]]; then
    echo ""
    info "Launching Production Installer  →  docker-compose.prod.yml"
    sleep 1

    exec bash "$SCRIPT_DIR/install-prod.sh" \
        ${DOMAIN_ARG:+--domain "$DOMAIN_ARG"} \
        ${EMAIL_ARG:+--email "$EMAIL_ARG"} \
        ${INSTALL_DIR_ARG:+--install-dir "$INSTALL_DIR_ARG"} \
        ${LETSENCRYPT_ARG:-} \
        ${TLS_ARG:+--tls "$TLS_ARG"} \
        ${CERT_ARG:+--cert "$CERT_ARG"} \
        ${KEY_ARG:+--key "$KEY_ARG"} \
        ${ADMINPW_ARG:+--admin-password "$ADMINPW_ARG"} \
        ${PRIVATE_ARG:-} \
        ${NO_MONITORING_ARG:-} \
        ${UNATTENDED_ARG:-}
fi
