#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════
# SOCIS-AI-PT — Cleanup Script
# Removes all containers, volumes, images, networks, and generated host files
#
# Usage:
#   bash cleanup.sh [OPTIONS]
#
# Options:
#   --full        Also remove generated host files (.env, SSL certs, node_modules,
#                 .venv, .next, __pycache__) — full factory reset
#   --images      Remove custom Docker images (backend, frontend, mcp_all, worker)
#   --reinstall   Automatically reinstall after cleanup
#   -h, --help    Show this help
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'

FULL_CLEAN=false
REMOVE_IMAGES=false
REINSTALL=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --full)       FULL_CLEAN=true;      shift ;;
        --images)     REMOVE_IMAGES=true;   shift ;;
        --reinstall)  REINSTALL=true;       shift ;;
        -h|--help)
            echo "SOCIS-AI-PT Cleanup Script"
            echo "Usage: bash $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --full        Remove generated host files (.env, SSL, node_modules, .venv, caches)"
            echo "  --images      Remove custom Docker images"
            echo "  --reinstall   Automatically reinstall after cleanup"
            echo "  -h, --help    Show this help"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/deploy/docker/docker-compose.dev.yml"

echo -e "${CYAN}"
echo "═══════════════════════════════════════════════════════════"
echo "  SOCIS-AI-PT Cleanup Script"
echo "═══════════════════════════════════════════════════════════"
echo -e "${RESET}"
echo -e "  Repo root : ${REPO_ROOT}"
echo -e "  Full clean: ${FULL_CLEAN}"
echo -e "  Rm images : ${REMOVE_IMAGES}"
echo ""

# ─── Step 1: Docker Compose down (cleanest path) ───────────────────────
echo -e "${YELLOW}${BOLD}► Step 1: Docker Compose down...${RESET}"
if [[ -f "$COMPOSE_FILE" ]]; then
    docker compose -f "$COMPOSE_FILE" --profile lab down --remove-orphans 2>/dev/null || true
    echo -e "${GREEN}  ✓ Compose stack stopped${RESET}"
else
    echo -e "${YELLOW}  ⚠ Compose file not found, falling back to manual removal${RESET}"
fi

# ─── Step 2: Remove any remaining containers (catch orphans) ───────────
echo -e "${YELLOW}${BOLD}► Step 2: Removing remaining platform containers...${RESET}"
SOCIS_CONTAINERS=$(docker ps -a --format "{{.Names}}" 2>/dev/null \
    | grep -E "^socis_|^mcp_all" || true)

if [[ -n "$SOCIS_CONTAINERS" ]]; then
    while IFS= read -r container; do
        echo -e "  ${YELLOW}Removing container:${RESET} $container"
        docker rm -f "$container" 2>/dev/null || true
    done <<< "$SOCIS_CONTAINERS"
    echo -e "${GREEN}  ✓ All platform containers removed${RESET}"
else
    echo -e "${GREEN}  ✓ No orphan containers found${RESET}"
fi

# ─── Step 3: Remove Docker volumes ─────────────────────────────────────
echo -e "${YELLOW}${BOLD}► Step 3: Removing Docker volumes...${RESET}"

# All volumes the platform creates — both bare names (mcp-servers compose)
# and docker_* prefixed names (deploy compose, created by Docker automatically).
VOLUME_PATTERNS=(
    "postgres_data"
    "redis_data"
    "minio_data"
    "ollama_data"
    "reports_data"
    "metasploit_data"
    "dvwa_db"
    "wordlists"
    "cve_lite_db"
    "projects_data"
)

# Build regex that matches both bare and docker_-prefixed volume names
VOLUME_REGEX=$(printf '%s|' "${VOLUME_PATTERNS[@]}")
VOLUME_REGEX="(docker_)?(${VOLUME_REGEX%|})"

SOCIS_VOLUMES=$(docker volume ls -q 2>/dev/null \
    | grep -E "$VOLUME_REGEX" || true)

if [[ -n "$SOCIS_VOLUMES" ]]; then
    while IFS= read -r vol; do
        echo -e "  ${YELLOW}Removing volume:${RESET} $vol"
        docker volume rm "$vol" 2>/dev/null || true
    done <<< "$SOCIS_VOLUMES"
    echo -e "${GREEN}  ✓ Platform volumes removed${RESET}"
else
    echo -e "${GREEN}  ✓ No platform volumes found${RESET}"
fi

# ─── Step 4: Remove Docker networks ────────────────────────────────────
echo -e "${YELLOW}${BOLD}► Step 4: Removing Docker networks...${RESET}"

# Network names: docker_socis-net, docker_lab-net (compose-prefixed)
SOCIS_NETWORKS=$(docker network ls --format "{{.Name}}" 2>/dev/null \
    | grep -E "(socis.net|lab.net|socis-net|lab-net)" || true)

if [[ -n "$SOCIS_NETWORKS" ]]; then
    while IFS= read -r net; do
        echo -e "  ${YELLOW}Removing network:${RESET} $net"
        docker network rm "$net" 2>/dev/null || true
    done <<< "$SOCIS_NETWORKS"
    echo -e "${GREEN}  ✓ Platform networks removed${RESET}"
else
    echo -e "${GREEN}  ✓ No platform networks found${RESET}"
fi

# ─── Step 5: Remove custom Docker images (opt-in) ──────────────────────
echo -e "${YELLOW}${BOLD}► Step 5: Custom Docker images...${RESET}"

PLATFORM_IMAGES=(
    "docker-backend"
    "docker-frontend"
    "docker-mcp_all"
    "docker-worker"
    "docker-metasploit_rpc"
    "socis/mcp-all"
)

if [[ "$REMOVE_IMAGES" == true ]]; then
    for img in "${PLATFORM_IMAGES[@]}"; do
        if docker image inspect "$img:latest" &>/dev/null; then
            echo -e "  ${YELLOW}Removing image:${RESET} $img"
            docker rmi -f "$img:latest" 2>/dev/null || true
        fi
    done
    echo -e "${GREEN}  ✓ Custom images removed${RESET}"
else
    echo -e "  ${CYAN}Skipped (pass --images to remove)${RESET}"
    echo -e "  Kept images: ${PLATFORM_IMAGES[*]}"
fi

# ─── Step 6: Clean Docker build cache ──────────────────────────────────
echo -e "${YELLOW}${BOLD}► Step 6: Cleaning Docker build cache...${RESET}"
docker builder prune -f --filter "until=168h" 2>/dev/null || true
echo -e "${GREEN}  ✓ Build cache cleaned${RESET}"

# ─── Step 7: Remove generated host files (opt-in with --full) ──────────
echo -e "${YELLOW}${BOLD}► Step 7: Generated host files...${RESET}"

if [[ "$FULL_CLEAN" == true ]]; then
    echo -e "  ${RED}FULL CLEAN — removing generated host files...${RESET}"

    # Generated secrets / env
    if [[ -f "${REPO_ROOT}/deploy/docker/.env" ]]; then
        echo -e "  ${YELLOW}Removing:${RESET} deploy/docker/.env"
        rm -f "${REPO_ROOT}/deploy/docker/.env"
    fi

    # Generated SSL certificates
    for f in cert.pem key.pem; do
        ssl_file="${REPO_ROOT}/deploy/nginx/ssl/${f}"
        if [[ -f "$ssl_file" ]]; then
            echo -e "  ${YELLOW}Removing:${RESET} deploy/nginx/ssl/${f}"
            rm -f "$ssl_file"
        fi
    done

    # Frontend build artifacts and dependencies
    for dir in \
        "${REPO_ROOT}/frontend/.next" \
        "${REPO_ROOT}/frontend/node_modules"; do
        if [[ -d "$dir" ]]; then
            echo -e "  ${YELLOW}Removing:${RESET} ${dir#"$REPO_ROOT/"}"
            rm -rf "$dir"
        fi
    done

    # Python virtual environment
    if [[ -d "${REPO_ROOT}/.venv" ]]; then
        echo -e "  ${YELLOW}Removing:${RESET} .venv"
        rm -rf "${REPO_ROOT}/.venv"
    fi

    # Python caches (backend + mcp-servers)
    find "${REPO_ROOT}" \
        -not -path "*/node_modules/*" \
        -not -path "*/.venv/*" \
        \( -name "__pycache__" -type d -o -name "*.pyc" -o -name "*.pyo" \) \
        -exec rm -rf {} + 2>/dev/null || true

    # Alembic generated migration cache (not version files)
    find "${REPO_ROOT}/backend/alembic/versions" \
        -name "*.pyc" -exec rm -f {} + 2>/dev/null || true

    echo -e "${GREEN}  ✓ Generated host files removed${RESET}"
else
    echo -e "  ${CYAN}Skipped (pass --full to also remove .env, SSL certs, node_modules, .venv, caches)${RESET}"
fi

# ─── Step 8: Sanity check — verify nothing is left ─────────────────────
echo ""
echo -e "${YELLOW}${BOLD}► Step 8: Sanity check...${RESET}"

REMAINING_CONTAINERS=$(docker ps -a --format "{{.Names}}" 2>/dev/null \
    | grep -E "^socis_" || true)
REMAINING_VOLUMES=$(docker volume ls -q 2>/dev/null \
    | grep -E "$VOLUME_REGEX" || true)

if [[ -z "$REMAINING_CONTAINERS" && -z "$REMAINING_VOLUMES" ]]; then
    echo -e "${GREEN}  ✓ Clean — no platform containers or volumes remain${RESET}"
else
    [[ -n "$REMAINING_CONTAINERS" ]] && echo -e "${RED}  ⚠ Containers still present:${RESET}" && echo "$REMAINING_CONTAINERS"
    [[ -n "$REMAINING_VOLUMES" ]]   && echo -e "${RED}  ⚠ Volumes still present:${RESET}"    && echo "$REMAINING_VOLUMES"
fi

# ─── Summary ───────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════"
echo "  Cleanup Complete!"
echo "═══════════════════════════════════════════════════════════${RESET}"
echo ""
echo "  To reinstall:  bash deploy/scripts/install-dev.sh"
echo "  To reinstall:  bash $0 --reinstall"
echo ""

# ─── Reinstall (opt-in) ────────────────────────────────────────────────
if [[ "$REINSTALL" == true ]]; then
    echo -e "${CYAN}► Starting automatic reinstall...${RESET}"
    cd "$REPO_ROOT"
    bash deploy/scripts/install-dev.sh --unattended
fi