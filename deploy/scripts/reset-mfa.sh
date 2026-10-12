#!/usr/bin/env bash
# Turn two-factor off for one account (use when the only administrator lost their authenticator).
#   bash deploy/scripts/reset-mfa.sh admin
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
[[ $# -eq 1 ]] || { echo "Usage: bash deploy/scripts/reset-mfa.sh USERNAME"; exit 2; }
COMPOSE="docker compose -f deploy/docker/docker-compose.dev.yml"
[[ -f deploy/docker/docker-compose.prod.yml && "${SOCIS_MODE:-dev}" == "prod" ]] && COMPOSE="docker compose -f deploy/docker/docker-compose.prod.yml"
$COMPOSE exec -T backend python tools/reset_mfa.py "$1"
