#!/usr/bin/env bash
# pin-images.sh — pin third-party images by digest (supply-chain hardening).
# Rewrites plain `image: name:tag` lines in a compose file to
# `image: name:tag@sha256:<digest>` using the digests of images ALREADY PULLED
# on this host, so what you tested is exactly what runs in prod.
#
# Usage:  bash pin-images.sh [compose-file] [--dry-run]
#   default compose-file: deploy/docker/docker-compose.prod.yml
# Run AFTER a successful install/pull on the host (images must exist locally).
# Lines using ${VAR:-...} (e.g. MINIO_IMAGE) are skipped — pin those in .env.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../docker" && pwd)"
FILE="${1:-$DIR/docker-compose.prod.yml}"; DRY=false
[[ "${1:-}" == "--dry-run" ]] && { FILE="$DIR/docker-compose.prod.yml"; DRY=true; }
[[ "${2:-}" == "--dry-run" ]] && DRY=true
[[ -f "$FILE" ]] || { echo "compose file not found: $FILE"; exit 1; }
$DRY || cp "$FILE" "$FILE.bak.$(date +%s)"
pinned=0; skipped=0
while IFS= read -r line; do
  if [[ "$line" =~ ^([[:space:]]+image:[[:space:]]+)([^[:space:]\$@#]+)[[:space:]]*$ ]]; then
    prefix="${BASH_REMATCH[1]}"; img="${BASH_REMATCH[2]}"
    digest="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$img" 2>/dev/null | grep -m1 '@sha256:' | sed 's/.*@//' || true)"
    if [[ -n "$digest" ]]; then
      echo "pin   $img -> @${digest:0:19}…"
      $DRY || sed -i "s|^${prefix}${img}[[:space:]]*\$|${prefix}${img}@${digest}|" "$FILE"
      pinned=$((pinned+1))
    else
      echo "skip  $img (not pulled locally — run install first)"; skipped=$((skipped+1))
    fi
  fi
done < "$FILE"
echo "Done: $pinned pinned, $skipped skipped. $($DRY && echo '(dry run, nothing written)' || echo "Backup: $FILE.bak.*")"
