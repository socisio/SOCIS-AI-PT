#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# List EVERY TypeScript error in the frontend, using the real compiler and the real type definitions.
#
#   bash deploy/scripts/typecheck-frontend.sh [install-dir]
#
# Why this exists: `next dev` never type-checks, and `next build` stops at the FIRST error. Production builds therefore
# do not block on type errors by default (NEXT_STRICT_BUILD=false); this tells you what is still there, all at once.
# Read-only: it only builds a throw-away image stage and prints its errors.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail
TARGET="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
DOCKER="${DOCKER_BIN:-docker}"
echo "Type-checking the frontend with the real TypeScript compiler (about a minute)…"
out=$($DOCKER build --target typecheck --progress=plain -f "$TARGET/frontend/Dockerfile" "$TARGET/frontend" 2>&1)
rc=$?
errs=$(echo "$out" | grep -E "error TS[0-9]+" | sed -E 's/^#[0-9]+ [0-9.]+ //' | sort -u)
if [[ $rc -eq 0 ]]; then
  echo "No type errors."
  exit 0
fi
if [[ -z "$errs" ]]; then
  echo "The type-check step failed for a reason other than type errors. Last lines of the build output:" >&2
  echo "$out" | tail -15 >&2
  exit 2
fi
n=$(echo "$errs" | wc -l)
echo
echo "$n type error(s):"
echo "$errs" | sed 's/^/  /'
echo
echo "$errs" | sed -E 's/\([0-9]+,[0-9]+\).*//; s/:[0-9]+:[0-9]+.*//' | sort | uniq -c | sort -rn | sed 's/^/  per file: /' | head -8
echo
echo "These do not stop the production build (NEXT_STRICT_BUILD=false). They are types only: no effect on how the app runs."
exit 1
