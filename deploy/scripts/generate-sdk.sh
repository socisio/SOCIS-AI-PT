#!/usr/bin/env bash
# generate-sdk.sh — Generate TypeScript and Python SDK clients from the OpenAPI spec.
#
# Usage:
#   ./deploy/scripts/generate-sdk.sh [--api-url <url>] [--out-dir <dir>]
#
# Requirements:
#   - Node.js >= 18 with npx (for TypeScript SDK)
#   - Python >= 3.9 with pip (for Python SDK)
#   - Running backend or a saved openapi.json file
#
# Environment variables (override defaults):
#   API_URL      Base URL of the running backend (default: http://localhost:8000)
#   OUT_DIR      Root output directory for generated SDKs (default: ./sdk)

set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────
API_URL="${API_URL:-http://localhost:8000}"
OUT_DIR="${OUT_DIR:-./sdk}"
SPEC_FILE="/tmp/socis_openapi.json"

# ── Argument parsing ─────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-url) API_URL="$2"; shift 2 ;;
    --out-dir)  OUT_DIR="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

echo "==> SOCIS-AI-PT SDK Generator"
echo "    API URL : $API_URL"
echo "    Output  : $OUT_DIR"
echo ""

# ── Step 1: Download OpenAPI spec ────────────────────────────────
echo "[1/4] Downloading OpenAPI spec from $API_URL/openapi.json ..."
if command -v curl &>/dev/null; then
  curl -fsSL "$API_URL/openapi.json" -o "$SPEC_FILE"
elif command -v wget &>/dev/null; then
  wget -qO "$SPEC_FILE" "$API_URL/openapi.json"
else
  echo "ERROR: curl or wget is required." >&2
  exit 1
fi
echo "      Spec saved to $SPEC_FILE"

# ── Step 2: Generate TypeScript SDK ─────────────────────────────
TS_OUT="$OUT_DIR/typescript"
echo "[2/4] Generating TypeScript SDK → $TS_OUT ..."
mkdir -p "$TS_OUT"

if command -v npx &>/dev/null; then
  npx --yes @hey-api/openapi-ts@latest \
    --input "$SPEC_FILE" \
    --output "$TS_OUT" \
    --client fetch \
    --name "SocisClient"
  echo "      TypeScript SDK generated."
else
  echo "      SKIP: npx not found — install Node.js >= 18 to generate the TypeScript SDK."
fi

# ── Step 3: Generate Python SDK ──────────────────────────────────
PY_OUT="$OUT_DIR/python"
echo "[3/4] Generating Python SDK → $PY_OUT ..."
mkdir -p "$PY_OUT"

if python3 -c "import openapi_python_client" &>/dev/null 2>&1; then
  openapi-python-client generate \
    --path "$SPEC_FILE" \
    --output-path "$PY_OUT" \
    --overwrite
  echo "      Python SDK generated."
else
  pip3 install --quiet openapi-python-client
  openapi-python-client generate \
    --path "$SPEC_FILE" \
    --output-path "$PY_OUT" \
    --overwrite
  echo "      Python SDK generated."
fi

# ── Step 4: Summary ──────────────────────────────────────────────
echo ""
echo "[4/4] SDK generation complete."
echo "      TypeScript : $TS_OUT"
echo "      Python     : $PY_OUT"
echo ""
echo "To use the TypeScript client:"
echo "  import { SocisClient } from './$TS_OUT';"
echo ""
echo "To use the Python client:"
echo "  pip install -e $PY_OUT"
