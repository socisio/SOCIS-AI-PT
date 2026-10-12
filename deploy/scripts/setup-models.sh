#!/usr/bin/env bash
set -euo pipefail

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[OLLAMA]${RESET} $*"; }
success() { echo -e "${GREEN}[   OK ]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[ WARN]${RESET} $*"; }
fail()    { echo -e "${RED}[ FAIL]${RESET} $*"; exit 1; }

# The bundled local Ollama container was removed. Point this at your EXTERNAL
# Ollama server (the same host you set as OLLAMA_REMOTE_URL). Falls back to
# OLLAMA_REMOTE_URL from the environment if OLLAMA_HOST is not given.
OLLAMA_HOST="${OLLAMA_HOST:-${OLLAMA_REMOTE_URL:-http://localhost:11434}}"
MODELFILE_DIR="${MODELFILE_DIR:-./backend/modelfiles}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

info "Checking Ollama connectivity at $OLLAMA_HOST..."
if ! curl -sf "$OLLAMA_HOST/api/tags" > /dev/null 2>&1; then
    fail "Ollama not reachable at $OLLAMA_HOST. Set OLLAMA_HOST (or OLLAMA_REMOTE_URL) to your external Ollama server, e.g. OLLAMA_HOST=http://192.168.1.50:11434 $0"
fi
success "Ollama is online."

# Create Custom Models (base models are pulled automatically by ollama create)
create_model() {
    local name="$1"
    local file="$2"
    
    if [[ ! -f "$file" ]]; then
        warn "Modelfile not found: $file"
        return 1
    fi
    
    info "Creating model: $name..."
    # `ollama create -f <Modelfile>` requires the Ollama CLI on the Ollama host
    # (the HTTP API cannot build from a Modelfile). Try, in order:
    #   1) a legacy local socis_ollama container (if this host still runs one)
    #   2) the ollama CLI on this machine (run this script ON the Ollama host)
    #   3) otherwise, tell the user to build models on the Ollama host.
    local container
    container=$(docker ps --filter "name=socis_ollama" --format "{{.Names}}" 2>/dev/null | head -1)
    if [[ -n "$container" ]]; then
        local dest="/tmp/$(basename "$file")"
        docker cp "$file" "${container}:${dest}" 2>/dev/null
        if docker exec "$container" ollama create "$name" -f "$dest" 2>&1; then
            success "$name created."
            return 0
        fi
    fi
    if command -v ollama >/dev/null 2>&1; then
        if OLLAMA_HOST="$OLLAMA_HOST" ollama create "$name" -f "$file" 2>&1; then
            success "$name created via ollama CLI."
            return 0
        fi
    fi
    warn "Could not build '$name' from here. Build it ON the Ollama host, e.g.:"
    warn "    scp $file <ollama-host>:/tmp/ && ssh <ollama-host> 'ollama create $name -f /tmp/$(basename "$file")'"
    return 1
}

create_model "socis-pentest" "$REPO_ROOT/backend/modelfiles/socis-pentest.Modelfile"
create_model "socis-recon"   "$REPO_ROOT/backend/modelfiles/socis-recon.Modelfile"
create_model "socis-exploit" "$REPO_ROOT/backend/modelfiles/socis-exploit.Modelfile"

# RAG uses nomic-embed-text for finding embeddings.
# Without this model, Ollama returns 404 "model not found" for embedding requests.
info "Ensuring embedding model exists (nomic-embed-text)..."
if [[ -n "$(docker ps --filter "name=socis_ollama" --format "{{.Names}}" 2>/dev/null | head -1)" ]]; then
    _embed_container=$(docker ps --filter "name=socis_ollama" --format "{{.Names}}" 2>/dev/null | head -1)
    docker exec "$_embed_container" ollama pull nomic-embed-text >/dev/null 2>&1 && success "Embedding model ready: nomic-embed-text" || warn "Could not pull nomic-embed-text"
else
    curl -sf -X POST "$OLLAMA_HOST/api/pull" \
        -H "Content-Type: application/json" \
        -d '{"name":"nomic-embed-text","stream":false}' >/dev/null 2>&1 \
        && success "Embedding model ready: nomic-embed-text" \
        || warn "Could not pull nomic-embed-text"
fi

# Remove base model tags — the weight blobs are shared with the custom models,
# so no disk space is freed, but the tag list stays clean.
info "Removing base model tags (weights are shared, no disk space lost)..."
_cleanup_container=$(docker ps --filter "name=socis_ollama" --format "{{.Names}}" 2>/dev/null | head -1)
for base in qwen2.5:7b llama3.1:8b deepseek-r1:8b; do
    if [[ -n "$_cleanup_container" ]]; then
        docker exec "$_cleanup_container" ollama rm "$base" 2>/dev/null && success "Removed tag: $base" || true
    else
        curl -sf -X DELETE "$OLLAMA_HOST/api/delete" \
            -H "Content-Type: application/json" \
            -d "{\"name\": \"$base\"}" 2>/dev/null && success "Removed tag: $base" || true
    fi
done

echo ""
success "All SOCIS-AI-PT models are ready!"
info "Available models:"
curl -sf "$OLLAMA_HOST/api/tags" 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for m in data.get('models', []):
        size_gb = m.get('size', 0) / 1e9
        print(f\"  • {m['name']:<35} {size_gb:.1f} GB\")
except Exception as e:
    print(f'Error: {e}')
" || warn "Could not list models"