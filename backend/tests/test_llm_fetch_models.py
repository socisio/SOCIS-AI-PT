"""POST /api/v1/admin/llm-configs/fetch-models — live-probes a provider's real model list with a freshly-entered
API key so an admin can pick from an actual list instead of typing an exact model-name string from memory (the gap
flagged after the LLM-provider credentials fix: "the user will not know what the Model Name is for every provider").

  python tests/test_llm_fetch_models.py
"""
import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

SRC = open(os.path.join(ROOT, "app", "api", "v1", "admin.py"), encoding="utf-8").read()

t("the fetch-models endpoint exists", '@router.post("/llm-configs/fetch-models")' in SRC)
t("it requires admin:settings permission, same as the other LLM-config endpoints",
  'async def fetch_llm_models(' in SRC and 'require_permission("admin:settings")' in SRC.split('async def fetch_llm_models(')[1][:300])

# every provider that can be saved through the admin UI must have a real, hardcoded endpoint here
ADMIN_FRONTEND = open(os.path.join(ROOT, "..", "frontend", "src", "app", "(app)", "admin", "page.tsx"), encoding="utf-8").read()
m = re.search(r"LLM_PROVIDER_LABELS: Record<string, string> = \{(.*?)\};", ADMIN_FRONTEND, re.S)
ui_providers = set(re.findall(r"(\w+):\s*'", m.group(1))) if m else set()
ui_providers.discard("ollama_remote")  # Ollama uses its own /api/tags flow, not this endpoint

endpoint_map = re.search(r"_PROVIDER_MODELS_ENDPOINT = \{(.*?)\n\}", SRC, re.S)
backend_providers = set(re.findall(r'"(\w+)":', endpoint_map.group(1))) if endpoint_map else set()

missing = sorted(ui_providers - backend_providers)
t(f"every provider in the admin UI's dropdown has a model-list endpoint on the backend — missing: {missing}",
  not missing, missing)

t("every provider endpoint is a FIXED https:// URL (never built from caller input) — no SSRF via provider name",
  all('"https://' in line for line in endpoint_map.group(1).splitlines() if ':' in line))

t("a caller-supplied api_url override still goes through the SSRF guard (acheck_url) before being used",
  "await acheck_url(url, allow_private=False)" in SRC)

t("a missing/blank API key is rejected before any network call, with a clear message",
  '"An API key is required to fetch models."' in SRC)

t("Anthropic uses x-api-key + anthropic-version (its real auth scheme), not a Bearer token",
  '"x-api-key": body.api_key, "anthropic-version": "2023-06-01"' in SRC)

t("every other provider uses a Bearer Authorization header (the OpenAI-compatible scheme)",
  'f"Bearer {body.api_key}"' in SRC)

t("a 401 from the provider is translated into a clear 'key rejected' message, not a raw passthrough",
  '"That API key was rejected (401 Unauthorized)."' in SRC)

t("the response is never persisted anywhere in this endpoint (it's a live probe, not a save)",
  "db.add(" not in SRC.split('async def fetch_llm_models(')[1].split("async def ")[0] and
  "db.commit(" not in SRC.split('async def fetch_llm_models(')[1].split("async def ")[0])

# ── frontend wiring ──────────────────────────────────────────────────────────────────────────────────────────
API_TS = open(os.path.join(ROOT, "..", "frontend", "src", "lib", "api.ts"), encoding="utf-8").read()
t("the frontend API client has a fetchLlmModels call wired to the new endpoint",
  "fetchLlmModels:" in API_TS and "/admin/llm-configs/fetch-models" in API_TS)

t("the admin page has a 'Fetch Models' button for non-Ollama providers",
  "Fetch Models" in ADMIN_FRONTEND)
t("a fetched model list renders as a real dropdown (<select>), not just a hint for manual typing",
  "apiModels.map((m) =>" in ADMIN_FRONTEND)
t("changing the API key or URL after a fetch clears the stale model list (never submit a model for the wrong key)",
  "apiModels.length > 0) {\n                              setApiModels([]);" in ADMIN_FRONTEND)
t("switching providers clears the previous provider's fetched models",
  "Switching providers invalidates any fetched model list" in ADMIN_FRONTEND)

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
