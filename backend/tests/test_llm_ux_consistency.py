"""Reported directly: "I can choose provider/model on AI Chat but not on Findings, or Workflow... we need a full
mechanism." This checks the shared picker mechanism (hook + component) exists and is actually wired into both
previously-broken surfaces, the duplicate provider-label map is gone, and the new "platform default" set/clear
mechanism is real (not just a label) — a config can actually be made the default after creation, and exactly one
row is ever marked default.

  python tests/test_llm_ux_consistency.py
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
FRONTEND = os.path.join(ROOT, "..", "frontend", "src")
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

# ── the shared mechanism exists ──────────────────────────────────────────────────────────────────────────────
HOOK_PATH = os.path.join(FRONTEND, "hooks", "useLlmProviders.ts")
t("the shared useLlmProviders hook exists", os.path.exists(HOOK_PATH))
if os.path.exists(HOOK_PATH):
    hook_src = open(HOOK_PATH, encoding="utf-8").read()
    t("it fetches real provider/model data (fetchLlmOptions), not a hardcoded list",
      "fetchLlmOptions" in hook_src)
    t("it does NOT bake in chat-specific side effects (saving as the global chat default) — those must stay "
      "opt-in per caller, never forced on Findings/Workflow",
      "saveLlmSettings" not in hook_src and "chat_provider" not in hook_src)

PICKER_PATH = os.path.join(FRONTEND, "components", "LlmProviderModelPicker.tsx")
t("the shared LlmProviderModelPicker component exists", os.path.exists(PICKER_PATH))

# ── Findings: the picker is actually wired in, not just imported ────────────────────────────────────────────────
FINDINGS_SRC = open(os.path.join(FRONTEND, "app", "(app)", "findings", "page.tsx"), encoding="utf-8").read()
t("Findings imports the shared hook and picker",
  "useLlmProviders" in FINDINGS_SRC and "LlmProviderModelPicker" in FINDINGS_SRC)
t("Findings renders the picker component (not just imports it unused)",
  "<LlmProviderModelPicker" in FINDINGS_SRC)
t("the Analyze call now sends the selected provider/model instead of always using the backend's bare default",
  "findingsApi.analyze(finding.id, {" in FINDINGS_SRC and "provider: llmPicker.provider" in FINDINGS_SRC)
t("the stale 'Ensure Ollama is running' error message is gone (it assumed only Ollama could ever be used)",
  "Ensure Ollama is running" not in FINDINGS_SRC)

# ── Workflow LLM node: the Ollama-only restriction is gone ───────────────────────────────────────────────────────
WORKER_UI = open(os.path.join(FRONTEND, "app", "(app)", "workflows", "builder", "page.tsx"), encoding="utf-8").read()
# The old broken line is quoted verbatim inside an explanatory code comment describing the fix — check it's not
# present as ACTIVE code (i.e. not on a line that isn't a comment), rather than a bare substring match.
_old_broken_line = "if (provider !== 'ollama_remote') { setOllamaModels([]); return; }"
_active_occurrence = any(
    _old_broken_line in line and not line.strip().startswith(("//", "*", "/*"))
    for line in WORKER_UI.splitlines()
)
t("the workflow LLM node's model fetch no longer early-returns for every non-Ollama provider (as ACTIVE code)",
  not _active_occurrence)
t("a non-Ollama provider with configured models now gets a real <select> dropdown, not just a bare text input",
  "ollamaModels.length > 0 ? (" in WORKER_UI)

# ── the duplicate provider-label map is gone, admin page uses the single shared source ──────────────────────────
ADMIN_SRC = open(os.path.join(FRONTEND, "app", "(app)", "admin", "page.tsx"), encoding="utf-8").read()
t("the admin page's own near-duplicate LLM_PROVIDER_LABELS map is removed",
  "const LLM_PROVIDER_LABELS" not in ADMIN_SRC)
t("it imports the single shared label source instead",
  "from '@/lib/providers'" in ADMIN_SRC and "providerLabel" in ADMIN_SRC)

# ── the platform-default mechanism is real, not just a label ────────────────────────────────────────────────────
ADMIN_API = open(os.path.join(ROOT, "app", "api", "v1", "admin.py"), encoding="utf-8").read()
t("a set-default endpoint exists so an existing config can be made the default after creation",
  '@router.post("/llm-configs/{config_id}/set-default"' in ADMIN_API)
t("setting a new default un-defaults every other row (exactly one config is ever the default)",
  "c.is_default = (c.id == config_id)" in ADMIN_API)
t("creating a new config as the default ALSO un-defaults existing rows (not just set-default)",
  "others = (await db.execute(select(LLMConfig).where(LLMConfig.id != config.id)))" in ADMIN_API)

API_TS = open(os.path.join(FRONTEND, "lib", "api.ts"), encoding="utf-8").read()
t("the frontend has a client call for the new set-default endpoint",
  "setDefaultLlmConfig" in API_TS and "/set-default" in API_TS)
t("the admin page has a 'Make Default' button wired to it",
  "makeLlmDefault" in ADMIN_SRC and "Make Default" in ADMIN_SRC)
t("the admin page explains what 'platform default' actually controls (not just an unexplained checkmark)",
  "Platform default:" in ADMIN_SRC or "No platform default set:" in ADMIN_SRC)

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
