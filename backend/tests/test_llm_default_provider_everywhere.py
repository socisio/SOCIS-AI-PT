"""Two real, separate gaps from the ones already fixed (test_llm_provider_credentials.py): the AUTOMATIC post-scan
analysis (run_scan's "LLM Analysis" step, which fires after every scan with no user request to read a provider
from) and the WORKFLOW BUILDER's LLM node were both hardcoded to Ollama regardless of what the admin configured as
their default/chosen provider. Reported directly: "I configure one Provider and I can't use it on... Workflow, or
AI Analyzer."

  python tests/test_llm_default_provider_everywhere.py
"""
import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

PROVIDERS_SRC = open(os.path.join(ROOT, "app", "core", "llm_providers.py"), encoding="utf-8").read()
t("resolve_default_llm_config exists — the true cross-provider 'what should an unattended process use' lookup",
  "async def resolve_default_llm_config" in PROVIDERS_SRC)
_default_cfg_body = PROVIDERS_SRC[PROVIDERS_SRC.index("async def resolve_default_llm_config"):
                                   PROVIDERS_SRC.index("def normalize_provider_fields")]
t("it queries ALL active configs (any provider) — no .provider == filter in its where() clause",
  ".where(LLMConfig.is_active == True)" in _default_cfg_body and
  "LLMConfig.provider ==" not in _default_cfg_body)
t("it orders by is_default first — the admin's actual chosen default wins regardless of provider",
  "LLMConfig.is_default.desc()" in _default_cfg_body)
t("it returns None (not a crash) when no LLMConfig exists at all, so callers can fall back cleanly",
  "if cfg is None:\n            return None" in PROVIDERS_SRC)

WORKER_SRC = open(os.path.join(ROOT, "app", "tasks", "scan_worker.py"), encoding="utf-8").read()

# ── automatic post-scan analysis (run_scan) ──────────────────────────────────────────────────────────────────
auto_section = WORKER_SRC[WORKER_SRC.index('"source": "unknown"'):WORKER_SRC.index('llm_duration_ms = int')]
t("the automatic post-scan analysis now resolves the admin's true default config (any provider), not just Ollama",
  "resolve_default_llm_config(db)" in auto_section)
t("it passes the resolved api_key through to chat() for the configured default provider",
  "api_key=cfg_api_key" in auto_section)
t("it still falls back to the Ollama .env default when no LLMConfig exists at all (behaviour preserved for a "
  "fresh install with nothing configured)",
  '"source": "ollama"' in auto_section and "settings.OLLAMA_DEFAULT_MODEL" in auto_section)

# ── workflow builder LLM node ─────────────────────────────────────────────────────────────────────────────────
node_section = WORKER_SRC[WORKER_SRC.index('elif node_type == "llm":'):WORKER_SRC.index('duration_ms = int(time.time() * 1000) - t0', WORKER_SRC.index('elif node_type == "llm":'))]
t("the workflow LLM node resolves credentials for whatever provider the node actually selected",
  "resolve_llm_credentials(db, provider.value)" in node_section)
t("a non-Ollama node provider is actually executed with that provider (not silently forced to Ollama)",
  "provider != LLMProvider.OLLAMA_REMOTE:\n                    try:\n                        async for token in llm_service.chat(\n                            prompt, provider=provider" in node_section)
t("the api_key is passed through to chat() for the node's chosen provider",
  "api_key=node_api_key" in node_section)
t("Ollama fallback only fires when the node's OWN chosen provider failed, not unconditionally for every non-Ollama node",
  "if not use_primary:" in node_section)

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
