"""Saving an OpenAI/Anthropic/OpenRouter/Grok/Mistral config in Admin -> AI providers stored the key, but nothing
ever read it back at runtime — every chat_<provider>() method in llm_service.py only ever used the .env variable.
Configuring a provider through the UI looked like it worked (the save succeeded) but silently had no effect on what
the platform actually used for AI chat, scan analysis, workflows, findings, or the payload generator.

This checks: the shared resolver exists and is wired into every real call site (not just one), every provider method
in llm_service.py actually accepts and uses the override, and the one call site that had an unrelated bug (falling
back to the Ollama default model for a non-Ollama provider) is fixed.

  python tests/test_llm_provider_credentials.py
"""
import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

# ── the shared resolver exists and is sound ─────────────────────────────────────────────────────────────────
PROVIDERS_SRC = open(os.path.join(ROOT, "app", "core", "llm_providers.py"), encoding="utf-8").read()
t("resolve_llm_credentials exists", "async def resolve_llm_credentials" in PROVIDERS_SRC)
t("it returns (None, None) for ollama_remote (its credential is a URL, handled separately)",
  "if provider == CANONICAL_OLLAMA:" in PROVIDERS_SRC)
t("it queries the active, default LLMConfig row for the given provider",
  "LLMConfig.is_active == True" in PROVIDERS_SRC and "LLMConfig.provider == provider" in PROVIDERS_SRC)
t("a decrypt failure (wrong/rotated ENCRYPTION_KEY) falls back to None, not a crash",
  "except ValueError:" in PROVIDERS_SRC and "api_key = None" in PROVIDERS_SRC)
t("any other lookup failure also falls back silently rather than breaking the chat request",
  "except Exception:\n        # Never let a credential-lookup problem take down" in PROVIDERS_SRC)

# ── llm_service.py: every non-Ollama method actually accepts and uses the override ─────────────────────────────
SVC_SRC = open(os.path.join(ROOT, "app", "services", "llm_service.py"), encoding="utf-8").read()
for method, env_var in [("chat_openai", "OPENAI_API_KEY"), ("chat_anthropic", "ANTHROPIC_API_KEY"),
                         ("chat_openrouter", "OPENROUTER_API_KEY"), ("chat_grok", "GROK_API_KEY"),
                         ("chat_mistral", "MISTRAL_API_KEY")]:
    i = SVC_SRC.index(f"async def {method}(")
    j = SVC_SRC.index("async def ", i + 10)
    body = SVC_SRC[i:j]
    t(f"{method} accepts an api_key parameter", "api_key: Optional[str] = None" in body)
    t(f"{method} accepts a base_url parameter", "base_url: Optional[str] = None" in body)
    t(f"{method} uses the passed api_key before falling back to settings.{env_var}",
      f"api_key or settings.{env_var}" in body)

t("chat() accepts api_key and forwards it to every non-Ollama branch",
  SVC_SRC.count("api_key=api_key, base_url=base_url") == 5)

# ── every real call site resolves and passes credentials (not just the shared helper existing in isolation) ───
LLM_API_SRC = open(os.path.join(ROOT, "app", "api", "v1", "llm.py"), encoding="utf-8").read()
t("llm.py's chat endpoint resolves credentials once and passes them to all 3 of its chat() calls",
  "resolve_llm_credentials(db, provider_key)" in LLM_API_SRC and
  LLM_API_SRC.count("api_key=chat_api_key") == 3)

FINDINGS_SRC = open(os.path.join(ROOT, "app", "api", "v1", "findings.py"), encoding="utf-8").read()
t("findings.py's analyze endpoint resolves credentials for non-Ollama providers",
  "resolve_llm_credentials(db, selected_provider)" in FINDINGS_SRC and "api_key=selected_api_key" in FINDINGS_SRC)
t("findings.py no longer falls back to the Ollama default model for a non-Ollama provider",
  not re.search(r'else:\s*\n\s*selected_model = _settings\.OLLAMA_DEFAULT_MODEL', FINDINGS_SRC) or
  "_default_cfg.model_name" in FINDINGS_SRC)

WORKER_SRC = open(os.path.join(ROOT, "app", "tasks", "scan_worker.py"), encoding="utf-8").read()
t("scan_worker.py's run_scan_ai_analysis (manual-analysis button) resolves credentials for non-Ollama providers",
  "resolve_llm_credentials(db, selected_provider)" in WORKER_SRC and "api_key=selected_api_key" in WORKER_SRC)
t("it resolves the provider's OWN default model from LLMConfig, not the Ollama default model",
  "_default_cfg.model_name if _default_cfg else" in WORKER_SRC)

TOOLS_SRC = open(os.path.join(ROOT, "app", "api", "v1", "tools.py"), encoding="utf-8").read()
t("tools.py's payload-generator helper resolves credentials for non-Ollama providers",
  "resolve_llm_credentials(_db, provider)" in TOOLS_SRC and "api_key=api_key" in TOOLS_SRC)

WS_SRC = open(os.path.join(ROOT, "app", "api", "websocket.py"), encoding="utf-8").read()
t("the WebSocket chat endpoint reads and forwards api_key from the user's LLM config",
  "api_key = llm_config.get(\"api_key\")" in WS_SRC and "api_key=api_key," in WS_SRC)
t("_get_user_llm_config resolves credentials for non-Ollama providers, not just Ollama's URL",
  "resolve_llm_credentials(db, provider)" in LLM_API_SRC)

# ── /llm/status now checks the database too, not just .env ─────────────────────────────────────────────────
t("/llm/status queries active LLMConfig rows to determine whether a provider is configured",
  "db_configured_providers" in LLM_API_SRC and "LLMConfig).where(LLMConfig.is_active == True)" in LLM_API_SRC)
t("each provider's status reflects EITHER the env var OR a saved DB config, not env-only",
  "bool(env_key) or from_db" in LLM_API_SRC)

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
