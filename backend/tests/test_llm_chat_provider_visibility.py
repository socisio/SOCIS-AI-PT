"""The AI Chat / payload-generator provider picker (/tools/payload-generator/llm-options) required BOTH a saved
LLMConfig row AND the provider's .env variable to be set before a cloud provider (OpenAI/Anthropic/OpenRouter/Grok/
Mistral) would even appear in the dropdown — so a provider configured purely through Admin -> AI providers -> Add LLM
Provider (the entire point of that feature; no .env edit required) never showed up in AI Chat at all. This is the
most likely exact cause of "I configure one Provider and I can't use it on AI Chat."

  python tests/test_llm_chat_provider_visibility.py
"""
import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

SRC = open(os.path.join(ROOT, "app", "api", "v1", "tools.py"), encoding="utf-8").read()
section = SRC[SRC.index('@router.get("/payload-generator/llm-options")'):SRC.index('return {"providers": providers}') + 40]

t("a cloud provider's own saved API key is tracked (cfg_has_own_key), not just the .env variable",
  "cfg_has_own_key" in section and "c.api_key_encrypted" in section)
t("a provider appears if EITHER the .env key OR its own saved config key is present — not requiring BOTH",
  "if cloud_configured and (env_key or cfg_has_own_key.get(pid)):" in section)
t("the old AND-both-required condition is gone",
  "if cloud_configured and api_key:" not in section)

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
