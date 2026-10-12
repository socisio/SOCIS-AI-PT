"""The /findings AI-analysis endpoint must resolve the ADMIN-SAVED LLM config (Admin -> AI providers) the same way
scan_worker.py's run_scan_ai_analysis does, and must dispatch through the unified multi-provider llm_service.chat()
— not a hardcoded chat_ollama() call that ignores the saved config and only works for Ollama. Found via: the admin
page had a working Remote Ollama config, but every /findings "Analyze" click failed with "No Ollama server
configured" regardless of provider.

  python tests/test_findings_ai_analysis.py
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

SRC = open(os.path.join(ROOT, "app", "api", "v1", "findings.py"), encoding="utf-8").read()

t("the endpoint no longer calls chat_ollama directly (which ignored the admin-saved config)",
  "chat_ollama(" not in SRC)
t("it dispatches through the unified multi-provider llm_service.chat() instead",
  "llm_service.chat(" in SRC)
t("it resolves the admin-saved Ollama URL from the database (SettingsService), not only a request field or env var",
  "settings_service.get_ollama_remote_url(db)" in SRC)
t("it resolves the admin-saved default model from the database when the request didn't specify one",
  "settings_service.get_ollama_remote_model(db)" in SRC)
t("the provider string is normalised the same way scan_worker.py does (so 'ollama_local' / legacy names still work)",
  "normalize_provider(selected_provider)" in SRC)
t("a bad/unknown provider string falls back to Ollama rather than raising to the client",
  "except ValueError:" in SRC and "provider = LLMProvider.OLLAMA_REMOTE" in SRC)

# cross-check: no OTHER api endpoint still calls chat_ollama directly (the same bug could recur elsewhere)
import glob
other_offenders = []
for f in glob.glob(os.path.join(ROOT, "app", "api", "**", "*.py"), recursive=True):
    if f.endswith("findings.py"):
        continue
    if "chat_ollama(" in open(f, encoding="utf-8").read():
        other_offenders.append(os.path.relpath(f, ROOT))
t(f"no other API endpoint bypasses the unified dispatcher the same way — offenders: {other_offenders}",
  not other_offenders, other_offenders)

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
