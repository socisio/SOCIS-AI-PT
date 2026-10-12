"""Tests for API-key regenerate (rotate in place) and the security model behind the tokens page.

Requested: "after I create the API key I can see it after created, and I can regenerate not create new one."
The regenerate endpoint rotates a key's secret in place (same id/name/created_at) and returns the new raw key once.
The "see it after created" part is intentionally shown-once: the backend stores only a hash, never the raw key —
re-displaying a stored raw key would mean a DB leak exposes every key, so this test also pins that the raw key is
never persisted.

  python tests/test_api_key_regenerate.py
"""
import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

SRC = open(os.path.join(ROOT, "app", "api", "v1", "api_keys.py"), encoding="utf-8").read()

t("a regenerate endpoint exists", '@router.post("/{key_id}/regenerate"' in SRC)
reg = SRC[SRC.index("async def regenerate_api_key"):SRC.index("@router.delete")]
t("regenerate rotates the secret in place (new hash + prefix, same row)",
  "api_key.key_hash = key_hash" in reg and "api_key.prefix = raw_key[:12]" in reg)
t("regenerate returns the new raw key once (APIKeyCreatedResponse with raw_key)",
  "raw_key=raw_key" in reg and "APIKeyCreatedResponse" in reg)
t("regenerate keeps the key's identity (does NOT create a new row — no db.add of a new APIKey)",
  "db.add(" not in reg)
t("regenerate is scoped to the caller's own keys (user_id match)",
  "APIKey.user_id == UUID(token[\"sub\"])" in reg)
t("regenerate blocks API-key-authed callers (can't self-mint, like create/revoke)",
  'if token.get("via_api_key"):' in reg)
t("regenerate reactivates a revoked key and resets usage history",
  "api_key.is_active = True" in reg and "api_key.last_used_at = None" in reg)

# Security model: the raw key is never stored, only its hash.
MODEL = open(os.path.join(ROOT, "app", "models", "api_key.py"), encoding="utf-8").read()
_col_lines = [l for l in MODEL.splitlines() if "mapped_column" in l]
t("the model stores only a hash of the key, never the raw value (re-display is impossible by design)",
  any("key_hash" in l for l in _col_lines) and not any(re.search(r"\braw", l) for l in _col_lines))
t("the create path returns raw_key but does not persist it", "raw_key, key_hash = APIKey.generate()" in SRC and "key_hash=key_hash" in SRC)

# Frontend wiring
FE = os.path.join(ROOT, "..", "frontend", "src")
API = open(os.path.join(FE, "lib", "api.ts"), encoding="utf-8").read()
t("the API client has apiKeysApi.regenerate", "regenerate: (id: string)" in API and "/regenerate`" in API)
TOK = open(os.path.join(FE, "components", "settings", "TokensSection.tsx"), encoding="utf-8").read()
t("the tokens UI has a Regenerate action per token", "const regenerate = async" in TOK and "onClick={() => regenerate(t)}" in TOK)
t("regenerate surfaces the new key via the same shown-once banner", "setFresh(r.data.raw_key)" in TOK)
t("regenerate confirms first (destructive — old secret stops working)", "askConfirm(" in TOK and "Regenerate token" in TOK)

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
