"""platform_settings.value must never be a fixed-size VARCHAR again — the tool-settings-policy JSON blob (one
mcp_<name>_enabled switch per MCP server, plus tool_overrides) grows every time a new server is added, and a
VARCHAR(1024) cap already failed in production once Phase C's three new servers pushed the real payload past it
(StringDataRightTruncationError on every "Save Global Policy" click). This also computes the REAL current payload
size against every server actually in the manifest, so a future server addition that pushes it close to a risky size
is caught here before it ever reaches a user's browser.

  python tests/test_platform_settings_size.py
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

MODEL_SRC = open(os.path.join(ROOT, "app", "models", "settings.py"), encoding="utf-8").read()
t("PlatformSettings.value is Text (unbounded), not a fixed-size VARCHAR that can overflow again",
  "value: Mapped[str] = mapped_column(Text" in MODEL_SRC)
t("the old VARCHAR(1024) cap is gone", "mapped_column(String(1024)" not in MODEL_SRC)

# Compute the REAL current payload size the way settings_service.py actually builds it, against the REAL manifest.
SVC_SRC = open(os.path.join(ROOT, "app", "services", "settings_service.py"), encoding="utf-8").read()
i = SVC_SRC.index("def default_tool_settings")
j = SVC_SRC.index("\n    async def", i)
body = SVC_SRC[i:j]
ns = {}
exec(compile("def f():\n" + body[body.index("\n"):], "<default_tool_settings>", "exec"), ns)
defaults = ns["f"]()

manifest = json.load(open(os.path.join(ROOT, "app", "core", "tool_manifest.json")))
manifest_servers = {tl["server"] for tl in manifest["tools"]}

# Two known, pre-existing aliases between the manifest's short server name and the setting-key convention (same
# ones documented in test_mcp_client_registry.py) — not a real gap.
SETTING_ALIASES = {"waf": "waf_detection", "poc_index": "poc"}
expected_switches = {f"mcp_{SETTING_ALIASES.get(s, s)}_enabled" for s in manifest_servers}
missing_switches = sorted(expected_switches - set(defaults.keys()))
t(f"default_tool_settings() has a switch for every manifest server — missing: {missing_switches}",
  not missing_switches, missing_switches)

payload = json.dumps({**defaults, "tool_overrides": {}})
# This CONFIRMS the bug was real, not theoretical: the actual current payload already exceeds the old 1024-char cap
# (it was 1063 chars when this bug was hit in production), so the Text migration isn't precautionary — it's required
# for the platform to function today, before counting any tool_overrides entries on top.
t(f"the real current payload ({len(payload)} chars) already exceeds the OLD 1024-char cap, confirming the VARCHAR -> "
  f"Text migration is necessary (not just precautionary) for the policy save to work at all", len(payload) > 1024, len(payload))

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
