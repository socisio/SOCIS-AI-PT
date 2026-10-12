"""Every real MCP server (per the manifest, the single source of truth for what servers exist) must be registered in
app/mcp/client.py — otherwise it is invisible on the /mcp admin page, the "Tools & MCP" admin section, and the "AI chat:
tool-by-tool" setting, even though it works fine in the workflow builder (which reads the manifest directly). This is
exactly the bug found in session review: the Active Directory server (and, pre-existing, anomaly/payload_generator) were
reachable from the builder but invisible in all three admin-facing surfaces because client.py's registration list is a
second, hand-maintained source of truth that the manifest-generation step does not touch.

  python tests/test_cve_propagation.py
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

CLIENT_SRC = open(os.path.join(ROOT, "app", "mcp", "client.py"), encoding="utf-8").read()
MANIFEST = json.load(open(os.path.join(ROOT, "app", "core", "tool_manifest.json")))

registered = set(re.findall(r'name="(\w+)_mcp"', CLIENT_SRC))
manifest_servers = {t["server"] for t in MANIFEST["tools"]}

# Two server short-names use a different registered name by a pre-existing, deliberate convention in two independent
# naming systems (the AI-chat direct-call code always uses the _mcp-suffixed registry name; the workflow
# builder/manifest uses the short name) — not a visibility gap. Documented here so this test doesn't flag them and a
# genuine future gap doesn't hide behind this allowance by accident.
KNOWN_ALIASES = {"waf": "waf_detection", "poc_index": "poc"}

missing = []
for s in sorted(manifest_servers):
    expected = KNOWN_ALIASES.get(s, s)
    if expected not in registered:
        missing.append(s)

t(f"every manifest server is registered in app/mcp/client.py (so it appears on /mcp, Tools & MCP, and the AI chat "
  f"tool-by-tool setting) — {len(missing)} missing", not missing, missing)

t("the new Active Directory server specifically is registered", "ad" in registered)
t("the pre-existing anomaly server is registered (was missing before this fix)", "anomaly" in registered)
t("the pre-existing payload_generator server is registered (was missing before this fix)", "payload_generator" in registered)

# the frontend /mcp page's icon map should have an entry for every server registered in client.py (a missing one just
# falls back to a generic icon — not a bug — but we want new/renamed servers to get a real icon deliberately, not by accident)
MCP_PAGE = os.path.join(ROOT, "..", "frontend", "src", "app", "(app)", "mcp", "page.tsx")
if os.path.exists(MCP_PAGE):
    page_src = open(MCP_PAGE, encoding="utf-8").read()
    icon_map = re.search(r"SERVER_ICONS[^{]*\{(.*?)\n\};", page_src, re.S)
    icons = set(re.findall(r"(\w+)_mcp:", icon_map.group(1))) if icon_map else set()
    no_icon = sorted(registered - icons)
    t(f"every registered server has a specific icon on the /mcp page (not just the generic fallback) — missing: {no_icon}",
      not no_icon, no_icon)

    # the EXACT bug that shipped: SERVER_ICONS had an entry for a server, but the page's own BUILTIN_SERVERS array (the
    # thing that actually drives the stat cards and the rendered server list) did not — so the page showed the old count
    # even though the live API, and even the icon map, were already correct.
    builtin_block = re.search(r"const BUILTIN_SERVERS = \[(.*?)\n\];", page_src, re.S)
    builtin_names = set(re.findall(r"name: '(\w+)_mcp'", builtin_block.group(1))) if builtin_block else set()
    missing_from_builtin = sorted(registered - builtin_names)
    t(f"every registered server is in the page's own BUILTIN_SERVERS array (not just SERVER_ICONS) — missing: {missing_from_builtin}",
      not missing_from_builtin, missing_from_builtin)

# the Global Tools & MCP Policy on/off switch (admin page) is a FOURTH hardcoded list, independent of the registry and
# BUILTIN_SERVERS — this is the exact gap the user hit: a server works in AI-chat tool-by-tool but has no on/off switch.
ADMIN_PAGE = os.path.join(ROOT, "..", "frontend", "src", "app", "(app)", "admin", "page.tsx")
if os.path.exists(ADMIN_PAGE):
    admin_src = open(ADMIN_PAGE, encoding="utf-8").read()
    switch_keys = set(re.findall(r"key: 'mcp_(\w+)_enabled'", admin_src))
    # map manifest short-names to the setting-key form (handles the two known aliases)
    SETTING_ALIASES = {"waf": "waf_detection", "poc_index": "poc"}
    expected_keys = {SETTING_ALIASES.get(s, s) for s in manifest_servers}
    missing_switch = sorted(expected_keys - switch_keys)
    t(f"every manifest server has an on/off switch in the admin page's Global Tools & MCP Policy — missing: {missing_switch}",
      not missing_switch, missing_switch)

# the backend's own settings_service.py default dict must also list every server (so a fresh install's defaults are complete)
SETTINGS_SVC = os.path.join(ROOT, "app", "services", "settings_service.py")
svc_src = open(SETTINGS_SVC, encoding="utf-8").read()
svc_keys = set(re.findall(r'"mcp_(\w+)_enabled"', svc_src))
missing_svc = sorted(expected_keys - svc_keys) if 'expected_keys' in dir() else []
t(f"every manifest server has a default in settings_service.py — missing: {missing_svc}", not missing_svc, missing_svc)

# the gap that bit us: a server can pass every check above (registered in client.py, visible on /mcp and in admin)
# while still being UNREACHABLE by real scans, because scan_worker.py's MCP_URLS (the actual routing table the
# worker uses to call a server) is a FIFTH independent list. Check it too.
WORKER_SRC = open(os.path.join(ROOT, "app", "tasks", "scan_worker.py"), encoding="utf-8").read()
mcp_urls_block = re.search(r"^MCP_URLS = \{(.*?)\n\}", WORKER_SRC, re.S | re.M)
worker_keys = set(re.findall(r'"(\w+)":\s*"http://mcp_all:\d+/mcp"', mcp_urls_block.group(1))) if mcp_urls_block else set()
missing_worker = sorted(manifest_servers - worker_keys)
t(f"every manifest server is routable in scan_worker.py's MCP_URLS (or a real scan can never reach it) — missing: {missing_worker}",
  not missing_worker, missing_worker)

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
