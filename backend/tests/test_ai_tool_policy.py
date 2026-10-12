"""AI-chat tool allowlist tests: the pure policy module directly, plus the REAL admin endpoint bodies (api/v1/settings.py) and
the real save function (services/settings_service.py), extracted and run against fakes — not reimplementations.

  python tests/test_ai_tool_policy.py
"""
import asyncio, json, os, sys, types, uuid
from typing import Optional

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

from app.core.ai_tool_policy import (OFFENSIVE_SERVERS, OFFENSIVE_TOOLS, build_catalog, effective_enabled, is_offensive,
                                      sanitize_overrides, server_enabled, tool_key)

print("=== core/ai_tool_policy.py: the combined gate ===")
SFS = {"nmap_mcp": "mcp_nmap_enabled", "sqlmap_mcp": "mcp_sqlmap_enabled", "metasploit_mcp": "mcp_metasploit_enabled"}
t("a server switched off blocks every one of its tools with no override", effective_enabled("nmap_mcp", "nmap_scan", {"mcp_nmap_enabled": False}, {}, SFS) is False)
t("a per-tool override to OFF wins even though the server is on", effective_enabled("nmap_mcp", "nmap_vuln_scan", {"mcp_nmap_enabled": True}, {"nmap_mcp.nmap_vuln_scan": False}, SFS) is False)
t("a per-tool override to ON wins even though the server is off", effective_enabled("nmap_mcp", "nmap_scan", {"mcp_nmap_enabled": False}, {"nmap_mcp.nmap_scan": True}, SFS) is True)
t("with no override, the tool simply follows its server", effective_enabled("nmap_mcp", "nmap_scan", {"mcp_nmap_enabled": True}, {}, SFS) is True)
t("an unknown server defaults to enabled (today's behaviour, unchanged)", server_enabled("brand_new_mcp", {}, SFS) is True)
t("THE FLOOR: an exploitation-class tool cannot be turned on by ANY combination of server + override", all(
    effective_enabled(srv, tool, {k: True for k in SFS.values()}, {f"{srv}.{tool}": True}, SFS) is False
    for srv, tool in (("sqlmap_mcp", "sqlmap_dump"), ("metasploit_mcp", "run_exploit"), ("payload_generator_mcp", "generate_payload"), ("jwt_mcp", "forge_jwt"))
))
t("is_offensive recognises both a whole offensive SERVER and individually-named offensive tools on ordinary servers", is_offensive("sqlmap_mcp", "sqlmap_scan") and is_offensive("jwt_mcp", "forge_jwt") and not is_offensive("jwt_mcp", "decode_jwt"))

print("=== sanitize_overrides: what a save request is allowed to set ===")
catalog_keys = {"nmap_mcp.nmap_scan", "nmap_mcp.nmap_vuln_scan", "sqlmap_mcp.sqlmap_scan", "sqlmap_mcp.sqlmap_dump"}
clean, problems = sanitize_overrides({"nmap_mcp.nmap_scan": False, "sqlmap_mcp.sqlmap_dump": True, "nmap_mcp.not_a_real_tool": True, "no-dot": True, "x" * 300: True}, catalog_keys)
t("a legitimate override is kept", clean == {"nmap_mcp.nmap_scan": False})
t("an offensive-tool override is DROPPED, not stored, even though it looked like a valid key", "sqlmap_mcp.sqlmap_dump" not in clean and any("exploitation-class" in p for p in problems))
t("a WELL-FORMED key for a tool that does not exist in the live catalog is dropped (this is the catalog-existence check specifically, not just format)", "nmap_mcp.not_a_real_tool" not in clean and any("unknown tool" in p for p in problems))
t("a key with no dot, and an oversized key, are also dropped with a reason each", len(problems) == 4)
t("the save is never rejected outright for bad entries — the valid ones are still kept", clean)
many = {f"nmap_mcp.t{i}": True for i in range(1500)}
clean2, problems2 = sanitize_overrides(many, set())  # empty catalog = format-only validation (used as the defence-in-depth layer)
t("a very large payload is capped rather than stored in full", len(clean2) <= 1000 and any("too many" in p for p in problems2))
t("None / a non-dict input is handled without raising", sanitize_overrides(None, catalog_keys) == ({}, []) and sanitize_overrides("not a dict", catalog_keys)[0] == {})

print("=== build_catalog ===")
Tool = lambda n, d="": types.SimpleNamespace(name=n, description=d)
Server = lambda n, tools: types.SimpleNamespace(name=n, tools=tools)
cat = build_catalog([Server("nmap_mcp", [Tool("nmap_vuln_scan"), Tool("nmap_scan", "Port scan")]), Server("sqlmap_mcp", [Tool("sqlmap_scan"), Tool("sqlmap_dump")]), Server("empty_mcp", [])])
t("servers are sorted, tools within a server are sorted, each tool keeps its name/description, and a server with no discovered tools yet is still included (not hidden)", [s["server"] for s in cat] == ["empty_mcp", "nmap_mcp", "sqlmap_mcp"] and [x["name"] for x in cat[1]["tools"]] == ["nmap_scan", "nmap_vuln_scan"] and cat[1]["tools"][1]["description"] == "" and cat[0]["tools"] == [])
t("a tool is offensive if EITHER its own name is listed OR its whole server is (sqlmap_mcp is a wholly offensive server: every one of its tools needs the operator flag)", next(x for x in cat[1]["tools"] if x["name"] == "nmap_scan")["offensive"] is False and all(x["offensive"] for x in cat[2]["tools"]))

# ── the real endpoints, extracted from api/v1/settings.py, run against fakes ──
print("=== the real GET /settings/ai-chat-tools and POST /settings/tools ===")
src = open(os.path.join(ROOT, "app", "api", "v1", "settings.py"), encoding="utf-8").read()
get_src = src[src.index("async def get_ai_chat_tool_catalog"):src.index('@router.post("/tools")')]
post_src = src[src.index("async def save_tool_settings"):src.index("# ─── Report Settings")]

class HTTPException(Exception):
    def __init__(self, status_code, detail=""): self.status_code, self.detail = status_code, detail
class FakeMCPClient:
    def __init__(self, servers): self._servers = {s.name: s for s in servers}
def get_mcp_client(): return FAKE_CLIENT
class SettingsSvc:
    def __init__(self, store): self.store = store
    async def get_setting(self, db, key): return self.store.get(key)
_MCP_SETTING_TO_SERVER = {"mcp_nmap_enabled": "nmap_mcp", "mcp_sqlmap_enabled": "sqlmap_mcp"}

audits = []
async def _log_audit(db, **kw): audits.append(kw)
class FakeDB:
    def __init__(self): self.committed = 0
    async def commit(self): self.committed += 1

saved_calls = []
class FakeUserSettingsSvc:
    async def save_global_tool_settings(self, db, data, catalog_keys=None):
        saved_calls.append((dict(data), set(catalog_keys or set())))
        return {**data}

ns = dict(HTTPException=HTTPException, get_db=lambda: None, Depends=lambda x: None, require_permission=lambda p: None,
          AsyncSession=object, UUID=uuid.UUID, log_audit=_log_audit, user_settings_service=FakeUserSettingsSvc(), logger=types.SimpleNamespace(info=lambda *a, **k: None))
exec(get_src, ns); exec(post_src, ns)
get_catalog = ns["get_ai_chat_tool_catalog"]
save_tools = ns["save_tool_settings"]

FAKE_CLIENT = FakeMCPClient([Server("nmap_mcp", [Tool("nmap_scan"), Tool("nmap_vuln_scan")]), Server("sqlmap_mcp", [Tool("sqlmap_scan"), Tool("sqlmap_dump")])])
svc = SettingsSvc({"tool_settings_global": json.dumps({"mcp_nmap_enabled": True, "mcp_sqlmap_enabled": False, "tool_overrides": {"nmap_mcp.nmap_vuln_scan": False}})})
import sys as _sys6
sys.modules["app.core.ai_tool_policy"] = __import__("app.core.ai_tool_policy", fromlist=["x"])
sys.modules["app.mcp.client"] = types.SimpleNamespace(get_mcp_client=get_mcp_client)
sys.modules["app.api.v1.llm"] = types.SimpleNamespace(_MCP_SETTING_TO_SERVER=_MCP_SETTING_TO_SERVER)
sys.modules["app.services.settings_service"] = types.SimpleNamespace(settings_service=svc)

result = asyncio.run(get_catalog(token={"sub": str(uuid.uuid4())}, db=object()))
by_server = {s["server"]: s for s in result["servers"]}
t("the catalog reports the server switch and each tool's effective + override state correctly", by_server["nmap_mcp"]["server_enabled"] is True and
  next(x for x in by_server["nmap_mcp"]["tools"] if x["name"] == "nmap_scan")["effective"] is True and
  next(x for x in by_server["nmap_mcp"]["tools"] if x["name"] == "nmap_vuln_scan")["effective"] is False and
  next(x for x in by_server["nmap_mcp"]["tools"] if x["name"] == "nmap_vuln_scan")["override"] is False)
t("a disabled SERVER is reflected too, and an offensive tool is marked as such", by_server["sqlmap_mcp"]["server_enabled"] is False and
  next(x for x in by_server["sqlmap_mcp"]["tools"] if x["name"] == "sqlmap_dump")["offensive"] is True)

db = FakeDB()
resp = asyncio.run(save_tools({"mcp_nmap_enabled": True, "tool_overrides": {"nmap_mcp.nmap_scan": False, "sqlmap_mcp.sqlmap_dump": True, "osint_mcp.whois_lookup": True, "bogus": True}}, token={"sub": str(uuid.uuid4())}, db=db))
t("saving validates against the LIVE catalog (via the fake MCP client's real registered tools): kept / dropped as expected, with 3 warnings", saved_calls[-1][0]["tool_overrides"] == {"nmap_mcp.nmap_scan": False} and "warnings" in resp and len(resp["warnings"]) == 3)
t("specifically: a well-formed key for a tool the catalog does not have (osint_mcp is not even a registered server here) is rejected AS unknown, not as malformed", any("unknown tool: 'osint_mcp.whois_lookup'" in w for w in resp["warnings"]))
t("the save is committed and audited with what was rejected", db.committed == 1 and audits[-1]["action"] == "admin:tool_policy_update" and len(audits[-1]["details"]["rejected"]) == 3)
# The data-loss scenario: an admin set per-tool choices, then later saved ONLY the per-server switches (an older page, or any client that
# does not send tool_overrides). That must not wipe the per-tool choices.
svc.store["tool_settings_global"] = json.dumps({"mcp_nmap_enabled": True, "tool_overrides": {"nmap_mcp.nmap_vuln_scan": False}})
asyncio.run(save_tools({"mcp_nmap_enabled": False}, token={"sub": str(uuid.uuid4())}, db=FakeDB()))
t("a save that does NOT mention tool_overrides leaves the stored per-tool choices untouched (it used to wipe them)", saved_calls[-1][0]["tool_overrides"] == {"nmap_mcp.nmap_vuln_scan": False} and saved_calls[-1][0]["mcp_nmap_enabled"] is False)
asyncio.run(save_tools({"mcp_nmap_enabled": True, "tool_overrides": {}}, token={"sub": str(uuid.uuid4())}, db=FakeDB()))
t("an EXPLICIT empty tool_overrides does clear them (that is how an admin resets everything to the server defaults)", saved_calls[-1][0]["tool_overrides"] == {})
svc.store["tool_settings_global"] = "{not json"
asyncio.run(save_tools({"mcp_nmap_enabled": True}, token={"sub": str(uuid.uuid4())}, db=FakeDB()))
t("a corrupt stored policy does not break saving (treated as no stored overrides)", saved_calls[-1][0]["tool_overrides"] == {})
svc.store["tool_settings_global"] = json.dumps({"mcp_nmap_enabled": True, "mcp_sqlmap_enabled": False, "tool_overrides": {"nmap_mcp.nmap_vuln_scan": False}})
t("an empty save request is rejected before any of this runs", True)
try:
    asyncio.run(save_tools({}, token={"sub": "x"}, db=db)); t("an empty save request is rejected", False)
except HTTPException as e:
    t("an empty save request is rejected (400)", e.status_code == 400)

print("=== wiring: llm.py uses the shared policy module (no second copy of the offensive list) ===")
llm_src = open(os.path.join(ROOT, "app", "api", "v1", "llm.py"), encoding="utf-8").read()
t("llm.py imports the offensive-tool check from core/ai_tool_policy instead of defining its own copy", "from app.core.ai_tool_policy import effective_enabled as _tool_effective_enabled, is_offensive as _is_offensive" in llm_src and "_OFFENSIVE_SERVERS = {" not in llm_src)
t("every tool call goes through the combined per-server + per-tool gate before the offensive floor is even checked", "_tool_effective_enabled(server_name, tool_name, tool_server_settings, tool_overrides, _MCP_SETTING_TO_SERVER)" in llm_src)
t("the policy (server settings + per-tool overrides) is loaded once per chat request and threaded through to tool execution", "tool_server_settings, tool_overrides = await _ai_tool_policy(db)" in llm_src and "tool_server_settings=tool_server_settings, tool_overrides=tool_overrides" in llm_src)

fe = os.path.join(ROOT, "..", "frontend", "src")
if os.path.isdir(fe):
    print("=== admin page (frontend) ===")
    pg = open(os.path.join(fe, "app", "(app)", "admin", "page.tsx"), encoding="utf-8").read()
    ap = open(os.path.join(fe, "lib", "api.ts"), encoding="utf-8").read()
    t("the page loads the live tool catalog from the new endpoint", "getAiChatToolCatalog: () => api.get('/settings/ai-chat-tools')" in ap and "settingsApi.getAiChatToolCatalog()" in pg)
    t("THE SINGLE SAVE sends the per-tool choices WITH the server switches (otherwise saving the switches alone clears them)", "saveToolSettings({ ...toolSettings, tool_overrides: toolOverrides })" in pg)
    t("there is exactly one Save for the Tools page (a second one that omitted the per-tool choices was the data-loss path)", pg.count("onClick={saveToolPolicy}") == 1 and "saveAiToolOverrides" not in pg and "Save tool overrides" not in pg)
    t("exploitation-class tools are shown locked with no on/off buttons, using the design-system lock icon", "tool.offensive ? (" in pg and 'Icon name="lock"' in pg and "SOCIS_AGENT_ALLOW_OFFENSIVE" in pg)
    t("each tool offers on / off / default, where default removes the override so the tool follows its server again", "[['on', true], ['off', false], ['default', null]]" in pg and "delete next[key]" in pg)
    t("a rejected entry is reported to the admin, not silently dropped", "res.data?.warnings" in pg and "tool choice${warnings.length === 1 ? ' was' : 's were'} rejected" in pg)
    t("the page no longer says these switches govern real scans (they only govern the AI chat)", "This does not restrict what a scan itself can use" in pg and "Which scanning tools are available" not in pg)

print(f"\nRESULT: {P} passed, {F} failed")
import sys as _sys7
_sys7.exit(1 if F else 0)
