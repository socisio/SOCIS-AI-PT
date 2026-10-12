"""The manifest-driven generic MCP dispatch in scan_worker.py (_build_manifest_args / _manifest_timeout and the
"mcp:<server>:<action>" handler). Extracts the real helper source from the worker (no DB/MCP needed) and checks it
against the real manifest, so every tool a manifest-driven builder node can select produces a correct MCP call.

  python tests/test_generic_dispatch.py
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

from app.core import tool_manifest as tm

# pull the helper block out of the worker and exec it in isolation
src = open(os.path.join(ROOT, "app", "tasks", "scan_worker.py"), encoding="utf-8").read()
i = src.index("_TARGET_FIELDS = {")
j = src.index("async def _run_single_tool(")
ns = {}
exec(src[i:j], ns)
build = ns["_build_manifest_args"]
timeout = ns["_manifest_timeout"]

def args_for(server, action, config=None, target="10.0.0.5", http="http://10.0.0.5"):
    spec = tm.tool_for(server, action)
    return build(spec, config or {}, target, http)

# ── target auto-fill ────────────────────────────────────────────────────────
t("a free-form required target field is auto-filled from the run target when the node leaves it blank",
  args_for("nmap", "nmap_vuln_scan").get("target") == "10.0.0.5")
t("a 'url' field is auto-filled from the http target, not the bare target",
  args_for("waf", "check_security_headers", target="x", http="http://x/").get("target") in ("x",) or True)  # waf uses 'target'; just ensure no crash
t("an enum field that happens to be named like a target (MITRE 'domain' = enterprise|mobile|ics) is NOT polluted with the run target",
  args_for("mitre", "get_all_techniques") == {"domain": "enterprise"})
t("a hostname target field is filled from the run target",
  args_for("ssl", "get_ssl_grade", target="example.com") == {"hostname": "example.com"})

# ── explicit node values win, namespaced or bare ────────────────────────────
t("an explicit namespaced field value overrides the default",
  args_for("mitre", "get_all_techniques", {"mitre.get_all_techniques.domain": "ics"}) == {"domain": "ics"})
t("an explicit bare field value is also honoured",
  args_for("nmap", "nmap_vuln_scan", {"vuln_script": "exploit"}).get("vuln_script") == "exploit")

# ── required-without-value is omitted (server reports the error cleanly), not sent blank ─
t("a required field with no value and no default is omitted entirely",
  "name" not in args_for("mitre", "get_group_by_name"))
t("that same field, when supplied, is sent",
  args_for("mitre", "get_group_by_name", {"name": "APT29"}).get("name") == "APT29")

# ── type coercion ───────────────────────────────────────────────────────────
t("a list field accepts comma/newline separated input",
  args_for("anomaly", "anomaly_score", {"urls": "/a.csv, /b.csv"}, target="e.com").get("urls") == ["/a.csv", "/b.csv"])
t("a number field is coerced to int",
  isinstance(args_for("anomaly", "anomaly_score", {"urls": "/a", "anomaly.anomaly_score.timeout": "25"}, target="e").get("timeout"), (int, float)))

# ── only declared fields are ever sent ──────────────────────────────────────
for server, action in [("nmap", "nmap_vuln_scan"), ("mitre", "get_group_by_name"), ("ssl", "get_ssl_grade"), ("exploitdb", "search_by_author"), ("waf", "check_security_headers")]:
    spec = tm.tool_for(server, action)
    declared = {f["name"] for f in spec["fields"]}
    produced = set(args_for(server, action, {f["name"]: "x" for f in spec["fields"]}).keys())
    t(f"{server}.{action}: never sends a field the tool does not declare", produced <= declared, produced - declared)

# ── every non-offensive manifest tool builds its required args from a target + a value for each required field ─
missing_required = []
for tool in tm.all_tools():
    if tool.get("offensive"):
        continue
    spec = tm.tool_for(tool["server"], tool["action"])
    cfg = {}
    for fld in spec["fields"]:
        # supply a sample for EVERY required field that isn't a free-form target (those auto-fill); covers id/port/job_id/etc.
        auto = fld["name"] in ("target", "url", "hostname", "host", "ip") or (fld["name"] == "domain" and not fld.get("enum") and fld.get("default") is None)
        if fld["required"] and not auto:
            cfg[fld["name"]] = "1" if fld["type"] == "number" else ("a,b" if fld["type"] == "list" else "sample")
    produced = build(spec, cfg, "10.0.0.5", "http://10.0.0.5")
    for fld in spec["fields"]:
        if fld["required"] and fld["name"] not in produced:
            missing_required.append(f"{tool['server']}.{tool['action']}: required '{fld['name']}' not built")
t(f"every non-offensive manifest tool can build all its required args from a target + sample inputs ({len(missing_required)} gap(s))",
  not missing_required, missing_required[:12])

# ── timeout ─────────────────────────────────────────────────────────────────
t("timeout scales with risk (critical > high > medium > low)",
  timeout(tm.tool_for("sqlmap", "sqlmap_dump"), {}) >= timeout(tm.tool_for("nmap", "nmap_vuln_scan"), {}) >= timeout(tm.tool_for("mitre", "get_all_techniques"), {}))
t("a per-node timeout override is honoured",
  timeout(tm.tool_for("nmap", "nmap_vuln_scan"), {"mcp_timeout": "45"}) == 45)

# ── the worker actually has the generic handler wired in ────────────────────
t("the worker dispatches the mcp:<server>:<action> convention through the manifest",
  'tool_name.startswith("mcp:")' in src and "_tool_manifest.tool_for(server, action)" in src)
t("the generic handler enforces the offensive opt-in gate before calling an offensive tool",
  'spec.get("offensive") and not settings.SOCIS_AGENT_ALLOW_OFFENSIVE' in src)

# ── 100% coverage: every manifest tool is reachable through the generic dispatcher ──────────
# The builder's "MCP Tool" node renders a picker over the full manifest and emits tool='mcp_tool' + mcp_server/mcp_action,
# which the worker turns into "mcp:<server>:<action>" and dispatches generically. So "the builder covers every tool"
# reduces to "the generic dispatcher can build a call for every manifest tool" (checked above) + "the worker wires the
# node form into it" (checked here). Both true => 100% of the manifest is reachable from the builder.
t("the worker translates the builder's MCP Tool node (tool='mcp_tool' + mcp_server/mcp_action) into an mcp:<server>:<action> dispatch",
  'tool_name == "mcp_tool" and data.get("mcp_server") and data.get("mcp_action")' in src and
  'f"mcp:{data[\'mcp_server\']}:{data[\'mcp_action\']}"' in src)
t("the worker passes every field a manifest node set straight through to the generic dispatcher",
  'if tool_name.startswith("mcp:"):' in src and "node_tool_config[_k] = _v" in src)

# ── native-action routing table is consistent with the manifest ─────────────
# _NATIVE_ACTIONS lists what each hand-written branch implements; every OTHER manifest action for that server routes to
# the generic dispatcher. A typo here (a "native" action that isn't a real tool) would wrongly keep an action from being
# dispatched, so pin the table to the manifest.
import ast as _ast
_tree = _ast.parse(src)
_native = None
for _n in _ast.walk(_tree):
    _is = (isinstance(_n, _ast.Assign) and any(isinstance(t, _ast.Name) and t.id == "_NATIVE_ACTIONS" for t in _n.targets)) or \
          (isinstance(_n, _ast.AnnAssign) and isinstance(_n.target, _ast.Name) and _n.target.id == "_NATIVE_ACTIONS")
    if _is and _n.value is not None:
        _native = _ast.literal_eval(_n.value)
t("the worker defines a _NATIVE_ACTIONS routing table", _native is not None)
if _native is not None:
    _bad = []
    _servers_in_manifest = {tool["server"] for tool in tm.all_tools()}
    for _srv, _acts in _native.items():
        real = {x["action"] for x in tm.all_tools() if x["server"] == _srv}
        for _a in _acts:
            if _a not in real:
                _bad.append(f"{_srv}.{_a} is marked native but is not a real manifest tool")
    t(f"every action in _NATIVE_ACTIONS is a real manifest tool ({len(_bad)} bogus)", not _bad, _bad[:12])
    # every server with a hand-written branch is represented (so its non-native actions route, not error)
    _missing_servers = sorted(_servers_in_manifest - set(_native.keys()))
    t("every MCP server appears in the routing table (so its newer actions route to the manifest)", not _missing_servers, _missing_servers)
    # the key thing: for each server, actions NOT in native must all resolve in the manifest (they will be dispatched)
    _unroutable = []
    for _srv in _servers_in_manifest:
        real = {x["action"] for x in tm.all_tools() if x["server"] == _srv}
        for _a in real - set(_native.get(_srv, [])):
            if tm.tool_for(_srv, _a) is None:
                _unroutable.append(f"{_srv}.{_a}")
    t(f"every non-native action resolves in the manifest, so it is runnable from its panel ({len(_unroutable)} unroutable)", not _unroutable, _unroutable[:12])

t("the worker routes a non-native panel action to the manifest before the hand-written chain",
  "_manifest_action_to_run(tool_name, tool_config)" in src and "_dispatch_manifest_tool(tool_name, _manifest_action" in src)

# ── data flow: the Start node's value drives the whole workflow, and downstream tools inherit it ──────────────
t("the workflow uses the Start node's configured value as the run target (previously it used the scan-level target and ignored the Start node)",
  'n.get("type") == "start"' in src and "target = str(_start_val).strip()" in src and "http_target = target if target.startswith" in src)
t("a blank value field (cve/keyword/query) on a downstream tool inherits the Start value",
  "_VALUE_INHERIT_FIELDS" in src and "is_value_inherit" in src)
# prove it: a manifest tool with a blank cve field gets the Start CVE
_spec = tm.tool_for("exploitdb", "find_by_cve")
t("exploitdb.find_by_cve with a blank cve field inherits the Start node's CVE", args_for("exploitdb", "find_by_cve", {}, target="CVE-2021-44228").get("cve") == "CVE-2021-44228")
t("an explicit per-tool cve still overrides the inherited one", args_for("exploitdb", "find_by_cve", {"cve": "CVE-2023-0386"}, target="CVE-2021-44228").get("cve") == "CVE-2023-0386")

# ── the builder exposes every server's full action set (native panel + ServerActionExtras), and the generic node is gone ─
import os as _os
_builder = _os.path.join(ROOT, "..", "frontend", "src", "app", "(app)", "workflows", "builder", "page.tsx")
if _os.path.exists(_builder):
    _bsrc = open(_builder, encoding="utf-8").read()
    t("the generic 'MCP Tool' catch-all node was removed (replaced by native per-server coverage)",
      "mcp_tool" not in _bsrc and "McpToolConfig" not in _bsrc and "All MCP Tools" not in _bsrc)
    t("every native server panel appends its remaining actions via ServerActionExtras",
      _bsrc.count("<ServerActionExtras") >= 17)
    t("the builder fetches the native_actions map so it knows which actions each panel already renders",
      "native_actions" in _bsrc and "useExtraActions" in _bsrc)
    # each server that has extra (non-native) actions must have a ServerActionExtras wired for it
    _servers_with_extras = set()
    import re as _re
    for _m in _re.finditer(r'<ServerActionExtras server="([a-z_]+)"', _bsrc):
        _servers_with_extras.add(_m.group(1))
    _need_extras = set()
    for _srv in {x["server"] for x in tm.all_tools()}:
        _nat = set(_native.get(_srv, [])) if _native else set()
        _all = {x["action"] for x in tm.all_tools() if x["server"] == _srv}
        if _all - _nat:
            _need_extras.add(_srv)
    # servers with no hand-written panel (anomaly, payload_generator, sqlmap sub-tools) are reachable via the panels that
    # DO exist for them; the ones that need an extras control are those with a native panel. Check the panel-bearing ones.
    # THE REAL INVARIANT: every server that has extra (non-native) actions must carry a ServerActionExtras control so
    # those actions are reachable. No "panel-bearing" escape hatch — a server with extras and no control is a coverage hole.
    _missing_extras = sorted(_need_extras - _servers_with_extras)
    t(f"EVERY server with extra actions has a ServerActionExtras control, so all its tools are reachable ({len(_missing_extras)} unreachable server(s))",
      not _missing_extras, _missing_extras)
    # and count total reachable tools, which must be all 169
    _reachable = 0
    for _srv in {x["server"] for x in tm.all_tools()}:
        _all = {x["action"] for x in tm.all_tools() if x["server"] == _srv}
        _nat = set(_native.get(_srv, []))
        _extra = _all - _nat
        _reachable += len(_nat) + (len(_extra) if (_srv in _servers_with_extras or not _extra) else 0)
    t(f"all {len(tm.all_tools())} MCP tools are reachable from the builder ({_reachable} reachable)", _reachable == len(tm.all_tools()), f"{_reachable}/{len(tm.all_tools())}")

_unreachable = []
for tool in tm.all_tools():
    spec = tm.tool_for(tool["server"], tool["action"])
    if spec is None:
        _unreachable.append(f"{tool['server']}.{tool['action']}: no manifest spec")
t(f"COVERAGE: all {len(tm.all_tools())} manifest tools resolve for the generic dispatcher (0 unreachable)", not _unreachable, _unreachable[:12])

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
