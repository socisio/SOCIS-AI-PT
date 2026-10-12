"""Phase 0 guardrail for 100% builder coverage: the shared tool manifest (app/core/tool_manifest.json) is the single
source of truth the workflow builder renders from and the scan worker dispatches from. This test checks it against the
REAL MCP server schemas (mcp-servers/*_server.py, read as data with ast.literal_eval — not a reimplementation):

  * every real MCP tool has exactly one manifest entry (nothing missing, nothing invented);
  * every manifest field matches the real tool's schema (no wrong names, no missing required fields);
  * routing (server short-name) resolves for every entry;
  * the offensive set in the manifest matches core/ai_tool_policy.py's single source of truth.

Coverage of the BUILDER and the WORKER against this manifest is checked in their own tests as each phase lands; this
test pins the manifest itself to reality so that "the builder covers the manifest" transitively means "covers every
real tool".

  python tests/test_tool_manifest.py
"""
import ast, glob, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
MCP_DIR = os.path.join(ROOT, "..", "mcp-servers")
MANIFEST = os.path.join(ROOT, "app", "core", "tool_manifest.json")
sys.path.insert(0, ROOT)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

# short-name -> server source file (authoritative: mirrors MCP_URLS in scan_worker.py)
SHORT_TO_FILE = {
    "nmap": "nmap_server.py", "cve": "cve_server.py", "nuclei": "nuclei_server.py", "osint": "osint_server.py",
    "metasploit": "metasploit_server.py", "waf": "waf_detection_server.py", "ffuf": "ffuf_server.py",
    "sqlmap": "sqlmap_server.py", "ssl": "ssl_server.py", "cisa_kev": "cisa_kev_server.py", "epss": "epss_server.py",
    "poc_index": "poc_server.py", "nikto": "nikto_server.py", "masscan": "masscan_server.py", "wpscan": "wpscan_server.py",
    "jwt": "jwt_server.py", "gobuster": "gobuster_server.py", "cve_lite": "cve_lite_server.py", "anomaly": "anomaly_server.py",
    "payload_generator": "payload_generator_server.py", "exploitdb": "exploitdb_server.py", "mitre": "mitre_server.py",
    "ad": "ad_server.py",
    "cloud": "cloud_server.py",
    "container": "container_server.py",
    "api_security": "api_security_server.py",
    "secrets": "secrets_server.py",
    "dns_deep": "dns_deep_server.py",
    "crack": "crack_server.py",
    "compliance": "compliance_server.py",
}


def _lit(n):
    try: return ast.literal_eval(n)
    except Exception: return None


def extract_server(path):
    tree = ast.parse(open(path, encoding="utf-8").read(), filename=path)
    for node in ast.walk(tree):
        is_tools = (isinstance(node, ast.Assign) and any(isinstance(x, ast.Name) and x.id == "TOOLS" for x in node.targets)) or \
                   (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "TOOLS")
        if not (is_tools and isinstance(node.value, ast.List)):
            continue
        out = {}
        for el in node.value.elts:
            if not isinstance(el, ast.Dict): continue
            d = {_lit(k): v for k, v in zip(el.keys, el.values)}
            name = _lit(d.get("name"))
            schema = d.get("inputSchema")
            required, props = [], set()
            if isinstance(schema, ast.Dict):
                sd = {_lit(k): v for k, v in zip(schema.keys, schema.values)}
                required = _lit(sd.get("required")) or [] if sd.get("required") is not None else []
                pnode = sd.get("properties")
                if isinstance(pnode, ast.Dict):
                    props = {_lit(k) for k in pnode.keys if _lit(k) is not None}
            if name:
                out[name] = {"required": set(required), "properties": props}
        return out
    return {}


def build_real_catalog():
    cat = {}
    for short, fname in SHORT_TO_FILE.items():
        p = os.path.join(MCP_DIR, fname)
        if os.path.exists(p):
            cat[short] = extract_server(p)
    return cat


if not (os.path.isdir(MCP_DIR) and os.path.exists(os.path.join(MCP_DIR, "nmap_server.py"))):
    print("SKIP: mcp-servers/ not present here (this check runs on the host / verify.sh)")
    print(f"\nRESULT: {P} passed, {F} failed"); sys.exit(0)

manifest = json.load(open(MANIFEST, encoding="utf-8"))
real = build_real_catalog()
real_total = sum(len(v) for v in real.values())
mtools = manifest["tools"]
mkeys = {(x["server"], x["action"]) for x in mtools}

t("the manifest file is well-formed (version + a non-empty tools list)", isinstance(manifest.get("version"), int) and len(mtools) > 0)
t("every manifest entry routes to a known server short-name", all(x["server"] in SHORT_TO_FILE for x in mtools))
t("no duplicate (server, action) entries in the manifest", len(mkeys) == len(mtools))

# every real tool is present exactly once
real_keys = {(short, name) for short, tools in real.items() for name in tools}
missing_from_manifest = sorted(real_keys - mkeys)
invented_in_manifest = sorted(mkeys - real_keys)
t(f"THE COVERAGE INVARIANT: every one of the {real_total} real MCP tools has a manifest entry ({len(missing_from_manifest)} missing)", not missing_from_manifest, missing_from_manifest[:20])
t(f"the manifest invents no tool that does not exist on a server ({len(invented_in_manifest)} invented)", not invented_in_manifest, invented_in_manifest[:20])

# every manifest field matches the real schema; every required field is marked required
field_problems = []
req_problems = []
for x in mtools:
    spec = real.get(x["server"], {}).get(x["action"])
    if spec is None:
        continue  # already reported as invented
    real_props = spec["properties"]
    for fld in x["fields"]:
        if real_props and fld["name"] not in real_props:
            field_problems.append(f"{x['server']}.{x['action']}: field '{fld['name']}' not in real schema {sorted(real_props)}")
    manifest_field_names = {f["name"] for f in x["fields"]}
    for r in spec["required"]:
        if r not in manifest_field_names:
            req_problems.append(f"{x['server']}.{x['action']}: required field '{r}' missing from manifest")
        else:
            fld = next(f for f in x["fields"] if f["name"] == r)
            if not fld["required"]:
                req_problems.append(f"{x['server']}.{x['action']}: field '{r}' is required by the server but not marked required")
t(f"no manifest field uses a name the real tool does not have ({len(field_problems)} problem(s))", not field_problems, field_problems[:12])
t(f"every server-required field is present and marked required in the manifest ({len(req_problems)} problem(s))", not req_problems, req_problems[:12])

# the offensive set must match ai_tool_policy's single source of truth (so the builder gate and the chat gate agree)
try:
    from app.core.ai_tool_policy import OFFENSIVE_TOOLS, is_offensive
    manifest_offensive = {(x["server"], x["action"]) for x in mtools if x.get("offensive")}
    policy_offensive = {(x["server"], x["action"]) for x in mtools if is_offensive(x["server"], x["action"])}
    t("the manifest's offensive flags match core/ai_tool_policy (one definition of what needs the operator opt-in)",
      manifest_offensive == policy_offensive, sorted(manifest_offensive ^ policy_offensive)[:12])
except Exception as e:
    t("ai_tool_policy importable for the offensive cross-check", False, str(e))

print(f"\nManifest covers {len(mkeys)} of {real_total} real MCP tools.")
print(f"RESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
