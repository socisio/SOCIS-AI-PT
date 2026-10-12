"""Does the AI chat's tool reference (system_prompt.py) actually match what the MCP tool servers will accept?

Each MCP server's TOOLS list (mcp-servers/*_server.py) is extracted with ast.literal_eval — real data, not a
reimplementation or a regex guess — and compared against every [MCP: server.tool {...}] example anywhere in
services/system_prompt.py: does the server/tool exist, is every required field present, is every field used one the
tool actually has. Found 101 real mismatches across 38 tools in 10 servers on first run (e.g. wpscan examples sent
"target" when the real field is "url"; sqlmap's example sent "url"/"options" when the real fields are
"target"/"level"/"risk"; masscan_range's example never sent its only required field, "cidr", at all). A tool whose
documented example cannot satisfy its own schema will fail every time the model copies it.

  python tests/test_mcp_tool_reference.py
"""
import ast, glob, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
MCP_DIR = os.path.join(ROOT, "..", "mcp-servers")
sys.path.insert(0, ROOT)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)


def _literal_or_none(node):
    try:
        return ast.literal_eval(node)
    except ValueError:
        return None


def extract_tools(path: str):
    """The server's real TOOLS list, read as data (ast.literal_eval), never imported or executed. Tolerates a non-literal
    property value inside inputSchema (e.g. an `enum` built from `list(SOME_DICT.keys())`) by keeping everything else."""
    tree = ast.parse(open(path, encoding="utf-8").read(), filename=path)
    for node in ast.walk(tree):
        is_tools = (isinstance(node, ast.Assign) and any(isinstance(x, ast.Name) and x.id == "TOOLS" for x in node.targets)) or \
                   (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "TOOLS")
        if not is_tools:
            continue
        if not isinstance(node.value, ast.List):
            return None
        tools = []
        for el in node.value.elts:
            if not isinstance(el, ast.Dict):
                continue
            d = {}
            for k, v in zip(el.keys, el.values):
                key = _literal_or_none(k)
                if key is None:
                    continue
                val = _literal_or_none(v)
                if val is None and isinstance(v, ast.Dict):
                    val = {}
                    for k2, v2 in zip(v.keys, v.values):
                        k2v = _literal_or_none(k2)
                        if k2v is not None:
                            val[k2v] = _literal_or_none(v2) if _literal_or_none(v2) is not None else "<non-literal>"
                d[key] = val
            tools.append(d)
        return tools
    return None


def build_catalog():
    cat = {}
    for f in sorted(glob.glob(os.path.join(MCP_DIR, "*_server.py"))):
        if f.endswith("template_server.py"):
            continue
        tools = extract_tools(f)
        if not tools:
            continue
        cat[os.path.basename(f)] = []
        for tool in tools:
            schema = tool.get("inputSchema") or {}
            if not isinstance(schema, dict):
                schema = {}
            props = schema.get("properties")
            cat[os.path.basename(f)].append({
                "name": tool.get("name"),
                "required": schema.get("required") or [],
                "properties": sorted(props.keys()) if isinstance(props, dict) else [],
            })
    return cat


def server_name_map():
    """registered MCP server name (e.g. "nmap_mcp") -> its source file, from the same table llm.py uses to gate tool calls."""
    src = open(os.path.join(ROOT, "app", "api", "v1", "llm.py"), encoding="utf-8").read()
    m = re.search(r'_MCP_SETTING_TO_SERVER: dict\[str, str\] = \{(.*?)\n\}', src, re.S)
    pairs = re.findall(r'"mcp_([a-z_]+)_enabled":\s*"([a-z_]+)_mcp"', m.group(1))
    return {f"{srv}_mcp": f"{short}_server.py" for short, srv in pairs}


def check_examples(prompt_text: str, tools_by_server: dict, ignore: set = frozenset()):
    """Every [MCP: server.tool {...}] in prompt_text, checked against tools_by_server. `ignore` holds (server, tool, line)
    triples allowed to fail JSON parsing — a known, correctly-named human-readable placeholder, e.g. {"port":N}."""
    problems = []
    for m in re.finditer(r'\[MCP:\s*([a-z0-9_]+)\.([a-z0-9_]+)\s*(\{[^\]]*?\})\]', prompt_text):
        srv, tool, argtext = m.group(1), m.group(2), m.group(3)
        ln = prompt_text[:m.start()].count("\n") + 1
        if srv not in tools_by_server:
            problems.append(("UNKNOWN_SERVER", ln, srv, tool, "")); continue
        tdefs = tools_by_server[srv]
        if tool not in tdefs:
            problems.append(("UNKNOWN_TOOL", ln, srv, tool, "")); continue
        try:
            args = json.loads(argtext)
        except Exception:
            if (srv, tool, ln) in ignore:
                continue
            problems.append(("BAD_JSON", ln, srv, tool, argtext[:60])); continue
        required, props = tdefs[tool]["required"], set(tdefs[tool]["properties"])
        missing = [r for r in required if r not in args]
        extra = [k for k in args if props and k not in props]
        if missing:
            problems.append(("MISSING_REQUIRED", ln, srv, tool, str(missing)))
        if extra:
            problems.append(("UNKNOWN_ARG", ln, srv, tool, str(extra)))
    return problems


# mcp-servers/ lives next to backend/ in the repository; the backend CONTAINER only has backend/, so this whole check runs on
# the host (verify.sh) and in CI, same as the other tests that need the real tool-server source.
_HAVE_MCP = os.path.isdir(MCP_DIR) and os.path.exists(os.path.join(MCP_DIR, "nmap_server.py"))
if not _HAVE_MCP:
    print("SKIP: mcp-servers/ not present here (this check runs on the host / verify.sh)")
else:
    CATALOG = build_catalog()
    SERVER_FILE = server_name_map()
    TOOLS_BY_SERVER = {srv: {x["name"]: x for x in CATALOG.get(fname, [])} for srv, fname in SERVER_FILE.items()}
    PROMPT = open(os.path.join(ROOT, "app", "services", "system_prompt.py"), encoding="utf-8").read()
    # the one deliberate placeholder line, correctly named (target, port are both real fields of nmap_mcp.port_check) but
    # written as {"target":"...","port":N} for readability in a natural-language cheat-sheet, not meant as literal JSON.
    KNOWN_PLACEHOLDERS = {("nmap_mcp", "port_check", 428)}

    t("every server file's TOOLS list was readable as data (ast.literal_eval), not just the ones with simple schemas", len(CATALOG) == len(SERVER_FILE) == 30)
    t("the extraction is exact: a known tool's required fields and full property list match hand-verified ground truth", TOOLS_BY_SERVER["nmap_mcp"]["nmap_scan"]["required"] == ["target"] and set(TOOLS_BY_SERVER["sqlmap_mcp"]["sqlmap_scan"]["properties"]) >= {"target", "level", "risk", "technique"})

    problems = check_examples(PROMPT, TOOLS_BY_SERVER, ignore=KNOWN_PLACEHOLDERS)
    t(f"every [MCP: server.tool {{...}}] example the AI chat is shown can actually be satisfied by the real tool's schema ({len(problems)} problem(s) found)", not problems, problems[:15])

    # this is the test that would have caught the original bug directly, independent of the full-file scan above
    WPSCAN = TOOLS_BY_SERVER["wpscan_mcp"]["wp_scan"]
    t("regression: wp_scan's required field really is 'url', not 'target' (the original, wrong example used 'target')", WPSCAN["required"] == ["url"] and "target" not in WPSCAN["properties"])
    MASSCAN = TOOLS_BY_SERVER["masscan_mcp"]["masscan_range"]
    t("regression: masscan_range's only required field really is 'cidr' (the original example never sent it)", MASSCAN["required"] == ["cidr"] and "start_ip" not in MASSCAN["properties"])
    SQLMAP = TOOLS_BY_SERVER["sqlmap_mcp"]["sqlmap_scan"]
    t("regression: sqlmap_scan takes 'target' (not 'url') and has no 'options' field at all", "target" in SQLMAP["required"] and "options" not in SQLMAP["properties"])

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
