"""Does every MCP call the scan worker makes (tasks/scan_worker.py::_run_single_tool, what runs when you pick a scan type or
workflow) match what the tool server will accept?

The worker source is parsed with `ast` (never executed): for each call to _call_mcp_tool(MCP_URLS["x"], tool, args) the tool name and
the argument keys are recovered — literally when the call spells them out, by tracing assignments inside the same `tool_name == ...`
branch when the arguments are built up in a variable — and compared with the server's real TOOLS schema (read as data with
ast.literal_eval, same extraction as test_mcp_tool_reference.py).

  python tests/test_worker_tool_calls.py          # prints the findings table with --report
"""
import ast, glob, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
MCP_DIR = os.path.join(ROOT, "..", "mcp-servers")
WORKER = os.path.join(ROOT, "app", "tasks", "scan_worker.py")
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

# MCP_URLS key (the worker's short name) -> the server source file that implements it. sqlmap_full shares sqlmap's server.
KEY_TO_FILE = {
    "nmap": "nmap_server.py", "cve": "cve_server.py", "nuclei": "nuclei_server.py", "osint": "osint_server.py", "metasploit": "metasploit_server.py",
    "waf": "waf_detection_server.py", "ffuf": "ffuf_server.py", "sqlmap": "sqlmap_server.py", "sqlmap_full": "sqlmap_server.py", "ssl": "ssl_server.py",
    "cisa_kev": "cisa_kev_server.py", "epss": "epss_server.py", "poc_index": "poc_server.py", "nikto": "nikto_server.py", "masscan": "masscan_server.py",
    "wpscan": "wpscan_server.py", "jwt": "jwt_server.py", "gobuster": "gobuster_server.py", "cve_lite": "cve_lite_server.py", "anomaly": "anomaly_server.py",
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


def _lit(node):
    try:
        return ast.literal_eval(node)
    except Exception:
        return None


def extract_server_tools(path):
    tree = ast.parse(open(path, encoding="utf-8").read(), filename=path)
    for node in ast.walk(tree):
        is_tools = (isinstance(node, ast.Assign) and any(isinstance(x, ast.Name) and x.id == "TOOLS" for x in node.targets)) or \
                   (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "TOOLS")
        if not (is_tools and isinstance(node.value, ast.List)):
            continue
        out = {}
        for el in node.value.elts:
            if not isinstance(el, ast.Dict):
                continue
            d = {_lit(k): v for k, v in zip(el.keys, el.values)}
            name = _lit(d.get("name"))
            schema = d.get("inputSchema")
            required, props = [], []
            if isinstance(schema, ast.Dict):
                sd = {_lit(k): v for k, v in zip(schema.keys, schema.values)}
                required = _lit(sd.get("required")) or [] if sd.get("required") is not None else []
                if isinstance(sd.get("properties"), ast.Dict):
                    props = [_lit(k) for k in sd["properties"].keys if _lit(k) is not None]
            if name:
                out[name] = {"required": required, "properties": set(props)}
        return out
    return {}


def build_catalog():
    cat = {}
    for key, fname in KEY_TO_FILE.items():
        p = os.path.join(MCP_DIR, fname)
        if os.path.exists(p) and fname not in cat:
            cat[fname] = extract_server_tools(p)
    return cat


# ── call extraction ─────────────────────────────────────────────────────────
def _parents(tree):
    m = {}
    for n in ast.walk(tree):
        for c in ast.iter_child_nodes(n):
            m[c] = n
    return m


def _contains(stmt, node):
    return any(n is node for n in ast.walk(stmt))


def _path_statements(stmts, call):
    """The flat, ORDERED list of statements that actually execute on the way to `call`, given a function/if body `stmts`
    that (transitively) contains it. An `if`/`elif`/`else` on the path contributes ONLY the branch actually taken (so a
    sibling branch's assignments to the same variable name are correctly excluded); a plain statement before it is
    still included (so an initial `args: dict = {...}` above a nested `if action == ...:` dispatch is still found)."""
    out = []
    for stmt in stmts:
        if not _contains(stmt, call):
            out.append(stmt)
            continue
        if stmt is call:
            return out
        if isinstance(stmt, ast.If):
            branch = stmt.body if _contains_list(stmt.body, call) else stmt.orelse
            out.extend(_path_statements(branch, call))
            return out
        # some other compound statement (With/Try/For/...) containing the call: descend into its direct child statement
        # lists the same way, falling back to "include the whole statement" if none of them match precisely.
        for field in ("body", "orelse", "finalbody", "handlers"):
            child = getattr(stmt, field, None)
            if isinstance(child, list) and child and any(isinstance(x, ast.AST) for x in child) and _contains_list(child, call):
                out.extend(_path_statements(child, call))
                return out
        out.append(stmt)
        return out
    return out


def _contains_list(stmts, node):
    return any(_contains(s, node) for s in stmts)


def _string_candidates(value):
    """Possible string values an expression can take: constants, either side of a conditional, the DEFAULT of x.get(key, default)."""
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return {value.value}
    if isinstance(value, ast.IfExp):
        return _string_candidates(value.body) | _string_candidates(value.orelse)
    if isinstance(value, ast.BoolOp):
        out = set()
        for v in value.values:
            out |= _string_candidates(v)
        return out
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and value.func.attr == "get" and len(value.args) >= 2:
        return _string_candidates(value.args[1])
    if isinstance(value, ast.Subscript) and isinstance(value.value, ast.Dict):
        out = set()
        for v in value.value.values:
            out |= _string_candidates(v)
        return out
    return set()


def _dict_keys(d, scope_nodes=None, before_line=None):
    keys, dynamic = set(), False
    for k, v in zip(d.keys, d.values):
        if k is None:
            # **spread: resolve a plain `**some_name` by tracing that name's own keys, so {**user_args, **token_arg} is not
            # just thrown away as "fully dynamic" when both operands are themselves traceable literal-built dicts.
            if isinstance(v, ast.Name) and scope_nodes is not None:
                sub_keys, sub_dynamic, sub_found = _trace_name_keys(v.id, scope_nodes, before_line)
                if sub_found:
                    keys |= sub_keys; dynamic |= sub_dynamic
                else:
                    dynamic = True
            else:
                dynamic = True
        elif isinstance(k, ast.Constant) and isinstance(k.value, str):
            keys.add(k.value)
        else:
            dynamic = True
    return keys, dynamic


def _trace_name_keys(name, scope_nodes, before_line):
    """keys of the dict held in variable `name`: its literal assignment(s), name["k"] = ..., name.update({...}), name.setdefault("k", ..)"""
    keys, dynamic, found = set(), False, False
    for root in scope_nodes:
        for n in ast.walk(root):
            if getattr(n, "lineno", 0) >= before_line:
                continue
            targets = None
            if isinstance(n, ast.Assign):
                targets = n.targets
            elif isinstance(n, ast.AnnAssign) and n.value is not None:
                targets = [n.target]
            if targets is not None:
                for tgt in targets:
                    if isinstance(tgt, ast.Name) and tgt.id == name:
                        found = True
                        if isinstance(n.value, ast.Dict):
                            k, dyn = _dict_keys(n.value, scope_nodes, before_line); keys |= k; dynamic |= dyn
                        else:
                            dynamic = True
                    if isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name) and tgt.value.id == name:
                        c = _lit(tgt.slice)
                        if isinstance(c, str):
                            keys.add(c)
                        else:
                            dynamic = True
            elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == name:
                if n.func.attr == "update" and n.args and isinstance(n.args[0], ast.Dict):
                    k, dyn = _dict_keys(n.args[0], scope_nodes, before_line); keys |= k; dynamic |= dyn
                elif n.func.attr == "update":
                    dynamic = True
                elif n.func.attr == "setdefault" and n.args and isinstance(_lit(n.args[0]), str):
                    keys.add(_lit(n.args[0]))
    return keys, dynamic, found


def _branch_of(call, parents):
    """innermost enclosing `if tool_name == "x"` (any level) — used only to LABEL a finding, not to scope the trace."""
    node = call
    while node in parents:
        child, node = node, parents[node]
        if isinstance(node, ast.If):
            test = node.test
            if isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and test.left.id == "tool_name" \
                    and len(test.comparators) == 1 and _lit(test.comparators[0]) is not None and isinstance(test.ops[0], ast.Eq):
                return _lit(test.comparators[0])
    return None


def _dispatch_chain_for(tool_var, args_var, scope_nodes, before_line):
    """Find a preceding `if tool_var == "a": args_var = {...}  elif tool_var == "b": ...` chain in scope_nodes (the SAME
    variable used as both the branch condition and, later, as the call's tool-name argument) and return, per branch,
    (literal, keys sent in THAT branch only, whether that branch's assignment was fully traceable). None if no such
    chain is found (falls back to the pooled, less precise extraction)."""
    for root in scope_nodes:
        for n in ast.walk(root):
            if not (isinstance(n, ast.If) and getattr(n, "lineno", 0) < before_line):
                continue
            test = n.test
            if not (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and test.left.id == tool_var
                    and len(test.comparators) == 1 and isinstance(test.ops[0], ast.Eq) and _lit(test.comparators[0]) is not None):
                continue
            # walk the elif-chain (nested in .orelse) collecting every `tool_var == "literal"` branch
            out = []
            node = n
            while True:
                lit = _lit(node.test.comparators[0])
                keys, dynamic, found = _trace_name_keys(args_var, [ast.Module(body=node.body, type_ignores=[])], before_line + 1)
                out.append((lit, keys, dynamic or not found))
                if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If) and isinstance(node.orelse[0].test, ast.Compare) \
                        and isinstance(node.orelse[0].test.left, ast.Name) and node.orelse[0].test.left.id == tool_var:
                    node = node.orelse[0]
                    continue
                break
            if len(out) > 1:    # a single `if` with no real elif chain isn't this pattern; need at least 2 branches to be confident
                return out
    return None


def extract_calls(src):
    tree = ast.parse(src)
    parents = _parents(tree)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == "_run_single_tool")
    calls = []
    for c in ast.walk(fn):
        if not (isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == "_call_mcp_tool" and len(c.args) >= 3):
            continue
        url, tool, args = c.args[0], c.args[1], c.args[2]
        mcp_key = None
        if isinstance(url, ast.Subscript) and isinstance(url.value, ast.Name) and url.value.id == "MCP_URLS":
            mcp_key = _lit(url.slice)
        branch = _branch_of(c, parents)
        # The precise statements that execute on the way to THIS call (correctly excludes sibling if/elif branches that
        # assign to the same variable name but do not apply to this call; still includes a shared initialisation that
        # sits before a nested dispatch).
        scope = [ast.Module(body=_path_statements(fn.body, c), type_ignores=[])]
        # Dynamic-tool pattern (osint-style): the tool name is a variable whose value is decided by a preceding
        # `if <that var> == "a": X = {...}  elif <that var> == "b": X = {...} ...` chain (the SAME var used as both the
        # branch condition and the tool name, X being the args variable), with the call placed AFTER the whole chain.
        # Each branch is really a SEPARATE call with its own tool name and its own args — checking them pooled together
        # (as one scope blindly ast.walk'd) falsely claims every branch sends every other branch's fields too.
        if isinstance(tool, ast.Name) and isinstance(args, ast.Name):
            chain = _dispatch_chain_for(tool.id, args.id, scope, c.lineno)
            if chain is not None:
                for lit, branch_keys, branch_dynamic in chain:
                    calls.append({"line": c.lineno, "branch": branch, "mcp_key": mcp_key, "tools": {lit}, "keys": branch_keys,
                                  "dynamic": branch_dynamic, "name_tool": True})
                continue
        if isinstance(tool, ast.Constant) and isinstance(tool.value, str):
            tools = {tool.value}
        elif isinstance(tool, ast.Name):
            tools = set()
            for root in scope:
                for n in ast.walk(root):
                    if isinstance(n, ast.Assign) and any(isinstance(x, ast.Name) and x.id == tool.id for x in n.targets) and n.lineno < c.lineno:
                        tools |= _string_candidates(n.value)
        else:
            tools = set()
        if isinstance(args, ast.Dict):
            keys, dynamic = _dict_keys(args, scope, c.lineno)
        elif isinstance(args, ast.Name):
            keys, dynamic, found = _trace_name_keys(args.id, scope, c.lineno)
            dynamic = dynamic or not found
        else:
            keys, dynamic = set(), True
        calls.append({"line": c.lineno, "branch": branch, "mcp_key": mcp_key, "tools": tools, "keys": keys, "dynamic": dynamic,
                      "name_tool": isinstance(tool, ast.Name)})
    return calls


def check_calls(calls, catalog):
    problems = []
    for c in calls:
        # The manifest-driven generic dispatcher calls _call_mcp_tool(MCP_URLS[server], action, ...) with VARIABLE
        # server/action — it is validated by test_generic_dispatch.py and test_tool_manifest.py, not here. Its server key
        # can't resolve to a literal, so skip exactly that one call site (variable key, no literal tool names).
        if c["mcp_key"] is None and not c["tools"]:
            continue
        fname = KEY_TO_FILE.get(c["mcp_key"])
        where = f"L{c['line']} [{c['branch']}] MCP_URLS[{c['mcp_key']!r}]"
        if fname is None:
            problems.append(("UNKNOWN_MCP_KEY", where, str(c["mcp_key"]))); continue
        tdefs = catalog.get(fname) or {}
        if not tdefs:
            problems.append(("NO_SCHEMA", where, fname)); continue
        for tool in sorted(c["tools"]):
            if tool not in tdefs:
                if re.fullmatch(r"[a-z][a-z0-9_]+", tool):
                    problems.append(("UNKNOWN_TOOL", where, f"{tool!r} is not a tool of {fname} (has: {', '.join(sorted(tdefs))[:110]})"))
                continue
            spec = tdefs[tool]
            unknown = sorted(k for k in c["keys"] if spec["properties"] and k not in spec["properties"])
            missing = [r for r in spec["required"] if r not in c["keys"]]
            if unknown:
                problems.append(("UNKNOWN_ARG", where, f"{tool}: sends {unknown}; real properties are {sorted(spec['properties'])}"))
            if missing and not c["dynamic"]:
                problems.append(("MISSING_REQUIRED", where, f"{tool}: never sends required {missing}; sends {sorted(c['keys'])}"))
            elif missing and c["dynamic"]:
                problems.append(("MISSING_REQUIRED?", where, f"{tool}: required {missing} not seen among {sorted(c['keys'])} (arguments partly built dynamically)"))
    return problems


if __name__ == "__main__":
    if not (os.path.isdir(MCP_DIR) and os.path.exists(os.path.join(MCP_DIR, "nmap_server.py"))):
        print("SKIP: mcp-servers/ not present here (this check runs on the host / verify.sh)")
        print(f"\nRESULT: {P} passed, {F} failed"); sys.exit(0)
    src = open(WORKER, encoding="utf-8").read()
    catalog = build_catalog()
    calls = extract_calls(src)
    problems = check_calls(calls, catalog)
    if "--report" in sys.argv:
        print(f"calls found: {len(calls)} | dynamic-arg calls: {sum(1 for c in calls if c['dynamic'])} | problems: {len(problems)}")
        for kind, where, detail in problems:
            print(f"  [{kind}] {where}: {detail}")
        sys.exit(0)
    t("the worker's MCP calls were all found and each resolved to a server schema (except the one manifest-driven generic dispatcher)", len(calls) >= 100 and all(c["mcp_key"] in KEY_TO_FILE for c in calls if not (c["mcp_key"] is None and not c["tools"])))

    # Sanity floor: if a tool's schema ever becomes unparseable (a renamed key, a malformed inputSchema), check_calls()
    # silently stops validating THAT tool rather than erroring — by design, the same convention used for a genuinely
    # undeclared schema elsewhere in this file. Catch the "silently stopped validating" case explicitly for the tools
    # this test actually relies on, so a schema-parsing regression fails loudly instead of just going quiet.
    for _srv, _tool, _min_props in (("masscan", "masscan_range", 3), ("sqlmap", "sqlmap_scan", 10), ("gobuster", "gobuster_fuzz", 5), ("nikto", "nikto_ssl_only", 4)):
        _fname = KEY_TO_FILE[_srv]
        _spec = catalog.get(_fname, {}).get(_tool)
        t(f"{_srv}.{_tool}\'s schema is still readable with its real property count (catches a renamed/malformed schema going silently unchecked)",
          _spec is not None and len(_spec["properties"]) >= _min_props, _spec)

    # Known, verified-harmless exceptions (checked by hand against the real tool-server handler code, not assumed):
    #  - ssl.check_ssl: the worker computes a port but the handler (handle_check_ssl) never reads it — dead, not an error.
    #  - gobuster_dns: shared per-mode extras (proxy/headers/username/password) are built once for dir/vhost/fuzz/dns and
    #    reused; DNS brute-forcing has no auth/proxy concept, so handle_gobuster_dns simply never reads them — dead, not an error.
    #  - mitre.generate_layer: the handler defaults a missing "scope" to "all" (arguments.get("scope","all")), so the call
    #    still succeeds; there is just no tool_config/UI field yet to request a narrower (group/tactic-specific) layer.
    KNOWN_EXCEPTIONS = {
        ("UNKNOWN_ARG", "ssl", "check_ssl"),
        ("UNKNOWN_ARG", "gobuster", "gobuster_dns"),
        ("MISSING_REQUIRED", "mitre", "generate_layer"),
    }
    def _key(p):
        kind, where, detail = p
        m = re.search(r"\[(\w+)\].*?: (\w+):", where + ": " + detail) or re.search(r"\] MCP_URLS\['(\w+)'\]: (\w+):", where)
        return (kind, m.group(1), m.group(2)) if m else (kind, None, None)
    unexpected = [p for p in problems if _key(p) not in KNOWN_EXCEPTIONS]
    t(f"every tool call the scan worker makes is correct, except the known harmless exceptions above ({len(unexpected)} unexpected problem(s))", not unexpected, unexpected[:12])
    t("the known exceptions are still exactly the 3 expected ones (not fewer — that would mean one silently got worse, not better)", len(problems) == len(KNOWN_EXCEPTIONS) and {_key(p) for p in problems} == KNOWN_EXCEPTIONS, problems)
    print(f"\nRESULT: {P} passed, {F} failed")
    sys.exit(1 if F else 0)
