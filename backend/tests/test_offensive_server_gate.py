"""Security audit round 2 finding: every offensive MCP tool (old and new) only checked SOCIS_AGENT_ALLOW_OFFENSIVE at
the backend's generic dispatcher (scan_worker.py's _dispatch_manifest_tool) — never at the MCP server itself. In
production the servers aren't reachable from outside the Docker network, but anything else on that internal network
(or a compromised backend process) could call an offensive tool directly with no check at all. Added a shared
offensive_action_allowed() helper and wired it into every server with a genuinely offensive action, as a
defense-in-depth layer in addition to (not instead of) the backend's own gate.

  python tests/test_offensive_server_gate.py
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
MCP_DIR = os.path.join(ROOT, "..", "mcp-servers")
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

AUTH_SRC = open(os.path.join(MCP_DIR, "mcp_auth.py"), encoding="utf-8").read()
t("the shared offensive_action_allowed() helper exists", "def offensive_action_allowed()" in AUTH_SRC)
t("it reads SOCIS_AGENT_ALLOW_OFFENSIVE from the environment (the same var the backend checks)",
  'os.environ.get("SOCIS_AGENT_ALLOW_OFFENSIVE"' in AUTH_SRC)

# Every manifest server/action pair marked offensive must have its MCP server call this helper somewhere before
# doing its real work — checked against the REAL manifest, not a hardcoded list, so a future offensive tool is
# caught by this test automatically.
MANIFEST = json.load(open(os.path.join(ROOT, "app", "core", "tool_manifest.json")))
SHORT_TO_FILE = {
    "ad": "ad_server.py", "crack": "crack_server.py", "metasploit": "metasploit_server.py",
    "sqlmap": "sqlmap_server.py", "jwt": "jwt_server.py", "payload_generator": "payload_generator_server.py",
}
offensive_servers = sorted({t["server"] for t in MANIFEST["tools"] if t["offensive"]})
t(f"every server with an offensive tool is one this test knows how to check — unmapped: "
  f"{[s for s in offensive_servers if s not in SHORT_TO_FILE]}",
  all(s in SHORT_TO_FILE for s in offensive_servers))

for server in offensive_servers:
    fname = SHORT_TO_FILE.get(server)
    if not fname:
        continue
    path = os.path.join(MCP_DIR, fname)
    if not os.path.exists(path):
        t(f"{fname} exists", False)
        continue
    src = open(path, encoding="utf-8").read()
    # the import may be at module level in a multi-name import (ad_server.py, crack_server.py: "from mcp_auth
    # import a, b, offensive_action_allowed") or a lazy import inside the specific handler (jwt_server.py,
    # metasploit_server.py, sqlmap_server.py: "from mcp_auth import offensive_action_allowed") — either is fine, as
    # long as it is actually imported from mcp_auth AND actually called (not just mentioned in a comment).
    imports_it = any(
        "from mcp_auth import" in line and "offensive_action_allowed" in line
        for line in src.splitlines()
    )
    calls_it = "offensive_action_allowed()" in src
    t(f"{fname} imports and calls offensive_action_allowed (defense-in-depth gate present)",
      imports_it and calls_it)

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
