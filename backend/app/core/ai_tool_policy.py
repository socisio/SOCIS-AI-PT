"""Which MCP tools the AI chat may call on its own, and who decided that (pure: unit-tested, no database/network).

Two layers, in order:
  1. A HARD FLOOR that nothing here can open. Exploitation-class tools (Metasploit execution, sqlmap shells/file read-write,
     payload generation, JWT forging) run only when the operator sets SOCIS_AGENT_ALLOW_OFFENSIVE on the server — never from
     an admin toggle, because the model's decision to call them can be steered by text the scan target or a web page controls
     (prompt injection). These are always shown locked in the admin UI.
  2. Everything else is admin-configurable at TWO levels: a whole server (existing per-server switches, e.g. "Nmap") and,
     within an enabled server, an individual tool (new: e.g. allow nmap_scan but not nmap_vuln_scan). An explicit per-tool
     choice always wins over the server's default; with no explicit choice the tool follows its server.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

# Exploitation-class: the hard floor. Mirrors api/v1/llm.py's historical _OFFENSIVE_SERVERS/_OFFENSIVE_TOOLS exactly (fix H-4);
# llm.py imports these from here now instead of defining its own copy, so there is one place this list can change.
OFFENSIVE_SERVERS = frozenset({"metasploit_mcp", "sqlmap_mcp", "payload_generator_mcp"})
OFFENSIVE_TOOLS = frozenset({
    "password_spray", "asrep_roast",  # Active Directory offensive (credential spraying / AS-REP roasting)
    "crack_hash",  # Password cracking offensive (wordlist attack against hashes)
    "sqlmap_os_shell", "sqlmap_sql_shell", "sqlmap_shell", "sqlmap_write_file", "sqlmap_read_file", "sqlmap_dump", "sqlmap_full_chain",
    "run_exploit", "run_auxiliary_module", "run_post_module", "send_session_command", "start_listener", "generate_payload", "forge_jwt",
})

MAX_OVERRIDES = 1000
_TOOL_KEY_MAX_LEN = 200


def is_offensive(server_name: str, tool_name: str) -> bool:
    return server_name in OFFENSIVE_SERVERS or tool_name in OFFENSIVE_TOOLS


def tool_key(server_name: str, tool_name: str) -> str:
    return f"{server_name}.{tool_name}"


def server_enabled(server_name: str, server_settings: Dict[str, object], setting_for_server: Dict[str, str]) -> bool:
    """The whole-server switch (existing per-server policy). Unknown servers default to enabled, matching today's behaviour."""
    key = setting_for_server.get(server_name)
    if key is None:
        return True
    return bool(server_settings.get(key, True))


def effective_enabled(server_name: str, tool_name: str, server_settings: Dict[str, object], tool_overrides: Dict[str, object],
                       setting_for_server: Dict[str, str]) -> bool:
    """May the AI chat ATTEMPT this tool? (The offensive hard floor is separate and still applies on top of this — see is_offensive.)
    Order: an explicit per-tool override wins; otherwise the tool follows its server's switch."""
    if is_offensive(server_name, tool_name):
        return False
    key = tool_key(server_name, tool_name)
    if key in tool_overrides:
        return bool(tool_overrides[key])
    return server_enabled(server_name, server_settings, setting_for_server)


def sanitize_overrides(raw: object, catalog_keys: Iterable[str]) -> Tuple[Dict[str, bool], List[str]]:
    """Validate an incoming `tool_overrides` payload before it is stored. Returns (clean overrides, problems). An override for an
    offensive tool is dropped (that floor is never admin-settable) rather than rejecting the whole save — the rest still applies."""
    problems: List[str] = []
    if raw is None:
        return {}, problems
    if not isinstance(raw, dict):
        return {}, ["tool_overrides must be an object of \"server.tool\": true/false"]
    known = set(catalog_keys)
    out: Dict[str, bool] = {}
    items = list(raw.items())
    if len(items) > MAX_OVERRIDES:
        problems.append(f"too many tool overrides (max {MAX_OVERRIDES})")
        items = items[:MAX_OVERRIDES]
    for k, v in items:
        key = str(k)
        if len(key) > _TOOL_KEY_MAX_LEN or "." not in key:
            problems.append(f"not a valid tool identifier: {key[:60]!r}")
            continue
        if known and key not in known:
            problems.append(f"unknown tool: {key[:80]!r}")
            continue
        server, _, tool = key.partition(".")
        if is_offensive(server, tool):
            problems.append(f"{key} is exploitation-class and cannot be enabled from here (needs SOCIS_AGENT_ALLOW_OFFENSIVE)")
            continue
        out[key] = bool(v)
    return out, problems


def build_catalog(servers: Iterable[object]) -> List[dict]:
    """servers: objects with .name and .tools (each tool with .name, .description) — e.g. MCPClient._servers.values(). ->
    [{server, tools: [{name, description, offensive}]}], sorted for a stable UI. A server with no discovered tools yet is
    included with an empty tools list rather than omitted, so the admin can still see and disable it."""
    out = []
    for s in sorted(servers, key=lambda s: getattr(s, "name", "")):
        name = getattr(s, "name", "")
        tools = sorted(getattr(s, "tools", None) or [], key=lambda t: getattr(t, "name", ""))
        out.append({
            "server": name,
            "tools": [{"name": t.name, "description": getattr(t, "description", "") or "", "offensive": is_offensive(name, t.name)} for t in tools],
        })
    return out
