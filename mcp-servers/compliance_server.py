#!/usr/bin/env python3
"""
SOCIS-AI-PT — Compliance Mapping MCP Server (HTTP transport)
FastAPI-based MCP server that maps a finding (by the tool that produced it, or a free-text description) to OWASP
Top 10 (2021), PTES phases, and MITRE ATT&CK tactics — so a report can show not just "what was found" but "which
standard category this falls under." Pure data lookup: no network, no subprocess, the simplest server in the
platform alongside secrets_server.py. Complements mitre_server.py (full ATT&CK technique/group/software lookup) by
doing the other direction: classifying one of THIS platform's findings into that framework, not browsing the
framework itself.

Tools exposed (v1):
  - classify_finding    : given a tool name (e.g. "sqlmap", "nikto") and/or a free-text finding description, return
                         the matching OWASP Top 10 category, PTES phase, and likely MITRE ATT&CK tactics
  - map_tool_to_standards: given just a platform tool/server name, return its typical OWASP/PTES/ATT&CK mapping
                          (useful for a report that wants "which standards does this workflow already cover")
  - list_mappings       : list every tool-to-standard mapping this server knows, for reference
"""

import json
import os
import re
import sys
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_auth import verify_mcp_auth, mcp_auth_error  # type: ignore

app = FastAPI(title="SOCIS Compliance Mapping MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "compliance-mcp"
MCP_PORT = 8133

# ─────────────────────────────────────────────────────────────────────────────
# The mapping table. Each entry: platform server/tool name -> OWASP Top 10 (2021) category, PTES phase, and the
# MITRE ATT&CK tactic(s) most associated with that kind of finding. This is a curated, best-effort classification —
# a single tool can surface findings that span categories; this gives the MOST LIKELY one(s) for a report to cite.
# ─────────────────────────────────────────────────────────────────────────────

_TOOL_MAPPING: dict[str, dict] = {
    "nmap":        {"owasp": None, "ptes": "Intelligence Gathering", "attack_tactics": ["Reconnaissance", "Discovery"]},
    "masscan":     {"owasp": None, "ptes": "Intelligence Gathering", "attack_tactics": ["Reconnaissance", "Discovery"]},
    "osint":       {"owasp": None, "ptes": "Intelligence Gathering", "attack_tactics": ["Reconnaissance"]},
    "cloud":       {"owasp": "A05:2021 - Security Misconfiguration", "ptes": "Intelligence Gathering", "attack_tactics": ["Reconnaissance", "Discovery"]},
    "dns_deep":    {"owasp": "A05:2021 - Security Misconfiguration", "ptes": "Intelligence Gathering", "attack_tactics": ["Reconnaissance"]},
    "ssl":         {"owasp": "A02:2021 - Cryptographic Failures", "ptes": "Vulnerability Analysis", "attack_tactics": ["Discovery"]},
    "waf":         {"owasp": "A05:2021 - Security Misconfiguration", "ptes": "Vulnerability Analysis", "attack_tactics": ["Defense Evasion"]},
    "nuclei":      {"owasp": "A06:2021 - Vulnerable and Outdated Components", "ptes": "Vulnerability Analysis", "attack_tactics": ["Initial Access"]},
    "nikto":       {"owasp": "A05:2021 - Security Misconfiguration", "ptes": "Vulnerability Analysis", "attack_tactics": ["Initial Access"]},
    "wpscan":      {"owasp": "A06:2021 - Vulnerable and Outdated Components", "ptes": "Vulnerability Analysis", "attack_tactics": ["Initial Access"]},
    "sqlmap":      {"owasp": "A03:2021 - Injection", "ptes": "Exploitation", "attack_tactics": ["Initial Access", "Collection"]},
    "ffuf":        {"owasp": "A01:2021 - Broken Access Control", "ptes": "Vulnerability Analysis", "attack_tactics": ["Discovery"]},
    "gobuster":    {"owasp": "A01:2021 - Broken Access Control", "ptes": "Vulnerability Analysis", "attack_tactics": ["Discovery"]},
    "jwt":         {"owasp": "A07:2021 - Identification and Authentication Failures", "ptes": "Exploitation", "attack_tactics": ["Credential Access", "Defense Evasion"]},
    "api_security": {"owasp": "A01:2021 - Broken Access Control", "ptes": "Vulnerability Analysis", "attack_tactics": ["Discovery", "Collection"]},
    "secrets":     {"owasp": "A02:2021 - Cryptographic Failures", "ptes": "Intelligence Gathering", "attack_tactics": ["Credential Access"]},
    "ad":          {"owasp": "A07:2021 - Identification and Authentication Failures", "ptes": "Exploitation", "attack_tactics": ["Credential Access", "Discovery", "Lateral Movement"]},
    "crack":       {"owasp": "A07:2021 - Identification and Authentication Failures", "ptes": "Exploitation", "attack_tactics": ["Credential Access"]},
    "metasploit":  {"owasp": None, "ptes": "Exploitation", "attack_tactics": ["Initial Access", "Execution", "Privilege Escalation"]},
    "payload_generator": {"owasp": None, "ptes": "Exploitation", "attack_tactics": ["Execution", "Defense Evasion"]},
    "container":   {"owasp": "A06:2021 - Vulnerable and Outdated Components", "ptes": "Vulnerability Analysis", "attack_tactics": ["Initial Access", "Privilege Escalation"]},
    "cve":         {"owasp": "A06:2021 - Vulnerable and Outdated Components", "ptes": "Vulnerability Analysis", "attack_tactics": ["Initial Access"]},
    "cve_lite":    {"owasp": "A06:2021 - Vulnerable and Outdated Components", "ptes": "Vulnerability Analysis", "attack_tactics": ["Initial Access"]},
    "exploitdb":   {"owasp": None, "ptes": "Vulnerability Analysis", "attack_tactics": ["Initial Access"]},
    "cisa_kev":    {"owasp": "A06:2021 - Vulnerable and Outdated Components", "ptes": "Vulnerability Analysis", "attack_tactics": ["Initial Access"]},
    "epss":        {"owasp": None, "ptes": "Vulnerability Analysis", "attack_tactics": []},
    "poc_index":   {"owasp": None, "ptes": "Vulnerability Analysis", "attack_tactics": ["Initial Access"]},
    "anomaly":     {"owasp": None, "ptes": "Post Exploitation", "attack_tactics": ["Exfiltration", "Command and Control"]},
}

# Keyword hints for free-text classification, used when the caller gives a description instead of (or in addition
# to) a tool name. Each tuple is (keyword, owasp_category) — first match wins, checked in order (most specific first).
_KEYWORD_HINTS: list[tuple[str, str]] = [
    ("sql injection", "A03:2021 - Injection"),
    ("sqli", "A03:2021 - Injection"),
    ("command injection", "A03:2021 - Injection"),
    ("xxe", "A05:2021 - Security Misconfiguration"),
    ("xss", "A03:2021 - Injection"),
    ("cross-site scripting", "A03:2021 - Injection"),
    ("ssrf", "A10:2021 - Server-Side Request Forgery"),
    ("server-side request forgery", "A10:2021 - Server-Side Request Forgery"),
    ("server side request forgery", "A10:2021 - Server-Side Request Forgery"),
    ("idor", "A01:2021 - Broken Access Control"),
    ("broken access", "A01:2021 - Broken Access Control"),
    ("privilege escalation", "A01:2021 - Broken Access Control"),
    ("weak password", "A07:2021 - Identification and Authentication Failures"),
    ("default credential", "A07:2021 - Identification and Authentication Failures"),
    ("session fixation", "A07:2021 - Identification and Authentication Failures"),
    ("outdated", "A06:2021 - Vulnerable and Outdated Components"),
    ("known vulnerable", "A06:2021 - Vulnerable and Outdated Components"),
    ("cve-", "A06:2021 - Vulnerable and Outdated Components"),
    ("misconfigur", "A05:2021 - Security Misconfiguration"),
    ("verbose error", "A05:2021 - Security Misconfiguration"),
    ("cors", "A05:2021 - Security Misconfiguration"),
    ("weak encryption", "A02:2021 - Cryptographic Failures"),
    ("weak cipher", "A02:2021 - Cryptographic Failures"),
    ("plaintext", "A02:2021 - Cryptographic Failures"),
    ("insecure deserialization", "A08:2021 - Software and Data Integrity Failures"),
    ("supply chain", "A08:2021 - Software and Data Integrity Failures"),
    ("no logging", "A09:2021 - Security Logging and Monitoring Failures"),
    ("insufficient logging", "A09:2021 - Security Logging and Monitoring Failures"),
]


def _classify_text(text: str) -> str | None:
    low = text.lower()
    for keyword, category in _KEYWORD_HINTS:
        if keyword in low:
            return category
    return None


# ─────────────────────────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "classify_finding",
        "description": "Classify a finding into OWASP Top 10 (2021), PTES phase, and likely MITRE ATT&CK tactics. "
                       "Give the platform tool/server name that produced the finding, a free-text description, or "
                       "both — tool name sets the baseline, free-text keywords refine it when more specific.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool": {"type": "string", "description": "Platform tool/server name, e.g. 'sqlmap', 'ad', 'nuclei'"},
                "description": {"type": "string", "description": "Free-text finding description, e.g. 'SQL injection in login form'"},
            },
            "properties_note": "At least one of tool or description should be given.",
        },
    },
    {
        "name": "map_tool_to_standards",
        "description": "Given a platform tool/server name, return its typical OWASP Top 10 / PTES / MITRE ATT&CK "
                       "mapping — useful for summarising which standards a completed workflow already covers.",
        "inputSchema": {
            "type": "object",
            "properties": {"tool": {"type": "string", "description": "Platform tool/server name"}},
            "required": ["tool"],
        },
    },
    {
        "name": "list_mappings",
        "description": "List every tool-to-standard mapping this server knows (all platform tools and their "
                       "OWASP/PTES/ATT&CK classification), for reference.",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

async def handle_classify_finding(a: dict) -> dict:
    tool = (a.get("tool") or "").strip().lower()
    description = (a.get("description") or "").strip()
    if not tool and not description:
        raise ValueError("Provide at least one of 'tool' or 'description'")

    base = _TOOL_MAPPING.get(tool, {"owasp": None, "ptes": None, "attack_tactics": []})
    owasp = base.get("owasp")
    source = "tool mapping" if owasp else None

    if description:
        text_match = _classify_text(description)
        if text_match:
            owasp = text_match
            source = "description keyword match" if text_match != base.get("owasp") else "tool mapping + description agree"

    return {
        "success": True,
        "output": {
            "tool": tool or None,
            "description": description or None,
            "owasp_top10_2021": owasp,
            "ptes_phase": base.get("ptes"),
            "attack_tactics": base.get("attack_tactics", []),
            "classification_source": source,
            "note": None if owasp else "No confident OWASP category match — this finding may not map cleanly to the Top 10.",
        },
    }


async def handle_map_tool_to_standards(a: dict) -> dict:
    tool = (a.get("tool") or "").strip().lower()
    if not tool:
        raise ValueError("tool is required")
    mapping = _TOOL_MAPPING.get(tool)
    if mapping is None:
        return {"success": True, "output": {"tool": tool, "known": False,
                                             "note": "No mapping known for this tool name.",
                                             "known_tools": sorted(_TOOL_MAPPING.keys())}}
    return {"success": True, "output": {"tool": tool, "known": True, **mapping}}


async def handle_list_mappings(a: dict) -> dict:
    return {"success": True, "output": {"mappings": {k: v for k, v in sorted(_TOOL_MAPPING.items())}}}


_HANDLERS = {
    "classify_finding": handle_classify_finding,
    "map_tool_to_standards": handle_map_tool_to_standards,
    "list_mappings": handle_list_mappings,
}


# ─────────────────────────────────────────────────────────────────────────────
# MCP PROTOCOL
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    return {"status": "healthy", "server": SERVER_NAME, "version": MCP_VERSION}


@app.post("/mcp")
async def mcp_handler(request: Request):
    if not verify_mcp_auth(request):
        return mcp_auth_error()
    try:
        payload = await request.json()
        req_id = payload.get("id")
        method = payload.get("method")
        params = payload.get("params", {})

        if method == "tools/list":
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})

        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {}) or {}
            handler = _HANDLERS.get(tool_name)
            if handler is None:
                return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                                     "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}})
            try:
                result = await handler(arguments)
            except ValueError as e:
                return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                                     "result": {"content": [{"type": "text",
                                                             "text": json.dumps({"success": False, "output": f"[!] {e}"})}]}})
            return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                                 "result": {"content": [{"type": "text", "text": json.dumps(result)}]}})

        return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                             "error": {"code": -32601, "message": f"Unknown method: {method}"}})
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32603, "message": f"Internal error: {str(e)[:200]}"}}, status_code=500)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=MCP_PORT, log_level="warning")
