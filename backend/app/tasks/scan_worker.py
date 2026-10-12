"""
SOCIS-AI-PT — Async Scan Orchestrator (ARQ + Redis)
Background task worker that runs the full pentest pipeline:
MCP tool containers → LLM analysis → save findings → notify via WebSocket.
"""

import asyncio
import json
import logging
import os
import uuid
import httpx
from datetime import datetime, timezone

from arq import create_pool
from arq.connections import RedisSettings

from app.config import settings

# Import all models at module level so SQLAlchemy's mapper registry is fully
# populated before any query triggers cascade mapper configuration.
# VulnComment MUST be imported before Vulnerability is first queried because
# Vulnerability has relationship("VulnComment", order_by="VulnComment.created_at").
import app.models  # noqa: F401 — registers all mappers via __init__.py

from app.services.webhook_service import emit_scan_event
from app.core.tool_outcome import exit_code_for, summarize as _summarize_tool_outcomes, tool_failed
from app.core import tool_manifest as _tool_manifest

logger = logging.getLogger(__name__)

_MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")


# ─── MCP Container URLs ───────────────────────────────────────

MCP_URLS = {
    "nmap":              "http://mcp_all:8101/mcp",
    "cve":               "http://mcp_all:8100/mcp",
    "nuclei":            "http://mcp_all:8102/mcp",
    "osint":             "http://mcp_all:8103/mcp",
    "metasploit":        "http://mcp_all:8104/mcp",
    "waf":               "http://mcp_all:8107/mcp",
    "ffuf":              "http://mcp_all:8108/mcp",
    "sqlmap":            "http://mcp_all:8109/mcp",
    "sqlmap_full":       "http://mcp_all:8109/mcp",
    "ssl":               "http://mcp_all:8112/mcp",
    "cisa_kev":          "http://mcp_all:8114/mcp",
    "epss":              "http://mcp_all:8115/mcp",
    "poc_index":         "http://mcp_all:8116/mcp",
    "nikto":             "http://mcp_all:8117/mcp",
    "masscan":           "http://mcp_all:8118/mcp",
    "wpscan":            "http://mcp_all:8119/mcp",
    "jwt":               "http://mcp_all:8120/mcp",
    "gobuster":          "http://mcp_all:8121/mcp",
    "cve_lite":          "http://mcp_all:8122/mcp",
    "anomaly":           "http://mcp_all:8123/mcp",
    "payload_generator": "http://mcp_all:8124/mcp",
    "exploitdb":         "http://mcp_all:8125/mcp",
    "ad":                "http://mcp_all:8126/mcp",
    "cloud":             "http://mcp_all:8127/mcp",
    "container":         "http://mcp_all:8128/mcp",
    "mitre":             "http://mcp_all:8105/mcp",
    "api_security":      "http://mcp_all:8129/mcp",
    "secrets":           "http://mcp_all:8130/mcp",
    "dns_deep":          "http://mcp_all:8131/mcp",
    "crack":             "http://mcp_all:8132/mcp",
    "compliance":        "http://mcp_all:8133/mcp",
}

# ─── Workflow Templates ───────────────────────────────────────

WORKFLOW_TEMPLATES: dict[str, dict] = {
    "full_pentest": {
        "name": "Full Penetration Test",
        "description": "Discovery → Recon → Vuln Detection → Threat Intel → Web Attacks → Exploitation",
        "steps": [
            {"step_id": 1, "name": "Port Discovery",   "tools": ["nmap", "masscan"],                              "port_filter": None},
            {"step_id": 2, "name": "Reconnaissance",   "tools": ["osint", "waf", "ssl"],                          "port_filter": None},
            {"step_id": 3, "name": "Vuln Detection",   "tools": ["nuclei", "cve"],                                "port_filter": None},
            {"step_id": 4, "name": "Threat Intel",     "tools": ["cisa_kev", "epss", "poc_index"],               "port_filter": None},
            {"step_id": 5, "name": "Web Attacks",      "tools": ["ffuf", "sqlmap", "nikto", "wpscan", "gobuster", "jwt"], "port_filter": [80, 443, 8080, 8443, 8000, 3000]},
            {"step_id": 6, "name": "Exploitation",     "tools": ["metasploit"],                               "port_filter": None},
        ],
    },
    "web_app": {
        "name": "Web Application Test",
        "description": "Port discovery → WAF + recon → Vuln detection → Threat intel → Web exploitation",
        "steps": [
            {"step_id": 1, "name": "Port Discovery",   "tools": ["nmap"],                "port_filter": None},
            {"step_id": 2, "name": "WAF & Recon",      "tools": ["waf", "osint"],        "port_filter": None},
            {"step_id": 3, "name": "Vuln Detection",   "tools": ["nuclei", "cve"],       "port_filter": None},
            {"step_id": 4, "name": "Threat Intel",     "tools": ["cisa_kev", "epss"],    "port_filter": None},
            {"step_id": 5, "name": "Web Exploitation", "tools": ["ffuf", "sqlmap", "nikto", "wpscan", "gobuster", "jwt"], "port_filter": [80, 443, 8080, 8443, 8000, 3000]},
        ],
    },
    "network_recon": {
        "name": "Network Reconnaissance",
        "description": "Port discovery → Recon + SSL → CVE + Threat Intel → Service exploitation",
        "steps": [
            {"step_id": 1, "name": "Port Discovery",      "tools": ["nmap", "masscan"],              "port_filter": None},
            {"step_id": 2, "name": "Recon & SSL",         "tools": ["osint", "ssl"],                "port_filter": None},
            {"step_id": 3, "name": "CVE Analysis",        "tools": ["cve", "cisa_kev", "epss"],    "port_filter": None},
            {"step_id": 4, "name": "Service Exploitation","tools": ["metasploit"],                 "port_filter": None},
        ],
    },
    "quick_scan": {
        "name": "Quick Scan",
        "description": "Port discovery → vulnerability detection",
        "steps": [
            {"step_id": 1, "name": "Port Discovery", "tools": ["nmap"],         "port_filter": None},
            {"step_id": 2, "name": "Vuln Detection", "tools": ["nuclei", "cve", "gobuster"], "port_filter": None},
        ],
    },
    "intelligent": {
        "name": "Intelligent Pentest",
        "description": "Port discovery → auto-routes tools based on detected services & open ports",
        "steps": [
            {"step_id": 1, "name": "Port Discovery", "tools": ["nmap"], "port_filter": None},
        ],
        "dynamic": True,
    },
    "wordpress": {
        "name": "WordPress Security Audit",
        "description": "Targeted WordPress scanner — enumerate plugins/themes/users, detect CVEs, brute-force logins",
        "steps": [
            {"step_id": 1, "name": "Port Discovery",  "tools": ["nmap"],                "port_filter": None},
            {"step_id": 2, "name": "WAF & Recon",     "tools": ["waf", "osint"],        "port_filter": None},
            {"step_id": 3, "name": "WordPress Scan",  "tools": ["wpscan", "nikto"],     "port_filter": [80, 443, 8080, 8443, 8000, 3000]},
            {"step_id": 4, "name": "Vuln Detection",  "tools": ["nuclei", "cve"],       "port_filter": None},
            {"step_id": 5, "name": "Threat Intel",    "tools": ["cisa_kev", "epss"],    "port_filter": None},
            {"step_id": 6, "name": "Web Attacks",     "tools": ["ffuf", "sqlmap"],      "port_filter": [80, 443, 8080, 8443, 8000, 3000]},
        ],
    },
    "api_security": {
        "name": "API Security Test",
        "description": "Discover API endpoints → SSL/TLS → vuln scan → JWT analysis → threat intel",
        "steps": [
            {"step_id": 1, "name": "Port Discovery", "tools": ["nmap"],                "port_filter": None},
            {"step_id": 2, "name": "SSL/TLS Audit",  "tools": ["ssl", "waf"],          "port_filter": None},
            {"step_id": 3, "name": "API Discovery",  "tools": ["ffuf", "gobuster"],    "port_filter": [80, 443, 8080, 8443, 8000, 3000]},
            {"step_id": 4, "name": "Vuln Detection", "tools": ["nuclei", "cve"],       "port_filter": None},
            {"step_id": 5, "name": "JWT Analysis",   "tools": ["jwt"],                 "port_filter": [80, 443, 8080, 8443, 8000, 3000]},
            {"step_id": 6, "name": "Threat Intel",   "tools": ["cisa_kev", "epss"],    "port_filter": None},
        ],
    },
    "sqli_chain": {
        "name": "SQL Injection Full Chain",
        "description": "Detect SQL injection → auto-enumerate DBs, tables, users, passwords → exploitation",
        "steps": [
            {"step_id": 1, "name": "Port Discovery",  "tools": ["nmap"],              "port_filter": None},
            {"step_id": 2, "name": "WAF Detection",   "tools": ["waf", "nikto"],      "port_filter": [80, 443, 8080, 8443, 8000, 3000]},
            {"step_id": 3, "name": "Vuln Detection",  "tools": ["nuclei", "cve"],     "port_filter": None},
            {"step_id": 4, "name": "SQLi Full Chain", "tools": ["sqlmap_full"],       "port_filter": [80, 443, 8080, 8443, 8000, 3000]},
            {"step_id": 5, "name": "Exploitation",    "tools": ["metasploit"],        "port_filter": None},
        ],
    },
    "ssl_audit": {
        "name": "SSL/TLS Audit",
        "description": "Certificate validity → cipher analysis → Heartbleed/POODLE detection → CVE threat intel",
        "steps": [
            {"step_id": 1, "name": "Port Discovery", "tools": ["nmap"],               "port_filter": None},
            {"step_id": 2, "name": "SSL/TLS Scan",   "tools": ["ssl"],                "port_filter": None},
            {"step_id": 3, "name": "Vuln Detection", "tools": ["nuclei", "cve"],      "port_filter": None},
            {"step_id": 4, "name": "Threat Intel",   "tools": ["cisa_kev", "epss"],   "port_filter": None},
        ],
    },
    "osint_recon": {
        "name": "OSINT & Passive Recon",
        "description": "Passive reconnaissance only — WHOIS, DNS, geoIP, WAF fingerprint, SSL cert. No active attacks.",
        "steps": [
            {"step_id": 1, "name": "Port Discovery", "tools": ["nmap"],               "port_filter": None},
            {"step_id": 2, "name": "OSINT",          "tools": ["osint"],              "port_filter": None},
            {"step_id": 3, "name": "WAF & SSL",      "tools": ["waf", "ssl"],         "port_filter": None},
            {"step_id": 4, "name": "Threat Intel",   "tools": ["cisa_kev", "cve"],    "port_filter": None},
        ],
    },
    "metasploit_full_chain": {
        "name": "Metasploit Full Chain",
        "description": "Recon → CVE/KEV/EPSS/PoC intel → Metasploit full-chain exploitation + optional interactive handoff",
        "steps": [
            {"step_id": 1, "name": "Port Discovery",      "tools": ["nmap"],                     "port_filter": None},
            {"step_id": 2, "name": "Vuln Intelligence",   "tools": ["cve", "cisa_kev", "epss", "poc_index"], "port_filter": None},
            {"step_id": 3, "name": "Metasploit Chain",    "tools": ["metasploit"],               "port_filter": None},
        ],
    },
}


# ─── MCP Call Helper ──────────────────────────────────────────

async def _call_mcp_tool(mcp_url: str, tool_name: str, arguments: dict, timeout: int = 120) -> dict:
    """
    Call a tool on an MCP server via JSON-RPC 2.0.
    Returns dict with 'output' (str) and 'success' (bool).
    """
    # Authorized scope: a tool step aimed at a host outside the project's authorized list (for example a host discovered during the
    # scan) does not run. The scan continues; this step reports why.
    from app.core.scope_guard import ScopeViolation, check_tool_call
    try:
        await check_tool_call(tool_name, arguments)
    except ScopeViolation as _sv:
        return {"output": f"[!] BLOCKED (outside the authorized scope): {_sv}", "success": False}
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    try:
        _headers = {"Content-Type": "application/json"}
        if _MCP_AUTH_TOKEN:
            _headers["Authorization"] = f"Bearer {_MCP_AUTH_TOKEN}"
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(mcp_url, json=payload, headers=_headers)
            data = resp.json()

        if "error" in data:
            return {"output": f"[!] MCP error: {data['error']}", "success": False}

        # Extract text content from result
        result = data.get("result", {})
        content = result.get("content", [])
        if content and isinstance(content, list):
            text = content[0].get("text", "")
        else:
            text = json.dumps(result)

        return {"output": text, "success": True}

    except httpx.TimeoutException:
        return {"output": f"[!] Timed out after {timeout}s calling {mcp_url}", "success": False}
    except Exception as e:
        return {"output": f"[!] Failed to call MCP {mcp_url}: {e}", "success": False}



# ─── Cancellation Helper ─────────────────────────────────────

async def _is_cancelled(scan_id: str) -> bool:
    """Check if a scan cancellation was requested via Redis flag."""
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(settings.REDIS_URL or "redis://localhost:6379")
        result = await r.exists(f"scan:cancel:{scan_id}")
        await r.aclose()
        return result > 0
    except Exception:
        return False


# ─── Per-Tool Dispatch ────────────────────────────────────────

# ─── Generic manifest-driven MCP dispatch ───────────────────────────────────
# Tools added via the shared manifest (app/core/tool_manifest.json) are dispatched here, by their (server, action),
# WITHOUT a hand-written branch each. A node selects a manifest tool and sets its fields; this maps those fields to the
# MCP call. The existing hand-written branches above are untouched — this only handles the "mcp:<server>:<action>"
# convention used by manifest-driven nodes.

# Field names that should default to the run's target/http_target when the node leaves them blank.
_TARGET_FIELDS = {"target", "url", "hostname", "host", "domain", "ip"}
# Value fields that should also inherit the Start node's value when left blank (so a CVE / keyword set once on the Start
# node flows into every downstream tool that needs it, without re-typing). Kept separate from _TARGET_FIELDS because the
# run target for these is the raw value, never the http:// form.
_VALUE_INHERIT_FIELDS = {"cve", "cve_id", "keyword", "query", "search"}


def _coerce_field(value, ftype: str):
    """Coerce a node-config string to the manifest field's declared type (numbers, bools, comma/newline lists)."""
    if value is None:
        return None
    if ftype == "number":
        try:
            return int(value)
        except (TypeError, ValueError):
            try:
                return float(value)
            except (TypeError, ValueError):
                return None
    if ftype == "bool":
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("1", "true", "yes", "on")
    if ftype == "list":
        if isinstance(value, list):
            return value
        parts = [p.strip() for p in str(value).replace("\n", ",").split(",")]
        return [p for p in parts if p]
    return value


def _build_manifest_args(spec: dict, tool_config: dict, target: str, http_target: str) -> dict:
    """Map a node's config to the MCP call arguments declared for this tool in the manifest. A field left blank falls
    back to the run target for target-like fields, then to the field's declared default. Only fields the tool actually
    declares are sent — nothing extraneous."""
    args: dict = {}
    server = spec["server"]
    for fld in spec.get("fields", []):
        name, ftype = fld["name"], fld.get("type", "text")
        # Config keys are looked up in order of specificity, so BOTH the manifest "MCP Tool" node and a native per-server
        # panel can feed this one dispatcher:
        #   1. "<server>.<action>.<field>"  — the generic MCP Tool node (namespaced, collision-free)
        #   2. "<server>_<field>"           — a native per-server panel's own key convention (e.g. mitre_query, waf_payload)
        #   3. "<field>"                    — a bare fallback
        key_specific = f"{server}.{spec['action']}.{name}"
        key_panel = f"{server}_{name}"
        raw = tool_config.get(key_specific)
        if raw is None or raw == "":
            raw = tool_config.get(key_panel)
        if raw is None or raw == "":
            raw = tool_config.get(name)
        # Only auto-fill the run target into a field that is genuinely a free-form target: target-like NAME, and no enum
        # and no declared default (an enum/default field like MITRE's "domain" = enterprise|mobile|ics is NOT a target).
        is_free_target = name in _TARGET_FIELDS and not fld.get("enum") and fld.get("default") is None
        # Value fields (cve/keyword/query) inherit the Start value too, so a CVE set on the Start node flows downstream.
        is_value_inherit = name in _VALUE_INHERIT_FIELDS and not fld.get("enum") and fld.get("default") is None
        if (raw is None or raw == "") and is_free_target:
            raw = http_target if name == "url" else target
        elif (raw is None or raw == "") and is_value_inherit:
            raw = target
        if raw is None or raw == "":
            if fld.get("default") is not None:
                args[name] = fld["default"]
            # a required field with no value and no default is left out; the server reports the error cleanly.
            continue
        coerced = _coerce_field(raw, ftype)
        if coerced is not None:
            args[name] = coerced
    return args


# Actions each hand-written server branch implements natively. Any OTHER action a panel offers (every action is in the
# manifest) is dispatched generically via the manifest — this is what lets each panel's dropdown list EVERY action the
# server has without a hand-written case for each. Validated against the manifest by tests/test_generic_dispatch.py.
_NATIVE_ACTIONS: dict[str, set[str]] = {
    "nmap": {"nmap_scan", "port_check", "os_detect"},
    "cve": {"search_cves", "lookup_cve", "get_severity", "cpe_search"},
    "nuclei": {"nuclei_scan", "nuclei_cve_scan", "nuclei_tech_detect", "list_templates"},
    "waf": {"fingerprint_waf", "test_bypass", "analyze_evasion"},
    "masscan": {"masscan_scan", "masscan_top_ports", "masscan_range"},
    "nikto": {"nikto_scan", "nikto_tuning", "nikto_ssl_only"},
    "wpscan": {"wp_scan", "wp_enum_users", "wp_enum_plugins", "wp_enum_themes"},
    "jwt": {"decode_jwt", "test_alg_none", "test_weak_secret", "forge_jwt", "analyze_claims"},
    "cve_lite": {"cve_lite_scan"},
    "metasploit": {"run_exploit", "run_auxiliary_module", "run_post_module", "list_exploits", "list_payloads",
                   "get_module_info", "list_active_sessions", "send_session_command", "terminate_session",
                   "generate_payload", "start_listener", "list_listeners", "stop_job"},
    "cisa_kev": {"check_kev", "search_kev", "get_recent_kev", "get_kev_stats"},
    "epss": {"get_epss_score", "get_epss_scores_bulk", "get_high_epss_cves", "epss_priority_analysis"},
    "poc_index": {"search_poc", "search_github_poc", "get_exploitdb_entry", "poc_risk_summary"},
    "exploitdb": {"search_exploits", "find_by_cve", "get_exploit", "get_recent_exploits", "get_trending_exploits",
                  "search_by_platform", "search_by_type", "export_search_results"},
    "mitre": {"search_techniques", "get_technique_by_id", "get_techniques_by_tactic", "get_techniques_by_platform",
              "get_subtechniques_of_technique", "get_technique_tactics", "search_groups", "get_techniques_used_by_group",
              "get_groups_using_technique", "get_mitigations_for_technique", "get_techniques_mitigated_by",
              "search_software", "get_software_using_technique", "get_all_tactics", "get_data_stats", "generate_layer"},
    "ssl": {"check_ssl"},
    "ffuf": {"ffuf_fuzz"},
    # sqlmap's two builder nodes ("SQLMap (detect)" and "SQLMap Full Chain") map to these; its other 16 sub-tools
    # (dump / shell / os_shell / enum_* / read_file / write_file …) route to the manifest, gated by the offensive opt-in.
    "sqlmap": {"sqlmap_scan", "sqlmap_full_chain"},
    "gobuster": {"gobuster_dir", "gobuster_dns", "gobuster_vhost", "gobuster_fuzz"},
    "osint": {"whois_lookup", "dns_lookup", "http_headers", "ip_geolocation", "subdomain_enum", "ssl_info", "tech_fingerprint"},
    "anomaly": set(),
    "payload_generator": set(),
    "ad": set(),
    "cloud": set(),
    "container": set(),
    "api_security": set(),
    "secrets": set(),
    "dns_deep": set(),
    "crack": set(),
    "compliance": set(),
}

# node-data key that a native panel uses to name its action, per server short-name (usually "<server>_action", but some
# panels use an abbreviation or a differently-named control).
_ACTION_KEY = {
    "exploitdb": "edb_action", "cisa_kev": "kev_action", "poc_index": "poc_action", "metasploit": "msf_action",
    "gobuster": "gobuster_mode", "osint": "osint_tool",
    # panels that had no action dropdown before — their "More Actions" control is their only action selector.
    "ssl": "ssl_action", "ffuf": "ffuf_action", "sqlmap": "sqlmap_action",
    "anomaly": "anomaly_action", "payload_generator": "payload_action",
    "ad": "ad_action",
    "cloud": "cloud_action",
    "container": "container_action",
    "api_security": "api_security_action",
    "secrets": "secrets_action",
    "dns_deep": "dns_deep_action",
    "crack": "crack_action",
    "compliance": "compliance_action",
}


def _panel_action_key(server: str) -> str:
    return _ACTION_KEY.get(server, f"{server}_action")


def _manifest_action_to_run(server: str, tool_config: dict):
    """If this node is a native-panel node whose chosen action is NOT one the hand-written branch implements, return that
    action name so it can be dispatched from the manifest instead; otherwise None (let the hand-written branch run)."""
    action = tool_config.get(_panel_action_key(server))
    if not action:
        # A server with NO native actions (anomaly, payload_generator) has no hand-written branch to fall through to;
        # if the node didn't pick an action, default to that server's first manifest tool so it still runs.
        if not _NATIVE_ACTIONS.get(server):
            tools = [t["action"] for t in _tool_manifest.all_tools() if t["server"] == server]
            return tools[0] if tools else None
        return None
    if action in _NATIVE_ACTIONS.get(server, set()):
        return None
    if _tool_manifest.tool_for(server, action) is not None:
        return action
    return None


async def _dispatch_manifest_tool(server: str, action: str, tool_config: dict, target: str, http_target: str) -> dict:
    """Dispatch one manifest tool (server, action) generically: resolve its schema, enforce the offensive opt-in gate,
    build its args from the node config, and call it. Used by both the generic "MCP Tool" node and the native-panel
    safety net, so there is exactly one place that turns a (server, action) + config into an MCP call."""
    spec = _tool_manifest.tool_for(server, action)
    if spec is None:
        return {"output": f"Unknown tool: {server}.{action}", "success": False}
    if spec.get("offensive") and not settings.SOCIS_AGENT_ALLOW_OFFENSIVE:
        return {
            "skipped": True,
            "reason": f"{server}.{action} is an exploitation-class tool; enable SOCIS_AGENT_ALLOW_OFFENSIVE on the server to use it.",
        }
    if server not in MCP_URLS:
        return {"output": f"No MCP route for server '{server}'", "success": False}
    args = _build_manifest_args(spec, tool_config, target, http_target)
    return await _call_mcp_tool(MCP_URLS[server], action, args, timeout=_manifest_timeout(spec, tool_config))


def _manifest_timeout(spec: dict, tool_config: dict) -> int:
    """Per-node override, else a sensible ceiling by risk (scans get longer than lookups)."""
    override = tool_config.get(f"{spec['server']}.{spec['action']}.timeout") or tool_config.get("mcp_timeout")
    if override:
        try:
            return max(10, int(override))
        except (TypeError, ValueError):
            pass
    return {"critical": 1200, "high": 600, "medium": 300}.get(spec.get("risk", "low"), 120)


async def _run_single_tool(
    tool_name: str, target: str, http_target: str, tool_config: dict
) -> tuple[str, dict, int]:
    """Execute one tool via MCP and return (tool_name, result_data, duration_ms)."""
    import time
    start_ms = int(time.time() * 1000)

    # A native per-server panel can now offer EVERY action that server has. If the chosen action is one the hand-written
    # branch below does not implement, dispatch it from the manifest instead (so the panel's dropdown is always complete
    # without a hand-written case for each action). Native actions fall through to their existing, tuned branch.
    _manifest_action = _manifest_action_to_run(tool_name, tool_config) if tool_name in _NATIVE_ACTIONS else None
    if _manifest_action is not None:
        result_data = await _dispatch_manifest_tool(tool_name, _manifest_action, tool_config, target, http_target)
        return tool_name, result_data, int(time.time() * 1000) - start_ms

    if tool_name == "nmap":
        nmap_action = tool_config.get("nmap_action", "nmap_scan")
        if nmap_action == "port_check":
            result_data = await _call_mcp_tool(
                MCP_URLS["nmap"], "port_check",
                {"target": target, "port": int(tool_config.get("nmap_check_port", 80))},
                timeout=30,
            )
        elif nmap_action == "os_detect":
            result_data = await _call_mcp_tool(
                MCP_URLS["nmap"], "os_detect",
                {"target": target},
                timeout=120,
            )
        else:  # nmap_scan
            args = {"target": target, "flags": tool_config.get("nmap_flags", "-sV -sC -T4 --open")}
            if tool_config.get("nmap_ports"):
                args["ports"] = tool_config["nmap_ports"]
            result_data = await _call_mcp_tool(
                MCP_URLS["nmap"], "nmap_scan", args, timeout=300,
            )
    elif tool_name == "whois":
        domain = tool_config.get("domain", target)
        result_data = await _call_mcp_tool(
            MCP_URLS["osint"], "whois_lookup",
            {"target": domain},
        )
    elif tool_name == "whatweb":
        url = tool_config.get("waf_url", http_target)
        result_data = await _call_mcp_tool(
            MCP_URLS["waf"], "fingerprint_waf",
            {"target": url},
        )
    elif tool_name == "curl_headers":
        result_data = await _call_mcp_tool(
            MCP_URLS["osint"], "http_headers",
            {"url": http_target},
        )
    elif tool_name == "dig":
        domain = tool_config.get("domain", target)
        record_type = tool_config.get("record_type", "A")
        result_data = await _call_mcp_tool(
            MCP_URLS["osint"], "dns_lookup",
            {"domain": domain, "record_type": record_type},
        )
    elif tool_name == "nuclei":
        nuclei_action = tool_config.get("nuclei_action", "nuclei_scan")
        if nuclei_action == "nuclei_cve_scan":
            args = {"target": http_target}
            if tool_config.get("nuclei_year"):
                args["year"] = int(tool_config["nuclei_year"])
            result_data = await _call_mcp_tool(
                MCP_URLS["nuclei"], "nuclei_cve_scan", args, timeout=660,
            )
        elif nuclei_action == "list_templates":
            args = {}
            if tool_config.get("nuclei_category"):
                args["category"] = tool_config["nuclei_category"]
            result_data = await _call_mcp_tool(
                MCP_URLS["nuclei"], "list_templates", args, timeout=30,
            )
        elif nuclei_action == "nuclei_tech_detect":
            result_data = await _call_mcp_tool(
                MCP_URLS["nuclei"], "nuclei_tech_detect",
                {"target": http_target}, timeout=120,
            )
        else:  # nuclei_scan
            args = {"target": http_target, "rate_limit": int(tool_config.get("nuclei_rate_limit", 50))}
            if tool_config.get("nuclei_templates"):
                args["templates"] = tool_config["nuclei_templates"]
            if tool_config.get("nuclei_severity"):
                args["severity"] = tool_config["nuclei_severity"]
            if tool_config.get("nuclei_concurrency"):
                args["concurrency"] = int(tool_config["nuclei_concurrency"])
            if tool_config.get("nuclei_retries") is not None:
                args["retries"] = int(tool_config["nuclei_retries"])
            if tool_config.get("nuclei_proxy"):
                args["proxy"] = tool_config["nuclei_proxy"]
            if tool_config.get("nuclei_headers"):
                args["headers"] = tool_config["nuclei_headers"]
            if tool_config.get("nuclei_exclude_tags"):
                args["exclude_tags"] = tool_config["nuclei_exclude_tags"]
            if tool_config.get("nuclei_no_interactsh"):
                args["no_interactsh"] = bool(tool_config["nuclei_no_interactsh"])
            result_data = await _call_mcp_tool(
                MCP_URLS["nuclei"], "nuclei_scan", args, timeout=660,
            )
    elif tool_name == "cve":
        cve_action = tool_config.get("cve_action", "search_cves")
        if cve_action == "lookup_cve":
            raw_cve = tool_config.get("cve_cve_id", "").strip() or target
            cve_ids = _extract_cve_ids(raw_cve)
            if len(cve_ids) > 1:
                bulk_results = []
                all_success = True
                for cve_id in cve_ids:
                    one = await _call_mcp_tool(
                        MCP_URLS["cve"], "lookup_cve", {"cve_id": cve_id}, timeout=60,
                    )
                    all_success = all_success and one.get("success", False)
                    bulk_results.append(
                        {"cve_id": cve_id, "success": one.get("success", False), "output": one.get("output", "")}
                    )
                result_data = {
                    "success": all_success,
                    "output": json.dumps(
                        {"mode": "bulk", "action": "lookup_cve", "cve_ids": cve_ids, "results": bulk_results}
                    ),
                }
            else:
                cve_id = cve_ids[0] if cve_ids else ""
                result_data = await _call_mcp_tool(
                    MCP_URLS["cve"], "lookup_cve", {"cve_id": cve_id}, timeout=60,
                )
        elif cve_action == "get_severity":
            raw_cve = tool_config.get("cve_cve_id", "").strip() or target
            cve_ids = _extract_cve_ids(raw_cve)
            if len(cve_ids) > 1:
                bulk_results = []
                all_success = True
                for cve_id in cve_ids:
                    one = await _call_mcp_tool(
                        MCP_URLS["cve"], "get_severity", {"cve_id": cve_id}, timeout=60,
                    )
                    all_success = all_success and one.get("success", False)
                    bulk_results.append(
                        {"cve_id": cve_id, "success": one.get("success", False), "output": one.get("output", "")}
                    )
                result_data = {
                    "success": all_success,
                    "output": json.dumps(
                        {"mode": "bulk", "action": "get_severity", "cve_ids": cve_ids, "results": bulk_results}
                    ),
                }
            else:
                cve_id = cve_ids[0] if cve_ids else ""
                result_data = await _call_mcp_tool(
                    MCP_URLS["cve"], "get_severity", {"cve_id": cve_id}, timeout=60,
                )
        elif cve_action == "cpe_search":
            result_data = await _call_mcp_tool(
                MCP_URLS["cve"], "cpe_search",
                {"cpe": tool_config.get("cve_cpe", "")}, timeout=60,
            )
        else:  # search_cves
            keyword = (
                tool_config.get("cve_keyword")
                or tool_config.get("_cve_keywords")
                or target
            )
            if _looks_like_only_cve_list(keyword):
                cve_ids = _extract_cve_ids(keyword)
                if len(cve_ids) > 1:
                    bulk_results = []
                    all_success = True
                    for cve_id in cve_ids:
                        one = await _call_mcp_tool(
                            MCP_URLS["cve"], "lookup_cve", {"cve_id": cve_id}, timeout=60,
                        )
                        all_success = all_success and one.get("success", False)
                        bulk_results.append(
                            {"cve_id": cve_id, "success": one.get("success", False), "output": one.get("output", "")}
                        )
                    result_data = {
                        "success": all_success,
                        "output": json.dumps(
                            {
                                "mode": "bulk",
                                "action": "lookup_cve_from_search",
                                "source_action": "search_cves",
                                "cve_ids": cve_ids,
                                "results": bulk_results,
                            }
                        ),
                    }
                else:
                    result_data = await _call_mcp_tool(
                        MCP_URLS["cve"], "lookup_cve", {"cve_id": cve_ids[0]}, timeout=60,
                    )
            else:
                args = {"keyword": keyword, "limit": tool_config.get("cve_limit", 20)}
                if tool_config.get("cve_severity"):
                    args["severity"] = tool_config["cve_severity"]
                result_data = await _call_mcp_tool(
                    MCP_URLS["cve"], "search_cves", args, timeout=60,
                )
    elif tool_name == "waf":
        waf_action = tool_config.get("waf_action", "fingerprint_waf")
        waf_target = tool_config.get("waf_url", http_target)
        if waf_action == "test_bypass":
            result_data = await _call_mcp_tool(
                MCP_URLS["waf"], "test_bypass",
                {
                    "target": waf_target,
                    "payload": tool_config.get("waf_payload", "' OR 1=1--"),
                },
                timeout=180,
            )
        elif waf_action == "analyze_evasion":
            args = {
                "target": waf_target,
                "attack_type": tool_config.get("waf_attack_type", "sqli"),
            }
            if tool_config.get("waf_waf_type"):
                args["waf_type"] = tool_config["waf_waf_type"]
            result_data = await _call_mcp_tool(
                MCP_URLS["waf"], "analyze_evasion", args, timeout=120,
            )
        else:  # fingerprint_waf
            args = {"target": waf_target}
            if tool_config.get("waf_protocol"):
                args["protocol"] = tool_config["waf_protocol"]
            result_data = await _call_mcp_tool(
                MCP_URLS["waf"], "fingerprint_waf", args, timeout=120,
            )
    elif tool_name == "ffuf":
        ffuf_target = tool_config.get("ffuf_url", f"{http_target}/FUZZ")
        args = {"target": ffuf_target, "threads": 20}  # 20 threads is polite against remote targets
        if tool_config.get("ffuf_wordlist"):
            args["wordlist"] = tool_config["ffuf_wordlist"]
        if tool_config.get("ffuf_extensions"):
            args["extensions"] = tool_config["ffuf_extensions"]
        if tool_config.get("ffuf_method"):
            args["method"] = tool_config["ffuf_method"]
        if tool_config.get("ffuf_threads"):
            args["threads"] = int(tool_config["ffuf_threads"])
        if tool_config.get("ffuf_rate"):
            args["rate"] = int(tool_config["ffuf_rate"])
        if tool_config.get("ffuf_timeout"):
            args["timeout"] = int(tool_config["ffuf_timeout"])
        if tool_config.get("ffuf_match_codes"):
            args["match_codes"] = tool_config["ffuf_match_codes"]
        if tool_config.get("ffuf_filter_codes"):
            args["filter_codes"] = tool_config["ffuf_filter_codes"]
        if tool_config.get("ffuf_filter_size"):
            args["filter_size"] = tool_config["ffuf_filter_size"]
        if tool_config.get("ffuf_filter_words"):
            args["filter_words"] = tool_config["ffuf_filter_words"]
        if tool_config.get("ffuf_data"):
            args["data"] = tool_config["ffuf_data"]
        if tool_config.get("ffuf_headers"):
            args["headers"] = tool_config["ffuf_headers"]
        if tool_config.get("ffuf_recursion"):
            args["recursion"] = bool(tool_config["ffuf_recursion"])
        if tool_config.get("ffuf_recursion_depth"):
            args["recursion_depth"] = int(tool_config["ffuf_recursion_depth"])
        result_data = await _call_mcp_tool(
            MCP_URLS["ffuf"], "ffuf_fuzz",
            args,
            timeout=350,  # ffuf_server caps at 200 s subprocess; 350 gives HTTP headroom
        )
    elif tool_name in ("sqlmap", "sqlmap_full"):
        sql_target = tool_config.get("sqlmap_url", http_target)
        mcp_tool   = "sqlmap_full_chain" if tool_name == "sqlmap_full" else "sqlmap_scan"
        args = {"target": sql_target, "level": 3, "risk": 2, "technique": "BEUSTQ", "threads": 4}
        if tool_config.get("sqlmap_data"):
            args["data"] = tool_config["sqlmap_data"]
        if tool_config.get("sqlmap_level"):
            args["level"] = tool_config["sqlmap_level"]
        if tool_config.get("sqlmap_risk"):
            args["risk"] = tool_config["sqlmap_risk"]
        if tool_config.get("sqlmap_technique"):
            args["technique"] = tool_config["sqlmap_technique"]
        if tool_config.get("sqlmap_threads"):
            args["threads"] = tool_config["sqlmap_threads"]
        if tool_config.get("sqlmap_cookie"):
            args["cookie"] = tool_config["sqlmap_cookie"]
        if tool_config.get("sqlmap_dbms"):
            args["dbms"] = tool_config["sqlmap_dbms"]
        if tool_config.get("sqlmap_proxy"):
            args["proxy"] = tool_config["sqlmap_proxy"]
        if tool_config.get("sqlmap_headers"):
            args["headers"] = tool_config["sqlmap_headers"]
        if tool_config.get("sqlmap_auth_type"):
            args["auth_type"] = tool_config["sqlmap_auth_type"]
        if tool_config.get("sqlmap_auth_cred"):
            args["auth_cred"] = tool_config["sqlmap_auth_cred"]
        if tool_config.get("sqlmap_delay") is not None:
            args["delay"] = int(tool_config["sqlmap_delay"])
        if tool_config.get("sqlmap_timeout"):
            args["timeout_secs"] = int(tool_config["sqlmap_timeout"])
        if tool_config.get("sqlmap_retries") is not None:
            args["retries"] = int(tool_config["sqlmap_retries"])
        if tool_config.get("sqlmap_time_sec"):
            args["time_sec"] = int(tool_config["sqlmap_time_sec"])
        if tool_config.get("sqlmap_tamper"):
            args["tamper"] = tool_config["sqlmap_tamper"]
        result_data = await _call_mcp_tool(
            MCP_URLS["sqlmap"], mcp_tool,
            args,
            timeout=1200,  # full chain: detect (~550s) + all enum steps (up to 10 min total)
        )
    elif tool_name == "ssl":
        hostname = tool_config.get("domain", target)
        port = tool_config.get("nikto_port", 443)
        result_data = await _call_mcp_tool(
            MCP_URLS["ssl"], "check_ssl",
            {"hostname": hostname, "port": port},
            timeout=130,
        )
    elif tool_name == "osint":
        osint_fn = tool_config.get("osint_tool", "whois_lookup")
        osint_target = tool_config.get("osint_target", target)
        if osint_fn == "whois_lookup":
            args: dict = {"target": osint_target}
        elif osint_fn == "dns_lookup":
            args = {"domain": osint_target, "record_type": tool_config.get("record_type", "all")}
        elif osint_fn == "http_headers":
            args = {"url": osint_target if osint_target.startswith("http") else f"https://{osint_target}"}
        elif osint_fn == "ip_geolocation":
            args = {"ip": osint_target}
        elif osint_fn == "subdomain_enum":
            args = {"domain": osint_target}
        elif osint_fn == "ssl_info":
            args = {"hostname": osint_target, "port": tool_config.get("nikto_port", 443)}
        elif osint_fn == "tech_fingerprint":
            args = {"url": osint_target if osint_target.startswith("http") else f"https://{osint_target}"}
        else:
            args = {"target": osint_target}
        result_data = await _call_mcp_tool(
            MCP_URLS["osint"], osint_fn,
            args,
            timeout=60,
        )
    elif tool_name == "mitre":
        mitre_action = tool_config.get("mitre_action", "search_techniques")
        domain = tool_config.get("mitre_domain", "enterprise")
        base_args: dict = {"domain": domain}

        if mitre_action == "search_techniques":
            q = tool_config.get("mitre_query") or target
            base_args["query"] = q
            if tool_config.get("mitre_limit"):
                base_args["limit"] = int(tool_config["mitre_limit"])
            result_data = await _call_mcp_tool(MCP_URLS["mitre"], "search_techniques", base_args, timeout=30)

        elif mitre_action == "get_technique_by_id":
            base_args["technique_id"] = tool_config.get("mitre_technique_id", "").upper()
            result_data = await _call_mcp_tool(MCP_URLS["mitre"], "get_technique_by_id", base_args, timeout=30)

        elif mitre_action == "get_techniques_by_tactic":
            base_args["tactic"] = tool_config.get("mitre_tactic", "")
            base_args["include_subtechniques"] = bool(tool_config.get("mitre_include_subtechniques", True))
            result_data = await _call_mcp_tool(MCP_URLS["mitre"], "get_techniques_by_tactic", base_args, timeout=30)

        elif mitre_action == "get_techniques_by_platform":
            base_args["platform"] = tool_config.get("mitre_platform", "Linux")
            base_args["include_subtechniques"] = bool(tool_config.get("mitre_include_subtechniques", False))
            result_data = await _call_mcp_tool(MCP_URLS["mitre"], "get_techniques_by_platform", base_args, timeout=30)

        elif mitre_action == "get_subtechniques_of_technique":
            base_args["technique_id"] = tool_config.get("mitre_technique_id", "").upper()
            result_data = await _call_mcp_tool(MCP_URLS["mitre"], "get_subtechniques_of_technique", base_args, timeout=30)

        elif mitre_action == "get_technique_tactics":
            base_args["technique_id"] = tool_config.get("mitre_technique_id", "").upper()
            result_data = await _call_mcp_tool(MCP_URLS["mitre"], "get_technique_tactics", base_args, timeout=30)

        elif mitre_action == "get_groups_using_technique":
            base_args["technique_id"] = tool_config.get("mitre_technique_id", "").upper()
            result_data = await _call_mcp_tool(MCP_URLS["mitre"], "get_groups_using_technique", base_args, timeout=30)

        elif mitre_action == "get_techniques_used_by_group":
            base_args["group_id"] = tool_config.get("mitre_group_id", "")
            result_data = await _call_mcp_tool(MCP_URLS["mitre"], "get_techniques_used_by_group", base_args, timeout=30)

        elif mitre_action == "search_groups":
            base_args["query"] = tool_config.get("mitre_query") or target
            if tool_config.get("mitre_limit"):
                base_args["limit"] = int(tool_config["mitre_limit"])
            result_data = await _call_mcp_tool(MCP_URLS["mitre"], "search_groups", base_args, timeout=30)

        elif mitre_action == "get_mitigations_for_technique":
            base_args["technique_id"] = tool_config.get("mitre_technique_id", "").upper()
            result_data = await _call_mcp_tool(MCP_URLS["mitre"], "get_mitigations_for_technique", base_args, timeout=30)

        elif mitre_action == "get_techniques_mitigated_by":
            base_args["mitigation_id"] = tool_config.get("mitre_mitigation_id", "").upper()
            result_data = await _call_mcp_tool(MCP_URLS["mitre"], "get_techniques_mitigated_by", base_args, timeout=30)

        elif mitre_action == "search_software":
            base_args["query"] = tool_config.get("mitre_query") or target
            if tool_config.get("mitre_limit"):
                base_args["limit"] = int(tool_config["mitre_limit"])
            result_data = await _call_mcp_tool(MCP_URLS["mitre"], "search_software", base_args, timeout=30)

        elif mitre_action == "get_software_using_technique":
            base_args["technique_id"] = tool_config.get("mitre_technique_id", "").upper()
            result_data = await _call_mcp_tool(MCP_URLS["mitre"], "get_software_using_technique", base_args, timeout=30)

        elif mitre_action == "get_all_tactics":
            result_data = await _call_mcp_tool(MCP_URLS["mitre"], "get_all_tactics", base_args, timeout=30)

        elif mitre_action == "get_data_stats":
            result_data = await _call_mcp_tool(MCP_URLS["mitre"], "get_data_stats", base_args, timeout=30)

        elif mitre_action == "generate_layer":
            layer_args = {**base_args, "name": tool_config.get("mitre_query") or f"Workflow Layer - {target}"}
            result_data = await _call_mcp_tool(MCP_URLS["mitre"], "generate_layer", layer_args, timeout=30)

        else:
            result_data = {"success": False, "output": f"Unknown mitre_action: {mitre_action}"}

    elif tool_name == "cisa_kev":
        action = tool_config.get("kev_action", "check_kev")
        if action == "check_kev":
            raw_cve = tool_config.get("kev_cve_id", "").strip() or target
            cve_ids = _extract_cve_ids(raw_cve)
            if len(cve_ids) > 1:
                bulk_results = []
                all_success = True
                for cve_id in cve_ids:
                    one = await _call_mcp_tool(
                        MCP_URLS["cisa_kev"], "check_kev",
                        {"cve_id": cve_id},
                        timeout=30,
                    )
                    all_success = all_success and one.get("success", False)
                    bulk_results.append(
                        {"cve_id": cve_id, "success": one.get("success", False), "output": one.get("output", "")}
                    )
                result_data = {
                    "success": all_success,
                    "output": json.dumps(
                        {"mode": "bulk", "action": "check_kev", "cve_ids": cve_ids, "results": bulk_results}
                    ),
                }
            elif not cve_ids:
                # No CVE ID available — search KEV by discovered service keyword or target
                keyword = tool_config.get("_cve_keywords", target).split("|")[0].strip()
                result_data = await _call_mcp_tool(
                    MCP_URLS["cisa_kev"], "search_kev",
                    {"keyword": keyword, "limit": tool_config.get("kev_limit", 10)},
                    timeout=30,
                )
            else:
                result_data = await _call_mcp_tool(
                    MCP_URLS["cisa_kev"], "check_kev",
                    {"cve_id": cve_ids[0]},
                    timeout=30,
                )
        elif action == "search_kev":
            result_data = await _call_mcp_tool(
                MCP_URLS["cisa_kev"], "search_kev",
                {
                    "keyword": tool_config.get("kev_keyword", target),
                    "ransomware_only": tool_config.get("kev_ransomware_only", False),
                    "limit": tool_config.get("kev_limit", 15),
                },
                timeout=30,
            )
        elif action == "get_recent_kev":
            result_data = await _call_mcp_tool(
                MCP_URLS["cisa_kev"], "get_recent_kev",
                {
                    "days": tool_config.get("kev_days", 30),
                    "limit": tool_config.get("kev_limit", 20),
                },
                timeout=30,
            )
        else:  # get_kev_stats
            result_data = await _call_mcp_tool(
                MCP_URLS["cisa_kev"], "get_kev_stats",
                {"top_n": tool_config.get("kev_limit", 10)},
                timeout=30,
            )
    elif tool_name == "epss":
        action = tool_config.get("epss_action", "get_epss_score")
        if action == "get_epss_score":
            cve_id = tool_config.get("epss_cve_id", "").strip()
            if not cve_id and target.upper().startswith("CVE-"):
                cve_id = target
            if not cve_id:
                # No CVE ID — return top high-risk CVEs for situational awareness
                result_data = await _call_mcp_tool(
                    MCP_URLS["epss"], "get_high_epss_cves",
                    {"min_score": 0.7, "limit": 10},
                    timeout=20,
                )
            else:
                result_data = await _call_mcp_tool(
                    MCP_URLS["epss"], "get_epss_score",
                    {"cve_id": cve_id},
                    timeout=20,
                )
        elif action == "get_epss_scores_bulk":
            raw_ids = tool_config.get("epss_cve_ids", "")
            cve_ids = [c.strip() for c in raw_ids.split(",") if c.strip()]
            result_data = await _call_mcp_tool(
                MCP_URLS["epss"], "get_epss_scores_bulk",
                {"cve_ids": cve_ids},
                timeout=30,
            )
        elif action == "get_high_epss_cves":
            result_data = await _call_mcp_tool(
                MCP_URLS["epss"], "get_high_epss_cves",
                {
                    "min_score": tool_config.get("epss_min_score", 0.5),
                    "limit": tool_config.get("epss_limit", 20),
                },
                timeout=20,
            )
        else:  # epss_priority_analysis
            raw_ids = tool_config.get("epss_cve_ids", "")
            cve_ids = [c.strip() for c in raw_ids.split(",") if c.strip()]
            result_data = await _call_mcp_tool(
                MCP_URLS["epss"], "epss_priority_analysis",
                {"cve_ids": cve_ids},
                timeout=30,
            )
    elif tool_name == "poc_index":
        action = tool_config.get("poc_action", "search_poc")
        limit = tool_config.get("poc_limit", 10)
        if action == "search_poc":
            # Prefer explicit query, then nmap service versions, then target
            query = (
                tool_config.get("poc_query")
                or tool_config.get("_cve_keywords")
                or target
            )
            result_data = await _call_mcp_tool(
                MCP_URLS["poc_index"], "search_poc",
                {"query": query, "limit": limit},
                timeout=30,
            )
        elif action == "search_github_poc":
            raw_cve = tool_config.get("poc_cve_id", "").strip() or target
            cve_ids = _extract_cve_ids(raw_cve)
            if len(cve_ids) > 1:
                bulk_results = []
                all_success = True
                for cve_id in cve_ids:
                    one = await _call_mcp_tool(
                        MCP_URLS["poc_index"], "search_github_poc",
                        {"cve_id": cve_id, "limit": limit},
                        timeout=30,
                    )
                    all_success = all_success and one.get("success", False)
                    bulk_results.append(
                        {"cve_id": cve_id, "success": one.get("success", False), "output": one.get("output", "")}
                    )
                result_data = {
                    "success": all_success,
                    "output": json.dumps(
                        {"mode": "bulk", "action": "search_github_poc", "cve_ids": cve_ids, "results": bulk_results}
                    ),
                }
            else:
                result_data = await _call_mcp_tool(
                    MCP_URLS["poc_index"], "search_github_poc",
                    {"cve_id": (cve_ids[0] if cve_ids else ""), "limit": limit},
                    timeout=30,
                )
        elif action == "get_exploitdb_entry":
            result_data = await _call_mcp_tool(
                MCP_URLS["poc_index"], "get_exploitdb_entry",
                {"query": tool_config.get("poc_query", target), "limit": limit},
                timeout=30,
            )
        else:  # poc_risk_summary
            raw_cve = tool_config.get("poc_cve_id", "").strip() or target
            cve_ids = _extract_cve_ids(raw_cve)
            if len(cve_ids) > 1:
                bulk_results = []
                all_success = True
                for cve_id in cve_ids:
                    one = await _call_mcp_tool(
                        MCP_URLS["poc_index"], "poc_risk_summary",
                        {"cve_id": cve_id},
                        timeout=60,
                    )
                    all_success = all_success and one.get("success", False)
                    bulk_results.append(
                        {"cve_id": cve_id, "success": one.get("success", False), "output": one.get("output", "")}
                    )
                result_data = {
                    "success": all_success,
                    "output": json.dumps(
                        {"mode": "bulk", "action": "poc_risk_summary", "cve_ids": cve_ids, "results": bulk_results}
                    ),
                }
            else:
                result_data = await _call_mcp_tool(
                    MCP_URLS["poc_index"], "poc_risk_summary",
                    {"cve_id": (cve_ids[0] if cve_ids else "")},
                    timeout=60,
                )
    elif tool_name == "exploitdb":
        action = tool_config.get("edb_action", "search_exploits")
        limit  = int(tool_config.get("edb_limit", 10) or 10)

        if action == "search_exploits":
            result_data = await _call_mcp_tool(
                MCP_URLS["exploitdb"], "search_exploits",
                {
                    "query":    tool_config.get("edb_query") or target or None,
                    "platform": tool_config.get("edb_platform") or None,
                    "type":     tool_config.get("edb_type") or None,
                    "verified": bool(tool_config.get("edb_verified_only", False)),
                    "limit":    min(limit, 100),
                },
                timeout=30,
            )

        elif action == "get_exploit":
            exploit_id = tool_config.get("edb_exploit_id")
            if not exploit_id:
                result_data = {"success": False, "output": "edb_exploit_id is required for get_exploit action"}
            else:
                result_data = await _call_mcp_tool(
                    MCP_URLS["exploitdb"], "get_exploit",
                    {"id": int(exploit_id), "include_code": True},
                    timeout=30,
                )

        elif action == "find_by_cve":
            raw_cve = tool_config.get("edb_cve_id", "").strip() or target
            cve_ids = _extract_cve_ids(raw_cve)
            if len(cve_ids) > 1:
                bulk_results: list[dict] = []
                all_success = True
                for cve_id in cve_ids:
                    one = await _call_mcp_tool(
                        MCP_URLS["exploitdb"], "find_by_cve",
                        {"cve": cve_id, "limit": limit},
                        timeout=30,
                    )
                    all_success = all_success and one.get("success", False)
                    bulk_results.append(
                        {"cve": cve_id, "success": one.get("success", False), "output": one.get("output", "")}
                    )
                result_data = {
                    "success": all_success,
                    "output": json.dumps(
                        {"mode": "bulk", "action": "find_by_cve", "cve_ids": cve_ids, "results": bulk_results}
                    ),
                }
            else:
                result_data = await _call_mcp_tool(
                    MCP_URLS["exploitdb"], "find_by_cve",
                    {"cve": (cve_ids[0] if cve_ids else raw_cve), "limit": limit},
                    timeout=30,
                )

        elif action == "get_recent_exploits":
            result_data = await _call_mcp_tool(
                MCP_URLS["exploitdb"], "get_recent_exploits",
                {"limit": min(limit, 50)},
                timeout=30,
            )

        elif action == "get_trending_exploits":
            result_data = await _call_mcp_tool(
                MCP_URLS["exploitdb"], "get_trending_exploits",
                {"days": int(tool_config.get("edb_days", 30) or 30), "limit": min(limit, 50)},
                timeout=30,
            )

        elif action == "search_by_platform":
            result_data = await _call_mcp_tool(
                MCP_URLS["exploitdb"], "search_by_platform",
                {
                    "platform": tool_config.get("edb_platform") or target or "linux",
                    "type":     tool_config.get("edb_type") or None,
                    "verified": bool(tool_config.get("edb_verified_only", False)),
                    "limit":    min(limit, 100),
                },
                timeout=30,
            )

        elif action == "search_by_type":
            result_data = await _call_mcp_tool(
                MCP_URLS["exploitdb"], "search_by_type",
                {
                    "type":     tool_config.get("edb_type") or "webapps",
                    "platform": tool_config.get("edb_platform") or None,
                    "verified": bool(tool_config.get("edb_verified_only", False)),
                    "limit":    min(limit, 100),
                },
                timeout=30,
            )

        else:  # export_search_results
            result_data = await _call_mcp_tool(
                MCP_URLS["exploitdb"], "export_search_results",
                {
                    "query":    tool_config.get("edb_query") or target or None,
                    "format":   tool_config.get("edb_format", "json"),
                    "platform": tool_config.get("edb_platform") or None,
                    "type":     tool_config.get("edb_type") or None,
                    "limit":    min(limit, 200),
                },
                timeout=60,
            )

    elif tool_name == "metasploit":
        msf_action = tool_config.get("msf_action", "run_auxiliary")

        # Auto-upgrade empty run_auxiliary nodes to full-chain mode so workflows
        # do not keep running only portscan when nmap context is already available.
        if (
            msf_action == "run_auxiliary"
            and not tool_config.get("msf_module")
            and tool_config.get("msf_auto_chain", True)
        ):
            msf_action = "run_full_chain"

        if msf_action == "run_full_chain":
            target_host = tool_config.get("msf_rhosts") or target
            open_ports = _to_int_ports(tool_config.get("msf_open_ports", []))
            # Service names from nmap -sV: {port: "mysql"}, enables non-standard port mapping
            msf_services: dict[int, str] = {
                int(k): str(v) for k, v in tool_config.get("msf_services", {}).items()
                if str(k).isdigit()
            }
            mode = str(tool_config.get("msf_chain_mode", "balanced")).lower()
            if mode not in ("balanced", "aggressive"):
                mode = "balanced"

            include_exploit_checks = bool(tool_config.get("msf_chain_exploit_checks", True))
            run_post = bool(tool_config.get("msf_chain_post", True))
            max_modules = int(tool_config.get("msf_chain_limit", 24 if mode == "balanced" else 40))
            max_modules = max(4, min(max_modules, 120))

            if not open_ports and tool_config.get("msf_target_port"):
                try:
                    open_ports = [int(tool_config.get("msf_target_port"))]
                except Exception:
                    open_ports = []

            if not open_ports:
                result_data = {
                    "success": False,
                    "output": json.dumps({
                        "success": False,
                        "mode": mode,
                        "message": "Metasploit full-chain requires open ports. Run nmap first or set msf_target_port.",
                        "exploited": False,
                        "has_session": False,
                        "attempted_modules": 0,
                    }),
                }
            else:
                plan = _plan_metasploit_full_chain(open_ports, mode, include_exploit_checks, msf_services)
                aux_modules: list[str] = list(plan.get("auxiliary_modules", []))
                exploit_checks: list[dict] = list(plan.get("exploit_checks", []))
                post_modules: list[str] = list(plan.get("post_modules", []))

                runs: list[dict] = []
                sessions: list[int] = []
                total_attempted = 0

                for module_path in aux_modules:
                    if total_attempted >= max_modules:
                        break
                    aux_args: dict = {"module_path": module_path, "rhosts": target_host}
                    if tool_config.get("msf_options"):
                        aux_args["options"] = tool_config["msf_options"]
                    one = await _call_mcp_tool(
                        MCP_URLS["metasploit"], "run_auxiliary_module", aux_args, timeout=240
                    )
                    total_attempted += 1
                    # Extract real MSF session IDs: prefer top-level msf_session_ids /
                    # session_id (set correctly by run_auxiliary_module after MCP fix).
                    # Fall back to parsing output JSON only as last resort.
                    _aux_sids: list[int] = []
                    for _s in (one.get("msf_session_ids") or []):
                        try: _aux_sids.append(int(_s))
                        except (TypeError, ValueError): pass
                    _aux_top = one.get("session_id")
                    if isinstance(_aux_top, int) and _aux_top not in _aux_sids:
                        _aux_sids.append(_aux_top)
                    if not _aux_sids:
                        _aux_obj = _try_json_dict(one.get("output", ""))
                        _aux_fb = _aux_obj.get("session_id")
                        if isinstance(_aux_fb, str) and _aux_fb.isdigit(): _aux_fb = int(_aux_fb)
                        if isinstance(_aux_fb, int): _aux_sids.append(_aux_fb)
                    sessions.extend(s for s in _aux_sids if s not in sessions)
                    session_id = _aux_sids[0] if _aux_sids else None
                    runs.append({
                        "phase": "auxiliary",
                        "module": module_path,
                        "success": bool(one.get("success", False)) or bool(_aux_sids),
                        "session_id": session_id,
                        "output": str(one.get("output", ""))[:1200],
                    })

                for exp in exploit_checks:
                    if total_attempted >= max_modules:
                        break
                    module_path = str(exp.get("module", "")).strip()
                    if not module_path:
                        continue
                    exp_args: dict = {
                        "exploit_path": module_path,
                        "target_host": target_host,
                        "check_first": bool(tool_config.get("msf_check_first", True)),
                    }
                    port = exp.get("port")
                    if isinstance(port, int):
                        exp_args["target_port"] = port
                    if tool_config.get("msf_payload"):
                        exp_args["payload"] = tool_config["msf_payload"]
                    if tool_config.get("msf_lhost"):
                        exp_args["lhost"] = tool_config["msf_lhost"]
                    if tool_config.get("msf_lport"):
                        exp_args["lport"] = int(tool_config["msf_lport"])
                    if tool_config.get("msf_options"):
                        exp_args["options"] = tool_config["msf_options"]
                    one = await _call_mcp_tool(
                        MCP_URLS["metasploit"], "run_exploit", exp_args, timeout=300
                    )
                    total_attempted += 1
                    # Extract real MSF session IDs from run_exploit MCP result
                    _exp_sids: list[int] = []
                    for _s in (one.get("msf_session_ids") or []):
                        try: _exp_sids.append(int(_s))
                        except (TypeError, ValueError): pass
                    _exp_top = one.get("session_id")
                    if isinstance(_exp_top, int) and _exp_top not in _exp_sids:
                        _exp_sids.append(_exp_top)
                    if not _exp_sids and one.get("has_session"):
                        _exp_obj = _try_json_dict(one.get("output", ""))
                        _exp_fb = _exp_obj.get("session_id")
                        if isinstance(_exp_fb, str) and _exp_fb.isdigit(): _exp_fb = int(_exp_fb)
                        if isinstance(_exp_fb, int): _exp_sids.append(_exp_fb)
                    sessions.extend(s for s in _exp_sids if s not in sessions)
                    session_id = _exp_sids[0] if _exp_sids else None
                    runs.append({
                        "phase": "exploit_check",
                        "module": module_path,
                        "port": port,
                        "success": bool(one.get("has_session", False)) or bool(_exp_sids),
                        "session_id": session_id,
                        "output": str(one.get("output", ""))[:1200],
                    })

                # Execute post modules only when at least one session was opened.
                sessions = sorted(list(set(s for s in sessions if isinstance(s, int))))
                if run_post and sessions:
                    for sid in sessions[:2]:
                        for post_module in post_modules:
                            if total_attempted >= max_modules:
                                break
                            one = await _call_mcp_tool(
                                MCP_URLS["metasploit"],
                                "run_post_module",
                                {"module_path": post_module, "session_id": sid},
                                timeout=180,
                            )
                            total_attempted += 1
                            runs.append({
                                "phase": "post",
                                "module": post_module,
                                "session_id": sid,
                                "success": bool(one.get("success", False)),
                                "output": str(one.get("output", ""))[:1200],
                            })

                success_count = sum(1 for r in runs if r.get("success"))
                failed_modules = [str(r.get("module", "")) for r in runs if not r.get("success")]
                payload = {
                    "success": success_count > 0,
                    "mode": mode,
                    "target": target_host,
                    "open_ports": open_ports,
                    "attempted_modules": len(runs),
                    "successful_modules": success_count,
                    "failed_modules": failed_modules[:40],
                    "sessions_opened": sessions,
                    "has_session": len(sessions) > 0,
                    "session_id": sessions[0] if sessions else None,
                    "exploited": len(sessions) > 0,
                    "runs": runs,
                }
                result_data = {
                    "success": success_count > 0,
                    "output": json.dumps(payload),
                    "msf_session_ids": [str(s) for s in sessions],
                }

        elif msf_action == "run_exploit":
            module = tool_config.get("msf_module", "exploit/multi/handler")
            opts: dict = {}
            if tool_config.get("msf_lhost"):
                opts["LHOST"] = tool_config["msf_lhost"]
            if tool_config.get("msf_lport"):
                opts["LPORT"] = str(tool_config["msf_lport"])
            if tool_config.get("msf_options"):
                opts.update(tool_config["msf_options"])
            call_args: dict = {
                "exploit_path": module,
                "target_host": target,
                "check_first": tool_config.get("msf_check_first", True),
            }
            if tool_config.get("msf_target_port"):
                call_args["target_port"] = tool_config["msf_target_port"]
            if tool_config.get("msf_payload"):
                call_args["payload"] = tool_config["msf_payload"]
            if opts:
                call_args["options"] = opts
            result_data = await _call_mcp_tool(
                MCP_URLS["metasploit"], "run_exploit", call_args, timeout=300)

        elif msf_action == "run_post":
            post_args: dict = {
                "module_path": tool_config.get("msf_module", ""),
                "session_id": int(tool_config.get("msf_session_id", 1)),
            }
            if tool_config.get("msf_options"):
                post_args["options"] = tool_config["msf_options"]
            result_data = await _call_mcp_tool(
                MCP_URLS["metasploit"], "run_post_module", post_args, timeout=120)

        elif msf_action == "list_exploits":
            le_args: dict = {"query": tool_config.get("msf_query") or target}
            if tool_config.get("msf_module_type"):
                le_args["type"] = tool_config["msf_module_type"]
            if tool_config.get("msf_limit"):
                le_args["limit"] = int(tool_config["msf_limit"])
            result_data = await _call_mcp_tool(
                MCP_URLS["metasploit"], "list_exploits", le_args, timeout=60)

        elif msf_action == "list_payloads":
            lp_args: dict = {}
            if tool_config.get("msf_query"):
                lp_args["query"] = tool_config["msf_query"]
            if tool_config.get("msf_platform"):
                lp_args["platform"] = tool_config["msf_platform"]
            if tool_config.get("msf_arch"):
                lp_args["arch"] = tool_config["msf_arch"]
            if tool_config.get("msf_limit"):
                lp_args["limit"] = int(tool_config["msf_limit"])
            result_data = await _call_mcp_tool(
                MCP_URLS["metasploit"], "list_payloads", lp_args, timeout=60)

        elif msf_action == "get_module_info":
            result_data = await _call_mcp_tool(
                MCP_URLS["metasploit"], "get_module_info",
                {"module_path": tool_config.get("msf_module", "")}, timeout=30)

        elif msf_action == "list_sessions":
            result_data = await _call_mcp_tool(
                MCP_URLS["metasploit"], "list_active_sessions", {}, timeout=30)

        elif msf_action == "send_command":
            result_data = await _call_mcp_tool(
                MCP_URLS["metasploit"], "send_session_command",
                {"session_id": int(tool_config.get("msf_session_id", 1)),
                 "command": tool_config.get("msf_command", ""),
                 "wait_ms": int(tool_config.get("msf_wait_ms", 300)),
                 "max_reads": int(tool_config.get("msf_max_reads", 8))}, timeout=60)

        elif msf_action == "interactive_handoff":
            session_id = tool_config.get("msf_session_id")
            selected_session_id = None

            if session_id is not None and str(session_id).strip() != "":
                try:
                    selected_session_id = int(session_id)
                except (TypeError, ValueError):
                    selected_session_id = None

            # If not provided, attempt to pick the newest active session.
            if selected_session_id is None:
                sessions_data = await _call_mcp_tool(
                    MCP_URLS["metasploit"], "list_active_sessions", {}, timeout=30)
                metasploit_sessions = sessions_data.get("metasploit") if isinstance(sessions_data, dict) else None
                if isinstance(metasploit_sessions, dict) and metasploit_sessions:
                    numeric_ids = []
                    for k in metasploit_sessions.keys():
                        try:
                            numeric_ids.append(int(k))
                        except (TypeError, ValueError):
                            continue
                    if numeric_ids:
                        selected_session_id = max(numeric_ids)

            handoff_payload = {
                "success": selected_session_id is not None,
                "interactive_handoff": True,
                "session_id": selected_session_id,
                "message": (
                    "Interactive handoff ready"
                    if selected_session_id is not None
                    else "No active Metasploit session available for handoff"
                ),
            }
            result_data = {
                "success": handoff_payload["success"],
                "output": json.dumps(handoff_payload),
            }

        elif msf_action == "terminate_session":
            result_data = await _call_mcp_tool(
                MCP_URLS["metasploit"], "terminate_session",
                {"session_id": int(tool_config.get("msf_session_id", 1))}, timeout=30)

        elif msf_action == "generate_payload":
            gp_args: dict = {
                "payload": tool_config.get("msf_payload", ""),
                "format": tool_config.get("msf_format", "exe"),
                "lhost": tool_config.get("msf_lhost", ""),
                "lport": int(tool_config.get("msf_lport", 4444)),
            }
            if tool_config.get("msf_options"):
                gp_args["options"] = tool_config["msf_options"]
            result_data = await _call_mcp_tool(
                MCP_URLS["metasploit"], "generate_payload", gp_args, timeout=60)

        elif msf_action == "start_listener":
            result_data = await _call_mcp_tool(
                MCP_URLS["metasploit"], "start_listener",
                {"payload": tool_config.get("msf_payload", ""),
                 "lhost": tool_config.get("msf_lhost", ""),
                 "lport": int(tool_config.get("msf_lport", 4444))}, timeout=60)

        elif msf_action == "list_listeners":
            result_data = await _call_mcp_tool(
                MCP_URLS["metasploit"], "list_listeners", {}, timeout=30)

        elif msf_action == "stop_job":
            result_data = await _call_mcp_tool(
                MCP_URLS["metasploit"], "stop_job",
                {"job_id": int(tool_config.get("msf_job_id", 0))}, timeout=30)

        else:  # default: run_auxiliary (explicit module)
            aux_opts: dict = {}
            if tool_config.get("msf_options"):
                aux_opts.update(tool_config["msf_options"])
            module_path = tool_config.get("msf_module", "").strip()
            if not module_path:
                result_data = {
                    "success": False,
                    "output": json.dumps({
                        "success": False,
                        "message": "No Metasploit module selected. Set a module path or choose Full Chain mode.",
                    }),
                }
            else:
                aux_args: dict = {
                    "module_path": module_path,
                    "rhosts": tool_config.get("msf_rhosts") or target,
                }
                if aux_opts:
                    aux_args["options"] = aux_opts
                result_data = await _call_mcp_tool(
                    MCP_URLS["metasploit"], "run_auxiliary_module", aux_args, timeout=300)
    elif tool_name == "subfinder":
        domain = tool_config.get("domain", target)
        result_data = await _call_mcp_tool(
            MCP_URLS["osint"], "subdomain_enum",
            {"domain": domain},
            timeout=120,
        )
    elif tool_name == "testssl":
        result_data = await _call_mcp_tool(
            MCP_URLS["ssl"], "check_ssl",
            {"hostname": target},
            timeout=130,
        )
    elif tool_name == "nikto":
        nikto_target = tool_config.get("nikto_url", http_target)
        # Default nikto timeout to 600s — nikto is slow on most targets
        nikto_timeout = int(tool_config.get("nikto_timeout", 600))
        args: dict = {"target": nikto_target, "timeout": nikto_timeout}
        if tool_config.get("nikto_port"):
            args["port"] = int(tool_config["nikto_port"])
        if tool_config.get("nikto_useragent"):
            args["useragent"] = tool_config["nikto_useragent"]
        if tool_config.get("nikto_proxy"):
            args["proxy"] = tool_config["nikto_proxy"]
        if tool_config.get("nikto_auth"):
            args["auth"] = tool_config["nikto_auth"]
        if tool_config.get("nikto_maxtime"):
            args["maxtime"] = tool_config["nikto_maxtime"]
        if tool_config.get("nikto_evasion"):
            args["evasion"] = tool_config["nikto_evasion"]
        nikto_action = tool_config.get("nikto_action", "nikto_scan")
        if nikto_action == "nikto_tuning":
            if tool_config.get("nikto_tuning"):
                args["tuning"] = tool_config["nikto_tuning"]
            result_data = await _call_mcp_tool(MCP_URLS["nikto"], "nikto_tuning", args, timeout=nikto_timeout + 30)
        elif nikto_action == "nikto_ssl_only":
            result_data = await _call_mcp_tool(MCP_URLS["nikto"], "nikto_ssl_only", args, timeout=nikto_timeout + 30)
        else:
            result_data = await _call_mcp_tool(MCP_URLS["nikto"], "nikto_scan", args, timeout=nikto_timeout + 30)
    elif tool_name == "masscan":
        def _masscan_port_count(port_spec: str) -> int:
            """Best-effort count of ports requested by a masscan port spec."""
            try:
                total = 0
                for token in str(port_spec or "").split(","):
                    part = token.strip()
                    if not part:
                        continue
                    if "-" in part:
                        lo_s, hi_s = part.split("-", 1)
                        lo, hi = int(lo_s), int(hi_s)
                        if hi >= lo:
                            total += (hi - lo + 1)
                    else:
                        int(part)
                        total += 1
                return total if total > 0 else 1024
            except Exception:
                return 1024

        def _masscan_timeout_for_scan(action: str, cfg: dict) -> int:
            """
            Estimate a safe timeout from scope/rate.
            We add a buffer for late responses and MCP overhead.
            """
            configured_timeout = cfg.get("timeout_override", cfg.get("timeout"))
            if configured_timeout is not None:
                try:
                    # Respect explicit node timeout from workflow config.
                    return max(30, min(int(configured_timeout), 900))
                except (TypeError, ValueError):
                    pass

            rate = max(1, int(cfg.get("masscan_rate", 1000) or 1000))
            if action == "masscan_top_ports":
                requested_ports = int(cfg.get("masscan_top", 1000) or 1000)
            elif action == "masscan_range":
                requested_ports = _masscan_port_count(str(cfg.get("masscan_ports", "22,80,443,445,3389,8080")))
            else:
                requested_ports = _masscan_port_count(str(cfg.get("masscan_ports", "1-1024")))

            est_seconds = (requested_ports / float(rate))
            timeout = int(est_seconds + 45)  # grace for response wait + processing
            return max(120, min(timeout, 900))

        masscan_action = tool_config.get("masscan_action", "masscan_scan")
        extra_args = tool_config.get("masscan_extra_args", "")
        if masscan_action == "masscan_top_ports":
            req_timeout = _masscan_timeout_for_scan(masscan_action, tool_config)
            result_data = await _call_mcp_tool(
                MCP_URLS["masscan"], "masscan_top_ports",
                {"target": target, "top": int(tool_config.get("masscan_top", 1000)),
                 "rate": int(tool_config.get("masscan_rate", 2000)),
                 "extra_args": extra_args,
                 "timeout": req_timeout}, timeout=req_timeout)
        elif masscan_action == "masscan_range":
            req_timeout = _masscan_timeout_for_scan(masscan_action, tool_config)
            result_data = await _call_mcp_tool(
                MCP_URLS["masscan"], "masscan_range",
                {"cidr": tool_config.get("masscan_cidr", target),
                 "ports": tool_config.get("masscan_ports", "22,80,443,445,3389,8080"),
                 "rate": int(tool_config.get("masscan_rate", 500)),
                 "extra_args": extra_args,
                 "timeout": req_timeout}, timeout=req_timeout)
        else:
            req_timeout = _masscan_timeout_for_scan(masscan_action, tool_config)
            result_data = await _call_mcp_tool(
                MCP_URLS["masscan"], "masscan_scan",
                {"target": target, "ports": tool_config.get("masscan_ports", "1-1024"),
                 "rate": int(tool_config.get("masscan_rate", 1000)),
                 "extra_args": extra_args,
                 "timeout": req_timeout}, timeout=req_timeout)
    elif tool_name == "wpscan":
        wpscan_action = tool_config.get("wpscan_action", "wp_scan")
        wpscan_url = tool_config.get("wpscan_url", http_target)
        token_arg: dict = {}
        if tool_config.get("wpscan_api_token"):
            token_arg["api_token"] = tool_config["wpscan_api_token"]
        if wpscan_action == "wp_enum_users":
            user_args: dict = {"url": wpscan_url}
            if tool_config.get("wpscan_username_wordlist"):
                user_args["usernames"] = tool_config["wpscan_username_wordlist"]
            if tool_config.get("wpscan_password_wordlist"):
                user_args["passwords"] = tool_config["wpscan_password_wordlist"]
            result_data = await _call_mcp_tool(
                MCP_URLS["wpscan"], "wp_enum_users",
                user_args, timeout=600)  # wp_enum_users has no api_token field (WPVulnDB data only applies to vuln lookups)
        elif wpscan_action == "wp_enum_plugins":
            result_data = await _call_mcp_tool(
                MCP_URLS["wpscan"], "wp_enum_plugins",
                {"url": wpscan_url, "detection_mode": tool_config.get("wpscan_detection", "mixed"), **token_arg}, timeout=300)
        elif wpscan_action == "wp_enum_themes":
            result_data = await _call_mcp_tool(
                MCP_URLS["wpscan"], "wp_enum_themes",
                {"url": wpscan_url, "detection_mode": tool_config.get("wpscan_detection", "mixed")}, timeout=180)
        else:
            result_data = await _call_mcp_tool(
                MCP_URLS["wpscan"], "wp_scan",
                {"url": wpscan_url, "enumerate": tool_config.get("wpscan_enumerate", "u,vp,vt"), **token_arg}, timeout=300)
    elif tool_name == "jwt":
        jwt_action = tool_config.get("jwt_action", "decode_jwt")
        jwt_token = tool_config.get("jwt_token", "")
        if jwt_action == "test_alg_none":
            result_data = await _call_mcp_tool(
                MCP_URLS["jwt"], "test_alg_none", {"token": jwt_token}, timeout=30)
        elif jwt_action == "test_weak_secret":
            result_data = await _call_mcp_tool(
                MCP_URLS["jwt"], "test_weak_secret",
                {"token": jwt_token, "wordlist": tool_config.get("jwt_wordlist", "passwords")}, timeout=120)
        elif jwt_action == "forge_jwt":
            result_data = await _call_mcp_tool(
                MCP_URLS["jwt"], "forge_jwt",
                {"secret": tool_config.get("jwt_secret", ""),
                 "algorithm": tool_config.get("jwt_algorithm", "HS256"),
                 "claims": tool_config.get("jwt_claims", {})}, timeout=30)
        elif jwt_action == "analyze_claims":
            result_data = await _call_mcp_tool(
                MCP_URLS["jwt"], "analyze_claims", {"token": jwt_token}, timeout=30)
        else:  # decode_jwt
            result_data = await _call_mcp_tool(
                MCP_URLS["jwt"], "decode_jwt", {"token": jwt_token}, timeout=30)
    elif tool_name == "gobuster":
        gobuster_mode = tool_config.get("gobuster_mode", "dir")
        # Common optional args
        _gob_extra: dict = {}
        if tool_config.get("gobuster_threads"):
            _gob_extra["threads"] = int(tool_config["gobuster_threads"])
        if tool_config.get("gobuster_timeout"):
            _gob_extra["timeout"] = int(tool_config["gobuster_timeout"])
        if tool_config.get("gobuster_proxy"):
            _gob_extra["proxy"] = tool_config["gobuster_proxy"]
        if tool_config.get("gobuster_headers"):
            _gob_extra["headers"] = tool_config["gobuster_headers"]
        if tool_config.get("gobuster_username"):
            _gob_extra["username"] = tool_config["gobuster_username"]
        if tool_config.get("gobuster_password"):
            _gob_extra["password"] = tool_config["gobuster_password"]
        if gobuster_mode == "dns":
            result_data = await _call_mcp_tool(
                MCP_URLS["gobuster"], "gobuster_dns",
                {"domain": tool_config.get("gobuster_domain", target),
                 "wordlist": tool_config.get("gobuster_wordlist", ""),
                 **_gob_extra}, timeout=600)
        elif gobuster_mode == "vhost":
            result_data = await _call_mcp_tool(
                MCP_URLS["gobuster"], "gobuster_vhost",
                {"url": tool_config.get("gobuster_url", http_target),
                 "domain": tool_config.get("gobuster_domain", target),
                 "wordlist": tool_config.get("gobuster_wordlist", ""),
                 **_gob_extra}, timeout=600)
        elif gobuster_mode == "fuzz":
            result_data = await _call_mcp_tool(
                MCP_URLS["gobuster"], "gobuster_fuzz",
                {"url": tool_config.get("gobuster_url", http_target + "/FUZZ"),
                 "wordlist": tool_config.get("gobuster_wordlist", ""),
                 **_gob_extra}, timeout=600)
        else:  # dir
            _dir_extra = {**_gob_extra}
            if tool_config.get("gobuster_expanded"):
                _dir_extra["expanded"] = bool(tool_config["gobuster_expanded"])
            result_data = await _call_mcp_tool(
                MCP_URLS["gobuster"], "gobuster_dir",
                {"url": tool_config.get("gobuster_url", http_target),
                 "wordlist": tool_config.get("gobuster_wordlist", ""),
                 "extensions": tool_config.get("gobuster_extensions", ""),
                 "status_codes": tool_config.get("gobuster_status_codes", "200,204,301,302,307,401,403"),
                 **_dir_extra}, timeout=600)
    elif tool_name == "cve_lite":
        cve_lite_action = tool_config.get("cve_lite_action", "scan")
        if cve_lite_action == "advisories_sync":
            result_data = await _call_mcp_tool(
                MCP_URLS["cve_lite"], "cve_lite_advisories_sync",
                {"output_path": tool_config.get("cve_lite_offline_db", "/tmp/cve-lite-advisories.sqlite3")},
                timeout=120)
        elif cve_lite_action == "version":
            result_data = await _call_mcp_tool(
                MCP_URLS["cve_lite"], "cve_lite_version", {}, timeout=15)
        else:  # scan (default)
            # Defense-in-depth: sanitize path before passing to MCP
            # (MCP also enforces allowed-roots via _validate_path)
            _raw_path = tool_config.get("cve_lite_project_path", "").strip().replace("\x00", "")
            import posixpath as _pp
            _norm_path = _pp.normpath(_raw_path) if _raw_path else ""
            # Reject if any traversal component survived normalization or path is relative
            _safe_project_path = (
                _norm_path
                if _raw_path and _norm_path.startswith("/") and ".." not in _norm_path.split("/")
                else ""
            )
            scan_args: dict = {
                "project_path": _safe_project_path,
            }
            if tool_config.get("cve_lite_min_severity"):
                scan_args["min_severity"] = tool_config["cve_lite_min_severity"]
            if tool_config.get("cve_lite_all"):
                scan_args["all"] = bool(tool_config["cve_lite_all"])
            if tool_config.get("cve_lite_prod_only"):
                scan_args["prod_only"] = bool(tool_config["cve_lite_prod_only"])
            if tool_config.get("cve_lite_usage"):
                scan_args["usage"] = bool(tool_config["cve_lite_usage"])
            if tool_config.get("cve_lite_only_used"):
                scan_args["only_used"] = bool(tool_config["cve_lite_only_used"])
            if tool_config.get("cve_lite_offline"):
                scan_args["offline"] = bool(tool_config["cve_lite_offline"])
            if tool_config.get("cve_lite_offline_db"):
                scan_args["offline_db"] = tool_config["cve_lite_offline_db"]
            if tool_config.get("cve_lite_fail_on"):
                scan_args["fail_on"] = tool_config["cve_lite_fail_on"]
            result_data = await _call_mcp_tool(
                MCP_URLS["cve_lite"], "cve_lite_scan", scan_args, timeout=120)
    elif tool_name.startswith("mcp:"):
        # Manifest-driven "MCP Tool" node: "mcp:<server>:<action>".
        parts = tool_name.split(":", 2)
        if len(parts) != 3:
            result_data = {"output": f"Malformed tool id: {tool_name}", "success": False}
        else:
            result_data = await _dispatch_manifest_tool(parts[1], parts[2], tool_config, target, http_target)
    else:
        result_data = {"output": f"Tool {tool_name} not yet configured", "success": False}

    duration_ms = int(time.time() * 1000) - start_ms
    return tool_name, result_data, duration_ms


# ─── Main Scan Task ───────────────────────────────────────────

async def _notify_ws(scan_id: str, event_type: str, payload: dict):
    """Broadcast a scan progress update over WebSocket via Redis pub/sub.

    The ARQ worker runs in a separate process/container from the API.
    In-memory ConnectionManager has no WebSocket connections here, so we
    publish to Redis and let the API's WebSocket endpoint forward it.
    """
    try:
        import redis.asyncio as aioredis
        redis_url = settings.REDIS_URL or "redis://redis:6379"
        r = aioredis.from_url(redis_url)
        msg = json.dumps({
            "type": event_type,
            "scan_id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **payload,
        })
        await r.publish(f"scan:{scan_id}", msg)
        await r.aclose()
    except Exception as e:
        logger.debug(f"WebSocket publish failed (non-critical): {e}")


async def _update_scan_status(db, scan_id: str, status: str, **kwargs):
    """Update scan status in the database."""
    from sqlalchemy import update
    from app.models.scan import Scan, ScanStatus
    stmt = (
        update(Scan)
        .where(Scan.id == uuid.UUID(scan_id))
        .values(status=status, **kwargs)
    )
    await db.execute(stmt)
    await db.commit()


# ─── Workflow Helpers ─────────────────────────────────────────

import re as _re_nmap
_NMAP_PORT_RE = _re_nmap.compile(r'(\d+)/tcp[ \t]+open[ \t]+(\S+)', _re_nmap.IGNORECASE)


def _extract_nmap_context(output: str) -> dict:
    """Parse nmap output (JSON or raw text) to extract open ports/services for workflow step filtering."""
    open_ports: list[int] = []
    services: dict[int, str] = {}
    host_up: bool = False

    # Try structured JSON first — nmap MCP server returns JSON with open_ports array
    try:
        parsed = json.loads(output)
        if isinstance(parsed, dict) and "open_ports" in parsed:
            host_up = bool(parsed.get("host_up", False))
            for p in parsed.get("open_ports", []):
                if isinstance(p, dict) and isinstance(p.get("port"), int):
                    port = p["port"]
                    svc = str(p.get("service", "")).lower()
                    open_ports.append(port)
                    services[port] = svc
    except Exception:
        pass

    # Fall back to regex parsing on raw nmap text
    if not open_ports:
        raw_text = output
        try:
            _p = json.loads(output)
            raw_text = _p.get("raw", output) if isinstance(_p, dict) else output
            if not host_up and "host is up" in raw_text.lower():
                host_up = True
        except Exception:
            if "host is up" in output.lower():
                host_up = True
        for m in _NMAP_PORT_RE.finditer(raw_text):
            port = int(m.group(1))
            svc = m.group(2).lower()
            open_ports.append(port)
            services[port] = svc

    # Detect HTTP ports by known port numbers OR by service name from nmap -sV detection.
    # This handles non-standard ports like HTTP on 9000, 8888, 3000 etc.
    _HTTP_SVC_KEYWORDS = ("http", "https", "web", "websocket", "ws/")
    http_ports = [
        p for p in open_ports
        if p in (80, 443, 8000, 8080, 8443, 3000, 8888)
        or any(kw in services.get(p, "").lower() for kw in _HTTP_SVC_KEYWORDS)
    ]
    return {
        "open_ports": open_ports,
        "services": services,
        "host_up": host_up,
        "has_http": len(http_ports) > 0,
        "http_ports": http_ports,
    }


def _to_int_ports(raw_ports) -> list[int]:
    ports: list[int] = []
    if isinstance(raw_ports, list):
        for p in raw_ports:
            if isinstance(p, int):
                ports.append(p)
            elif isinstance(p, dict) and isinstance(p.get("port"), int):
                ports.append(int(p["port"]))
            else:
                try:
                    ports.append(int(str(p)))
                except Exception:
                    continue
    elif isinstance(raw_ports, str):
        for p in raw_ports.split(","):
            p = p.strip()
            if not p:
                continue
            try:
                ports.append(int(p))
            except Exception:
                continue
    return sorted(list(set(ports)))


def _try_json_dict(raw: str) -> dict:
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


_MSF_AUX_BY_PORT_BALANCED: dict[int, list[str]] = {
    21: ["auxiliary/scanner/ftp/ftp_version", "auxiliary/scanner/ftp/anonymous"],
    22: ["auxiliary/scanner/ssh/ssh_version", "auxiliary/scanner/ssh/ssh_enumusers"],
    25: ["auxiliary/scanner/smtp/smtp_version", "auxiliary/scanner/smtp/smtp_enum"],
    53: ["auxiliary/gather/dns_info", "auxiliary/gather/dns_enum"],
    80: ["auxiliary/scanner/http/http_version", "auxiliary/scanner/http/title", "auxiliary/scanner/http/robots_txt"],
    110: ["auxiliary/scanner/pop3/pop3_version"],
    139: ["auxiliary/scanner/smb/smb_version", "auxiliary/scanner/smb/smb_enumshares"],
    143: ["auxiliary/scanner/imap/imap_version"],
    443: ["auxiliary/scanner/http/http_version", "auxiliary/scanner/http/title"],
    445: ["auxiliary/scanner/smb/smb_version", "auxiliary/scanner/smb/smb_enumshares", "auxiliary/scanner/smb/smb_ms17_010"],
    3306: ["auxiliary/scanner/mysql/mysql_version", "auxiliary/scanner/mysql/mysql_login"],
    3389: ["auxiliary/scanner/rdp/rdp_scanner"],
    5432: ["auxiliary/scanner/postgres/postgres_version", "auxiliary/scanner/postgres/postgres_login"],
    5900: ["auxiliary/scanner/vnc/vnc_none_auth", "auxiliary/scanner/vnc/vnc_login"],
    6379: ["auxiliary/scanner/redis/redis_server"],
    8080: ["auxiliary/scanner/http/http_version", "auxiliary/scanner/http/title"],
    8443: ["auxiliary/scanner/http/http_version", "auxiliary/scanner/http/title"],
}

# Service-name → modules: used when nmap finds a service on a NON-STANDARD port.
# Keys are lowercase substrings matched against nmap's service detection output.
_MSF_AUX_BY_SERVICE: dict[str, list[str]] = {
    "ftp":          ["auxiliary/scanner/ftp/ftp_version", "auxiliary/scanner/ftp/anonymous"],
    "ssh":          ["auxiliary/scanner/ssh/ssh_version", "auxiliary/scanner/ssh/ssh_enumusers"],
    "smtp":         ["auxiliary/scanner/smtp/smtp_version", "auxiliary/scanner/smtp/smtp_enum"],
    "pop3":         ["auxiliary/scanner/pop3/pop3_version"],
    "imap":         ["auxiliary/scanner/imap/imap_version"],
    "telnet":       ["auxiliary/scanner/telnet/telnet_version"],
    "http":         ["auxiliary/scanner/http/http_version", "auxiliary/scanner/http/title", "auxiliary/scanner/http/robots_txt"],
    "https":        ["auxiliary/scanner/http/http_version", "auxiliary/scanner/http/title"],
    "web":          ["auxiliary/scanner/http/http_version", "auxiliary/scanner/http/title"],
    "mysql":        ["auxiliary/scanner/mysql/mysql_version", "auxiliary/scanner/mysql/mysql_login"],
    "postgres":     ["auxiliary/scanner/postgres/postgres_version", "auxiliary/scanner/postgres/postgres_login"],
    "ms-sql":       ["auxiliary/scanner/mssql/mssql_ping", "auxiliary/scanner/mssql/mssql_schemadump"],
    "mssql":        ["auxiliary/scanner/mssql/mssql_ping", "auxiliary/scanner/mssql/mssql_schemadump"],
    "microsoft-ds": ["auxiliary/scanner/smb/smb_version", "auxiliary/scanner/smb/smb_enumshares", "auxiliary/scanner/smb/smb_ms17_010"],
    "smb":          ["auxiliary/scanner/smb/smb_version", "auxiliary/scanner/smb/smb_enumshares"],
    "netbios":      ["auxiliary/scanner/smb/smb_version"],
    "rdp":          ["auxiliary/scanner/rdp/rdp_scanner"],
    "ms-wbt-server":["auxiliary/scanner/rdp/rdp_scanner"],
    "vnc":          ["auxiliary/scanner/vnc/vnc_none_auth", "auxiliary/scanner/vnc/vnc_login"],
    "redis":        ["auxiliary/scanner/redis/redis_server"],
    "mongodb":      ["auxiliary/scanner/mongodb/mongodb_login"],
    "snmp":         ["auxiliary/scanner/snmp/snmp_login"],
    "dns":          ["auxiliary/gather/dns_info"],
    "domain":       ["auxiliary/gather/dns_info"],
    "oracle":       ["auxiliary/scanner/oracle/oracle_login"],
}

# Same idea but for exploit checks on non-standard ports
_MSF_EXPLOIT_CHECKS_BY_SERVICE: dict[str, list[str]] = {
    "microsoft-ds": ["exploit/windows/smb/ms17_010_eternalblue", "exploit/windows/smb/ms17_010_psexec", "exploit/windows/smb/psexec"],
    "smb":          ["exploit/windows/smb/ms17_010_eternalblue", "exploit/windows/smb/ms17_010_psexec"],
    "rdp":          ["exploit/windows/rdp/cve_2019_0708_bluekeep_rce"],
    "ms-wbt-server":["exploit/windows/rdp/cve_2019_0708_bluekeep_rce"],
    "ftp":          ["exploit/unix/ftp/vsftpd_234_backdoor"],
    "http":         ["exploit/multi/http/struts2_content_type_ognl", "exploit/multi/http/tomcat_mgr_upload"],
    "https":        ["exploit/multi/http/log4shell_header_injection"],
    "netbios":      ["exploit/windows/smb/ms08_067_netapi"],
}

_MSF_AUX_AGGRESSIVE_EXTRA: list[str] = [
    "auxiliary/scanner/smb/smb_login",
    "auxiliary/scanner/ssh/ssh_login",
    "auxiliary/scanner/http/http_login",
    "auxiliary/scanner/mssql/mssql_login",
    "auxiliary/scanner/snmp/snmp_login",
]

_MSF_EXPLOIT_CHECKS_BY_PORT: dict[int, list[str]] = {
    445: ["exploit/windows/smb/ms17_010_eternalblue", "exploit/windows/smb/ms17_010_psexec", "exploit/windows/smb/psexec"],
    139: ["exploit/windows/smb/ms08_067_netapi"],
    3389: ["exploit/windows/rdp/cve_2019_0708_bluekeep_rce"],
    21: ["exploit/unix/ftp/vsftpd_234_backdoor"],
    80: ["exploit/multi/http/struts2_content_type_ognl", "exploit/multi/http/tomcat_mgr_upload"],
    8080: ["exploit/multi/http/tomcat_mgr_upload", "exploit/multi/http/jenkins_script_console"],
    443: ["exploit/multi/http/log4shell_header_injection"],
}

_MSF_POST_CHAIN_BALANCED = [
    "post/multi/gather/env",
    "post/multi/recon/local_exploit_suggester",
]

_MSF_POST_CHAIN_AGGRESSIVE = _MSF_POST_CHAIN_BALANCED + [
    "post/windows/gather/enum_logged_on_users",
    "post/linux/gather/enum_system",
]


def _plan_metasploit_full_chain(
    open_ports: list[int],
    mode: str,
    include_exploit_checks: bool,
    services: dict[int, str] | None = None,  # port → service name from nmap -sV
) -> dict:
    services = services or {}
    aux_modules: list[str] = []
    exploit_checks: list[dict] = []

    for port in open_ports:
        svc = services.get(port, "").lower()

        # 1. Try exact port-number match first (covers standard well-known ports)
        port_mods = _MSF_AUX_BY_PORT_BALANCED.get(port, [])
        if port_mods:
            aux_modules.extend(port_mods)
        elif svc:
            # 2. Fall back to service-name match for non-standard ports
            #    e.g. MySQL on 3307, SSH on 2222, HTTP on 9000
            for svc_key, mods in _MSF_AUX_BY_SERVICE.items():
                if svc_key in svc:
                    aux_modules.extend(mods)
                    break

        if include_exploit_checks:
            # Check port-based exploits first
            port_exploits = _MSF_EXPLOIT_CHECKS_BY_PORT.get(port, [])
            for mod in port_exploits:
                exploit_checks.append({"module": mod, "port": port})
            # If no port match, try service-name based exploits
            if not port_exploits and svc:
                for svc_key, mods in _MSF_EXPLOIT_CHECKS_BY_SERVICE.items():
                    if svc_key in svc:
                        for mod in mods:
                            exploit_checks.append({"module": mod, "port": port})
                        break

    # Ensure some baseline discovery if no mapped service modules were selected.
    if not aux_modules and open_ports:
        aux_modules = ["auxiliary/scanner/portscan/syn"]

    if mode == "aggressive":
        aux_modules.extend(_MSF_AUX_AGGRESSIVE_EXTRA)

    seen_aux: set[str] = set()
    uniq_aux = [m for m in aux_modules if not (m in seen_aux or seen_aux.add(m))]

    seen_exp: set[str] = set()
    uniq_exp: list[dict] = []
    for e in exploit_checks:
        m = str(e.get("module", ""))
        if m and m not in seen_exp:
            seen_exp.add(m)
            uniq_exp.append(e)

    post_modules = _MSF_POST_CHAIN_AGGRESSIVE if mode == "aggressive" else _MSF_POST_CHAIN_BALANCED

    return {
        "auxiliary_modules": uniq_aux,
        "exploit_checks": uniq_exp,
        "post_modules": post_modules,
    }


# ── Tool names that may appear in condition expressions ─────────────────
_CONDITION_TOOLS = frozenset({
    "nmap", "nuclei", "ffuf", "sqlmap", "sqlmap_full", "nikto", "wpscan", "gobuster",
    "masscan", "cisa_kev", "epss", "cve", "poc_index", "poc",
    "ssl", "waf", "whatweb", "osint", "metasploit", "jwt", "llm",
    "mitre",
    "any", "all",
})


def _evaluate_condition(expression: str, nmap_ctx: dict, node_outputs: dict) -> bool:
    """Evaluate a workflow condition expression.

    Format: ``tool:check`` or ``tool:check:param``

    Examples::

        nmap:host_up          nuclei:has_critical    ffuf:has_results
        nmap:port_open:443    epss:score_above:0.5   any:success
        true / false          (boolean constants)
    """
    expr = (expression or "").strip()
    if not expr:
        return False

    parts = expr.split(":")
    tool = parts[0].lower()
    check = parts[1].lower() if len(parts) > 1 else "success"
    param = parts[2] if len(parts) > 2 else None

    # ── Boolean constants ────────────────────────────────────────────────────
    if tool in ("true", "yes", "1") and len(parts) == 1:
        return True
    if tool in ("false", "no", "0") and len(parts) == 1:
        return False

    # ── Legacy flat keywords (backward compat) ───────────────────────────────
    if tool not in _CONDITION_TOOLS:
        expr_lower = expr.lower()
        if expr_lower in ("true", "yes", "1"):
            return True
        if expr_lower in ("false", "no", "0"):
            return False
        open_ports = nmap_ctx.get("open_ports", [])
        if expr_lower == "host_up":
            return nmap_ctx.get("host_up", False)
        if expr_lower in ("has_open_ports", "any_port_open"):
            return len(open_ports) > 0
        if expr_lower == "has_http":
            return nmap_ctx.get("has_http", False)
        if expr_lower == "has_ssl":
            return any(p in open_ports for p in (443, 8443))
        if expr_lower == "has_ssh":
            return 22 in open_ports
        if expr_lower == "has_ftp":
            return 21 in open_ports
        if expr_lower == "has_smb":
            return 445 in open_ports or 139 in open_ports
        if expr_lower == "has_mysql":
            return 3306 in open_ports
        if expr_lower == "has_postgres":
            return 5432 in open_ports
        if expr_lower == "has_redis":
            return 6379 in open_ports
        # port:N or port_open:N
        if expr_lower.startswith(("port:", "port_open:")):
            try:
                return int(expr_lower.split(":")[1]) in open_ports
            except (ValueError, IndexError):
                return False
        # open_ports > N
        if expr_lower.startswith("open_ports"):
            try:
                n = int(expr_lower.split(">")[1].strip())
                return len(open_ports) > n
            except Exception:
                return False
        if expr_lower in ("has_vulns", "has_findings", "has_vulnerabilities"):
            for out in node_outputs.values():
                try:
                    p = json.loads(out.get("output", ""))
                    for key in ("findings", "results", "vulnerabilities"):
                        lst = p.get(key) or []
                        if isinstance(lst, list) and len(lst) > 0:
                            return True
                except Exception:
                    pass
            return False
        if expr_lower in ("has_critical", "has_high", "has_medium"):
            sev_map = {"has_critical": ("critical",), "has_high": ("critical", "high"),
                       "has_medium": ("critical", "high", "medium")}
            sevs = sev_map.get(expr_lower, ())
            for out in node_outputs.values():
                try:
                    p = json.loads(out.get("output", ""))
                    for key in ("findings", "results", "vulnerabilities"):
                        lst = p.get(key) or []
                        if any(str(f.get("severity", "")).lower() in sevs for f in lst):
                            return True
                except Exception:
                    pass
            return False
        if expr_lower in ("all_success", "all.success"):
            return len(node_outputs) > 0 and all(v.get("success", False) for v in node_outputs.values())
        if expr_lower in ("any_failed", "any.failed"):
            return any(not v.get("success", True) for v in node_outputs.values())
        return False

    # ── Global: any / all ────────────────────────────────────────────────────
    if tool == "any":
        if check == "success":
            return any(v.get("success", False) for v in node_outputs.values())
        if check in ("failed", "fail"):
            return any(not v.get("success", True) for v in node_outputs.values())
        return False

    if tool == "all":
        if check == "success":
            return len(node_outputs) > 0 and all(v.get("success", False) for v in node_outputs.values())
        return False

    # ── Nmap: use structured nmap_ctx ────────────────────────────────────────
    if tool == "nmap":
        open_ports = nmap_ctx.get("open_ports", [])
        if check == "host_up":
            return nmap_ctx.get("host_up", False)
        if check in ("has_open_ports", "any_port_open"):
            return len(open_ports) > 0
        if check == "has_http":
            return nmap_ctx.get("has_http", False)
        if check == "has_ssl":
            return any(p in open_ports for p in (443, 8443))
        if check == "has_ssh":
            return 22 in open_ports
        if check == "has_ftp":
            return 21 in open_ports
        if check == "has_smb":
            return 445 in open_ports or 139 in open_ports
        if check == "has_mysql":
            return 3306 in open_ports
        if check == "has_postgres":
            return 5432 in open_ports
        if check == "has_redis":
            return 6379 in open_ports
        if check == "port_open":
            try:
                return int(param) in open_ports  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return False
        if check == "ports_open":
            try:
                requested = [int(p.strip()) for p in (param or "").split(",") if p.strip()]
                return bool(requested) and all(p in open_ports for p in requested)
            except (TypeError, ValueError):
                return False
        if check == "any_ports_open":
            try:
                requested = [int(p.strip()) for p in (param or "").split(",") if p.strip()]
                return any(p in open_ports for p in requested)
            except (TypeError, ValueError):
                return False
        if check == "ports_gt":
            try:
                return len(open_ports) > int(param)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return False
        if check == "success":
            return any(
                v.get("_tool") == "nmap" and v.get("success", False)
                for v in node_outputs.values()
            )
        return False

    # ── Find the most recent output for this tool in node_outputs ────────────
    # node_outputs is an ordered dict (insertion order = execution order)
    tool_out: dict | None = None
    for out in reversed(list(node_outputs.values())):
        if out.get("_tool") == tool or (tool == "poc" and out.get("_tool") == "poc_index"):
            tool_out = out
            break

    # Success/failure checks work without needing parsed JSON
    if check == "success":
        return tool_out.get("success", False) if tool_out else False
    if check in ("failed", "fail"):
        return not tool_out.get("success", True) if tool_out else True

    if tool_out is None:
        return False

    # Parse JSON output
    try:
        parsed = json.loads(tool_out.get("output", ""))
        if not isinstance(parsed, dict):
            parsed = None
    except Exception:
        parsed = None

    if parsed is None:
        return False

    # ── Nuclei ───────────────────────────────────────────────────────────────
    if tool == "nuclei":
        findings = (
            parsed.get("findings") or parsed.get("results")
            or parsed.get("vulnerabilities") or []
        )
        if check == "has_findings":
            return len(findings) > 0
        if check == "has_critical":
            return any(str(f.get("severity", "")).lower() == "critical" for f in findings)
        if check == "has_high":
            return any(str(f.get("severity", "")).lower() in ("critical", "high") for f in findings)
        if check == "has_medium":
            return any(str(f.get("severity", "")).lower() in ("critical", "high", "medium") for f in findings)
        if check == "has_low":
            return len(findings) > 0
        if check == "findings_gt":
            try:
                return len(findings) > int(param)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return False

    # ── FFUF ─────────────────────────────────────────────────────────────────
    elif tool == "ffuf":
        results = parsed.get("results") or parsed.get("findings") or []
        if check == "has_results":
            return len(results) > 0
        if check == "results_gt":
            try:
                return len(results) > int(param)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return False

    # ── SQLMap / SQLMap Full Chain ────────────────────────────────────────────
    elif tool in ("sqlmap", "sqlmap_full"):
        if check in ("is_vulnerable", "has_findings", "vulnerable"):
            vulns = (
                parsed.get("injections") or parsed.get("results")
                or parsed.get("vulnerabilities") or []
            )
            injectable = (
                parsed.get("injectable") or parsed.get("vulnerable")
                or parsed.get("is_vulnerable")
            )
            return bool(injectable) or len(vulns) > 0
        if check == "is_dba":
            return bool(parsed.get("is_dba"))
        if check == "has_databases":
            return len(parsed.get("databases", [])) > 0
        if check == "has_users":
            return len(parsed.get("users", [])) > 0

    # ── Nikto ────────────────────────────────────────────────────────────────
    elif tool == "nikto":
        if check == "has_findings":
            findings = (
                parsed.get("findings") or parsed.get("results")
                or parsed.get("vulnerabilities") or []
            )
            return len(findings) > 0

    # ── WPScan ───────────────────────────────────────────────────────────────
    elif tool == "wpscan":
        if check in ("has_findings", "has_vulns"):
            vulns = (
                parsed.get("vulnerabilities") or parsed.get("findings")
                or parsed.get("plugins_with_vulns") or []
            )
            return len(vulns) > 0

    # ── Gobuster ─────────────────────────────────────────────────────────────
    elif tool == "gobuster":
        if check == "has_results":
            results = parsed.get("results") or parsed.get("findings") or []
            return len(results) > 0

    # ── Masscan ──────────────────────────────────────────────────────────────
    elif tool == "masscan":
        if check == "has_open_ports":
            ports = parsed.get("open_ports") or parsed.get("ports") or []
            return len(ports) > 0
        if check == "host_up":
            ports = parsed.get("open_ports") or parsed.get("ports") or []
            return bool(parsed.get("host_up") or len(ports) > 0)

    # ── CISA KEV ─────────────────────────────────────────────────────────────
    elif tool == "cisa_kev":
        if check == "in_kev":
            return bool(parsed.get("in_kev"))
        if check == "has_entries":
            entries = parsed.get("results") or parsed.get("cves") or []
            return len(entries) > 0

    # ── EPSS ─────────────────────────────────────────────────────────────────
    elif tool == "epss":
        score = 0.0
        try:
            score = float(parsed.get("epss_score") or parsed.get("score") or 0)
        except (TypeError, ValueError):
            pass
        if check == "high_risk":
            return score > 0.5
        if check == "score_above":
            try:
                return score > float(param)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return score > 0.5

    # ── CVE ──────────────────────────────────────────────────────────────────
    elif tool == "cve":
        results = parsed.get("results") or parsed.get("cves") or []
        total = parsed.get("total")
        count = int(total) if total is not None else len(results)
        if check == "has_results":
            return count > 0
        if check == "has_critical":
            return any(str(r.get("severity", "")).lower() == "critical" for r in results)
        if check == "has_high":
            return any(str(r.get("severity", "")).lower() in ("critical", "high") for r in results)

    # ── PoC Index ────────────────────────────────────────────────────────────
    elif tool in ("poc_index", "poc"):
        if check == "has_findings":
            exploits = (
                parsed.get("exploits") or parsed.get("github_poc_repos") or []
            )
            count = int(
                parsed.get("count") or parsed.get("total_found") or len(exploits)
            )
            return count > 0

    # ── SSL/TLS ──────────────────────────────────────────────────────────────
    elif tool == "ssl":
        if check == "has_vulns":
            issues = (
                parsed.get("issues") or parsed.get("vulnerabilities")
                or parsed.get("warnings") or []
            )
            return len(issues) > 0
        if check == "expired":
            return bool(parsed.get("expired") or parsed.get("is_expired"))

    # ── WAF Detection ────────────────────────────────────────────────────────
    elif tool in ("waf", "whatweb"):
        if check == "detected":
            waf_name = (
                parsed.get("waf") or parsed.get("waf_detected")
                or parsed.get("firewall") or ""
            )
            return bool(waf_name) and str(waf_name).lower() not in (
                "none", "false", "no waf", ""
            )

    # ── Metasploit ───────────────────────────────────────────────────────────
    elif tool == "metasploit":
        if check == "exploited":
            return bool(
                parsed.get("session_id") or parsed.get("session") or parsed.get("exploited")
            )
        if check == "has_session":
            return bool(parsed.get("session_id") or parsed.get("session"))

    # ── JWT ──────────────────────────────────────────────────────────────────
    elif tool == "jwt":
        if check == "has_vulns":
            vulns = parsed.get("vulnerabilities") or parsed.get("issues") or []
            return len(vulns) > 0

    # ── CVE Lite ─────────────────────────────────────────────────────────────
    elif tool == "cve_lite":
        findings = parsed.get("findings") or []
        finding_count = int(parsed.get("finding_count") or len(findings))
        if check == "has_findings":
            return finding_count > 0
        if check == "has_high":
            return any(
                str(f.get("severity", "")).lower() in ("critical", "high")
                for f in findings
            )
        if check == "has_critical":
            return any(
                str(f.get("severity", "")).lower() == "critical"
                for f in findings
            )
        if check == "threshold_reached":
            return bool(parsed.get("threshold_reached"))
        if check == "findings_gt":
            try:
                return finding_count > int(param)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return False

    return False


_RISK_RANK: dict[str, int] = {
    "UNKNOWN": 0,
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}

_CVE_ID_RE = _re_nmap.compile(r"\bCVE-\d{4}-\d{4,7}\b", _re_nmap.IGNORECASE)


def _extract_cve_ids(raw: str | None) -> list[str]:
    """Extract unique CVE IDs from free text, preserving first-seen order."""
    if not raw:
        return []
    found = _CVE_ID_RE.findall(raw)
    deduped: list[str] = []
    seen: set[str] = set()
    for cve_id in found:
        normalized = cve_id.upper()
        if normalized not in seen:
            seen.add(normalized)
            deduped.append(normalized)
    return deduped


def _looks_like_only_cve_list(raw: str | None) -> bool:
    """Return True when input is composed of CVE IDs and simple separators only."""
    if not raw:
        return False
    cve_ids = _extract_cve_ids(raw)
    if not cve_ids:
        return False
    stripped = _CVE_ID_RE.sub("", raw)
    # Allow separators/spaces only after removing CVE IDs.
    return _re_nmap.sub(r"[\s,;|]+", "", stripped) == ""


def _cvss_to_severity(score: float) -> str:
    """Convert a CVSS base score to its NVD severity label."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


# Matches: "cvss_score": 6.5  or  cvss_score=6.5
_CVSS_SCORE_RE = _re_nmap.compile(r'"cvss_score"\s*:\s*([0-9]+(?:\.[0-9]+)?)', _re_nmap.IGNORECASE)
# Matches: "severity": "MEDIUM"  (from CVE tool JSON output)
_CVSS_SEV_RE = _re_nmap.compile(r'"severity"\s*:\s*"(CRITICAL|HIGH|MEDIUM|LOW|NONE)"', _re_nmap.IGNORECASE)


def _extract_cvss_max_from_text(text: str) -> str | None:
    """
    Parse CVSS scores / severity labels from CVE tool JSON embedded in tool_output_text.
    Returns the highest authoritative CVSS-derived severity found, or None when no CVE
    data is present.  CVSS scores take precedence over severity strings.
    """
    max_rank = 0
    max_sev: str | None = None

    # Prefer deriving severity from numeric score (most precise)
    for m in _CVSS_SCORE_RE.finditer(text):
        try:
            sev = _cvss_to_severity(float(m.group(1)))
            rank = _RISK_RANK.get(sev, 0)
            if rank > max_rank:
                max_rank = rank
                max_sev = sev
        except (ValueError, TypeError):
            pass

    # Fall back / supplement with explicit severity strings from CVE JSON
    for m in _CVSS_SEV_RE.finditer(text):
        sev = m.group(1).upper()
        rank = _RISK_RANK.get(sev, 0)
        if rank > max_rank:
            max_rank = rank
            max_sev = sev

    return max_sev


def _reconcile_risk_level(
    llm_risk_level: str,
    parsed_vulns: list[dict],
    cvss_max: str | None = None,
) -> str:
    """
    Determine the final risk level:
    1. Start with the LLM's overall RISK_LEVEL.
    2. Escalate if any parsed vulnerability has a higher severity.
    3. When authoritative CVSS data is available (cvss_max), cap the result so the AI
       cannot inflate risk beyond what NVD/CVSS actually scores the CVEs.
    """
    final = (llm_risk_level or "UNKNOWN").upper()
    max_vuln_risk = "UNKNOWN"

    for v in parsed_vulns or []:
        sev = str(v.get("severity", "UNKNOWN")).upper()
        if sev in _RISK_RANK and _RISK_RANK[sev] > _RISK_RANK.get(max_vuln_risk, 0):
            max_vuln_risk = sev

    if _RISK_RANK.get(max_vuln_risk, 0) > _RISK_RANK.get(final, 0):
        final = max_vuln_risk

    # Cap to authoritative CVSS ceiling when available
    if cvss_max and _RISK_RANK.get(final, 0) > _RISK_RANK.get(cvss_max.upper(), 0):
        final = cvss_max.upper()

    return final


# ─── Expected durations (seconds) for progress estimation ────────────────────

def _all_tools_failed(tool_rows) -> tuple[bool, list[str]]:
    """tool_rows: ScanToolResult rows, or (name, result_data) pairs from a still-in-memory dict. True + reasons when every tool that
    was not itself skipped failed (an empty run is not 'all failed': nothing ran to fail)."""
    entries = []
    for row in tool_rows:
        if isinstance(row, tuple):
            name, data = row
            raw, parsed, code = data.get("output", ""), data, data.get("exit_code")
        else:
            name, raw, parsed, code = row.tool_name, row.raw_output, row.parsed_output, row.exit_code
        entries.append({"tool_name": name, "failed": tool_failed(raw, parsed, code),
                        "skipped": isinstance(parsed, dict) and parsed.get("skipped") is True,
                        "failure_reason": raw if isinstance(raw, str) else ""})
    outcome = _summarize_tool_outcomes(entries)
    return outcome["all_failed"], [f"{e['tool_name']}: {e['failure_reason'][:160]}" for e in entries if e["failed"] and not e["skipped"]]


TOOL_EXPECTED_DURATIONS: dict[str, int] = {
    "nmap": 120, "nuclei": 90, "sqlmap": 300, "sqlmap_full": 600, "ffuf": 30,
    "waf": 15, "cve": 10, "metasploit": 60, "ssl": 20,
    "cisa_kev": 10, "epss": 10, "poc_index": 15, "osint": 15,
    "cve_lite": 60,
}


def _build_dynamic_steps(nmap_ctx: dict, nmap_service_versions: list) -> list:
    """Build workflow steps dynamically based on nmap-discovered open ports and services."""
    open_ports: list = nmap_ctx.get("open_ports", [])
    http_ports: list = nmap_ctx.get("http_ports", [])
    steps: list = []
    step_id = 2  # step 1 is always nmap

    # CVE lookup step (always if services detected)
    if nmap_service_versions:
        steps.append({"step_id": step_id, "name": "CVE Analysis", "tools": ["cve"], "port_filter": None})
        step_id += 1

    # Web steps when HTTP/HTTPS ports are found
    if http_ports:
        vuln_tools = ["waf", "nuclei"]
        if any(p in open_ports for p in [443, 8443]):
            vuln_tools.append("ssl")
        steps.append({"step_id": step_id, "name": "Web Vulnerability Scan", "tools": vuln_tools, "port_filter": None})
        step_id += 1
        steps.append({"step_id": step_id, "name": "Web Exploitation", "tools": ["ffuf", "sqlmap"], "port_filter": None})
        step_id += 1

    # Service-specific Metasploit auxiliary steps
    msf_steps = []
    if 21 in open_ports:
        msf_steps.append(("FTP Enumeration", "auxiliary/scanner/ftp/anonymous"))
    if 22 in open_ports:
        msf_steps.append(("SSH Enumeration", "auxiliary/scanner/ssh/ssh_version"))
    if 445 in open_ports or 139 in open_ports:
        msf_steps.append(("SMB Enumeration", "auxiliary/scanner/smb/smb_version"))
    if 3306 in open_ports:
        msf_steps.append(("MySQL Enumeration", "auxiliary/scanner/mysql/mysql_version"))
    if 5432 in open_ports:
        msf_steps.append(("PostgreSQL Enumeration", "auxiliary/scanner/postgres/postgres_version"))
    if 6379 in open_ports:
        msf_steps.append(("Redis Enumeration", "auxiliary/scanner/redis/redis_server"))
    if 25 in open_ports or 465 in open_ports or 587 in open_ports:
        msf_steps.append(("SMTP Enumeration", "auxiliary/scanner/smtp/smtp_version"))

    for step_name, msf_module in msf_steps:
        steps.append({
            "step_id": step_id, "name": step_name,
            "tools": ["metasploit"], "port_filter": None,
            "msf_module_override": msf_module,
        })
        step_id += 1

    # Fallback if nothing useful discovered
    if not steps:
        steps.append({"step_id": step_id, "name": "Vulnerability Detection", "tools": ["nuclei", "cve"], "port_filter": None})

    return steps


async def _execute_workflow(
    scan_id: str,
    target: str,
    steps: list,
    run_tool_fn,  # async callable(tool_name) -> (name, result_data, duration_ms)
    nmap_ctx_out: dict | None = None,  # mutable dict updated with nmap findings so callers can react
    dynamic: bool = False,  # if True, build remaining steps from nmap findings after step 1
    tool_config: dict | None = None,  # mutable config dict; updated with nmap service versions
) -> list:
    """
    Execute tools as a sequential workflow chain.
    Each step runs after the previous one completes. nmap output is parsed
    to auto-filter subsequent steps by open port and to derive the correct
    HTTP target URL (e.g. http://target:8080 instead of just http://target).
    RuntimeError is only raised if the nmap discovery step itself fails.
    """
    all_gathered: list = []
    # default context: assume HTTP available until we have real nmap data
    nmap_ctx: dict = {"open_ports": [], "services": {}, "has_http": True, "http_ports": []}
    if nmap_ctx_out is not None:
        nmap_ctx_out.update(nmap_ctx)

    for step in steps:
        step_id = step.get("step_id", "?")
        step_name = step.get("name", f"Step {step_id}")
        step_tools: list[str] = step.get("tools", [])
        port_filter: list[int] | None = step.get("port_filter")

        # Skip step if required ports aren't open (only after nmap has run)
        if port_filter and nmap_ctx["open_ports"]:
            if not any(p in nmap_ctx["open_ports"] for p in port_filter):
                logger.info(
                    "Workflow %s/%s skipped — ports %s not in open ports %s",
                    step_id, step_name, port_filter, nmap_ctx["open_ports"],
                )
                await _notify_ws(scan_id, "workflow_step", {
                    "step_id": step_id, "step_name": step_name,
                    "status": "skipped", "tools": step_tools,
                    "reason": f"Required ports {port_filter} not open",
                })
                continue

        await _notify_ws(scan_id, "workflow_step", {
            "step_id": step_id, "step_name": step_name,
            "status": "running", "tools": step_tools,
        })
        logger.info("Workflow step %s '%s' starting: %s", step_id, step_name, step_tools)

        step_gathered = await asyncio.gather(
            *[run_tool_fn(t) for t in step_tools], return_exceptions=True,
        )

        # Separate exceptions from normal results
        clean_gathered = []
        exc_tools = []
        for item in step_gathered:
            if isinstance(item, Exception):
                exc_tools.append(str(item))
            else:
                clean_gathered.append(item)
        step_gathered = clean_gathered

        # Categorise tool failures: nmap is fatal (subsequent steps need its data).
        # All other tool failures are warnings — log and continue.
        failed = [n for n, d, _ in step_gathered if not d.get("success", True)]
        nmap_failed = "nmap" in failed or any("nmap" in s for s in exc_tools)

        if failed or exc_tools:
            logger.warning(
                "Workflow step %s '%s' — %d tool(s) failed: %s%s",
                step_id, step_name, len(failed) + len(exc_tools),
                failed, (" exceptions: " + str(exc_tools)) if exc_tools else "",
            )

        if nmap_failed and step_id == 1:
            # nmap in the discovery step is mandatory — cannot continue without port data
            await _notify_ws(scan_id, "workflow_step", {
                "step_id": step_id, "step_name": step_name,
                "status": "failed", "tools": step_tools, "failed_tools": failed + exc_tools,
            })
            raise RuntimeError(
                f"Workflow step '{step_name}' failed: nmap (port discovery) returned errors — cannot continue"
            )

        if failed or exc_tools:
            # Non-fatal: emit partial failure but continue to next step
            await _notify_ws(scan_id, "workflow_step", {
                "step_id": step_id, "step_name": step_name,
                "status": "completed", "tools": step_tools,
                "failed_tools": failed + exc_tools,
                "warning": f"Some tools had errors: {failed + exc_tools}",
            })

        all_gathered.extend(step_gathered)

        # Update nmap context after any step that ran nmap
        for t_name, t_data, _ in step_gathered:
            if t_name == "nmap":
                nmap_ctx = _extract_nmap_context(t_data.get("output", ""))
                if nmap_ctx_out is not None:
                    nmap_ctx_out.update(nmap_ctx)  # propagate to caller (run_scan uses this)
                logger.info(
                    "Nmap context: %d open ports, has_http=%s, http_ports=%s",
                    len(nmap_ctx["open_ports"]), nmap_ctx["has_http"], nmap_ctx["http_ports"],
                )
                # Inject service version strings into tool_config so cve/poc_index/cisa_kev
                # can use them as keywords instead of falling back to the raw target domain.
                if tool_config is not None and "_cve_keywords" not in tool_config:
                    try:
                        nmap_parsed = json.loads(t_data.get("output", "{}"))
                        svc_strs = [
                            p["version"].strip()
                            for p in nmap_parsed.get("open_ports", [])
                            if p.get("version") and p["version"].strip()
                        ]
                        if svc_strs:
                            tool_config["_cve_keywords"] = " | ".join(svc_strs[:4])
                            logger.info("Injected _cve_keywords: %s", tool_config["_cve_keywords"])
                    except (json.JSONDecodeError, KeyError, TypeError) as e:
                        logger.debug(f"Could not inject CVE keywords: {e}")

                # Dynamic workflow: inject remaining steps based on nmap findings
                if dynamic and step_id == 1:
                    svc_versions: list = nmap_ctx_out.get("nmap_service_versions", []) if nmap_ctx_out else []
                    dynamic_steps = _build_dynamic_steps(nmap_ctx, svc_versions)
                    # Extend the steps list in-place so the for-loop iterates the new steps
                    steps.extend(dynamic_steps)
                    logger.info(
                        "Intelligent workflow: %d dynamic steps added: %s",
                        len(dynamic_steps), [s["name"] for s in dynamic_steps],
                    )
                    # Notify frontend so it can pre-render pending steps
                    await _notify_ws(scan_id, "workflow_plan", {
                        "steps": [
                            {"step_id": s["step_id"], "step_name": s["name"], "tools": s["tools"]}
                            for s in dynamic_steps
                        ],
                    })

        # Only send "completed" event here if we didn't already send it (partial failure path above)
        if not (failed or exc_tools):
            await _notify_ws(scan_id, "workflow_step", {
                "step_id": step_id, "step_name": step_name,
                "status": "completed", "tools": step_tools,
            })
        logger.info("Workflow step %s '%s' completed", step_id, step_name)

    return all_gathered


# ─── Graph-Based Workflow Executor (n8n-style) ────────────────

def _topo_sort(nodes: list[dict], edges: list[dict]) -> list[str]:
    """
    Kahn's algorithm topological sort.
    Returns list of node IDs in execution order.
    Skips 'start' nodes as a dummy entry point.
    """
    from collections import deque
    in_deg: dict[str, int] = {n["id"]: 0 for n in nodes}
    adj: dict[str, list[str]] = {n["id"]: [] for n in nodes}
    for e in edges:
        src, tgt = e["source"], e["target"]
        adj.setdefault(src, []).append((tgt, e.get("sourceHandle")))
        in_deg[tgt] = in_deg.get(tgt, 0) + 1

    queue = deque([nid for nid, deg in in_deg.items() if deg == 0])
    order: list[str] = []
    while queue:
        nid = queue.popleft()
        order.append(nid)
        for (child, _handle) in adj.get(nid, []):
            in_deg[child] -= 1
            if in_deg[child] == 0:
                queue.append(child)
    return order


def _resolve_prompt(prompt: str, node_outputs: dict[str, dict]) -> str:
    """Replace {{node_id.output}} placeholders in LLM prompt templates.

    If the prompt contains no {{…}} placeholders, all upstream node outputs
    are automatically injected as a structured context block so the LLM
    always has real data to work with.
    """
    import re

    def _repl(m: re.Match) -> str:
        node_id = m.group(1)
        field   = m.group(2)
        data = node_outputs.get(node_id, {})
        return str(data.get(field, data.get("output", "")))

    resolved = re.sub(r'\{\{(\w[\w\-]*)\.([\w]+)\}\}', _repl, prompt)

    # If the prompt had no placeholders, auto-inject upstream outputs as context
    if resolved == prompt:
        context_parts: list[str] = []
        for nid, out in node_outputs.items():
            if nid == "target":
                continue
            raw_output = out.get("output", "")
            if raw_output and str(raw_output).strip():
                context_parts.append(f"[{nid}]\n{str(raw_output)[:3000]}")
        if context_parts:
            context_block = "\n\n".join(context_parts)
            resolved = (
                f"You are a professional penetration testing assistant.\n"
                f"IMPORTANT RULES — follow these strictly:\n"
                f"1. Only report findings, vulnerabilities, or issues that are EXPLICITLY present in the tool output below.\n"
                f"2. Do NOT infer, guess, extrapolate, or hallucinate vulnerabilities that are not directly shown in the data.\n"
                f"3. If a tool did not detect something, do not mention it as a finding.\n"
                f"4. If the data shows only informational results (e.g. WHOIS, DNS, headers), summarize those facts — do not add vulnerability assessments unless the tool explicitly flagged them.\n"
                f"5. Use wording like 'not detected', 'not tested', or 'not present in results' rather than inventing negative findings.\n\n"
                f"The following are the raw findings collected from the security workflow tools:\n\n"
                f"{context_block}\n\n"
                f"---\n"
                f"User instruction: {prompt}"
            )

    return resolved


async def _execute_workflow_graph(
    scan_id: str,
    target: str,
    nodes: list[dict],
    edges: list[dict],
    default_llm: dict | None,
    http_target: str,
    db=None,
    scan_obj=None,
) -> list[tuple[str, dict, int]]:
    """
    Execute a visual (n8n-style) node graph workflow.
    Follows topological order derived from edges.
    Sends node_start / node_complete / node_failed WS events per node.
    Returns list of (node_id, result_data, duration_ms).
    """
    import time
    from app.services.llm_service import llm_service
    from app.models.llm_config import LLMProvider

    node_map = {n["id"]: n for n in nodes}
    edge_map: dict[str, list[dict]] = {}   # source -> list of edges
    for e in edges:
        edge_map.setdefault(e["source"], []).append(e)

    order = _topo_sort(nodes, edges)
    node_outputs: dict[str, dict] = {}   # node_id -> {output, success, duration_ms}
    results: list[tuple[str, dict, int]] = []

    # Track nmap findings so later web-attack nodes target the right port
    nmap_ctx: dict = {"open_ports": [], "services": {}, "has_http": True, "http_ports": []}

    # CVE IDs found by any CVE-producing node (CVE Lookup's keyword search, CVE Lite's dependency scan) so a later
    # KEV / EPSS / PoC / CVE node can use them automatically — without this, a workflow like keyword -> CVE Lookup ->
    # CISA KEV only worked if the user re-typed the CVE, exactly the Start-node inheritance gap, but node-to-node.
    cve_ctx: list[str] = []

    # Skipped nodes (due to condition branching or missing ports)
    skipped: set[str] = set()

    for node_id in order:
        node = node_map.get(node_id)
        if node is None:
            continue
        if node_id in skipped:
            continue

        node_type = node.get("type", "tool")
        data: dict = node.get("data") or {}

        # ── Start node: just record target override ────────────
        if node_type == "start":
            t = data.get("target") or target
            node_outputs[node_id] = {"output": t, "success": True, "duration_ms": 0}
            await _notify_ws(scan_id, "node_complete", {
                "node_id": node_id, "node_type": "start",
                "output": t, "duration_ms": 0, "success": True,
            })
            continue

        await _notify_ws(scan_id, "node_start", {
            "node_id": node_id, "node_type": node_type,
            "tool": data.get("tool"), "label": data.get("label"),
        })
        t0 = int(time.time() * 1000)

        try:
            # ── Tool node ──────────────────────────────────────
            if node_type == "tool":
                tool_name = data.get("tool", "")
                # A manifest-driven "MCP Tool" node stores tool='mcp_tool' plus mcp_server/mcp_action; turn it into the
                # "mcp:<server>:<action>" id the generic dispatcher in _run_single_tool understands.
                if tool_name == "mcp_tool" and data.get("mcp_server") and data.get("mcp_action"):
                    tool_name = f"mcp:{data['mcp_server']}:{data['mcp_action']}"
                tool_timeout = data.get("timeout")
                tool_flags = data.get("flags")
                port_filter: list[int] | None = data.get("port_filter")

                # Skip if port_filter not satisfied
                if port_filter and nmap_ctx["open_ports"]:
                    if not any(p in nmap_ctx["open_ports"] for p in port_filter):
                        skipped.add(node_id)
                        await _notify_ws(scan_id, "node_complete", {
                            "node_id": node_id, "node_type": "tool", "tool": tool_name,
                            "output": f"Skipped — ports {port_filter} not open",
                            "duration_ms": 0, "success": True, "skipped": True,
                        })
                        node_outputs[node_id] = {"output": "", "success": True, "duration_ms": 0, "skipped": True}
                        continue

                # Build tool-specific config overlay from node data
                node_tool_config: dict = {}
                if tool_flags:
                    node_tool_config["nmap_flags"] = tool_flags
                if tool_timeout:
                    node_tool_config["timeout_override"] = tool_timeout

                # ── Pass all per-tool config fields from node data ──
                # cve
                for _k in ("cve_keyword", "cve_limit", "cve_action", "cve_severity", "cve_cve_id", "cve_cpe"):
                    if data.get(_k) is not None:
                        node_tool_config[_k] = data[_k]
                # cisa_kev
                if data.get("kev_action"):
                    node_tool_config["kev_action"] = data["kev_action"]
                if data.get("kev_cve_id") is not None:
                    node_tool_config["kev_cve_id"] = data["kev_cve_id"]
                if data.get("kev_keyword"):
                    node_tool_config["kev_keyword"] = data["kev_keyword"]
                if data.get("kev_limit"):
                    node_tool_config["kev_limit"] = data["kev_limit"]
                if data.get("kev_ransomware_only") is not None:
                    node_tool_config["kev_ransomware_only"] = data["kev_ransomware_only"]
                if data.get("kev_days"):
                    node_tool_config["kev_days"] = data["kev_days"]
                # epss
                if data.get("epss_action"):
                    node_tool_config["epss_action"] = data["epss_action"]
                if data.get("epss_cve_id") is not None:
                    node_tool_config["epss_cve_id"] = data["epss_cve_id"]
                if data.get("epss_cve_ids"):
                    node_tool_config["epss_cve_ids"] = data["epss_cve_ids"]
                if data.get("epss_min_score"):
                    node_tool_config["epss_min_score"] = data["epss_min_score"]
                if data.get("epss_limit"):
                    node_tool_config["epss_limit"] = data["epss_limit"]
                # poc_index
                if data.get("poc_action"):
                    node_tool_config["poc_action"] = data["poc_action"]
                if data.get("poc_query"):
                    node_tool_config["poc_query"] = data["poc_query"]
                if data.get("poc_cve_id"):
                    node_tool_config["poc_cve_id"] = data["poc_cve_id"]
                if data.get("poc_limit"):
                    node_tool_config["poc_limit"] = data["poc_limit"]
                # nuclei
                for _k in ("nuclei_templates", "nuclei_severity", "nuclei_action",
                           "nuclei_rate_limit", "nuclei_year", "nuclei_category"):
                    if data.get(_k) is not None:
                        node_tool_config[_k] = data[_k]
                # subfinder / dig / whois / ssl
                if data.get("domain"):
                    node_tool_config["domain"] = data["domain"]
                if data.get("record_type"):
                    node_tool_config["record_type"] = data["record_type"]
                # ffuf
                if data.get("ffuf_url"):
                    node_tool_config["ffuf_url"] = data["ffuf_url"]
                if data.get("ffuf_wordlist"):
                    node_tool_config["ffuf_wordlist"] = data["ffuf_wordlist"]
                if data.get("ffuf_extensions"):
                    node_tool_config["ffuf_extensions"] = data["ffuf_extensions"]
                if data.get("ffuf_method"):
                    node_tool_config["ffuf_method"] = data["ffuf_method"]
                # sqlmap
                if data.get("sqlmap_url"):
                    node_tool_config["sqlmap_url"] = data["sqlmap_url"]
                if data.get("sqlmap_data"):
                    node_tool_config["sqlmap_data"] = data["sqlmap_data"]
                if data.get("sqlmap_level"):
                    node_tool_config["sqlmap_level"] = data["sqlmap_level"]
                if data.get("sqlmap_risk"):
                    node_tool_config["sqlmap_risk"] = data["sqlmap_risk"]
                if data.get("sqlmap_technique"):
                    node_tool_config["sqlmap_technique"] = data["sqlmap_technique"]
                # nikto
                if data.get("nikto_url"):
                    node_tool_config["nikto_url"] = data["nikto_url"]
                if data.get("nikto_host"):
                    node_tool_config["nikto_host"] = data["nikto_host"]
                if data.get("nikto_port"):
                    node_tool_config["nikto_port"] = data["nikto_port"]
                if data.get("nikto_timeout"):
                    node_tool_config["nikto_timeout"] = data["nikto_timeout"]
                # nmap
                for _k in ("nmap_flags", "nmap_action", "nmap_ports", "nmap_check_port"):
                    if data.get(_k) is not None:
                        node_tool_config[_k] = data[_k]
                # waf
                for _k in ("waf_url", "waf_action", "waf_protocol", "waf_payload",
                           "waf_waf_type", "waf_attack_type"):
                    if data.get(_k) is not None:
                        node_tool_config[_k] = data[_k]
                # metasploit
                for _k in (
                    "msf_action", "msf_module", "msf_payload", "msf_lhost",
                    "msf_lport", "msf_target_port", "msf_check_first", "msf_rhosts",
                    "msf_session_id", "msf_command", "msf_query", "msf_module_type",
                    "msf_platform", "msf_arch", "msf_format", "msf_limit",
                    "msf_job_id", "msf_options", "msf_chain_mode", "msf_chain_limit",
                    "msf_chain_exploit_checks", "msf_chain_post", "msf_wait_ms", "msf_max_reads",
                ):
                    if data.get(_k) is not None:
                        node_tool_config[_k] = data[_k]
                # gobuster
                for _k in ("gobuster_mode", "gobuster_url", "gobuster_wordlist",
                           "gobuster_extensions", "gobuster_domain"):
                    if data.get(_k) is not None:
                        node_tool_config[_k] = data[_k]
                # jwt
                for _k in ("jwt_action", "jwt_secret", "jwt_algorithm",
                           "jwt_claims", "jwt_wordlist"):
                    if data.get(_k) is not None:
                        node_tool_config[_k] = data[_k]
                # wpscan
                for _k in ("wpscan_url", "wpscan_enumerate", "wpscan_api_token"):
                    if data.get(_k) is not None:
                        node_tool_config[_k] = data[_k]
                # masscan
                for _k in ("masscan_action", "masscan_ports", "masscan_rate", "masscan_top", "masscan_cidr", "masscan_targets", "masscan_extra_args"):
                    if data.get(_k) is not None:
                        node_tool_config[_k] = data[_k]
                # cve_lite
                for _k in (
                    "cve_lite_action", "cve_lite_project_path", "cve_lite_min_severity",
                    "cve_lite_all", "cve_lite_prod_only", "cve_lite_usage",
                    "cve_lite_only_used", "cve_lite_offline", "cve_lite_offline_db",
                    "cve_lite_fail_on",
                ):
                    if data.get(_k) is not None:
                        node_tool_config[_k] = data[_k]
                # mitre
                for _k in (
                    "mitre_action", "mitre_domain", "mitre_technique_id",
                    "mitre_tactic", "mitre_platform", "mitre_query",
                    "mitre_group_id", "mitre_mitigation_id", "mitre_limit",
                    "mitre_include_subtechniques",
                ):
                    if data.get(_k) is not None:
                        node_tool_config[_k] = data[_k]

                # ── CVE-type tools: auto-use target as the CVE/keyword when blank ──
                # When workflow_type is 'cve' or 'keyword', the start node target
                # holds a CVE ID or keyword. Fill in defaults so tools don't need
                # the user to re-enter the same value.
                target_cve_ids = _extract_cve_ids(target)
                is_cve_target = len(target_cve_ids) > 0
                target_cve_csv = ", ".join(target_cve_ids)

                if tool_name == "cve":
                    if not node_tool_config.get("cve_action"):
                        node_tool_config["cve_action"] = "search_cves"
                    if not node_tool_config.get("cve_keyword"):
                        node_tool_config["cve_keyword"] = target
                    if (
                        node_tool_config.get("cve_action") in ("lookup_cve", "get_severity")
                        and not node_tool_config.get("cve_cve_id")
                    ):
                        node_tool_config["cve_cve_id"] = target_cve_csv if is_cve_target else ""

                if tool_name == "cisa_kev":
                    if not node_tool_config.get("kev_action"):
                        node_tool_config["kev_action"] = "check_kev" if is_cve_target else "search_kev"
                    if node_tool_config.get("kev_action") == "check_kev" and not node_tool_config.get("kev_cve_id"):
                        node_tool_config["kev_cve_id"] = target_cve_csv if is_cve_target else ""
                    if node_tool_config.get("kev_action") == "search_kev" and not node_tool_config.get("kev_keyword"):
                        node_tool_config["kev_keyword"] = target
                if tool_name == "epss":
                    if not node_tool_config.get("epss_action"):
                        node_tool_config["epss_action"] = "get_epss_score"
                    if node_tool_config.get("epss_action") == "get_epss_score" and not node_tool_config.get("epss_cve_id"):
                        node_tool_config["epss_cve_id"] = target_cve_ids[0] if is_cve_target else ""
                    if (
                        node_tool_config.get("epss_action") in ("get_epss_scores_bulk", "epss_priority_analysis")
                        and not node_tool_config.get("epss_cve_ids")
                    ):
                        node_tool_config["epss_cve_ids"] = target_cve_csv if is_cve_target else ""
                if tool_name == "poc_index" and not node_tool_config.get("poc_query") and not node_tool_config.get("poc_cve_id"):
                    node_tool_config["poc_query"] = target
                if (
                    tool_name == "poc_index"
                    and node_tool_config.get("poc_action") in ("search_github_poc", "poc_risk_summary")
                    and not node_tool_config.get("poc_cve_id")
                ):
                    node_tool_config["poc_cve_id"] = target_cve_csv if is_cve_target else ""

                # Effective HTTP target from nmap context
                eff_http = http_target
                if nmap_ctx["http_ports"]:
                    best = nmap_ctx["http_ports"][0]
                    proto = "https" if best in (443, 8443) else "http"
                    eff_http = f"{proto}://{target}:{best}"

                if tool_name == "metasploit":
                    if nmap_ctx.get("open_ports"):
                        node_tool_config["msf_open_ports"] = nmap_ctx.get("open_ports", [])
                    if nmap_ctx.get("services"):
                        node_tool_config["msf_services"] = nmap_ctx.get("services", {})

                # ── Manifest-driven node ("mcp:<server>:<action>"): pass every field the node set straight through.
                # Keys are namespaced ("<server>.<action>.<field>") or bare field names; the generic dispatcher reads both.
                if tool_name.startswith("mcp:"):
                    for _k, _v in data.items():
                        if _k in ("tool", "label", "timeout", "flags", "port_filter"):
                            continue
                        if _v is not None and _v != "":
                            node_tool_config[_k] = _v
                    if data.get("timeout"):
                        node_tool_config["mcp_timeout"] = data["timeout"]

                # Inherit CVE IDs found earlier in this workflow (by a CVE Lookup or CVE Lite node) into a CVE-consuming
                # node whose own field is still blank — so "keyword -> CVE Lookup -> CISA KEV" and "CVE Lite -> CVE
                # Lookup -> EPSS" chains work without re-typing the CVE at every step. An explicit value on the node
                # itself always wins; this only fills in what the node left empty.
                if cve_ctx and tool_name in ("cisa_kev", "epss", "poc_index", "cve"):
                    _cve_joined = ", ".join(cve_ctx[:20])
                    _field = {"cisa_kev": "kev_cve_id", "epss": "epss_cve_id", "poc_index": "poc_cve_id", "cve": "cve_cve_id"}[tool_name]
                    if not str(node_tool_config.get(_field, "")).strip():
                        node_tool_config[_field] = _cve_joined

                _, result_data, duration_ms = await _run_single_tool(
                    tool_name, target, eff_http, node_tool_config
                )

                # A CVE-producing node's findings become available to any LATER node in the workflow.
                if tool_name in ("cve", "cve_lite"):
                    _found = _extract_cve_ids(result_data.get("output", ""))
                    for _c in _found:
                        if _c not in cve_ctx:
                            cve_ctx.append(_c)
                    cve_ctx[:] = cve_ctx[:50]  # keep this bounded for very large dependency scans

                # Update nmap context if this was an nmap node
                if tool_name == "nmap":
                    nmap_ctx = _extract_nmap_context(result_data.get("output", ""))
                    # Trim the verbose raw text from stored output — structured data is preserved
                    try:
                        _nmap_out = json.loads(result_data["output"])
                        if isinstance(_nmap_out, dict) and "raw" in _nmap_out:
                            _raw = _nmap_out["raw"]
                            if len(_raw) > 1000:
                                _nmap_out["raw"] = _raw[:1000] + f"\n… [{len(_raw) - 1000} chars truncated]"
                            result_data = {**result_data, "output": json.dumps(_nmap_out)}
                    except Exception:
                        pass

                node_outputs[node_id] = {**result_data, "duration_ms": duration_ms, "_tool": tool_name}
                results.append((tool_name, result_data, duration_ms))
                _ws_evt: dict = {
                    "node_id": node_id, "node_type": "tool", "tool": tool_name,
                    # Keep full tool output so frontend can parse valid JSON summaries.
                    "output": result_data.get("output", ""),
                    "duration_ms": duration_ms,
                    "success": result_data.get("success", False),
                }
                # Forward MSF session IDs so the Terminal tab can detect live sessions.
                if result_data.get("msf_session_ids"):
                    _ws_evt["msf_session_ids"] = result_data["msf_session_ids"]
                await _notify_ws(scan_id, "node_complete", _ws_evt)

            # ── LLM node ───────────────────────────────────────
            elif node_type == "llm":
                # Node config overrides default_llm
                provider_str = data.get("provider") or (default_llm or {}).get("provider", "ollama_remote")
                model = data.get("model") or (default_llm or {}).get("model", "qwen2.5:7b")
                remote_url = data.get("remote_url") or (default_llm or {}).get("remote_url")
                prompt_tmpl = data.get("prompt", "Summarize the findings from the workflow tools above. Only report what was actually found in the tool output — do not add vulnerabilities or issues not explicitly present in the data.")
                output_key = data.get("output_key", "analysis")

                # Inject target into node_outputs so {{start.output}} works
                prompt = _resolve_prompt(prompt_tmpl, {**node_outputs, "target": {"output": target}})

                response = ""
                try:
                    from app.core.llm_providers import normalize_provider
                    provider = LLMProvider(normalize_provider(provider_str))
                except ValueError:
                    provider = LLMProvider.OLLAMA_REMOTE

                # Resolve the admin-saved API key for whatever provider this node actually selected. Previously this
                # block captured the node's chosen provider correctly but then only ever executed against Ollama —
                # a node configured for OpenAI/Anthropic/etc. silently ran Ollama instead, with no key for any other
                # provider ever threaded through at all. Ollama's "credential" is its URL, not an api_key.
                node_api_key = None
                if provider != LLMProvider.OLLAMA_REMOTE and db is not None:
                    try:
                        from app.core.llm_providers import resolve_llm_credentials
                        node_api_key, _resolved_url = await resolve_llm_credentials(db, provider.value)
                        if not remote_url:
                            remote_url = _resolved_url
                    except Exception:
                        node_api_key = None

                use_primary = False
                if provider == LLMProvider.OLLAMA_REMOTE and remote_url:
                    try:
                        async for token in llm_service.chat(
                            prompt, provider=provider, model=model, remote_url=remote_url
                        ):
                            response += token
                        use_primary = True
                        logger.info(f"Workflow LLM: Successfully used remote Ollama at {remote_url}")
                    except Exception as remote_err:
                        logger.warning(f"Workflow LLM: Remote Ollama at {remote_url} failed: {remote_err}. Falling back to the default Ollama server.")
                        response = ""
                elif provider != LLMProvider.OLLAMA_REMOTE:
                    try:
                        async for token in llm_service.chat(
                            prompt, provider=provider, model=model, remote_url=remote_url, api_key=node_api_key
                        ):
                            response += token
                        use_primary = True
                        logger.info(f"Workflow LLM: Successfully used {provider.value}")
                    except Exception as provider_err:
                        logger.warning(f"Workflow LLM: {provider.value} failed: {provider_err}. Falling back to the default Ollama server.")
                        response = ""

                # Fall back to the default (env-configured) Ollama server only if the node's OWN chosen provider
                # failed or had no URL/key — never silently substitute Ollama for a provider that simply hasn't been
                # tried yet (that was the bug: this used to be the unconditional path for every non-Ollama node).
                if not use_primary:
                    try:
                        async for token in llm_service.chat(
                            prompt, provider=LLMProvider.OLLAMA_REMOTE, model=model
                        ):
                            response += token
                        logger.info("Workflow LLM: Successfully used Ollama (fallback)")
                    except Exception as local_err:
                        logger.error(f"Workflow LLM: Ollama fallback failed: {local_err}")
                        response = f"[!] LLM Analysis failed: {str(local_err)[:200]}"

                duration_ms = int(time.time() * 1000) - t0
                node_outputs[node_id] = {output_key: response, "output": response, "success": True, "duration_ms": duration_ms}
                results.append(("llm_analysis", {"output": response, "success": True}, duration_ms))
                await _notify_ws(scan_id, "node_complete", {
                    "node_id": node_id, "node_type": "llm",
                    "output": response,
                    "duration_ms": duration_ms, "success": True,
                })

            # ── Condition node ─────────────────────────────────
            elif node_type == "condition":
                expression = data.get("expression", "true")
                result_bool = _evaluate_condition(expression, nmap_ctx, node_outputs)

                duration_ms = int(time.time() * 1000) - t0
                node_outputs[node_id] = {"output": str(result_bool), "result": result_bool, "success": True, "duration_ms": duration_ms}
                await _notify_ws(scan_id, "node_complete", {
                    "node_id": node_id, "node_type": "condition",
                    "output": str(result_bool), "result": result_bool,
                    "duration_ms": duration_ms, "success": True,
                })

                # Skip nodes on the losing branch
                losing_handle = "no" if result_bool else "yes"
                for e in edge_map.get(node_id, []):
                    if e.get("sourceHandle") == losing_handle:
                        skipped.add(e["target"])

            # ── Report node ────────────────────────────────────
            elif node_type == "report":
                template = data.get("template", "standard")
                report_format = data.get("report_format", "html")
                report_theme = data.get("report_theme", "dark")
                summary = "\n\n".join(
                    f"=== {nid} ===\n{out.get('output', '')[:1000]}"
                    for nid, out in node_outputs.items()
                )

                # ── Generate HTML file and persist a Report DB record ──────
                try:
                    import html as _html
                    from app.models.report import Report as ReportModel
                    from app.models.enums import ReportFormat as RF, ReportStatus as RS
                    from app.services.report_service import REPORTS_DIR

                    bg         = "#0d1117" if report_theme == "dark" else "#ffffff"
                    text_col   = "#c9d1d9" if report_theme == "dark" else "#1f2937"
                    border_col = "#30363d" if report_theme == "dark" else "#e5e7eb"
                    card_bg    = "#161b22" if report_theme == "dark" else "#f9fafb"
                    accent     = "#0ff0fc"

                    sections_html = ""
                    for nid, out in node_outputs.items():
                        output_text = str(out.get("output", "")).strip()
                        if not output_text:
                            continue
                        node_label = next(
                            (n.get("data", {}).get("label") or n.get("data", {}).get("tool") or nid
                             for n in nodes if n.get("id") == nid),
                            nid,
                        )
                        escaped_label  = _html.escape(node_label)
                        escaped_output = _html.escape(output_text[:6000])
                        sections_html += (
                            f'<div style="background:{card_bg};border:1px solid {border_col};'
                            f'border-radius:8px;padding:1.25rem;margin-bottom:1.25rem;">'
                            f'<h3 style="color:{accent};font-size:0.85rem;font-weight:600;'
                            f'margin:0 0 0.75rem;text-transform:uppercase;letter-spacing:0.05em;">'
                            f'{escaped_label}</h3>'
                            f'<pre style="white-space:pre-wrap;word-break:break-word;'
                            f'font-family:monospace;font-size:0.8rem;color:{text_col};margin:0;">'
                            f'{escaped_output}</pre></div>'
                        )

                    generated_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                    empty_fallback = '<p style="opacity:0.5">No tool outputs collected.</p>'
                    html_content = (
                        '<!DOCTYPE html><html lang="en"><head>'
                        '<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                        f'<title>SOCIS-AI-PT Workflow Report — {_html.escape(target)}</title>'
                        f'<style>*{{box-sizing:border-box;margin:0;padding:0}}'
                        f'body{{background:{bg};color:{text_col};font-family:"Segoe UI",system-ui,sans-serif;'
                        'line-height:1.6;padding:2rem}'
                        '.container{max-width:960px;margin:0 auto}'
                        f'.header{{border-bottom:2px solid {accent};padding-bottom:1rem;margin-bottom:2rem}}'
                        f'.header h1{{color:{accent};font-size:1.5rem;font-weight:700}}'
                        '.meta{font-size:0.8rem;opacity:0.6;margin-top:0.4rem}</style></head>'
                        '<body><div class="container">'
                        '<div class="header">'
                        '<h1>SOCIS-AI-PT — Workflow Report</h1>'
                        f'<p>Target: <strong>{_html.escape(target)}</strong></p>'
                        f'<div class="meta">Template: {_html.escape(template)} &nbsp;|&nbsp; '
                        f'Theme: {_html.escape(report_theme.capitalize())} &nbsp;|&nbsp; '
                        f'Generated: {generated_ts}</div></div>'
                        + (sections_html or empty_fallback) +
                        '</div></body></html>'
                    )

                    report_id = uuid.uuid4()
                    report_filename = f"report_{report_id}.html"
                    report_path = REPORTS_DIR / report_filename
                    report_path.write_text(html_content, encoding="utf-8")
                    file_size = report_path.stat().st_size

                    if db is not None and scan_obj is not None:
                        # Map report_format to ReportFormat enum (default html)
                        fmt_map = {"pdf": RF.PDF, "html": RF.HTML, "json": RF.JSON, "csv": RF.CSV}
                        db_fmt = fmt_map.get(report_format, RF.HTML)
                        report_record = ReportModel(
                            id=report_id,
                            scan_id=scan_obj.id,
                            generated_by=scan_obj.initiated_by,
                            format=db_fmt,
                            status=RS.COMPLETED,
                            file_path=str(report_path),
                            file_url=f"/api/v1/reports/{report_id}/download",
                            file_size_bytes=file_size,
                            brand_name="SOCIS-AI-PT",
                        )
                        try:
                            db.add(report_record)
                            await db.commit()
                            logger.info("Workflow report saved to DB: %s (scan=%s)", report_path, scan_id)
                        except Exception as db_rep_err:
                            # Roll back the poisoned transaction so the session
                            # remains usable for subsequent commits (e.g. tool results).
                            await db.rollback()
                            logger.warning(
                                "Report node: DB insert failed (FK or integrity error) — "
                                "report file kept on disk, DB record skipped: %s", db_rep_err
                            )
                    else:
                        logger.warning("Report node: db/scan_obj not available, skipping DB record.")

                except Exception as rep_err:
                    logger.error("Workflow report generation failed: %s", rep_err)

                duration_ms = int(time.time() * 1000) - t0
                node_outputs[node_id] = {
                    "output": summary, "success": True, "duration_ms": duration_ms,
                    "report_format": report_format, "report_theme": report_theme,
                }
                await _notify_ws(scan_id, "node_complete", {
                    "node_id": node_id, "node_type": "report",
                    "output": f"Report generated ({template} template, {report_format.upper()}, {report_theme} theme)",
                    "duration_ms": duration_ms, "success": True,
                })

            else:
                duration_ms = int(time.time() * 1000) - t0
                node_outputs[node_id] = {"output": f"Unknown node type: {node_type}", "success": False, "duration_ms": duration_ms}
                await _notify_ws(scan_id, "node_failed", {
                    "node_id": node_id, "node_type": node_type,
                    "error": f"Unknown node type: {node_type}",
                })

        except Exception as exc:
            duration_ms = int(time.time() * 1000) - t0
            logger.exception("Graph node %s (%s) failed: %s", node_id, node_type, exc)
            node_outputs[node_id] = {"output": str(exc), "success": False, "duration_ms": duration_ms}
            await _notify_ws(scan_id, "node_failed", {
                "node_id": node_id, "node_type": node_type, "error": str(exc),
            })

    return results


# ─── Main Scan Task ───────────────────────────────────────────

async def run_scan(ctx, scan_id: str):
    """
    Full async penetration test pipeline executed as an ARQ background task.
    Pipeline: Start → Recon Tools → LLM Analysis → Parse Results → Save → Complete
    """
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from app.core.database import engine
    from app.models.scan import Scan, ScanStatus, ScanType
    from app.models.vulnerability import Vulnerability, Severity
    from app.models.vuln_comment import VulnComment  # registers mapper so Vulnerability relationship resolves
    from app.models.fix import Fix, FixSource, FixPriority
    from app.models.ai_analysis import AIAnalysis
    from app.services.llm_service import llm_service, SYSTEM_PROMPT
    from app.services.rag_service import rag_service
    from sqlalchemy import select
    import time

    async_session = async_sessionmaker(engine, expire_on_commit=False)

    async with async_session() as db:
        # ─ 1. Fetch scan from DB ──────────────────────────────
        result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
        scan = result.scalar_one_or_none()
        if not scan:
            return {"error": f"Scan {scan_id} not found"}

        # ─ 1b. Authorized-scope gate: the authoritative check for EVERY scan (API, workflow, schedule trigger, cron) ──────────
        from app.services import scope_service as _scope_service
        from app.core.scope_guard import set_scan_scope as _set_scan_scope
        _scope_msg, _scan_scope = await _scope_service.worker_gate(db, scan)
        if _scope_msg:
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
            await _notify_ws(scan_id, "status", {"status": "failed", "message": _scope_msg})
            await emit_scan_event(db, scan, "scan.failed", error=_scope_msg)
            return {"scan_id": scan_id, "status": "failed", "error": _scope_msg}
        _set_scan_scope(_scan_scope)   # tool calls made by this scan are checked against the same list

        target = scan.target
        tool_config = scan.tool_config or {}
        auto_ai_analysis = bool(tool_config.get("auto_ai_analysis", False))

        # ─ 2. Mark as RUNNING ─────────────────────────────────
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        await db.commit()
        await _notify_ws(scan_id, "status", {"status": "running", "message": f"Starting scan on {target}"})

        # Fire plugin on_scan_start hooks
        from app.plugins.loader import plugin_manager
        for plugin_cls in plugin_manager.plugins.values():
            try:
                await plugin_cls().on_scan_start(scan_id, target, tool_config)
            except Exception as _pe:
                logger.debug("Plugin on_scan_start error: %s", _pe)

        # Fire builtin plugin on_scan_start hooks
        try:
            from app.plugins.builtin import get_all_plugin_ids
            from app.services.plugin_config_service import get_plugin_config_row, load_plugin_instance
            from app.core.database import async_session as _async_session
            async with _async_session() as _bdb:
                for _bpid in get_all_plugin_ids():
                    _brow = await get_plugin_config_row(_bdb, _bpid)
                    if _brow and _brow.enabled:
                        _binst = load_plugin_instance(_bpid, _brow)
                        if _binst:
                            try:
                                await _binst.on_scan_start(scan_id, target, tool_config)
                            except Exception as _bpe:
                                logger.debug("Builtin plugin %s on_scan_start error: %s", _bpid, _bpe)
        except Exception as _buite:
            logger.debug("Builtin plugin scan_start batch error: %s", _buite)

        # ─ 3. Run Recon Tools in parallel (max 4 concurrent) ──
        tool_results = {}
        tools_to_run = tool_config.get("tools", ["nmap", "whois", "whatweb", "curl_headers", "dig"])

        # Normalise target for HTTP-based tools
        http_target = target if target.startswith("http") else f"http://{target}"

        # ─ Opt-in: AI payload pre-injection ───────────────────
        # If enabled, generate attack payloads via payload_generator MCP and
        # inject them into tool_config for ffuf / sqlmap fuzzing tools.
        if tool_config.get("ai_payloads", False):
            try:
                await _notify_ws(scan_id, "status", {"status": "running", "message": "Generating AI-assisted payloads..."})
                _payload_resp = await _call_mcp_tool(
                    MCP_URLS["payload_generator"], "generate_wordlist",
                    {"vuln_types": ["sqli", "xss", "lfi", "rce"], "include_ai": True, "deduplicate": True},
                    timeout=60,
                )
                if _payload_resp and "wordlist" in _payload_resp:
                    tool_config.setdefault("ffuf_wordlist_extra", [])
                    tool_config["ffuf_wordlist_extra"].extend(
                        (_payload_resp["wordlist"] or "").splitlines()[:200]
                    )
                    tool_config["sqlmap_extra_payloads"] = True
            except Exception as _payload_err:
                logger.warning("AI payload pre-injection failed (non-fatal): %s", _payload_err)

        # Shared nmap context — updated by _execute_workflow after Step 1 runs.
        # _run_with_semaphore reads this to use the correct HTTP port for web tools.
        workflow_nmap_ctx: dict = {"open_ports": [], "services": {}, "has_http": True, "http_ports": []}

        semaphore = asyncio.Semaphore(4)  # cap concurrent MCP calls

        async def _quick_triage(tool_name: str, output: str) -> str:
            """Lightweight single-sentence severity triage for a tool result."""
            from app.models.llm_config import LLMProvider
            prompt = (
                f"You are a security analyst. In ONE sentence classify the severity of these "
                f"{tool_name} findings on {target}.\n"
                f"Output format: TRIAGE: <CRITICAL|HIGH|MEDIUM|LOW|INFO> - <reason>\n\n"
                f"{output[:2000]}"
            )
            try:
                response = ""
                async for token in llm_service.chat(
                    prompt, provider=LLMProvider.OLLAMA_REMOTE, model=(settings.OLLAMA_REMOTE_MODEL or settings.OLLAMA_DEFAULT_MODEL)
                ):
                    response += token
                return response.strip()
            except Exception:
                return "TRIAGE: UNKNOWN - Could not analyze"

        async def _run_with_semaphore(tool_name: str):
            # Bail early if the user requested cancellation
            if await _is_cancelled(scan_id):
                return tool_name, {"output": "Scan cancelled", "success": False}, 0
            async with semaphore:
                await _notify_ws(scan_id, "tool_start", {"tool": tool_name})
                # Launch background progress emitter
                expected_secs = TOOL_EXPECTED_DURATIONS.get(tool_name, 60)
                start_ts = time.time()

                async def _emit_progress():
                    while True:
                        await asyncio.sleep(5)
                        elapsed = time.time() - start_ts
                        pct = min(90, int((elapsed / expected_secs) * 90))
                        await _notify_ws(scan_id, "tool_progress", {"tool": tool_name, "progress": pct})

                progress_task = asyncio.create_task(_emit_progress())
                try:
                    # For workflow mode: use the actual HTTP port nmap found (e.g. 8080 not 80)
                    effective_http = http_target
                    if workflow_nmap_ctx["http_ports"]:
                        best_port = workflow_nmap_ctx["http_ports"][0]
                        proto = "https" if best_port in (443, 8443) else "http"
                        effective_http = f"{proto}://{target}:{best_port}"

                    run_tool_config = tool_config
                    if tool_name == "metasploit":
                        run_tool_config = dict(tool_config)
                        if workflow_nmap_ctx.get("open_ports"):
                            run_tool_config["msf_open_ports"] = workflow_nmap_ctx.get("open_ports", [])
                        if workflow_nmap_ctx.get("services"):
                            run_tool_config["msf_services"] = workflow_nmap_ctx.get("services", {})

                    name, result_data, duration_ms = await _run_single_tool(
                        tool_name, target, effective_http, run_tool_config
                    )
                finally:
                    progress_task.cancel()
                    try:
                        await progress_task
                    except asyncio.CancelledError:
                        pass

                await _notify_ws(scan_id, "tool_complete", {
                    "tool": name,
                    "duration_ms": duration_ms,
                    "success": result_data.get("success", False),
                })
                # Per-tool AI triage (4.2)
                triage = await _quick_triage(name, result_data.get("output", ""))
                await _notify_ws(scan_id, "tool_triage", {"tool": name, "triage": triage})

                # Fire plugin on_tool_complete hooks
                for plugin_cls in plugin_manager.plugins.values():
                    try:
                        await plugin_cls().on_tool_complete(scan_id, name, result_data)
                    except Exception as _pe:
                        logger.debug("Plugin on_tool_complete error: %s", _pe)

                # Fire builtin plugin on_tool_complete hooks
                try:
                    from app.plugins.builtin import get_all_plugin_ids as _bpids2
                    from app.services.plugin_config_service import get_plugin_config_row as _brow2, load_plugin_instance as _binst2
                    from app.core.database import async_session as _async_session2
                    async with _async_session2() as _bdb2:
                        for _bpid2 in _bpids2():
                            _brow2v = await _brow2(_bdb2, _bpid2)
                            if _brow2v and _brow2v.enabled:
                                _binstv = _binst2(_bpid2, _brow2v)
                                if _binstv:
                                    try:
                                        await _binstv.on_tool_complete(scan_id, name, result_data)
                                    except Exception as _bpe2:
                                        logger.debug("Builtin plugin %s on_tool_complete error: %s", _bpid2, _bpe2)
                except Exception as _buite2:
                    logger.debug("Builtin plugin tool_complete batch error: %s", _buite2)

                # ── Incremental DB save ────────────────────────────────────────
                # Save immediately so a page refresh mid-scan reflects real state.
                # The batch-save at the end will skip already-saved rows.
                try:
                    from app.models.scan import ScanToolResult as _STR
                    async with async_session() as _save_db:
                        _rec = _STR(
                            scan_id=uuid.UUID(scan_id),
                            tool_name=name,
                            raw_output=result_data.get("output", ""),
                            parsed_output=result_data,
                            duration_ms=duration_ms,
                            exit_code=exit_code_for(result_data),
                        )
                        _save_db.add(_rec)
                        await _save_db.commit()
                except Exception as _db_err:
                    logger.warning("Incremental tool save failed for %s: %s", name, _db_err)

                return name, result_data, duration_ms

        # ─ Workflow mode: sequential chained steps OR graph ──
        scan_type_val = getattr(scan.scan_type, 'value', str(scan.scan_type))
        if scan_type_val == "workflow":
            # ── Graph-based (n8n-style) workflow ───────────────
            graph = tool_config.get("graph")
            if graph and graph.get("nodes"):
                # The Start node's configured value (IP / domain / CVE / keyword / URL) is the workflow's primary target,
                # and every downstream tool inherits it when its own field is blank. Use it as the run target so that
                # configuring the Start node actually drives the whole workflow (previously the scan-level target was used
                # and the Start node's value was ignored).
                _start_node = next((n for n in graph["nodes"] if n.get("type") == "start"), None)
                _start_val = ((_start_node or {}).get("data") or {}).get("target") if _start_node else None
                if _start_val and str(_start_val).strip():
                    target = str(_start_val).strip()
                    http_target = target if target.startswith("http") else f"http://{target}"
                try:
                    gathered = await _execute_workflow_graph(
                        scan_id=scan_id,
                        target=target,
                        nodes=graph["nodes"],
                        edges=graph.get("edges", []),
                        default_llm=tool_config.get("default_llm"),
                        http_target=http_target,
                        db=db,
                        scan_obj=scan,
                    )
                except Exception as gf_err:
                    scan.status = ScanStatus.FAILED
                    scan.completed_at = datetime.now(timezone.utc)
                    await db.commit()
                    await emit_scan_event(db, scan, "scan.failed", error=str(gf_err))
                    await _notify_ws(scan_id, "status", {"status": "failed", "message": str(gf_err)})
                    return {"scan_id": scan_id, "status": "failed", "error": str(gf_err)}
            else:
                # ── Legacy sequential-step workflow ───────────────
                workflow_id = tool_config.get("workflow_id", "full_pentest")
                template = WORKFLOW_TEMPLATES.get(workflow_id, WORKFLOW_TEMPLATES["full_pentest"])
                steps = tool_config.get("steps") or list(template["steps"])
                is_dynamic = template.get("dynamic", False)
                try:
                    gathered = await _execute_workflow(
                        scan_id, target, steps, _run_with_semaphore,
                        nmap_ctx_out=workflow_nmap_ctx, dynamic=is_dynamic,
                        tool_config=tool_config,
                    )
                except RuntimeError as wf_err:
                    scan.status = ScanStatus.FAILED
                    scan.completed_at = datetime.now(timezone.utc)
                    await db.commit()
                    await emit_scan_event(db, scan, "scan.failed", error=str(wf_err))
                    await _notify_ws(scan_id, "status", {"status": "failed", "message": str(wf_err)})
                    return {"scan_id": scan_id, "status": "failed", "error": str(wf_err)}
        else:
            gathered = await asyncio.gather(
                *[_run_with_semaphore(t) for t in tools_to_run],
                return_exceptions=False,
            )

        # ─ Agent mode: LLM decides follow-up tools (4.4) ─────
        if scan_type_val == "agent":
            from app.models.llm_config import LLMProvider
            import re as _re
            MAX_AGENT_ITERS = 4
            agent_tools_run: set[str] = set(tools_to_run)
            for _iter in range(MAX_AGENT_ITERS):
                if await _is_cancelled(scan_id):
                    break
                interim_summary = "\n".join(
                    f"=== {n.upper()} ===\n{d.get('output','')[:500]}"
                    for n, d, _ in gathered
                )
                agent_prompt = (
                    f"Based on these findings on {target}, what tools should run next?\n"
                    f"Available: {', '.join(MCP_URLS.keys())}\n"
                    f"Already run: {', '.join(agent_tools_run)}\n\n"
                    f"{interim_summary}\n\n"
                    f"Reply with: NEXT_TOOLS: tool1,tool2 (or DONE)"
                )
                decision = ""
                async for tok in llm_service.chat(
                    agent_prompt, provider=LLMProvider.OLLAMA_REMOTE, model=(settings.OLLAMA_REMOTE_MODEL or settings.OLLAMA_DEFAULT_MODEL)
                ):
                    decision += tok
                if "DONE" in decision or "NEXT_TOOLS:" not in decision:
                    break
                m = _re.search(r"NEXT_TOOLS:\s*(.+)", decision)
                if not m:
                    break
                next_tools = [t.strip() for t in m.group(1).split(",") if t.strip() in MCP_URLS and t.strip() not in agent_tools_run]
                if not next_tools:
                    break
                extra = await asyncio.gather(*[_run_with_semaphore(t) for t in next_tools])
                gathered = list(gathered) + list(extra)
                agent_tools_run.update(next_tools)

        # Check for cancellation after all tools finish
        if await _is_cancelled(scan_id):
            scan.status = "cancelled"
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
            return {"scan_id": scan_id, "status": "cancelled"}

        # Batch-save any tool results not yet written by incremental saves
        from app.models.scan import ScanToolResult
        _seen_tool_names: dict[str, int] = {}  # track count per base tool_name for dedup-safe keys
        for tool_name, result_data, duration_ms in gathered:
            # Make tool_name unique when the same tool appears in multiple nodes
            _count = _seen_tool_names.get(tool_name, 0)
            _seen_tool_names[tool_name] = _count + 1
            unique_tool_name = tool_name if _count == 0 else f"{tool_name}_{_count}"
            tool_results[unique_tool_name] = result_data
            try:
                exists_q = await db.execute(
                    select(ScanToolResult).where(
                        ScanToolResult.scan_id == uuid.UUID(scan_id),
                        ScanToolResult.tool_name == unique_tool_name,
                    )
                )
                if exists_q.scalar_one_or_none() is None:
                    tool_record = ScanToolResult(
                        scan_id=uuid.UUID(scan_id),
                        tool_name=unique_tool_name,
                        raw_output=result_data.get("output", ""),
                        parsed_output=result_data,
                        duration_ms=duration_ms,
                        exit_code=exit_code_for(result_data),
                    )
                    db.add(tool_record)
            except Exception as db_err:
                logger.error(f"Failed to save tool result for {unique_tool_name}: {db_err}")
        try:
            await db.commit()
        except Exception as _batch_commit_err:
            # Session may be in PendingRollback state from a failed report/node insert;
            # roll back and retry so the scan status can still be persisted.
            logger.warning("Batch tool-result commit failed, rolling back and retrying: %s", _batch_commit_err)
            await db.rollback()

        if not auto_ai_analysis:
            _all_failed, _fail_reasons = _all_tools_failed(tool_results.items())
            if _all_failed:
                scan.status = ScanStatus.FAILED
                scan.completed_at = datetime.now(timezone.utc)
                await db.commit()
                _err = "; ".join(_fail_reasons) or "every tool failed"
                await emit_scan_event(db, scan, "scan.failed", error=_err)
                await _notify_ws(scan_id, "status", {"status": "failed", "message": _err})
                return {"scan_id": scan_id, "status": "failed", "error": _err}
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            await db.commit()
            await emit_scan_event(db, scan, "scan.completed")
            await _notify_ws(scan_id, "complete", {
                "status": "completed",
                "risk_level": scan.risk_level,
                "vulnerability_count": 0,
                "exploit_count": 0,
                "message": "Tool execution completed. Run AI Analysis from the AI tab to generate findings.",
            })
            return {
                "scan_id": scan_id,
                "status": "completed",
                "risk_level": scan.risk_level,
                "vulnerabilities": 0,
                "ai_analysis": "manual",
            }

        # ─ 4. Build LLM Prompt ────────────────────────────────
        # Build complete tool outputs for LLM analysis (no truncation - LLM needs full context)
        tool_output_text = "\n\n".join(
            f"=== {name.upper()} ===\n{str(data.get('output', str(data)))}"
            for name, data in tool_results.items()
        )

        # Load dynamic system prompt from DB if one is configured (4.5)
        active_system_prompt = SYSTEM_PROMPT
        try:
            from app.models.prompt_template import PromptTemplate
            pt_result = await db.execute(
                select(PromptTemplate).where(
                    PromptTemplate.is_active == True,
                    PromptTemplate.is_default == True,
                    (PromptTemplate.scan_type == str(scan.scan_type)) |
                    (PromptTemplate.scan_type == None),
                ).order_by(PromptTemplate.scan_type.desc())  # prefer type-specific over generic
            )
            pt = pt_result.scalars().first()
            if pt:
                # Prepend methodology prompt — base SYSTEM_PROMPT (MCP tool tags,
                # [SEARCH:] rules, workflow JSON format) is always appended beneath.
                active_system_prompt = pt.system_prompt + "\n\n" + SYSTEM_PROMPT
        except Exception as e:
            logger.debug(f"Could not load custom system prompt: {e}")

        # RAG: fetch similar past findings for context (4.3)
        rag_context_block = ""
        try:
            similar = await rag_service.find_similar(
                db, f"Target: {target}\n{tool_output_text[:500]}", limit=5
            )
            if similar:
                rag_context_block = (
                    "\n\nSIMILAR PAST FINDINGS (for reference):\n"
                    + "\n---\n".join(similar)
                )
        except Exception as e:
            logger.debug(f"RAG similarity search failed: {e}")

        llm_user_prompt = f"""═══════════════════════════════════════════════════════════════════
TARGET: {target}
═══════════════════════════════════════════════════════════════════

{tool_output_text}{rag_context_block}

═══════════════════════════════════════════════════════════════════
Analyze the above reconnaissance data. For EVERY vulnerability found,
output it using EXACTLY this format (one per line block):

VULN: <name> | SEVERITY: <critical|high|medium|low> | PORT: <port> | SERVICE: <service>
DESC: <one-line description>
FIX: <one-line recommendation>

End your response with:
RISK_LEVEL: <CRITICAL|HIGH|MEDIUM|LOW>
SUMMARY: <2-3 sentence overall assessment>
═══════════════════════════════════════════════════════════════════
"""
        llm_prompt = f"{active_system_prompt}\n\n{llm_user_prompt}"  # for storage

        # ─ 5. LLM Analysis ────────────────────────────────────
        scan.status = ScanStatus.ANALYZING
        await db.commit()
        await _notify_ws(scan_id, "status", {"status": "analyzing", "message": "AI is analyzing findings..."})

        llm_response = ""
        llm_start = time.time()
        llm_metadata = {
            "source": "unknown",
            "provider": "unknown",
            "model": "",
            "remote_url": None,
        }
        try:
            # Determine which LLM provider and model to use. This runs unattended after EVERY scan — there is no
            # user request to read a provider choice from — so it must use the admin's actual configured default
            # (whichever provider that is), not assume Ollama. Previously this was hardcoded to Ollama with no
            # lookup at all, so configuring e.g. OpenAI as the default provider had no effect on this step.
            from app.services.settings_service import SettingsService
            from app.models.llm_config import LLMProvider
            from app.core.llm_providers import resolve_default_llm_config, normalize_provider

            settings_service = SettingsService()
            default_cfg = await resolve_default_llm_config(db)

            use_default = False
            if default_cfg:
                try:
                    provider_value = default_cfg["provider"]
                    model = default_cfg["model"]
                    cfg_api_key = default_cfg["api_key"]
                    cfg_api_url = default_cfg["api_url"]
                    # Ollama's "credential" is its URL, resolved via the admin setting if the config row didn't
                    # carry one of its own; every other provider uses the config's own api_url/api_key as-is.
                    if provider_value == "ollama_remote" and not cfg_api_url:
                        cfg_api_url = await settings_service.get_ollama_remote_url(db)
                    try:
                        provider = LLMProvider(provider_value)
                    except ValueError:
                        provider = LLMProvider.OLLAMA_REMOTE
                    llm_metadata = {
                        "source": "configured_default",
                        "provider": str(provider.value),
                        "model": model,
                        "remote_url": cfg_api_url,
                    }
                    use_default = True
                    await _notify_ws(scan_id, "status", {
                        "status": "analyzing",
                        "message": f"AI analyzing with {provider.value} ({model})",
                        "llm_source": "configured_default",
                        "llm_provider": str(provider.value),
                        "llm_model": model,
                        "llm_remote_url": cfg_api_url,
                    })
                    async for token in llm_service.chat(
                        llm_user_prompt, provider=provider, model=model, remote_url=cfg_api_url,
                        api_key=cfg_api_key, system_prompt=active_system_prompt,
                    ):
                        llm_response += token
                        await _notify_ws(scan_id, "llm_token", {"token": token})
                except Exception as default_err:
                    logger.warning(f"Configured default LLM ({default_cfg.get('provider')}) failed: {default_err}. "
                                    f"Falling back to the Ollama .env default.")
                    llm_response = ""
                    use_default = False

            # Final fallback: no LLMConfig row exists at all, or the configured default just failed — use the
            # Ollama .env default, exactly as this step always did before any provider was ever configured.
            if not use_default:
                provider = LLMProvider.OLLAMA_REMOTE
                model = settings.OLLAMA_DEFAULT_MODEL or "socis-pentest"
                _fallback_url = settings.OLLAMA_REMOTE_URL or None
                llm_metadata = {
                    "source": "ollama",
                    "provider": str(provider.value),
                    "model": model,
                    "remote_url": _fallback_url,
                }
                await _notify_ws(scan_id, "status", {
                    "status": "analyzing",
                    "message": f"AI analyzing with Ollama ({model})",
                    "llm_source": "ollama",
                    "llm_provider": str(provider.value),
                    "llm_model": model,
                })
                async for token in llm_service.chat(llm_user_prompt, provider=provider, model=model, remote_url=_fallback_url, system_prompt=active_system_prompt):
                    llm_response += token
                    await _notify_ws(scan_id, "llm_token", {"token": token})
        except Exception as e:
            logger.error(f"LLM analysis failed (both configured default and Ollama fallback): {type(e).__name__}: {e!r}")
            llm_response = f"[!] LLM analysis failed: {type(e).__name__}: {str(e)[:200]}"
            llm_metadata = {
                "source": "failed",
                "provider": "unknown",
                "model": "",
                "remote_url": (cfg_api_url if 'cfg_api_url' in locals() else None) or (_fallback_url if '_fallback_url' in locals() else None),
            }

        llm_duration_ms = int((time.time() - llm_start) * 1000)

        # ─ 6. Parse and Save AI Results ───────────────────────
        parsed_vulns = llm_service.parse_vulnerabilities(llm_response)
        parsed_exploits = llm_service.parse_exploits(llm_response)
        # Extract authoritative CVSS ceiling from CVE tool output so the AI
        # cannot inflate the risk above what NVD/CVSS actually rates the CVEs.
        cvss_ceiling = _extract_cvss_max_from_text(tool_output_text)
        risk_level = _reconcile_risk_level(
            llm_service.parse_risk_level(llm_response), parsed_vulns, cvss_max=cvss_ceiling
        )

        # Save AI analysis record
        ai_analysis = AIAnalysis(
            scan_id=uuid.UUID(scan_id),
            prompt=llm_prompt[:5000],  # Truncate for storage
            response=llm_response,
            risk_level=risk_level,
            parsed_data={
                "vulnerabilities": parsed_vulns,
                "exploits": parsed_exploits,
                "llm_metadata": llm_metadata,
            },
            duration_ms=llm_duration_ms,
        )
        db.add(ai_analysis)
        await db.commit()

        # Save vulnerabilities to DB
        import hashlib as _hashlib
        # Simple OWASP Top-10 keyword → category map
        OWASP_MAP = {
            "injection": "A03:2021 - Injection",
            "sql": "A03:2021 - Injection",
            "xss": "A03:2021 - Injection",
            "auth": "A07:2021 - Identification and Authentication Failures",
            "broken auth": "A07:2021 - Identification and Authentication Failures",
            "sensitive data": "A02:2021 - Cryptographic Failures",
            "crypto": "A02:2021 - Cryptographic Failures",
            "ssrf": "A10:2021 - Server-Side Request Forgery",
            "xxe": "A05:2021 - Security Misconfiguration",
            "misconfigur": "A05:2021 - Security Misconfiguration",
            "deseri": "A08:2021 - Software and Data Integrity Failures",
            "component": "A06:2021 - Vulnerable and Outdated Components",
            "logging": "A09:2021 - Security Logging and Monitoring Failures",
            "access control": "A01:2021 - Broken Access Control",
        }

        for vuln_data in parsed_vulns:
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            severity = severity_map.get(vuln_data.get("severity", "medium").lower(), Severity.MEDIUM)

            vuln_name = str(vuln_data.get("vuln_name") or "Unknown").strip()[:500]
            port = str(vuln_data.get("port") or "").strip()[:20] or None
            service_raw = str(vuln_data.get("service") or "").strip()
            description_raw = str(vuln_data.get("description") or "").strip()

            # Guard: LLM sometimes bleeds description into service field.
            if len(service_raw) > 100:
                if not description_raw:
                    description_raw = service_raw
                service_raw = service_raw[:100]
            service = service_raw[:200] or None

            # Deduplication fingerprint
            raw_fp = f"{vuln_name.lower().strip()}:{port or ''}:{(service or '').lower().strip()}"
            fingerprint = _hashlib.sha256(raw_fp.encode()).hexdigest()

            # OWASP auto-mapping
            name_lower = vuln_name.lower()
            owasp_cat = next(
                (v for k, v in OWASP_MAP.items() if k in name_lower), None
            )

            vuln = Vulnerability(
                scan_id=uuid.UUID(scan_id),
                vuln_name=vuln_name,
                severity=severity,
                port=port,
                service=service,
                description=description_raw or None,
                cve_id=str(vuln_data.get("cve_id") or "")[:20] or None,
                fingerprint=fingerprint,
                owasp_category=owasp_cat,
            )
            db.add(vuln)
            await db.flush()  # generate vuln.id before referencing in Fix
            fix_text = (vuln_data.get("fix") or "").strip()
            if fix_text:
                fix_priority = FixPriority.HIGH if severity in (Severity.CRITICAL, Severity.HIGH) else FixPriority.MEDIUM
                db.add(Fix(vuln_id=vuln.id, fix_text=fix_text, source=FixSource.AI, priority=fix_priority))

        await db.commit()

        # Store RAG embeddings in the background (non-blocking, best-effort) (4.3)
        try:
            result_vulns = await db.execute(
                select(Vulnerability).where(Vulnerability.scan_id == uuid.UUID(scan_id))
            )
            for sv in result_vulns.scalars().all():
                content = f"{sv.vuln_name} {sv.description or ''} {sv.cve_id or ''}".strip()
                asyncio.ensure_future(rag_service.store_finding(db, str(sv.id), content))
        except Exception:
            pass  # Embeddings are best-effort

        # ─ Opt-in: Anomaly scoring on tool results ─────────────
        if tool_config.get("enable_anomaly_detection", False):
            try:
                await _notify_ws(scan_id, "status", {"status": "running", "message": "Running anomaly detection on tool results..."})
                from app.models.scan import ScanToolResult as _STR2
                from sqlalchemy import select as _select
                _tool_rows = (await db.execute(
                    _select(_STR2).where(_STR2.scan_id == uuid.UUID(scan_id))
                )).scalars().all()

                # Collect HTTP-related tool outputs as sample URLs (best-effort)
                _sample_urls: list[str] = [http_target]
                for _row in _tool_rows:
                    _out = (_row.raw_output or "")[:500]
                    for _token in _out.split():
                        if _token.startswith("http") and len(_token) > 10:
                            _sample_urls.append(_token[:200])
                _sample_urls = list(dict.fromkeys(_sample_urls))[:30]

                # Train if no model yet
                _anomaly_train_resp = await _call_mcp_tool(
                    MCP_URLS["anomaly"], "anomaly_status", {"target": http_target}, timeout=15
                )
                if not (_anomaly_train_resp or {}).get("model_exists", False):
                    await _call_mcp_tool(
                        MCP_URLS["anomaly"], "anomaly_train",
                        {"target": http_target, "sample_urls": _sample_urls, "timeout": 10},
                        timeout=120,
                    )

                # Score the sample URLs
                _score_resp = await _call_mcp_tool(
                    MCP_URLS["anomaly"], "anomaly_score",
                    {"target": http_target, "urls": _sample_urls, "timeout": 10},
                    timeout=120,
                )
                if _score_resp and "scored_responses" in _score_resp:
                    _scored_map = {
                        s["url"]: s.get("anomaly_score")
                        for s in _score_resp["scored_responses"]
                        if s.get("anomaly_score") is not None
                    }
                    for _row in _tool_rows:
                        if _row.anomaly_score is None and http_target in _scored_map:
                            _row.anomaly_score = _scored_map[http_target]
                    await db.commit()

                await _notify_ws(scan_id, "anomaly_complete", {
                    "anomalous_count": (_score_resp or {}).get("anomalous_count", 0),
                    "total": (_score_resp or {}).get("total", 0),
                })
            except Exception as _anomaly_err:
                logger.warning("Anomaly detection opt-in failed (non-fatal): %s", _anomaly_err)

        # ─ 7. Mark as COMPLETED (or FAILED if every tool that ran failed — a scan with no real data is not a success) ──
        _all_failed, _fail_reasons = _all_tools_failed(tool_results.items())
        scan.completed_at = datetime.now(timezone.utc)
        scan.risk_level = risk_level
        if _all_failed:
            scan.status = ScanStatus.FAILED
            await db.commit()
            _err = "; ".join(_fail_reasons) or "every tool failed"
            await emit_scan_event(db, scan, "scan.failed", error=_err)
            await _notify_ws(scan_id, "status", {"status": "failed", "message": _err})
        else:
            scan.status = ScanStatus.COMPLETED
            await db.commit()
            await emit_scan_event(db, scan, "scan.completed")
            await _notify_ws(scan_id, "complete", {
                "status": "completed",
                "risk_level": risk_level,
                "vulnerability_count": len(parsed_vulns),
                "exploit_count": len(parsed_exploits),
                "message": f"Scan complete. Found {len(parsed_vulns)} vulnerabilities. Risk: {risk_level}",
            })

        # Fire plugin lifecycle hooks: on_scan_complete + on_critical_vuln
        all_findings = [
            {"name": v.get("name", ""), "severity": v.get("severity", "info")}
            for v in parsed_vulns
        ]
        for plugin_cls in plugin_manager.plugins.values():
            try:
                await plugin_cls().on_scan_complete(scan_id, all_findings, risk_level)
            except Exception as _pe:
                logger.debug("Plugin on_scan_complete error: %s", _pe)

        for vuln_data in parsed_vulns:
            if vuln_data.get("severity", "").lower() in ("critical", "high"):
                for plugin_cls in plugin_manager.plugins.values():
                    try:
                        await plugin_cls().on_critical_vuln(
                            scan_id, vuln_data.get("name", ""), vuln_data.get("severity", "")
                        )
                    except Exception as _pe:
                        logger.debug("Plugin on_critical_vuln error: %s", _pe)

        # Fire builtin plugin on_scan_complete + on_critical_vuln hooks
        try:
            from app.plugins.builtin import get_all_plugin_ids as _bpids3
            from app.services.plugin_config_service import get_plugin_config_row as _brow3, load_plugin_instance as _binst3
            from app.core.database import async_session as _async_session3
            async with _async_session3() as _bdb3:
                _enabled_instances = []
                for _bpid3 in _bpids3():
                    _brow3v = await _brow3(_bdb3, _bpid3)
                    if _brow3v and _brow3v.enabled:
                        _binstv3 = _binst3(_bpid3, _brow3v)
                        if _binstv3:
                            _enabled_instances.append((_bpid3, _binstv3, _brow3v))

                for (_bpid3, _binstv3, _brow3v) in _enabled_instances:
                    try:
                        await _binstv3.on_scan_complete(scan_id, all_findings, risk_level)
                    except Exception as _bpe3:
                        logger.debug("Builtin plugin %s on_scan_complete error: %s", _bpid3, _bpe3)

                for vuln_data in parsed_vulns:
                    if vuln_data.get("severity", "").lower() in ("critical", "high"):
                        for (_bpid3, _binstv3, _brow3v) in _enabled_instances:
                            try:
                                await _binstv3.on_critical_vuln(
                                    scan_id, vuln_data.get("vuln_name", ""), vuln_data.get("severity", "")
                                )
                            except Exception as _bpe3b:
                                logger.debug("Builtin plugin %s on_critical_vuln error: %s", _bpid3, _bpe3b)

                # Update trigger counts and timestamps
                for (_bpid3, _binstv3, _brow3v) in _enabled_instances:
                    _brow3v.trigger_count = (_brow3v.trigger_count or 0) + 1
                    _brow3v.last_triggered_at = datetime.now(timezone.utc)
                await _bdb3.commit()

        except Exception as _buite3:
            logger.debug("Builtin plugin scan_complete batch error: %s", _buite3)

        # Dispatch enterprise notifications (email + webhook adapters)
        user_id_str = str(scan.initiated_by) if hasattr(scan, "initiated_by") else None
        try:
            if user_id_str:
                from app.services.notification_delivery_service import notification_delivery_service
                await notification_delivery_service.dispatch_scan_notifications(
                    db=db,
                    user_id=user_id_str,
                    target=target,
                    risk_level=risk_level,
                    vulnerabilities=parsed_vulns,
                    scan_id=scan_id,
                )
        except Exception as _de:
            logger.debug("Notification dispatch error: %s", _de)

        # Create in-app notifications
        try:
            from app.models.notification import Notification as _Notif
            user_id_for_notif = getattr(scan, "initiated_by", None)
            if user_id_for_notif:
                # Scan completed notification
                db.add(_Notif(
                    user_id=user_id_for_notif,
                    type="scan_complete",
                    title="Scan Completed",
                    message=f"Scan of {target} finished. Risk: {risk_level}. Found {len(parsed_vulns)} vulnerabilities.",
                    resource_type="scan",
                    resource_id=scan_id,
                ))
                # Critical vuln notifications
                for _vd in parsed_vulns:
                    if _vd.get("severity", "").lower() in ("critical", "high"):
                        db.add(_Notif(
                            user_id=user_id_for_notif,
                            type="critical_vuln",
                            title=f"{_vd.get('severity','').upper()} Vulnerability Found",
                            message=_vd.get("name", "Unknown vulnerability"),
                            resource_type="scan",
                            resource_id=scan_id,
                        ))
                await db.commit()
        except Exception as _ne:
            logger.debug("Notification creation error: %s", _ne)

        return {
            "scan_id": scan_id,
            "status": "completed",
            "risk_level": risk_level,
            "vulnerabilities": len(parsed_vulns),
        }


# ─── ARQ Pool Factory ─────────────────────────────────────────

async def get_arq_pool():
    """Create and return an ARQ connection pool."""
    return await create_pool(RedisSettings.from_dsn(settings.REDIS_URL or ""))


# ─── Cron: Tick Scheduled Scans ───────────────────────────────

async def run_scheduled_scans(ctx):
    """
    ARQ cron task — runs every minute.
    Finds active ScanSchedules whose next_run_at <= now, enqueues a scan,
    then advances next_run_at to the following cron slot.
    """
    from croniter import croniter
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from sqlalchemy import select
    from app.core.database import engine
    from app.models.scan_schedule import ScanSchedule
    from app.models.scan import Scan, ScanStatus, ScanType

    async_session = async_sessionmaker(engine, expire_on_commit=False)
    now = datetime.now(timezone.utc)

    async with async_session() as db:
        result = await db.execute(
            select(ScanSchedule).where(
                ScanSchedule.is_active == True,
                ScanSchedule.next_run_at <= now,
            )
        )
        schedules = result.scalars().all()
        pool = await get_arq_pool()
        import random
        from datetime import timedelta as _timedelta
        # Spread a burst of same-slot schedules over a window so they don't all
        # hit the queue/tools at once (perf #5). Window scales with count, capped.
        _jitter_window = min(len(schedules) * 5, 120)
        for schedule in schedules:
            scan = Scan(
                project_id=schedule.project_id,
                initiated_by=schedule.created_by,
                target=schedule.target,
                tool_config=schedule.tool_config,
                scan_type=ScanType.FULL,
                status=ScanStatus.PENDING,
            )
            db.add(scan)
            await db.flush()
            _defer = _timedelta(seconds=random.uniform(0, _jitter_window)) if _jitter_window else None
            await pool.enqueue_job("run_scan", str(scan.id), _defer_by=_defer)
            schedule.last_run_at = now
            schedule.last_scan_id = scan.id
            it = croniter(schedule.cron_expression, now)
            schedule.next_run_at = it.get_next(datetime)
        await db.commit()
        await pool.aclose()


async def run_scan_ai_analysis(ctx, scan_id: str, provider_str: str | None = None, model: str | None = None, remote_url: str | None = None):
    """Run manual AI analysis for an existing scan using selected provider/model."""
    import time
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from app.core.database import engine
    from app.models.scan import Scan, ScanStatus
    from app.models.ai_analysis import AIAnalysis
    from app.models.vuln_comment import VulnComment  # noqa: F401 — ensures mapper registered before Vulnerability
    from app.models.vulnerability import Vulnerability, Severity
    from app.models.fix import Fix, FixSource, FixPriority
    from app.models.llm_config import LLMProvider
    from app.models.prompt_template import PromptTemplate
    from app.services.llm_service import llm_service, SYSTEM_PROMPT
    from app.services.rag_service import rag_service
    from app.services.settings_service import SettingsService

    async_session = async_sessionmaker(engine, expire_on_commit=False)

    async with async_session() as db:
        scan_result = await db.execute(
            select(Scan).where(Scan.id == uuid.UUID(scan_id)).options(selectinload(Scan.tool_results))
        )
        scan = scan_result.scalar_one_or_none()
        if not scan:
            logger.error(f"Manual AI analysis: scan not found {scan_id}")
            return {"scan_id": scan_id, "status": "failed", "error": "Scan not found"}

        if not scan.tool_results:
            return {"scan_id": scan_id, "status": "failed", "error": "No tool results available"}

        target = scan.target
        scan.status = ScanStatus.ANALYZING
        await db.commit()
        await _notify_ws(scan_id, "status", {"status": "analyzing", "message": "Manual AI analysis started..."})

        tool_output_text = "\n\n".join(
            f"=== {tr.tool_name.upper()} ===\n{tr.raw_output or ''}"
            for tr in scan.tool_results
        )

        active_system_prompt = SYSTEM_PROMPT
        try:
            pt_result = await db.execute(
                select(PromptTemplate).where(
                    PromptTemplate.is_active == True,
                    PromptTemplate.is_default == True,
                    (PromptTemplate.scan_type == str(scan.scan_type)) |
                    (PromptTemplate.scan_type == None),
                ).order_by(PromptTemplate.scan_type.desc())
            )
            pt = pt_result.scalars().first()
            if pt:
                # Prepend methodology prompt — base SYSTEM_PROMPT (MCP tool tags,
                # [SEARCH:] rules, workflow JSON format) is always appended beneath.
                active_system_prompt = pt.system_prompt + "\n\n" + SYSTEM_PROMPT
        except Exception as e:
            logger.debug(f"Could not load custom system prompt: {e}")

        rag_context_block = ""
        try:
            similar = await rag_service.find_similar(db, f"Target: {target}\n{tool_output_text[:500]}", limit=5)
            if similar:
                rag_context_block = "\n\nSIMILAR PAST FINDINGS (for reference):\n" + "\n---\n".join(similar)
        except Exception as e:
            logger.debug(f"RAG similarity search failed: {e}")

        llm_user_prompt = f"""═══════════════════════════════════════════════════════════════════
TARGET: {target}
═══════════════════════════════════════════════════════════════════

{tool_output_text}{rag_context_block}

═══════════════════════════════════════════════════════════════════
Analyze the above reconnaissance data. For EVERY vulnerability found,
output it using EXACTLY this format (one per line block):

VULN: <name> | SEVERITY: <critical|high|medium|low> | PORT: <port> | SERVICE: <service>
DESC: <one-line description>
FIX: <one-line recommendation>

End your response with:
RISK_LEVEL: <CRITICAL|HIGH|MEDIUM|LOW>
SUMMARY: <2-3 sentence overall assessment>
═══════════════════════════════════════════════════════════════════
"""
        llm_prompt = f"{active_system_prompt}\n\n{llm_user_prompt}"

        settings_service = SettingsService()
        selected_provider = provider_str or "ollama_remote"
        selected_model = model
        selected_remote_url = remote_url
        selected_api_key: str | None = None

        if selected_provider == "ollama_remote":
            if not selected_model:
                selected_model = await settings_service.get_ollama_remote_model(db) or "qwen2.5:7b"
            if not selected_remote_url:
                selected_remote_url = await settings_service.get_ollama_remote_url(db)
        else:
            # Resolve the admin-saved API key/URL (Admin -> AI providers -> Add LLM Provider) for this provider,
            # and its default model, instead of falling back to the Ollama default model — the previous behaviour
            # used settings.OLLAMA_DEFAULT_MODEL even for e.g. OpenAI, which is a different provider's model name.
            from app.core.llm_providers import resolve_llm_credentials
            selected_api_key, _resolved_api_url = await resolve_llm_credentials(db, selected_provider)
            if not selected_remote_url:
                selected_remote_url = _resolved_api_url
            if not selected_model:
                from sqlalchemy import select as _select
                from app.models.llm_config import LLMConfig as _LLMConfig
                _default_cfg = (
                    await db.execute(
                        _select(_LLMConfig)
                        .where(_LLMConfig.is_active == True, _LLMConfig.provider == selected_provider)  # noqa: E712
                        .order_by(_LLMConfig.is_default.desc(), _LLMConfig.created_at.asc())
                    )
                ).scalars().first()
                selected_model = _default_cfg.model_name if _default_cfg else (settings.OLLAMA_DEFAULT_MODEL or "qwen2.5:7b")

        llm_response = ""
        llm_start = time.time()
        llm_metadata = {
            "source": "unknown",
            "provider": selected_provider,
            "model": selected_model,
            "remote_url": selected_remote_url,
            "manual": True,
        }

        try:
            from app.core.llm_providers import normalize_provider
            provider = LLMProvider(normalize_provider(selected_provider))
        except ValueError:
            provider = LLMProvider.OLLAMA_REMOTE

        await _notify_ws(scan_id, "status", {
            "status": "analyzing",
            "message": f"Manual AI analysis with {provider.value} ({selected_model})",
            "llm_source": "ollama" if provider == LLMProvider.OLLAMA_REMOTE else "api",
            "llm_provider": provider.value,
            "llm_model": selected_model,
            "llm_remote_url": selected_remote_url,
        })

        try:
            async for token in llm_service.chat(
                llm_user_prompt,
                provider=provider,
                model=selected_model,
                remote_url=selected_remote_url,
                system_prompt=active_system_prompt,
                api_key=selected_api_key,
            ):
                llm_response += token
                await _notify_ws(scan_id, "llm_token", {"token": token})
        except Exception as e:
            logger.error(f"Manual AI analysis failed for scan {scan_id}: {type(e).__name__}: {e!r}")
            llm_response = f"[!] LLM analysis failed: {type(e).__name__}: {str(e)[:200]}"
            llm_metadata["source"] = "failed"

        llm_duration_ms = int((time.time() - llm_start) * 1000)
        parsed_vulns = llm_service.parse_vulnerabilities(llm_response)
        parsed_exploits = llm_service.parse_exploits(llm_response)
        cvss_ceiling = _extract_cvss_max_from_text(tool_output_text)
        risk_level = _reconcile_risk_level(
            llm_service.parse_risk_level(llm_response), parsed_vulns, cvss_max=cvss_ceiling
        )

        ai_analysis = AIAnalysis(
            scan_id=uuid.UUID(scan_id),
            prompt=llm_prompt[:5000],
            response=llm_response,
            risk_level=risk_level,
            parsed_data={
                "vulnerabilities": parsed_vulns,
                "exploits": parsed_exploits,
                "llm_metadata": llm_metadata,
            },
            duration_ms=llm_duration_ms,
        )
        db.add(ai_analysis)

        # Persist parsed vulnerabilities so the global Vulnerabilities page reflects manual AI runs.
        import hashlib as _hashlib
        from sqlalchemy import select as _select

        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }

        existing_q = await db.execute(
            _select(Vulnerability.fingerprint).where(Vulnerability.scan_id == uuid.UUID(scan_id))
        )
        existing_fps = {fp for fp in existing_q.scalars().all() if fp}

        owasp_map = {
            "injection": "A03:2021 - Injection",
            "sql": "A03:2021 - Injection",
            "xss": "A03:2021 - Injection",
            "auth": "A07:2021 - Identification and Authentication Failures",
            "broken auth": "A07:2021 - Identification and Authentication Failures",
            "sensitive data": "A02:2021 - Cryptographic Failures",
            "crypto": "A02:2021 - Cryptographic Failures",
            "ssrf": "A10:2021 - Server-Side Request Forgery",
            "xxe": "A05:2021 - Security Misconfiguration",
            "misconfigur": "A05:2021 - Security Misconfiguration",
            "deseri": "A08:2021 - Software and Data Integrity Failures",
            "component": "A06:2021 - Vulnerable and Outdated Components",
            "logging": "A09:2021 - Security Logging and Monitoring Failures",
            "access control": "A01:2021 - Broken Access Control",
        }

        for vuln_data in parsed_vulns:
            vuln_name = str(vuln_data.get("vuln_name") or "Unknown").strip()[:500]
            port = str(vuln_data.get("port") or "").strip()[:20] or None
            service_raw = str(vuln_data.get("service") or "").strip()
            description_raw = str(vuln_data.get("description") or "").strip()

            # Guard: LLM sometimes bleeds the description into the service field.
            # If service is implausibly long (>100 chars) it's not a real service name.
            if len(service_raw) > 100:
                # Rescue: if description is empty, move the overflow there
                if not description_raw:
                    description_raw = service_raw
                service_raw = service_raw[:100]
            service = service_raw[:200] or None

            raw_fp = f"{vuln_name.lower().strip()}:{port or ''}:{(service or '').lower().strip()}"
            fingerprint = _hashlib.sha256(raw_fp.encode()).hexdigest()
            if fingerprint in existing_fps:
                continue

            severity = severity_map.get(str(vuln_data.get("severity", "medium")).lower(), Severity.MEDIUM)
            name_lower = str(vuln_name).lower()
            owasp_cat = next((v for k, v in owasp_map.items() if k in name_lower), None)

            vuln = Vulnerability(
                scan_id=uuid.UUID(scan_id),
                vuln_name=vuln_name,
                severity=severity,
                port=port,
                service=service,
                description=description_raw or None,
                cve_id=str(vuln_data.get("cve_id") or "")[:20] or None,
                fingerprint=fingerprint,
                owasp_category=owasp_cat,
            )
            db.add(vuln)
            await db.flush()

            fix_text = str(vuln_data.get("fix") or "").strip()
            if fix_text:
                fix_priority = FixPriority.HIGH if severity in (Severity.CRITICAL, Severity.HIGH) else FixPriority.MEDIUM
                db.add(Fix(vuln_id=vuln.id, fix_text=fix_text, source=FixSource.AI, priority=fix_priority))

            existing_fps.add(fingerprint)

        # Same rule as the automatic path: if every tool this scan ran had already failed, a manual AI analysis run over that
        # data does not make the scan a success.
        _all_failed, _fail_reasons = _all_tools_failed(scan.tool_results)
        scan.completed_at = datetime.now(timezone.utc)
        scan.risk_level = risk_level
        if _all_failed:
            scan.status = ScanStatus.FAILED
            await db.commit()
            _err = "; ".join(_fail_reasons) or "every tool failed"
            await emit_scan_event(db, scan, "scan.failed", error=_err)
            await _notify_ws(scan_id, "status", {"status": "failed", "message": _err})
            return {"scan_id": scan_id, "status": "failed", "error": _err}
        scan.status = ScanStatus.COMPLETED
        await db.commit()
        await emit_scan_event(db, scan, "scan.completed")

        await _notify_ws(scan_id, "complete", {
            "status": "completed",
            "risk_level": risk_level,
            "vulnerability_count": len(parsed_vulns),
            "exploit_count": len(parsed_exploits),
            "message": f"Manual AI analysis complete. Risk: {risk_level}",
        })

        return {
            "scan_id": scan_id,
            "status": "completed",
            "risk_level": risk_level,
            "vulnerabilities": len(parsed_vulns),
        }


# ─── CVE Lite Advisory Sync ───────────────────────────────────

async def _sync_cve_lite_advisories(ctx: dict) -> None:
    """Daily cron: refresh the offline cve-lite advisory DB at /var/cve-lite/advisories.sqlite3."""
    import logging
    logger = logging.getLogger(__name__)
    logger.info("[cve_lite_sync] Starting daily advisory sync...")
    result = await _call_mcp_tool(
        MCP_URLS["cve_lite"],
        "cve_lite_advisories_sync",
        {
            "db_path": "/var/cve-lite/advisories.sqlite3",
            "ecosystems": ["npm", "PyPI", "Go", "Maven", "RubyGems", "NuGet", "Packagist"],
        },
        timeout=600,  # 10 min — first run downloads full OSV dataset
    )
    if result.get("success"):
        logger.info("[cve_lite_sync] Advisory sync completed successfully.")
    else:
        logger.warning("[cve_lite_sync] Advisory sync failed: %s", result.get("output", "unknown error"))


class WorkerSettings:
    """ARQ worker configuration. Run with: python -m arq app.tasks.scan_worker.WorkerSettings"""
    from arq.cron import cron as _cron
    from app.tasks.backup_worker import backup_database as _backup_database
    functions = [run_scan, run_scan_ai_analysis]
    cron_jobs = [
        _cron(run_scheduled_scans, minute={0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55}),  # every 5 min
        _cron(_backup_database, hour={2}, minute={0}),  # daily at 02:00 UTC
        _cron(_sync_cve_lite_advisories, hour={1}, minute={0}),  # daily at 01:00 UTC
    ]
    redis_settings = RedisSettings.from_dsn(settings.REDIS_URL or "")
    # Concurrency + timeout are env-tunable (perf #5). With multiple worker
    # replicas (compose: worker-scale service) the effective concurrency is
    # max_jobs × replicas, all pulling from the same Redis queue.
    max_jobs = int(os.environ.get("ARQ_MAX_JOBS", "10"))
    job_timeout = int(os.environ.get("ARQ_JOB_TIMEOUT", "3600"))  # per-scan ceiling
    keep_result = 3600


class WorkerSettingsNoCron:
    """Scaling worker — processes the SAME job queue as WorkerSettings but runs
    NO cron jobs (perf #5). Scheduled scans / backups / CVE sync must fire once,
    so only the primary `worker` service owns the cron_jobs; additional replicas
    use this class so they add scan throughput without duplicating cron work.

    Run with: python -m arq app.tasks.scan_worker.WorkerSettingsNoCron
    """
    functions = [run_scan, run_scan_ai_analysis]
    cron_jobs = []  # intentionally empty — cron only runs on the primary worker
    redis_settings = RedisSettings.from_dsn(settings.REDIS_URL or "")
    max_jobs = int(os.environ.get("ARQ_MAX_JOBS", "10"))
    job_timeout = int(os.environ.get("ARQ_JOB_TIMEOUT", "3600"))
    keep_result = 3600
