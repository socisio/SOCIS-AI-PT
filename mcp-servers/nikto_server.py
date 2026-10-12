#!/usr/bin/env python3
"""
SOCIS-AI-PT — Nikto MCP Server (HTTP transport)
Web server vulnerability scanner

Provides:
1. nikto_scan     - Full Nikto scan against a web server
2. nikto_tuning   - Targeted scan using Nikto tuning options
3. nikto_ssl_only - SSL/TLS-focused Nikto scan
"""

import json
import asyncio
import re
import logging
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from mcp_auth import verify_mcp_auth, mcp_auth_error

# ───────────────────────────────────────────────────────────
# CONFIGURATION
# ───────────────────────────────────────────────────────────

TOOL_NAME = "nikto"
MCP_PORT = 8117
MCP_VERSION = "1.0"
SERVER_NAME = f"{TOOL_NAME}-mcp"

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ───────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ───────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "nikto_scan",
        "description": "Run a full Nikto web server vulnerability scan. Detects outdated software, dangerous files, misconfigurations, and known CVEs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or host (e.g., http://example.com or 192.168.1.1)"},
                "port":   {"type": "integer", "description": "Port to scan (default: 80 for HTTP, 443 for HTTPS)", "default": 80},
                "timeout": {"type": "integer", "description": "Scan timeout in seconds", "default": 300},
                "useragent": {"type": "string", "description": "Override User-Agent string"},
                "proxy":    {"type": "string", "description": "HTTP proxy URL e.g. http://127.0.0.1:8080"},
                "auth":     {"type": "string", "description": "HTTP Basic auth credentials: user:password"},
                "maxtime":  {"type": "string", "description": "Maximum scan time e.g. 60s, 5m, 1h"},
                "evasion":  {"type": "string", "description": "Evasion technique codes (1-9): 1=Random URI encoding, 2=Directory self-reference, 3=Premature URL ending, 4=Prepend long random string, 5=Fake parameter, 6=TAB as request spacer, 7=Change case of URL, 8=Use Windows path separator, 9=Session splicing"},
            },
            "required": ["target"]
        }
    },
    {
        "name": "nikto_tuning",
        "description": "Run a targeted Nikto scan using tuning options to focus on specific vulnerability categories.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or host"},
                "tuning": {"type": "string", "description": "Nikto tuning codes: 1=Interesting File/Seen in logs, 2=Misconfiguration, 3=Information Disclosure, 4=Injection(XSS/Script/HTML), 5=Remote File Retrieval, 6=Denial of Service, 7=Remote File Retrieval(Server), 8=Command Execution/Remote Shell, 9=SQL Injection, 0=File Upload, a=Authentication Bypass, b=Software Identification, c=Remote Source Inclusion, x=Reverse Tuning (exclude). Combine: e.g. 1234", "default": "1234"},
                "port":    {"type": "integer", "description": "Port to scan", "default": 80},
                "timeout": {"type": "integer", "description": "Scan timeout in seconds", "default": 300},
                "useragent": {"type": "string", "description": "Override User-Agent string"},
                "proxy":    {"type": "string", "description": "HTTP proxy URL"},
                "auth":     {"type": "string", "description": "HTTP Basic auth: user:password"},
                "maxtime":  {"type": "string", "description": "Maximum scan time e.g. 60s, 5m"},
                "evasion":  {"type": "string", "description": "Evasion technique codes 1-9"},
            },
            "required": ["target"]
        }
    },
    {
        "name": "nikto_ssl_only",
        "description": "Run Nikto focused on SSL/TLS issues — expired certs, weak ciphers, insecure redirects, HSTS issues.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target hostname or URL (HTTPS)"},
                "port": {
                    "type": "integer",
                    "description": "HTTPS port",
                    "default": 443
                },
                "timeout": {
                    "type": "integer",
                    "description": "Scan timeout in seconds",
                    "default": 180
                },
                # The handler (handle_nikto_ssl_only -> _build_nikto_extra_args) already reads and uses all four of these;
                # they were missing from this tool's own schema, so nothing advertised them as real options.
                "useragent": {"type": "string", "description": "Override User-Agent string"},
                "proxy":     {"type": "string", "description": "HTTP proxy URL e.g. http://127.0.0.1:8080"},
                "auth":      {"type": "string", "description": "HTTP Basic auth credentials: user:password"},
                "maxtime":   {"type": "string", "description": "Maximum scan time e.g. 60s, 5m, 1h"},
                "evasion":   {"type": "string", "description": "Evasion technique codes (1-9)"}
            },
            "required": ["target"]
        }
    },
]

# FastAPI app
app = FastAPI(title=f"SOCIS {TOOL_NAME} MCP Server", docs_url=None)

# ───────────────────────────────────────────────────────────
# MCP PROTOCOL HANDLERS
# ───────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    return {"status": "healthy", "server": SERVER_NAME, "version": MCP_VERSION}


@app.post("/mcp")
async def handle_mcp_request(request: Request):
    if not verify_mcp_auth(request):
        return mcp_auth_error()
    try:
        data = await request.json()
        req_id = data.get("id")
        method = data.get("method")

        log.info(f"[MCP] Received request: {method}")

        if method == "tools/list":
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})

        elif method == "tools/call":
            tool_name = data.get("params", {}).get("name")
            arguments = data.get("params", {}).get("arguments", {})

            log.info(f"[MCP] Executing tool: {tool_name}")

            if not any(t["name"] == tool_name for t in TOOLS):
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": f"Unknown tool: {tool_name}"}},
                    status_code=400
                )

            try:
                if tool_name == "nikto_scan":
                    result = await handle_nikto_scan(arguments)
                elif tool_name == "nikto_tuning":
                    result = await handle_nikto_tuning(arguments)
                elif tool_name == "nikto_ssl_only":
                    result = await handle_nikto_ssl_only(arguments)
                else:
                    raise ValueError(f"No handler for tool: {tool_name}")

                return JSONResponse({
                    "jsonrpc": "2.0", "id": req_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}
                })

            except ValueError as e:
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}},
                    status_code=400
                )
            except asyncio.TimeoutError:
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": "Tool execution timeout"}},
                    status_code=504
                )
            except Exception as e:
                log.error(f"[MCP] Tool error: {e}")
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": str(e)}},
                    status_code=500
                )

        else:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}},
                status_code=404
            )

    except json.JSONDecodeError:
        return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}, status_code=400)
    except Exception as e:
        log.error(f"[MCP] Unexpected error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ───────────────────────────────────────────────────────────
# INPUT VALIDATION
# ───────────────────────────────────────────────────────────

_TARGET_RE = re.compile(r'^[a-zA-Z0-9.\-_:/?=&%#+@]+$')
_TUNING_RE = re.compile(r'^[0-9abcx]+$')


def _validate_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("'target' parameter is required")
    if not _TARGET_RE.match(target):
        raise ValueError(f"Invalid target format: {target}")
    # SSRF / internal-scope guard (fix H-5).
    from mcp_auth import validate_scan_target
    validate_scan_target(target)
    return target


def _build_nikto_target(target: str, port: int) -> tuple[str, list[str]]:
    """Return (display_target, nikto_cmd_args_list). Nikto uses -h for host and -p for port.

    When target is a full URL (http:// or https://), nikto embeds the port from the URL itself.
    Passing -p alongside a full URI causes: 'The -port option cannot be used with a full URI'.
    """
    if target.startswith("http://") or target.startswith("https://"):
        # Full URL — let nikto derive the port from the URL; do NOT pass -p
        return target, ["-h", target, "-Format", "txt", "-nointeractive"]
    else:
        # Bare hostname/IP — port must be specified explicitly
        return target, ["-h", target, "-p", str(port), "-Format", "txt", "-nointeractive"]


# ───────────────────────────────────────────────────────────
# TOOL IMPLEMENTATIONS
# ───────────────────────────────────────────────────────────

async def _run_nikto(cmd: list[str], timeout: int) -> str:
    try:
        # Bound concurrent scanner processes per server (perf #3).
        from mcp_auth import scan_slot
        async with scan_slot():
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout.decode(errors="replace").strip()
        if not output and stderr:
            output = stderr.decode(errors="replace").strip()
        return output or "[No output from nikto]"
    except asyncio.TimeoutError:
        raise asyncio.TimeoutError(f"Nikto scan timed out after {timeout}s")
    except FileNotFoundError:
        raise RuntimeError("nikto is not installed. Install with: apt-get install -y nikto")


_EVASION_RE = re.compile(r'^[1-9]+$')


def _build_nikto_extra_args(args: dict) -> list[str]:
    """Build extra nikto CLI args from optional config fields."""
    extra: list[str] = []
    useragent = str(args.get("useragent", "") or "").strip()
    proxy = str(args.get("proxy", "") or "").strip()
    auth = str(args.get("auth", "") or "").strip()
    maxtime = str(args.get("maxtime", "") or "").strip()
    evasion = str(args.get("evasion", "") or "").strip()
    if useragent:
        extra += ["-useragent", useragent]
    if proxy:
        extra += ["-useproxy", "-proxy", proxy]
    if auth and ":" in auth:
        extra += ["-id", auth]
    if maxtime:
        extra += ["-maxtime", maxtime]
    if evasion and _EVASION_RE.match(evasion):
        extra += ["-evasion", evasion]
    return extra


async def handle_nikto_scan(args: dict) -> dict:
    target = _validate_target(args.get("target", ""))
    port = int(args.get("port", 80))
    timeout = min(int(args.get("timeout", 300)), 600)
    extra = _build_nikto_extra_args(args)

    _, base_args = _build_nikto_target(target, port)
    cmd = ["nikto"] + base_args + extra

    log.info(f"[nikto_scan] target={target} port={port}")
    output = await _run_nikto(cmd, timeout)

    return {
        "tool": "nikto_scan",
        "target": target,
        "port": port,
        "output": output,
        "success": True,
    }


async def handle_nikto_tuning(args: dict) -> dict:
    target = _validate_target(args.get("target", ""))
    port = int(args.get("port", 80))
    timeout = min(int(args.get("timeout", 300)), 600)
    tuning = args.get("tuning", "1234").strip()
    extra = _build_nikto_extra_args(args)

    if not _TUNING_RE.match(tuning):
        raise ValueError(f"Invalid tuning value '{tuning}'. Use digits 0-9 and letters a, b, c, x only.")

    _, base_args = _build_nikto_target(target, port)
    cmd = ["nikto"] + base_args + ["-Tuning", tuning] + extra

    log.info(f"[nikto_tuning] target={target} tuning={tuning}")
    output = await _run_nikto(cmd, timeout)

    return {
        "tool": "nikto_tuning",
        "target": target,
        "port": port,
        "tuning": tuning,
        "output": output,
        "success": True,
    }


async def handle_nikto_ssl_only(args: dict) -> dict:
    target = _validate_target(args.get("target", ""))
    port = int(args.get("port", 443))
    timeout = min(int(args.get("timeout", 180)), 400)
    extra = _build_nikto_extra_args(args)

    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    cmd = ["nikto", "-h", host, "-p", str(port), "-ssl", "-Format", "txt", "-nointeractive"] + extra

    log.info(f"[nikto_ssl_only] host={host} port={port}")
    output = await _run_nikto(cmd, timeout)

    return {
        "tool": "nikto_ssl_only",
        "target": host,
        "port": port,
        "output": output,
        "success": True,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=MCP_PORT, log_level="info")
