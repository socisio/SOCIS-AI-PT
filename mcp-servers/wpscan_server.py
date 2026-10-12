#!/usr/bin/env python3
"""
SOCIS-AI-PT — WPScan MCP Server (HTTP transport)
WordPress vulnerability scanner

Provides:
1. wp_scan          - Full WordPress scan
2. wp_enum_users    - Enumerate WordPress users
3. wp_enum_plugins  - Enumerate installed plugins and check for vulnerabilities
4. wp_enum_themes   - Enumerate installed themes and check for vulnerabilities
"""

import json
import asyncio
import re
import os
import logging
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from mcp_auth import verify_mcp_auth, mcp_auth_error

# ───────────────────────────────────────────────────────────
# CONFIGURATION
# ───────────────────────────────────────────────────────────

TOOL_NAME = "wpscan"
MCP_PORT = 8119
MCP_VERSION = "1.0"
SERVER_NAME = f"{TOOL_NAME}-mcp"

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# Optional WPVulnDB API token — raises scan result quality significantly
WPSCAN_API_TOKEN = os.environ.get("WPSCAN_API_TOKEN", "")

# Wordlist directory (safe, container-side only)
WORDLIST_DIR = os.environ.get("WORDLIST_DIR", "/usr/share/wordlists")

# ───────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ───────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "wp_scan",
        "description": "Run a full WPScan against a WordPress site. Detects version, vulnerable plugins/themes, user accounts, and configuration issues.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "WordPress site URL (e.g., https://example.com)"
                },
                "enumerate": {
                    "type": "string",
                    "description": "What to enumerate: u=users, p=plugins, t=themes, vp=vulnerable plugins, vt=vulnerable themes, ap=all plugins, at=all themes. Combine with commas: u,vp,vt",
                    "default": "u,vp,vt"
                },
                "api_token": {
                    "type": "string",
                    "description": "WPVulnDB API token (optional — increases vuln data quality)"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Scan timeout in seconds",
                    "default": 300
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "wp_enum_users",
        "description": "Enumerate WordPress user accounts via WPScan — checks author pages, REST API, XML-RPC, and login hints.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "WordPress site URL"
                },
                "max_users": {
                    "type": "integer",
                    "description": "Maximum number of user IDs to probe",
                    "default": 25
                },
                "passwords": {
                    "type": "string",
                    "description": "Built-in wordlist name for password brute-force (passwords, common, big). Leave empty to enumerate only without brute-force."
                },
                "usernames": {
                    "type": "string",
                    "description": "Built-in wordlist name for username enumeration (usernames, common). Leave empty to auto-detect via WordPress API."
                },
                "timeout": {
                    "type": "integer",
                    "description": "Scan timeout in seconds",
                    "default": 120
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "wp_enum_plugins",
        "description": "Enumerate installed WordPress plugins and check for known vulnerabilities using WPScan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "WordPress site URL"
                },
                "detection_mode": {
                    "type": "string",
                    "description": "Plugin detection mode: passive, aggressive, or mixed",
                    "default": "mixed",
                    "enum": ["passive", "aggressive", "mixed"]
                },
                "api_token": {
                    "type": "string",
                    "description": "WPVulnDB API token (optional)"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Scan timeout in seconds",
                    "default": 300
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "wp_enum_themes",
        "description": "Enumerate installed WordPress themes and check for known vulnerabilities using WPScan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "WordPress site URL"
                },
                "detection_mode": {
                    "type": "string",
                    "description": "Theme detection mode: passive, aggressive, or mixed",
                    "default": "mixed",
                    "enum": ["passive", "aggressive", "mixed"]
                },
                "timeout": {
                    "type": "integer",
                    "description": "Scan timeout in seconds",
                    "default": 120
                }
            },
            "required": ["url"]
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
                if tool_name == "wp_scan":
                    result = await handle_wp_scan(arguments)
                elif tool_name == "wp_enum_users":
                    result = await handle_wp_enum_users(arguments)
                elif tool_name == "wp_enum_plugins":
                    result = await handle_wp_enum_plugins(arguments)
                elif tool_name == "wp_enum_themes":
                    result = await handle_wp_enum_themes(arguments)
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

_URL_RE = re.compile(r'^https?://[a-zA-Z0-9.\-_:/?=&%#+@]+$')
_ENUM_RE = re.compile(r'^[a-zA-Z,]+$')
_DETECT_RE = re.compile(r'^(passive|aggressive|mixed)$')


def _validate_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("'url' parameter is required")
    if not _URL_RE.match(url):
        raise ValueError(f"Invalid URL format: {url!r}. Must start with http:// or https://")
    from mcp_auth import validate_url_target  # SSRF guard (fix H-5)
    validate_url_target(url)
    return url


def _get_token(args: dict) -> str:
    """Return API token from args (preferred) or environment variable."""
    return args.get("api_token", "").strip() or WPSCAN_API_TOKEN


def _get_wordlist(name: str) -> str:
    """Resolve a built-in wordlist name to its full path.
    Only bare filenames (no path separators, no leading dots) are allowed;
    this prevents any path-traversal attacks.
    """
    name = name.strip()
    if not name:
        return ""
    if "/" in name or ".." in name or name.startswith("."):
        raise ValueError(f"Invalid wordlist name: {name!r}")
    # Append .txt extension if not already present
    filename = name if name.endswith(".txt") else f"{name}.txt"
    full_path = os.path.join(WORDLIST_DIR, filename)
    if not os.path.isfile(full_path):
        raise ValueError(f"Wordlist not found: {filename!r} (looked in {WORDLIST_DIR})")
    return full_path


async def _run_wpscan(cmd: list[str], timeout: int) -> str:
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
        err = stderr.decode(errors="replace").strip()
        # WPScan writes progress to stderr; stdout has the actual findings
        if not output:
            output = err
        return output or "[No output from wpscan]"
    except asyncio.TimeoutError:
        raise asyncio.TimeoutError(f"WPScan timed out after {timeout}s")
    except FileNotFoundError:
        raise RuntimeError("wpscan is not installed. Install with: gem install wpscan")


# ───────────────────────────────────────────────────────────
# TOOL IMPLEMENTATIONS
# ───────────────────────────────────────────────────────────

async def handle_wp_scan(args: dict) -> dict:
    url = _validate_url(args.get("url", ""))
    enumerate = args.get("enumerate", "u,vp,vt").strip()
    if not _ENUM_RE.match(enumerate):
        raise ValueError(f"Invalid enumerate value: {enumerate!r}")
    timeout = min(int(args.get("timeout", 300)), 600)
    token = _get_token(args)

    cmd = ["wpscan", "--url", url, "--enumerate", enumerate, "--no-banner", "--format", "cli"]
    if token:
        cmd += ["--api-token", token]

    log.info(f"[wp_scan] url={url} enumerate={enumerate} token={'yes' if token else 'no'}")
    output = await _run_wpscan(cmd, timeout)

    return {
        "tool": "wp_scan",
        "url": url,
        "enumerate": enumerate,
        "api_token_used": bool(token),
        "output": output,
        "success": True,
    }


async def handle_wp_enum_users(args: dict) -> dict:
    url = _validate_url(args.get("url", ""))
    max_users = min(int(args.get("max_users", 25)), 100)
    timeout = min(int(args.get("timeout", 120)), 300)
    passwords_name = args.get("passwords", "").strip()
    usernames_name = args.get("usernames", "").strip()

    # Resolve & validate wordlist paths if provided (raises ValueError on bad input)
    wordlist_path = _get_wordlist(passwords_name) if passwords_name else ""
    userlist_path = _get_wordlist(usernames_name) if usernames_name else ""

    # If a password wordlist is requested, allow more time for brute-force
    if wordlist_path:
        timeout = min(timeout + 300, 600)

    cmd = [
        "wpscan", "--url", url,
        "--enumerate", "u",
        "--users-range", f"1-{max_users}",
        "--no-banner", "--format", "cli",
    ]
    if userlist_path:
        cmd += ["--usernames", userlist_path]
    if wordlist_path:
        cmd += ["--password-attack", "wp-login", "--passwords", wordlist_path]

    log.info(f"[wp_enum_users] url={url} max_users={max_users} userlist={'yes' if userlist_path else 'no'} wordlist={'yes' if wordlist_path else 'no'}")
    output = await _run_wpscan(cmd, timeout)

    return {
        "tool": "wp_enum_users",
        "url": url,
        "max_users": max_users,
        "usernames_wordlist": usernames_name or None,
        "passwords_wordlist": passwords_name or None,
        "output": output,
        "success": True,
    }


async def handle_wp_enum_plugins(args: dict) -> dict:
    url = _validate_url(args.get("url", ""))
    detection_mode = args.get("detection_mode", "mixed").strip()
    if not _DETECT_RE.match(detection_mode):
        raise ValueError(f"Invalid detection_mode: {detection_mode!r}")
    timeout = min(int(args.get("timeout", 300)), 600)
    token = _get_token(args)

    cmd = [
        "wpscan", "--url", url,
        "--enumerate", "ap",
        "--plugins-detection", detection_mode,
        "--plugins-version-detection", detection_mode,
        "--no-banner", "--format", "cli",
    ]
    if token:
        cmd += ["--api-token", token]

    log.info(f"[wp_enum_plugins] url={url} mode={detection_mode}")
    output = await _run_wpscan(cmd, timeout)

    return {
        "tool": "wp_enum_plugins",
        "url": url,
        "detection_mode": detection_mode,
        "api_token_used": bool(token),
        "output": output,
        "success": True,
    }


async def handle_wp_enum_themes(args: dict) -> dict:
    url = _validate_url(args.get("url", ""))
    detection_mode = args.get("detection_mode", "mixed").strip()
    if not _DETECT_RE.match(detection_mode):
        raise ValueError(f"Invalid detection_mode: {detection_mode!r}")
    timeout = min(int(args.get("timeout", 120)), 300)

    cmd = [
        "wpscan", "--url", url,
        "--enumerate", "at",
        "--themes-detection", detection_mode,
        "--no-banner", "--format", "cli",
    ]

    log.info(f"[wp_enum_themes] url={url} mode={detection_mode}")
    output = await _run_wpscan(cmd, timeout)

    return {
        "tool": "wp_enum_themes",
        "url": url,
        "detection_mode": detection_mode,
        "output": output,
        "success": True,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=MCP_PORT, log_level="info")
