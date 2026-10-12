#!/usr/bin/env python3
"""
SOCIS-AI-PT — Gobuster MCP Server (HTTP transport)
Directory, DNS, and vhost brute-force enumeration

Provides:
1. gobuster_dir   - Directory/file brute-force on a web server
2. gobuster_dns   - DNS subdomain enumeration
3. gobuster_vhost - Virtual host enumeration
4. gobuster_fuzz  - Generic fuzzing with FUZZ placeholder
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

TOOL_NAME = "gobuster"
MCP_PORT = 8121
MCP_VERSION = "1.0"
SERVER_NAME = f"{TOOL_NAME}-mcp"

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# Default wordlist directory (populated by Dockerfile)
WORDLIST_DIR = os.environ.get("WORDLIST_DIR", "/usr/share/wordlists")
DEFAULT_WORDLIST = os.path.join(WORDLIST_DIR, "common.txt")

# ───────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ───────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "gobuster_dir",
        "description": "Brute-force web directories and files on a target web server using gobuster in dir mode.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":          {"type": "string",  "description": "Target URL (e.g., http://example.com)"},
                "wordlist":     {"type": "string",  "description": "Built-in wordlist name: common (default), big, subdomains, parameters, passwords, usernames.", "default": "common"},
                "extensions":   {"type": "string",  "description": "File extensions to check (comma-separated, e.g., php,html,js,txt)", "default": ""},
                "threads":      {"type": "integer", "description": "Number of concurrent threads", "default": 20},
                "status_codes": {"type": "string",  "description": "Status codes to report (default: 200,204,301,302,307,401,403)", "default": "200,204,301,302,307,401,403"},
                "timeout":      {"type": "integer", "description": "Scan timeout in seconds", "default": 300},
                "proxy":        {"type": "string",  "description": "HTTP/HTTPS proxy URL e.g. http://127.0.0.1:8080"},
                "headers":      {"type": "string",  "description": "Extra HTTP headers, newline-separated e.g. 'Authorization: Bearer token'"},
                "username":     {"type": "string",  "description": "Username for HTTP Basic authentication"},
                "password":     {"type": "string",  "description": "Password for HTTP Basic authentication"},
                "expanded":     {"type": "boolean", "description": "Show full URL in output instead of path", "default": False},
            },
            "required": ["url"]
        }
    },
    {
        "name": "gobuster_dns",
        "description": "Enumerate subdomains of a domain using gobuster DNS mode.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain":   {"type": "string",  "description": "Target domain (e.g., example.com)"},
                "wordlist": {"type": "string",  "description": "Built-in wordlist name: subdomains (default for DNS), common, big.", "default": "subdomains"},
                "threads":  {"type": "integer", "description": "Number of concurrent threads", "default": 20},
                "timeout":  {"type": "integer", "description": "Scan timeout in seconds", "default": 300},
            },
            "required": ["domain"]
        }
    },
    {
        "name": "gobuster_vhost",
        "description": "Enumerate virtual hosts on a web server using gobuster vhost mode.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":      {"type": "string",  "description": "Target URL/IP to probe for vhosts (e.g., http://10.10.10.1)"},
                "domain":   {"type": "string",  "description": "Base domain to append to wordlist entries (e.g., example.com)"},
                "wordlist": {"type": "string",  "description": "Built-in wordlist name: common (default), big, subdomains.", "default": "common"},
                "threads":  {"type": "integer", "description": "Number of concurrent threads", "default": 20},
                "timeout":  {"type": "integer", "description": "Scan timeout in seconds", "default": 300},
                "proxy":    {"type": "string",  "description": "HTTP/HTTPS proxy URL"},
                "headers":  {"type": "string",  "description": "Extra HTTP headers, newline-separated"},
                "username": {"type": "string",  "description": "Username for HTTP Basic auth"},
                "password": {"type": "string",  "description": "Password for HTTP Basic auth"},
            },
            "required": ["url", "domain"]
        }
    },
    {
        "name": "gobuster_fuzz",
        "description": "Generic fuzzing mode using gobuster — replaces FUZZ placeholder in URL, headers, or body.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url":      {"type": "string",  "description": "URL with FUZZ placeholder (e.g., http://example.com/page?id=FUZZ)"},
                "wordlist": {"type": "string",  "description": "Built-in wordlist name: parameters (default for fuzz), common, big.", "default": "parameters"},
                "threads":  {"type": "integer", "description": "Number of concurrent threads", "default": 20},
                "timeout":  {"type": "integer", "description": "Scan timeout in seconds", "default": 300},
                "proxy":    {"type": "string",  "description": "HTTP/HTTPS proxy URL"},
                "headers":  {"type": "string",  "description": "Extra HTTP headers, newline-separated"},
                # The handler (_build_gobuster_extra_args) already reads and passes these as -U/-P; undeclared before.
                # Whether gobuster's own `fuzz` subcommand accepts -U/-P the same way `dir` does is unverified here.
                "username": {"type": "string",  "description": "HTTP Basic auth username (paired with password)"},
                "password": {"type": "string",  "description": "HTTP Basic auth password (paired with username)"},
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
                if tool_name == "gobuster_dir":
                    result = await handle_gobuster_dir(arguments)
                elif tool_name == "gobuster_dns":
                    result = await handle_gobuster_dns(arguments)
                elif tool_name == "gobuster_vhost":
                    result = await handle_gobuster_vhost(arguments)
                elif tool_name == "gobuster_fuzz":
                    result = await handle_gobuster_fuzz(arguments)
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
_DOMAIN_RE = re.compile(r'^[a-zA-Z0-9.\-]+$')
_STATUS_RE = re.compile(r'^[\d,]+$')
_EXT_RE = re.compile(r'^[a-zA-Z0-9,]+$')


def _validate_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("'url' parameter is required")
    if not _URL_RE.match(url):
        raise ValueError(f"Invalid URL: {url!r}")
    from mcp_auth import validate_url_target  # SSRF guard (fix H-5)
    validate_url_target(url)
    return url


def _validate_domain(domain: str) -> str:
    domain = domain.strip()
    if not domain:
        raise ValueError("'domain' parameter is required")
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid domain: {domain!r}")
    from mcp_auth import validate_scan_target  # SSRF guard (fix H-5)
    validate_scan_target(domain)
    return domain


def _get_wordlist(name: str) -> str:
    """Resolve a built-in wordlist name to its full path.

    Only bare filenames (no path separators, no leading dots) are accepted
    to prevent any path-traversal attacks.  The caller receives a validated
    absolute path that is always inside WORDLIST_DIR.

    Supported names: common, big, subdomains, parameters, passwords, usernames
    """
    name = (name or "").strip()
    if not name:
        # Fall back to the default wordlist
        if os.path.isfile(DEFAULT_WORDLIST):
            return DEFAULT_WORDLIST
        raise ValueError("Default wordlist not found. Ensure the container wordlists volume is populated.")
    # Security: reject anything that could escape WORDLIST_DIR
    if "/" in name or ".." in name or name.startswith("."):
        raise ValueError(f"Invalid wordlist name: {name!r}")
    filename = name if name.endswith(".txt") else f"{name}.txt"
    full_path = os.path.join(WORDLIST_DIR, filename)
    if not os.path.isfile(full_path):
        raise ValueError(
            f"Wordlist {filename!r} not found in {WORDLIST_DIR}. "
            f"Available names: common, big, subdomains, parameters, passwords, usernames"
        )
    return full_path


async def _run_gobuster(cmd: list[str], timeout: int) -> str:
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
        if not output and err:
            output = err
        return output or "[No output from gobuster]"
    except asyncio.TimeoutError:
        raise asyncio.TimeoutError(f"Gobuster timed out after {timeout}s")
    except FileNotFoundError:
        raise RuntimeError("gobuster is not installed — check Dockerfile installation step")


# Matches ANSI escape sequences (for stripping color codes from gobuster output)
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _parse_gobuster_dir(output: str) -> list[dict]:
    """Parse gobuster dir output.

    Handles both legacy format:  /admin (Status: 200)
    and modern gobuster v3.6+ format:
        /admin                (Status: 200) [Size: 1234]
        http://host:80/admin  (Status: 200) [Size: 1234]
        admin                 (Status: 200) [Size: 1234]   ← relative paths (no leading /)
    ANSI colour codes are stripped before parsing.
    """
    results = []
    for line in output.splitlines():
        line = _strip_ansi(line).strip()
        if not line or line.startswith("=") or line.startswith("Gobuster") or line.startswith("["):
            continue
        # Strip optional full URL prefix (http://host:port), then capture path + status
        # Path may or may not start with /
        m = re.match(r'^(?:https?://[^\s/]*)?(/?[^\s]+?)\s+\(Status:\s*(\d+)\)', line)
        if m:
            path = m.group(1)
            # Ensure path starts with /
            if not path.startswith("/"):
                path = "/" + path
            results.append({"path": path, "status": int(m.group(2))})
    return results


def _parse_gobuster_dns(output: str) -> list[dict]:
    results = []
    for line in output.splitlines():
        m = re.match(r'^Found:\s+(\S+)', line.strip())
        if m:
            results.append({"subdomain": m.group(1)})
    return results


def _parse_gobuster_vhost(output: str) -> list[dict]:
    results = []
    for line in output.splitlines():
        m = re.match(r'^Found:\s+(\S+)\s+\(Status:\s*(\d+)\)', line.strip())
        if m:
            results.append({"vhost": m.group(1), "status": int(m.group(2))})
    return results


# ───────────────────────────────────────────────────────────
# TOOL IMPLEMENTATIONS
# ───────────────────────────────────────────────────────────

_PROXY_RE = re.compile(r'^https?://[a-zA-Z0-9.\-_:@/]+$')
_HEADER_KEY_RE = re.compile(r'^[a-zA-Z0-9\-]+$')


def _build_gobuster_extra_args(args: dict) -> list[str]:
    """Build extra gobuster CLI args from optional config fields."""
    extra: list[str] = []
    proxy = str(args.get("proxy", "") or "").strip()
    headers = str(args.get("headers", "") or "").strip()
    username = str(args.get("username", "") or "").strip()
    password = str(args.get("password", "") or "").strip()
    expanded = bool(args.get("expanded", False))
    if proxy and _PROXY_RE.match(proxy):
        extra += ["--proxy", proxy]
    if headers:
        for h in headers.splitlines():
            h = h.strip()
            if h and ":" in h:
                key = h.split(":")[0].strip()
                if _HEADER_KEY_RE.match(key):
                    extra += ["-H", h]
    if username and password:
        extra += ["-U", username, "-P", password]
    if expanded:
        extra += ["-e"]
    return extra


async def handle_gobuster_dir(args: dict) -> dict:
    url = _validate_url(args.get("url", ""))
    wordlist = _get_wordlist(args.get("wordlist", "common"))
    threads = min(int(args.get("threads", 20)), 100)
    timeout = min(int(args.get("timeout", 300)), 600)
    extra = _build_gobuster_extra_args(args)

    extensions = args.get("extensions", "").strip()
    if extensions and not _EXT_RE.match(extensions):
        raise ValueError(f"Invalid extensions: {extensions!r}")

    status_codes = args.get("status_codes", "200,204,301,302,307,401,403").strip()
    if not _STATUS_RE.match(status_codes):
        raise ValueError(f"Invalid status_codes: {status_codes!r}")

    cmd = [
        "gobuster", "dir",
        "-u", url,
        "-w", wordlist,
        "-t", str(threads),
        "-s", status_codes,
        "--status-codes-blacklist", "",   # clear default 404 blacklist (conflicts with -s in v3.6+)
        "--no-error",
        "--no-color",
    ] + extra
    if extensions:
        cmd += ["-x", extensions]

    log.info(f"[gobuster_dir] url={url} wordlist={wordlist} threads={threads}")
    raw = await _run_gobuster(cmd, timeout)
    found = _parse_gobuster_dir(raw)

    return {
        "tool": "gobuster_dir",
        "url": url,
        "wordlist": wordlist,
        "found": found,
        "raw_output": raw,
        "success": True,
    }


async def handle_gobuster_dns(args: dict) -> dict:
    domain = _validate_domain(args.get("domain", ""))
    wordlist = _get_wordlist(args.get("wordlist", "subdomains"))
    threads = min(int(args.get("threads", 20)), 100)
    timeout = min(int(args.get("timeout", 300)), 600)

    cmd = [
        "gobuster", "dns",
        "-d", domain,
        "-w", wordlist,
        "-t", str(threads),
        "--no-error",
        "--no-color",
    ]

    log.info(f"[gobuster_dns] domain={domain} wordlist={wordlist}")
    raw = await _run_gobuster(cmd, timeout)
    found = _parse_gobuster_dns(raw)

    return {
        "tool": "gobuster_dns",
        "domain": domain,
        "wordlist": wordlist,
        "found": found,
        "raw_output": raw,
        "success": True,
    }


async def handle_gobuster_vhost(args: dict) -> dict:
    url = _validate_url(args.get("url", ""))
    domain = _validate_domain(args.get("domain", ""))
    wordlist = _get_wordlist(args.get("wordlist", "common"))
    threads = min(int(args.get("threads", 20)), 100)
    timeout = min(int(args.get("timeout", 300)), 600)
    extra = _build_gobuster_extra_args(args)

    cmd = [
        "gobuster", "vhost",
        "-u", url,
        "--domain", domain,
        "-w", wordlist,
        "-t", str(threads),
        "--no-error",
        "--append-domain",
        "--no-color",
    ] + extra

    log.info(f"[gobuster_vhost] url={url} domain={domain} wordlist={wordlist}")
    raw = await _run_gobuster(cmd, timeout)
    found = _parse_gobuster_vhost(raw)

    return {
        "tool": "gobuster_vhost",
        "url": url,
        "domain": domain,
        "wordlist": wordlist,
        "found": found,
        "raw_output": raw,
        "success": True,
    }


async def handle_gobuster_fuzz(args: dict) -> dict:
    url = _validate_url(args.get("url", ""))
    if "FUZZ" not in url:
        raise ValueError("URL must contain 'FUZZ' as the injection placeholder (e.g., http://example.com/page?id=FUZZ)")
    wordlist = _get_wordlist(args.get("wordlist", "parameters"))
    threads = min(int(args.get("threads", 20)), 100)
    timeout = min(int(args.get("timeout", 300)), 600)
    extra = _build_gobuster_extra_args(args)

    cmd = [
        "gobuster", "fuzz",
        "-u", url,
        "-w", wordlist,
        "-t", str(threads),
        "--no-error",
        "--no-color",
    ] + extra

    log.info(f"[gobuster_fuzz] url={url} wordlist={wordlist}")
    raw = await _run_gobuster(cmd, timeout)

    return {
        "tool": "gobuster_fuzz",
        "url": url,
        "wordlist": wordlist,
        "raw_output": raw,
        "success": True,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=MCP_PORT, log_level="info")
