#!/usr/bin/env python3
"""
SOCIS-AI-PT — ffuf MCP Server (HTTP transport)
FastAPI-based MCP server for web fuzzing via ffuf.
"""

import json
import os
import subprocess
import asyncio
import threading
import functools
from concurrent.futures import ThreadPoolExecutor
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any
from mcp_auth import verify_mcp_auth, mcp_auth_error, validate_url_target

app = FastAPI(title="SOCIS ffuf MCP Server", docs_url=None)

MCP_VERSION = "1.1"
SERVER_NAME = "ffuf_mcp"

# Thread pool for blocking subprocess calls
_executor = ThreadPoolExecutor(max_workers=4)

# Wordlist directory - mount your own wordlists here
WORDLIST_DIR = os.environ.get("WORDLIST_DIR", "/usr/share/wordlists")
os.makedirs(WORDLIST_DIR, exist_ok=True)

def _get_wordlist(name: str) -> str | None:
    """Get wordlist path by name (SECURE - only from WORDLIST_DIR)."""
    # Block path traversal
    if ".." in name or "/" in name or name.startswith("."):
        return None
    path = os.path.join(WORDLIST_DIR, f"{name}.txt")
    if os.path.isfile(path):
        return path
    # Also check without .txt extension
    if os.path.isfile(os.path.join(WORDLIST_DIR, name)):
        return os.path.join(WORDLIST_DIR, name)
    return None

def _list_wordlists() -> dict:
    """List available wordlists from WORDLIST_DIR."""
    available = {}
    if not os.path.isdir(WORDLIST_DIR):
        return available
    for f in os.listdir(WORDLIST_DIR):
        path = os.path.join(WORDLIST_DIR, f)
        if os.path.isfile(path) and f.endswith(".txt"):
            name = f[:-4]  # remove .txt
            try:
                size = os.path.getsize(path)
                available[name] = {"path": path, "size": size}
            except Exception:
                pass
    return available


TOOLS = [
    {
        "name": "ffuf_fuzz",
        "description": "Fuzz directories and files on a web target using ffuf.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target":       {"type": "string",  "description": "Target URL (FUZZ placeholder inserted automatically)"},
                "wordlist":     {"type": "string",  "description": "Wordlist to use (dropdown)", "enum": ["common", "big", "small", "subdomains", "parameters"], "default": "common"},
                "extensions":   {"type": "string",  "description": "Comma-separated file extensions to try", "default": "php,html,txt"},
                "threads":      {"type": "integer", "description": "Concurrent threads (1-100)", "default": 20},
                "method":       {"type": "string",  "description": "HTTP method: GET, POST, PUT, DELETE, HEAD", "default": "GET"},
                "rate":         {"type": "integer", "description": "Max requests per second (0 = unlimited)", "default": 0},
                "timeout":      {"type": "integer", "description": "Per-request timeout in seconds", "default": 10},
                "match_codes":  {"type": "string",  "description": "Show only responses with these HTTP status codes e.g. 200,301,302"},
                "filter_codes": {"type": "string",  "description": "Hide responses with these HTTP status codes e.g. 404,400"},
                "filter_size":  {"type": "string",  "description": "Hide responses with this size in bytes (comma-separated for multiple) e.g. 1234,5678"},
                "filter_words": {"type": "string",  "description": "Hide responses with this word count e.g. 42"},
                "data":         {"type": "string",  "description": "POST body data (for POST fuzzing) e.g. username=FUZZ&password=test"},
                "headers":      {"type": "string",  "description": "Extra HTTP headers, newline-separated e.g. 'Authorization: Bearer token'"},
                "recursion":    {"type": "boolean", "description": "Enable recursive fuzzing", "default": False},
                "recursion_depth": {"type": "integer", "description": "Max recursion depth (1-5)", "default": 2},
            },
            "required": ["target"],
        },
    },
    {
        "name": "ffuf_subdomains",
        "description": "Discover subdomains using ffuf.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain (e.g., example.com)"
                },
                "wordlist": {
                    "type": "string", 
                    "description": "Wordlist dropdown",
                    "enum": ["common", "big", "small", "subdomains", "parameters"],
                    "default": "common"
                },
                "threads": {
                    "type": "integer",
                    "description": "Concurrent threads",
                    "default": 20
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "ffuf_parameters",
        "description": "Fuzz GET parameters (query strings).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL with FUZZ placeholder"
                },
                "wordlist": {
                    "type": "string", 
                    "description": "Wordlist dropdown",
                    "enum": ["common", "big", "small", "subdomains", "parameters"],
                    "default": "common"
                },
                "threads": {
                    "type": "integer",
                    "description": "Concurrent threads",
                    "default": 20
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "ffuf_vhost",
        "description": "Discover virtual hosts (Host header fuzzing).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL"
                },
                "domain": {
                    "type": "string",
                    "description": "Base domain for vhosts"
                },
                "wordlist": {
                    "type": "string", 
                    "description": "Wordlist dropdown",
                    "enum": ["common", "big", "small", "subdomains", "parameters"],
                    "default": "common"
                },
                "threads": {
                    "type": "integer",
                    "description": "Concurrent threads",
                    "default": 20
                },
            },
            "required": ["target", "domain"],
        },
    },
    {
        "name": "ffuf_recursive",
        "description": "Recursive directory fuzzing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target base URL"
                },
                "wordlist": {
                    "type": "string", 
                    "description": "Wordlist dropdown",
                    "enum": ["common", "big", "small", "subdomains", "parameters"],
                    "default": "common"
                },
                "depth": {
                    "type": "integer",
                    "description": "Recursion depth (1-5)",
                    "default": 2
                },
                "extensions": {
                    "type": "string",
                    "description": "File extensions",
                    "default": "php,html,txt"
                },
                "threads": {
                    "type": "integer",
                    "description": "Concurrent threads",
                    "default": 20
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "ffuf_filter_codes",
        "description": "Filter by HTTP status codes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL"
                },
                "wordlist": {
                    "type": "string", 
                    "description": "Wordlist dropdown",
                    "enum": ["common", "big", "small", "subdomains", "parameters"],
                    "default": "common"
                },
                "filter_codes": {
                    "type": "string",
                    "description": "Codes to filter OUT (e.g., 302,404)",
                    "default": "302,404"
                },
                "show_codes": {
                    "type": "string",
                    "description": "Codes to SHOW (e.g., 200,301)",
                    "default": "200,204,301,302,307,401,403"
                },
                "threads": {
                    "type": "integer",
                    "description": "Concurrent threads",
                    "default": 20
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "ffuf_list_wordlists",
        "description": "List available wordlists with sizes.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


def _run_ffuf(target: str, wordlist: str, mode: str = "fuzz", extensions: str = "php,html,txt", threads: int = 20, domain: str = "", depth: int = 2, filter_codes: str = "", show_codes: str = "") -> str:
    """Generic ffuf runner with different modes."""
    if "FUZZ" not in target and mode != "subdomains":
        target = target.rstrip("/") + "/FUZZ"

    tid = threading.get_ident()
    out_file = f"/tmp/ffuf_{mode}_{os.getpid()}_{tid}.json"
    threads = max(1, min(100, threads))

    if mode == "subdomains":
        base_domain = domain or target.lstrip("https://").lstrip("http://").split("/")[0]
        cmd = ["ffuf",
               "-u", f"https://FUZZ.{base_domain}",
               "-w", wordlist,
               "-t", str(threads),
               "-o", out_file, "-of", "json", "-s",
               "-timeout", "10", "-maxtime", "120"]
    else:
        cmd = ["ffuf", "-u", target, "-w", wordlist, "-t", str(threads),
               "-o", out_file, "-of", "json", "-s", "-timeout", "10", "-maxtime", "120"]
        if mode == "fuzz":
            cmd.extend(["-e", extensions])
        elif mode == "vhost":
            vhost_domain = domain or "FUZZ"
            cmd.extend(["-H", f"Host: FUZZ.{vhost_domain}", "-mc", "200,301,302,401"])
        elif mode == "recursive":
            rec_depth = max(1, min(5, depth))
            cmd.extend(["-recursion", "-recursion-depth", str(rec_depth), "-e", extensions])

    if filter_codes:
        cmd.extend(["-fc", filter_codes])
    if show_codes:
        cmd.extend(["-mc", show_codes])
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=160)
    try:
        if os.path.exists(out_file):
            with open(out_file) as f:
                data = json.load(f)
            results = data.get("results", [])
            if not results:
                return "No findings."
            
            lines = []
            for r in results[:100]:
                status = r.get("status", 0)
                url = r.get("url", r.get("host", ""))
                length = r.get("length", 0)
                lines.append(f"[{status}] {url} ({length} bytes)")
            return f"Found {len(results)} result(s):\n" + "\n".join(lines)
    except Exception as e:
        pass
    
    output = result.stdout or result.stderr or ""
    return f"Completed.\n{output[-2000:]}" if output else "No output."


async def handle_ffuf_fuzz(arguments: dict) -> str:
    target = arguments.get("target", "")
    if not target:
        return "Error: 'target' is required."

    try:
        validate_url_target(target)
    except ValueError as e:
        return f"Error: {e}"

    wordlist_name = arguments.get("wordlist", "common")
    wordlist_path = _get_wordlist(wordlist_name)
    if not wordlist_path:
        return f"Error: Wordlist '{wordlist_name}' not found. Use ffuf_list_wordlists to see available."

    extensions = str(arguments.get("extensions", "php,html,txt") or "php,html,txt")
    threads = max(1, min(100, int(arguments.get("threads", 20))))
    method = str(arguments.get("method", "GET") or "GET").upper()
    rate = max(0, int(arguments.get("rate", 0) or 0))
    timeout_per_req = max(1, min(60, int(arguments.get("timeout", 10) or 10)))
    match_codes = str(arguments.get("match_codes", "") or "").strip()
    filter_codes = str(arguments.get("filter_codes", "") or "").strip()
    filter_size = str(arguments.get("filter_size", "") or "").strip()
    filter_words = str(arguments.get("filter_words", "") or "").strip()
    data = str(arguments.get("data", "") or "").strip()
    headers_raw = str(arguments.get("headers", "") or "").strip()
    recursion = bool(arguments.get("recursion", False))
    recursion_depth = max(1, min(5, int(arguments.get("recursion_depth", 2) or 2)))

    if "FUZZ" not in target:
        target = target.rstrip("/") + "/FUZZ"

    tid = threading.get_ident()
    out_file = f"/tmp/ffuf_fuzz_{os.getpid()}_{tid}.json"
    cmd = [
        "ffuf", "-u", target,
        "-w", wordlist_path,
        "-t", str(threads),
        "-X", method,
        "-o", out_file, "-of", "json", "-s",
        "-timeout", str(timeout_per_req),
        "-maxtime", "180",
        "-e", extensions,
    ]
    if rate:
        cmd += ["-rate", str(rate)]
    if match_codes:
        cmd += ["-mc", match_codes]
    if filter_codes:
        cmd += ["-fc", filter_codes]
    if filter_size:
        cmd += ["-fs", filter_size]
    if filter_words:
        cmd += ["-fw", filter_words]
    if data:
        cmd += ["-d", data]
    if headers_raw:
        for h in headers_raw.splitlines():
            h = h.strip()
            if h and ":" in h:
                cmd += ["-H", h]
    if recursion:
        cmd += ["-recursion", "-recursion-depth", str(recursion_depth)]

    loop = asyncio.get_event_loop()

    def _run() -> str:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=200)
        try:
            if os.path.exists(out_file):
                with open(out_file) as f:
                    data_json = json.load(f)
                results = data_json.get("results", [])
                if not results:
                    return "No findings."
                lines = []
                for r in results[:100]:
                    status = r.get("status", 0)
                    url = r.get("url", r.get("host", ""))
                    length = r.get("length", 0)
                    lines.append(f"[{status}] {url} ({length} bytes)")
                return f"Found {len(results)} result(s):\n" + "\n".join(lines)
        except Exception:
            pass
        output = result.stdout or result.stderr or ""
        return f"Completed.\n{output[-2000:]}" if output else "No output."

    return await loop.run_in_executor(_executor, _run)


async def handle_ffuf_subdomains(arguments: dict) -> str:
    domain = arguments.get("domain", "")
    if not domain:
        return "Error: 'domain' is required."
    
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
    target = f"https://{domain}"
    
    try:
        validate_url_target(target)
    except ValueError as e:
        return f"Error: {e}"
    
    wordlist_name = arguments.get("wordlist", "common")
    wordlist_path = _get_wordlist(wordlist_name)
    if not wordlist_path:
        return f"Error: Wordlist '{wordlist_name}' not found."
    
    threads = max(1, min(100, arguments.get("threads", 20)))
    
    loop = asyncio.get_event_loop()
    fn = functools.partial(_run_ffuf, target, wordlist_path, "subdomains", "", threads, domain=domain)
    result = await loop.run_in_executor(_executor, fn)
    return result


async def handle_ffuf_parameters(arguments: dict) -> str:
    target = arguments.get("target", "")
    if not target:
        return "Error: 'target' is required."
    if "FUZZ" not in target:
        target = target.rstrip("/") + "?FUZZ=test"
    
    try:
        validate_url_target(target)
    except ValueError as e:
        return f"Error: {e}"
    
    wordlist_name = arguments.get("wordlist", "common")
    wordlist_path = _get_wordlist(wordlist_name)
    if not wordlist_path:
        return f"Error: Wordlist '{wordlist_name}' not found."
    
    threads = max(1, min(100, arguments.get("threads", 20)))
    
    loop = asyncio.get_event_loop()
    fn = functools.partial(_run_ffuf, target, wordlist_path, "parameters", "", threads)
    result = await loop.run_in_executor(_executor, fn)
    return result


async def handle_ffuf_vhost(arguments: dict) -> str:
    target = arguments.get("target", "")
    domain = arguments.get("domain", "")
    if not target or not domain:
        return "Error: 'target' and 'domain' required."
    
    try:
        validate_url_target(target)
    except ValueError as e:
        return f"Error: {e}"
    
    wordlist_name = arguments.get("wordlist", "common")
    wordlist_path = _get_wordlist(wordlist_name)
    if not wordlist_path:
        return f"Error: Wordlist '{wordlist_name}' not found."
    
    threads = max(1, min(100, arguments.get("threads", 20)))
    
    loop = asyncio.get_event_loop()
    fn = functools.partial(_run_ffuf, target, wordlist_path, "vhost", "", threads, domain=domain)
    result = await loop.run_in_executor(_executor, fn)
    return result


async def handle_ffuf_recursive(arguments: dict) -> str:
    target = arguments.get("target", "")
    if not target:
        return "Error: 'target' is required."
    
    try:
        validate_url_target(target)
    except ValueError as e:
        return f"Error: {e}"
    
    wordlist_name = arguments.get("wordlist", "common")
    wordlist_path = _get_wordlist(wordlist_name)
    if not wordlist_path:
        return f"Error: Wordlist '{wordlist_name}' not found."
    
    extensions = arguments.get("extensions", "php,html,txt")
    depth = max(1, min(5, arguments.get("depth", 2)))
    threads = max(1, min(100, arguments.get("threads", 20)))
    
    loop = asyncio.get_event_loop()
    fn = functools.partial(_run_ffuf, target, wordlist_path, "recursive", extensions, threads, depth=depth)
    result = await loop.run_in_executor(_executor, fn)
    return result


async def handle_ffuf_filter_codes(arguments: dict) -> str:
    target = arguments.get("target", "")
    if not target:
        return "Error: 'target' is required."
    
    try:
        validate_url_target(target)
    except ValueError as e:
        return f"Error: {e}"
    
    wordlist_name = arguments.get("wordlist", "common")
    wordlist_path = _get_wordlist(wordlist_name)
    if not wordlist_path:
        return f"Error: Wordlist '{wordlist_name}' not found."
    
    filter_codes = arguments.get("filter_codes", "302,404")
    show_codes = arguments.get("show_codes")
    threads = max(1, min(100, arguments.get("threads", 20)))
    
    loop = asyncio.get_event_loop()
    fn = functools.partial(_run_ffuf, target, wordlist_path, "filter", "", threads,
                           filter_codes=filter_codes, show_codes=show_codes or "")
    result = await loop.run_in_executor(_executor, fn)
    return result


def handle_list_wordlists() -> str:
    """List available wordlists."""
    wordlists = _list_wordlists()
    if not wordlists:
        return "No wordlists found. Mount wordlist files to WORDLIST_DIR."
    
    lines = ["📁 Available Wordlists:"]
    for name, info in wordlists.items():
        size_kb = info["size"] // 1024
        lines.append(f"  • {name}: {info['path']} ({size_kb} KB)")
    
    return "\n".join(lines)


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
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            try:
                if tool_name == "ffuf_fuzz":
                    result = await handle_ffuf_fuzz(arguments)
                elif tool_name == "ffuf_subdomains":
                    result = await handle_ffuf_subdomains(arguments)
                elif tool_name == "ffuf_parameters":
                    result = await handle_ffuf_parameters(arguments)
                elif tool_name == "ffuf_vhost":
                    result = await handle_ffuf_vhost(arguments)
                elif tool_name == "ffuf_recursive":
                    result = await handle_ffuf_recursive(arguments)
                elif tool_name == "ffuf_filter_codes":
                    result = await handle_ffuf_filter_codes(arguments)
                elif tool_name == "ffuf_list_wordlists":
                    result = handle_list_wordlists()
                else:
                    raise ValueError(f"Unknown tool: {tool_name}")
                return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": result}]}})
            except Exception as e:
                return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}}, status_code=400)
        elif method == "initialize":
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": SERVER_NAME, "version": MCP_VERSION}}})
        else:
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}}, status_code=404)
    except Exception as e:
        return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(e)}}, status_code=500)


@app.get("/health")
async def health():
    return {"status": "healthy", "server": SERVER_NAME}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8108, log_level="warning")
