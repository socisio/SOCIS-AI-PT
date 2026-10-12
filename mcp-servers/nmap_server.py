#!/usr/bin/env python3
"""
SOCIS-AI-PT — Nmap MCP Server (HTTP transport)
FastAPI-based MCP server for network scanning via nmap.
"""

import json
import asyncio
import re
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_auth import verify_mcp_auth, mcp_auth_error, sanitize_nmap_flags  # type: ignore
from nmap_parse import parse_open_ports  # type: ignore

app = FastAPI(title="SOCIS Nmap MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "nmap-mcp"

# Wordlist directory shared with other MCP servers
WORDLIST_DIR = os.environ.get("WORDLIST_DIR", "/usr/share/wordlists")


def _get_wordlist(name: str) -> str:
    """Resolve a built-in wordlist name to its full path.
    Only bare filenames (no path separators, no leading dots) are allowed;
    this prevents path-traversal attacks.
    """
    name = name.strip()
    if not name:
        return ""
    if "/" in name or ".." in name or name.startswith("."):
        raise ValueError(f"Invalid wordlist name: {name!r}")
    filename = name if name.endswith(".txt") or name.endswith(".lst") else f"{name}.txt"
    full_path = os.path.join(WORDLIST_DIR, filename)
    if not os.path.isfile(full_path):
        raise ValueError(f"Wordlist not found: {filename!r} (looked in {WORDLIST_DIR})")
    return full_path

TOOLS = [
    {
        "name": "nmap_scan",
        "description": "Run an nmap port scan against a target IP, hostname, or CIDR range. Returns parsed open ports, services, and version info.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP address, hostname, or CIDR (e.g. 192.168.1.1 or 10.0.0.0/24)"
                },
                "flags": {
                    "type": "string",
                    "description": "nmap scan type",
                    "enum": ["-sV -sC -T4 --open", "-sS -sV -sC -T4 --open", "-sT -sV -T4 --open", "-sU -sV -T4 --open", "-sL -sn -T4", "-Pn -sV -sC -T4 --open"],
                    "default": "-sV -sC -T4 --open"
                },
                "ports": {
                    "type": "string",
                    "description": "Port specification (e.g. '22,80,443' or '1-1000' or 'top100')",
                    "default": ""
                },
                "timeout": {
                    "type": "integer",
                    "description": "Scan timeout in seconds",
                    "default": 300
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "port_check",
        "description": "Check if a specific port is open on a target.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "port": {"type": "integer"}
            },
            "required": ["target", "port"]
        }
    },
    {
        "name": "os_detect",
        "description": "Attempt OS detection on a target.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "nmap_quick_scan",
        "description": "Fast scan for common ports (top 100).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "preset": {
                    "type": "string",
                    "description": "Quick scan preset",
                    "enum": ["top100", "top1000", "top10000", "top500"],
                    "default": "top100"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "nmap_service_scan",
        "description": "Detect services and versions on open ports.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "service_detect": {
                    "type": "string",
                    "description": "Service detection level",
                    "enum": ["-sV", "-sV --version-intensity 9", "-sV --script=default"],
                    "default": "-sV"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "nmap_vuln_scan",
        "description": "Scan for common vulnerabilities using nmap NSE scripts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "vuln_script": {
                    "type": "string",
                    "description": "Vulnerability script to run",
                    "enum": ["vuln", "exploit", "discovery", "auth", "brute"],
                    "default": "vuln"
                }
            },
            "required": ["target"]
        }
    },
    {   
        "name": "nmap_smb_scan",
        "description": "Scan for SMB vulnerabilities and enumerations. For brute mode, optionally supply custom wordlists from /usr/share/wordlists/.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "smb_type": {
                    "type": "string",
                    "description": "SMB check type",
                    "enum": ["enum", "vuln", "brute"],
                    "default": "enum"
                },
                "passdb": {
                    "type": "string",
                    "description": "Built-in wordlist name for password brute-force (e.g. common, big). Used only when smb_type=brute. Leave empty to use nmap's default passwords.lst."
                },
                "userdb": {
                    "type": "string",
                    "description": "Built-in wordlist name for username list. Used only when smb_type=brute. Leave empty to use nmap's default usernames.lst."
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "nmap_brute_scan",
        "description": "Run nmap brute-force credential attacks against network services (SSH, FTP, HTTP, Telnet, etc.) using built-in wordlists.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP address or hostname"
                },
                "service": {
                    "type": "string",
                    "description": "Service/protocol to brute-force",
                    "enum": ["ssh", "ftp", "http", "telnet", "smtp", "pop3", "imap", "vnc", "rdp"],
                    "default": "ssh"
                },
                "passdb": {
                    "type": "string",
                    "description": "Built-in wordlist name for passwords (e.g. common, big). Defaults to nmap's passwords.lst."
                },
                "userdb": {
                    "type": "string",
                    "description": "Built-in wordlist name for usernames. Defaults to nmap's usernames.lst."
                },
                "port": {
                    "type": "integer",
                    "description": "Target port (auto-detected from service if omitted)"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "nmap_http_scan",
        "description": "Scan HTTP services for vulnerabilities and info.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "http_script": {
                    "type": "string",
                    "description": "HTTP check type",
                    "enum": ["http-title", "http-headers", "http-methods", "http-robots", "http-waf-detect", "http-sql-injection"],
                    "default": "http-title"
                }
            },
            "required": ["target"]
        }
    }
]


async def run_nmap(target: str, flags: str = "-sV -sC -T4 --open", ports: str = "", timeout: int = 300) -> dict:
    """Execute nmap and parse results."""
    # Security: whitelist target format
    if not re.match(r'^[a-zA-Z0-9.\-_:/]+$', target):
        raise ValueError(f"Invalid target format: {target}")

    # SSRF / internal-scope guard (fix H-5).
    from mcp_auth import validate_scan_target
    validate_scan_target(target.split("/")[0])

    # Security: validate flags against whitelist to prevent command injection
    try:
        safe_flags = sanitize_nmap_flags(flags)
    except ValueError as e:
        raise ValueError(f"Unsafe nmap flags rejected: {e}")

    cmd = ["nmap"] + safe_flags
    if ports:
        # Validate port specification
        if ports == "top100":
            cmd += ["--top-ports", "100"]
        elif re.match(r'^[\d,\-]+$', ports):
            cmd += ["-p", ports]
        else:
            raise ValueError(f"Invalid port specification: {ports}")
    cmd.append(target)

    try:
        # Bound concurrent nmap processes per server (perf #3).
        from mcp_auth import scan_slot
        async with scan_slot():
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=timeout)
        output = stdout.decode()

        # Parse open ports
        open_ports = parse_open_ports(output)   # line-safe: a port without a version no longer swallows the next port (nmap_parse.py)

        # OS detection
        os_guess = None
        os_match = re.search(r"OS details: (.+)$", output, re.MULTILINE)
        if os_match:
            os_guess = os_match.group(1).strip()

        host_up = "Host is up" in output

        return {
            "target": target,
            "host_up": host_up,
            "open_ports": open_ports,
            "os_guess": os_guess,
            "raw": output
        }
    except asyncio.TimeoutError:
        raise TimeoutError(f"nmap scan timed out for {target}")
    except Exception as e:
        raise RuntimeError(f"nmap error: {e}")


async def handle_tool_call(tool_name: str, arguments: dict[str, Any]) -> dict:
    """Handle MCP tool calls."""
    if tool_name == "nmap_scan":
        target = arguments["target"]
        flags = arguments.get("flags", "-sV -sC -T4 --open")
        ports = arguments.get("ports", "")
        timeout = arguments.get("timeout", 300)
        return await run_nmap(target, flags, ports, timeout=timeout)

    elif tool_name == "port_check":
        target = arguments["target"]
        port = arguments["port"]
        result = await run_nmap(target, "-sT -T4", str(port))
        is_open = any(p["port"] == port for p in result["open_ports"])
        return {"target": target, "port": port, "open": is_open}

    elif tool_name == "os_detect":
        target = arguments["target"]
        result = await run_nmap(target, "-O --osscan-guess -T4")
        return {"target": target, "os_guess": result.get("os_guess"), "raw": result["raw"]}
    
    elif tool_name == "nmap_quick_scan":
        target = arguments["target"]
        preset = arguments.get("preset", "top100")
        return await run_nmap(target, f"-T4 --{preset}")
    
    elif tool_name == "nmap_service_scan":
        target = arguments["target"]
        service_detect = arguments.get("service_detect", "-sV")
        if "script" in service_detect:
            return await run_nmap(target, f"{service_detect} -sC -T4")
        return await run_nmap(target, f"{service_detect} -sC -T4")
    
    elif tool_name == "nmap_vuln_scan":
        target = arguments["target"]
        vuln_script = arguments.get("vuln_script", "vuln")
        return await run_nmap(target, f"--script={vuln_script} -sV -T4")
    
    elif tool_name == "nmap_smb_scan":
        target = arguments["target"]
        smb_type = arguments.get("smb_type", "enum")
        script_map = {"enum": "smb-enum-shares,smb-enum-users", "vuln": "smb-vuln*,smb-check-vulns", "brute": "smb-brute"}
        script = script_map.get(smb_type, "smb-enum-shares,smb-enum-users")
        if smb_type == "brute":
            # Build script-args for wordlists if provided
            script_args_parts = []
            passdb_name = arguments.get("passdb", "").strip()
            userdb_name = arguments.get("userdb", "").strip()
            if passdb_name:
                passdb_path = _get_wordlist(passdb_name)
                script_args_parts.append(f"passdb={passdb_path}")
            if userdb_name:
                userdb_path = _get_wordlist(userdb_name)
                script_args_parts.append(f"userdb={userdb_path}")
            extra = ["--script-args", ",".join(script_args_parts)] if script_args_parts else []
            if not re.match(r'^[a-zA-Z0-9.\-_:/]+$', target):
                raise ValueError(f"Invalid target format: {target}")
            cmd = ["nmap", f"--script={script}", "-p", "139,445", "-T4", target] + extra
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            return {"target": target, "smb_type": smb_type, "raw": stdout.decode()}
        return await run_nmap(target, f"--script={script} -p 139,445 -T4")

    elif tool_name == "nmap_brute_scan":
        target = arguments["target"]
        if not re.match(r'^[a-zA-Z0-9.\-_:/]+$', target):
            raise ValueError(f"Invalid target format: {target}")
        service = arguments.get("service", "ssh")
        service_scripts = {
            "ssh": ("ssh-brute", 22), "ftp": ("ftp-brute", 21),
            "http": ("http-brute", 80), "telnet": ("telnet-brute", 23),
            "smtp": ("smtp-brute", 25), "pop3": ("pop3-brute", 110),
            "imap": ("imap-brute", 143), "vnc": ("vnc-brute", 5900),
            "rdp": ("rdp-brute", 3389),
        }
        if service not in service_scripts:
            raise ValueError(f"Unsupported service: {service!r}")
        script_name, default_port = service_scripts[service]
        port = int(arguments.get("port") or default_port)
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port: {port}")
        # Build script-args for wordlists
        script_args_parts = []
        passdb_name = arguments.get("passdb", "").strip()
        userdb_name = arguments.get("userdb", "").strip()
        if passdb_name:
            passdb_path = _get_wordlist(passdb_name)
            script_args_parts.append(f"passdb={passdb_path}")
        if userdb_name:
            userdb_path = _get_wordlist(userdb_name)
            script_args_parts.append(f"userdb={userdb_path}")
        cmd = ["nmap", f"--script={script_name}", "-p", str(port), "-T4", target]
        if script_args_parts:
            cmd += ["--script-args", ",".join(script_args_parts)]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        return {"target": target, "service": service, "port": port, "raw": stdout.decode()}
    
    elif tool_name == "nmap_http_scan":
        target = arguments["target"]
        http_script = arguments.get("http_script", "http-title")
        script_map = {"http-title": "http-title", "http-headers": "http-headers", "http-methods": "http-methods", "http-robots": "http-robots.txt", "http-waf-detect": "http-waf-detect", "http-sql-injection": "http-sql-injection"}
        script = http_script if http_script in ["http-waf-detect", "http-sql-injection"] else script_map.get(http_script, "http-title")
        return await run_nmap(target, f"--script={script} -sV -p 80,443,8080 -T4")

    else:
        raise ValueError(f"Unknown tool: {tool_name}")


@app.post("/mcp")
async def mcp_handler(request: Request):
    """Handle MCP JSON-RPC requests."""
    if not verify_mcp_auth(request):
        return mcp_auth_error()
    try:
        payload = await request.json()
        req_id = payload.get("id")
        method = payload.get("method")
        params = payload.get("params", {})

        if method == "tools/list":
            result = {"tools": TOOLS}
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result})

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            try:
                result = await handle_tool_call(tool_name, arguments)
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}
                })
            except Exception as e:
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32000, "message": str(e)}
                }, status_code=400)

        elif method == "initialize":
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": MCP_VERSION},
                }
            })

        else:
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"}
            }, status_code=404)

    except Exception as e:
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32603, "message": str(e)}
        }, status_code=500)


@app.get("/health")
async def health():
    return {"status": "healthy", "server": SERVER_NAME}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8101, log_level="warning")
