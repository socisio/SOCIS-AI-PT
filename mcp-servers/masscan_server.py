#!/usr/bin/env python3
"""
SOCIS-AI-PT — Masscan MCP Server (HTTP transport)
Massively fast network port scanner

Provides:
1. masscan_scan      - Scan a target with custom port range
2. masscan_top_ports - Scan top N most common ports
3. masscan_range     - Scan an IP range with specific ports
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

TOOL_NAME = "masscan"
MCP_PORT = 8118
MCP_VERSION = "1.0"
SERVER_NAME = f"{TOOL_NAME}-mcp"

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# Safe rate cap — masscan can saturate links; cap to protect shared infra
MAX_RATE = 10000

# ───────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ───────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "masscan_scan",
        "description": "Run masscan against a target IP or CIDR range with custom port specification. Much faster than nmap for large port sweeps.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP address or CIDR range (e.g., 192.168.1.1 or 10.0.0.0/24)"
                },
                "ports": {
                    "type": "string",
                    "description": "Port specification (e.g., 80,443,8080 or 1-1000 or 0-65535)",
                    "default": "1-1024"
                },
                "rate": {
                    "type": "integer",
                    "description": "Packets per second (max 10000 for safety)",
                    "default": 1000
                },
                "timeout": {
                    "type": "integer",
                    "description": "Scan timeout in seconds",
                    "default": 120
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional masscan flags (whitelisted: --banners, --source-port, --source-ip, --router-mac, --adapter-ip/--port/--mac, --retries, --wait, --offline, --ping, --arp, --ttl, --http-user-agent, --pcap-payloads, --nmap). Unsupported flags are dropped."
                },
            },
            "required": ["target"]
        }
    },
    {
        "name": "masscan_top_ports",
        "description": "Quickly scan the top N most common ports on a target using masscan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target IP address or CIDR range"
                },
                "top": {
                    "type": "integer",
                    "description": "Number of top ports to scan (100, 1000, or 10000)",
                    "default": 1000,
                    "enum": [100, 1000, 10000]
                },
                "rate": {
                    "type": "integer",
                    "description": "Packets per second",
                    "default": 2000
                },
                "timeout": {
                    "type": "integer",
                    "description": "Scan timeout in seconds",
                    "default": 60
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional masscan flags (whitelisted: --banners, --source-port, --source-ip, --router-mac, --adapter-ip/--port/--mac, --retries, --wait, --offline, --ping, --arp, --ttl, --http-user-agent, --pcap-payloads, --nmap). Unsupported flags are dropped."
                },
            },
            "required": ["target"]
        }
    },
    {
        "name": "masscan_range",
        "description": "Scan an IP range (CIDR) for specific ports — useful for internal network mapping.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cidr": {
                    "type": "string",
                    "description": "CIDR range to scan (e.g., 192.168.1.0/24)"
                },
                "ports": {
                    "type": "string",
                    "description": "Ports to check (e.g., 22,80,443,3389)",
                    "default": "22,80,443,445,3389,8080"
                },
                "rate": {
                    "type": "integer",
                    "description": "Packets per second",
                    "default": 500
                },
                "timeout": {
                    "type": "integer",
                    "description": "Scan timeout in seconds",
                    "default": 120
                },
                "extra_args": {
                    "type": "string",
                    "description": "Additional masscan flags (whitelisted: --banners, --source-port, --source-ip, --router-mac, --adapter-ip/--port/--mac, --retries, --wait, --offline, --ping, --arp, --ttl, --http-user-agent, --pcap-payloads, --nmap). Unsupported flags are dropped."
                },
            },
            "required": ["cidr"]
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
                if tool_name == "masscan_scan":
                    result = await handle_masscan_scan(arguments)
                elif tool_name == "masscan_top_ports":
                    result = await handle_masscan_top_ports(arguments)
                elif tool_name == "masscan_range":
                    result = await handle_masscan_range(arguments)
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

_IP_CIDR_RE = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$'
)
_PORTS_RE = re.compile(r'^[\d,\-]+$')


def _validate_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("'target' parameter is required")
    if not _IP_CIDR_RE.match(target):
        raise ValueError(f"Invalid IP/CIDR format: {target!r}. Expected e.g. 192.168.1.1 or 10.0.0.0/24")
    # SSRF / internal-scope guard (fix H-5). Validate network/host address.
    from mcp_auth import validate_scan_target
    check_host = target.split("/")[0] if "/" in target else target
    validate_scan_target(check_host)
    return target


def _validate_ports(ports: str) -> str:
    ports = ports.strip().replace(" ", "")

    # Accept common human formatting for ranges, e.g. "1-65,535".
    # Without normalization this would be interpreted as "1-65,535" (two tokens)
    # and scan the wrong scope.
    ports = re.sub(
        r"(\d+)-(\d{1,3}(?:,\d{3})+)",
        lambda m: f"{m.group(1)}-{m.group(2).replace(',', '')}",
        ports,
    )

    if not _PORTS_RE.match(ports):
        raise ValueError(f"Invalid port specification: {ports!r}. Use digits, commas, and hyphens only.")
    return ports


def _clamp_rate(rate: int) -> int:
    return max(1, min(rate, MAX_RATE))


def _parse_masscan_output(raw: str) -> list[dict]:
    """Parse masscan output lines into structured dicts."""
    # Common service name hints by port (fast/static; avoids extra lookups)
    service_by_port = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
        88: "kerberos", 110: "pop3", 111: "rpcbind", 123: "ntp",
        135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn",
        143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds",
        465: "smtps", 514: "syslog", 587: "submission", 631: "ipp", 636: "ldaps",
        873: "rsync", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
        2049: "nfs", 2375: "docker", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
        5672: "amqp", 5900: "vnc", 6379: "redis", 6443: "kubernetes-api",
        8080: "http-alt", 8443: "https-alt", 9000: "sonarqube", 9200: "elasticsearch",
        27017: "mongodb",
    }

    results = []
    # masscan outputs: Discovered open port <port>/tcp on <ip>
    for line in raw.splitlines():
        m = re.match(r'Discovered open port (\d+)/(\w+) on ([\d.]+)', line.strip())
        if m:
            port = int(m.group(1))
            results.append({
                "port": port,
                "protocol": m.group(2),
                "ip": m.group(3),
                "state": "open",
                "service": service_by_port.get(port, "unknown"),
            })
    return results


async def _run_masscan(cmd: list[str], timeout: int) -> str:
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
        return output or "[No output from masscan]"
    except asyncio.TimeoutError:
        raise asyncio.TimeoutError(f"Masscan timed out after {timeout}s")
    except FileNotFoundError:
        raise RuntimeError("masscan is not installed. Install with: apt-get install -y masscan")


# ───────────────────────────────────────────────────────────
# TOOL IMPLEMENTATIONS
# ───────────────────────────────────────────────────────────

# Top port lists (same as nmap defaults)
_TOP_100 = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"
_TOP_1000 = "1-1024,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888,9000,9200,27017"
_TOP_10000 = "0-10000"


def _append_extra_args(cmd: list, extra_args: str) -> list:
    """Safely append user-supplied extra masscan flags (whitelist-validated)."""
    allowed_prefix = (
        "--banners", "--source-port", "--source-ip", "--router-mac",
        "--adapter-ip", "--adapter-port", "--adapter-mac", "--retries",
        "--wait", "--offline", "--ping", "--arp", "--ttl",
        "--http-user-agent", "--pcap-payloads", "--nmap",
    )
    if not extra_args or not extra_args.strip():
        return cmd
    import shlex
    tokens = shlex.split(extra_args.strip())
    safe: list = []
    skip_next = False
    for i, tok in enumerate(tokens):
        if skip_next:
            safe.append(tok)
            skip_next = False
            continue
        if any(tok.startswith(p) for p in allowed_prefix):
            safe.append(tok)
            # if the flag takes a value as the next token (e.g. --source-port 61000)
            if "=" not in tok and i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                skip_next = True
        else:
            log.warning(f"[masscan] extra_args: ignoring unsupported flag '{tok}'")
    return cmd + safe


async def handle_masscan_scan(args: dict) -> dict:
    target = _validate_target(args.get("target", ""))
    ports = _validate_ports(args.get("ports", "1-1024"))
    rate = _clamp_rate(int(args.get("rate", 1000)))
    timeout = min(int(args.get("timeout", 120)), 300)
    extra_args = args.get("extra_args", "")

    cmd = ["masscan", target, "-p", ports, "--rate", str(rate), "--open"]
    cmd = _append_extra_args(cmd, extra_args)

    log.info(f"[masscan_scan] target={target} ports={ports} rate={rate}")
    raw = await _run_masscan(cmd, timeout)
    parsed = _parse_masscan_output(raw)

    return {
        "tool": "masscan_scan",
        "target": target,
        "ports": ports,
        "rate": rate,
        "open_ports": parsed,
        "raw_output": raw,
        "success": True,
    }


async def handle_masscan_top_ports(args: dict) -> dict:
    target = _validate_target(args.get("target", ""))
    top = int(args.get("top", 1000))
    rate = _clamp_rate(int(args.get("rate", 2000)))
    timeout = min(int(args.get("timeout", 60)), 300)
    extra_args = args.get("extra_args", "")

    if top == 100:
        ports = _TOP_100
    elif top == 10000:
        ports = _TOP_10000
    else:
        ports = _TOP_1000

    cmd = ["masscan", target, "-p", ports, "--rate", str(rate), "--open"]
    cmd = _append_extra_args(cmd, extra_args)

    log.info(f"[masscan_top_ports] target={target} top={top} rate={rate}")
    raw = await _run_masscan(cmd, timeout)
    parsed = _parse_masscan_output(raw)

    return {
        "tool": "masscan_top_ports",
        "target": target,
        "top_ports_requested": top,
        "rate": rate,
        "open_ports": parsed,
        "raw_output": raw,
        "success": True,
    }


async def handle_masscan_range(args: dict) -> dict:
    cidr = _validate_target(args.get("cidr", ""))
    ports = _validate_ports(args.get("ports", "22,80,443,445,3389,8080"))
    rate = _clamp_rate(int(args.get("rate", 500)))
    timeout = min(int(args.get("timeout", 120)), 300)
    extra_args = args.get("extra_args", "")

    cmd = ["masscan", cidr, "-p", ports, "--rate", str(rate), "--open"]
    cmd = _append_extra_args(cmd, extra_args)

    log.info(f"[masscan_range] cidr={cidr} ports={ports} rate={rate}")
    raw = await _run_masscan(cmd, timeout)
    parsed = _parse_masscan_output(raw)

    return {
        "tool": "masscan_range",
        "cidr": cidr,
        "ports": ports,
        "rate": rate,
        "open_ports": parsed,
        "raw_output": raw,
        "success": True,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=MCP_PORT, log_level="info")
