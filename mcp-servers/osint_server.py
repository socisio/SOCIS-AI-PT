#!/usr/bin/env python3
"""
SOCIS-AI-PT — OSINT MCP Server (HTTP transport)
FastAPI-based MCP server for open-source intelligence gathering.
Tools: whois, DNS, HTTP headers, Shodan, subdomain enum, IP geolocation.
"""

import json
import asyncio
import socket
import re
import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any
from mcp_auth import verify_mcp_auth, mcp_auth_error, validate_url_target
from target_scope import whois_skip_reason  # type: ignore

app = FastAPI(title="SOCIS OSINT MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "osint-mcp"

TOOLS = [
    {
        "name": "whois_lookup",
        "description": "Perform WHOIS lookup for a domain or IP address. Returns registrar, registration dates, nameservers, and contact info.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Domain name or IP address"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds",
                    "default": 30
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "dns_lookup",
        "description": "Perform DNS record lookups (A, AAAA, MX, NS, TXT, SOA, CNAME) for a domain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Domain to query"
                },
                "record_type": {
                    "type": "string",
                    "description": "DNS record type",
                    "enum": ["all", "A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "SRV", "CAA"],
                    "default": "all"
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds",
                    "default": 30
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "http_headers",
        "description": "Fetch HTTP response headers from a URL to identify technologies, security settings, and server information.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to fetch headers from"
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "ip_geolocation",
        "description": "Get geolocation, ASN, and organization information for an IP address.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {
                    "type": "string",
                    "description": "IP address to geolocate"
                }
            },
            "required": ["ip"]
        }
    },
    {
        "name": "subdomain_enum",
        "description": "Enumerate subdomains for a domain using passive DNS and certificate transparency logs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Base domain to enumerate"
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "ssl_info",
        "description": "Get SSL/TLS certificate details for a domain: issuer, expiry, SANs, cipher suites.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string",
                    "description": "Domain to inspect"
                },
                "port": {
                    "type": "integer",
                    "description": "Port to connect to",
                    "default": 443
                }
            },
            "required": ["hostname"]
        }
    },
    {
        "name": "tech_fingerprint",
        "description": "Fingerprint web technologies using HTTP headers and response analysis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"}
            },
            "required": ["url"]
        }
    }
]


def _extract_hostname(value: str) -> str:
    """Strip protocol, path, port, auth from any URL or bare host/IP."""
    value = value.strip()
    # Add a scheme if missing so urlparse works correctly
    if "://" not in value:
        value = "https://" + value
    from urllib.parse import urlparse
    parsed = urlparse(value)
    host = parsed.hostname or parsed.netloc
    return (host or value).lower().rstrip(".")


def validate_domain(domain: str) -> str:
    domain = _extract_hostname(domain)
    if not re.match(r'^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$', domain):
        raise ValueError(f"Invalid domain: {domain}")
    return domain


def validate_ip(ip: str) -> str:
    try:
        socket.inet_aton(ip)
        return ip
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return ip
        except socket.error:
            raise ValueError(f"Invalid IP: {ip}")


async def run_cmd(cmd: list[str], timeout: int = 30) -> str:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    return stdout.decode()


async def handle_tool(tool_name: str, arguments: dict) -> Any:

    if tool_name == "whois_lookup":
        target = _extract_hostname(arguments["target"])
        timeout = arguments.get("timeout", 30)
        why = whois_skip_reason(target)
        if why:                      # a private address has no public registration: do not return (and the report must not print) the IANA special-use record
            return {"target": target, "skipped": True, "reason": why}
        raw = await run_cmd(["whois", target], timeout=timeout)
        # Parse key fields
        fields = {}
        for line in raw.split("\n"):
            for key in ["Registrar:", "Creation Date:", "Updated Date:", "Expiry Date:",
                        "Name Server:", "Registrant Email:", "Tech Email:"]:
                if line.strip().startswith(key):
                    val = line.split(":", 1)[1].strip()
                    k = key.rstrip(":")
                    if k in fields:
                        if isinstance(fields[k], list):
                            fields[k].append(val)
                        else:
                            fields[k] = [fields[k], val]
                    else:
                        fields[k] = val
        return {"target": target, "fields": fields, "raw": raw[:3000]}

    elif tool_name == "dns_lookup":
        domain = validate_domain(arguments["domain"])
        _ALLOWED_RECORD_TYPES = {"A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "SRV", "CAA", "ALL"}
        record_type = arguments.get("record_type", "all").upper()
        if record_type not in _ALLOWED_RECORD_TYPES:
            raise ValueError(f"Invalid record_type {record_type!r}. Allowed: {sorted(_ALLOWED_RECORD_TYPES)}")
        timeout = arguments.get("timeout", 30)
        results = {}

        types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "SRV", "CAA"] if record_type == "ALL" else [record_type]

        for rtype in types:
            try:
                raw = await run_cmd(["dig", "+short", rtype, domain], timeout=timeout)
                records = [r.strip() for r in raw.strip().split("\n") if r.strip()]
                if records:
                    results[rtype] = records
            except Exception:
                pass

        # Reverse IP for A records
        if "A" in results:
            resolve = results["A"][0] if results["A"] else None
            results["_resolved_ip"] = resolve

        return {"domain": domain, "records": results}

    elif tool_name == "http_headers":
        url = arguments["url"]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        validate_url_target(url)
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            r = await client.head(url)
            return {
                "url": str(r.url),
                "status_code": r.status_code,
                "headers": dict(r.headers),
                "redirect_count": len(r.history),
            }

    elif tool_name == "ip_geolocation":
        ip = validate_ip(arguments["ip"])
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(f"https://ipinfo.io/{ip}/json")
            data = r.json()
        return {
            "ip": ip,
            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "org": data.get("org"),  # ASN + org name
            "timezone": data.get("timezone"),
            "loc": data.get("loc"),  # lat,lon
            "hostname": data.get("hostname"),
        }

    elif tool_name == "subdomain_enum":
        domain = validate_domain(arguments["domain"])
        subdomains = set()

        # Certificate Transparency (crt.sh)
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    headers={"Accept": "application/json"},
                )
                for entry in r.json():
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(f".{domain}") or sub == domain:
                            subdomains.add(sub)
        except Exception:
            pass

        # subfinder if available
        try:
            raw = await run_cmd(["subfinder", "-d", domain, "-silent"], timeout=60)
            for line in raw.strip().split("\n"):
                if line.strip():
                    subdomains.add(line.strip())
        except Exception:
            pass

        sorted_subs = sorted(subdomains)
        return {
            "domain": domain,
            "total": len(sorted_subs),
            "subdomains": sorted_subs[:200],
        }

    elif tool_name == "ssl_info":
        # Accept both hostname (current schema) and domain (legacy caller compatibility).
        hostname = arguments.get("hostname") or arguments.get("domain")
        if not hostname:
            raise ValueError("ssl_info requires 'hostname' (or legacy 'domain').")
        domain = validate_domain(hostname)
        port = int(arguments.get("port", 443))
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid port: {port}")
        raw = await run_cmd(
            ["openssl", "s_client", "-connect", f"{domain}:{port}", "-showcerts"],
            timeout=20,
        )
        result = {"domain": domain, "port": port, "raw": raw[:4000]}

        # Extract key info
        for line in raw.split("\n"):
            if "subject=" in line:
                result["subject"] = line.split("subject=")[1].strip()
            elif "issuer=" in line:
                result["issuer"] = line.split("issuer=")[1].strip()
            elif "notAfter=" in line:
                result["expires"] = line.split("notAfter=")[1].strip()
            elif "notBefore=" in line:
                result["issued"] = line.split("notBefore=")[1].strip()

        return result

    elif tool_name == "tech_fingerprint":
        url = arguments["url"]
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        validate_url_target(url)

        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            r = await client.get(url)

        headers = dict(r.headers)
        body_preview = r.text[:5000]
        tech = []

        # Fingerprint from headers
        server = headers.get("server", "")
        if server:
            tech.append({"name": "Server", "value": server})

        x_powered = headers.get("x-powered-by", "")
        if x_powered:
            tech.append({"name": "Backend", "value": x_powered})

        if "wp-content" in body_preview:
            tech.append({"name": "CMS", "value": "WordPress"})
        if "drupal" in body_preview.lower():
            tech.append({"name": "CMS", "value": "Drupal"})
        if "joomla" in body_preview.lower():
            tech.append({"name": "CMS", "value": "Joomla"})
        if "react" in body_preview.lower() or "__NEXT_DATA__" in body_preview:
            tech.append({"name": "Frontend", "value": "Next.js/React"})
        if "angular" in body_preview.lower():
            tech.append({"name": "Frontend", "value": "Angular"})

        # Security headers check
        security_headers = {}
        for h in ["strict-transport-security", "content-security-policy",
                  "x-frame-options", "x-content-type-options"]:
            security_headers[h] = headers.get(h, "MISSING")

        return {
            "url": url,
            "status_code": r.status_code,
            "detected_technologies": tech,
            "security_headers": security_headers,
        }

    else:
        raise ValueError(f"Unknown tool: {tool_name}")


def make_response(id: Any, result: Any) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": id, "result": result})


def make_error(id: Any, code: int, message: str) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})


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
                result = await handle_tool(tool_name, arguments)
                return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}})
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
    uvicorn.run(app, host="0.0.0.0", port=8103, log_level="warning")
