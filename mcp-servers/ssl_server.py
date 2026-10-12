#!/usr/bin/env python3
"""
SOCIS-AI-PT — SSL Labs MCP Server (HTTP transport)
FastAPI-based MCP server for TLS/SSL grading via SSL Labs API.
"""

import asyncio
import json as _json_top
import httpx
from target_scope import ssl_labs_skip_reason  # type: ignore
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any

app = FastAPI(title="SOCIS SSL Labs MCP Server", docs_url=None)

MCP_VERSION = "1.1"
SERVER_NAME = "ssl_mcp"
_SSLLABS_BASE = "https://api.ssllabs.com/api/v3"

# Try to import mcp_auth - if not available, create dummy
try:
    from mcp_auth import verify_mcp_auth, mcp_auth_error
except ImportError:
    def verify_mcp_auth(request: Request) -> bool:
        return True
    def mcp_auth_error():
        return JSONResponse({"error": "Unauthorized"}, status_code=401)


TOOLS = [
    {
        "name": "check_ssl",
        "description": (
            "Check SSL/TLS configuration and grade using the SSL Labs API. "
            "Returns detailed grading, protocol info, and security findings."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string", 
                    "description": "Hostname to check (e.g. example.com, google.com)"
                },
                "hide_results": {
                    "type": "boolean",
                    "description": "Hide results from public list (default: true)",
                    "default": True
                }
            },
            "required": ["hostname"],
        },
    },
    {
        "name": "get_ssl_grade",
        "description": "Quick SSL grade check - returns only the letter grade (A-F or T).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string", 
                    "description": "Hostname to check"
                }
            },
            "required": ["hostname"],
        },
    },
    {
        "name": "check_ssl_vulnerabilities",
        "description": "Check for specific SSL/TLS vulnerabilities (Heartbleed, POODLE, etc.).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hostname": {
                    "type": "string", 
                    "description": "Hostname to check"
                }
            },
            "required": ["hostname"],
        },
    },
]


async def handle_check_ssl(arguments: dict) -> str:
    import json as _json
    hostname = arguments["hostname"]
    hide = arguments.get("hide_results", True)

    async with httpx.AsyncClient(timeout=120) as client:
        # Start new assessment
        await client.get(f"{_SSLLABS_BASE}/analyze", params={"host": hostname, "startNew": "on", "all": "done", "hideResults": str(hide).lower()})
        data = {}

        # Poll for results (max 90 seconds)
        for _ in range(9):
            await asyncio.sleep(10)
            resp = await client.get(f"{_SSLLABS_BASE}/analyze", params={"host": hostname, "all": "done"})
            data = resp.json()
            if data.get("status") == "READY":
                break
            if data.get("status") == "ERROR":
                return _json.dumps({"error": data.get("message", "Unknown SSL Labs error"), "host": hostname})

    if data.get("status") != "READY":
        return _json.dumps({"error": f"Assessment still in progress: {data.get('status', 'unknown')}. Try again later.", "host": hostname})

    endpoints = data.get("endpoints", [])
    if not endpoints:
        return _json.dumps({"error": "No endpoints returned by SSL Labs", "host": hostname})

    endpoint_results = []
    for ep in endpoints:
        grade = ep.get("grade", "N/A")
        ip = ep.get("ipAddress", "?")
        msg = ep.get("statusMessage", "")

        ep_result: dict = {"ip": ip, "grade": grade, "status": msg}

        if ep.get("details"):
            d = ep["details"]
            protocols = d.get("protocols", [{}])
            proto = protocols[0] if protocols else {}
            ep_result["protocol"] = (proto.get("name", "") + " " + proto.get("version", "")).strip() or "?"
            ep_result["key_exchange"] = d.get("keyExchange") or d.get("keyExch") or "?"
            ep_result["cipher_strength"] = d.get("cipherStrength")
            ep_result["forward_secrecy"] = bool(d.get("forwardSecrecy"))
            ep_result["hsts"] = d.get("hstsPolicy", {}).get("status", "absent")
            ep_result["hsts_max_age"] = d.get("hstsPolicy", {}).get("maxAge")
            ep_result["hsts_preload"] = bool(d.get("hstsPolicy", {}).get("preloaded", False))
            ep_result["vulnerabilities"] = {
                "heartbleed": bool(d.get("heartbleed", False)),
                "poodle": bool(d.get("poodle", False)),
                "rc4": bool(d.get("rc4", False)),
                "ticketbleed": bool(d.get("ticketbleed", False)),
                "freak": bool(d.get("freak", False)),
                "logjam": bool(d.get("logjam", False)),
                "crime": bool(d.get("crime", False)),
                "beast": bool(d.get("beast", False)),
            }

        endpoint_results.append(ep_result)

    # Summarise to top-level for easy frontend parsing
    first = endpoint_results[0]
    result = {
        "host": hostname,
        "grade": first.get("grade", "N/A"),
        "ip": first.get("ip", "?"),
        "status": first.get("status", ""),
        "protocol": first.get("protocol", "?"),
        "key_exchange": first.get("key_exchange"),
        "cipher_strength": first.get("cipher_strength"),
        "forward_secrecy": first.get("forward_secrecy"),
        "hsts": first.get("hsts"),
        "hsts_max_age": first.get("hsts_max_age"),
        "hsts_preload": first.get("hsts_preload"),
        "vulnerabilities": first.get("vulnerabilities", {}),
        "endpoints_count": len(endpoint_results),
        "all_grades": [e.get("grade", "N/A") for e in endpoint_results],
        "endpoints": endpoint_results,
    }
    return _json.dumps(result)


async def handle_get_ssl_grade(arguments: dict) -> str:
    hostname = arguments["hostname"]
    
    async with httpx.AsyncClient(timeout=120) as client:
        await client.get(f"{_SSLLABS_BASE}/analyze", params={"host": hostname, "startNew": "on", "all": "done"})
        data = {}
        
        for _ in range(9):
            await asyncio.sleep(10)
            resp = await client.get(f"{_SSLLABS_BASE}/analyze", params={"host": hostname, "all": "done"})
            data = resp.json()
            if data.get("status") == "READY":
                break
    
    if data.get("status") != "READY":
        return f"T (Assessment in progress)"
    
    endpoints = data.get("endpoints", [])
    if not endpoints:
        return "T (No endpoints)"
    
    grade = endpoints[0].get("grade", "T")
    return grade


async def handle_check_ssl_vulnerabilities(arguments: dict) -> str:
    import json as _json
    hostname = arguments["hostname"]

    async with httpx.AsyncClient(timeout=120) as client:
        await client.get(f"{_SSLLABS_BASE}/analyze", params={"host": hostname, "startNew": "on", "all": "done"})
        data = {}

        for _ in range(9):
            await asyncio.sleep(10)
            resp = await client.get(f"{_SSLLABS_BASE}/analyze", params={"host": hostname, "all": "done"})
            data = resp.json()
            if data.get("status") == "READY":
                break

    if data.get("status") != "READY":
        return _json.dumps({"error": f"Status: {data.get('status', 'unknown')}", "host": hostname})

    endpoints = data.get("endpoints", [])
    if not endpoints:
        return _json.dumps({"error": "No endpoints found", "host": hostname})

    ep = endpoints[0]
    if not ep.get("details"):
        return _json.dumps({"error": "No detailed results available", "host": hostname})

    d = ep["details"]

    def to_bool(val):
        if val is True: return True
        if val is False: return False
        if val == 1: return True
        if val == 0: return False
        return bool(val)

    vulns = {
        "heartbleed": to_bool(d.get("heartbleed")),
        "poodle":     to_bool(d.get("poodle")),
        "ticketbleed": to_bool(d.get("ticketbleed")),
        "freak":      to_bool(d.get("freak")),
        "logjam":     to_bool(d.get("logjam")),
        "crime":      to_bool(d.get("crime")),
        "beast":      to_bool(d.get("beast")),
        "rc4":        to_bool(d.get("rc4")),
    }
    vulnerable_items = [k for k, v in vulns.items() if v]

    return _json.dumps({
        "host": hostname,
        "ip": ep.get("ipAddress", "?"),
        "grade": ep.get("grade", "N/A"),
        "vulnerable": len(vulnerable_items) > 0,
        "vulnerable_count": len(vulnerable_items),
        "vulnerable_items": vulnerable_items,
        "vulnerabilities": vulns,
    })


async def handle_tool(tool_name: str, arguments: dict) -> Any:
    # SSL Labs is a PUBLIC web service: it can only assess public host names. Never send it an IP address or an internal name (that discloses
    # internal addressing to a third party, can never succeed and used to cost a 90 second poll). Answer at once with a clear "skipped".
    why = ssl_labs_skip_reason(str(arguments.get("hostname", "")))
    if why:
        return _json_top.dumps({"skipped": True, "reason": why, "host": arguments.get("hostname")})
    if tool_name == "check_ssl":
        return await handle_check_ssl(arguments)
    elif tool_name == "get_ssl_grade":
        return await handle_get_ssl_grade(arguments)
    elif tool_name == "check_ssl_vulnerabilities":
        return await handle_check_ssl_vulnerabilities(arguments)
    else:
        raise ValueError(f"Unknown tool: {tool_name}")


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
                result = await handle_tool(tool_name, arguments)
                content = result if isinstance(result, str) else result
                return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": str(content)}]}})
            except ValueError as e:
                return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": str(e)}}, status_code=400)
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
    uvicorn.run(app, host="0.0.0.0", port=8112, log_level="warning")
