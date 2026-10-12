#!/usr/bin/env python3
"""
SOCIS-AI-PT — API Security MCP Server (HTTP transport)
FastAPI-based MCP server for modern API attack-surface recon: GraphQL introspection and risky-query detection,
OpenAPI/Swagger spec discovery, and common API misconfiguration checks (CORS, verbose errors, missing rate-limit
headers). Complements the existing jwt_server (token-level attacks) and ffuf/gobuster (generic path fuzzing) —
this server is schema- and protocol-aware for the modern API surface (GraphQL/REST), not a generic fuzzer.

Written to match the platform's other thin-wrapper servers: no third-party MCP-server code, shared mcp_auth.py for
token auth + scope validation, httpx for all network I/O (no subprocess, no shell).

Tools exposed (v1):
  - graphql_introspect     : send a standard introspection query, parse the returned schema, flag exposed mutations
                              and types that look sensitive (e.g. containing "user", "admin", "password", "token")
  - graphql_query_risk     : when introspection is disabled, probe a small set of common query/mutation names to see
                              which ones the endpoint still accepts (recon only — sends queries, never mutations with
                              real side-effecting arguments)
  - openapi_discover       : check common OpenAPI/Swagger spec paths and, if found, list the exposed endpoints
  - api_misconfig_check    : check CORS policy (wildcard origin + credentials, reflected origin), verbose error
                              disclosure (stack traces in error responses), and missing rate-limit headers

All four are safe, read-only recon — none are offensive, none need the operator opt-in.
"""

import asyncio
import json
import os
import re
import sys
import uvicorn
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_auth import verify_mcp_auth, mcp_auth_error, validate_url_target  # type: ignore

app = FastAPI(title="SOCIS API Security MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "api-security-mcp"
MCP_PORT = 8129

DEFAULT_TIMEOUT = 20
MAX_TIMEOUT = 60

_SENSITIVE_NAME_HINTS = ("user", "admin", "password", "secret", "token", "credential", "key", "auth", "role",
                         "permission", "account", "payment", "billing", "internal", "debug")


def _clean_timeout(raw: Any) -> int:
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT
    return max(5, min(v, MAX_TIMEOUT))


async def _post_json(url: str, body: dict, timeout: int, headers: dict | None = None) -> dict:
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            resp = await client.post(url, json=body, headers=headers or {})
            try:
                parsed = resp.json()
            except ValueError:
                parsed = None
            return {"reachable": True, "status": resp.status_code, "headers": dict(resp.headers),
                     "json": parsed, "text": resp.text[:4000]}
    except httpx.TimeoutException:
        return {"reachable": False, "error": "timeout"}
    except httpx.ConnectError:
        return {"reachable": False, "error": "connection failed"}
    except Exception as e:  # noqa: BLE001
        return {"reachable": False, "error": str(e)[:200]}


async def _get(url: str, timeout: int, headers: dict | None = None) -> dict:
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            resp = await client.get(url, headers=headers or {})
            return {"reachable": True, "status": resp.status_code, "headers": dict(resp.headers),
                     "text": resp.text[:8000]}
    except httpx.TimeoutException:
        return {"reachable": False, "error": "timeout"}
    except httpx.ConnectError:
        return {"reachable": False, "error": "connection failed"}
    except Exception as e:  # noqa: BLE001
        return {"reachable": False, "error": str(e)[:200]}


# Standard GraphQL introspection query (read-only — it only asks the schema to describe itself).
_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields { name }
    }
  }
}
"""

# A handful of common, low-risk query/mutation NAMES to probe when introspection is disabled — this sends the name
# with an empty/minimal argument set and only looks at whether the server recognises it (a validation-error response
# still reveals the field exists), never a real mutation with meaningful arguments.
_COMMON_FIELD_PROBES = ["user", "users", "me", "viewer", "login", "createUser", "updateUser", "deleteUser",
                        "resetPassword", "admin", "config", "settings"]

_OPENAPI_PATHS = ["/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs", "/api-docs", "/swagger/v1/swagger.json",
                   "/api/swagger.json", "/api/openapi.json", "/.well-known/openapi.json", "/docs/openapi.json"]


# ─────────────────────────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "graphql_introspect",
        "description": "Send a standard GraphQL introspection query to an endpoint and parse the schema it returns, "
                       "flagging mutations and types whose names look sensitive (user, admin, password, token, …). "
                       "Read-only — introspection only asks the schema to describe itself.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "GraphQL endpoint URL, e.g. https://api.example.com/graphql"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 20},
            },
            "required": ["target"],
        },
    },
    {
        "name": "graphql_query_risk",
        "description": "When introspection is disabled, probe a small set of common query/mutation field names "
                       "(user, login, createUser, resetPassword, admin, …) to see which ones the endpoint still "
                       "recognises. Sends only minimal/empty arguments — recon only, no real mutation side effects.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "GraphQL endpoint URL"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 20},
            },
            "required": ["target"],
        },
    },
    {
        "name": "openapi_discover",
        "description": "Check common OpenAPI/Swagger specification paths on a target and, if one is found, list the "
                       "exposed endpoints, methods, and whether authentication appears to be required for each.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Base URL of the target, e.g. https://api.example.com"},
                "timeout": {"type": "integer", "description": "Per-path timeout in seconds", "default": 10},
            },
            "required": ["target"],
        },
    },
    {
        "name": "api_misconfig_check",
        "description": "Check an API endpoint for common misconfigurations: permissive/reflected CORS policy "
                       "(especially combined with credentials), verbose error disclosure (stack traces in error "
                       "responses), and missing rate-limit headers.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "API endpoint URL to check"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 20},
            },
            "required": ["target"],
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

async def handle_graphql_introspect(a: dict) -> dict:
    target = validate_url_target(a["target"])
    timeout = _clean_timeout(a.get("timeout"))
    result = await _post_json(target, {"query": _INTROSPECTION_QUERY}, timeout)
    if not result.get("reachable"):
        return {"success": False, "output": {"target": target, "error": result.get("error", "unreachable")}}
    body = result.get("json")
    if not isinstance(body, dict) or "data" not in body or not body.get("data", {}).get("__schema"):
        return {"success": True, "output": {"target": target, "introspection_enabled": False,
                                             "note": "Introspection appears disabled or this is not a GraphQL endpoint."}}
    schema = body["data"]["__schema"]
    types = schema.get("types") or []
    sensitive_types = []
    mutation_fields = []
    for t in types:
        name = (t.get("name") or "")
        if not name or name.startswith("__"):
            continue
        if any(h in name.lower() for h in _SENSITIVE_NAME_HINTS):
            sensitive_types.append(name)
        if t.get("kind") == "OBJECT" and name == (schema.get("mutationType") or {}).get("name"):
            mutation_fields = [f.get("name") for f in (t.get("fields") or []) if f.get("name")]
    return {
        "success": True,
        "output": {
            "target": target,
            "introspection_enabled": True,
            "total_types": len([t for t in types if not (t.get("name") or "").startswith("__")]),
            "mutation_count": len(mutation_fields),
            "mutations": mutation_fields[:40],
            "sensitive_looking_types": sorted(set(sensitive_types))[:30],
        },
    }


async def handle_graphql_query_risk(a: dict) -> dict:
    target = validate_url_target(a["target"])
    timeout = _clean_timeout(a.get("timeout"))
    recognised = []
    for field in _COMMON_FIELD_PROBES:
        query = "{ " + field + " }"
        result = await _post_json(target, {"query": query}, timeout)
        if not result.get("reachable"):
            continue
        body = result.get("json")
        if not isinstance(body, dict):
            continue
        errors = body.get("errors") or []
        # "Cannot query field X" means the field does NOT exist; any other error (e.g. a missing-argument complaint,
        # an auth error) means the server recognised the field name.
        unknown_field = any("cannot query field" in str(e.get("message", "")).lower() for e in errors)
        if not unknown_field:
            recognised.append(field)
    return {
        "success": True,
        "output": {"target": target, "probed": len(_COMMON_FIELD_PROBES), "recognised_fields": recognised},
    }


async def handle_openapi_discover(a: dict) -> dict:
    base = validate_url_target(a["target"]).rstrip("/")
    timeout = _clean_timeout(a.get("timeout", 10))
    found = []
    for path in _OPENAPI_PATHS:
        result = await _get(base + path, timeout)
        if result.get("reachable") and result.get("status") == 200:
            text = result.get("text", "")
            try:
                spec = json.loads(text)
            except ValueError:
                continue
            paths = spec.get("paths") or {}
            endpoints = []
            for p, methods in list(paths.items())[:60]:
                for method in methods:
                    if method.lower() in ("get", "post", "put", "delete", "patch"):
                        op = methods[method] or {}
                        requires_auth = bool(op.get("security")) or bool(spec.get("security"))
                        endpoints.append({"path": p, "method": method.upper(), "requires_auth": requires_auth})
            found.append({"spec_path": path, "title": spec.get("info", {}).get("title", ""),
                          "endpoint_count": len(endpoints), "endpoints": endpoints[:50]})
    return {
        "success": True,
        "output": {"target": base, "specs_found": len(found), "specs": found,
                   "paths_checked": len(_OPENAPI_PATHS)},
    }


async def handle_api_misconfig_check(a: dict) -> dict:
    target = validate_url_target(a["target"])
    timeout = _clean_timeout(a.get("timeout"))
    findings = []
    # CORS check: send a cross-origin preflight-style request with a clearly foreign Origin.
    probe_origin = "https://socis-cors-probe.invalid"
    result = await _get(target, timeout, headers={"Origin": probe_origin})
    if result.get("reachable"):
        headers = {k.lower(): v for k, v in result.get("headers", {}).items()}
        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")
        if acao == "*":
            findings.append({"issue": "CORS wildcard origin", "severity": "medium",
                             "detail": "Access-Control-Allow-Origin: * — any site can read responses (not combined with credentials, but still broad)."})
        if acao == probe_origin:
            sev = "high" if acac.lower() == "true" else "medium"
            findings.append({"issue": "CORS reflects arbitrary Origin", "severity": sev,
                             "detail": f"The server reflected our made-up Origin back verbatim"
                                       + (" WITH Access-Control-Allow-Credentials: true — a cross-site attacker can read authenticated responses." if sev == "high" else ".")})
        # verbose error check: hit the endpoint in a way likely to trigger a 4xx/5xx and look for stack-trace markers
        body = result.get("text", "") if "text" in result else ""
    err_probe = await _get(target.rstrip("/") + "/%00%ff", timeout)
    if err_probe.get("reachable"):
        body = (err_probe.get("text") or "")
        stack_markers = ["Traceback (most recent call last)", "at java.", "Exception in thread", "stack trace",
                         "<b>Fatal error</b>", "System.Exception", "NullPointerException"]
        if any(m in body for m in stack_markers):
            findings.append({"issue": "Verbose error disclosure", "severity": "medium",
                             "detail": "An error response appears to include a stack trace or internal framework detail."})
        headers2 = {k.lower(): v for k, v in err_probe.get("headers", {}).items()}
        if not any(h in headers2 for h in ("x-ratelimit-limit", "ratelimit-limit", "retry-after")):
            findings.append({"issue": "No rate-limit headers observed", "severity": "low",
                             "detail": "Neither X-RateLimit-* nor RateLimit-* nor Retry-After was present on this response "
                                       "(a single check — absence here doesn't prove there is no rate limiting elsewhere)."})
    return {"success": True, "output": {"target": target, "findings_count": len(findings), "findings": findings}}


_HANDLERS = {
    "graphql_introspect": handle_graphql_introspect,
    "graphql_query_risk": handle_graphql_query_risk,
    "openapi_discover": handle_openapi_discover,
    "api_misconfig_check": handle_api_misconfig_check,
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
