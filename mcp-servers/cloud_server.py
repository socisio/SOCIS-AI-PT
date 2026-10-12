#!/usr/bin/env python3
"""
SOCIS-AI-PT — Cloud Recon MCP Server (HTTP transport)
FastAPI-based MCP server for unauthenticated, read-only cloud misconfiguration recon: public storage buckets (S3 /
Azure Blob / GCS), cloud-provider fingerprinting, and SSRF-via-metadata exposure checks on a target web application.

All checks are read-only HTTP requests (HEAD/GET) — no cloud credentials are used or required, and nothing here ever
connects outbound to a cloud metadata service IP directly: metadata_check sends a normal validated-target web request
and inspects whether the *target's own response* leaks metadata-endpoint content (an SSRF indicator), it never dials
169.254.169.254 itself. Written to match the platform's other thin-wrapper servers (ad_server.py, nmap_server.py, …):
no third-party MCP-server code, shared mcp_auth.py for token auth + scope validation, httpx for all network I/O
(no subprocess, no shell).

Tools exposed (v1):
  - bucket_enum        : check whether a named bucket exists and whether it is publicly listable/readable, across
                          AWS S3, Azure Blob, and Google Cloud Storage
  - bucket_guess        : try common bucket-name permutations derived from a company/domain name
  - cloud_fingerprint   : identify which cloud provider (AWS/Azure/GCP/Cloudflare/other) a target is hosted behind,
                          via response headers and DNS/CNAME patterns
  - metadata_check      : test whether a target web app's responses leak cloud instance-metadata content (an SSRF
                          indicator) — the request goes to the TARGET, never to a metadata-service IP directly

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
from mcp_auth import verify_mcp_auth, mcp_auth_error, validate_scan_target, validate_url_target  # type: ignore

app = FastAPI(title="SOCIS Cloud Recon MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "cloud-mcp"
MCP_PORT = 8127

DEFAULT_TIMEOUT = 20
MAX_TIMEOUT = 60

# ─────────────────────────────────────────────────────────────────────────────
# Validation helpers
# ─────────────────────────────────────────────────────────────────────────────

# A bucket/company name is an identifier, never a host to connect to directly — but we still constrain its character
# set so it can only ever be interpolated into the FIXED, hardcoded provider URL templates below, never anywhere else.
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,62}[a-z0-9]$", re.IGNORECASE)


def _clean_name(name: str, field: str = "name") -> str:
    n = (name or "").strip().lower()
    if not n or not _NAME_RE.match(n):
        raise ValueError(f"Invalid {field}: must be 3-64 chars, letters/digits/dot/hyphen only")
    return n


def _clean_timeout(raw: Any) -> int:
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT
    return max(5, min(v, MAX_TIMEOUT))


async def _http_check(url: str, method: str = "GET", timeout: int = DEFAULT_TIMEOUT) -> dict:
    """One read-only HTTP request. Never raises — connection errors, timeouts, and non-2xx are all normal, meaningful
    results for recon (a 404 vs a 200 vs a connection refusal all say something different about a bucket's state)."""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            resp = await client.request(method, url)
            return {
                "reachable": True,
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body_snippet": resp.text[:2000] if method == "GET" else "",
            }
    except httpx.TimeoutException:
        return {"reachable": False, "error": "timeout"}
    except httpx.ConnectError:
        return {"reachable": False, "error": "connection failed (likely does not exist / DNS NXDOMAIN)"}
    except Exception as e:  # noqa: BLE001
        return {"reachable": False, "error": str(e)[:200]}


# Fixed, hardcoded URL templates per provider — the bucket NAME is the only variable, and it is already constrained by
# _NAME_RE, so this can never become a request to an attacker-chosen host.
_PROVIDER_URLS = {
    "aws_s3": "https://{name}.s3.amazonaws.com/",
    "azure_blob": "https://{name}.blob.core.windows.net/{name}?restype=container&comp=list",
    "gcs": "https://storage.googleapis.com/{name}/",
}


async def _check_bucket_one(provider: str, name: str, timeout: int) -> dict:
    url = _PROVIDER_URLS[provider].format(name=name)
    result = await _http_check(url, "GET", timeout)
    if not result.get("reachable"):
        return {"provider": provider, "exists": False, "public": False, "detail": result.get("error", "unreachable")}
    status = result["status"]
    # 200 on a list/GET = public listing; 403 = exists but access denied (private, still confirms the name is taken);
    # 404/NoSuchBucket = does not exist.
    body = result.get("body_snippet", "")
    not_found = status == 404 or "NoSuchBucket" in body or "BlobNotFound" in body or "ContainerNotFound" in body
    exists = not not_found
    public = status == 200 and exists
    return {
        "provider": provider,
        "exists": exists,
        "public_listing": public,
        "http_status": status,
        "detail": "publicly listable" if public else ("exists, access denied" if exists else "does not exist"),
    }


# ─────────────────────────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "bucket_enum",
        "description": "Check whether a named cloud storage bucket exists and whether it is publicly listable, across "
                       "AWS S3, Azure Blob Storage, and Google Cloud Storage. Read-only, no credentials used.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Bucket / container name to check, e.g. 'acme-backups'"},
                "providers": {"type": "array", "items": {"type": "string", "enum": ["aws_s3", "azure_blob", "gcs"]},
                              "description": "Which providers to check (default: all three)"},
                "timeout": {"type": "integer", "description": "Per-request timeout in seconds", "default": 20},
            },
            "required": ["name"],
        },
    },
    {
        "name": "bucket_guess",
        "description": "Derive and check common bucket-name permutations from a company or domain name (e.g. 'acme' "
                       "-> acme, acme-backup, acme-prod, acme-dev, acme-assets, acme-static, acme-uploads, ...). "
                       "Read-only recon across all three cloud providers.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "base": {"type": "string", "description": "Company or domain name to derive permutations from"},
                "limit": {"type": "integer", "description": "Max permutations to try", "default": 15},
                "timeout": {"type": "integer", "description": "Per-request timeout in seconds", "default": 15},
            },
            "required": ["base"],
        },
    },
    {
        "name": "cloud_fingerprint",
        "description": "Identify which cloud provider (AWS / Azure / GCP / Cloudflare / other) a target web host is "
                       "running behind, from its response headers and hosting patterns. Read-only, one request to "
                       "the target.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host or URL, e.g. example.com or https://example.com"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 20},
            },
            "required": ["target"],
        },
    },
    {
        "name": "metadata_check",
        "description": "Test whether a target web application's own responses leak cloud instance-metadata content — "
                       "an indicator of an SSRF vulnerability reachable through that app. This sends a normal request "
                       "to the TARGET only; it never connects to a cloud metadata-service IP directly.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL to probe, e.g. https://example.com/fetch?url="},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 20},
            },
            "required": ["target"],
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

async def handle_bucket_enum(a: dict) -> dict:
    name = _clean_name(a["name"], "bucket name")
    timeout = _clean_timeout(a.get("timeout"))
    providers = a.get("providers") or list(_PROVIDER_URLS.keys())
    providers = [p for p in providers if p in _PROVIDER_URLS] or list(_PROVIDER_URLS.keys())
    results = await asyncio.gather(*[_check_bucket_one(p, name, timeout) for p in providers])
    found = [r for r in results if r["exists"]]
    return {
        "success": True,
        "output": {"bucket": name, "checked": len(results), "found": len(found), "results": results},
    }


async def handle_bucket_guess(a: dict) -> dict:
    base = _clean_name(a["base"], "base name")
    # strip a leading www. and any TLD-looking suffix for a cleaner base, e.g. "example.com" -> "example"
    stem = re.sub(r"^www\.", "", base).split(".")[0]
    limit = max(1, min(int(a.get("limit", 15) or 15), 30))
    timeout = _clean_timeout(a.get("timeout", 15))
    suffixes = ["", "-backup", "-backups", "-prod", "-production", "-dev", "-staging", "-assets", "-static",
                "-uploads", "-media", "-data", "-files", "-public", "-private", "-internal", "-logs", "-cdn",
                "-images", "-www", "-app"]
    candidates = [f"{stem}{suf}" for suf in suffixes][:limit]
    all_results = []
    for cand in candidates:
        try:
            name = _clean_name(cand)
        except ValueError:
            continue
        res = await asyncio.gather(*[_check_bucket_one(p, name, timeout) for p in _PROVIDER_URLS])
        found = [r for r in res if r["exists"]]
        if found:
            all_results.append({"name": name, "matches": found})
    return {
        "success": True,
        "output": {"base": stem, "candidates_tried": len(candidates), "found": len(all_results), "results": all_results},
    }


_CLOUD_HEADER_SIGNATURES = [
    ("AWS", ["x-amz-", "amazonaws"]),
    ("Azure", ["x-azure-", "azurewebsites", "windows.net"]),
    ("GCP", ["x-goog-", "googleusercontent", "google frontend"]),
    ("Cloudflare", ["cf-ray", "cloudflare"]),
    ("Akamai", ["akamai"]),
    ("Fastly", ["x-served-by", "fastly"]),
]


async def handle_cloud_fingerprint(a: dict) -> dict:
    target = validate_scan_target(a["target"])
    timeout = _clean_timeout(a.get("timeout"))
    url = target if str(a["target"]).startswith("http") else f"https://{target}"
    result = await _http_check(url, "GET", timeout)
    if not result.get("reachable"):
        return {"success": False, "output": {"target": target, "error": result.get("error", "unreachable")}}
    headers_blob = " ".join(f"{k}:{v}" for k, v in result.get("headers", {}).items()).lower()
    matches = [name for name, sigs in _CLOUD_HEADER_SIGNATURES if any(sig.lower() in headers_blob for sig in sigs)]
    return {
        "success": True,
        "output": {
            "target": target,
            "http_status": result.get("status"),
            "server_header": result.get("headers", {}).get("server", ""),
            "likely_providers": matches or ["unknown / not detected from headers"],
        },
    }


# Content that would only ever appear in real AWS/Azure/GCP instance-metadata responses — used to detect an SSRF leak
# in the TARGET's own output, never fetched directly by this server.
_METADATA_MARKERS = [
    "ami-id", "instance-id", "iam/security-credentials", "placement/availability-zone",  # AWS IMDS
    "compute/metadata", "service-accounts", "project/project-id",                          # GCP metadata
    "instance/compute/metadata", "scheduledevents",                                        # Azure IMDS
]


async def handle_metadata_check(a: dict) -> dict:
    url = validate_url_target(a["target"])
    timeout = _clean_timeout(a.get("timeout"))
    result = await _http_check(url, "GET", timeout)
    if not result.get("reachable"):
        return {"success": False, "output": {"target": url, "error": result.get("error", "unreachable")}}
    body = (result.get("body_snippet") or "").lower()
    leaked = [m for m in _METADATA_MARKERS if m in body]
    return {
        "success": True,
        "output": {
            "target": url,
            "http_status": result.get("status"),
            "metadata_leak_indicators_found": len(leaked),
            "indicators": leaked,
            "note": "The target's own response was inspected for metadata-service content; "
                    "169.254.169.254 was never contacted directly by this check.",
        },
    }


_HANDLERS = {
    "bucket_enum": handle_bucket_enum,
    "bucket_guess": handle_bucket_guess,
    "cloud_fingerprint": handle_cloud_fingerprint,
    "metadata_check": handle_metadata_check,
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
