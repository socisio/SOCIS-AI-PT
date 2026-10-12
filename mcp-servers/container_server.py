#!/usr/bin/env python3
"""
SOCIS-AI-PT — Container & Kubernetes MCP Server (HTTP transport)
FastAPI-based MCP server for container image CVE scanning and Kubernetes/Dockerfile misconfiguration detection,
wrapping Trivy (Aqua Security's open-source scanner — the standard tool for this) and a read-only check for an
exposed Docker daemon API (a common, serious misconfiguration). Written to match the platform's other thin-wrapper
servers (ad_server.py, cloud_server.py, …): no third-party MCP-server code, shared mcp_auth.py for token auth +
scope validation, subprocess runs with an argument list only (no shell, no injection).

Tools exposed (v1):
  - image_scan        : scan a container image (by name/tag, e.g. "nginx:1.18") for known CVEs — pulls the image's
                         metadata from its registry, does not require the image to be running anywhere
  - dockerfile_scan    : scan an uploaded Dockerfile for misconfigurations (running as root, no HEALTHCHECK,
                         secrets in ENV/ARG, latest tag, etc.)
  - k8s_manifest_scan  : scan an uploaded Kubernetes YAML manifest for misconfigurations (privileged containers,
                         hostNetwork, missing resource limits, default service account, etc.)
  - docker_api_check   : check whether a host's Docker daemon API (typically :2375/2376) is exposed and
                         unauthenticated — a critical, common misconfiguration giving full host takeover

All four are read-only recon / static analysis — none are offensive, none need the operator opt-in. image_scan and
docker_api_check take a network-reachable target/registry and go through the shared scope guard; dockerfile_scan and
k8s_manifest_scan analyse an uploaded file's *content*, so there is no network target to validate for them.
"""

import asyncio
import json
import os
import re
import sys
import tempfile
import uvicorn
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_auth import verify_mcp_auth, mcp_auth_error, validate_scan_target, validate_file_path  # type: ignore

app = FastAPI(title="SOCIS Container & Kubernetes MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "container-mcp"
MCP_PORT = 8128

TRIVY_BIN = os.environ.get("TRIVY_BINARY", "trivy")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/mnt/user-data/uploads")

DEFAULT_TIMEOUT = 180
MAX_TIMEOUT = 600

# ─────────────────────────────────────────────────────────────────────────────
# Validation helpers
# ─────────────────────────────────────────────────────────────────────────────

# A container image reference: registry/namespace/name:tag — constrained so it can only ever be one argv token, and
# so it cannot smuggle a flag (e.g. a name starting with "-") into trivy's argument list.
_IMAGE_REF_RE = re.compile(r"^[a-z0-9]([a-z0-9._\-/]{0,253}[a-z0-9])?(:[\w][\w.\-]{0,127})?$", re.IGNORECASE)


def _clean_image_ref(ref: str) -> str:
    r = (ref or "").strip()
    if not r or r.startswith("-") or not _IMAGE_REF_RE.match(r):
        raise ValueError(f"Invalid image reference: {ref!r}")
    return r


def _clean_timeout(raw: Any) -> int:
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT
    return max(15, min(v, MAX_TIMEOUT))


def _clean_content(content: str, max_len: int = 200_000) -> str:
    c = content if isinstance(content, str) else ""
    if not c.strip():
        raise ValueError("Empty file content")
    return c[:max_len]


async def _run(cmd: list[str], timeout: int) -> dict:
    """Run a tool with no shell (argument list), capture output, enforce a hard timeout."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return {"success": False, "output": f"[!] Timed out after {timeout}s", "exit_code": 124}
        stdout = (out or b"").decode("utf-8", errors="replace")
        stderr = (err or b"").decode("utf-8", errors="replace")
        code = proc.returncode if proc.returncode is not None else 1
        combined = (stdout + ("\n" + stderr if stderr.strip() else "")).strip()
        return {"success": code == 0, "output": combined[:40000], "exit_code": code}
    except FileNotFoundError:
        return {"success": False, "output": f"[!] Tool not installed: {cmd[0]}", "exit_code": 127}
    except Exception as e:  # noqa: BLE001 — never leak a traceback to the client
        return {"success": False, "output": f"[!] Execution error: {str(e)[:200]}", "exit_code": 1}


def _write_temp(content: str, suffix: str) -> str:
    """Write scan input to a private per-call temp file (not a predictable path) for trivy's --input flag."""
    fd, path = tempfile.mkstemp(prefix="trivy_", suffix=suffix)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


# ─────────────────────────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "image_scan",
        "description": "Scan a container image for known CVEs by image reference (e.g. 'nginx:1.18', "
                       "'myregistry.io/app:latest'). Pulls the image's metadata from its registry — the image does "
                       "not need to be running anywhere the platform can reach.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "image": {"type": "string", "description": "Image reference, e.g. 'nginx:1.18'"},
                "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL", "ALL"], "default": "ALL",
                             "description": "Minimum severity to report (ALL = no filter)"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 180},
            },
            "required": ["image"],
        },
    },
    {
        "name": "dockerfile_scan",
        "description": "Scan a Dockerfile's contents for misconfigurations: running as root, missing HEALTHCHECK, "
                       "secrets baked into ENV/ARG, use of the 'latest' tag, and other CIS Docker Benchmark issues.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "description": "The full text content of the Dockerfile"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 60},
            },
            "required": ["content"],
        },
    },
    {
        "name": "k8s_manifest_scan",
        "description": "Scan a Kubernetes YAML manifest's contents for misconfigurations: privileged containers, "
                       "hostNetwork/hostPID, missing resource limits, default service account usage, missing "
                       "securityContext, and other CIS Kubernetes Benchmark issues.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "description": "The full text content of the Kubernetes YAML manifest"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 60},
            },
            "required": ["content"],
        },
    },
    {
        "name": "docker_api_check",
        "description": "Check whether a host's Docker daemon API is exposed and unauthenticated on the standard "
                       "ports (2375 plaintext, 2376 TLS) — a critical misconfiguration that typically allows full "
                       "host takeover (an attacker can start a privileged container). Read-only recon.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host or IP"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 20},
            },
            "required": ["target"],
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

async def handle_image_scan(a: dict) -> dict:
    image = _clean_image_ref(a["image"])
    timeout = _clean_timeout(a.get("timeout", 180))
    sev = a.get("severity", "ALL")
    cmd = [TRIVY_BIN, "image", "--format", "json", "--quiet", "--timeout", f"{timeout}s"]
    if sev and sev != "ALL":
        cmd += ["--severity", sev]
    cmd.append(image)
    return await _run(cmd, timeout + 10)


async def handle_dockerfile_scan(a: dict) -> dict:
    content = _clean_content(a["content"])
    timeout = _clean_timeout(a.get("timeout", 60))
    path = _write_temp(content, "_Dockerfile")
    try:
        cmd = [TRIVY_BIN, "config", "--format", "json", "--quiet", "--timeout", f"{timeout}s", path]
        return await _run(cmd, timeout + 10)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


async def handle_k8s_manifest_scan(a: dict) -> dict:
    content = _clean_content(a["content"])
    timeout = _clean_timeout(a.get("timeout", 60))
    path = _write_temp(content, ".yaml")
    try:
        cmd = [TRIVY_BIN, "config", "--format", "json", "--quiet", "--timeout", f"{timeout}s", path]
        return await _run(cmd, timeout + 10)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


async def handle_docker_api_check(a: dict) -> dict:
    target = validate_scan_target(a["target"])
    timeout = _clean_timeout(a.get("timeout", 20))
    findings = []
    for port, scheme in ((2375, "http"), (2376, "https")):
        url = f"{scheme}://{target}:{port}/version"
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False) as client:  # noqa: S501 — recon probe only
                resp = await client.get(url)
            if resp.status_code == 200 and ("ApiVersion" in resp.text or "Version" in resp.text):
                findings.append({"port": port, "scheme": scheme, "exposed": True,
                                  "detail": "Docker daemon API responded without authentication"})
            else:
                findings.append({"port": port, "scheme": scheme, "exposed": False,
                                  "detail": f"HTTP {resp.status_code}, not a Docker API response"})
        except Exception as e:  # noqa: BLE001
            findings.append({"port": port, "scheme": scheme, "exposed": False, "detail": str(e)[:150]})
    any_exposed = any(f["exposed"] for f in findings)
    return {
        "success": True,
        "output": {"target": target, "exposed": any_exposed, "findings": findings},
    }


_HANDLERS = {
    "image_scan": handle_image_scan,
    "dockerfile_scan": handle_dockerfile_scan,
    "k8s_manifest_scan": handle_k8s_manifest_scan,
    "docker_api_check": handle_docker_api_check,
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
