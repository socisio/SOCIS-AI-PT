#!/usr/bin/env python3
"""
SOCIS-AI-PT — CVE Lite MCP Server (HTTP transport)
FastAPI-based MCP server wrapping OWASP cve-lite-cli for JavaScript/TypeScript
dependency vulnerability scanning using OSV advisory data.

Port: 8122
"""

import asyncio
import json
import os
import re
import tempfile
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any
from mcp_auth import verify_mcp_auth, mcp_auth_error

app = FastAPI(title="SOCIS CVE Lite MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "cve-lite-mcp"

# Allowed root paths for project scanning (security: path allowlist)
# Override via CVE_LITE_ALLOWED_ROOTS env var (colon-separated paths)
_DEFAULT_ALLOWED_ROOTS = ["/projects", "/tmp", "/workspace", "/app/projects", "/var/cve-lite"]
_allowed_roots_env = os.environ.get("CVE_LITE_ALLOWED_ROOTS", "")
ALLOWED_ROOTS: list[str] = (
    [p.strip() for p in _allowed_roots_env.split(":") if p.strip()]
    if _allowed_roots_env
    else _DEFAULT_ALLOWED_ROOTS
)

TOOLS = [
    {
        "name": "cve_lite_scan",
        "description": (
            "Scan a JavaScript/TypeScript project directory for known dependency vulnerabilities "
            "using OWASP cve-lite-cli with OSV advisory data. Returns structured JSON with "
            "findings, severity levels, CVE aliases, fix suggestions, and affected package paths. "
            "Supports package-lock.json, yarn.lock, pnpm-lock.yaml and package.json manifests."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "project_path": {
                    "type": "string",
                    "description": "Absolute path to the project directory containing package.json or lockfile."
                },
                "min_severity": {
                    "type": "string",
                    "description": "Minimum severity to report: none, low, medium, high, critical.",
                    "default": "medium"
                },
                "all": {
                    "type": "boolean",
                    "description": "Include vulnerabilities in all dependencies (including dev). Default false (prod-focused).",
                    "default": False
                },
                "prod_only": {
                    "type": "boolean",
                    "description": "Only scan production dependencies (exclude devDependencies).",
                    "default": False
                },
                "usage": {
                    "type": "boolean",
                    "description": "Include usage analysis showing which source files import vulnerable packages.",
                    "default": False
                },
                "only_used": {
                    "type": "boolean",
                    "description": "Only report vulnerabilities in packages that are actually imported in source files.",
                    "default": False
                },
                "offline": {
                    "type": "boolean",
                    "description": "Use a local offline SQLite advisory database instead of fetching from OSV.",
                    "default": False
                },
                "offline_db": {
                    "type": "string",
                    "description": "Path to local OSV SQLite database for offline scanning. Required when offline=true.",
                    "default": ""
                },
                "fail_on": {
                    "type": "string",
                    "description": "Treat findings at or above this severity as non-zero exit (informational, does not cause error). Values: none, low, medium, high, critical.",
                    "default": "critical"
                },
                "osv_url": {
                    "type": "string",
                    "description": "Custom OSV API URL (optional, for air-gapped or custom OSV deployments).",
                    "default": ""
                }
            },
            "required": ["project_path"]
        }
    },
    {
        "name": "cve_lite_advisories_sync",
        "description": (
            "Sync the OSV advisory database locally for offline scanning. Downloads ~217K advisories "
            "in under 10 seconds and stores them in a SQLite file. Use the output path with "
            "cve_lite_scan offline=true for air-gapped environments."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "output_path": {
                    "type": "string",
                    "description": "Path where the SQLite advisory DB will be saved. Defaults to /tmp/cve-lite-advisories.sqlite3.",
                    "default": "/tmp/cve-lite-advisories.sqlite3"
                }
            },
            "required": []
        }
    },
    {
        "name": "cve_lite_version",
        "description": "Return the installed version of cve-lite-cli.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
]


def _validate_path(path: str) -> str:
    """Validate that path stays within allowed roots (prevent path traversal)."""
    # Resolve symlinks and normalize
    try:
        resolved = os.path.realpath(path)
    except Exception:
        raise ValueError(f"Invalid path: {path}")

    for root in ALLOWED_ROOTS:
        try:
            resolved_root = os.path.realpath(root)
            # Check if resolved path starts with an allowed root
            if resolved.startswith(resolved_root + os.sep) or resolved == resolved_root:
                return resolved
        except Exception:
            continue

    raise ValueError(
        f"Path '{path}' is not within any allowed root directory. "
        f"Allowed roots: {', '.join(ALLOWED_ROOTS)}"
    )


async def _run_subprocess(cmd: list[str], timeout: int = 120) -> tuple[int, str, str]:
    """Run a subprocess asynchronously and return (returncode, stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return -1, "", f"Process timed out after {timeout}s"

        return proc.returncode or 0, stdout_bytes.decode("utf-8", errors="replace"), stderr_bytes.decode("utf-8", errors="replace")
    except FileNotFoundError:
        return -1, "", "cve-lite binary not found. Install with: npm install -g cve-lite-cli"
    except Exception as e:
        return -1, "", str(e)


async def handle_cve_lite_scan(arguments: dict) -> dict:
    project_path = arguments.get("project_path", "").strip()
    if not project_path:
        return {"success": False, "error": "project_path is required"}

    # Security: validate path against allowlist
    try:
        safe_path = _validate_path(project_path)
    except ValueError as e:
        return {"success": False, "error": str(e)}

    if not os.path.isdir(safe_path):
        return {"success": False, "error": f"Directory not found: {safe_path}"}

    # Build command
    cmd = ["cve-lite", safe_path, "--json"]

    min_severity = arguments.get("min_severity", "medium")
    if min_severity and min_severity != "none":
        cmd += ["--min-severity", min_severity]

    if arguments.get("all"):
        cmd.append("--all")

    if arguments.get("prod_only"):
        cmd.append("--prod-only")

    if arguments.get("usage"):
        cmd.append("--usage")

    if arguments.get("only_used"):
        cmd.append("--only-used")

    fail_on = arguments.get("fail_on", "critical")
    if fail_on and fail_on != "none":
        cmd += ["--fail-on", fail_on]

    offline = arguments.get("offline", False)
    if offline:
        cmd.append("--offline")
        offline_db = arguments.get("offline_db", "").strip()
        if offline_db:
            try:
                safe_db = _validate_path(offline_db)
                cmd += ["--offline-db", safe_db]
            except ValueError as e:
                return {"success": False, "error": str(e)}

    osv_url = arguments.get("osv_url", "").strip()
    if osv_url:
        # Basic URL validation
        if not re.match(r'^https?://', osv_url):
            return {"success": False, "error": "osv_url must start with http:// or https://"}
        cmd += ["--osv-url", osv_url]

    returncode, stdout, stderr = await _run_subprocess(cmd, timeout=120)

    # exit code 1 with JSON on stdout = fail_on threshold reached (not an error)
    # exit code 1 with no JSON / error on stderr = real error
    if returncode == -1:
        return {"success": False, "error": stderr or "Unknown error running cve-lite"}

    # Try to parse JSON output.
    # cve-lite prints informational header lines (e.g. "Advisory source: OSV …")
    # to stdout before the JSON block — strip them by finding the first { or [.
    parsed: dict = {}
    parse_error = ""
    if stdout.strip():
        # Find the first JSON-start character
        json_start = -1
        for i, ch in enumerate(stdout):
            if ch in ('{', '['):
                json_start = i
                break
        json_text = stdout[json_start:].strip() if json_start >= 0 else ""
        if json_text:
            try:
                parsed = json.loads(json_text)
            except json.JSONDecodeError as e:
                parse_error = str(e)
        else:
            parse_error = "no JSON block found in cve-lite output"

    # If returncode != 0 and no JSON parsed, treat as real error
    if returncode not in (0, 1):
        error_msg = stderr.strip() or parse_error or f"cve-lite exited with code {returncode}"
        return {"success": False, "error": error_msg, "exit_code": returncode}

    if not parsed and parse_error:
        return {
            "success": False,
            "error": f"Failed to parse cve-lite JSON output: {parse_error}",
            "raw_output": stdout[:2000],
            "exit_code": returncode,
        }

    # Normalize findings
    findings = parsed.get("findings", [])
    finding_count = parsed.get("findingCount", len(findings))
    package_count = parsed.get("packageCount", 0)

    # Classify fail_on threshold reached
    threshold_reached = returncode == 1 and fail_on and fail_on != "none"

    return {
        "success": True,
        "project_path": safe_path,
        "finding_count": finding_count,
        "package_count": package_count,
        "threshold_reached": threshold_reached,
        "fail_on_severity": fail_on if threshold_reached else None,
        "mode": parsed.get("mode"),
        "source": parsed.get("source"),
        "findings": findings,
        "suggested_fix_commands": parsed.get("suggestedFixCommands", {}),
        "notes": parsed.get("notes", []),
        "warnings": parsed.get("warnings", []),
        "skipped_dependencies": parsed.get("skippedDependencies", []),
        "exit_code": returncode,
    }


async def handle_cve_lite_advisories_sync(arguments: dict) -> dict:
    output_path = arguments.get("output_path", "/tmp/cve-lite-advisories.sqlite3").strip()
    if not output_path:
        output_path = "/tmp/cve-lite-advisories.sqlite3"

    # Ensure output directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir and not os.path.isdir(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as e:
            return {"success": False, "error": f"Cannot create output directory: {e}"}

    # Security: only allow writing to /tmp or allowed roots
    allowed_write_roots = ["/tmp"] + ALLOWED_ROOTS
    path_ok = any(
        os.path.realpath(output_path).startswith(os.path.realpath(r) + os.sep)
        or os.path.realpath(output_path) == os.path.realpath(r)
        for r in allowed_write_roots
    )
    if not path_ok:
        return {
            "success": False,
            "error": f"Output path '{output_path}' is not within an allowed directory."
        }

    cmd = ["cve-lite", "advisories", "sync", "--output", output_path]
    returncode, stdout, stderr = await _run_subprocess(cmd, timeout=120)

    if returncode != 0:
        return {
            "success": False,
            "error": stderr.strip() or f"advisories sync failed with exit code {returncode}",
            "exit_code": returncode,
        }

    db_size = None
    if os.path.isfile(output_path):
        db_size = os.path.getsize(output_path)

    return {
        "success": True,
        "output_path": output_path,
        "db_size_bytes": db_size,
        "message": stdout.strip() or "Advisory database synced successfully.",
    }


async def handle_cve_lite_version(_arguments: dict) -> dict:
    returncode, stdout, stderr = await _run_subprocess(["cve-lite", "--version"], timeout=15)
    if returncode != 0:
        return {
            "success": False,
            "error": stderr.strip() or "Failed to get cve-lite version",
        }
    version_str = stdout.strip() or stderr.strip()
    return {"success": True, "version": version_str}


async def handle_tool(tool_name: str, arguments: dict) -> Any:
    if tool_name == "cve_lite_scan":
        return await handle_cve_lite_scan(arguments)
    elif tool_name == "cve_lite_advisories_sync":
        return await handle_cve_lite_advisories_sync(arguments)
    elif tool_name == "cve_lite_version":
        return await handle_cve_lite_version(arguments)
    else:
        return {"error": f"Unknown tool: {tool_name}"}


# ─── MCP JSON-RPC 2.0 handler ─────────────────────────────────

@app.post("/mcp")
async def mcp_endpoint(request: Request):
    auth_error = verify_mcp_auth(request)
    if not auth_error:
        return mcp_auth_error()

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None})

    method = body.get("method", "")
    params = body.get("params", {})
    req_id = body.get("id")

    def ok(result: Any):
        return JSONResponse({"jsonrpc": "2.0", "result": result, "id": req_id})

    def err(code: int, msg: str):
        return JSONResponse({"jsonrpc": "2.0", "error": {"code": code, "message": msg}, "id": req_id})

    if method == "initialize":
        return ok({
            "protocolVersion": MCP_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": "1.0.0"},
        })

    if method == "tools/list":
        return ok({"tools": TOOLS})

    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        try:
            result = await handle_tool(tool_name, arguments)
            return ok({
                "content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}],
                "isError": not result.get("success", True),
            })
        except Exception as exc:
            return ok({
                "content": [{"type": "text", "text": json.dumps({"error": str(exc), "success": False})}],
                "isError": True,
            })

    return err(-32601, f"Method not found: {method}")


@app.get("/health")
async def health():
    return {"status": "ok", "server": SERVER_NAME}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8122, log_level="warning")
