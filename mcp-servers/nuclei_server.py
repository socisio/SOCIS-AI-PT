#!/usr/bin/env python3
"""
SOCIS-AI-PT — Nuclei MCP Server (HTTP transport)
FastAPI-based MCP server for template-based vulnerability scanning.
"""

import json
import asyncio
import re
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any
from mcp_auth import verify_mcp_auth, mcp_auth_error

# Allowlists for template_type parameters — enforced at handler level
_ALLOWED_EXPOSED_TYPES = {"exposures", "files", "misconfiguration", "vulnerabilities"}
_ALLOWED_DNS_TYPES    = {"zone-transfer", "takeover", "cname", "a", "mx", "ns"}
_ALLOWED_SSL_TYPES    = {"heartbleed", "cancer", "expire", "weak", "self-signed"}
# Safe regex for user-supplied template tags / relative paths (no absolute, no traversal)
_TEMPLATE_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9,._\-/]*$')
# Allowed severity values
_ALLOWED_SEVERITIES = {
    "critical,high,medium,low,info", "critical,high,medium", "critical,high",
    "critical", "high,medium,low", "all",
}


def _validate_template(value: str) -> str:
    """Validate a user-supplied nuclei template path or tag name.
    Only relative, non-traversal paths are accepted."""
    value = value.strip()
    if not value:
        return ""
    if not _TEMPLATE_RE.match(value):
        raise ValueError(f"Invalid template path/tag {value!r}. Use relative paths or tag names only.")
    if "." in value.split("/") or ".." in value:
        raise ValueError(f"Path traversal detected in template value: {value!r}")
    return value


def _validate_severity(value: str) -> str:
    """Ensure severity string is one of the allowed enum values."""
    if value not in _ALLOWED_SEVERITIES:
        return "critical,high,medium"  # safe default
    return value

app = FastAPI(title="SOCIS Nuclei MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "nuclei-mcp"

TOOLS = [
    {
        "name": "nuclei_scan",
        "description": "Run Nuclei vulnerability scanner against a target URL or IP. Returns structured findings with CVEs and severity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target":        {"type": "string",  "description": "Target URL or IP (e.g. https://example.com or 192.168.1.1)"},
                "severity":      {"type": "string",  "description": "Filter by severity", "enum": ["critical,high,medium,low,info", "critical,high,medium", "critical,high", "critical", "high,medium,low", "all"], "default": "critical,high,medium"},
                "timeout":       {"type": "integer", "description": "Scan timeout in seconds (60-1800)", "default": 600},
                "templates":     {"type": "string",  "description": "Template path or tag (e.g. 'cves/' or 'exposures/' or '-tags cve')", "default": ""},
                "rate_limit":    {"type": "integer", "description": "Max requests per second", "default": 100},
                "concurrency":   {"type": "integer", "description": "Number of templates to run concurrently (nuclei -c flag)", "default": 25},
                "retries":       {"type": "integer", "description": "Number of retries for failed requests", "default": 1},
                "proxy":         {"type": "string",  "description": "HTTP/SOCKS5 proxy URL e.g. http://127.0.0.1:8080"},
                "headers":       {"type": "string",  "description": "Extra HTTP headers, newline-separated e.g. 'Authorization: Bearer token'"},
                "exclude_tags":  {"type": "string",  "description": "Exclude templates with these tags, comma-separated e.g. dos,fuzz"},
                "no_interactsh": {"type": "boolean", "description": "Disable interactsh OOB server (use for isolated networks)", "default": False},
            },
            "required": ["target"]
        }
    },
    {
        "name": "nuclei_cve_scan",
        "description": "Run Nuclei with only CVE templates against a target.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "year": {
                    "type": "integer",
                    "description": "CVE year filter (e.g. 2024 for CVE-2024-*)",
                    "default": 0
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "list_templates",
        "description": "List available Nuclei template categories.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Filter by category (e.g. cves, exposures, misconfiguration)",
                    "default": ""
                }
            }
        }
    },
    {
        "name": "nuclei_tech_detect",
        "description": "Detect technologies running on a target using Nuclei tech templates.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"}
            },
            "required": ["target"]
        }
    },
    {
        "name": "nuclei_exposed_scan",
        "description": "Scan for exposed files, configs, and sensitive data (exposures, files, configs).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "template_type": {
                    "type": "string",
                    "description": "Template type to scan",
                    "enum": ["exposures", "files", "misconfiguration", "vulnerabilities"],
                    "default": "exposures"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "nuclei_dns_scan",
        "description": "Run DNS vulnerability scan (dns zone transfer, subdomains, takeovers).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "template_type": {
                    "type": "string",
                    "description": "DNS template type",
                    "enum": ["zone-transfer", "takeover", "cname", "a", "mx", "ns"],
                    "default": "zone-transfer"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "nuclei_ssl_scan",
        "description": "Scan SSL/TLS configurations for vulnerabilities.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "template_type": {
                    "type": "string",
                    "description": "SSL template type",
                    "enum": ["heartbleed", "cancer", "expire", "weak", "self-signed"],
                    "default": "heartbleed"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "nuclei_update_templates",
        "description": "Update Nuclei template definitions to latest version.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]


def parse_nuclei_output(raw: str) -> list[dict]:
    """Parse nuclei JSONL output into structured findings."""
    findings = []
    for line in raw.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            findings.append({
                "template_id": data.get("template-id"),
                "name": data.get("info", {}).get("name"),
                "severity": data.get("info", {}).get("severity"),
                "description": data.get("info", {}).get("description"),
                "tags": data.get("info", {}).get("tags", []),
                "matched_at": data.get("matched-at"),
                "extracted_results": data.get("extracted-results", []),
                "curl_command": data.get("curl-command"),
                "cve_id": data.get("info", {}).get("classification", {}).get("cve-id"),
                "cvss_score": data.get("info", {}).get("classification", {}).get("cvss-score"),
            })
        except json.JSONDecodeError:
            # Nuclei non-JSON line (progress, etc.)
            pass
    return findings


async def run_nuclei(target: str, extra_args: list[str], timeout_secs: int = 840) -> dict:
    """Execute nuclei and return parsed findings."""
    if not re.match(r'^[a-zA-Z0-9.\-_:/?=&%#+@]+$', target):
        raise ValueError(f"Invalid target format: {target}")

    # SSRF / internal-scope guard (fix H-5).
    from mcp_auth import validate_url_target
    validate_url_target(target)

    # -duc        : disable update-check so startup is instant
    # -timeout 10 : per-request HTTP timeout (nuclei flag, in seconds)
    # -bulk-size 25: templates per host batch — keeps memory bounded
    # timeout_secs: overall asyncio cap — must be > nuclei's own wall-clock limit
    cmd = [
        "nuclei",
        "-target", target,
        "-j",           # JSONL output to stdout
        "-silent",
        "-duc",         # disable update check at startup
        "-timeout", "10",      # per-request HTTP timeout
        "-bulk-size", "25",    # templates per batch
        *extra_args,
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_secs)
    except asyncio.TimeoutError:
        try:
            proc.kill()
            await asyncio.wait_for(proc.wait(), timeout=5)
        except Exception:
            pass
        raise RuntimeError(f"Nuclei scan timed out after {timeout_secs} seconds")

    raw = stdout.decode("utf-8", errors="replace")
    stderr_txt = stderr.decode("utf-8", errors="replace")
    findings = parse_nuclei_output(raw)

    result: dict = {
        "target": target,
        "total": len(findings),
        "findings": findings,
    }
    # Surface stderr if nuclei reported errors or returned nothing
    if stderr_txt.strip() and not findings:
        result["scan_info"] = stderr_txt[-800:]
    if proc.returncode not in (0, None) and not findings:
        result["exit_code"] = proc.returncode
        if not result.get("scan_info") and stderr_txt.strip():
            result["scan_info"] = stderr_txt[-800:]
    return result


async def handle_tool_call(tool_name: str, arguments: dict) -> Any:
    if tool_name == "nuclei_scan":
        target = arguments["target"]
        severity = _validate_severity(arguments.get("severity", "critical,high,medium"))
        rate_limit = max(1, min(500, int(arguments.get("rate_limit", 100))))
        concurrency = max(1, min(100, int(arguments.get("concurrency", 25))))
        retries = max(0, min(5, int(arguments.get("retries", 1))))
        proxy = str(arguments.get("proxy", "") or "").strip()
        headers_raw = str(arguments.get("headers", "") or "").strip()
        exclude_tags = str(arguments.get("exclude_tags", "") or "").strip()
        no_interactsh = bool(arguments.get("no_interactsh", False))
        templates = _validate_template(arguments.get("templates", ""))  # raises on bad input

        args = ["-severity", severity, "-rate-limit", str(rate_limit),
                "-c", str(concurrency), "-retries", str(retries)]
        if templates:
            # Only allow relative paths (validated above) — tag names have no slash
            if "/" in templates or templates.endswith(".yaml"):
                args += ["-t", templates]
            else:
                args += ["-tags", templates]
        if proxy:
            args += ["-proxy", proxy]
        if headers_raw:
            for h in headers_raw.splitlines():
                h = h.strip()
                if h and ":" in h:
                    args += ["-H", h]
        if exclude_tags:
            args += ["-etags", exclude_tags]
        if no_interactsh:
            args += ["-no-interactsh"]
        return await run_nuclei(target, args, timeout_secs=600)

    elif tool_name == "nuclei_cve_scan":
        target = arguments["target"]
        year = int(arguments.get("year", 0))
        if year and not (1990 <= year <= 2030):
            raise ValueError(f"CVE year out of range: {year}")
        # nuclei v3 moved CVE templates under http/cves/; fall back to cves/ for older installs
        import os
        import subprocess
        _tmpl_dir = subprocess.run(
            ["nuclei", "-version"], capture_output=True, text=True
        )
        _home = os.path.expanduser("~")
        _cve_v3 = os.path.join(_home, "nuclei-templates", "http", "cves")
        _cve_v2 = os.path.join(_home, "nuclei-templates", "cves")
        if os.path.isdir(_cve_v3):
            args = ["-t", "http/cves/"]
        elif os.path.isdir(_cve_v2):
            args = ["-t", "cves/"]
        else:
            args = ["-tags", "cve"]  # fallback: run by tag
        if year:
            args += ["-tags", f"cve-{year}"]
        return await run_nuclei(target, args, timeout_secs=600)

    elif tool_name == "list_templates":
        category = _validate_template(arguments.get("category", ""))  # raises on bad input
        cmd = ["nuclei", "-list-templates"]
        if category:
            cmd += ["-t", category]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        lines = stdout.decode().strip().split("\n")
        categories = list(set(l.split("/")[0] for l in lines if "/" in l))
        return {"categories": sorted(categories), "total_templates": len(lines)}

    elif tool_name == "nuclei_tech_detect":
        target = arguments["target"]
        return await run_nuclei(target, ["-t", "technologies/", "-severity", "info"], timeout_secs=300)

    elif tool_name == "nuclei_exposed_scan":
        target = arguments["target"]
        template_type = arguments.get("template_type", "exposures")
        if template_type not in _ALLOWED_EXPOSED_TYPES:
            raise ValueError(f"Invalid template_type {template_type!r}. Allowed: {sorted(_ALLOWED_EXPOSED_TYPES)}")
        return await run_nuclei(target, ["-t", f"{template_type}/", "-severity", "critical,high,medium"])

    elif tool_name == "nuclei_dns_scan":
        target = arguments["target"]
        template_type = arguments.get("template_type", "zone-transfer")
        if template_type not in _ALLOWED_DNS_TYPES:
            raise ValueError(f"Invalid template_type {template_type!r}. Allowed: {sorted(_ALLOWED_DNS_TYPES)}")
        return await run_nuclei(target, ["-t", f"dns/{template_type}"])

    elif tool_name == "nuclei_ssl_scan":
        target = arguments["target"]
        template_type = arguments.get("template_type", "heartbleed")
        if template_type not in _ALLOWED_SSL_TYPES:
            raise ValueError(f"Invalid template_type {template_type!r}. Allowed: {sorted(_ALLOWED_SSL_TYPES)}")
        return await run_nuclei(target, ["-t", f"ssl/{template_type}"])
    
    elif tool_name == "nuclei_update_templates":
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-ut", "-up",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        return {"updated": proc.returncode == 0, "output": stdout.decode()[:500]}

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
                result = await handle_tool_call(tool_name, arguments)
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}
                })
            except Exception as e:
                err_msg = str(e) or f"[{type(e).__name__}]"
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32000, "message": err_msg}
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
    uvicorn.run(app, host="0.0.0.0", port=8102, log_level="warning")
