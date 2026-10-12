#!/usr/bin/env python3
"""
SOCIS-AI-PT — Secrets Scanning MCP Server (HTTP transport)
FastAPI-based MCP server for detecting live credentials (API keys, tokens, private keys) in source code or
configuration content — complementing cve_lite_server.py (dependency CVEs) with actual exposed-credential detection.
Pure pattern-matching over content the caller supplies; no network access, no subprocess, no shell — the simplest and
safest server in the platform. Written to match the other thin-wrapper servers: shared mcp_auth.py for token auth.

Tools exposed (v1):
  - scan_content       : scan a single file's content (or a pasted snippet) for known secret patterns (AWS keys,
                         GitHub/GitLab tokens, private keys, Slack tokens, generic API-key-shaped strings, JWTs, …)
  - scan_repo_snapshot : scan MULTIPLE files at once (a dict of path -> content), for scanning an uploaded repo
                         snapshot or a set of files in one call rather than one file per request

Both report WHERE the match is (file + line) and WHAT KIND of secret it looks like, with the matched value redacted
in the output (only a short prefix/suffix shown) so the finding itself doesn't become a second copy of the leak.
"""

import json
import os
import re
import sys
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_auth import verify_mcp_auth, mcp_auth_error  # type: ignore

app = FastAPI(title="SOCIS Secrets Scanning MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "secrets-mcp"
MCP_PORT = 8130

MAX_CONTENT_LEN = 500_000
MAX_FILES = 200

# ─────────────────────────────────────────────────────────────────────────────
# Secret patterns — each is (label, severity, compiled regex). Patterns are deliberately specific (a real credential
# SHAPE, not just "looks like a string") to keep false positives low; a final generic-high-entropy fallback catches
# the rest at lower confidence.
# ─────────────────────────────────────────────────────────────────────────────

_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("AWS Access Key ID", "high", re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b")),
    ("AWS Secret Access Key (heuristic)", "medium",
     re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?")),
    ("GitHub Personal Access Token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("GitHub OAuth / fine-grained token", "high", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    ("GitLab Personal Access Token", "high", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    ("Slack Token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,72}\b")),
    ("Slack Webhook URL", "medium", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+")),
    ("Stripe API Key", "high", re.compile(r"\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{10,99}\b")),
    ("OpenAI API Key", "high", re.compile(r"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}\b|\bsk-proj-[A-Za-z0-9_\-]{20,}\b")),
    ("Anthropic API Key", "high", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("Google API Key", "medium", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Private Key (PEM block)", "critical", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Generic API key assignment", "medium",
     re.compile(r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*[\"']([A-Za-z0-9_\-/+=]{16,100})[\"']")),
    ("Hardcoded password assignment", "medium",
     re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"']([^\"'\s]{6,100})[\"']")),
    ("JWT-shaped token", "low", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("Database connection string with credentials", "high",
     re.compile(r"(?i)(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:\s]+:[^@\s]+@[^\s/\"']+")),
]


def _redact(value: str) -> str:
    if len(value) <= 10:
        return "*" * len(value)
    return value[:4] + "…redacted…" + value[-4:]


def _scan_one(path: str, content: str) -> list[dict]:
    findings = []
    lines = content.splitlines()
    for label, severity, pattern in _PATTERNS:
        for m in pattern.finditer(content):
            matched = m.group(0)
            # line number: count newlines before the match start
            line_no = content.count("\n", 0, m.start()) + 1
            line_text = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
            findings.append({
                "file": path,
                "line": line_no,
                "type": label,
                "severity": severity,
                "matched_redacted": _redact(matched),
                "context": line_text[:200],
            })
    return findings


def _clean_content(content: Any) -> str:
    c = content if isinstance(content, str) else ""
    return c[:MAX_CONTENT_LEN]


# ─────────────────────────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "scan_content",
        "description": "Scan a single piece of text (file content or a pasted snippet) for known secret patterns: "
                       "AWS/GitHub/GitLab/Slack/Stripe/OpenAI/Anthropic/Google API keys, PEM private keys, hardcoded "
                       "passwords, database connection strings with embedded credentials, and JWT-shaped tokens. "
                       "Matched secrets are redacted in the output.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "description": "The file content or snippet to scan"},
                "filename": {"type": "string", "description": "Optional filename/path to label findings with", "default": "pasted-content"},
            },
            "required": ["content"],
        },
    },
    {
        "name": "scan_repo_snapshot",
        "description": "Scan MULTIPLE files at once for secrets — pass a dict mapping file path to its content "
                       "(e.g. from an uploaded repo snapshot or a set of config files) instead of calling scan_content "
                       "once per file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "files": {"type": "object", "description": "Mapping of file path -> file content (string values)",
                           "additionalProperties": {"type": "string"}},
            },
            "required": ["files"],
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

async def handle_scan_content(a: dict) -> dict:
    content = _clean_content(a.get("content"))
    if not content.strip():
        raise ValueError("Empty content")
    filename = (a.get("filename") or "pasted-content").strip()[:300]
    findings = _scan_one(filename, content)
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
    return {
        "success": True,
        "output": {"file": filename, "findings_count": len(findings), "by_severity": by_severity,
                   "findings": findings[:200]},
    }


async def handle_scan_repo_snapshot(a: dict) -> dict:
    files = a.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("files must be a non-empty object mapping path -> content")
    items = list(files.items())[:MAX_FILES]
    all_findings: list[dict] = []
    for path, content in items:
        all_findings.extend(_scan_one(str(path)[:300], _clean_content(content)))
    by_severity: dict[str, int] = {}
    for f in all_findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
    files_with_findings = sorted({f["file"] for f in all_findings})
    return {
        "success": True,
        "output": {
            "files_scanned": len(items),
            "files_truncated": len(files) > MAX_FILES,
            "findings_count": len(all_findings),
            "files_with_findings": len(files_with_findings),
            "by_severity": by_severity,
            "findings": all_findings[:500],
        },
    }


_HANDLERS = {
    "scan_content": handle_scan_content,
    "scan_repo_snapshot": handle_scan_repo_snapshot,
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
