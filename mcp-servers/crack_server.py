#!/usr/bin/env python3
"""
SOCIS-AI-PT — Password Cracking MCP Server (HTTP transport)
FastAPI-based MCP server wrapping John the Ripper — closes the loop with hashes other tools dump (sqlmap's DB
password dump, the AD server's AS-REP/kerberoast hashes, NTLM hashes from SMB). Written to match the platform's other
thin-wrapper servers: no third-party MCP-server code, subprocess runs with an argument list only (no shell).

Every run is TIME-BOXED (never an open-ended brute force) and WORDLIST-based only (no mask/incremental mode) —
this is a wordlist-attack tool for testing password strength against a dictionary, not an unbounded cracking rig.

Tools exposed (v1):
  - crack_hash       : run a wordlist attack against one or more hashes (format auto-detected, or specified
                       explicitly — e.g. "NT" for the NTLM hashes the AD server's tools produce)
  - list_formats     : list the hash formats John the Ripper supports (so a caller can pick the right --format)

Offensive: cracking a hash the operator doesn't have authorization to attempt against is exactly the kind of
offensive action gated elsewhere in the platform (Metasploit, AD password spray) — crack_hash is marked offensive
and only runs with the operator's SOCIS_AGENT_ALLOW_OFFENSIVE opt-in. list_formats is safe, read-only.
"""

import asyncio
import json
import os
import re
import sys
import tempfile
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_auth import verify_mcp_auth, mcp_auth_error, validate_file_path, offensive_action_allowed  # type: ignore

app = FastAPI(title="SOCIS Password Cracking MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "crack-mcp"
MCP_PORT = 8132

JOHN_BIN = os.environ.get("JOHN_BINARY", "john")
WORDLIST_DIR = os.environ.get("WORDLIST_DIR", "/usr/share/wordlists")

# Hard ceiling on run time — this is a bounded wordlist pass, not an open-ended crack session.
DEFAULT_TIMEOUT = 300
MAX_TIMEOUT = 1800

# A conservative allow-list of format names users will actually need here (NTLM from AD/SMB, common web-app hashes
# from a sqlmap dump, Unix crypt formats) rather than exposing John's full ~470-format list as free text.
_ALLOWED_FORMATS = {
    "auto", "NT", "LM", "Raw-MD5", "Raw-SHA1", "Raw-SHA256", "Raw-SHA512", "md5crypt", "sha256crypt", "sha512crypt",
    "bcrypt", "krb5pa-sha1", "krb5tgs", "krb5asrep", "mysql", "mysql-sha1", "postgres", "mssql",
}

_HASH_LINE_RE = re.compile(r"^[^\s:]+:.*$")


def _clean_timeout(raw: Any) -> int:
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT
    return max(15, min(v, MAX_TIMEOUT))


def _clean_format(fmt: Any) -> str:
    f = (fmt or "auto").strip()
    if f not in _ALLOWED_FORMATS:
        raise ValueError(f"Unsupported format {f!r}. Allowed: {sorted(_ALLOWED_FORMATS)}")
    return f


def _clean_hashes(raw: Any) -> str:
    """hashes is either a newline-separated block of "user:hash" (or bare hash) lines, or a list of such lines."""
    if isinstance(raw, list):
        lines = [str(x).strip() for x in raw if str(x).strip()]
    elif isinstance(raw, str):
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
    else:
        lines = []
    if not lines:
        raise ValueError("No hashes provided")
    if len(lines) > 5000:
        raise ValueError("Too many hashes in one run (max 5000) — split into multiple calls")
    return "\n".join(lines) + "\n"


def _resolve_wordlist(name: Any) -> str:
    n = (name or "rockyou.txt").strip() if isinstance(name, str) else "rockyou.txt"
    if n.startswith("/"):
        return validate_file_path(n, [WORDLIST_DIR, "/mnt/user-data/uploads", "/tmp"])
    if "/" in n or ".." in n or n.startswith("."):
        raise ValueError(f"Invalid wordlist name: {n!r}")
    path = os.path.join(WORDLIST_DIR, n)
    if not os.path.isfile(path):
        raise ValueError(f"Wordlist not found: {n!r}")
    return path


async def _run(cmd: list[str], timeout: int) -> dict:
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
        return {"success": True, "output": combined[:20000], "exit_code": code}  # John exits non-zero on "no cracks found" too — not a real failure
    except FileNotFoundError:
        return {"success": False, "output": f"[!] Tool not installed: {cmd[0]}", "exit_code": 127}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "output": f"[!] Execution error: {str(e)[:200]}", "exit_code": 1}


# ─────────────────────────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "crack_hash",
        "description": "OFFENSIVE: run a time-boxed wordlist attack (John the Ripper) against one or more password "
                       "hashes. Only runs when the server operator has enabled SOCIS_AGENT_ALLOW_OFFENSIVE. Format is "
                       "auto-detected unless specified (e.g. 'NT' for NTLM hashes from the AD server, 'krb5asrep' for "
                       "AS-REP roast hashes, 'Raw-MD5'/'mysql' for a web-app DB dump).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "hashes": {"description": "Hash(es) to crack: one 'user:hash' (or bare hash) per line, or a list of such lines",
                           "oneOf": [{"type": "array", "items": {"type": "string"}}, {"type": "string"}]},
                "format": {"type": "string", "description": "John format name, or 'auto' to let John detect it", "default": "auto"},
                "wordlist": {"type": "string", "description": "Wordlist filename in the wordlists dir (default rockyou.txt)", "default": "rockyou.txt"},
                "timeout": {"type": "integer", "description": "Hard time limit in seconds for this run", "default": 300},
            },
            "required": ["hashes"],
        },
    },
    {
        "name": "list_formats",
        "description": "List the hash format names John the Ripper supports for crack_hash's 'format' argument in "
                       "this platform (a curated subset covering NTLM/AD, Kerberos, common web-app and DB hashes).",
        "inputSchema": {"type": "object", "properties": {}},
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

async def handle_crack_hash(a: dict) -> dict:
    if not offensive_action_allowed():
        raise ValueError("Password cracking is an exploitation-class action and requires SOCIS_AGENT_ALLOW_OFFENSIVE "
                          "to be enabled on the server (defense-in-depth check — the backend's own gate should "
                          "already have blocked this; seeing this error means this server was called directly).")
    hash_block = _clean_hashes(a.get("hashes"))
    fmt = _clean_format(a.get("format"))
    wordlist = _resolve_wordlist(a.get("wordlist"))
    timeout = _clean_timeout(a.get("timeout"))

    fd, hash_path = tempfile.mkstemp(prefix="crack_", suffix=".hashes")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(hash_block)
    pot_fd, pot_path = tempfile.mkstemp(prefix="crack_", suffix=".pot")
    os.close(pot_fd)
    try:
        cmd = [JOHN_BIN, f"--wordlist={wordlist}", f"--pot={pot_path}"]
        if fmt != "auto":
            cmd.append(f"--format={fmt}")
        cmd.append(hash_path)
        run_result = await _run(cmd, timeout)

        show_cmd = [JOHN_BIN, f"--pot={pot_path}", "--show"]
        if fmt != "auto":
            show_cmd.append(f"--format={fmt}")
        show_cmd.append(hash_path)
        show_result = await _run(show_cmd, min(timeout, 30))

        cracked = []
        for line in (show_result.get("output") or "").splitlines():
            if _HASH_LINE_RE.match(line) and ":" in line and not line.lower().startswith(("password hashes", "guesses:")):
                user, _, rest = line.partition(":")
                cracked.append({"account": user, "cracked_line": line[:300]})

        return {
            "success": True,
            "output": {
                "hashes_submitted": hash_block.count("\n"),
                "cracked_count": len(cracked),
                "cracked": cracked[:500],
                "run_summary": (run_result.get("output") or "")[-2000:],
            },
        }
    finally:
        for p in (hash_path, pot_path):
            try:
                os.unlink(p)
            except OSError:
                pass


async def handle_list_formats(a: dict) -> dict:
    return {"success": True, "output": {"formats": sorted(_ALLOWED_FORMATS)}}


_HANDLERS = {
    "crack_hash": handle_crack_hash,
    "list_formats": handle_list_formats,
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
