#!/usr/bin/env python3
"""
SOCIS-AI-PT — Active Directory MCP Server (HTTP transport)
FastAPI-based MCP server for Active Directory / internal-network enumeration and credential testing.

Wraps NetExec (the maintained successor to CrackMapExec) and kerbrute — standard, trusted offensive-security CLIs —
in the same thin-wrapper style as every other SOCIS MCP server (nmap_server.py, sqlmap_server.py, …). No third-party
MCP-server code is run: this file is written to match the platform's own 22 servers, uses the shared mcp_auth.py for
token auth + scope validation, and executes the underlying tools with create_subprocess_exec (argument list, never a
shell) so there is no command injection.

Tools exposed (v1):
  - smb_enum        : SMB share / session / host-info enumeration (safe recon)
  - ldap_enum       : domain users / groups / computers over LDAP (safe recon)
  - user_enum       : validate which usernames exist via Kerberos pre-auth (kerbrute) (recon)
  - null_session    : anonymous SMB/LDAP access check (safe recon)
  - password_spray  : ONE password across MANY users (OFFENSIVE — gated by the manifest's offensive flag + the
                      server operator's SOCIS_AGENT_ALLOW_OFFENSIVE opt-in, exactly like Metasploit/sqlmap shells)
  - asrep_roast     : list AS-REP-roastable accounts (no pre-auth) (OFFENSIVE — gated)

Every target host is passed through validate_scan_target() (the shared scope guard: refuses loopback, link-local,
cloud-metadata, and anything outside the operator-allowed private ranges), so these tools can never be pointed at the
platform's own infrastructure or an unauthorised host.
"""

import asyncio
import json
import os
import re
import sys
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_auth import verify_mcp_auth, mcp_auth_error, validate_scan_target, validate_file_path, offensive_action_allowed  # type: ignore

app = FastAPI(title="SOCIS Active Directory MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "ad-mcp"
MCP_PORT = 8126

# Binaries. NetExec installs as `nxc` (and sometimes legacy `crackmapexec`); kerbrute as `kerbrute`.
NXC_BIN = os.environ.get("NXC_BINARY", "nxc")
KERBRUTE_BIN = os.environ.get("KERBRUTE_BINARY", "kerbrute")
WORDLIST_DIR = os.environ.get("WORDLIST_DIR", "/usr/share/wordlists")

# A conservative default so a spray/enum can't hammer a DC or hang the worker.
DEFAULT_TIMEOUT = 300
MAX_TIMEOUT = 1800

# ─────────────────────────────────────────────────────────────────────────────
# Input validation helpers (defence-in-depth on top of validate_scan_target)
# ─────────────────────────────────────────────────────────────────────────────

# Usernames, domains, passwords for AD are not arbitrary shell input; we still constrain them so nothing odd reaches
# the argument list, and (critically) they are always passed as separate argv entries, never interpolated into a shell.
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._@\-\\$]{1,256}$")
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9.\-]{1,255}$")


def _clean_target(target: str) -> str:
    """Scope-check and normalise a target host/IP (raises ValueError if out of scope)."""
    return validate_scan_target(target)


def _clean_domain(domain: str) -> str:
    d = (domain or "").strip()
    if not d:
        return ""
    if not _DOMAIN_RE.match(d):
        raise ValueError(f"Invalid domain: {d!r}")
    return d


def _clean_username(username: str) -> str:
    u = (username or "").strip()
    if not u:
        return ""
    if not _USERNAME_RE.match(u):
        raise ValueError(f"Invalid username: {u!r}")
    return u


def _clean_timeout(raw: Any) -> int:
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT
    return max(10, min(v, MAX_TIMEOUT))


def _resolve_wordlist(name: str) -> str:
    """A user list / password list must be a bare filename inside WORDLIST_DIR, or an absolute path inside an allowed
    directory — never arbitrary path traversal."""
    name = (name or "").strip()
    if not name:
        return ""
    if name.startswith("/"):
        # absolute path: confine to the shared wordlist / uploads dirs via the shared validator
        return validate_file_path(name, [WORDLIST_DIR, "/mnt/user-data/uploads", "/tmp"])
    if "/" in name or ".." in name or name.startswith("."):
        raise ValueError(f"Invalid wordlist name: {name!r}")
    path = os.path.join(WORDLIST_DIR, name)
    if not os.path.isfile(path):
        raise ValueError(f"Wordlist not found: {name!r}")
    return path


async def _run(cmd: list[str], timeout: int) -> dict:
    """Run a tool with no shell (argument list), capture output, enforce a hard timeout. Returns a structured dict the
    report/UI layer can render; a non-zero exit or timeout is reported as a clean failure, never raised to the client."""
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
        return {"success": code == 0, "output": combined[:20000], "exit_code": code}
    except FileNotFoundError:
        return {"success": False, "output": f"[!] Tool not installed: {cmd[0]}", "exit_code": 127}
    except Exception as e:  # noqa: BLE001 — never leak a traceback to the client
        return {"success": False, "output": f"[!] Execution error: {str(e)[:200]}", "exit_code": 1}


def _nxc_auth_args(arguments: dict) -> list[str]:
    """Shared NetExec auth flags from the node config — all as separate argv entries."""
    args: list[str] = []
    username = _clean_username(arguments.get("username", ""))
    password = arguments.get("password", "")
    nt_hash = arguments.get("hash", "")
    domain = _clean_domain(arguments.get("domain", ""))
    if username:
        args += ["-u", username]
    if nt_hash:
        # a hash is hex[:hex]; constrain it so nothing odd reaches argv
        if not re.match(r"^[A-Fa-f0-9:]{1,100}$", str(nt_hash)):
            raise ValueError("Invalid NT hash")
        args += ["-H", str(nt_hash)]
    elif password is not None and str(password) != "":
        args += ["-p", str(password)]
    else:
        # no creds -> anonymous / null attempt; NetExec accepts empty -u '' -p ''
        args += ["-u", "", "-p", ""]
    if domain:
        args += ["-d", domain]
    return args


# ─────────────────────────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "smb_enum",
        "description": "Enumerate a Windows/SMB host: OS, hostname, domain, signing status, shares and sessions. Safe "
                       "recon — read-only. Works anonymously or with credentials.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host or CIDR, e.g. 10.0.0.10 or 10.0.0.0/24"},
                "username": {"type": "string", "description": "Optional username"},
                "password": {"type": "string", "description": "Optional password"},
                "hash": {"type": "string", "description": "Optional NT/NTLM hash (instead of a password)"},
                "domain": {"type": "string", "description": "Optional AD domain, e.g. corp.local"},
                "shares": {"type": "boolean", "description": "Also enumerate accessible shares", "default": True},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 300},
            },
            "required": ["target"],
        },
    },
    {
        "name": "ldap_enum",
        "description": "Enumerate domain users, groups and computers over LDAP. Safe recon — read-only. Needs valid "
                       "credentials for most environments; some allow anonymous bind.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain controller host/IP"},
                "username": {"type": "string", "description": "Username"},
                "password": {"type": "string", "description": "Password"},
                "hash": {"type": "string", "description": "NT hash (instead of a password)"},
                "domain": {"type": "string", "description": "AD domain, e.g. corp.local"},
                "collect": {"type": "string", "enum": ["users", "groups", "computers"], "default": "users",
                            "description": "What to enumerate"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 300},
            },
            "required": ["target"],
        },
    },
    {
        "name": "user_enum",
        "description": "Validate which usernames exist in a domain via Kerberos pre-authentication (kerbrute userenum). "
                       "Recon — it only checks existence, it does not attempt passwords.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain controller host/IP"},
                "domain": {"type": "string", "description": "AD domain, e.g. corp.local"},
                "userlist": {"type": "string", "description": "Username wordlist filename (in the wordlists dir) or an "
                                                             "allowed absolute path"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 300},
            },
            "required": ["target", "domain", "userlist"],
        },
    },
    {
        "name": "null_session",
        "description": "Check for anonymous (null-session) SMB/LDAP access — a common misconfiguration that exposes "
                       "users and shares without credentials. Safe recon.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host/IP"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 120},
            },
            "required": ["target"],
        },
    },
    {
        "name": "password_spray",
        "description": "OFFENSIVE: try ONE password against MANY usernames over SMB (low-and-slow to avoid lockouts). "
                       "Only runs when the server operator has enabled SOCIS_AGENT_ALLOW_OFFENSIVE and the target is "
                       "authorised. Use a single password and a user list.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host/IP or domain controller"},
                "password": {"type": "string", "description": "The single password to spray"},
                "userlist": {"type": "string", "description": "Username wordlist filename or allowed absolute path"},
                "domain": {"type": "string", "description": "AD domain, e.g. corp.local"},
                "continue_on_success": {"type": "boolean", "description": "Keep going after a hit", "default": True},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 600},
            },
            "required": ["target", "password", "userlist"],
        },
    },
    {
        "name": "asrep_roast",
        "description": "OFFENSIVE: list accounts that do not require Kerberos pre-authentication (AS-REP roastable) and "
                       "capture their crackable hashes. Gated by SOCIS_AGENT_ALLOW_OFFENSIVE.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain controller host/IP"},
                "domain": {"type": "string", "description": "AD domain, e.g. corp.local"},
                "username": {"type": "string", "description": "Optional username (if you already have one)"},
                "password": {"type": "string", "description": "Optional password"},
                "userlist": {"type": "string", "description": "Optional username wordlist to test"},
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 300},
            },
            "required": ["target", "domain"],
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

async def handle_smb_enum(a: dict) -> dict:
    target = _clean_target(a["target"])
    timeout = _clean_timeout(a.get("timeout"))
    cmd = [NXC_BIN, "smb", target] + _nxc_auth_args(a)
    if a.get("shares", True):
        cmd.append("--shares")
    cmd += ["--sessions"]
    return await _run(cmd, timeout)


async def handle_ldap_enum(a: dict) -> dict:
    target = _clean_target(a["target"])
    timeout = _clean_timeout(a.get("timeout"))
    collect = a.get("collect", "users")
    flag = {"users": "--users", "groups": "--groups", "computers": "--computers"}.get(collect, "--users")
    cmd = [NXC_BIN, "ldap", target] + _nxc_auth_args(a) + [flag]
    return await _run(cmd, timeout)


async def handle_user_enum(a: dict) -> dict:
    target = _clean_target(a["target"])
    domain = _clean_domain(a["domain"])
    if not domain:
        raise ValueError("domain is required for user enumeration")
    userlist = _resolve_wordlist(a["userlist"])
    timeout = _clean_timeout(a.get("timeout"))
    cmd = [KERBRUTE_BIN, "userenum", "--dc", target, "-d", domain, userlist]
    return await _run(cmd, timeout)


async def handle_null_session(a: dict) -> dict:
    target = _clean_target(a["target"])
    timeout = _clean_timeout(a.get("timeout", 120))
    # anonymous bind: empty user/pass
    cmd = [NXC_BIN, "smb", target, "-u", "", "-p", "", "--shares"]
    return await _run(cmd, timeout)


async def handle_password_spray(a: dict) -> dict:
    if not offensive_action_allowed():
        raise ValueError("Password spraying is an exploitation-class action and requires SOCIS_AGENT_ALLOW_OFFENSIVE "
                          "to be enabled on the server (defense-in-depth check — the backend's own gate should "
                          "already have blocked this; seeing this error means this server was called directly).")
    target = _clean_target(a["target"])
    password = a.get("password", "")
    if password is None or str(password) == "":
        raise ValueError("password is required for a spray")
    userlist = _resolve_wordlist(a["userlist"])
    domain = _clean_domain(a.get("domain", ""))
    timeout = _clean_timeout(a.get("timeout", 600))
    cmd = [NXC_BIN, "smb", target, "-u", userlist, "-p", str(password)]
    if domain:
        cmd += ["-d", domain]
    if a.get("continue_on_success", True):
        cmd.append("--continue-on-success")
    return await _run(cmd, timeout)


async def handle_asrep_roast(a: dict) -> dict:
    if not offensive_action_allowed():
        raise ValueError("AS-REP roasting is an exploitation-class action and requires SOCIS_AGENT_ALLOW_OFFENSIVE "
                          "to be enabled on the server (defense-in-depth check — the backend's own gate should "
                          "already have blocked this; seeing this error means this server was called directly).")
    target = _clean_target(a["target"])
    domain = _clean_domain(a["domain"])
    if not domain:
        raise ValueError("domain is required for AS-REP roasting")
    timeout = _clean_timeout(a.get("timeout"))
    # NetExec's ldap module with the asreproast option; creds optional (some domains allow it unauthenticated).
    # Write hashes to a private per-call temp file (not a predictable /tmp path — avoids collision between concurrent
    # scans and a symlink pre-creation race), then fold its contents into the output and clean it up.
    import tempfile
    fd, out_path = tempfile.mkstemp(prefix="asrep_", suffix=".out")
    os.close(fd)
    try:
        cmd = [NXC_BIN, "ldap", target] + _nxc_auth_args(a) + ["--asreproast", out_path]
        result = await _run(cmd, timeout)
        try:
            with open(out_path, "r", encoding="utf-8", errors="replace") as fh:
                hashes = fh.read().strip()
            if hashes:
                result["output"] = (result.get("output", "") + "\n\n[AS-REP hashes]\n" + hashes)[:20000]
        except OSError:
            pass
        return result
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


_HANDLERS = {
    "smb_enum": handle_smb_enum,
    "ldap_enum": handle_ldap_enum,
    "user_enum": handle_user_enum,
    "null_session": handle_null_session,
    "password_spray": handle_password_spray,
    "asrep_roast": handle_asrep_roast,
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
                # validation / scope errors are returned as a clean, non-fatal result
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
