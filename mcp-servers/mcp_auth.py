"""
SOCIS-AI-PT — MCP Server Authentication Middleware
Shared module for validating bearer tokens on all MCP server endpoints.
"""

import os
import re
import hmac
import ipaddress
import logging
import socket
from typing import Optional
from functools import wraps
from fastapi import Request
from fastapi.responses import JSONResponse

log = logging.getLogger(__name__)

# Shared secret read from environment; all MCP servers and the backend must share this.
MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")

if not MCP_AUTH_TOKEN:
    # Log loudly but do NOT raise at import time — a RuntimeError here would prevent
    # the health-check endpoint from starting, causing Docker restart loops.
    # All authenticated endpoints will still return 401 (see verify_mcp_auth below).
    log.critical(
        "MCP_AUTH_TOKEN is not set! "
        "All MCP API requests will be rejected with 401. "
        "Set MCP_AUTH_TOKEN in your environment to enable MCP server functionality."
    )


def _ct_eq(a: str, b: str) -> bool:
    """Constant-time string comparison (fix M-1)."""
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode(), b.encode())


# ─── Scanner concurrency guard (perf #3) ─────────────────────
# Each scanner MCP server spawns an external tool process per request with no
# bound, so N concurrent scans → N simultaneous nmap/nuclei/sqlmap processes in
# one container → CPU thrash / OOM. This semaphore caps concurrent subprocesses
# per server process. Tune via MCP_MAX_CONCURRENT_SCANS (default 3). Acquire it
# around the subprocess call; excess requests wait (back-pressure) rather than
# fork-bombing the host.
import asyncio as _asyncio

_MAX_CONCURRENT = int(os.environ.get("MCP_MAX_CONCURRENT_SCANS", "3"))
_scan_semaphore: "Optional[_asyncio.Semaphore]" = None


def scan_slot() -> "_asyncio.Semaphore":
    """Return the process-wide scan semaphore (lazily created on the running loop)."""
    global _scan_semaphore
    if _scan_semaphore is None:
        _scan_semaphore = _asyncio.Semaphore(_MAX_CONCURRENT)
    return _scan_semaphore


def verify_mcp_auth(request: Request) -> bool:
    """Check that the request carries a valid MCP bearer token.

    Uses a constant-time comparison to avoid timing side-channels (fix M-1).
    Returns False if no server token is configured.
    """
    if not MCP_AUTH_TOKEN:
        return False
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return _ct_eq(auth_header[7:], MCP_AUTH_TOKEN)
    return _ct_eq(request.headers.get("X-MCP-Token", ""), MCP_AUTH_TOKEN)


def mcp_auth_error(req_id=None) -> JSONResponse:
    """Return a standard JSON-RPC auth error."""
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32001, "message": "Unauthorized — invalid or missing MCP_AUTH_TOKEN"},
        },
        status_code=401,
    )


def offensive_action_allowed() -> bool:
    """True if this server process may run an exploitation-class action (password spraying, AS-REP roasting,
    hash cracking, Metasploit, sqlmap's shell-spawning actions, …).

    Found during a security audit: the ONLY place that ever checked SOCIS_AGENT_ALLOW_OFFENSIVE was the backend's
    generic manifest dispatcher (scan_worker.py's _dispatch_manifest_tool) — every MCP server itself, old and new
    alike, only documented the gate in comments/docstrings and executed unconditionally if called directly. In
    production the MCP servers are not reachable from outside the Docker network, but anything else on that
    internal network (or a compromised backend process) could call an offensive tool with no check at all. This is
    the defense-in-depth layer: every offensive handler must call this BEFORE doing anything, in addition to (not
    instead of) the backend's own gate.
    """
    import os as _os
    return _os.environ.get("SOCIS_AGENT_ALLOW_OFFENSIVE", "").strip().lower() in ("1", "true", "yes", "on")


# ─── Input Sanitization Helpers ──────────────────────────────

# Allowed nmap flags whitelist (safe subset)
_ALLOWED_NMAP_FLAGS = {
    "-sV", "-sC", "-sT", "-sS", "-sU", "-sN", "-sF", "-sX", "-sA",
    "-O", "-A", "-Pn", "-PE", "-PP", "-PM", "-PS", "-PA", "-PU", "-PY",
    "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    "--open", "--top-ports", "--osscan-guess", "--version-intensity",
    "-p", "-F", "-r", "--reason", "--traceroute",
    "-v", "-vv", "-d",
}

# Pattern for nmap flag + value combos like --top-ports 100
_NMAP_FLAG_VALUE_RE = re.compile(r'^-{1,2}[a-zA-Z][a-zA-Z0-9\-]*$')


def sanitize_nmap_flags(flags: str) -> list[str]:
    """Parse and validate nmap flags against a safe whitelist.
    Returns a list of sanitized tokens.
    Raises ValueError on disallowed flags.
    """
    tokens = flags.split()
    sanitized = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in _ALLOWED_NMAP_FLAGS:
            sanitized.append(token)
            # Some flags take a value argument
            if token in ("-p", "--top-ports", "--version-intensity", "-PS", "-PA", "-PU") and i + 1 < len(tokens):
                val = tokens[i + 1]
                # Value must be alphanumeric, commas, dashes (port ranges)
                if re.match(r'^[a-zA-Z0-9,\-]+$', val):
                    sanitized.append(val)
                    i += 1
        elif _NMAP_FLAG_VALUE_RE.match(token):
            # Unknown but looks like a flag — reject for safety
            raise ValueError(f"Disallowed nmap flag: {token}")
        else:
            raise ValueError(f"Invalid nmap flag token: {token}")
        i += 1
    return sanitized


# ─── SSRF / Target-Scope Validation (fix H-5) ────────────────
_ALWAYS_BLOCKED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("100.64.0.0/10"),
]
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
]


def _allow_private_targets() -> bool:
    return os.environ.get("MCP_ALLOW_PRIVATE_TARGETS", "false").strip().lower() in (
        "1", "true", "yes", "on",
    )


def _allowed_private_nets() -> list:
    """MCP_ALLOWED_PRIVATE_NETS: comma/space-separated networks (for example 192.168.20.0/24) that tools MAY target even though they are
    private. This is the precise alternative to MCP_ALLOW_PRIVATE_TARGETS=true, which opens ALL private space, including the
    platform's own Docker network (Postgres, Redis, MinIO). An entry is ignored if it is not entirely inside private space, or if it
    overlaps a network that is never allowed (loopback, link-local/metadata, ...)."""
    out = []
    for tok in re.split(r"[,\s]+", os.environ.get("MCP_ALLOWED_PRIVATE_NETS", "").strip()):
        if not tok:
            continue
        try:
            net = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            logging.getLogger(__name__).warning("MCP_ALLOWED_PRIVATE_NETS: ignoring invalid entry %r", tok)
            continue
        inside_private = any(net.version == p.version and net.subnet_of(p) for p in _PRIVATE_NETS)
        overlaps_blocked = any(net.version == b.version and net.overlaps(b) for b in _ALWAYS_BLOCKED_NETS)
        if not inside_private or overlaps_blocked:
            logging.getLogger(__name__).warning("MCP_ALLOWED_PRIVATE_NETS: ignoring %s (must be inside private space and never overlap a blocked range)", net)
            continue
        out.append(net)
    return out


def _ip_is_blocked(ip) -> bool:
    for net in _ALWAYS_BLOCKED_NETS:
        if ip.version == net.version and ip in net:
            return True
    for net in _PRIVATE_NETS:
        if ip.version == net.version and ip in net:
            if _allow_private_targets():
                return False
            return not any(ip.version == a.version and ip in a for a in _allowed_private_nets())
    return False


def _resolve_and_check_host(hostname: str) -> None:
    """Resolve hostname and raise if ANY resolved IP is in a blocked range."""
    if not hostname:
        raise ValueError("Empty target host")
    try:
        ip = ipaddress.ip_address(hostname.strip("[]"))
        if _ip_is_blocked(ip):
            raise ValueError(f"Target address is in a blocked range: {hostname}")
        return
    except ValueError as exc:
        if "blocked range" in str(exc):
            raise
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise ValueError(f"Target host does not resolve: {hostname}")
    for family, _, _, _, sockaddr in infos:
        addr = sockaddr[0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _ip_is_blocked(ip):
            raise ValueError(
                f"Target host '{hostname}' resolves to a blocked address ({addr})"
            )


def validate_url_target(url: str) -> str:
    """Validate a target URL (scheme + not internal). Hardened vs denylist bypass (fix H-5)."""
    import urllib.parse
    parsed = urllib.parse.urlparse(url if "://" in url else f"http://{url}")
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid URL scheme: {parsed.scheme}")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Could not parse target host from URL: {url}")
    _resolve_and_check_host(hostname)
    return url


def validate_scan_target(target: str) -> str:
    """Validate a bare host/IP scan target (nmap/masscan/nikto/etc.) (fix H-5)."""
    import urllib.parse
    t = (target or "").strip()
    if not t:
        raise ValueError("Empty scan target")
    if "://" in t:
        t = urllib.parse.urlparse(t).hostname or t
    else:
        t = t.split("/")[0]
    host = t
    if host.count(":") == 1 and not host.startswith("["):
        host = host.split(":")[0]
    _resolve_and_check_host(host)
    return target


def validate_file_path(path: str, allowed_dirs: list[str]) -> str:
    """Validate that a file path is within allowed directories (prevents path traversal)."""
    import os.path
    real = os.path.realpath(path)
    if not any(real.startswith(os.path.realpath(d)) for d in allowed_dirs):
        raise ValueError(f"Path '{path}' is outside allowed directories: {allowed_dirs}")
    if not os.path.isfile(real):
        raise ValueError(f"File not found: {path}")
    return real
