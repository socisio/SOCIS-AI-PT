#!/usr/bin/env python3
"""
SOCIS-AI-PT — SQLMap MCP Server (HTTP transport)
FastAPI-based MCP server for SQL injection testing via sqlmap.
With background scanning support!
"""

import subprocess
import asyncio
import time
import uuid
import os
import threading
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
from typing import Dict, Any
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from mcp_auth import verify_mcp_auth, mcp_auth_error, validate_url_target

app = FastAPI(title="SOCIS SQLMap MCP Server", docs_url=None)

MCP_VERSION = "1.1"
SERVER_NAME = "sqlmap_mcp"

# Thread pool for sqlmap
_executor = ThreadPoolExecutor(max_workers=2)

# SQLMap's own data directory (for built-in wordlist)
_SQLMAP_WORDLIST = os.path.join(
    os.path.dirname(subprocess.run(["python3", "-c", "import sqlmap; print(sqlmap.__file__)"],
                                   capture_output=True, text=True).stdout.strip()),
    "data", "txt", "smalldict.txt"
)

# Store for background scans — guarded by a lock for thread safety (MED-04 fix)
_scans: Dict[str, Dict[str, Any]] = {}
_scans_lock = threading.Lock()

# Maximum number of retained scan results and TTL for completed scans
_MAX_SCANS = 200
_SCAN_TTL_SECONDS = 3600  # 1 hour


def _evict_old_scans() -> None:
    """Remove completed/errored scans older than TTL or when over the cap.
    Must be called with _scans_lock held.
    """
    now = time.time()
    # Remove expired entries
    expired = [
        sid for sid, s in _scans.items()
        if s.get("status") in ("completed", "error")
        and now - s.get("started_at", now) > _SCAN_TTL_SECONDS
    ]
    for sid in expired:
        del _scans[sid]
    # Enforce max cap by removing oldest completed scans first
    if len(_scans) > _MAX_SCANS:
        candidates = sorted(
            ((sid, s.get("started_at", 0)) for sid, s in _scans.items()
             if s.get("status") in ("completed", "error")),
            key=lambda x: x[1],
        )
        for sid, _ in candidates[:len(_scans) - _MAX_SCANS]:
            del _scans[sid]

def _run_sqlmap_background(scan_id: str, target: str, data: str | None, cookie: str | None,
                           level: int, risk: int, technique: str = "BEUSTQ",
                           threads: int = 4):
    """Run sqlmap in background (for background status-based API) and store result."""
    try:
        with _scans_lock:
            _scans[scan_id]["status"] = "running"
            _scans[scan_id]["progress"] = "Starting sqlmap..."

        output_dir = f"/tmp/sqlmap/{scan_id}"
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        cmd = [
            "sqlmap", "-u", target, "--batch", "--random-agent",
            "--level", str(level), "--risk", str(risk),
            "--technique", technique,
            "--threads", str(min(threads, 10)),
            "--forms", "--crawl=2",
            "--timeout=30", "--retries=2",
            "--banner", "--current-db", "--current-user", "--is-dba",
            "--output-dir", output_dir,
        ]
        if data:
            cmd.extend(["--data", data])
        if cookie:
            cmd.extend(["--cookie", cookie])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=550)
        output = result.stdout or result.stderr or ""

        with _scans_lock:
            _scans[scan_id]["status"] = "completed"
            _scans[scan_id]["output"] = output
            _scans[scan_id]["completed_at"] = time.time()

    except Exception as e:
        with _scans_lock:
            _scans[scan_id]["status"] = "error"
            _scans[scan_id]["error"] = str(e)


def _get_target_output_dir(target: str) -> str:
    """Return a consistent per-target output directory for SQLMap session reuse."""
    import hashlib
    target_hash = hashlib.sha256(target.encode()).hexdigest()[:16]
    return f"/tmp/sqlmap/targets/{target_hash}"


def _sqlmap_scan_sync(target: str, data: str | None, cookie: str | None,
                      level: int, risk: int, technique: str, threads: int,
                      dbms: str = "", proxy: str = "", headers: str = "",
                      auth_type: str = "", auth_cred: str = "",
                      delay: int = 0, timeout_secs: int = 30, retries: int = 2,
                      time_sec: int = 5, tamper: str = "") -> dict:
    """Blocking sqlmap full scan — all techniques, structured JSON result.
    Uses a consistent per-target output-dir so follow-up enum steps reuse
    already-found injection points without repeating the detection phase."""
    level   = max(1, min(5, level))
    risk    = max(1, min(3, risk))
    threads = max(1, min(10, threads))
    timeout_secs = max(5, min(120, timeout_secs))
    retries = max(0, min(10, retries))
    time_sec = max(1, min(60, time_sec))
    delay = max(0, min(30, delay))

    # Consistent output dir per target — SQLMap stores session.sqlite here so
    # enum steps can reuse discovered injection points without re-detection.
    output_dir = _get_target_output_dir(target)
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    cmd = [
        "sqlmap", "-u", target, "--batch", "--random-agent",
        "--level",     str(level),
        "--risk",      str(risk),
        "--technique", technique,
        "--threads",   str(threads),
        f"--timeout={timeout_secs}", f"--retries={retries}",
        f"--time-sec={time_sec}",
        "--flush-session",  # always start fresh — avoids cached "not injectable" results
        "--banner", "--current-db", "--current-user", "--is-dba",
        "--output-dir", output_dir,
    ]
    if data:
        # Explicit POST data provided — test only that endpoint with given params.
        # Do NOT use --forms/--crawl here; they conflict with --data and can cause
        # SQLMap to ignore the provided params or exit prematurely.
        cmd.extend(["--data", data])
    else:
        # No specific POST data — let SQLMap discover forms on the page.
        cmd.extend(["--forms", "--crawl=2"])
    if cookie:
        cmd.extend(["--cookie", cookie])
    if dbms:
        cmd.extend(["--dbms", dbms])
    if proxy:
        cmd.extend(["--proxy", proxy])
    if headers:
        # headers can be newline-separated e.g. "X-Forwarded-For: 127.0.0.1\nAccept: */*"
        for h in headers.splitlines():
            h = h.strip()
            if h:
                cmd.extend(["--header", h])
    if auth_type and auth_cred:
        cmd.extend(["--auth-type", auth_type, "--auth-cred", auth_cred])
    if delay:
        cmd.extend(["--delay", str(delay)])
    if tamper:
        cmd.extend(["--tamper", tamper])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=550)
    output = (result.stdout or "") + (result.stderr or "")

    # ── Parse key fields from output ──────────────────────────────────────
    injectable  = (
        "appears to be injectable" in output
        or ("sql injection" in output.lower() and "not injectable" not in output)
    )
    detected_dbms = dbms  # start with user-supplied value if any
    current_db   = ""
    current_user = ""
    is_dba       = False
    injections: list[str] = []
    parameters: list[str] = []

    for line in output.split("\n"):
        ls = line.strip()
        if "DBMS:" in ls:
            detected_dbms = ls.split("DBMS:")[-1].strip()
        if "current database:" in ls.lower():
            current_db   = ls.split(":", 1)[-1].strip().strip("'")
        if "current user:" in ls.lower():
            current_user = ls.split(":", 1)[-1].strip().strip("'")
        if "is DBA:" in ls:
            is_dba = "True" in ls
        if "appears to be injectable" in ls:
            injections.append(ls)
        if "Parameter:" in ls:
            parameters.append(ls.replace("Parameter:", "").strip())

    return {
        "target":       target,
        "vulnerable":   injectable,
        "injectable":   injectable,
        "injections":   injections,
        "parameters":   list(set(parameters)),
        "dbms":         detected_dbms,
        "current_db":   current_db,
        "current_user": current_user,
        "is_dba":       is_dba,
        "technique":    technique,
        "level":        level,
        "risk":         risk,
        "summary":      _format_sqlmap_output(output),
        "raw_tail":     output[-2000:] if output else "",
        "success":      True,
    }


def _run_sqlmap_enum_sync(target: str, mode: str, cookie: str | None,
                          data: str | None = None, proxy: str = "",
                          headers: str = "", auth_type: str = "", auth_cred: str = "",
                          delay: int = 0, tamper: str = "", **kwargs) -> str:
    """Run a single sqlmap enum step synchronously, reusing the per-target output dir."""
    output_dir = _get_target_output_dir(target)
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    cmd = [
        "sqlmap", "-u", target, "--batch", "--random-agent",
        "--level=5", "--risk=3", "--technique=BEUSTQ",
        "--timeout=30", "--retries=1",
        "--output-dir", output_dir,
    ]
    if cookie:
        cmd.extend(["--cookie", cookie])
    if data:
        cmd.extend(["--data", data])
    if proxy:
        cmd.extend(["--proxy", proxy])
    if headers:
        for h in headers.splitlines():
            h = h.strip()
            if h:
                cmd.extend(["--header", h])
    if auth_type and auth_cred:
        cmd.extend(["--auth-type", auth_type, "--auth-cred", auth_cred])
    if delay:
        cmd.extend(["--delay", str(delay)])
    if tamper:
        cmd.extend(["--tamper", tamper])

    if mode == "databases":
        cmd.append("--dbs")
    elif mode == "tables":
        db = kwargs.get("database", "")
        cmd.extend(["--tables", "-D", db]) if db else cmd.append("--tables")
    elif mode == "columns":
        cmd.extend(["--columns", "-D", kwargs.get("database", ""), "-T", kwargs.get("table", "")])
    elif mode == "dump":
        cmd.extend(["--dump", "-D", kwargs.get("database", ""), "-T", kwargs.get("table", "")])
    elif mode == "users":
        cmd.append("--users")
    elif mode == "passwords":
        cmd.extend(["--users", "--passwords"])
        if kwargs.get("crack") and os.path.isfile(_SQLMAP_WORDLIST):
            cmd.extend(["--crack", "--wordlist", _SQLMAP_WORDLIST])
    elif mode == "privileges":
        cmd.append("--privileges")
    elif mode == "roles":
        cmd.append("--roles")
    elif mode == "current-db":
        cmd.append("--current-db")
    elif mode == "current-user":
        cmd.append("--current-user")
    elif mode == "is-dba":
        cmd.append("--is-dba")
    elif mode == "schema":
        cmd.extend(["--schema", "--dump"])
    elif mode == "file-read":
        cmd.extend(["--file-read", kwargs.get("file", "")])
    elif mode == "os-shell":
        cmd.append("--os-shell")
    else:
        return f"Unknown mode: {mode}"

    res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    out = (res.stdout or "") + (res.stderr or "")
    return out[-3000:] if out else "No output"


_SQLMAP_LOG_SKIP = (
    "starting @", "ending @", "resumed", "fetched",
    "logging", "sqlmap resumed", "retrieved:",
)

def _parse_sqlmap_names(raw: str, prefix: str = "[*]") -> list[str]:
    """Extract clean names from sqlmap [*] bullet lines, filtering out log timestamps."""
    names: list[str] = []
    for line in raw.split("\n"):
        s = line.strip()
        if not s.startswith(prefix):
            continue
        name = s[len(prefix):].strip().strip("'\"")
        if not name:
            continue
        low = name.lower()
        if any(skip in low for skip in _SQLMAP_LOG_SKIP):
            continue
        names.append(name)
    return names


def _parse_sqlmap_table_rows(raw: str) -> list[str]:
    """Extract table names from sqlmap --tables output (pipe-delimited rows)."""
    tables: list[str] = []
    for line in raw.split("\n"):
        stripped = line.strip().strip("|").strip()
        if (
            stripped
            and not stripped.startswith("-")
            and not stripped.startswith("+")
            and not stripped.startswith("[")
            and not stripped.lower().startswith("database:")
            and not stripped.lower().startswith("table:")
            and len(stripped) < 128
        ):
            # Check it doesn't look like a log timestamp
            if not any(skip in stripped.lower() for skip in _SQLMAP_LOG_SKIP):
                tables.append(stripped)
    return tables


def _parse_sqlmap_dump(raw: str) -> list[dict]:
    """Parse sqlmap --dump output table into list-of-dicts rows."""
    rows: list[dict] = []
    headers: list[str] = []
    in_table = False
    for line in raw.split("\n"):
        stripped = line.strip()
        if stripped.startswith("+") and "-" in stripped:
            if not in_table:
                in_table = True
            continue
        if in_table and stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if not headers:
                headers = cells
            else:
                rows.append(dict(zip(headers, cells)))
    return rows


# Tables that likely contain credentials — always dump these
_CRED_TABLES = {
    "users", "user", "accounts", "account", "members", "member",
    "login", "logins", "credentials", "credentials", "admins", "admin",
    "auth", "authentication", "passwords", "passwd", "customers",
    "employees", "staff", "people", "persons", "clients", "dvwausers",
}


def _sqlmap_full_chain_sync(target: str, data: str | None, cookie: str | None,
                             level: int, risk: int, technique: str, threads: int,
                             dbms: str = "", proxy: str = "", headers: str = "",
                             auth_type: str = "", auth_cred: str = "",
                             delay: int = 0, timeout_secs: int = 30, retries: int = 2,
                             time_sec: int = 5, tamper: str = "") -> dict:
    """
    Complete SQLMap exploitation chain:
      1. Detection scan — find injectable parameters
      2. If vulnerable:
         a. Enumerate: current-db, current-user, is-dba, all databases,
            all users, password hashes, privileges
         b. For EVERY discovered database → enumerate tables
         c. For tables matching credential keywords → dump full data
      3. Return unified structured result
    """
    # Step 1: Detection
    initial = _sqlmap_scan_sync(target, data, cookie, level, risk, technique, threads,
                                 dbms=dbms, proxy=proxy, headers=headers,
                                 auth_type=auth_type, auth_cred=auth_cred,
                                 delay=delay, timeout_secs=timeout_secs,
                                 retries=retries, time_sec=time_sec, tamper=tamper)

    if not initial.get("vulnerable"):
        return {**initial, "phase": "detection_only",
                "message": "No SQL injection found. No enumeration performed."}

    chain: dict[str, str] = {}

    # Common kwargs reused across all enum/dump steps
    _enum_kw = dict(
        data=data, proxy=proxy, headers=headers,
        auth_type=auth_type, auth_cred=auth_cred,
        delay=delay, tamper=tamper,
    )

    # Step 2: Core enumeration (reuses detection session — no re-scan)
    enum_steps = [
        ("current_db",   "current-db",   {}),
        ("current_user", "current-user", {}),
        ("is_dba",       "is-dba",       {}),
        ("databases",    "databases",    {}),
        ("users",        "users",        {}),
        ("passwords",    "passwords",    {"crack": True}),
        ("privileges",   "privileges",   {}),
    ]
    for key, mode, kwargs in enum_steps:
        try:
            chain[key] = _run_sqlmap_enum_sync(target, mode, cookie, **{**_enum_kw, **kwargs})
        except Exception as e:
            chain[key] = f"[error] {e}"

    # ── Parse structured data from raw enum outputs ────────────────────
    databases: list[str] = _parse_sqlmap_names(chain.get("databases", ""))
    users:     list[str] = _parse_sqlmap_names(chain.get("users", ""))

    # Resolve current DB from detection or current_db step
    db_to_enum = initial.get("current_db") or ""
    if not db_to_enum:
        for line in chain.get("current_db", "").split("\n"):
            if "current database:" in line.lower():
                candidate = line.split(":", 1)[-1].strip().strip("'\"")
                if candidate and not any(s in candidate.lower() for s in _SQLMAP_LOG_SKIP):
                    db_to_enum = candidate
                    break

    # Ensure current DB is in the list even if --dbs missed it
    if db_to_enum and db_to_enum not in databases:
        databases.insert(0, db_to_enum)

    # Step 3: Enumerate tables for EVERY database
    all_tables: dict[str, list[str]] = {}   # {db_name: [table, ...]}
    dumps:      dict[str, list[dict]] = {}  # {db.table: [row_dict, ...]}

    dbs_to_scan = databases if databases else ([db_to_enum] if db_to_enum else [])
    for db in dbs_to_scan[:8]:   # cap at 8 DBs to avoid runaway
        try:
            raw_tables = _run_sqlmap_enum_sync(target, "tables", cookie,
                                               database=db, **_enum_kw)
            chain[f"tables_{db}"] = raw_tables
            table_list = _parse_sqlmap_table_rows(raw_tables)
            all_tables[db] = table_list

            # Step 4: Dump credential tables
            for tbl in table_list:
                if tbl.lower().replace(" ", "") in _CRED_TABLES or tbl.lower() in _CRED_TABLES:
                    try:
                        raw_dump = _run_sqlmap_enum_sync(target, "dump", cookie,
                                                         database=db, table=tbl, **_enum_kw)
                        chain[f"dump_{db}_{tbl}"] = raw_dump
                        parsed_rows = _parse_sqlmap_dump(raw_dump)
                        if parsed_rows:
                            dumps[f"{db}.{tbl}"] = parsed_rows
                    except Exception as e:
                        chain[f"dump_{db}_{tbl}"] = f"[error] {e}"
        except Exception as e:
            chain[f"tables_{db}"] = f"[error] {e}"
            all_tables[db] = []

    # Flat list of all tables for the primary DB (used by ToolNode)
    tables = all_tables.get(db_to_enum, [])
    if not tables and all_tables:
        tables = next(iter(all_tables.values()), [])

    return {
        **initial,
        "phase":          "complete",
        "enumeration":    chain,
        "databases":      databases,
        "tables":         tables,
        "all_tables":     all_tables,
        "users":          users,
        "dumps":          dumps,
        "db_enumerated":  db_to_enum,
    }


TOOLS = [
    {
        "name": "sqlmap_scan",
        "description": (
            "Run a full SQL injection scan against a target URL using all injection techniques. "
            "Runs synchronously and returns complete structured results including vulnerability status, "
            "DBMS info, injected parameters, current DB/user and DBA status."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target":     {"type": "string",  "description": "Target URL to test (GET or POST)"},
                "data":       {"type": "string",  "description": "POST body data (optional, e.g. 'user=a&pass=b')"},
                "level":      {"type": "integer", "description": "Test depth 1-5 (5 = most thorough)", "default": 3},
                "risk":       {"type": "integer", "description": "Risk level 1-3 (3 = all payloads)", "default": 2},
                "technique":  {"type": "string",  "description": "Injection techniques to test (any combo of B E U S T Q)", "default": "BEUSTQ"},
                "threads":    {"type": "integer", "description": "Concurrent threads 1-10", "default": 4},
                "cookie":     {"type": "string",  "description": "Session cookie for authenticated scans (optional)"},
                "dbms":       {"type": "string",  "description": "Force backend DBMS: mysql, mssql, oracle, postgresql, sqlite, access, firebird, maxdb, sybase, db2, hsqldb, h2, informix (speeds up scan)"},
                "proxy":      {"type": "string",  "description": "HTTP/HTTPS proxy URL e.g. http://127.0.0.1:8080"},
                "headers":    {"type": "string",  "description": "Extra HTTP headers, newline-separated e.g. 'X-Forwarded-For: 127.0.0.1'"},
                "auth_type":  {"type": "string",  "description": "HTTP authentication type: Basic, Digest, NTLM"},
                "auth_cred":  {"type": "string",  "description": "HTTP authentication credentials: user:password"},
                "delay":      {"type": "integer", "description": "Delay in seconds between each HTTP request (0 = no delay)", "default": 0},
                "timeout_secs": {"type": "integer", "description": "Seconds to wait for connection (default 30)", "default": 30},
                "retries":    {"type": "integer", "description": "Retries when connection timeout (default 2)", "default": 2},
                "time_sec":   {"type": "integer", "description": "Seconds to delay for time-based blind SQLi detection (default 5)", "default": 5},
                "tamper":     {"type": "string",  "description": "Tamper script(s) comma-separated for WAF bypass e.g. space2comment,between,randomcase"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "sqlmap_full_chain",
        "description": (
            "Complete SQL injection exploitation chain: detect → if vulnerable, automatically enumerate "
            "current DB/user, DBA status, all databases, tables, users, and password hashes in one step. "
            "Returns a unified structured result. Use this for a full SQLMap pentest."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target":     {"type": "string",  "description": "Target URL to test (GET or POST)"},
                "data":       {"type": "string",  "description": "POST body data (optional)"},
                "level":      {"type": "integer", "description": "Test depth 1-5 (5 = most thorough)", "default": 3},
                "risk":       {"type": "integer", "description": "Risk level 1-3 (3 = all payloads)", "default": 2},
                "technique":  {"type": "string",  "description": "Injection techniques (BEUSTQ = all)", "default": "BEUSTQ"},
                "threads":    {"type": "integer", "description": "Concurrent threads 1-10", "default": 4},
                "cookie":     {"type": "string",  "description": "Session cookie for authenticated scans (optional)"},
                "dbms":       {"type": "string",  "description": "Force backend DBMS e.g. mysql, mssql, postgresql"},
                "proxy":      {"type": "string",  "description": "HTTP/HTTPS proxy URL"},
                "headers":    {"type": "string",  "description": "Extra HTTP headers, newline-separated"},
                "auth_type":  {"type": "string",  "description": "HTTP auth type: Basic, Digest, NTLM"},
                "auth_cred":  {"type": "string",  "description": "HTTP auth credentials: user:password"},
                "delay":      {"type": "integer", "description": "Delay between requests in seconds", "default": 0},
                "timeout_secs": {"type": "integer", "description": "Connection timeout in seconds", "default": 30},
                "retries":    {"type": "integer", "description": "Connection retries", "default": 2},
                "time_sec":   {"type": "integer", "description": "Delay for time-based blind SQLi (seconds)", "default": 5},
                "tamper":     {"type": "string",  "description": "Tamper scripts comma-separated e.g. space2comment,between"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "sqlmap_enum_databases",
        "description": "Enumerate databases after finding SQLi. Use target URL or scan_id from sqlmap_scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL with SQLi"},
                "scan_id": {"type": "string", "description": "Scan ID from sqlmap_scan"},
                "cookie": {"type": "string", "description": "Cookie (optional)"},
            },
        },
    },
    {
        "name": "sqlmap_enum_tables",
        "description": "Enumerate tables from a specific database.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL with SQLi"},
                "scan_id": {"type": "string", "description": "Scan ID from sqlmap_scan"},
                "database": {"type": "string", "description": "Database name"},
                "cookie": {"type": "string", "description": "Cookie (optional)"},
            },
            "required": ["database"],
        },
    },
    {
        "name": "sqlmap_enum_columns",
        "description": "Enumerate columns from a table.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL with SQLi"},
                "scan_id": {"type": "string", "description": "Scan ID from sqlmap_scan"},
                "database": {"type": "string", "description": "Database name"},
                "table": {"type": "string", "description": "Table name"},
                "cookie": {"type": "string", "description": "Cookie (optional)"},
            },
            "required": ["database", "table"],
        },
    },
    {
        "name": "sqlmap_dump",
        "description": "Dump data from a table (extract all data).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL with SQLi"},
                "scan_id": {"type": "string", "description": "Scan ID from sqlmap_scan"},
                "database": {"type": "string", "description": "Database name"},
                "table": {"type": "string", "description": "Table name"},
                "cookie": {"type": "string", "description": "Cookie (optional)"},
            },
            "required": ["database", "table"],
        },
    },
    {
        "name": "sqlmap_users",
        "description": "Get database users and their roles.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL with SQLi"},
                "scan_id": {"type": "string", "description": "Scan ID from sqlmap_scan"},
                "cookie": {"type": "string", "description": "Cookie (optional)"},
            },
        },
    },
    {
        "name": "sqlmap_passwords",
        "description": "Get password hashes from database users. Optionally attempt to crack them using sqlmap's built-in dictionary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL with SQLi"},
                "scan_id": {"type": "string", "description": "Scan ID from sqlmap_scan"},
                "cookie": {"type": "string", "description": "Cookie (optional)"},
                "crack": {
                    "type": "boolean",
                    "description": "Attempt to crack extracted hashes using sqlmap's built-in dictionary (smalldict.txt — 10,180 common passwords). Default: false.",
                    "default": False
                },
            },
        },
    },
    {
        "name": "sqlmap_shell",
        "description": "Get interactive sqlmap shell for manual commands.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL with SQLi"},
                "scan_id": {"type": "string", "description": "Scan ID from sqlmap_scan"},
                "cookie": {"type": "string", "description": "Cookie (optional)"},
            },
        },
    },
    {
        "name": "sqlmap_os_shell",
        "description": "Try to get operating system shell via SQL injection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL with SQLi"},
                "scan_id": {"type": "string", "description": "Scan ID from sqlmap_scan"},
                "cookie": {"type": "string", "description": "Cookie (optional)"},
            },
        },
    },
    {
        "name": "sqlmap_privileges",
        "description": "Check current user privileges.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL with SQLi"},
                "scan_id": {"type": "string", "description": "Scan ID from sqlmap_scan"},
                "cookie": {"type": "string", "description": "Cookie (optional)"},
            },
        },
    },
    {
        "name": "sqlmap_current_db",
        "description": "Get current database name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL with SQLi"},
                "scan_id": {"type": "string", "description": "Scan ID from sqlmap_scan"},
                "cookie": {"type": "string", "description": "Cookie (optional)"},
            },
        },
    },
    {
        "name": "sqlmap_current_user",
        "description": "Get current database user.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL with SQLi"},
                "scan_id": {"type": "string", "description": "Scan ID from sqlmap_scan"},
                "cookie": {"type": "string", "description": "Cookie (optional)"},
            },
        },
    },
    {
        "name": "sqlmap_is_dba",
        "description": "Check if current user is DBA.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target":  {"type": "string", "description": "Target URL with SQLi"},
                "scan_id": {"type": "string", "description": "Scan ID from sqlmap_scan"},
                "cookie":  {"type": "string", "description": "Cookie (optional)"},
            },
        },
    },
    {
        "name": "sqlmap_read_file",
        "description": "Read file from server filesystem.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "file": {"type": "string", "description": "File path to read"},
                "cookie": {"type": "string", "description": "Cookie (optional)"},
            },
            "required": ["target", "file"],
        },
    },
    {
        "name": "sqlmap_write_file",
        "description": "Write file to server filesystem.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL"},
                "file": {"type": "string", "description": "File path to write"},
                "content": {"type": "string", "description": "Content to write"},
                "cookie": {"type": "string", "description": "Cookie (optional)"},
            },
            "required": ["target", "file", "content"],
        },
    },
    {
        "name": "sqlmap_status",
        "description": "Check status of a background scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "Scan ID from sqlmap_scan"},
            },
            "required": ["scan_id"],
        },
    },
    {
        "name": "sqlmap_results",
        "description": "Get results of a completed scan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "Scan ID from sqlmap_scan"},
            },
            "required": ["scan_id"],
        },
    },
]


def _run_sqlmap_sync(target: str, data: str | None, level: int, risk: int) -> str:
    """Blocking sqlmap execution — run in a thread pool."""
    # Validate level/risk ranges
    level = max(1, min(5, level))
    risk = max(1, min(3, risk))
    cmd = [
        "sqlmap", "-u", target, "--batch",
        "--level", str(level), "--risk", str(risk),
        "--output-dir", "/tmp/sqlmap", "--forms", "--crawl=1",
        "--timeout=15", "--retries=1", "--random-agent",
        "--ignore-code=301,302", "--maxtime=120",
    ]
    if data:
        cmd.extend(["--data", data])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=200)
    output = result.stdout or result.stderr or ""
    return output[-4000:] if output else "No SQL injection found."


def _format_sqlmap_output(output: str) -> str:
    """Format sqlmap output for better UI display."""
    lines = output.split('\n')
    result_lines = []
    found_vulnerable = False
    dbms = ""
    
    if "appears to be injectable" in output or "is vulnerable" in output.lower():
        found_vulnerable = True
        result_lines.append("⚠️  SQL INJECTION VULNERABILITY FOUND!")
        result_lines.append("")
    
    if "DBMS:" in output:
        for line in lines:
            if "DBMS:" in line:
                dbms = line.strip()
                result_lines.append(f"📊 {dbms}")
                break
    
    # Databases
    if "available databases [" in output:
        result_lines.append("📁 Databases:")
        for line in lines:
            if line.strip().startswith("[*]") or line.strip().startswith("|"):
                result_lines.append(f"  {line.strip().strip('|').strip()}")
        result_lines.append("")
    
    # Tables
    if "fetching tables" in output or "Table:" in output:
        result_lines.append("📋 Tables:")
        in_table = False
        for line in lines:
            if "Table:" in line or "tables]" in line:
                in_table = True
            if in_table and (line.strip().startswith("[") or line.strip().startswith("|")):
                result_lines.append(f"  {line.strip().strip('|').strip()}")
            if in_table and line.strip().startswith("---"):
                break
        result_lines.append("")
    
    # Columns - extract user/pass
    if "user_id" in output.lower() or "first_name" in output.lower() or "last_name" in output.lower():
        result_lines.append("🔑 Credentials Found:")
        for line in lines:
            if line.strip().startswith("|"):
                result_lines.append(f"  {line.strip()}")
        result_lines.append("")
    
    # Users
    if "database management system users" in output or "fetching database users" in output:
        result_lines.append("👤 Database Users:")
        for line in lines:
            if "[*]" in line:
                result_lines.append(f"  {line.strip()}")
        result_lines.append("")
    
    # Privileges
    if "privileges:" in output or "privilege:" in output:
        result_lines.append("🔐 User Privileges:")
        for line in lines:
            if "privilege:" in line.lower():
                result_lines.append(f"  {line.strip()}")
        result_lines.append("")
    
    # Current DB/User
    if "current database:" in output:
        for line in lines:
            if "current database:" in line:
                result_lines.append(f"🗄️  Current Database: {line.split('current database:')[1].strip().strip(chr(39))}")
        result_lines.append("")
    
    if "current user:" in output:
        for line in lines:
            if "current user:" in line:
                result_lines.append(f"👤 Current User: {line.split('current user:')[1].strip().strip(chr(39))}")
        result_lines.append("")
    
    # IS DBA
    if "is DBA:" in output:
        for line in lines:
            if "is DBA:" in line:
                result_lines.append(f"⭐ {line.strip()}")
        result_lines.append("")
    
    if found_vulnerable:
        result_lines.append("="*50)
        result_lines.append("🛡️  REMEDIATION:")
        result_lines.append("• Use parameterized queries (prepared statements)")
        result_lines.append("• Implement input validation and sanitization")
        result_lines.append("• Apply principle of least privilege to database")
        result_lines.append("• Use WAF for additional protection")
    else:
        if not result_lines:
            result_lines.append("ℹ️  Operation completed")
    
    result_lines.append("")
    result_lines.append("─"*50)
    result_lines.append("📝 Full Details (last 3000 chars):")
    result_lines.append("─"*50)
    result_lines.append(output[-3000:])
    
    return "\n".join(result_lines)


def handle_sqlmap_scan(arguments: dict) -> str:
    target = arguments["target"]
    data = arguments.get("data")
    cookie = arguments.get("cookie")
    level = int(arguments.get("level", 1))
    risk = int(arguments.get("risk", 1))
    cmd = [
        "sqlmap", "-u", target, "--batch",
        "--level", str(level), "--risk", str(risk),
        "--output-dir", "/tmp/sqlmap", "--forms", "--crawl=1",
        "--timeout=20", "--retries=1", "--random-agent",
    ]
    if data:
        cmd.extend(["--data", data])
    if cookie:
        cmd.extend(["--cookie", cookie])
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
    output = result.stdout or result.stderr or ""
    
    if not output:
        return "No output received from sqlmap"
    
    return _format_sqlmap_output(output)


def handle_sqlmap_status(scan_id: str) -> Dict[str, Any]:
    """Check status of a background scan."""
    with _scans_lock:
        if scan_id not in _scans:
            return {"error": "Scan ID not found", "status": "unknown"}
        scan = _scans[scan_id].copy()
    return {
        "scan_id": scan_id,
        "status": scan.get("status", "unknown"),
        "progress": scan.get("progress", ""),
        "started_at": scan.get("started_at", ""),
    }


def handle_sqlmap_results(scan_id: str) -> str:
    """Get results of a completed scan."""
    with _scans_lock:
        if scan_id not in _scans:
            return "Error: Scan ID not found"
        scan = _scans[scan_id].copy()
    
    status = scan.get("status", "unknown")
    
    if status == "running":
        return "Scan still running... Use sqlmap_status to check progress."
    
    if status == "error":
        return f"Error during scan: {scan.get('error', 'Unknown error')}"
    
    output = scan.get("output", "No output")
    return _format_sqlmap_output(output)


_SCAN_DIR = "/tmp/sqlmap_sessions"


def _ensure_scan_dir():
    Path(_SCAN_DIR).mkdir(parents=True, exist_ok=True)


def _get_session_file(target: str) -> str:
    import hashlib
    target_hash = hashlib.sha256(target.encode()).hexdigest()[:16]
    return f"{_SCAN_DIR}/session_{target_hash}.txt"


def _run_sqlmap_enum(target: str, mode: str, cookie: str | None, **kwargs) -> str:
    """Run sqlmap enumeration commands."""
    _ensure_scan_dir()
    session_file = _get_session_file(target)
    
    cmd = ["sqlmap", "-u", target, "--batch", "--random-agent", 
           "--level=5", "--risk=3", "--technique=BEUSTQ",
           "--delay=1", "--timeout=30", "--smart", "--force-eps",
           "--session", session_file]
    
    if cookie:
        cmd.extend(["--cookie", cookie])
    
    if mode == "databases":
        cmd.extend(["--dbs"])
    elif mode == "tables":
        cmd.extend(["--tables", "-D", kwargs.get("database", "")])
    elif mode == "columns":
        cmd.extend(["--columns", "-D", kwargs.get("database", ""), "-T", kwargs.get("table", "")])
    elif mode == "dump":
        cmd.extend(["--dump", "-D", kwargs.get("database", ""), "-T", kwargs.get("table", ""), "--no-union", "--no-eta"])
    elif mode == "users":
        cmd.extend(["--users"])
    elif mode == "passwords":
        cmd.extend(["--users", "--passwords"])
        # If crack=True is stored in kwargs, attempt offline hash cracking
        if kwargs.get("crack") and os.path.isfile(_SQLMAP_WORDLIST):
            cmd.extend(["--crack", "--wordlist", _SQLMAP_WORDLIST])
    elif mode == "shell":
        cmd.extend(["--sql-shell"])
    elif mode == "os-shell":
        cmd.extend(["--os-shell"])
    elif mode == "privileges":
        cmd.extend(["--privileges"])
    elif mode == "roles":
        cmd.extend(["--roles"])
    elif mode == "schema":
        cmd.extend(["--schema", "--dump"])
    elif mode == "current-db":
        cmd.extend(["--current-db"])
    elif mode == "current-user":
        cmd.extend(["--current-user"])
    elif mode == "is-dba":
        cmd.extend(["--is-dba"])
    elif mode == "file-read":
        cmd.extend(["--file-read", kwargs.get("file", "")])
    elif mode == "file-write":
        if kwargs.get("content"):
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
                f.write(kwargs.get("content", ""))
                tmpfile = f.name
            cmd.extend(["--file-write", tmpfile, "--file-dest", kwargs.get("file", "")])
    
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    output = result.stdout or result.stderr or "No output"
    return _format_sqlmap_output(output)


def handle_enum_tool(tool_name: str, arguments: dict) -> str:
    """Handle enumeration tools - supports target URL OR scan_id."""
    # Get target - either from arguments or from scan_id lookup
    target = arguments.get("target", "")
    scan_id_arg = arguments.get("scan_id", "")
    
    if not target and scan_id_arg:
        # Look up target from previous scan
        if scan_id_arg in _scans:
            target = _scans[scan_id_arg].get("target", "")
        if not target:
            return f"Error: No target found for scan_id {scan_id_arg}"
    
    if not target:
        return "Error: Provide target URL or scan_id"
    
    cookie = arguments.get("cookie")
    
    validate_url_target(target)
    
    mode_map = {
        "sqlmap_enum_databases": ("databases", {}),
        "sqlmap_enum_tables": ("tables", {"database": arguments.get("database", "")}),
        "sqlmap_enum_columns": ("columns", {"database": arguments.get("database", ""), "table": arguments.get("table", "")}),
        "sqlmap_dump": ("dump", {"database": arguments.get("database", ""), "table": arguments.get("table", "")}),
        "sqlmap_users": ("users", {}),
        "sqlmap_passwords": ("passwords", {"crack": arguments.get("crack", False)}),
        "sqlmap_shell": ("shell", {}),
        "sqlmap_os_shell": ("os-shell", {}),
        "sqlmap_privileges": ("privileges", {}),
        "sqlmap_roles": ("roles", {}),
        "sqlmap_schema": ("schema", {}),
        "sqlmap_current_db": ("current-db", {}),
        "sqlmap_current_user": ("current-user", {}),
        "sqlmap_is_dba": ("is-dba", {}),
        "sqlmap_read_file": ("file-read", {"file": arguments.get("file", "")}),
        "sqlmap_write_file": ("file-write", {"file": arguments.get("file", ""), "content": arguments.get("content", "")}),
    }
    
    if tool_name not in mode_map:
        return f"Error: Unknown tool {tool_name}"
    
    mode, kwargs = mode_map[tool_name]
    
    # Run in background with lock protection
    scan_id = str(uuid.uuid4())[:8]
    with _scans_lock:
        _evict_old_scans()
        _scans[scan_id] = {
            "status": "starting",
            "target": target,
            "mode": mode,
            "started_at": time.time(),
        }
    
    def run_enum():
        try:
            with _scans_lock:
                _scans[scan_id]["status"] = "running"
            output = _run_sqlmap_enum(target, mode, cookie, **kwargs)
            with _scans_lock:
                _scans[scan_id]["status"] = "completed"
                _scans[scan_id]["output"] = output
        except Exception as e:
            with _scans_lock:
                _scans[scan_id]["status"] = "error"
                _scans[scan_id]["error"] = str(e)
    
    thread = Thread(target=run_enum)
    thread.daemon = True
    thread.start()
    
    tool_descriptions = {
        "sqlmap_enum_databases": "Enumerating databases",
        "sqlmap_enum_tables": f"Enumerating tables in database: {arguments.get('database', '')}",
        "sqlmap_enum_columns": f"Enumerating columns in table: {arguments.get('table', '')}",
        "sqlmap_dump": f"Dumping data from: {arguments.get('database', '')}.{arguments.get('table', '')}",
        "sqlmap_users": "Getting database users",
        "sqlmap_passwords": "Getting password hashes",
        "sqlmap_shell": "Starting SQL shell",
        "sqlmap_os_shell": "Getting OS shell",
    }
    
    return f"""🔍 {tool_descriptions.get(tool_name, 'Running')}...

Scan ID: {scan_id}

Use these commands to check status:
• sqlmap_status (scan_id: {scan_id})
• sqlmap_results (scan_id: {scan_id})"""


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
            # Defense-in-depth: the backend's generic manifest dispatcher is the primary gate for every
            # exploitation-class tool (checked before this server is ever called) — this server itself never
            # verified the opt-in independently, so anything else reachable on the internal Docker network could
            # otherwise call these directly (dump data, spawn an OS shell, read/write arbitrary files) with no check.
            _OFFENSIVE_SQLMAP_TOOLS = {
                "sqlmap_dump", "sqlmap_full_chain", "sqlmap_os_shell",
                "sqlmap_read_file", "sqlmap_shell", "sqlmap_write_file",
            }
            if tool_name in _OFFENSIVE_SQLMAP_TOOLS:
                from mcp_auth import offensive_action_allowed
                if not offensive_action_allowed():
                    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text",
                        "text": f"[!] '{tool_name}' is an exploitation-class action and requires "
                                "SOCIS_AGENT_ALLOW_OFFENSIVE to be enabled on the server (defense-in-depth check — "
                                "the backend's own gate should already have blocked this)."}]}})
            try:
                if tool_name == "sqlmap_scan":
                    target    = arguments.get("target", "")
                    validate_url_target(target)
                    data      = arguments.get("data")
                    cookie    = arguments.get("cookie")
                    level     = max(1, min(5,  int(arguments.get("level",     3))))
                    risk      = max(1, min(3,  int(arguments.get("risk",      2))))
                    threads   = max(1, min(10, int(arguments.get("threads",   4))))
                    technique = str(arguments.get("technique", "BEUSTQ")).upper()
                    technique = "".join(c for c in technique if c in "BEUSTQ") or "BEUSTQ"
                    dbms      = str(arguments.get("dbms", "") or "")
                    proxy     = str(arguments.get("proxy", "") or "")
                    headers   = str(arguments.get("headers", "") or "")
                    auth_type = str(arguments.get("auth_type", "") or "")
                    auth_cred = str(arguments.get("auth_cred", "") or "")
                    delay     = max(0, min(30,  int(arguments.get("delay",     0))))
                    timeout_secs = max(5, min(120, int(arguments.get("timeout_secs", 30))))
                    retries   = max(0, min(10, int(arguments.get("retries",    2))))
                    time_sec  = max(1, min(60, int(arguments.get("time_sec",   5))))
                    tamper    = str(arguments.get("tamper", "") or "")

                    loop = asyncio.get_event_loop()
                    scan_result = await loop.run_in_executor(
                        None, _sqlmap_scan_sync,
                        target, data, cookie, level, risk, technique, threads,
                        dbms, proxy, headers, auth_type, auth_cred,
                        delay, timeout_secs, retries, time_sec, tamper
                    )
                    return JSONResponse({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": json.dumps(scan_result, indent=2)}]}
                    })
                elif tool_name == "sqlmap_full_chain":
                    target    = arguments.get("target", "")
                    validate_url_target(target)
                    data      = arguments.get("data")
                    cookie    = arguments.get("cookie")
                    level     = max(1, min(5,  int(arguments.get("level",     3))))
                    risk      = max(1, min(3,  int(arguments.get("risk",      2))))
                    threads   = max(1, min(10, int(arguments.get("threads",   4))))
                    technique = str(arguments.get("technique", "BEUSTQ")).upper()
                    technique = "".join(c for c in technique if c in "BEUSTQ") or "BEUSTQ"
                    dbms      = str(arguments.get("dbms", "") or "")
                    proxy     = str(arguments.get("proxy", "") or "")
                    headers   = str(arguments.get("headers", "") or "")
                    auth_type = str(arguments.get("auth_type", "") or "")
                    auth_cred = str(arguments.get("auth_cred", "") or "")
                    delay     = max(0, min(30,  int(arguments.get("delay",     0))))
                    timeout_secs = max(5, min(120, int(arguments.get("timeout_secs", 30))))
                    retries   = max(0, min(10, int(arguments.get("retries",    2))))
                    time_sec  = max(1, min(60, int(arguments.get("time_sec",   5))))
                    tamper    = str(arguments.get("tamper", "") or "")

                    loop = asyncio.get_event_loop()
                    chain_result = await loop.run_in_executor(
                        None, _sqlmap_full_chain_sync,
                        target, data, cookie, level, risk, technique, threads,
                        dbms, proxy, headers, auth_type, auth_cred,
                        delay, timeout_secs, retries, time_sec, tamper
                    )
                    return JSONResponse({
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"content": [{"type": "text", "text": json.dumps(chain_result, indent=2)}]}
                    })
                elif tool_name == "sqlmap_status":
                    scan_id = arguments.get("scan_id", "")
                    result = handle_sqlmap_status(scan_id)
                    return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": str(result)}]}}
                elif tool_name == "sqlmap_results":
                    scan_id = arguments.get("scan_id", "")
                    result = handle_sqlmap_results(scan_id)
                    return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": result}]}}
                elif tool_name in ["sqlmap_enum_databases", "sqlmap_enum_tables", "sqlmap_enum_columns", "sqlmap_dump", "sqlmap_users", "sqlmap_passwords", "sqlmap_shell", "sqlmap_os_shell", "sqlmap_privileges", "sqlmap_roles", "sqlmap_schema", "sqlmap_current_db", "sqlmap_current_user", "sqlmap_is_dba", "sqlmap_read_file", "sqlmap_write_file"]:
                    result = handle_enum_tool(tool_name, arguments)
                    return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": result}]}}
                else:
                    raise ValueError(f"Unknown tool: {tool_name}")
            except Exception as e:
                err_msg = str(e) or f"[{type(e).__name__}]"
                return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": err_msg}}, status_code=400)
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
    uvicorn.run(app, host="0.0.0.0", port=8109, log_level="warning")
