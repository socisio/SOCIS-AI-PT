"""
SOCIS-AI-PT — Async MCP Client
Connects to MCP servers and manages tool discovery + execution.
"""

import json
import asyncio
import subprocess
import httpx
import os
from typing import Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from app.config import settings

import logging
log = logging.getLogger(__name__)

# Shared MCP auth token — must match what MCP servers expect
_MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")


@dataclass
class MCPTool:
    name: str
    description: str
    input_schema: dict = field(default_factory=dict)


@dataclass
class MCPServer:
    name: str
    transport: str   # "stdio" | "http" | "sse"
    command: Optional[list[str]] = None
    url: Optional[str] = None
    status: str = "unconfigured"
    tools: list[MCPTool] = field(default_factory=list)
    _process: Optional[asyncio.subprocess.Process] = None


class MCPClient:
    """
    Async MCP client for SOCIS-AI-PT.
    Manages multiple MCP server connections via stdio or HTTP.
    """

    def __init__(self):
        self._servers: dict[str, MCPServer] = {}
        self._lock = asyncio.Lock()

    # ─── Server Registry ──────────────────────────────────────

    def register_server(self, server: MCPServer):
        self._servers[server.name] = server
        log.info(f"[MCP] Registered server: {server.name} ({server.transport})")

    def get_server(self, name: str) -> Optional[MCPServer]:
        return self._servers.get(name)

    def list_servers(self) -> list[dict]:
        return [
            {
                "name": s.name,
                "transport": s.transport,
                "status": s.status,
                "tools": [
                    {
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.input_schema,
                    }
                    for t in s.tools
                ],
            }
            for s in self._servers.values()
        ]

    # ─── Tool Discovery ───────────────────────────────────────

    async def discover_tools(self, server_name: str) -> list[MCPTool]:
        server = self._servers.get(server_name)
        if not server:
            raise ValueError(f"Server '{server_name}' not registered")

        try:
            if server.transport in ("stdio",):
                tools = await self._stdio_list_tools(server)
            elif server.transport == "http":
                tools = await self._http_list_tools(server)
            elif server.transport == "sse":
                tools = await self._http_list_tools(server)
            else:
                raise ValueError(f"Unknown transport: {server.transport}")

            server.tools = tools
            server.status = "online"
            return tools
        except Exception as e:
            server.status = "error"
            log.error(f"[MCP] Tool discovery failed for {server_name}: {e}")
            raise

    # ─── Tool Execution ───────────────────────────────────────

    async def call_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: dict[str, Any],
        timeout: int = 120,
    ) -> dict[str, Any]:
        # Authorized scope: refuse (ScopeViolation) when the arguments aim at a target outside the caller's authorized scope.
        from app.core.scope_guard import check_tool_call
        await check_tool_call(tool_name, arguments)
        server = self._servers.get(server_name)
        if not server:
            raise ValueError(f"Server '{server_name}' not registered")

        log.info(f"[MCP] Calling {server_name}.{tool_name} with {list(arguments.keys())}")
        start = datetime.utcnow()

        try:
            if server.transport == "stdio":
                result = await self._stdio_call_tool(server, tool_name, arguments, timeout)
            elif server.transport in ("http", "sse"):
                result = await self._http_call_tool(server, tool_name, arguments, timeout)
            else:
                raise ValueError(f"Unknown transport: {server.transport}")

            elapsed = (datetime.utcnow() - start).total_seconds()
            log.info(f"[MCP] {server_name}.{tool_name} completed in {elapsed:.2f}s")
            return result
        except asyncio.TimeoutError:
            server.status = "timeout"
            raise TimeoutError(f"Tool {tool_name} timed out after {timeout}s")
        except Exception as e:
            server.status = "error"
            log.error(f"[MCP] Error calling {server_name}.{tool_name}: {e}")
            raise

    # ─── stdio Transport ──────────────────────────────────────

    async def _stdio_call_tool(
        self,
        server: MCPServer,
        tool_name: str,
        arguments: dict,
        timeout: int,
    ) -> dict:
        if not server.command:
            raise ValueError(f"No command configured for stdio server {server.name}")

        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        payload = json.dumps(request) + "\n"

        try:
            proc = await asyncio.create_subprocess_exec(
                *server.command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(payload.encode()),
                timeout=timeout,
            )
            raw = stdout.decode().strip()
            if not raw:
                raise RuntimeError(f"Empty response from MCP server. stderr: {stderr.decode()}")

            response = json.loads(raw)
            if "error" in response:
                raise RuntimeError(f"MCP Error: {response['error']}")
            return response.get("result", {})
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Invalid JSON from MCP server: {e}")

    async def _stdio_list_tools(self, server: MCPServer) -> list[MCPTool]:
        if not server.command:
            return []

        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        payload = json.dumps(request) + "\n"

        proc = await asyncio.create_subprocess_exec(
            *server.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(payload.encode()), timeout=30)
        response = json.loads(stdout.decode().strip())
        tools_data = response.get("result", {}).get("tools", [])
        return [
            MCPTool(
                name=t["name"],
                description=t.get("description", ""),
                input_schema=t.get("inputSchema", {}),
            )
            for t in tools_data
        ]

    # ─── HTTP / SSE Transport ─────────────────────────────────

    async def _http_call_tool(
        self,
        server: MCPServer,
        tool_name: str,
        arguments: dict,
        timeout: int,
    ) -> dict:
        if not server.url:
            raise ValueError(f"No URL configured for HTTP server {server.name}")

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        try:
            _headers = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            }
            if _MCP_AUTH_TOKEN:
                _headers["Authorization"] = f"Bearer {_MCP_AUTH_TOKEN}"
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    f"{server.url}/mcp",
                    json=payload,
                    headers=_headers,
                )
                if response.status_code >= 400:
                    # Try to parse JSON error body before raising
                    try:
                        err_data = response.json()
                        err_msg = err_data.get("error", {})
                        if isinstance(err_msg, dict):
                            err_msg = err_msg.get("message", response.text)
                        raise RuntimeError(f"MCP server error ({response.status_code}): {err_msg}")
                    except (ValueError, KeyError):
                        raise RuntimeError(f"MCP server error ({response.status_code}): {response.text}")
                data = response.json()
                if "error" in data:
                    err = data["error"]
                    msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
                    raise RuntimeError(f"MCP Error: {msg}")
                return data.get("result", {})
        except httpx.TimeoutException:
            raise TimeoutError(f"MCP server '{server.name}' timed out after {timeout}s")

    async def _http_list_tools(self, server: MCPServer) -> list[MCPTool]:
        if not server.url:
            return []
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        _headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if _MCP_AUTH_TOKEN:
            _headers["Authorization"] = f"Bearer {_MCP_AUTH_TOKEN}"
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(
                f"{server.url}/mcp",
                json=payload,
                headers=_headers,
            )
            response.raise_for_status()
            tools_data = response.json().get("result", {}).get("tools", [])
        return [
            MCPTool(name=t["name"], description=t.get("description", ""), input_schema=t.get("inputSchema", {}))
            for t in tools_data
        ]

    # ─── Connectivity Test ────────────────────────────────────

    async def test_server(self, server_name: str) -> bool:
        try:
            await self.discover_tools(server_name)
            return True
        except Exception:
            return False


# ─── Singleton ────────────────────────────────────────────────

_mcp_client: Optional[MCPClient] = None


def get_mcp_client() -> MCPClient:
    global _mcp_client
    if _mcp_client is None:
        _mcp_client = MCPClient()
        _register_builtin_servers(_mcp_client)
    return _mcp_client


def _is_docker() -> bool:
    """Check if running inside a Docker container."""
    try:
        with open('/.dockerenv', 'r'):
            return True
    except FileNotFoundError:
        return False


def _register_builtin_servers(client: MCPClient):
    """Register all 8 built-in SOCIS-AI-PT MCP servers."""

    # 1. Nmap MCP (HTTP)
    client.register_server(MCPServer(
        name="nmap_mcp",
        transport="http",
        url="http://mcp_all:8101" if _is_docker() else "http://localhost:8101",
        status="unconfigured",
    ))

    # 2. Nuclei MCP (HTTP)
    client.register_server(MCPServer(
        name="nuclei_mcp",
        transport="http",
        url="http://mcp_all:8102" if _is_docker() else "http://localhost:8102",
        status="unconfigured",
    ))

    # 3. CVE/NVD MCP (HTTP)
    client.register_server(MCPServer(
        name="cve_mcp",
        transport="http",
        url="http://mcp_all:8100" if _is_docker() else "http://localhost:8100",
        status="unconfigured",
    ))

    # 4. OSINT MCP (HTTP)
    client.register_server(MCPServer(
        name="osint_mcp",
        transport="http",
        url="http://mcp_all:8103" if _is_docker() else "http://localhost:8103",
        status="unconfigured",
    ))

    # 5. Metasploit MCP (HTTP)
    client.register_server(MCPServer(
        name="metasploit_mcp",
        transport="http",
        url="http://mcp_all:8104" if _is_docker() else "http://localhost:8104",
        status="unconfigured",
    ))

    # 6. WAF Detection MCP (HTTP) - Phase 1 Web Security
    client.register_server(MCPServer(
        name="waf_detection_mcp",
        transport="http",
        url="http://mcp_all:8107" if _is_docker() else "http://localhost:8107",
        status="unconfigured",
    ))

    # 9. ffuf MCP (HTTP) - Phase 7 Directory/API Fuzzing
    client.register_server(MCPServer(
        name="ffuf_mcp",
        transport="http",
        url="http://mcp_all:8108" if _is_docker() else "http://localhost:8108",
        status="unconfigured",
    ))

    # 10. SQLMap MCP (HTTP) - Phase 7 SQL Injection
    client.register_server(MCPServer(
        name="sqlmap_mcp",
        transport="http",
        url="http://mcp_all:8109" if _is_docker() else "http://localhost:8109",
        status="unconfigured",
    ))

    # 11. SSL Labs MCP (HTTP) - Phase 7 TLS/SSL Grading
    client.register_server(MCPServer(
        name="ssl_mcp",
        transport="http",
        url="http://mcp_all:8112" if _is_docker() else "http://localhost:8112",
        status="unconfigured",
    ))

    # 12. CISA KEV MCP (HTTP) - Known Exploited Vulnerabilities catalog
    client.register_server(MCPServer(
        name="cisa_kev_mcp",
        transport="http",
        url="http://mcp_all:8114" if _is_docker() else "http://localhost:8114",
        status="unconfigured",
    ))

    # 16. EPSS MCP (HTTP) - Exploit Prediction Scoring System
    client.register_server(MCPServer(
        name="epss_mcp",
        transport="http",
        url="http://mcp_all:8115" if _is_docker() else "http://localhost:8115",
        status="unconfigured",
    ))

    # 17. PoC Index MCP (HTTP) - Proof-of-Concept exploit search (Sploitus, GitHub, ExploitDB)
    client.register_server(MCPServer(
        name="poc_mcp",
        transport="http",
        url="http://mcp_all:8116" if _is_docker() else "http://localhost:8116",
        status="unconfigured",
    ))

    # Nikto MCP (HTTP) - Web server vulnerability scanner
    client.register_server(MCPServer(
        name="nikto_mcp",
        transport="http",
        url="http://mcp_all:8117" if _is_docker() else "http://localhost:8117",
        status="unconfigured",
    ))

    # Masscan MCP (HTTP) - Massively fast port scanner
    client.register_server(MCPServer(
        name="masscan_mcp",
        transport="http",
        url="http://mcp_all:8118" if _is_docker() else "http://localhost:8118",
        status="unconfigured",
    ))

    # WPScan MCP (HTTP) - WordPress vulnerability scanner
    client.register_server(MCPServer(
        name="wpscan_mcp",
        transport="http",
        url="http://mcp_all:8119" if _is_docker() else "http://localhost:8119",
        status="unconfigured",
    ))

    # JWT MCP (HTTP) - JWT decode, forge and attack testing
    client.register_server(MCPServer(
        name="jwt_mcp",
        transport="http",
        url="http://mcp_all:8120" if _is_docker() else "http://localhost:8120",
        status="unconfigured",
    ))

    # Gobuster MCP (HTTP) - Directory, DNS and vhost brute-force
    client.register_server(MCPServer(
        name="gobuster_mcp",
        transport="http",
        url="http://mcp_all:8121" if _is_docker() else "http://localhost:8121",
        status="unconfigured",
    ))

    # CVE Lite MCP (HTTP) - OWASP JS/TS dependency vulnerability scanner (OSV data)
    client.register_server(MCPServer(
        name="cve_lite_mcp",
        transport="http",
        url="http://mcp_all:8122" if _is_docker() else "http://localhost:8122",
        status="unconfigured",
    ))

    # MITRE ATT&CK MCP (HTTP) - Full ATT&CK framework: techniques, groups, software, mitigations
    if settings.MCP_MITRE_ENABLED:
        client.register_server(MCPServer(
            name="mitre_mcp",
            transport="http",
            url="http://mcp_all:8105" if _is_docker() else "http://localhost:8105",
            status="unconfigured",
        ))

    # ExploitDB MCP (HTTP) - Full Exploit-DB dataset: 47k+ exploits, 18 tools
    client.register_server(MCPServer(
        name="exploitdb_mcp",
        transport="http",
        url="http://mcp_all:8125" if _is_docker() else "http://localhost:8125",
        status="unconfigured",
    ))

    # Anomaly Detection MCP (HTTP) - ML-based traffic anomaly detection
    client.register_server(MCPServer(
        name="anomaly_mcp",
        transport="http",
        url="http://mcp_all:8123" if _is_docker() else "http://localhost:8123",
        status="unconfigured",
    ))

    # Payload Generator MCP (HTTP) - attack payload / wordlist generation
    client.register_server(MCPServer(
        name="payload_generator_mcp",
        transport="http",
        url="http://mcp_all:8124" if _is_docker() else "http://localhost:8124",
        status="unconfigured",
    ))

    # Active Directory MCP (HTTP) - NetExec/Impacket/kerbrute: SMB/LDAP enum, user enum, password spray, AS-REP roast
    client.register_server(MCPServer(
        name="ad_mcp",
        transport="http",
        url="http://mcp_all:8126" if _is_docker() else "http://localhost:8126",
        status="unconfigured",
    ))

    # Cloud Recon MCP (HTTP) - unauthenticated bucket enum, cloud fingerprinting, metadata-leak (SSRF) checks
    client.register_server(MCPServer(
        name="cloud_mcp",
        transport="http",
        url="http://mcp_all:8127" if _is_docker() else "http://localhost:8127",
        status="unconfigured",
    ))

    # Container & Kubernetes MCP (HTTP) - Trivy image/Dockerfile/K8s-manifest scanning, exposed-Docker-API check
    client.register_server(MCPServer(
        name="container_mcp",
        transport="http",
        url="http://mcp_all:8128" if _is_docker() else "http://localhost:8128",
        status="unconfigured",
    ))

    # API Security MCP (HTTP) - GraphQL introspection, OpenAPI discovery, API misconfig checks (CORS, verbose errors)
    client.register_server(MCPServer(
        name="api_security_mcp",
        transport="http",
        url="http://mcp_all:8129" if _is_docker() else "http://localhost:8129",
        status="unconfigured",
    ))

    # Secrets Scanning MCP (HTTP) - detect live credentials (API keys, tokens, private keys) in code/config content
    client.register_server(MCPServer(
        name="secrets_mcp",
        transport="http",
        url="http://mcp_all:8130" if _is_docker() else "http://localhost:8130",
        status="unconfigured",
    ))

    # DNS Deep MCP (HTTP) - zone transfer checks, subdomain takeover detection, SPF/DKIM/DMARC posture
    client.register_server(MCPServer(
        name="dns_deep_mcp",
        transport="http",
        url="http://mcp_all:8131" if _is_docker() else "http://localhost:8131",
        status="unconfigured",
    ))

    # Password Cracking MCP (HTTP) - John the Ripper wordlist attacks against hashes dumped by other tools
    client.register_server(MCPServer(
        name="crack_mcp",
        transport="http",
        url="http://mcp_all:8132" if _is_docker() else "http://localhost:8132",
        status="unconfigured",
    ))

    # Compliance Mapping MCP (HTTP) - maps findings to OWASP Top 10 / PTES phases / MITRE ATT&CK tactics
    client.register_server(MCPServer(
        name="compliance_mcp",
        transport="http",
        url="http://mcp_all:8133" if _is_docker() else "http://localhost:8133",
        status="unconfigured",
    ))
