"""
SOCIS-AI-PT — MCP API Routes (Updated with real client)
"""

from fastapi import APIRouter, Depends, HTTPException
from app.core.security import require_permission
from app.mcp.client import get_mcp_client, MCPServer
import logging
logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/servers")
async def list_mcp_servers(token: dict = Depends(require_permission("scans:read"))):
    """List all registered MCP servers and their status."""
    client = get_mcp_client()
    return {"servers": client.list_servers()}


@router.post("/servers")
async def add_mcp_server(
    data: dict,
    token: dict = Depends(require_permission("admin:write")),
):
    """Register a new MCP server (http/sse; stdio only if explicitly enabled)."""
    from app.config import settings
    from app.core.mcp_registration import validate_registration, RegistrationError
    client = get_mcp_client()
    try:
        spec = validate_registration(
            data,
            allow_stdio=bool(getattr(settings, "MCP_ALLOW_STDIO_SERVERS", False)),
            existing=set(client._servers.keys()),
        )
    except RegistrationError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message)
    client.register_server(MCPServer(
        name=spec["name"], transport=spec["transport"],
        command=spec["command"], url=spec["url"],
    ))
    return {"message": f"Server '{spec['name']}' registered", "server": spec["name"]}


@router.delete("/servers/{name}")
async def remove_mcp_server(
    name: str,
    token: dict = Depends(require_permission("admin:write")),
):
    """Remove a registered MCP server."""
    client = get_mcp_client()
    if name not in client._servers:
        raise HTTPException(status_code=404, detail=f"Server '{name}' not found")
    del client._servers[name]
    return {"message": f"Server '{name}' removed"}


@router.post("/servers/{name}/test")
async def test_mcp_server(
    name: str,
    token: dict = Depends(require_permission("scans:read")),
):
    """Test connectivity and discover tools for a registered MCP server."""
    client = get_mcp_client()
    server = client.get_server(name)
    if not server:
        raise HTTPException(status_code=404, detail=f"Server '{name}' not found")

    try:
        tools = await client.discover_tools(name)
        return {
            "server": name,
            "status": "online",
            "tools": [{"name": t.name, "description": t.description} for t in tools],
            "tool_count": len(tools),
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Server '{name}' unreachable: {str(e)}")


from app.core.scope_guard import ScopeViolation


@router.post("/servers/{name}/call")
async def call_mcp_tool(
    name: str,
    data: dict,
    token: dict = Depends(require_permission("scans:execute")),
):
    """
    Call a specific tool on an MCP server.
    Body: { "tool": "nmap_scan", "arguments": { "target": "192.168.1.1" } }
    """
    client = get_mcp_client()
    tool_name = data.get("tool")
    arguments = data.get("arguments", {})

    if not tool_name:
        raise HTTPException(status_code=400, detail="'tool' is required")

    try:
        # Some tools (amass, nuclei, etc.) need more than the default 120s.
        # Metasploit listing tools poll for up to 60s internally; add headroom.
        long_running = {"nuclei_scan", "sqlmap_scan", "ffuf_fuzz"}
        metasploit_tools = {
            "list_all_exploits", "list_auxiliary_modules", "list_exploit_modules",
            "list_post_modules", "list_payloads", "run_exploit", "run_auxiliary_module",
            "run_post_module", "generate_payload", "run_exploit_module",
        }
        if tool_name in metasploit_tools:
            tool_timeout = 300
        elif tool_name in long_running:
            tool_timeout = 300
        else:
            tool_timeout = 120
        from app.core.scope_guard import set_source
        set_source("mcp_console")
        result = await client.call_tool(name, tool_name, arguments, timeout=tool_timeout)
        return {"server": name, "tool": tool_name, "result": result}
    except ScopeViolation as e:
        raise HTTPException(status_code=403, detail=str(e), headers={"X-SOCIS-Error": "target_out_of_scope", "X-SOCIS-Can-Override": "0"})
    except TimeoutError as e:
        logger.warning("Request failed (HTTP 504)", exc_info=True)
        raise HTTPException(status_code=504, detail="Upstream service timed out")
    except ValueError as e:
        logger.warning("Request failed (HTTP 404)", exc_info=True)
        raise HTTPException(status_code=404, detail="Not found")
    except Exception as e:
        logger.warning("Request failed (HTTP 500)", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal error")


@router.get("/servers/{name}/tools")
async def list_server_tools(
    name: str,
    token: dict = Depends(require_permission("scans:read")),
):
    """List all discovered tools for a specific MCP server, refreshing discovery."""
    client = get_mcp_client()
    server = client.get_server(name)
    if not server:
        raise HTTPException(status_code=404, detail=f"Server '{name}' not found")
    try:
        tools = await client.discover_tools(name)
        return {"server": name, "tools": [{"name": t.name, "description": t.description, "schema": t.input_schema} for t in tools]}
    except Exception as e:
        logger.warning("Request failed (HTTP 503)", exc_info=True)
        raise HTTPException(status_code=503, detail="Service unavailable")


@router.get("/tool-guide")
async def get_tool_guide(token: dict = Depends(require_permission("scans:read"))):
    """
    Return a structured list of all MCP servers and their tools for the UI help modal.
    Response: { "servers": [{ "server", "url", "status", "tools": [{ "name", "description", "example" }] }] }
    """
    from app.services.system_prompt import build_tool_guide
    client = get_mcp_client()
    return {"servers": build_tool_guide(client)}
