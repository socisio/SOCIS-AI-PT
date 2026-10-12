# Backend Integration Guide for New MCPs

This document shows exactly how to integrate new MCP servers with the SOCIS-AI-PT backend.

## Files to Modify

### 1. `backend/app/mcp/client.py`

Add your new MCP server registration in the `_register_builtin_servers()` function.

**Location**: [Lines 260-320 in current file](file://d:\SOCIS-AI-PT\backend\app\mcp\client.py#L260)

**Current Pattern** (copy and modify):

```python
def _register_builtin_servers(client: MCPClient):
    """Register all built-in SOCIS-AI-PT MCP servers."""

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

    # ... existing servers ...

    # NEW: Add your MCP here
    # X. [YourToolName] MCP (HTTP)
    client.register_server(MCPServer(
        name="{tool}_mcp",
        transport="http",
        url="http://mcp_all:{PORT}" if _is_docker() else "http://localhost:{PORT}",
        status="unconfigured",
    ))
```

> **Important**: All MCP servers run inside the single `socis_mcp_all` container. The Docker hostname is always `mcp_all` regardless of the logical server name. Only the port differs per server.

**Example - Adding a custom MCP at port 8120**:

```python
    # X. My Custom MCP (HTTP)
    client.register_server(MCPServer(
        name="my_custom_mcp",
        transport="http",
        url="http://mcp_all:8120" if _is_docker() else "http://localhost:8120",
        status="unconfigured",
    ))
```

**Key Points**:
- Each MCP needs a unique `name` (logical identifier used by the AI)
- The Docker hostname is always `mcp_all` — this is the consolidated container
- Use `_is_docker()` conditional for portability (Docker vs local dev)
- Transport is always "http" for our architecture
- Initial status is "unconfigured" (client discovers tools on first call)

### 2. `backend/app/config.py`

Add configuration flags for your tool.

**Location**: Look for `MCP_*_ENABLED` settings

**Current Pattern**:

```python
class Settings(BaseSettings):
    # ... existing settings ...
    
    # MCP Server Toggles
    MCP_NMAP_ENABLED: bool = True
    MCP_NUCLEI_ENABLED: bool = True
    MCP_CVE_ENABLED: bool = True
    MCP_OSINT_ENABLED: bool = True
    MCP_METASPLOIT_ENABLED: bool = True
    
    # ADD HERE:
    MCP_{TOOLNAME}_ENABLED: bool = True
```

**Example - OWASP ZAP**:

```python
    MCP_OWASP_ZAP_ENABLED: bool = True
```

**Tool Timeout Configuration**:

Add timeout settings for long-running tools:

```python
    # Tool Execution Timeouts (seconds)
    TOOL_TIMEOUT_DEFAULT: int = 120
    TOOL_TIMEOUT_NMAP: int = 300
    TOOL_TIMEOUT_NIKTO: int = 600
    TOOL_TIMEOUT_NUCLEI: int = 600
    
    # ADD HERE:
    TOOL_TIMEOUT_{TOOLNAME}: int = {SECONDS}
```

**Example - OWASP ZAP timeout**:

```python
    TOOL_TIMEOUT_OWASP_ZAP: int = 900  # 15 minutes for thorough scans
```

### 3. (Optional) `backend/app/api/v1/mcp.py`

This file already handles dynamic MCP discovery, so **NO CHANGES NEEDED** unless you want custom endpoints.

Current implementation automatically:
- Discovers all registered MCPs
- Lists their tools
- Routes tool calls to the correct server
- Handles errors and timeouts

### 4. (Optional) `.env` and `.env.example`

Add environment variables for tool-specific configuration.

**Pattern**:

```env
# [ToolName] Configuration
{TOOL}_API_KEY=
{TOOL}_CONFIG_PATH=/config/{tool}.conf
{TOOL}_LOG_LEVEL=info
{TOOL}_ENABLE_CACHING=true
```

**Example - OWASP ZAP**:

```env
# OWASP ZAP Configuration
ZAP_API_KEY=
ZAP_PROXY_HOST=localhost
ZAP_PROXY_PORT=8090
ZAP_TIMEOUT=900
ZAP_ENABLE_API=true
```

Update `.env.example` with:
```env
# Copy actual values or leave empty for defaults
ZAP_API_KEY=
ZAP_PROXY_HOST=localhost
ZAP_PROXY_PORT=8090
```

## Step-by-Step Integration

### Step 1: Create MCP Server File
✅ Create `{tool}_server.py` in `/mcp-servers/`
   - See template_server.py for template
   - Define TOOLS list with tool schema
   - Implement handle_tool_X functions

### Step 2: Add Supervisord Entry
✅ Add a `[program:{tool}_mcp]` entry to `mcp-servers/supervisord.conf`
   - Set the correct port via `--port` argument or env var in the command
   - Set `autostart=true`, `autorestart=true`
   - All processes run inside the same `socis_mcp_all` container
   - Add the port to the `ports:` list in `deploy/docker/docker-compose.yml` under `mcp_all`

### Step 3: Register in Backend
✅ Update `backend/app/mcp/client.py`
   - Add registration in `_register_builtin_servers()`
   - Use same port as docker-compose

### Step 4: Add Configuration
✅ Update `backend/app/config.py`
   - Add MCP_{TOOL}_ENABLED setting
   - Add TOOL_TIMEOUT_{TOOL} setting
   - Default timeouts: 120-900 seconds

### Step 5: Add Environment Variables (Optional)
✅ Update `.env` and `.env.example`
   - Add tool-specific env vars
   - Document configuration

### Step 6: Rebuild and Test
```bash
# Rebuild the consolidated mcp_all image (includes your new server)
cd deploy/docker
docker compose build mcp_all

# Recreate mcp_all with the new image
docker compose up -d mcp_all

# Rebuild and restart backend to pick up client.py changes
docker compose build backend worker
docker compose up -d backend worker

# Confirm your new process is running inside mcp_all
docker exec socis_mcp_all supervisorctl \
  -c /etc/supervisor/supervisord.conf \
  -s unix:///tmp/supervisor.sock status

# Verify registration via API
curl -H "Authorization: Bearer {TOKEN}" \
  http://localhost/api/v1/mcp/servers
```

## Complete Example: Adding OWASP ZAP MCP

### 1️⃣ Create `owasp_zap_server.py`

```python
#!/usr/bin/env python3
"""SOCIS-AI-PT — OWASP ZAP MCP Server"""

import json
import asyncio
import httpx
import logging
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

log = logging.getLogger(__name__)
app = FastAPI(title="SOCIS OWASP ZAP MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "owasp-zap-mcp"
ZAP_HOST = "owasp_zap_api"
ZAP_PORT = 8080

TOOLS = [
    {
        "name": "active_scan",
        "description": "Run OWASP ZAP active scan on target URL. Actively tests for vulnerabilities.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Target URL (e.g., https://example.com)"
                },
                "scan_policy": {
                    "type": "string",
                    "description": "Scan policy: default, light, balanced, aggressive",
                    "default": "balanced"
                },
                "context_name": {
                    "type": "string",
                    "description": "Context/site name in ZAP",
                    "default": "Default Context"
                }
            },
            "required": ["target_url"]
        }
    },
    {
        "name": "baseline_scan",
        "description": "Run OWASP ZAP baseline scan. Passive scanning only, no active testing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_url": {"type": "string"},
                "ajax_spider": {
                    "type": "boolean",
                    "description": "Enable AJAX spider for JavaScript-heavy sites",
                    "default": False
                }
            },
            "required": ["target_url"]
        }
    },
    {
        "name": "generate_report",
        "description": "Generate HTML/PDF report of scan results",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {
                    "type": "string",
                    "description": "Scan ID from active_scan or baseline_scan"
                },
                "report_type": {
                    "type": "string",
                    "enum": ["html", "pdf", "markdown"],
                    "default": "html"
                }
            },
            "required": ["scan_id"]
        }
    }
]

@app.get("/health")
async def health():
    return {"status": "healthy", "server": SERVER_NAME}

@app.post("/")
async def handle_request(request: Request):
    data = await request.json()
    method = data.get("method")
    
    if method == "tools/list":
        return JSONResponse({"tools": TOOLS})
    
    elif method == "tools/call":
        tool_name = data.get("params", {}).get("name")
        arguments = data.get("params", {}).get("arguments", {})
        
        try:
            if tool_name == "active_scan":
                result = await handle_active_scan(arguments)
            elif tool_name == "baseline_scan":
                result = await handle_baseline_scan(arguments)
            elif tool_name == "generate_report":
                result = await handle_generate_report(arguments)
            else:
                return JSONResponse({"error": f"Unknown tool: {tool_name}"}, status_code=400)
            
            return JSONResponse({"result": result, "success": True})
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=500)
    
    return JSONResponse({"error": "Unknown method"}, status_code=400)

async def handle_active_scan(args: dict) -> dict:
    target = args.get("target_url")
    policy = args.get("scan_policy", "balanced")
    
    async with httpx.AsyncClient() as client:
        # Start scan
        response = await client.get(
            f"http://{ZAP_HOST}:{ZAP_PORT}/JSON/ascan/action/scan",
            params={
                "url": target,
                "scanPolicyName": policy
            }
        )
        scan_id = response.json().get("scan")
        
        # Poll for completion
        while True:
            status = await client.get(
                f"http://{ZAP_HOST}:{ZAP_PORT}/JSON/ascan/view/scanProgress",
                params={"scanId": scan_id}
            )
            progress = status.json().get("scanProgress", [{}])[0].get("Progress", "0")
            
            if progress == "100":
                break
            
            await asyncio.sleep(5)
        
        # Get alerts
        alerts = await client.get(
            f"http://{ZAP_HOST}:{ZAP_PORT}/JSON/core/view/alerts",
            params={"baseurl": target}
        )
        
        return {
            "scan_id": scan_id,
            "target": target,
            "policy": policy,
            "status": "completed",
            "alerts": alerts.json().get("alerts", [])
        }

async def handle_baseline_scan(args: dict) -> dict:
    target = args.get("target_url")
    ajax = args.get("ajax_spider", False)
    
    async with httpx.AsyncClient() as client:
        # Spider target
        spider = await client.get(
            f"http://{ZAP_HOST}:{ZAP_PORT}/JSON/spider/action/scan",
            params={"url": target, "ajax": "true" if ajax else "false"}
        )
        
        await asyncio.sleep(10)  # Let passive scanner work
        
        alerts = await client.get(
            f"http://{ZAP_HOST}:{ZAP_PORT}/JSON/core/view/alerts",
            params={"baseurl": target}
        )
        
        return {
            "target": target,
            "scan_type": "baseline",
            "status": "completed",
            "alerts": alerts.json().get("alerts", [])
        }

async def handle_generate_report(args: dict) -> dict:
    scan_id = args.get("scan_id")
    report_type = args.get("report_type", "html")
    
    # Implementation depends on ZAP API for report generation
    return {
        "scan_id": scan_id,
        "report_type": report_type,
        "location": f"/reports/{scan_id}.{report_type}"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8106)
```

### 2️⃣ Update `docker-compose.yml`

Add at end of services section:

```yaml
  owasp_zap_mcp:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: socis_owasp_zap_mcp
    restart: unless-stopped
    command: ["python3", "owasp_zap_server.py"]
    ports:
      - "8106:8106"
    networks: [socis-net]
    depends_on:
      owasp_zap_api:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8106/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  owasp_zap_api:
    image: owasp/zap2docker-stable:latest
    container_name: socis_owasp_zap_api
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "8090:8090"
    networks: [socis-net]
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### 3️⃣ Update `backend/app/mcp/client.py`

In `_register_builtin_servers()` function, add:

```python
    # 6. OWASP ZAP MCP (HTTP)
    client.register_server(MCPServer(
        name="owasp_zap_mcp",
        transport="http",
        url="http://owasp_zap_mcp:8106" if _is_docker() else "http://localhost:8106",
        status="unconfigured",
    ))
```

### 4️⃣ Update `backend/app/config.py`

Add:

```python
    MCP_OWASP_ZAP_ENABLED: bool = True
    TOOL_TIMEOUT_OWASP_ZAP: int = 900  # 15 minutes
```

### 5️⃣ Test Integration

```bash
# Start services
cd mcp-servers
docker-compose up -d

# Check status
docker-compose ps
curl http://localhost:8106/health

# Restart backend
cd ../deploy/docker
docker-compose restart backend
sleep 10

# Test via API
TOKEN=$(curl -s -X POST http://localhost/api/v1/auth/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin&password=admin' | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Check if new MCP is registered
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost/api/v1/mcp/servers | python3 -m json.tool | grep -i "owasp"

# Test tool execution
curl -s -X POST http://localhost/api/v1/mcp/servers/owasp_zap_mcp/test \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

## Troubleshooting

### MCP Not Appearing in API

```bash
# Check docker logs
docker-compose logs owasp_zap_mcp --tail=50

# Check backend can reach it
docker-compose exec backend curl http://owasp_zap_mcp:8106/health

# Check backend config reloaded
docker-compose logs backend --tail=20 | grep "registered"
```

### Tool Discovery Fails

```bash
# Test MCP directly
curl http://localhost:8106/ \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"method":"tools/list"}'
```

### Timeout Issues

- Increase TOOL_TIMEOUT in config.py
- Check container resources (CPU, memory)
- Monitor with: `docker stats owasp_zap_mcp`

## Next: Test Your MCP

Once integrated, test via:

1. **API Endpoint**: `GET /api/v1/mcp/servers/{name}`
2. **Tool List**: `GET /api/v1/mcp/servers/{name}/tools`
3. **Tool Execution**: `POST /api/v1/mcp/servers/{name}/call`
4. **Frontend UI**: Tools page auto-discovers new MCPs

---

**Status**: Ready for Implementation  
**Last Updated**: 2026-04-17

---

## Currently Registered MCP Servers

| Port | Name | Description |
|------|------|-------------|
| 8100 | `cve_mcp` | NVD CVE database queries |
| 8101 | `nmap_mcp` | Network port/service/OS scanning |
| 8102 | `nuclei_mcp` | Template-based vulnerability scanning |
| 8103 | `osint_mcp` | Passive reconnaissance (WHOIS, DNS, geoIP) |
| 8104 | `metasploit_mcp` | Full Metasploit Framework via RPC |
| 8107 | `waf_detection_mcp` | WAF detection and bypass testing |
| 8108 | `ffuf_mcp` | Web directory/parameter/subdomain fuzzing |
| 8109 | `sqlmap_mcp` | SQL injection detection & exploitation |
| 8112 | `ssl_mcp` | TLS/certificate analysis |
| 8114 | `cisa_kev_mcp` | CISA Known Exploited Vulnerabilities |
| 8115 | `epss_mcp` | FIRST.org EPSS exploitation probability |
| 8116 | `poc_mcp` | PoC exploit search (Sploitus/GitHub/ExploitDB) |
| 8117 | `nikto_mcp` | Web server vulnerability scanner |
| 8118 | `masscan_mcp` | Massively fast port scanner |
| 8119 | `wpscan_mcp` | WordPress vulnerability scanner |
| 8120 | `jwt_mcp` | JWT decode, forge and attack testing |
| 8121 | `gobuster_mcp` | Directory, DNS and vhost brute-force |

> Next available port: **8122**
