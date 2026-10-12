# MCP Integration Guide — SOCIS-AI-PT

## Overview

Model Context Protocol (MCP) is the backbone of SOCIS-AI-PT's agentic AI capability. All 22 security servers expose a **JSON-RPC 2.0 interface over HTTP**, protected by a shared bearer token (`MCP_AUTH_TOKEN`). The FastAPI backend's MCP client discovers available tools at startup and routes AI-generated tool tags to the appropriate server at runtime.

---

## What is MCP?

MCP (Model Context Protocol) allows:
- **Language Models** to invoke external tools with typed arguments
- **Security Tools** to expose standardized schemas for discovery and execution
- **Custom Integrations** through a simple HTTP + JSON-RPC 2.0 interface

**In SOCIS-AI-PT**, the LLM emits tool-call tags (`[MCP: server.tool {...}]`) in its first-pass response. The backend parses these tags, dispatches the calls to the correct MCP servers in parallel, collects live results, and feeds them back to the LLM for its final synthesized response.

---

## Architecture

All 22 MCP servers run as supervised processes inside a **single `mcp_all` container** (managed by supervisord). This reduces the container count to just 2 (`socis_mcp_all` + `socis_metasploit_rpc`).

```
┌─────────────┐
│   Backend   │  FastAPI (Port 8000)
│  MCP Client │  app/mcp/client.py
└──────┬──────┘
       │  JSON-RPC 2.0 over HTTP + Bearer auth
       │
       ▼
┌──────────────────────────────────────────────────┐
│            socis_mcp_all container                │
│               (supervisord)                       │
│                                                   │
│  ├─► cve_mcp               (8100)  NVD CVE       │
│  ├─► nmap_mcp              (8101)  Nmap           │
│  ├─► nuclei_mcp            (8102)  Nuclei         │
│  ├─► osint_mcp             (8103)  OSINT          │
│  ├─► metasploit_mcp        (8104)  MSF RPC        │
│  ├─► mitre_mcp             (8105)  MITRE ATT&CK   │
│  ├─► waf_detection_mcp     (8107)  WAF            │
│  ├─► ffuf_mcp              (8108)  ffuf           │
│  ├─► sqlmap_mcp            (8109)  SQLMap         │
│  ├─► ssl_mcp               (8112)  SSL/TLS        │
│  ├─► cisa_kev_mcp          (8114)  KEV            │
│  ├─► epss_mcp              (8115)  EPSS           │
│  ├─► poc_mcp               (8116)  PoC Index      │
│  ├─► nikto_mcp             (8117)  Nikto          │
│  ├─► masscan_mcp           (8118)  Masscan        │
│  ├─► wpscan_mcp            (8119)  WPScan         │
│  ├─► jwt_mcp               (8120)  JWT            │
│  ├─► gobuster_mcp          (8121)  Gobuster       │
│  ├─► cve_lite_mcp          (8122)  CVE Lite       │
│  ├─► anomaly_mcp           (8123)  Anomaly ML     │
│  ├─► payload_generator_mcp (8124)  Payloads       │
│  └─► exploitdb_mcp         (8125)  ExploitDB      │
└──────────────────────────────────────────────────┘

┌──────────────────────┐
│  socis_metasploit_rpc │  msfrpcd (Port 55553) — kept separate
│  (metasploit image)   │  metasploit_mcp inside mcp_all connects here
└──────────────────────┘
```

---

## Active MCP Servers

| Port | Server | Tools | Description |
|------|--------|-------|-------------|
| 8100 | `cve_mcp` | `lookup_cve`, `search_cves`, `get_severity`, `cpe_search` | NVD CVE database queries |
| 8101 | `nmap_mcp` | `nmap_scan`, `nmap_quick_scan`, `nmap_service_scan`, `nmap_vuln_scan`, `nmap_smb_scan`, `nmap_http_scan`, `port_check`, `os_detect` | Network port/service/OS scanning |
| 8102 | `nuclei_mcp` | `nuclei_scan`, `nuclei_cve_scan`, `nuclei_tech_detect`, `nuclei_exposed_scan`, `nuclei_dns_scan`, `nuclei_ssl_scan`, `list_templates`, `nuclei_update_templates` | Template-based vulnerability scanning |
| 8103 | `osint_mcp` | `whois_lookup`, `dns_lookup`, `http_headers`, `ip_geolocation`, `subdomain_enum`, `ssl_info`, `tech_fingerprint` | Passive reconnaissance |
| 8104 | `metasploit_mcp` | `list_exploits`, `run_exploit`, `run_auxiliary_module`, `run_post_module`, `generate_payload`, `list_active_sessions`, `send_session_command`, `terminate_session`, `list_listeners`, `start_listener`, `stop_job`, `list_payloads`, `get_module_info` | Full Metasploit Framework via RPC |
| 8105 | `mitre_mcp` | `get_data_stats`, `get_all_tactics`, `get_technique_by_id`, `search_techniques`, `get_all_techniques`, `get_all_subtechniques`, `get_techniques_by_tactic`, `get_techniques_by_platform`, `get_subtechniques_of_technique`, `get_technique_tactics`, `get_all_groups`, `get_group_by_name`, `search_groups`, `get_groups_using_technique`, `get_techniques_used_by_group`, `get_software_used_by_group`, `get_all_software`, `search_software`, `get_software_using_technique`, `get_all_mitigations`, `get_mitigations_for_technique`, `get_techniques_mitigated_by`, `get_all_campaigns`, `get_campaigns_using_technique`, `get_all_datasources`, `get_datasources_detecting_technique`, `generate_layer` | Full MITRE ATT&CK dataset (Enterprise, Mobile, ICS) — 27 tools |
| 8107 | `waf_detection_mcp` | `fingerprint_waf`, `test_bypass`, `analyze_evasion` | WAF detection and bypass testing |
| 8108 | `ffuf_mcp` | `ffuf_fuzz`, `ffuf_subdomains`, `ffuf_parameters`, `ffuf_vhost`, `ffuf_recursive`, `ffuf_filter_codes`, `ffuf_list_wordlists` | Web directory/parameter/subdomain fuzzing |
| 8109 | `sqlmap_mcp` | `sqlmap_scan`, `sqlmap_enum_databases`, `sqlmap_dump_table`, `sqlmap_check_status` | SQL injection detection & exploitation |
| 8112 | `ssl_mcp` | `check_ssl`, `get_ssl_grade`, `check_ssl_vulnerabilities` | TLS/certificate analysis |
| 8114 | `cisa_kev_mcp` | `check_kev`, `search_kev`, `get_kev_stats`, `get_recent_kev` | CISA Known Exploited Vulnerabilities catalog |
| 8115 | `epss_mcp` | `get_epss_score`, `get_epss_scores_bulk`, `get_high_epss_cves`, `epss_priority_analysis` | FIRST.org EPSS exploitation probability |
| 8116 | `poc_mcp` | `search_poc`, `search_github_poc`, `get_exploitdb_entry`, `poc_risk_summary` | PoC exploit search (Sploitus/GitHub/ExploitDB) |
| 8117 | `nikto_mcp` | `nikto_scan`, `nikto_tuning`, `nikto_ssl_only` | Web server vulnerability scanner |
| 8118 | `masscan_mcp` | `masscan_scan`, `masscan_top_ports`, `masscan_range` | Massively fast port scanner |
| 8119 | `wpscan_mcp` | `wp_scan`, `wp_enum_users`, `wp_enum_plugins`, `wp_enum_themes` | WordPress vulnerability scanner |
| 8120 | `jwt_mcp` | `decode_jwt`, `test_alg_none`, `test_weak_secret`, `forge_jwt`, `analyze_claims` | JWT decode, forge and attack testing |
| 8121 | `gobuster_mcp` | `gobuster_dir`, `gobuster_dns`, `gobuster_vhost`, `gobuster_fuzz` | Directory, DNS and vhost brute-force |
| 8122 | `cve_lite_mcp` | `cve_lite_scan`, `cve_lite_advisories_sync`, `cve_lite_version` | Lightweight offline CVE scanning against installed packages |
| 8123 | `anomaly_mcp` | `anomaly_train`, `anomaly_score`, `anomaly_status` | ML-based anomaly detection for scan result analysis |
| 8124 | `payload_generator_mcp` | `generate_payloads`, `generate_wordlist`, `list_vuln_types` | Context-aware payload and wordlist generation |
| 8125 | `exploitdb_mcp` | `search_exploits`, `get_exploit`, `find_by_cve`, `get_recent_exploits`, `get_statistics`, `search_by_platform`, `search_by_type`, `search_by_author`, `search_by_date_range`, `search_by_tags`, `get_platform_statistics`, `get_trending_exploits`, `compare_exploits`, `get_exploit_timeline`, `batch_get_exploits`, `get_related_exploits`, `validate_exploit_id`, `export_search_results` | Offline ExploitDB mirror — 47k+ exploits, 18 tools |

---

## Authentication

All MCP servers require a bearer token in every request:

```
Authorization: Bearer <MCP_AUTH_TOKEN>
```

The `MCP_AUTH_TOKEN` must be identical across:
- All MCP server containers (`mcp-servers/docker-compose.yml`)
- The backend container (`deploy/docker/docker-compose.yml`)
- Your `.env` file

Generate a secure token:
```bash
openssl rand -hex 32
```

---

## Running MCP Servers

All MCP servers start automatically as part of the main stack:

```bash
cd deploy/docker
docker compose up -d
```

Check status:
```bash
# All 22 supervised processes inside the container
docker exec socis_mcp_all supervisorctl -c /etc/supervisor/supervisord.conf \
  -s unix:///tmp/supervisor.sock status

# Via API
curl -s http://localhost:8000/api/v1/mcp/servers | python3 -m json.tool

# Direct health check per port
curl http://localhost:8100/health   # cve_mcp
curl http://localhost:8101/health   # nmap_mcp
curl http://localhost:8102/health   # nuclei_mcp
curl http://localhost:8105/health   # mitre_mcp
curl http://localhost:8122/health   # cve_lite_mcp
curl http://localhost:8123/health   # anomaly_mcp
curl http://localhost:8124/health   # payload_generator_mcp
curl http://localhost:8125/health   # exploitdb_mcp
# ... same pattern for all 22 ports
```

---

## Tool Dispatch from AI Chat

The LLM system prompt instructs the model to emit tool tags. The backend parses and dispatches them:

```python
# Tag format
[SEARCH: CVE-2021-44228]          # auto-enrichment: NVD + KEV + EPSS + PoC
[MCP: nmap_mcp.nmap_scan {"target":"192.168.1.1","flags":"-sV"}]
[MCP: nuclei_mcp.nuclei_scan {"target":"https://example.com"}]
[MCP: cisa_kev_mcp.check_kev {"cve_id":"CVE-2021-44228"}]
```

`[SEARCH: CVE-XXXX-YYYY]` automatically fans out to all four intel sources in parallel and combines results before Pass 2.

---

## Building a Custom MCP Server

Each server follows the same pattern:

```python
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from mcp_auth import verify_mcp_auth, mcp_auth_error
import uvicorn

app = FastAPI()

TOOLS = [
    {
        "name": "my_tool",
        "description": "Does something useful",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target to operate on"}
            },
            "required": ["target"]
        }
    }
]

async def handle_tool(tool_name: str, arguments: dict):
    if tool_name == "my_tool":
        target = arguments["target"]
        # ... do work ...
        return {"content": [{"type": "text", "text": f"Result for {target}"}]}
    raise ValueError(f"Unknown tool: {tool_name}")

@app.post("/mcp")
async def mcp_endpoint(request: Request):
    auth_error = await verify_mcp_auth(request)
    if auth_error:
        return mcp_auth_error()
    body = await request.json()
    method = body.get("method")
    if method == "tools/list":
        return JSONResponse({"jsonrpc": "2.0", "id": body["id"],
                             "result": {"tools": TOOLS}})
    if method == "tools/call":
        params = body.get("params", {})
        result = await handle_tool(params["name"], params.get("arguments", {}))
        return JSONResponse({"jsonrpc": "2.0", "id": body["id"], "result": result})

@app.get("/health")
async def health():
    return {"status": "ok", "server": "my_mcp"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8120)
```

Then register in `backend/app/mcp/client.py`:
```python
client.register_server(MCPServer(
    name="my_mcp",
    transport="http",
    url="http://my_mcp:8120" if _is_docker() else "http://localhost:8120",
))
```

And add a service to `deploy/docker/docker-compose.yml` with the same `MCP_AUTH_TOKEN` env var.

---

## Troubleshooting

### Server shows "Error" state in UI
```bash
# Check logs for all MCP servers (all run inside mcp_all)
docker compose logs mcp_all --tail=50

# Check individual process status inside the container
docker exec socis_mcp_all supervisorctl -c /etc/supervisor/supervisord.conf \
  -s unix:///tmp/supervisor.sock status

# Restart a specific MCP process if it crashed
docker exec socis_mcp_all supervisorctl -c /etc/supervisor/supervisord.conf \
  -s unix:///tmp/supervisor.sock restart nmap_mcp

# Verify MCP_AUTH_TOKEN matches
docker compose exec backend env | grep MCP_AUTH_TOKEN
docker compose exec mcp_all env | grep MCP_AUTH_TOKEN

# Test tool discovery directly
curl -s -X POST http://localhost:8101/mcp \
  -H "Authorization: Bearer <your-token>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

### Tool call returns "Server not found"
Verify the server name matches exactly. The registered names are:
`cve_mcp`, `nmap_mcp`, `nuclei_mcp`, `osint_mcp`, `metasploit_mcp`, `mitre_mcp`, `waf_detection_mcp`, `ffuf_mcp`, `sqlmap_mcp`, `ssl_mcp`, `cisa_kev_mcp`, `epss_mcp`, `poc_mcp`, `nikto_mcp`, `masscan_mcp`, `wpscan_mcp`, `jwt_mcp`, `gobuster_mcp`, `cve_lite_mcp`, `anomaly_mcp`, `payload_generator_mcp`, `exploitdb_mcp`


### MCP Servers (all run inside `socis_mcp_all`)

All 22 servers are supervised processes inside the single `socis_mcp_all` container. The `socis_metasploit_rpc` container runs separately (different base image).

| Process | Port | Tools | Container |
|---------|------|-------|-----------|
| `cve_mcp` | 8100 | `lookup_cve`, `search_cves`, `get_severity`, `cpe_search` | `socis_mcp_all` |
| `nmap_mcp` | 8101 | `nmap_scan`, `nmap_quick_scan`, `nmap_service_scan`, `nmap_vuln_scan`, `port_check`, `os_detect` | `socis_mcp_all` |
| `nuclei_mcp` | 8102 | `nuclei_scan`, `nuclei_cve_scan`, `nuclei_tech_detect`, `nuclei_exposed_scan`, `list_templates` | `socis_mcp_all` |
| `osint_mcp` | 8103 | `whois_lookup`, `dns_lookup`, `http_headers`, `ip_geolocation`, `subdomain_enum`, `ssl_info`, `tech_fingerprint` | `socis_mcp_all` |
| `metasploit_mcp` | 8104 | `list_exploits`, `run_exploit`, `run_auxiliary_module`, `generate_payload`, `list_active_sessions`, `send_session_command` + 7 more | `socis_mcp_all` |
| `mitre_mcp` | 8105 | `get_all_tactics`, `get_technique_by_id`, `search_techniques`, `get_techniques_by_tactic`, `get_all_groups`, `get_techniques_used_by_group`, `get_all_mitigations`, `generate_layer` + 19 more | `socis_mcp_all` |
| `waf_detection_mcp` | 8107 | `fingerprint_waf`, `test_bypass`, `analyze_evasion` | `socis_mcp_all` |
| `ffuf_mcp` | 8108 | `ffuf_fuzz`, `ffuf_subdomains`, `ffuf_parameters`, `ffuf_vhost`, `ffuf_recursive`, `ffuf_list_wordlists` | `socis_mcp_all` |
| `sqlmap_mcp` | 8109 | `sqlmap_scan`, `sqlmap_enum_databases`, `sqlmap_dump_table`, `sqlmap_check_status` | `socis_mcp_all` |
| `ssl_mcp` | 8112 | `check_ssl`, `get_ssl_grade`, `check_ssl_vulnerabilities` | `socis_mcp_all` |
| `cisa_kev_mcp` | 8114 | `check_kev`, `search_kev`, `get_kev_stats`, `get_recent_kev` | `socis_mcp_all` |
| `epss_mcp` | 8115 | `get_epss_score`, `get_epss_scores_bulk`, `get_high_epss_cves`, `epss_priority_analysis` | `socis_mcp_all` |
| `poc_mcp` | 8116 | `search_poc`, `search_github_poc`, `get_exploitdb_entry`, `poc_risk_summary` | `socis_mcp_all` |
| `nikto_mcp` | 8117 | `nikto_scan`, `nikto_tuning`, `nikto_ssl_only` | `socis_mcp_all` |
| `masscan_mcp` | 8118 | `masscan_scan`, `masscan_top_ports`, `masscan_range` | `socis_mcp_all` |
| `wpscan_mcp` | 8119 | `wp_scan`, `wp_enum_users`, `wp_enum_plugins`, `wp_enum_themes` | `socis_mcp_all` |
| `jwt_mcp` | 8120 | `decode_jwt`, `test_alg_none`, `test_weak_secret`, `forge_jwt`, `analyze_claims` | `socis_mcp_all` |
| `gobuster_mcp` | 8121 | `gobuster_dir`, `gobuster_dns`, `gobuster_vhost`, `gobuster_fuzz` | `socis_mcp_all` |
| `cve_lite_mcp` | 8122 | `cve_lite_scan`, `cve_lite_advisories_sync`, `cve_lite_version` | `socis_mcp_all` |
| `anomaly_mcp` | 8123 | `anomaly_train`, `anomaly_score`, `anomaly_status` | `socis_mcp_all` |
| `payload_generator_mcp` | 8124 | `generate_payloads`, `generate_wordlist`, `list_vuln_types` | `socis_mcp_all` |
| `exploitdb_mcp` | 8125 | `search_exploits`, `get_exploit`, `find_by_cve`, `get_recent_exploits`, `search_by_platform`, `export_search_results` + 12 more | `socis_mcp_all` |
| msfrpcd | 55553 | Metasploit RPC daemon (used internally by `metasploit_mcp`) | `socis_metasploit_rpc` |

---

## Setup MCP Servers

### 1. Docker Compose Setup

All MCP servers run as a **single `mcp_all` service** in `deploy/docker/docker-compose.yml`, managed internally by supervisord. The compose entry looks like:

```yaml
services:
  mcp_all:
    build:
      context: ../../mcp-servers
      dockerfile: Dockerfile
    container_name: socis_mcp_all
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      metasploit_rpc:
        condition: service_healthy
    ports:
      - "8100:8100"
      - "8101:8101"
      - "8102:8102"
      - "8103:8103"
      - "8104:8104"
      - "8107:8107"
      - "8108:8108"
      - "8109:8109"
      - "8112:8112"
      - "8114:8114"
      - "8115:8115"
      - "8116:8116"
      - "8117:8117"
      - "8118:8118"
      - "8119:8119"
      - "8120:8120"
      - "8121:8121"
      - "8122:8122"
      - "8123:8123"
      - "8124:8124"
      - "8125:8125"
    environment:
      MCP_AUTH_TOKEN: ${MCP_AUTH_TOKEN:-}
      DATABASE_URL: ...
      MSF_HOST: metasploit_rpc
      # ... all env vars for all 22 servers
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8100/health"]
    networks: [socis-net]

  # Metasploit RPC stays as a separate container (different base image)
  metasploit_rpc:
    image: metasploitframework/metasploit-framework:latest
    container_name: socis_metasploit_rpc
    # ...
```

The process list inside `mcp_all` is defined in `mcp-servers/supervisord.conf`:

```ini
[supervisord]
nodaemon=true

[program:cve_mcp]
command=python3 cve_server.py
autostart=true
autorestart=true

[program:nmap_mcp]
command=python3 nmap_server.py
# ... 10 more entries
```

To add a new MCP server to the consolidated container, see [Backend Integration Guide](../BACKEND-INTEGRATION-GUIDE.md).

  cve-server:
    build:
      context: .
      dockerfile: Dockerfile
      args:
        SERVER_NAME: cve
    ports:
      - "8005:8000"
    environment:
      - CVE_API_KEY=${CVE_API_KEY}
    restart: unless-stopped
```

### 2. Start MCP Services

```bash
# Start all MCP servers
cd mcp-servers
docker-compose up -d

# Verify services are running
docker-compose ps

# Check logs
docker-compose logs -f
```

### 3. Configure Backend Connection

In `backend/app/config.py`:

```python
class MCPConfig:
    SERVERS = {
        "nmap": {
            "host": "localhost",
            "port": 8001,
            "timeout": 300,
            "enabled": True
        },
        "metasploit": {
            "host": "localhost",
            "port": 8002,
            "timeout": 600,
            "enabled": True
        },
        "nuclei": {
            "host": "localhost",
            "port": 8003,
            "timeout": 1800,
            "enabled": True
        },
        "osint": {
            "host": "localhost",
            "port": 8004,
            "timeout": 300,
            "enabled": True
        },
        "cve": {
            "host": "localhost",
            "port": 8005,
            "timeout": 60,
            "enabled": True
        }
    }
```

---

## MCP Server Details

### CVE MCP Server (8100)

**File:** `mcp-servers/cve_server.py`  
**Purpose:** CVE/NVD database lookup and CVSS scoring

**Tools:** `lookup_cve`, `search_cves`, `get_severity`, `cpe_search`

```python
result = await client.call_tool("cve_mcp", "lookup_cve", {"cve_id": "CVE-2024-1234"})
```

### Nmap MCP Server (8101)

**File:** `mcp-servers/nmap_server.py`  
**Purpose:** Network discovery and port scanning

**Tools:** `nmap_scan`, `port_check`, `os_detect`

```python
result = await client.call_tool("nmap_mcp", "nmap_scan", {
    "target": "192.168.1.0/24", "flags": "-T4 --open -sV"
})
```

### Nuclei MCP Server (8102)

**File:** `mcp-servers/nuclei_server.py`  
**Purpose:** Template-based vulnerability scanning

**Tools:** `nuclei_scan`, `nuclei_cve_scan`, `list_templates`, `nuclei_tech_detect`

> **Timeout:** `nuclei_scan` runs with a 300 s backend timeout.

### OSINT MCP Server (8103)

**File:** `mcp-servers/osint_server.py`  
**Purpose:** Open-source intelligence gathering

**Tools:** `whois_lookup`, `dns_lookup`, `http_headers`, `ip_geolocation`, `subdomain_enum`, `ssl_info`, `tech_fingerprint`

### Metasploit MCP Server (8104)

**File:** `mcp-servers/metasploit_server.py`  
**Purpose:** Full exploitation framework integration

**Tools (13):** `list_exploits`, `list_payloads`, `get_module_info`, `run_exploit`, `run_auxiliary_module`, `run_post_module`, `list_active_sessions`, `send_session_command`, `terminate_session`, `generate_payload`, `list_listeners`, `start_listener`, `stop_job`

> Requires Metasploit RPC server (`socis_metasploit_rpc`, port 55553).

### MITRE ATT&CK MCP Server (8105)

**File:** `mcp-servers/mitre_server.py`  
**Purpose:** Full MITRE ATT&CK knowledge base — Enterprise, Mobile, and ICS domains. ATT&CK v18.

**Tools (27):** `get_data_stats`, `get_all_tactics`, `get_technique_by_id`, `search_techniques`, `get_all_techniques`, `get_all_subtechniques`, `get_techniques_by_tactic`, `get_techniques_by_platform`, `get_subtechniques_of_technique`, `get_technique_tactics`, `get_all_groups`, `get_group_by_name`, `search_groups`, `get_groups_using_technique`, `get_techniques_used_by_group`, `get_software_used_by_group`, `get_all_software`, `search_software`, `get_software_using_technique`, `get_all_mitigations`, `get_mitigations_for_technique`, `get_techniques_mitigated_by`, `get_all_campaigns`, `get_campaigns_using_technique`, `get_all_datasources`, `get_datasources_detecting_technique`, `generate_layer`

```python
# Search techniques by tactic
result = await client.call_tool("mitre_mcp", "get_techniques_by_tactic",
    {"tactic": "initial-access", "domain": "enterprise"})

# Map a threat group to TTPs
result = await client.call_tool("mitre_mcp", "get_techniques_used_by_group",
    {"group_name": "APT29"})

# Generate an ATT&CK Navigator layer JSON
result = await client.call_tool("mitre_mcp", "generate_layer",
    {"technique_ids": ["T1078", "T1190"], "name": "Campaign Layer"})
```

### WAF Detection MCP Server (8107)

**File:** `mcp-servers/waf_detection_server.py`  
**Tools:** `fingerprint_waf`, `test_bypass`, `analyze_evasion`

### ffuf MCP Server (8108)

**File:** `mcp-servers/ffuf_server.py`  
**Purpose:** Web directory/parameter fuzzing

**Tools:** `ffuf_fuzz`

> **Timeout:** 300 s backend timeout for long wordlist scans.

```python
result = await client.call_tool("ffuf_mcp", "ffuf_fuzz", {
    "url": "https://example.com/FUZZ",
    "wordlist": "/usr/share/wordlists/dirb/common.txt"
})
```

### sqlmap MCP Server (8109)

**File:** `mcp-servers/sqlmap_server.py`  
**Purpose:** SQL injection detection and exploitation

**Tools:** `sqlmap_scan`, `sqlmap_enum_databases`, `sqlmap_dump_table`, `sqlmap_check_status`

### CVE Lite MCP Server (8122)

**File:** `mcp-servers/cve_lite_server.py`  
**Purpose:** Lightweight offline CVE scanning against installed software packages

**Tools:** `cve_lite_scan`, `cve_lite_advisories_sync`, `cve_lite_version`

### Anomaly Detection MCP Server (8123)

**File:** `mcp-servers/anomaly_server.py`  
**Purpose:** ML-based anomaly detection — trains on baseline scan results and scores new results for statistical outliers

**Tools:** `anomaly_train`, `anomaly_score`, `anomaly_status`

```python
# Train a model on baseline scan data
result = await client.call_tool("anomaly_mcp", "anomaly_train",
    {"scan_data": baseline_results})

# Score new scan results against baseline
result = await client.call_tool("anomaly_mcp", "anomaly_score",
    {"scan_data": new_results})
```

### Payload Generator MCP Server (8124)

**File:** `mcp-servers/payload_generator_server.py`  
**Purpose:** Context-aware payload and wordlist generation for manual testing

**Tools:** `generate_payloads`, `generate_wordlist`, `list_vuln_types`

```python
# Generate payloads for a specific vulnerability type
result = await client.call_tool("payload_generator_mcp", "generate_payloads",
    {"vuln_type": "sqli", "context": "mysql"})
```

### ExploitDB MCP Server (8125)

**File:** `mcp-servers/exploitdb_server.py`  
**Purpose:** Offline mirror of the Exploit-DB database — 47,000+ exploit entries with 24-hour background refresh from the official GitLab CSV source

**Tools (18):** `search_exploits`, `get_exploit`, `find_by_cve`, `get_recent_exploits`, `get_statistics`, `search_by_platform`, `search_by_type`, `search_by_author`, `search_by_date_range`, `search_by_tags`, `get_platform_statistics`, `get_trending_exploits`, `compare_exploits`, `get_exploit_timeline`, `batch_get_exploits`, `get_related_exploits`, `validate_exploit_id`, `export_search_results`

```python
# Find exploits for a CVE
result = await client.call_tool("exploitdb_mcp", "find_by_cve",
    {"cve_id": "CVE-2021-44228"})

# Search exploits by platform
result = await client.call_tool("exploitdb_mcp", "search_by_platform",
    {"platform": "linux", "limit": 20})

# Get exploit details by EDB-ID
result = await client.call_tool("exploitdb_mcp", "get_exploit",
    {"exploit_id": 51685})
```

**Tools:** `sqlmap_scan`

> **Timeout:** 300 s backend timeout.

```python
result = await client.call_tool("sqlmap_mcp", "sqlmap_scan", {
    "url": "http://example.com/page?id=1",
    "level": 2, "risk": 1
})
```

### SSL MCP Server (8112)

**File:** `mcp-servers/ssl_server.py`  
**Purpose:** TLS/certificate analysis

**Tools:** `check_ssl`

```python
result = await client.call_tool("ssl_mcp", "check_ssl", {"host": "example.com", "port": 443})
```

### CISA KEV MCP Server (8114)

**File:** `mcp-servers/cisa_kev_server.py`  
**Purpose:** CISA Known Exploited Vulnerabilities catalog lookup

**Tools:** `check_kev`, `search_kev`, `get_kev_stats`, `get_recent_kev`

```python
# Check if CVE is in CISA KEV
result = await client.call_tool("cisa_kev_mcp", "check_kev", {"cve_id": "CVE-2021-44228"})
# Recent additions (last N days)
result = await client.call_tool("cisa_kev_mcp", "get_recent_kev", {"days": 30})
```

### EPSS MCP Server (8115)

**File:** `mcp-servers/epss_server.py`  
**Purpose:** EPSS (Exploit Prediction Scoring System) probability scoring

**Tools:** `get_epss_score`, `get_epss_scores_bulk`, `get_high_epss_cves`, `epss_priority_analysis`

```python
# Get EPSS score for a single CVE
result = await client.call_tool("epss_mcp", "get_epss_score", {"cve_id": "CVE-2021-44228"})
# Prioritize a list of CVEs by EPSS
result = await client.call_tool("epss_mcp", "epss_priority_analysis", {
    "cve_list": ["CVE-2021-44228", "CVE-2022-26134"]
})
```

### PoC MCP Server (8116)

**File:** `mcp-servers/poc_server.py`  
**Purpose:** Proof-of-concept and exploit intelligence (ExploitDB, GitHub)

**Tools:** `search_poc`, `search_github_poc`, `get_exploitdb_entry`, `poc_risk_summary`

```python
# Search for public PoCs
result = await client.call_tool("poc_mcp", "search_poc", {"cve_id": "CVE-2021-44228"})
result = await client.call_tool("poc_mcp", "get_exploitdb_entry", {"edb_id": "50592"})
```

---

## BackendMCP Integration

### MCP Client Setup

In `backend/app/mcp/client.py`:

```python
from mcp.client import MCPClient
from app.config import settings

class MCPServerPool:
    def __init__(self):
        self.servers = {}
        self.clients = {}
    
    async def initialize(self):
        """Initialize all configured MCP servers"""
        for server_name, config in settings.MCP.SERVERS.items():
            if not config.get("enabled", True):
                continue
            
            client = MCPClient(
                host=config["host"],
                port=config["port"],
                timeout=config.get("timeout", 300)
            )
            
            try:
                await client.connect()
                self.clients[server_name] = client
                print(f"✓ Connected to {server_name} MCP server")
            except Exception as e:
                print(f"✗ Failed to connect to {server_name}: {e}")
    
    async def invoke_tool(self, server: str, tool: str, params: dict):
        """Invoke a tool on an MCP server"""
        if server not in self.clients:
            raise ValueError(f"Server '{server}' not available")
        
        client = self.clients[server]
        return await client.invoke_tool(tool, params)
    
    async def list_tools(self, server: str):
        """List available tools on a server"""
        if server not in self.clients:
            raise ValueError(f"Server '{server}' not available")
        
        client = self.clients[server]
        return await client.list_tools()

# Global pool instance
mcp_pool = MCPServerPool()
```

### Using MCP in Services

In `backend/app/services/tool_service.py`:

```python
from app.mcp.client import mcp_pool

class ToolService:
    async def execute_scan(self, tool: str, params: dict):
        """Execute a scanning tool via MCP"""
        try:
            result = await mcp_pool.invoke_tool(tool, "scan", params)
            return {
                "status": "success",
                "data": result,
                "tool": tool
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "tool": tool
            }
    
    async def get_available_tools(self):
        """Get all available tools"""
        tools = {}
        for server_name in mcp_pool.clients:
            try:
                tools[server_name] = await mcp_pool.list_tools(server_name)
            except Exception as e:
                tools[server_name] = {"error": str(e)}
        
        return tools
```

### API Endpoint

In `backend/app/api/v1/mcp.py`:

```python
from fastapi import APIRouter, Depends
from app.services.tool_service import ToolService
from app.core.security import get_current_user

router = APIRouter(prefix="/mcp", tags=["mcp"])
tool_service = ToolService()

@router.get("/servers")
async def list_servers(current_user = Depends(get_current_user)):
    """List all available MCP servers and their status"""
    servers = []
    for server_name, client in mcp_pool.clients.items():
        try:
            health = await client.health_check()
            servers.append({
                "name": server_name,
                "status": "healthy" if health else "unhealthy",
                "tools": await client.list_tools()
            })
        except Exception as e:
            servers.append({
                "name": server_name,
                "status": "offline",
                "error": str(e)
            })
    
    return {"servers": servers}

@router.post("/tools/{tool}/execute")
async def execute_tool(tool: str, params: dict, current_user = Depends(get_current_user)):
    """Execute a tool via MCP"""
    result = await tool_service.execute_scan(tool, params)
    return result

@router.get("/tools")
async def list_all_tools(current_user = Depends(get_current_user)):
    """List all available tools across all servers"""
    return await tool_service.get_available_tools()
```

---

## Creating Custom MCP Servers

### Server Structure

Create a new directory `mcp-servers/custom-mcp/`:

```
custom-mcp/
├── Dockerfile
├── requirements.txt
├── main.py
├── tools.py
└── config.py
```

### Dockerfile

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

ENV SERVER_PORT=8000
EXPOSE 8000

CMD ["python", "main.py"]
```

### Server Implementation

**main.py**:
```python
from fastapi import FastAPI
from pydantic import BaseModel
import os

app = FastAPI(title="Custom MCP Server")

PORT = int(os.getenv("SERVER_PORT", 8000))

class ToolRequest(BaseModel):
    name: str
    params: dict

@app.get("/tools")
async def list_tools():
    """List available tools"""
    return {
        "tools": [
            {
                "name": "custom_tool",
                "description": "My custom security tool",
                "params": {
                    "target": {"type": "string", "required": True},
                    "option": {"type": "string", "required": False}
                }
            }
        ]
    }

@app.post("/invoke")
async def invoke_tool(request: ToolRequest):
    """Invoke a tool"""
    tool_name = request.name
    tool_params = request.params
    
    if tool_name == "custom_tool":
        result = await execute_custom_tool(tool_params)
        return result
    
    return {"error": f"Unknown tool: {tool_name}"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

async def execute_custom_tool(params: dict):
    """Execute custom tool logic"""
    # Your tool implementation here
    return {"status": "success", "result": "..."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
```

### Register Custom Server

1. Add to `docker-compose.yml`
2. Update `backend/app/config.py`
3. Restart services

---

## AI Integration with MCP

### LLM Tool Binding

In `backend/app/services/llm_service.py`:

```python
from app.mcp.client import mcp_pool

class LLMService:
    async def execute_with_tools(self, scan_id: str, user_query: str):
        """Execute LLM with access to MCP tools"""
        
        # Get available tools
        available_tools = await mcp_pool.list_all_tools()
        
        # Define tool calling function
        async def call_tool(tool_name: str, params: dict):
            server, tool = tool_name.split(":")
            result = await mcp_pool.invoke_tool(server, tool, params)
            return result
        
        # Stream LLM response with tool calls
        async for response in self.llm.stream_with_tools(
            messages=[{"role": "user", "content": user_query}],
            tools=available_tools,
            tool_executor=call_tool,
            system="You are a security expert. Use available tools to analyze vulnerabilities."
        ):
            yield response
```

### Example: AI-Driven Scan

```python
# User asks AI to scan a target
user_query = "Perform a comprehensive security scan of 192.168.1.0/24"

async for response in llm_service.execute_with_tools(scan_id, user_query):
    # AI decides to call Nmap
    # -> Invokes nmap_mcp.nmap_scan({target: "192.168.1.0/24"})
    # -> Gets results and analyzes
    # -> Calls nuclei_mcp.nuclei_scan({target: "findings"})
    # -> Synthesizes findings into report
    
    print(response)  # Stream response to user
```

---

## Monitoring MCP Servers

### Health Checks

```bash
# Check individual server health
curl http://localhost:8100/health  # CVE
curl http://localhost:8101/health  # Nmap
curl http://localhost:8102/health  # Nuclei
curl http://localhost:8103/health  # OSINT
curl http://localhost:8104/health  # Metasploit
curl http://localhost:8108/health  # ffuf
curl http://localhost:8109/health  # sqlmap
curl http://localhost:8112/health  # SSL
curl http://localhost:8114/health  # CISA KEV
curl http://localhost:8115/health  # EPSS
curl http://localhost:8116/health  # PoC

# Check all servers via backend
curl http://localhost:8000/api/v1/mcp/servers \
  -H "Authorization: Bearer $TOKEN"
```

### Logs

```bash
# View MCP server logs
docker-compose -f mcp-servers/docker-compose.yml logs -f nmap-server
docker-compose -f mcp-servers/docker-compose.yml logs -f nuclei-server

# View backend MCP client logs
docker-compose logs -f backend | grep -i mcp
```

### Performance Monitoring

```python
# In backend logs
2026-04-14 14:22:00 INFO: MCP Tool Execution
  - Tool: nmap_mcp.nmap_scan
  - Duration: 45.3s
  - Status: success
  - Results: 23 hosts discovered

2026-04-14 14:22:46 INFO: MCP Tool Execution
  - Tool: nuclei_mcp.nuclei_scan
  - Duration: 120.5s
  - Status: success
  - Results: 12 vulnerabilities found
```

---

## Troubleshooting

### Server Connection Issues

```bash
# Check if server is running
docker-compose -f mcp-servers/docker-compose.yml ps

# Restart server
docker-compose -f mcp-servers/docker-compose.yml restart nmap-server

# Check logs for errors
docker-compose -f mcp-servers/docker-compose.yml logs nmap-server | tail -50

# Test connection from backend
docker-compose exec backend curl http://nmap-server:8000/health
```

### Tool Execution Timeout

```python
# Increase timeout in config
SERVERS = {
    "nuclei": {
        "timeout": 3600,  # 1 hour instead of 30 min
    }
}

# Or set per-tool timeout
await mcp_pool.invoke_tool(
    "nuclei", 
    "nuclei_scan", 
    params,
    timeout=1800  # Request-specific timeout
)
```

### Memory/Resource Issues

```bash
# Monitor resource usage
docker stats mcp-servers_nmap-server_1

# Limit resource usage
docker-compose -f mcp-servers/docker-compose.yml up -d
# Add to docker-compose.yml:
# deploy:
#   resources:
#     limits:
#       cpus: '2'
#       memory: 2G
```

---

## Best Practices

1. **Tool Timeouts**: Set appropriate timeouts based on tool complexity
2. **Parallel Execution**: Use async/await for concurrent tool calls
3. **Error Handling**: Wrap tool calls in try-catch with fallbacks
4. **Logging**: Enable detailed logging for debugging
5. **Resource Limits**: Set Docker resource limits to prevent runaway processes
6. **API Keys**: Store sensitive keys in environment variables/secrets
7. **Tool Versioning**: Pin tool versions in Dockerfile
8. **Testing**: Test tools independently before integrating with AI

---

## AI Assistant Automation Guide

### Overview
The AI Security Assistant can automatically invoke MCP tools based on your scenarios. Just describe what you want in natural language, and the AI will use special tags to call the appropriate tools.

### How It Works

The AI uses special tags in its responses:

| Tag | Purpose | Example |
|-----|---------|---------|
| `[SEARCH: query]` | Auto-search CVE/NVD database | `[SEARCH: CVE-2021-44228]` |
| `[MCP: server.tool {args}]` | Direct MCP tool call | `[MCP: nmap_mcp.nmap_scan {target: 192.168.1.1}]` |
| `[TOOL: command]` | CLI tool execution | `[TOOL: nmap -sV 192.168.1.1]` |

### AI Assistant Tag Syntax

#### 1. CVE/Threat Search Tag
```
[SEARCH: CVE-2021-44228]
```
**Auto-queries**: NVD + CISA KEV + EPSS + PoC Index in parallel

#### 2. Direct MCP Tool Call
```
[MCP: nmap_mcp.nmap_scan 192.168.1.1]
```

#### 3. CLI Tool Tag
```
[TOOL: nmap -sV 192.168.1.1 -oX scan.xml]
```

### Examples

#### Example 1: Scan a Target

**User:** "Scan 192.168.1.1 for open ports"

**AI Response:**
```
[MCP: nmap_mcp.nmap_scan 192.168.1.1]
```

#### Example 2: Look up a CVE

**User:** "Tell me about CVE-2021-44228 (Log4Shell)"

**AI Response:**
```
[SEARCH: CVE-2021-44228]
```

#### Example 3: Run OSINT

**User:** "Do a WHOIS lookup on example.com"

**AI Response:**
```
[MCP: osint_mcp.whois_lookup example.com]
```

#### Example 4: Full Vulnerability Assessment

**User:** "Scan example.com for vulnerabilities"

**AI Response:**
```
[MCP: nmap_mcp.nmap_scan example.com]
[MCP: nuclei_mcp.nuclei_scan https://example.com]
```

### MCP Tools Available to AI

| Server | Port | Tools |
|--------|------|-------|
| cve_mcp | 8100 | `lookup_cve`, `search_cves`, `get_severity`, `cpe_search` |
| nmap_mcp | 8101 | `nmap_scan`, `port_check`, `os_detect`, `nmap_quick_scan`, `nmap_service_scan`, `nmap_vuln_scan`, `nmap_smb_scan`, `nmap_http_scan` |
| nuclei_mcp | 8102 | `nuclei_scan`, `nuclei_cve_scan`, `list_templates`, `nuclei_tech_detect`, `nuclei_exposed_scan`, `nuclei_dns_scan`, `nuclei_ssl_scan`, `nuclei_update_templates` |
| osint_mcp | 8103 | `whois_lookup`, `dns_lookup`, `http_headers`, `ip_geolocation`, `subdomain_enum`, `ssl_info`, `tech_fingerprint` |
| metasploit_mcp | 8104 | `list_exploits`, `list_all_exploits`, `list_auxiliary_modules`, `list_exploit_modules`, `list_post_modules`, `list_payloads`, `get_module_info`, `run_exploit`, `run_auxiliary_module`, `run_post_module`, `list_active_sessions`, `send_session_command`, `terminate_session`, `generate_payload`, `list_listeners`, `start_listener`, `stop_job` |
| waf_mcp | 8107 | `fingerprint_waf`, `test_bypass`, `analyze_evasion`, `scan_waf_nmap`, `check_security_headers`, `test_protocols`, `detect_rate_limit`, `test_tls_fingerprint` |
| ffuf_mcp | 8108 | `ffuf_fuzz`, `ffuf_subdomains`, `ffuf_parameters`, `ffuf_vhost`, `ffuf_recursive`, `ffuf_filter_codes`, `ffuf_list_wordlists` |
| sqlmap_mcp | 8109 | `sqlmap_scan`, `sqlmap_enum_databases`, `sqlmap_enum_tables`, `sqlmap_enum_columns`, `sqlmap_dump`, `sqlmap_users`, `sqlmap_passwords`, `sqlmap_shell`, `sqlmap_os_shell`, `sqlmap_privileges`, `sqlmap_current_db`, `sqlmap_current_user`, `sqlmap_is_dba`, `sqlmap_read_file`, `sqlmap_write_file`, `sqlmap_status`, `sqlmap_results` |
| ssl_mcp | 8112 | `check_ssl`, `get_ssl_grade`, `check_ssl_vulnerabilities` |
| cisa_kev_mcp | 8114 | `check_kev`, `search_kev`, `get_kev_stats`, `get_recent_kev` |
| epss_mcp | 8115 | `get_epss_score`, `get_epss_scores_bulk`, `get_high_epss_cves`, `epss_priority_analysis` |
| poc_mcp | 8116 | `search_poc`, `search_github_poc`, `get_exploitdb_entry`, `poc_risk_summary` |
| nikto_mcp | 8117 | `nikto_scan`, `nikto_tuning`, `nikto_ssl_only` |
| masscan_mcp | 8118 | `masscan_scan`, `masscan_top_ports`, `masscan_range` |
| wpscan_mcp | 8119 | `wp_scan`, `wp_enum_users`, `wp_enum_plugins`, `wp_enum_themes` |
| jwt_mcp | 8120 | `decode_jwt`, `test_alg_none`, `test_weak_secret`, `forge_jwt`, `analyze_claims` |
| gobuster_mcp | 8121 | `gobuster_dir`, `gobuster_dns`, `gobuster_vhost`, `gobuster_fuzz` |

### Correct Tag Syntax

```
# CVE Search - auto queries all 4 sources in parallel
[SEARCH: CVE-2021-44228]

# Direct MCP call - server.tool target
[MCP: nmap_mcp.nmap_scan 192.168.1.1]

# With JSON args
[MCP: nuclei_mcp.nuclei_scan {"target": "https://example.com", "severity": "critical"}]

# OSINT
[MCP: osint_mcp.whois_lookup example.com]

# SSL check
[MCP: ssl_mcp.check_ssl example.com]

# CVE lookup
[MCP: cve_mcp.lookup_cve CVE-2021-44228]

# CISA KEV check
[MCP: cisa_kev_mcp.check_kev CVE-2021-44228]

# EPSS score
[MCP: epss_mcp.get_epss_score CVE-2021-44228]

# PoC search
[MCP: poc_mcp.search_poc CVE-2021-44228]
```

### Creating Automation Workflows via AI

**Natural Language (Recommended):**
```
User: "Scan 192.168.1.1 for open ports and check for vulnerabilities"
```

**Explicit Tags:**
```
[MCP: nmap_mcp.nmap_scan 192.168.1.1]
[SEARCH: CVE-2021-44228]
```

---

## Support

- **MCP Specification**: https://modelcontextprotocol.io
- **GitHub**: https://github.com/0x4hm3d/SOCIS-AI-PT
- **Issues**: https://github.com/0x4hm3d/SOCIS-AI-PT/issues
