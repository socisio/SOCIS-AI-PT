# Metasploit MCP Server Configuration Guide

This document provides complete setup instructions for the Metasploit MCP server integration in SOCIS-AI-PT.

**Reference:** [GitHub - GH05TCREW/MetasploitMCP](https://github.com/GH05TCREW/MetasploitMCP)

## Quick Start

### 1. Prerequisites

- **Metasploit Framework** installed on your system
- **Metasploit RPC Server (msfrpcd)** running with authentication
- **Docker** for running containerized MCP service

### 2. Start Metasploit RPC Server

Before the MCP service can connect, you need to run `msfrpcd` (Metasploit Framework RPC daemon):

```bash
# Linux/Mac
msfrpcd -P yourpassword -S -a 127.0.0.1 -p 55553

# Windows (in Metasploit command prompt or PowerShell with msfconsole loaded)
msfrpcd -P yourpassword -S -a 127.0.0.1 -p 55553
```

**Parameters explained:**
- `-P yourpassword` - Set RPC authentication password (REQUIRED - match in .env)
- `-S` - Use SSL/TLS encryption
- `-a 127.0.0.1` - Bind to localhost (use 0.0.0.0 for network access)
- `-p 55553` - Listen on port 55553 (default)

### 3. Configure Environment Variables

Edit `.env` file in the `mcp-servers/` directory:

```env
# ─── Metasploit RPC Configuration ─────────────────────────────────────
MSF_HOST=127.0.0.1              # RPC server host
MSF_PORT=55553                  # RPC server port
MSF_PASSWORD=yourpassword       # RPC authentication password (REQUIRED!)
MSF_SSL=false                   # Use HTTPS for RPC (true/false)
PAYLOAD_SAVE_DIR=               # Optional: custom payload save location
```

### 4. Deploy MCP Service

```bash
cd mcp-servers/
docker compose up -d metasploit_mcp
```

### 5. Verify Configuration

Check health endpoint:

```bash
curl http://localhost:8104/health
```

Expected response:
```json
{
  "status": "healthy",
  "server": "metasploit-mcp",
  "configured": true,
  "rpc_host": "127.0.0.1",
  "rpc_port": 55553
}
```

Note: `"configured": true` only shows when `MSF_PASSWORD` is set.

## Configuration Options

### MSF_HOST

Where your Metasploit RPC server is running:

| Value | Use Case |
|-------|----------|
| `127.0.0.1` or `localhost` | Local RPC server (same machine) |
| `host.docker.internal` | Windows/Mac Docker Desktop (access host from container) |
| `metasploit_framework` | Docker container name (if MSF running in Docker) |
| `192.168.1.100` | Remote Metasploit RPC server |
| `your-domain.com` | Remote server by hostname |

### MSF_PORT

Metasploit RPC listening port. Default: `55553`

Must match the `-p` parameter used when starting `msfrpcd`.

### MSF_PASSWORD

**CRITICAL:** RPC authentication password.

- Must match the password used when starting `msfrpcd` with `-P` flag
- If not set, RPC calls will fail with authentication errors
- Check health endpoint - `"configured"` will be `false` if password is missing

### MSF_SSL

Whether to use SSL/TLS for RPC connection:
- `true` - Use HTTPS (recommended for remote servers)
- `false` - Use HTTP (default for local testing)

Must match how `msfrpcd` was started (use `-S` flag for SSL).

### PAYLOAD_SAVE_DIR

Directory where `generate_payload` tool saves output files:
- Empty/not set: Uses default `~/payloads`
- Absolute path: `/custom/path/to/payloads`
- Must exist or have write permissions

## Available Tools (13 Total)

### Module Discovery
- **list_exploits** - Search available exploit modules
- **list_payloads** - List all available payloads with filtering
- **get_module_info** - Get detailed module information

### Exploitation & Execution
- **run_exploit** - Execute an exploit with options
- **run_auxiliary_module** - Run scanner/utility modules
- **run_post_module** - Execute post-exploitation modules

### Session Management
- **list_active_sessions** - Show all active sessions
- **send_session_command** - Run commands in sessions
- **terminate_session** - Kill a session

### Payload Generation
- **generate_payload** - Generate payload files (exe, elf, python, etc.)

### Handler Management
- **list_listeners** - Show active handlers/jobs
- **start_listener** - Create multi/handler for reverse connections
- **stop_job** - Terminate jobs

## Deployment Scenarios

### Scenario 1: Local Development (Windows/Mac Docker Desktop)

```env
MSF_HOST=host.docker.internal
MSF_PORT=55553
MSF_PASSWORD=dev_password
MSF_SSL=false
```

**Setup:**
```bash
# Start msfrpcd on host machine
msfrpcd -P dev_password -S -a 127.0.0.1 -p 55553

# Deploy MCP
cd mcp-servers && docker compose up -d metasploit_mcp
```

### Scenario 2: Docker Compose with Metasploit Container

```env
MSF_HOST=metasploit_framework
MSF_PORT=55553
MSF_PASSWORD=docker_password
MSF_SSL=false
```

**Setup:** Add Metasploit service to docker-compose.yml and configure both services to use same network.

### Scenario 3: Remote Metasploit RPC Server

```env
MSF_HOST=pentest-server.example.com
MSF_PORT=55553
MSF_PASSWORD=remote_password
MSF_SSL=true
```

**Setup:** Ensure remote server has public RPC access and firewall rules allow port 55553.

### Scenario 4: Linux Local Setup

```env
MSF_HOST=127.0.0.1
MSF_PORT=55553
MSF_PASSWORD=linux_password
MSF_SSL=false
```

**Setup:**
```bash
# Start msfrpcd
msfrpcd -P linux_password -S -a 127.0.0.1 -p 55553

# Deploy (same as other scenarios)
cd mcp-servers && docker compose up -d metasploit_mcp
```

## Troubleshooting

### "Cannot reach Metasploit RPC server"

**Cause:** MCP container cannot connect to RPC server

**Solutions:**
1. Verify `msfrpcd` is running:
   ```bash
   ps aux | grep msfrpcd
   ```

2. Check firewall:
   ```bash
   # Test direct connection
   curl http://127.0.0.1:55553
   ```

3. Verify MSF_HOST is correct
4. For Docker on Mac/Windows, use `host.docker.internal` instead of `127.0.0.1`

### "RPC error: authentication failed" or "MSF_PASSWORD not set"

**Cause:** Password mismatch or missing configuration

**Solutions:**
1. Verify password matches between `msfrpcd -P` and `.env` MSF_PASSWORD
2. Confirm `.env` file has MSF_PASSWORD set:
   ```bash
   grep MSF_PASSWORD mcp-servers/.env
   ```
3. Restart MCP service after changing password:
   ```bash
   docker compose up -d --force-recreate metasploit_mcp
   ```

### Tool returns "error: unknown"

**Cause:** RPC method not implemented or connection issue

**Solutions:**
1. Check health endpoint: `curl http://localhost:8104/health`
2. Verify Metasploit RPC server is running
3. Check logs: `docker logs socis_metasploit_mcp`

### "Payload save directory doesn't exist"

**Cause:** PAYLOAD_SAVE_DIR points to non-existent path

**Solutions:**
1. Create directory:
   ```bash
   mkdir -p /path/to/payloads
   ```
2. Or leave PAYLOAD_SAVE_DIR empty to use `~/payloads`
3. Restart service after updating

## Testing the Integration

### 1. Test Health Endpoint

```bash
curl http://localhost:8104/health
```

Should return status `healthy` with `"configured": true`.

### 2. List Available Tools

```bash
curl -X POST http://localhost:8104/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

Should return 13 tools.

### 3. Search for Exploits (via Backend API)

```bash
# First, authenticate with backend
AUTH_TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.access_token')

# Then test tool call
curl -X POST http://localhost:8000/api/v1/mcp/servers/metasploit_mcp/test \
  -H "Authorization: Bearer $AUTH_TOKEN"
```

## Security Considerations

### ⚠️ Important

This tool provides direct access to Metasploit Framework capabilities, including:
- Running exploits against systems
- Executing arbitrary code on target systems
- Modifying target systems through post-exploitation

**Only use in authorized penetration testing environments with explicit written permission.**

### Best Practices

1. **Secure RPC Password** - Use strong, random password for `msfrpcd`
2. **Network Isolation** - Run RPC server only on trusted networks
3. **SSL/TLS** - Use MSF_SSL=true for remote deployments
4. **Access Control** - Restrict who has API access to SOCIS-AI-PT backend
5. **Logging** - Monitor all tool usage and RPC calls
6. **Firewall Rules** - Restrict port 55553 to trusted sources only

## Related Documentation

- **Official MetasploitMCP:** https://github.com/GH05TCREW/MetasploitMCP
- **Metasploit Framework:** https://www.metasploit.com/
- **MCP Protocol:** https://modelcontextprotocol.io/
- **SOCIS-AI-PT Documentation:** See docs/ folder

## Support

For issues related to:
- **Metasploit RPC:** Check Metasploit Framework documentation
- **MCP Protocol:** Refer to official MetasploitMCP GitHub
- **SOCIS-AI-PT Integration:** Review this guide and mcp-servers/ code
