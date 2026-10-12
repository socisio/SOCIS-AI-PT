# SOCIS-AI-PT API Documentation

## Overview

The SOCIS-AI-PT API is a RESTful API built with FastAPI that provides endpoints for penetration testing, vulnerability management, AI analysis, and security operations. The API uses JWT-based authentication and WebSocket support for real-time updates.

**Base URL**: `/api/v1/`  
**Authentication**: JWT Bearer Token  
**Response Format**: JSON

---

## Authentication

### Login

Authenticate with username/password or OAuth credentials.

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "your_password"
}
```

**Response** (200 OK):
```json
{
  "access_token": "<example-jwt>",
  "refresh_token": "<example-jwt>",
  "token_type": "bearer",
  "user": {
    "id": "user_123",
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin"
  }
}
```

### Refresh Token

Get a new access token using the refresh token.

```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "<example-jwt>"
}
```

### Using the Token

Include the access token in the Authorization header for all requests:

```http
Authorization: Bearer <example-jwt>
```

---

## Core Endpoints

### Projects

#### List Projects

```http
GET /api/v1/projects
```

**Query Parameters**:
- `skip` (int): Number of records to skip (default: 0)
- `limit` (int): Number of records to return (default: 50)
- `status` (string): Filter by status (active/completed/archived/paused)

**Response** (200 OK):
```json
{
  "total": 5,
  "projects": [
    {
      "id": "proj_123",
      "name": "Customer A - Security Audit",
      "description": "Full infrastructure pentest",
      "scope": "10.0.0.0/8",
      "status": "active",
      "created_at": "2026-01-15T10:30:00Z",
      "updated_at": "2026-04-14T14:22:00Z"
    }
  ]
}
```

#### Create Project

```http
POST /api/v1/projects
Content-Type: application/json

{
  "name": "New Project",
  "description": "Project description",
  "scope": "192.168.0.0/16"
}
```

#### Get Project Detail

```http
GET /api/v1/projects/{project_id}
```

#### Update Project

```http
PUT /api/v1/projects/{project_id}
Content-Type: application/json

{
  "name": "Updated Name",
  "status": "paused"
}
```

#### Delete Project

```http
DELETE /api/v1/projects/{project_id}
```

---

### Scans

#### List Scans

```http
GET /api/v1/scans
```

**Query Parameters**:
- `project_id` (string): Filter by project
- `status` (string): pending | running | analyzing | completed | failed | cancelled
- `page` (int): Page number (default: 1)
- `limit` (int): Records per page (default: 20)

**Response** (200 OK):
```json
{
  "total": 42,
  "scans": [
    {
      "id": "scan_123",
      "project_id": "proj_123",
      "name": "Full Network Scan",
      "status": "completed",
      "progress": 100,
      "vulnerabilities_count": 15,
      "critical_count": 2,
      "high_count": 5,
      "created_at": "2026-04-10T08:00:00Z",
      "updated_at": "2026-04-10T12:30:00Z"
    }
  ]
}
```

#### Create Scan

```http
POST /api/v1/scans
Content-Type: application/json

{
  "project_id": "proj_123",
  "name": "Web Application Scan",
  "scan_type": "web",
  "targets": ["https://example.com"],
  "tools": ["nuclei", "nmap"],
  "intensity": "aggressive"
}
```

**Scan Types**: web | network | api | cloud | container

#### Get Scan Detail

```http
GET /api/v1/scans/{scan_id}
```

**Response** (200 OK):
```json
{
  "id": "scan_123",
  "project_id": "proj_123",
  "name": "Full Network Scan",
  "status": "completed",
  "progress": 100,
  "target": "10.0.0.0/8",
  "scan_type": "network",
  "tools_used": ["nmap", "nuclei"],
  "vulnerabilities": [
    {
      "id": "vuln_001",
      "name": "SQL Injection",
      "cve_id": "CVE-2024-1234",
      "severity": "critical",
      "cvss_score": 9.8,
      "status": "open"
    }
  ],
  "tool_results": [
    {
      "tool": "nmap",
      "status": "completed",
      "findings": 45,
      "errors": 0
    }
  ],
  "created_at": "2026-04-10T08:00:00Z",
  "completed_at": "2026-04-10T12:30:00Z"
}
```

#### Cancel Scan

```http
POST /api/v1/scans/{scan_id}/cancel
```

#### Delete Scan

```http
DELETE /api/v1/scans/{scan_id}
```

---

### Vulnerabilities

#### List Vulnerabilities

```http
GET /api/v1/vulnerabilities
```

**Query Parameters**:
- `severity` (string): critical | high | medium | low | info
- `cve_id` (string): Search by CVE ID
- `vuln_name` (string): Search by vulnerability name
- `status` (string): open | fixed | resolved | false_positive
- `page` (int): Page number (default: 1)

**Response** (200 OK):
```json
{
  "total": 156,
  "vulnerabilities": [
    {
      "id": "vuln_001",
      "scan_id": "scan_123",
      "name": "SQL Injection",
      "cve_id": "CVE-2024-1234",
      "cwe_ids": ["CWE-89"],
      "severity": "critical",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "description": "Application is vulnerable to SQL injection...",
      "affected_component": "Database layer",
      "remediation": "Use parameterized queries",
      "status": "open",
      "tool_source": "nuclei",
      "first_seen": "2026-04-10T08:00:00Z",
      "last_seen": "2026-04-14T10:00:00Z"
    }
  ]
}
```

#### Get Vulnerability Detail

```http
GET /api/v1/vulnerabilities/{vuln_id}
```

#### Get CVE Information

```http
GET /api/v1/vulnerabilities/{vuln_id}/cve-info
```

**Response**:
```json
{
  "cve_id": "CVE-2024-1234",
  "published": "2024-03-15T00:00:00Z",
  "updated": "2026-04-10T00:00:00Z",
  "description": "...",
  "cvss_v3": {
    "score": 9.8,
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
  },
  "references": ["https://nvd.nist.gov/..."],
  "affected_versions": ["1.0.0", "1.0.1"],
  "available_patch": "1.0.2"
}
```

#### Update Vulnerability Status

```http
PATCH /api/v1/vulnerabilities/{vuln_id}
Content-Type: application/json

{
  "status": "fixed",
  "notes": "Applied security patch 1.0.2"
}
```

---

### Reports

#### Generate Report

```http
POST /api/v1/reports
Content-Type: application/json

{
  "scan_id": "scan_123",
  "format": "pdf",
  "include_remediation": true,
  "include_ai_analysis": true
}
```

**Formats**: pdf | html | json | csv

**Response** (202 Accepted):
```json
{
  "report_id": "rpt_123",
  "status": "generating",
  "format": "pdf",
  "progress": 0,
  "estimated_time": 60
}
```

#### Get Report Status

```http
GET /api/v1/reports/{report_id}
```

#### Download Report

```http
GET /api/v1/reports/{report_id}/download
```

#### List Reports

```http
GET /api/v1/reports?scan_id=scan_123
```

---

### AI Analysis

#### Chat with AI

```http
POST /api/v1/llm/chat
Content-Type: application/json

{
  "messages": [
    {
      "role": "user",
      "content": "Analyze these vulnerabilities and suggest remediation"
    }
  ],
  "scan_id": "scan_123",
  "provider": "ollama_remote",
  "model": "socis-pentest"
}
```

#### Stream Chat Response

```http
GET /api/v1/llm/chat/stream?scan_id=scan_123&provider=ollama_remote
```

Use Server-Sent Events (SSE) to receive streaming responses.

#### Get Available Models

```http
GET /api/v1/llm/models?provider=ollama_remote
```

**Response**:
```json
{
  "models": [
    {
      "name": "socis-pentest",
      "size_gb": 3.5,
      "parameters": "7b",
      "context_window": 4096
    },
    {
      "name": "socis-recon",
      "size_gb": 3.5,
      "parameters": "7b"
    }
  ]
}
```

---

### Tools

#### List Available Tools

```http
GET /api/v1/tools
```

**Response**:
```json
{
  "tools": [
    {
      "id": "nmap",
      "name": "Nmap",
      "description": "Network scanning and host discovery",
      "version": "7.93",
      "status": "available",
      "categories": ["recon", "network"]
    },
    {
      "id": "nuclei",
      "name": "Nuclei",
      "description": "Vulnerability scanner",
      "version": "3.0.0",
      "status": "available",
      "categories": ["vulnerability", "web"]
    }
  ]
}
```

#### Get Tool Results

```http
GET /api/v1/scans/{scan_id}/tools/{tool_name}/results
```

---

### MCP Servers

#### List MCP Servers

```http
GET /api/v1/mcp/servers
```

**Response**:
```json
{
  "status": "success",
  "servers": [
    {
      "name": "cve_mcp",
      "status": "online",
      "port": 8100,
      "tool_count": 4,
      "tools": ["lookup_cve", "search_cves", "get_severity", "cpe_search"]
    },
    {
      "name": "nmap_mcp",
      "status": "online",
      "port": 8101,
      "tool_count": 8,
      "tools": ["nmap_scan", "nmap_quick_scan", "nmap_service_scan", "port_check", "os_detect"]
    }
  ]
}
```

**Active servers**: `cve_mcp` (8100), `nmap_mcp` (8101), `nuclei_mcp` (8102), `osint_mcp` (8103), `metasploit_mcp` (8104), `waf_detection_mcp` (8107), `ffuf_mcp` (8108), `sqlmap_mcp` (8109), `ssl_mcp` (8112), `cisa_kev_mcp` (8114), `epss_mcp` (8115), `poc_mcp` (8116), `nikto_mcp` (8117), `masscan_mcp` (8118), `wpscan_mcp` (8119), `jwt_mcp` (8120), `gobuster_mcp` (8121)

#### Test MCP Server

```http
POST /api/v1/mcp/servers/{server_name}/test
```

Checks connectivity and tool discovery for a specific server. Example: `server_name` = `cisa_kev_mcp`

#### Invoke MCP Tool Directly

```http
POST /api/v1/mcp/servers/{server_name}/call
Content-Type: application/json

{
  "tool": "lookup_cve",
  "arguments": {
    "cve_id": "CVE-2021-44228"
  }
}
```

**Response**:
```json
{
  "status": "success",
  "result": {
    "content": [{"type": "text", "text": "..."}]
  },
  "duration_ms": 320
}
```

> **Long-running tools**: `ffuf_fuzz`, `sqlmap_scan`, `nuclei_scan` have a 300 s timeout. All others default to 120 s.

---

### Admin

#### User Management

**List Users**:
```http
GET /api/v1/admin/users
```

**Create User**:
```http
POST /api/v1/admin/users
Content-Type: application/json

{
  "username": "newuser",
  "email": "user@example.com",
  "password": "secure_password",
  "role": "analyst"
}
```

**Update User**:
```http
PUT /api/v1/admin/users/{user_id}
Content-Type: application/json

{
  "role": "viewer",
  "is_active": true
}
```

**Delete User**:
```http
DELETE /api/v1/admin/users/{user_id}
```

#### LLM Configuration

**List LLM Configs**:
```http
GET /api/v1/admin/llm-configs
```

**Add LLM Provider**:
```http
POST /api/v1/admin/llm-configs
Content-Type: application/json

{
  "name": "OpenAI GPT-4",
  "provider": "openai",
  "model_name": "gpt-4",
  "api_key": "sk-...",
  "base_url": "https://api.openai.com/v1"
}
```

#### Audit Logs

**Get Audit Logs**:
```http
GET /api/v1/admin/audit-logs?limit=100
```

**Response**:
```json
{
  "logs": [
    {
      "id": "log_123",
      "user_id": "user_123",
      "action": "scan_created",
      "resource": "scan_456",
      "details": "Created new scan",
      "ip_address": "192.168.1.100",
      "timestamp": "2026-04-14T14:22:00Z"
    }
  ]
}
```

---

## User Settings

### GET `/api/v1/settings/llm`

Retrieve the authenticated user's saved AI provider and model preferences.

**Permission**: Any authenticated user

**Response**:
```json
{
  "chat_provider": "ollama_remote",
  "chat_model": "socis-pentest",
  "ollama_url": "http://localhost:11434"
}
```

> Settings are stored per-user in the `user_settings.llm_settings` JSON column. The AI Chat page reads and writes these automatically when the user changes provider or model.

### POST `/api/v1/settings/llm`

Save LLM provider/model preference for the current user.

**Request Body**:
```json
{
  "chat_provider": "openai",
  "chat_model": "gpt-4o"
}
```

**Response**:
```json
{
  "status": "saved",
  "settings": {
    "chat_provider": "openai",
    "chat_model": "gpt-4o"
  }
}
```

---

## Health Endpoints

### GET `/health`

Basic backend liveness check.

```json
{"status": "healthy", "version": "1.0.0"}
```

### GET `/api/services-health`

Detailed readiness check — database, Redis, and Ollama connectivity. No authentication required.

```json
{
  "database": "ok",
  "redis": "ok",
  "ollama": {"connected": true, "models": 3}
}
```

Used by the Dashboard's **Platform Status** widget.

---

## LLM Providers

Valid values for the `provider` field:

| Value | Description |
|-------|-------------|
| `ollama_remote` | External Ollama server (admin-configured). The old `ollama_local` value is accepted and mapped to this. |
| `openai` | OpenAI API (GPT-4o, etc.) |
| `anthropic` | Anthropic Claude API |
| `custom` | Custom LLM endpoint |

---

## Permission Reference

| Endpoint | Required Permission |
|----------|--------------------|
| `GET/POST /admin/dashboard` | `admin:access` |
| `GET /admin/users` | `users:read` |
| `PATCH /admin/users/{id}` | `users:write` |
| `DELETE /admin/users/{id}` | `users:delete` |
| `GET/POST /admin/llm-configs` | `admin:settings` |
| `GET /admin/audit-logs` | `admin:access` |
| `POST /llm/chat` | `llm:chat` |
| `GET /llm/status` | `llm:chat` |
| `GET /llm/models` | `llm:chat` |
| `GET/POST /settings/llm` | authenticated (any role) |
| `GET /mcp/servers` | authenticated |
| `POST /mcp/servers/{name}/test` | authenticated |
| `POST /mcp/servers/{name}/call` | authenticated |

---

## WebSocket Connections

### Real-time Scan Updates

```javascript
const ws = new WebSocket('wss://your-server/api/v1/ws/scan/{scan_id}');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Scan update:', data);
  // {
  //   "status": "running",
  //   "progress": 45,
  //   "current_task": "Running nuclei scan",
  //   "vulnerabilities_found": 8
  // }
};
```

---

## Error Handling

### Standard Error Response

```json
{
  "detail": "Error message",
  "statusCode": 400,
  "errorCode": "VALIDATION_ERROR"
}
```

### Common HTTP Status Codes

| Status | Meaning |
|--------|---------|
| 200 | Success |
| 201 | Created |
| 202 | Accepted (async processing) |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 409 | Conflict |
| 500 | Internal Server Error |

---

## Rate Limiting

API requests are rate limited to prevent abuse:
- **Default**: 100 requests per minute per user
- **Burst**: 500 requests per minute for authenticated users
- **Header**: `X-RateLimit-Remaining` included in all responses

---

## Pagination

All list endpoints support pagination:

```http
GET /api/v1/scans?page=2&limit=50
```

**Response**:
```json
{
  "total": 256,
  "page": 2,
  "limit": 50,
  "pages": 6,
  "data": [...]
}
```

---

## Data Models

### User Roles

- **admin**: Full access to all features
- **analyst**: Can create and manage scans, view reports
- **viewer**: Read-only access
- **api_user**: API-only access for automation

### Scan Status

- **pending**: Waiting to start
- **running**: Currently executing
- **analyzing**: AI analysis in progress
- **completed**: Finished successfully
- **failed**: Encountered error
- **cancelled**: User cancelled

### Severity Levels

- **critical**: CVSS 9.0-10.0
- **high**: CVSS 7.0-8.9
- **medium**: CVSS 4.0-6.9
- **low**: CVSS 0.1-3.9
- **info**: Informational findings

---

## Best Practices

1. **Always use HTTPS** in production
2. **Store tokens securely** (httpOnly cookies preferred)
3. **Implement token refresh** before expiration
4. **Use specific API scopes** rather than full access
5. **Log all API calls** for audit trail
6. **Rate limit client-side** to reduce failures
7. **Handle errors gracefully** with proper error messages
8. **Monitor API usage** for anomalies

---

## Environment-Only Configuration

These settings cannot be changed via the UI — they must be set in the `.env` file:

```env
# Database
DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/db
DATABASE_POOL_SIZE=20

# Cache
REDIS_URL=redis://:pass@host:6379/0

# Security
JWT_SECRET_KEY=secret-key
SECRET_KEY=app-secret-key
ALLOWED_ORIGINS=["http://localhost:3000"]
SECURE_COOKIES=true

# MCP Auth
MCP_AUTH_TOKEN=your-strong-token-here

# Timeouts (seconds)
TOOL_TIMEOUT_DEFAULT=120
TOOL_TIMEOUT_NMAP=300
TOOL_TIMEOUT_NUCLEI=600
```

---

## Support

- GitHub: https://github.com/0x4hm3d/socis-ai-pt
- Issues: https://github.com/0x4hm3d/socis-ai-pt/issues
