# SOCIS-AI-PT

<div align="center">
  <img src="SOCIS-AI-PT.png" alt="SOCIS-AI-PT Logo" width="600" />
  <h1>SOCIS-AI-PT</h1>
  <p><strong>AI-Powered Enterprise Penetration Testing Platform</strong></p>
  <p>
    <img src="https://img.shields.io/badge/License-BSL%201.1-blue" alt="BSL 1.1" />
    <img src="https://img.shields.io/badge/Next.js-15-black" alt="Next.js 15" />
    <img src="https://img.shields.io/badge/FastAPI-0.136-green" alt="FastAPI" />
    <img src="https://img.shields.io/badge/Python-3.12-blue" alt="Python 3.12" />
    <img src="https://img.shields.io/badge/PostgreSQL-16-336791" alt="PostgreSQL 16" />
    <img src="https://img.shields.io/badge/Ollama-local%20LLM-orange" alt="Ollama" />
    <img src="https://img.shields.io/badge/MCP-30%20servers-purple" alt="30 MCP Servers" />
  </p>
</div>

---

## Overview

**SOCIS-AI-PT** is a full-stack, enterprise-grade AI penetration testing platform that combines 30 specialized security MCP (Model Context Protocol) servers with large language models. The AI doesn't just analyze — it **acts**: autonomously calling live security tools, querying threat intelligence databases in real-time, and synthesizing results into professional reports. Deploy on-premise, on a LAN, or in the cloud.

---

## ✨ Key Features

### 🤖 Agentic AI Security Assistant
The AI Chat is the core of the platform — it detects intent and autonomously selects and executes the right tools:
- **"Tell me about CVE-2021-44228"** → Triggers parallel queries to NVD, CISA KEV, EPSS, and PoC Index simultaneously
- **"Scan 192.168.1.1 for open ports"** → Runs `nmap_scan` via the Nmap MCP server
- **"Check https://example.com for web vulnerabilities"** → Chains Nuclei + ffuf + WAF detection
- **"What's the exploit probability for this CVE?"** → Queries EPSS scoring API
- Two-pass streaming: shows which tools are being called, then streams the synthesized report

### 🔌 30 Integrated MCP Security Servers
All servers expose a JSON-RPC 2.0 interface over HTTP, protected by a shared bearer token
(full list of 30 programs in `mcp-servers/supervisord.conf`):

| Port | Server | Tools | Category |
|------|--------|-------|----------|
| 8100 | **CVE / NVD** | `lookup_cve`, `search_cves`, `get_severity`, `cpe_search` | Threat Intel |
| 8101 | **Nmap** | `nmap_scan`, `nmap_quick_scan`, `nmap_service_scan`, `nmap_vuln_scan`, `nmap_smb_scan`, `nmap_http_scan`, `port_check`, `os_detect` | Network Recon |
| 8102 | **Nuclei** | `nuclei_scan`, `nuclei_cve_scan`, `nuclei_tech_detect`, `nuclei_exposed_scan`, `nuclei_dns_scan`, `nuclei_ssl_scan`, `list_templates`, `nuclei_update_templates` | Vuln Scanning |
| 8103 | **OSINT** | `whois_lookup`, `dns_lookup`, `http_headers`, `ip_geolocation`, `subdomain_enum`, `ssl_info`, `tech_fingerprint` | Intelligence |
| 8104 | **Metasploit** | `list_exploits`, `run_exploit`, `run_auxiliary_module`, `generate_payload`, `list_active_sessions`, `send_session_command`, `start_listener` + 6 more | Exploitation |
| 8107 | **WAF Detection** | `fingerprint_waf`, `test_bypass`, `analyze_evasion` | Web Security |
| 8108 | **ffuf** | `ffuf_fuzz`, `ffuf_subdomains`, `ffuf_parameters`, `ffuf_vhost`, `ffuf_recursive`, `ffuf_filter_codes`, `ffuf_list_wordlists` | Fuzzing |
| 8109 | **SQLMap** | `sqlmap_scan`, `sqlmap_enum_databases`, `sqlmap_dump_table`, `sqlmap_check_status` | SQL Injection |
| 8112 | **SSL/TLS** | `check_ssl`, `get_ssl_grade`, `check_ssl_vulnerabilities` | Cryptography |
| 8114 | **CISA KEV** | `check_kev`, `search_kev`, `get_kev_stats`, `get_recent_kev` | Threat Intel |
| 8115 | **EPSS** | `get_epss_score`, `get_epss_scores_bulk`, `get_high_epss_cves`, `epss_priority_analysis` | Risk Scoring |
| 8116 | **PoC Index** | `search_poc`, `search_github_poc`, `get_exploitdb_entry`, `poc_risk_summary` | Exploit Intel |
| 8117 | **Nikto** | `nikto_scan`, `nikto_tuning`, `nikto_ssl_only` | Web Server Vuln |
| 8118 | **Masscan** | `masscan_scan`, `masscan_top_ports`, `masscan_range` | Fast Port Scan |
| 8119 | **WPScan** | `wp_scan`, `wp_enum_users`, `wp_enum_plugins`, `wp_enum_themes` | WordPress Vuln |
| 8120 | **JWT** | `decode_jwt`, `test_alg_none`, `test_weak_secret`, `forge_jwt`, `analyze_claims` | JWT Attacks |
| 8121 | **Gobuster** | `gobuster_dir`, `gobuster_dns`, `gobuster_vhost`, `gobuster_fuzz` | Brute-Force |

### 🛡️ Platform Features
| Feature | Details |
|---------|---------|
| **Multi-LLM** | External Ollama server, OpenAI, Anthropic, OpenRouter, Grok, Mistral |
| **Persistent AI Sessions** | Chat history saved to PostgreSQL, survives refresh/re-login |
| **Conversation Context** | Last 20 turns sent with every request — true multi-turn awareness |
| **Enterprise Auth** | JWT + HttpOnly cookies + RBAC (4 roles) + OAuth2 (Google/Microsoft) |
| **MFA Support** | TOTP-based multi-factor authentication |
| **Real-time Streaming** | SSE token streaming + WebSocket scan progress |
| **Scan Scheduler** | Cron-based recurring scan scheduling |
| **Workflow Builder** | Visual node-based automated pentest workflows |
| **White-label Reports** | PDF/HTML/JSON/CSV with custom branding (Jinja2 templates) |
| **API Key Management** | Programmatic access via API keys |
| **Notifications** | Webhook + in-app notifications |
| **Container Native** | Docker Compose production stack + on-prem installer |
| **LAN/Remote Deploy** | Relative-URL frontend — works from any LAN IP without CORS issues |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Browser (Next.js 15 — React, TypeScript)                   │
│  Relative /api/* URLs → nginx proxies to backend             │
└────────────────────────┬────────────────────────────────────┘
                         │ HTTP / WebSocket
                    ┌────▼─────┐
                    │  nginx   │  Reverse proxy + TLS termination
                    └────┬─────┘
                         │
              ┌──────────▼──────────┐
              │  FastAPI Backend    │  REST + WebSocket + SSE
              │  (Python 3.12)      │
              │  ARQ Worker         │  Async scan tasks
              └──┬───────────────┬──┘
                 │               │
         ┌───────▼────┐   ┌──────▼──────┐
         │ PostgreSQL │   │    Redis    │  Task queue + cache
         └────────────┘   └─────────────┘
                 │
         ┌───────▼──────────────────────────────────────┐
         │  MCP Client  →  30 HTTP MCP Servers                          │
         │  cve · nmap · nuclei · osint · metasploit                    │
         │  waf · ffuf · sqlmap · ssl · kev · epss · poc                │
         │  nikto · masscan · wpscan · jwt · gobuster                   │
         └──────────────────────────────────────────────────────────────┘
                 │
         ┌───────▼──────────────────────────────────────┐
         │  External Ollama server (self-hosted)         │
         │  OpenAI API          /  Anthropic API         │
         └──────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Ubuntu 22.04+ | Ubuntu 24.04 LTS |
| RAM | 8 GB | 16+ GB |
| CPU | 2 cores | 4+ cores |
| Disk | 20 GB | 50+ GB |
| GPU | None | Only on the *external* Ollama host, if you self-host a model |
| Docker | 20.10+ | Latest Compose v2 |

### Option 1: Development Setup (Recommended)

```bash
# 1. Clone
git clone https://github.com/0x4hm3d/socis-ai-pt.git
cd socis-ai-pt

# 2. Copy and configure environment
cp deploy/docker/.env.example deploy/docker/.env
# Edit deploy/docker/.env — generate secrets with: openssl rand -hex 32

# 3. Run development installer (auto-detects OS, installs Docker)
bash deploy/scripts/install-dev.sh

# 4. Start all services
cd deploy/docker
docker compose up -d

# 5. Pull AI models
bash ../../deploy/scripts/setup-models.sh

# Access
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000/docs
# Default login: admin / the generated ADMIN_PASSWORD in deploy/docker/.env — change it in Settings after first login
```

### Option 2: Production (On-Premise with SSL)

```bash
git clone https://github.com/0x4hm3d/socis-ai-pt.git /opt/socis-ai-pt
cd /opt/socis-ai-pt

# Configure production environment (set strong secrets!)
cp deploy/docker/.env.example deploy/docker/.env
nano deploy/docker/.env

sudo bash deploy/scripts/install-prod.sh \
  --domain socis.company.com \
  --email admin@company.com \
  --letsencrypt \
  --unattended
```

### Option 3: LAN Deployment (No SSL)

```bash
cd deploy/docker
docker compose up -d
# Set SECURE_COOKIES=false in .env for HTTP-only LAN access
# Access from any host on the LAN: http://<server-ip>:3000
```

---

## Configuration

### Environment Variables

Copy `deploy/docker/.env.example` to `deploy/docker/.env` and set:

```env
# Required — generate with: openssl rand -hex 32
SECRET_KEY=...
JWT_SECRET_KEY=...
MCP_AUTH_TOKEN=...

# Database
DB_PASSWORD=...
DATABASE_URL=postgresql+asyncpg://socis_admin:DBPASSWORD@postgres:5432/socis_ai_pt

# Redis
REDIS_PASSWORD=...
REDIS_URL=redis://:REDISPASSWORD@redis:6379/0

# Admin account (dev default: Admin123!)
ADMIN_PASSWORD=...

# Cookies — set false for HTTP/LAN, true for HTTPS/production
SECURE_COOKIES=false
```

### LLM Providers

| Provider | How to configure |
|---------|-----------------|
| **Ollama (external)** | Run Ollama on a separate host. Admin UI → Settings → Remote Ollama, or set `OLLAMA_REMOTE_URL` in `.env`. There is no bundled Ollama container. |
| **OpenAI** | Set `OPENAI_API_KEY` in `.env` |
| **Anthropic** | Set `ANTHROPIC_API_KEY` in `.env` |

### AI Models (Ollama)

```bash
# Pull recommended models
bash deploy/scripts/setup-models.sh

# Models:
# socis-pentest  (qwen2.5:7b)  — general pentest analysis
# socis-recon    (llama3.1:8b) — recon output interpretation
# socis-exploit  (deepseek-r1:8b) — CVE/exploit research
```

---

## AI Chat — How Tool Dispatch Works

The system uses a **two-pass agentic pipeline**:

```
User message
     │
     ▼
Pass 1 — LLM reads message + system prompt
  • Emits special tags: [SEARCH: CVE-2021-44228]
  •                     [MCP: nmap_mcp.nmap_scan {"target":"..."}]
  • Tags are NOT shown to the user
     │
     ▼
Tag dispatch (parallel for SEARCH, sequential for MCP)
  • [SEARCH] → queries NVD + CISA KEV + EPSS + PoC Index simultaneously
  • [MCP] → calls the named server.tool with parsed arguments
     │
     ▼
Pass 2 — LLM receives live tool data + writes synthesis
  • Streams final report to the user via SSE
  • Shows "⚡ Live data retrieved from: CVE Database · CISA KEV · EPSS" badge
```

### Example Prompts

```
Tell me about CVE-2021-44228
  → [SEARCH: CVE-2021-44228] → 4 parallel intel queries → report

Scan 192.168.1.100 for open ports
  → [MCP: nmap_mcp.nmap_scan {"target":"192.168.1.100","flags":"-sV"}]

Check https://target.com for web vulnerabilities
  → [MCP: nuclei_mcp.nuclei_scan {"target":"https://target.com"}]
  → [MCP: waf_detection_mcp.fingerprint_waf {"target":"https://target.com"}]

Is CVE-2023-44487 actively exploited?
  → [MCP: cisa_kev_mcp.check_kev {"cve_id":"CVE-2023-44487"}]

What's the SSL grade for github.com?
  → [MCP: ssl_mcp.check_ssl {"hostname":"github.com"}]
```

---

## Project Structure

```
socis-ai-pt/
├── backend/                    # FastAPI application
│   ├── app/
│   │   ├── api/v1/             # REST API routes (55+ endpoints)
│   │   │   ├── auth.py         # Login, logout, MFA, OAuth
│   │   │   ├── llm.py          # AI chat, agentic tool dispatch, model management
│   │   │   ├── mcp.py          # MCP server management API
│   │   │   ├── scans.py        # Scan CRUD + results
│   │   │   ├── vulnerabilities.py
│   │   │   ├── projects.py
│   │   │   ├── reports.py
│   │   │   ├── admin.py        # User mgmt, platform settings, remote LLM config
│   │   │   ├── chat_sessions.py
│   │   │   ├── settings.py     # Per-user settings (LLM prefs, etc.)
│   │   │   ├── workflows.py
│   │   │   └── schedules.py
│   │   ├── core/               # DB engine, security, exceptions
│   │   ├── mcp/
│   │   │   └── client.py       # MCP client, server registry, tool dispatch
│   │   ├── models/             # SQLAlchemy ORM (12+ tables)
│   │   ├── services/
│   │   │   ├── llm_service.py  # Multi-provider LLM router + system prompt
│   │   │   └── tool_service.py
│   │   └── tasks/              # ARQ async scan worker
│   ├── migrations/             # Alembic schema migrations
│   ├── modelfiles/             # Ollama model profiles
│   └── requirements.txt
├── frontend/                   # Next.js 15 (App Router, TypeScript)
│   └── src/
│       ├── app/(app)/
│       │   ├── dashboard/      # Platform status + stats
│       │   ├── ai-chat/        # Agentic AI chat with session history
│       │   ├── scans/          # Scan management
│       │   ├── vulnerabilities/
│       │   ├── projects/
│       │   ├── reports/
│       │   ├── mcp/            # MCP Tool Explorer + Executor
│       │   ├── workflows/      # Visual workflow builder
│       │   └── admin/          # Admin panel (users, LLM config, MCP)
│       └── components/
│           ├── Sidebar.tsx
│           ├── MarkdownRenderer.tsx
│           └── MCPHelpModal.tsx
├── mcp-servers/                # 30 HTTP MCP servers (Python/FastAPI, see supervisord.conf)
│   ├── cve_server.py           # NVD CVE database
│   ├── nmap_server.py
│   ├── nuclei_server.py
│   ├── osint_server.py
│   ├── metasploit_server.py
│   ├── waf_detection_server.py
│   ├── ffuf_server.py
│   ├── sqlmap_server.py
│   ├── ssl_server.py
│   ├── cisa_kev_server.py
│   ├── epss_server.py
│   ├── poc_server.py
│   ├── nikto_server.py
│   ├── masscan_server.py
│   ├── wpscan_server.py
│   ├── jwt_server.py
│   ├── gobuster_server.py
│   └── mcp_auth.py             # Shared bearer-token auth middleware
├── deploy/
│   ├── docker/
│   │   ├── docker-compose.yml  # Full production stack
│   │   └── .env.example        # Configuration template
│   ├── nginx/                  # Reverse proxy config
│   └── scripts/
│       ├── install-dev.sh
│       ├── install-prod.sh
│       ├── setup-models.sh
│       └── cleanup.sh
└── docs/                       # Full documentation
```

---

## API Reference

Base URL: `http://localhost:8000/api/v1`  
Authentication: HttpOnly cookie (set on login) or `Authorization: Bearer <api-key>`

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/login` | Login — sets JWT cookie |
| `POST` | `/auth/logout` | Logout — clears cookie |
| `POST` | `/llm/chat` | Agentic AI chat (SSE streaming) |
| `GET` | `/llm/models` | List available LLM models |
| `GET` | `/llm/status` | LLM provider connectivity |
| `GET` | `/mcp/servers` | List all MCP servers + tools |
| `POST` | `/mcp/execute` | Execute a specific MCP tool |
| `GET` | `/scans` | List scans |
| `POST` | `/scans` | Create and run a scan |
| `GET` | `/vulnerabilities` | List vulnerabilities |
| `GET` | `/projects` | List projects |
| `POST` | `/reports` | Generate report |
| `GET` | `/admin/settings` | Platform settings (admin) |
| `POST` | `/admin/settings/remote-ollama` | Configure remote Ollama (admin) |
| `GET` | `/api/services-health` | Backend, DB, Redis, Ollama status |

Full API docs: `http://localhost:8000/docs` (Swagger UI)

---

## Troubleshooting

### MCP servers in Error state
```bash
# Check MCP_AUTH_TOKEN is set in deploy/docker/.env
# and matches across all services
grep MCP_AUTH_TOKEN deploy/docker/.env

# Restart backend to reload token
docker compose restart backend
```

### "Config needed" in Platform Status
```bash
# Backend health check
curl http://localhost:8000/api/services-health
```

### LAN access — 401 errors
```bash
# Ensure SECURE_COOKIES=false in .env for HTTP
# Frontend uses relative URLs — same-origin cookies work from any IP
```

### Ollama models missing
```bash
bash deploy/scripts/setup-models.sh
# or manually:
docker exec -it socis_ollama ollama create socis-pentest -f /modelfiles/socis-pentest.Modelfile
```

### Container logs
```bash
docker compose logs backend --tail=100
docker compose logs frontend --tail=50
docker compose logs mcp_all --tail=50
```

---

## Security Notes

- **Never commit `.env` files** — they are gitignored
- Generate all secrets with `openssl rand -hex 32`
- Set `SECURE_COOKIES=true` when deploying with HTTPS
- `ADMIN_PASSWORD` is generated per install (see `deploy/docker/.env`) — change it in Settings after first login
- MCP servers are protected by a shared bearer token (`MCP_AUTH_TOKEN`) — rotate periodically

---

## Documentation

| Guide | Description |
|-------|-------------|
| [docs/deployment/DEPLOYMENT_GUIDE.md](docs/deployment/DEPLOYMENT_GUIDE.md) | Full deployment guide |
| [docs/mcp-integration/MCP_INTEGRATION_GUIDE.md](docs/mcp-integration/MCP_INTEGRATION_GUIDE.md) | MCP server setup & extension |
| [docs/user-guide/USER_GUIDE.md](docs/user-guide/USER_GUIDE.md) | End-user guide |
| [docs/api/README.md](docs/api/README.md) | Full API reference |
| [docs/QUICK_REFERENCE.md](docs/QUICK_REFERENCE.md) | Common commands & endpoints |

---

## License

Business Source License 1.1 (BSL 1.1) — see [LICENSE](LICENSE).

Free for non-production use. Contact for commercial licensing.

---

<div align="center">
  <p>Built with ❤️ by SOCIS | Enterprise Cybersecurity</p>
</div>

