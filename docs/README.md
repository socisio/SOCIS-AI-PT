# SOCIS-AI-PT Documentation

Welcome to the SOCIS-AI-PT documentation. This guide covers all aspects of the platform - from API usage to deployment and user workflows.

---

## 📚 Documentation Structure

### [API Documentation](api/README.md)

Complete REST API reference with:
- **Authentication** - JWT token handling and HttpOnly cookie auth
- **Core Endpoints** - Projects, Scans, Vulnerabilities, Reports
- **AI Analysis** - LLM chat, model listing, streaming SSE
- **Tools & MCP** - 22 MCP servers with correct names, ports, and tools
- **User Settings** - Per-user LLM provider/model preferences
- **Health Checks** - `/health` and `/api/services-health`
- **Admin** - User management, LLM configs, audit logs
- **WebSocket** - Real-time scan updates
- **Permissions** - Full permission reference table
- **LLM Providers** - Valid provider enum values
- **Environment Config** - Variables not available via UI

**When to use**: Building integrations, automation, or client applications

---

### [Deployment Guide](deployment/DEPLOYMENT_GUIDE.md)

Complete deployment instructions for all environments:
- **Quick Start** - Get running in 15 minutes
- **Production Setup** - Enterprise-grade deployment
- **Docker Compose** - Containerized deployment
- **Kubernetes** - Cloud-native deployment
- **Health Checks** - Monitoring and troubleshooting
- **Backup & Recovery** - Data protection strategies
- **Security Hardening** - Production-ready security

**When to use**: Setting up deployment for development, staging, or production

---

### [Frontend Deployment](deployment/FRONTEND_DEPLOYMENT.md)

Next.js frontend deployment guide covering:
- **Local Development** - Development server setup
- **Production Build** - Optimized builds
- **Docker** - Container deployment
- **Nginx Proxy** - Reverse proxy configuration
- **Performance Optimization** - Bundle size and caching
- **Monitoring** - Health checks and error tracking
- **Security** - HTTPS and security headers

**When to use**: Deploying or configuring the web interface

---

### [Backend Deployment](deployment/BACKEND_DEPLOYMENT.md)

FastAPI backend deployment guide covering:
- **Local Development** - Development environment setup
- **Production Deployment** - On-premise installation
- **Systemd Service** - Production service management
- **Docker** - Containerized deployment
- **Database Management** - PostgreSQL setup and backups
- **Monitoring** - Logging and metrics
- **Performance Tuning** - Optimization strategies

**When to use**: Deploying or configuring the API server

---

### [MCP Integration Guide](mcp-integration/MCP_INTEGRATION_GUIDE.md)

Model Context Protocol integration documentation:
- **Overview** - What is MCP and its benefits
- **Architecture** - 22-server MCP stack in a single supervised container
- **Server Setup** - All 22 servers: Nmap, Metasploit, Nuclei, OSINT, CVE, MITRE ATT&CK, ExploitDB, Anomaly, Payload Generator, CVE Lite + 12 more
- **Backend Integration** - Using MCP in the application
- **Custom Servers** - Building your own MCP servers
- **AI Integration** - Enabling AI tool calling (full coverage for all 22 servers)
- **Monitoring** - Health checks and troubleshooting

**When to use**: Setting up security tools, creating custom integrations, or understanding tool ecosystem

---

### [User Guide](user-guide/USER_GUIDE.md)

End-user documentation covering:
- **Getting Started** - Login, dashboard overview, navigation
- **Projects & Scans** - Creating and managing penetration test engagements
- **Vulnerability Management** - Triage, severity, and remediation tracking
- **Reports** - Generating PDF/HTML executive and technical reports
- **AI Chat Assistant** - Interactive threat intelligence and CVE lookup
- **AI Prompt Templates** - Built-in offensive methodology prompts (auto-seeded), admin management via Settings → Admin Control → Prompt Templates
- **Administration** - User management, LLM configs, audit logs, SSO, tool policy

**When to use**: Day-to-day platform usage, onboarding new users, admin configuration

Complete user guide for the platform:
- **Getting Started** - Login and navigation
- **Dashboard** - Overview and quick access
- **Projects** - Project management
- **Scans** - Creating and running security scans
- **Results** - Viewing scan results and findings
- **Vulnerabilities** - Managing discovered vulnerabilities
- **Reports** - Generating security reports
- **AI Chat** - Using the AI analyst assistant
- **Administration** - User and system management
- **Best Practices** - Effective usage patterns

**When to use**: Learning how to use the platform or training others

---

## 🚀 Quick Start by Role

### I'm a Developer
1. Read [API Documentation](api/README.md) for endpoint reference
2. Check [Backend Deployment](deployment/BACKEND_DEPLOYMENT.md) for local setup
3. See [Frontend Deployment](deployment/FRONTEND_DEPLOYMENT.md) for UI development

### I'm a DevOps Engineer
1. Start with [Deployment Guide](deployment/DEPLOYMENT_GUIDE.md) for overview
2. Follow [Backend Deployment](deployment/BACKEND_DEPLOYMENT.md) for API setup
3. Follow [Frontend Deployment](deployment/FRONTEND_DEPLOYMENT.md) for UI setup
4. Reference [MCP Integration Guide](mcp-integration/MCP_INTEGRATION_GUIDE.md) for tools

### I'm a Security Analyst
1. Read [User Guide](user-guide/USER_GUIDE.md) to learn the platform
2. Reference [API Documentation](api/README.md) for automation
3. Use [AI Chat](user-guide/USER_GUIDE.md#ai-chat-assistant) for analysis
4. Follow [User Guide - Reports](user-guide/USER_GUIDE.md#reports) for reporting

### I'm a System Administrator
1. Follow [Deployment Guide](deployment/DEPLOYMENT_GUIDE.md) for setup
2. Configure users in [User Guide - Administration](user-guide/USER_GUIDE.md#administration)
3. Monitor with health checks in [Deployment Guide](deployment/DEPLOYMENT_GUIDE.md#health-checks--monitoring)
4. Backup data using [Deployment Guide](deployment/DEPLOYMENT_GUIDE.md#backup--recovery)

---

## 📖 Common Tasks

### "How do I deploy SOCIS-AI-PT?"
→ [Deployment Guide](deployment/DEPLOYMENT_GUIDE.md)

### "How do I integrate SOCIS-AI-PT with my tools?"
→ [API Documentation](api/README.md) + [MCP Integration Guide](mcp-integration/MCP_INTEGRATION_GUIDE.md)

### "How do I use the platform to find vulnerabilities?"
→ [User Guide](user-guide/USER_GUIDE.md)

### "How do I set up custom security tools?"
→ [MCP Integration Guide](mcp-integration/MCP_INTEGRATION_GUIDE.md#creating-custom-mcp-servers)

### "How do I backup my data?"
→ [Deployment Guide - Backup & Recovery](deployment/DEPLOYMENT_GUIDE.md#backup--recovery)

### "How do I troubleshoot issues?"
→ See Troubleshooting sections in relevant deployment guides

### "How do I optimize performance?"
→ See Performance Tuning sections in deployment guides

### "How do I set up automated scanning?"
→ [API Documentation](api/README.md) + [User Guide - Scanning](user-guide/USER_GUIDE.md#creating-scans)

---

## 🔐 Security & Best Practices

All documentation includes security-specific guidance:
- **API Security** - [API Docs > Best Practices](api/README.md#best-practices)
- **Deployment Security** - [Deployment Guide > Security Hardening](deployment/DEPLOYMENT_GUIDE.md#security-hardening)
- **Frontend Security** - [Frontend Deployment > Security](deployment/FRONTEND_DEPLOYMENT.md#security-best-practices)
- **Backend Security** - [Backend Deployment > Security](deployment/BACKEND_DEPLOYMENT.md#security-hardening)
- **User Management** - [User Guide > Administration](user-guide/USER_GUIDE.md#administration)

---

## 📊 Architecture Overview

### High-Level Architecture
```
┌─────────────────────────────────────────────┐
│           Frontend (Next.js 15)             │
│         http://localhost:3000               │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│      Nginx Reverse Proxy (Optional)         │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│     Backend API (FastAPI)                   │
│     http://localhost:8000/api/v1            │
└─────────────────────────────────────────────┘
       │                    │
       │                    ▼
       │            ┌───────────────┐
       │            │  PostgreSQL   │
       │            │  (Database)   │
       │            └───────────────┘
       │
       ├──► ┌──────────────┐     ┌──────────┐
       │    │    Redis     │────▶│ Ollama   │
       │    │   (Cache)    │     │  (LLM)   │
       │    └──────────────┘     └──────────┘
       │
       └──► ┌────────────────────────────────┐
            │  MCP Servers (Tools)           │
            ├── Nmap (Port 8001)             │
            ├── Metasploit (Port 8002)       │
            ├── Nuclei (Port 8003)           │
            ├── OSINT (Port 8004)            │
            └── CVE (Port 8005)              │
            └────────────────────────────────┘
```

### Key Components

**Frontend**:
- Next.js 15 React application
- Real-time scan updates via WebSocket
- AI-powered analysis interface
- Responsive design for mobile/desktop

**Backend**:
- FastAPI Python service
- JWT-based authentication
- WebSocket support for real-time updates
- Async task processing

**Database**:
- PostgreSQL for persistent data
- Redis for caching and sessions
- Alembic for schema migrations

**Integrations**:
- Ollama for local LLM inference
- External LLM APIs (OpenAI, Anthropic)
- MCP servers for security tools

---

## 📞 Getting Help

### Documentation
- **API Issues**: See [API Documentation](api/README.md#error-handling)
- **Deployment Issues**: See [Deployment Guide](deployment/DEPLOYMENT_GUIDE.md#troubleshooting)
- **User Issues**: See [User Guide](user-guide/USER_GUIDE.md#troubleshooting)

### External Resources
- **GitHub Issues**: https://github.com/0x4hm3d/SOCIS-AI-PT/issues
- **FastAPI Docs**: https://fastapi.tiangolo.com
- **Next.js Docs**: https://nextjs.org
- **PostgreSQL Docs**: https://www.postgresql.org/docs
- **Docker Docs**: https://docs.docker.com

### Support Channels
- **Email**: support@socis-ai-pt.com
- **GitHub Discussions**: https://github.com/0x4hm3d/SOCIS-AI-PT/discussions
- **Community Forum**: https://forum.socis-ai-pt.com

---

## 📝 Documentation Information

**Last Updated**: April 14, 2026  
**Version**: 1.0.0  
**Status**: Complete and Production-Ready

---

## 🎯 Which Documentation Should I Read?

| Need | Document | Time |
|------|----------|------|
| Deploy locally | Deployment Guide + Backend/Frontend Deployments | 30 min |
| Deploy to production | Deployment Guide + Backend/Frontend Deployments | 2 hours |
| Use the platform | User Guide | 1 hour |
| Build with API | API Documentation | 1 hour |
| Integrate tools | MCP Integration Guide | 2 hours |
| Troubleshoot issues | See Troubleshooting in relevant docs | 30 min |
| Optimize performance | Performance Tuning in relevant docs | 1 hour |

---

**Start here based on your role**:
- 👨‍💻 **Developer**: [Backend Deployment](deployment/BACKEND_DEPLOYMENT.md)
- 🚀 **DevOps**: [Deployment Guide](deployment/DEPLOYMENT_GUIDE.md)
- 🔐 **Security**: [User Guide](user-guide/USER_GUIDE.md)
- 🔧 **Integration**: [API Documentation](api/README.md)
