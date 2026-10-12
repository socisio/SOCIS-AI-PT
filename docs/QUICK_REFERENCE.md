# SOCIS-AI-PT Quick Reference

Fast lookup guide for common questions and tasks.

---

## 🚀 Getting Started (5 minutes)

### Local Development

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
export DATABASE_URL=postgresql://user:password@localhost:5432/socis_db
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev
# Visit http://localhost:3000
```

### Docker Compose

```bash
cd deploy/docker
docker-compose up -d
# Visit http://localhost:3000

# GPU/Ollama support
docker-compose -f docker-compose.yml -f docker-compose.gpu.yml up -d
```

---

## 📋 API Quick Reference

### Authentication
```bash
# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin", "password":"password"}'

# Use token
curl -H "Authorization: Bearer TOKEN" \
  http://localhost:8000/api/v1/projects
```

### Common Endpoints
```bash
# List projects
GET /api/v1/projects

# Create scan
POST /api/v1/scans

# List vulnerabilities
GET /api/v1/vulnerabilities

# Generate report
POST /api/v1/reports

# AI chat
POST /api/v1/llm/chat
```

See [API Documentation](api/README.md) for complete reference.

---

## 🔧 Deployment Checklists

### 15-Minute Quick Start
- [ ] Clone repo
- [ ] docker-compose up -d
- [ ] Visit http://localhost:3000

### Production Deployment
- [ ] [Production Setup](deployment/DEPLOYMENT_GUIDE.md#production-deployment)
- [ ] [Backend Deployment](deployment/BACKEND_DEPLOYMENT.md#production-deployment)
- [ ] [Frontend Deployment](deployment/FRONTEND_DEPLOYMENT.md#production-build)
- [ ] Configure SSL certificates
- [ ] Set environment variables
- [ ] Run database migrations
- [ ] Create admin user
- [ ] Test all endpoints

---

## 🛠️ Common Tasks

### Create an Admin User

**Docker**:
```bash
docker-compose exec backend python -m app.scripts.init_admin \
  --username admin \
  --password secure_password \
  --email admin@example.com
```

**Local**:
```bash
python -m app.scripts.init_admin \
  --username admin \
  --password secure_password \
  --email admin@example.com
```

### Backup Database

**Local PostgreSQL**:
```bash
pg_dump socis_db > backup.sql
```

**Docker**:
```bash
docker-compose exec postgres pg_dump \
  -U socis socis_db > backup.sql
```

### Check MCP Server Status

```bash
# Check all 22 MCP processes inside the container
docker exec socis_mcp_all supervisorctl -c /etc/supervisor/supervisord.conf \
  -s unix:///tmp/supervisor.sock status

# Via the API
curl -s http://localhost:8000/api/v1/mcp/servers | python3 -m json.tool

# Direct health checks for the new servers
curl http://localhost:8105/health   # mitre_mcp
curl http://localhost:8122/health   # cve_lite_mcp
curl http://localhost:8123/health   # anomaly_mcp
curl http://localhost:8124/health   # payload_generator_mcp
curl http://localhost:8125/health   # exploitdb_mcp
```

### View Logs

**Docker**:
```bash
docker-compose logs -f backend
docker-compose logs -f frontend
```

**Systemd**:
```bash
sudo journalctl -u socis-backend -f
```

### Restart Services

**Docker**:
```bash
docker-compose restart backend
docker-compose restart frontend
```

**Systemd**:
```bash
sudo systemctl restart socis-backend
```

---

## 🔍 Troubleshooting

### API Not Responding

```bash
# Check if running
curl http://localhost:8000/health

# Check logs
docker-compose logs backend | tail -50

# Restart
docker-compose restart backend
```

### Database Connection Error

```bash
# Check if PostgreSQL is running
docker-compose ps | grep postgres

# Check connection
docker-compose exec backend \
  psql $DATABASE_URL -c "SELECT 1;"

# Reset database (WARNING: Deletes data)
docker-compose down -v
docker-compose up -d
```

### Frontend Won't Load

```bash
# Check if frontend is running
curl http://localhost:3000

# Check logs
docker-compose logs frontend | tail -50

# Check API URL is correct
# In browser console: console.log(process.env.NEXT_PUBLIC_API_URL)

# Clear browser cache and reload
```

### MCP Tool Not Working

```bash
# Check if MCP servers are running
curl http://localhost:8100/health  # CVE MCP
curl http://localhost:8101/health  # Nmap MCP
curl http://localhost:8114/health  # CISA KEV MCP

# Check all servers via API
curl http://localhost:8000/api/v1/mcp/servers -H "Authorization: Bearer $TOKEN"

# Check backend MCP logs
sg docker -c "docker logs socis_backend --tail 50" | grep -i mcp
```

---

## 🔐 Security Essentials

### Change Default Credentials

```bash
# Change admin password
# Via Admin panel or:
python scripts/change_password.py admin new_password
```

### Generate JWT Secret

```bash
# Generate strong secret
python -c 'import secrets; print(secrets.token_urlsafe(32))'

# Update in .env
JWT_SECRET=your-generated-secret

# Restart to apply
docker-compose restart backend
```

### Enable HTTPS

```nginx
# In nginx.conf
server {
    listen 443 ssl http2;
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
}
```

### Backup Secrets

```bash
# Backup .env file (keep secure!)
cp .env .env.backup
chmod 600 .env.backup
```

---

## 📊 Monitoring Commands

### Check Service Health

```bash
# All services
curl http://localhost:8000/health

# Database
curl http://localhost:8000/health/db

# Redis
curl http://localhost:8000/health/redis

# Ollama
curl http://localhost:8000/health/ollama
```

### View Resource Usage

```bash
# Container stats
docker stats

# Disk space
df -h

# Database size
docker-compose exec postgres psql -U socis -d socis_db \
  -c "SELECT pg_size_pretty(pg_database_size(current_database()));"
```

### Check Error Logs

```bash
# Backend errors
docker-compose logs backend | grep ERROR

# Frontend errors
docker-compose logs frontend | grep ERROR

# Database errors
docker-compose logs postgres | grep ERROR
```

---

## 🎯 Configuration Quick Reference

### Environment Variables

**Backend**:
```bash
DATABASE_URL=postgresql://user:pass@host:5432/db
REDIS_URL=redis://host:6379/0
JWT_SECRET=your-secret
OLLAMA_REMOTE_URL=http://<your-ollama-host>:11434
LOG_LEVEL=info
```

**Frontend**:
```bash
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
```

### Port Mapping

| Service | Port | URL |
|---------|------|-----|
| Frontend | 3000 | http://localhost:3000 |
| Backend | 8000 | http://localhost:8000 |
| Nginx | 80/443 | http://localhost |
| Ollama | 11434 | http://localhost:11434 |
| MinIO | 9001 | http://localhost:9001 |
| PostgreSQL | 5432 | (internal only) |
| Redis | 6379 | (internal only) |
| CVE MCP | 8100 | (internal only) |
| Nmap MCP | 8101 | (internal only) |
| Nuclei MCP | 8102 | (internal only) |
| OSINT MCP | 8103 | (internal only) |
| Metasploit MCP | 8104 | (internal only) |
| Burp Suite MCP | 8105 | (internal only) |
| OWASP ZAP MCP | 8106 | (internal only) |
| WAF Detection MCP | 8107 | (internal only) |
| ffuf MCP | 8108 | (internal only) |
| sqlmap MCP | 8109 | (internal only) |
| SSL MCP | 8112 | (internal only) |
| CISA KEV MCP | 8114 | (internal only) |
| EPSS MCP | 8115 | (internal only) |
| PoC MCP | 8116 | (internal only) |
| Metasploit RPC | 55553 | (internal only) |
| Lab DVWA | 4280 | http://localhost:4280 |
| Lab Metasploitable2 | 2222/2121/2180/... | (lab environment) |

---

## 🔗 Important Links

| Resource | URL |
|----------|-----|
| GitHub | https://github.com/0x4hm3d/SOCIS-AI-PT |
| Issues | https://github.com/0x4hm3d/SOCIS-AI-PT/issues |
| API Docs | http://localhost:8000/docs |
| Full Docs | See [Documentation Index](README.md) |

---

## 📞 Help & Support

- **Documentation**: [Full Docs](README.md)
- **API Reference**: [API Docs](api/README.md)
- **Deployment**: [Deployment Guide](deployment/DEPLOYMENT_GUIDE.md)
- **User Guide**: [User Manual](user-guide/USER_GUIDE.md)
- **Email**: support@socis-ai-pt.com
- **GitHub Issues**: https://github.com/0x4hm3d/SOCIS-AI-PT/issues

---

## 💡 Pro Tips

1. **Use Docker Compose for everything** - Eliminates configuration issues
2. **Read logs when things fail** - They always tell you what's wrong
3. **Check health endpoints** - Quick way to diagnose service issues
4. **Backup before changes** - Always backup database before upgrades
5. **Monitor resource usage** - Keep eye on disk space and memory
6. **Use environment variables** - Never hardcode secrets
7. **Test locally first** - Test changes in Docker Compose before production
8. **AI Chat settings persist** - Provider & model saved per-user in DB via `GET/POST /api/v1/settings/llm`; no localStorage needed
9. **Long-running tools** - `ffuf_fuzz`, `sqlmap_scan`, `nuclei_scan`, `amass_enum` have 300 s backend timeout

---

**Last Updated**: April 20, 2026  
**Quick Reference Version**: 2.0.0
