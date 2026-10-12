# Backend Deployment Guide

## Overview

This guide covers deploying the SOCIS-AI-PT backend (FastAPI Python application) to various environments.

---

## Backend Stack

- **Framework**: FastAPI 0.104+
- **Python**: 3.9+
- **Database**: PostgreSQL 15
- **Cache**: Redis 7+
- **ORM**: SQLAlchemy
- **Migrations**: Alembic
- **Task Queue**: Celery (optional)
- **LLM**: Ollama, OpenAI, Anthropic APIs

---

## Prerequisites

### System Requirements

- **Python**: 3.9 or higher
- **PostgreSQL**: 12 or higher
- **Redis**: 6 or higher
- **Memory**: 2GB minimum
- **Storage**: 10GB (includes models)
- **Network**: Accessible from frontend

### Python Dependencies

```bash
pip install -r backend/requirements.txt
```

Key packages:
- fastapi
- sqlalchemy
- psycopg2-binary
- redis
- uvicorn
- python-jose
- passlib
- requests

---

## Local Development

### 1. Setup Python Environment

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate  # Windows
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment

Create `.env`:

```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/socis_db

# Redis
REDIS_URL=redis://localhost:6379/0

# Ollama
OLLAMA_REMOTE_URL=http://<your-ollama-host>:11434

# JWT
JWT_SECRET=your-secret-key-change-in-production
JWT_ALGORITHM=HS256
JWT_EXPIRATION=3600

# CORS
CORS_ORIGINS=http://localhost:3000

# Logging
LOG_LEVEL=debug
```

### 4. Setup Database

```bash
# Create database
createdb socis_db

# Run migrations
alembic upgrade head

# Create admin user
python -m app.scripts.init_admin \
  --username admin \
  --password securepassword \
  --email admin@example.com
```

### 5. Start Server

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**API Available at**: http://localhost:8000
**Docs**: http://localhost:8000/docs

---

## Production Deployment

### 1. System Preparation

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install system dependencies
sudo apt-get install -y \
  python3.9 \
  python3.9-venv \
  python3.9-dev \
  postgresql \
  postgresql-contrib \
  redis-server \
  git \
  build-essential \
  libpq-dev
```

### 2. Setup Application User

```bash
# Create application user
sudo useradd -m -s /bin/bash socis

# Grant sudo (optional)
sudo usermod -aG sudo socis

# Switch to user
sudo su - socis
```

### 3. Clone Repository

```bash
git clone https://github.com/0x4hm3d/SOCIS-AI-PT.git
cd SOCIS-AI-PT
```

### 4. Setup Python Environment

```bash
cd backend

python3.9 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pip install gunicorn
```

### 5. Configure Database

```bash
# Switch to postgres user
sudo su - postgres

# Create database and user
createdb socis_db
createuser socis WITH PASSWORD 'secure_password'

# Grant privileges
psql
postgres=# ALTER ROLE socis CREATEDB;
postgres=# GRANT ALL PRIVILEGES ON DATABASE socis_db TO socis;
postgres=# \q
```

### 6. Setup Environment

```bash
# Create production .env
cat > .env.prod << 'EOF'
ENVIRONMENT=production
DATABASE_URL=postgresql://socis:secure_password@localhost:5432/socis_db
REDIS_URL=redis://localhost:6379/0
OLLAMA_REMOTE_URL=http://<your-ollama-host>:11434

JWT_SECRET=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
JWT_ALGORITHM=HS256
JWT_EXPIRATION=86400

CORS_ORIGINS=https://your-domain.com
ALLOWED_HOSTS=your-domain.com

LOG_LEVEL=info
LOG_FORMAT=json

SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=app-specific-password
EOF
```

### 7. Run Migrations

```bash
source venv/bin/activate
alembic upgrade head
```

### 8. Create Admin User

```bash
python -m app.scripts.init_admin \
  --username admin \
  --password $(python -c 'import secrets; print(secrets.token_urlsafe(16))') \
  --email admin@your-domain.com
```

---

## Systemd Service

### Create Service File

```bash
sudo tee /etc/systemd/system/socis-backend.service > /dev/null << 'EOF'
[Unit]
Description=SOCIS-AI-PT Backend
After=network.target postgresql.service redis-server.service

[Service]
Type=notify
User=socis
WorkingDirectory=/home/socis/SOCIS-AI-PT/backend
Environment=PATH=/home/socis/SOCIS-AI-PT/backend/venv/bin
EnvironmentFile=/home/socis/SOCIS-AI-PT/backend/.env.prod
ExecStart=/home/socis/SOCIS-AI-PT/backend/venv/bin/gunicorn \
  --workers 4 \
  --worker-class uvicorn.workers.UvicornWorker \
  --bind 0.0.0.0:8000 \
  --timeout 120 \
  --error-logfile - \
  --access-logfile - \
  app.main:app

Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
```

### Start Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable socis-backend
sudo systemctl start socis-backend

# Check status
sudo systemctl status socis-backend

# View logs
sudo journalctl -u socis-backend -f
```

---

## Docker Deployment

### Build Docker Image

```bash
# From project root
docker build -f backend/Dockerfile -t socis-backend:latest .

# With build args
docker build \
  -f backend/Dockerfile \
  --build-arg PYTHON_VERSION=3.9 \
  -t socis-backend:latest \
  .
```

### Run Container

```bash
docker run -d \
  -p 8000:8000 \
  -e DATABASE_URL=postgresql://socis:password@postgres:5432/socis_db \
  -e REDIS_URL=redis://redis:6379/0 \
  -e OLLAMA_REMOTE_URL=http://<your-ollama-host>:11434 \
  -e JWT_SECRET=your-secret-key \
  --name socis-backend \
  socis-backend:latest
```

### Docker Compose

```yaml
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: socis_db
      POSTGRES_USER: socis
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U socis"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  backend:
    build:
      context: .
      dockerfile: backend/Dockerfile
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql://socis:secure_password@postgres:5432/socis_db
      REDIS_URL: redis://redis:6379/0
      JWT_SECRET: your-secret-key
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    restart: unless-stopped

volumes:
  postgres_data:
```

---

## Nginx Configuration

### Proxy Configuration

```nginx
upstream backend {
    server backend:8000;
    keepalive 32;
}

server {
    listen 80;
    server_name your-domain.com;

    client_max_body_size 100M;

    # Compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript;
    gzip_min_length 1000;

    # Proxy to backend
    location /api/v1/ {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 120s;
        proxy_read_timeout 120s;
        
        # Buffering
        proxy_buffering off;
    }

    # Health check endpoint
    location /health {
        access_log off;
        proxy_pass http://backend/health;
    }
}
```

### HTTPS with SSL

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # ... rest of config
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

---

## Database Management

### Backup PostgreSQL

```bash
# Single database
pg_dump socis_db > socis_db_backup.sql

# With compression
pg_dump socis_db | gzip > socis_db_backup.sql.gz

# Docker container
docker-compose exec postgres pg_dump \
  -U socis socis_db > backup.sql
```

### Restore Database

```bash
# From SQL dump
psql socis_db < backup.sql

# From compressed dump
gunzip -c backup.sql.gz | psql socis_db

# Docker container
docker-compose exec -T postgres psql \
  -U socis socis_db < backup.sql
```

### Automated Backups

```bash
#!/bin/bash
# /home/socis/backup.sh

BACKUP_DIR="/backups/socis"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Database backup
pg_dump -h localhost -U socis socis_db | \
  gzip > $BACKUP_DIR/db_$TIMESTAMP.sql.gz

# Keep only last 7 days
find $BACKUP_DIR -type f -mtime +7 -delete

echo "Backup completed: $TIMESTAMP"
```

Add to crontab:
```bash
0 3 * * * /home/socis/backup.sh  # 3 AM daily
```

---

## Monitoring

### Health Endpoints

```bash
# API health
curl http://localhost:8000/health

# Database health
curl http://localhost:8000/health/db

# Redis health
curl http://localhost:8000/health/redis

# Ollama health
curl http://localhost:8000/health/ollama
```

### Logs

**Development**:
```bash
# View real-time logs
tail -f app.log
```

**Production with Systemd**:
```bash
# View logs
journalctl -u socis-backend -f

# View specific errors
journalctl -u socis-backend --since "1 hour ago" | grep ERROR
```

**Docker**:
```bash
docker logs -f socis-backend
docker-compose logs -f backend
```

### Metrics

Enable Prometheus metrics (optional):

```python
# app/main.py
from prometheus_client import Counter, Histogram, make_wsgi_app
from fastapi.middleware.wsgi import WSGIMiddleware

app.add_middleware(WSGIMiddleware, app=make_wsgi_app())
```

Access metrics at: http://localhost:8000/metrics

---

## Performance Tuning

### PostgreSQL Optimization

```sql
-- Increase connection pool
ALTER SYSTEM SET max_connections = 200;

-- Optimize shared buffers
ALTER SYSTEM SET shared_buffers = '2GB';

-- Optimize work memory
ALTER SYSTEM SET work_mem = '20MB';

-- Restart PostgreSQL
SELECT pg_reload_conf();
```

### Application Tuning

```python
# app/config.py
class DatabaseConfig:
    POOL_SIZE = 20          # Connection pool size
    MAX_OVERFLOW = 10       # Max overflow connections
    POOL_RECYCLE = 3600     # Recycle connections every hour

class GunicornConfig:
    workers = 4             # CPU cores * 2 + 1
    worker_class = "uvicorn.workers.UvicornWorker"
    worker_connections = 100
    timeout = 120
```

### Caching

```python
# app/services/cache.py
from redis import Redis

redis_client = Redis.from_url(REDIS_URL)

@redis_client.cache(ttl=3600)
async def get_vulnerabilities():
    # Cached for 1 hour
    pass
```

---

## Security Hardening

### API Security

1. **Rate Limiting**:
```python
from slowapi import Limiter

limiter = Limiter(key_func=get_remote_address)

@app.post("/api/v1/auth/login")
@limiter.limit("5/minute")
async def login():
    pass
```

2. **Input Validation**:
```python
from pydantic import BaseModel, validator

class ScanRequest(BaseModel):
    target: str
    
    @validator('target')
    def validate_target(cls, v):
        # Validate IP/domain format
        pass
```

3. **CORS Configuration**:
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-domain.com"],
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_credentials=True,
)
```

### JWT Security

```bash
# Generate strong secret
openssl rand -base64 32

# Rotate regularly
# Update JWT_SECRET and restart service
```

### Database Security

```bash
# Strong password
openssl rand -base64 16

# Limit database user privileges
GRANT SELECT, INSERT, UPDATE, DELETE ON socis_db.* TO socis;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO socis;
```

---

## Troubleshooting

### Port Already in Use

```bash
# Find process using port 8000
lsof -i :8000

# Kill process
kill -9 <PID>

# Or use different port
gunicorn --bind 0.0.0.0:8001 app.main:app
```

### Database Connection Issues

```bash
# Test PostgreSQL connection
psql -h localhost -U socis -d socis_db -c "SELECT 1;"

# Check PostgreSQL status
sudo systemctl status postgresql

# View PostgreSQL logs
sudo tail -f /var/log/postgresql/postgresql.log
```

### Redis Connection Issues

```bash
# Test Redis connection
redis-cli ping

# Check Redis status
sudo systemctl status redis-server

# View Redis logs
sudo tail -f /var/log/redis/redis-server.log
```

### Ollama Connection Issues

```bash
# Test Ollama API
curl http://localhost:11434/api/tags

# Check Ollama status
docker ps | grep ollama

# Check available models
curl http://localhost:11434/api/tags | jq .
```

---

## Deployment Checklist

- [ ] Python 3.9+ installed
- [ ] PostgreSQL 12+ installed and running
- [ ] Redis 6+ installed and running
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] Database created and migrations run
- [ ] Admin user created
- [ ] Environment variables configured
- [ ] Gunicorn/Uvicorn configured
- [ ] Nginx reverse proxy configured
- [ ] SSL/TLS certificates installed (if HTTPS)
- [ ] Systemd service created and enabled
- [ ] Health checks endpoint responding
- [ ] Monitoring configured
- [ ] Backup script created and scheduled
- [ ] Security hardening applied
- [ ] Documentation updated

---

## Support

- **FastAPI Docs**: https://fastapi.tiangolo.com
- **Deployment Docs**: https://fastapi.tiangolo.com/deployment/
- **GitHub Issues**: https://github.com/0x4hm3d/SOCIS-AI-PT/issues
- **Community**: https://github.com/tiangolo/fastapi/discussions
