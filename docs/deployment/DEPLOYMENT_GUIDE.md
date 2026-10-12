# SOCIS-AI-PT Deployment Guide

## Overview

This guide covers deploying SOCIS-AI-PT in various environments:
- **Docker Compose** (Local/Development)
- **Docker Compose** (Production On-Premise)
- **Kubernetes** (Enterprise/Cloud)
- **Manual** (Development Setup)

---

## Prerequisites

### System Requirements

**Minimum**:
- CPU: 4 cores
- RAM: 8 GB
- Storage: 50 GB (includes models)
- OS: Linux (Ubuntu 20.04+), macOS, or Windows with WSL2

**Recommended**:
- CPU: 8+ cores
- RAM: 32 GB
- Storage: 200 GB SSD
- GPU: NVIDIA with CUDA 11.8+ (for LLM inference)

### Software Requirements

- Docker 20.10+
- Docker Compose 2.0+
- Git
- Python 3.9+ (for manual setup)

---

## Quick Start with Docker Compose

### 1. Clone Repository

```bash
git clone https://github.com/0x4hm3d/SOCIS-AI-PT.git
cd SOCIS-AI-PT
```

### 2. Configure Environment

Edit `deploy/docker/docker-compose.yml` or create `.env`:

```bash
# Backend Configuration
BACKEND_PORT=8000
BACKEND_DEBUG=false
DATABASE_URL=postgresql://socis:password@postgres:5432/socis_db
REDIS_URL=redis://redis:6379/0

# Frontend Configuration
FRONTEND_PORT=3000
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1

# LLM Configuration
OLLAMA_REMOTE_URL=http://<your-ollama-host>:11434
OLLAMA_MODEL=socis-pentest

# Security
JWT_SECRET=your-secret-key-here-change-in-production
CORS_ORIGINS=http://localhost:3000

# Logging
LOG_LEVEL=info
```

### 3. Start Services

```bash
cd deploy/docker
docker-compose -f docker-compose.yml up -d
```

### 4. Wait for Services

```bash
# Check service status
docker-compose ps

# View logs
docker-compose logs -f

# Wait for database migration
docker-compose logs backend | grep "Application startup complete"
```

### 5. Access Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000/api/v1
- **API Docs**: http://localhost:8000/docs
- **Admin Panel**: http://localhost:3000/admin

### 6. Initial Setup

```bash
# Create default admin user
docker-compose exec backend python -m app.scripts.init_admin \
  --username admin \
  --password securepassword \
  --email admin@example.com

# Load AI models
docker-compose exec backend python -m app.scripts.setup_models
```

---

## Production Deployment (On-Premise)

### 1. System Preparation

```bash
# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

### 2. Clone & Configure

```bash
# Clone repository
git clone https://github.com/0x4hm3d/SOCIS-AI-PT.git /opt/socis-ai-pt
cd /opt/socis-ai-pt

# Create production environment file
cat > .env.prod << EOF
# Backend Config
BACKEND_PORT=8000
BACKEND_DEBUG=false
ENVIRONMENT=production

# Database
DATABASE_URL=postgresql://socis:$(openssl rand -base64 32)@postgres:5432/socis_db
DATABASE_POOL_SIZE=20

# Redis
REDIS_URL=redis://redis:6379/0

# Frontend
FRONTEND_PORT=3000
NEXT_PUBLIC_API_URL=https://your-domain.com/api/v1

# LLM
OLLAMA_REMOTE_URL=http://<your-ollama-host>:11434

# Security
JWT_SECRET=$(openssl rand -base64 32)
JWT_ALGORITHM=HS256
JWT_EXPIRATION=3600
CORS_ORIGINS=https://your-domain.com

# TLS/SSL
SSL_CERT_PATH=/etc/nginx/ssl/cert.pem
SSL_KEY_PATH=/etc/nginx/ssl/key.pem

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ADMIN_EMAIL=admin@your-domain.com

# Logging
LOG_LEVEL=info
LOG_FORMAT=json
EOF
```

### 3. SSL/TLS Configuration

```bash
# Generate self-signed certificate (or use Let's Encrypt)
cd deploy/nginx/ssl
bash generate_ssl.sh

# Or use Let's Encrypt
sudo apt-get install certbot python3-certbot-nginx -y
sudo certbot certonly --standalone -d your-domain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/your-domain.com/fullchain.pem /opt/socis-ai-pt/deploy/nginx/ssl/cert.pem
sudo cp /etc/letsencrypt/live/your-domain.com/privkey.pem /opt/socis-ai-pt/deploy/nginx/ssl/key.pem
```

### 4. Update Nginx Configuration

Edit `deploy/nginx/nginx.conf`:

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Proxy to backend
    location /api/ {
        proxy_pass http://backend:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Proxy to frontend
    location / {
        proxy_pass http://frontend:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name your-domain.com;
    return 301 https://$server_name$request_uri;
}
```

### 5. Deploy with Compose

```bash
# Use production docker-compose file
docker-compose -f docker-compose.onprem.yml \
  --env-file .env.prod \
  up -d

# Wait for services to be ready
sleep 30

# Run migrations
docker-compose exec backend alembic upgrade head

# Initialize admin user
docker-compose exec backend python -m app.scripts.init_admin \
  --username admin \
  --password $(openssl rand -base64 16) \
  --email admin@your-domain.com

# Load models
docker-compose exec backend python -m app.scripts.setup_models
```

### 6. Backup Strategy

```bash
# Daily database backup
docker-compose exec postgres pg_dump \
  -U socis socis_db > /backup/socis_db_$(date +%Y%m%d).sql

# Or use automated backup
cat > /opt/socis-ai-pt/backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/backup/socis-ai-pt"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup database
docker-compose exec -T postgres pg_dump \
  -U socis socis_db | gzip > $BACKUP_DIR/db_$TIMESTAMP.sql.gz

# Backup config and data
tar -czf $BACKUP_DIR/app_$TIMESTAMP.tar.gz \
  -C /opt socis-ai-pt/

# Keep only last 7 days
find $BACKUP_DIR -type f -mtime +7 -delete

echo "Backup completed: $TIMESTAMP"
EOF

# Schedule with cron (3 AM daily)
(crontab -l; echo "0 3 * * * bash /opt/socis-ai-pt/backup.sh") | crontab -
```

---

## Kubernetes Deployment

### 1. Prerequisites

```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

### 2. Create Namespace and Secrets

```bash
# Create namespace
kubectl create namespace socis-ai-pt

# Create secrets
kubectl -n socis-ai-pt create secret generic socis-secrets \
  --from-literal=database-password=$(openssl rand -base64 32) \
  --from-literal=jwt-secret=$(openssl rand -base64 32) \
  --from-literal=redis-password=$(openssl rand -base64 32)

# Create TLS certificate secret (if using cert-manager)
kubectl -n socis-ai-pt create secret tls socis-tls \
  --cert=path/to/cert.pem \
  --key=path/to/key.pem
```

### 3. Deploy with Helm

```bash
# Add Helm repo (if available)
helm repo add socis-ai-pt https://charts.socis-ai-pt.com

# Install chart
helm install socis-ai-pt socis-ai-pt/socis-ai-pt \
  --namespace socis-ai-pt \
  --values deploy/kubernetes/helm/socis-ai-pt/values.yaml

# Or deploy using kubectl
kubectl apply -f deploy/kubernetes/helm/socis-ai-pt/
```

### 4. Configure Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: socis-ingress
  namespace: socis-ai-pt
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  ingressClassName: nginx
  tls:
  - hosts:
    - your-domain.com
    secretName: socis-tls
  rules:
  - host: your-domain.com
    http:
      paths:
      - path: /api
        pathType: Prefix
        backend:
          service:
            name: socis-backend
            port:
              number: 8000
      - path: /
        pathType: Prefix
        backend:
          service:
            name: socis-frontend
            port:
              number: 3000
```

### 5. Monitor Deployment

```bash
# Check pod status
kubectl -n socis-ai-pt get pods

# View logs
kubectl -n socis-ai-pt logs -f deployment/socis-backend

# Port forward for testing
kubectl -n socis-ai-pt port-forward svc/socis-frontend 3000:3000
kubectl -n socis-ai-pt port-forward svc/socis-backend 8000:8000
```

---

## Health Checks & Monitoring

### Health Endpoints

```bash
# Backend health
curl http://localhost:8000/health

# Database connectivity
curl http://localhost:8000/health/db

# Redis connectivity
curl http://localhost:8000/health/redis

# Ollama connectivity
curl http://localhost:8000/health/ollama
```

### Monitoring Setup

```bash
# View logs
docker-compose logs -f backend
docker-compose logs -f frontend

# Monitor resource usage
docker stats

# Check disk usage
df -h /var/lib/docker/volumes/

# Database monitoring
docker-compose exec postgres psql -U socis -d socis_db -c "SELECT version();"
```

---

## Troubleshooting

### Database Connection Issues

```bash
# Check if PostgreSQL is running
docker-compose ps | grep postgres

# Test connection
docker-compose exec backend psql $DATABASE_URL -c "SELECT 1;"

# Reset database (WARNING: Deletes all data)
docker-compose exec postgres psql -U postgres -c "DROP DATABASE socis_db; CREATE DATABASE socis_db;"
docker-compose exec backend alembic upgrade head
```

### API Not Responding

```bash
# Check backend logs
docker-compose logs backend | tail -50

# Test API health
curl -v http://localhost:8000/health

# Check if port is in use
lsof -i :8000
```

### Frontend Not Loading

```bash
# Check frontend logs
docker-compose logs frontend

# Check if frontend process is running
docker-compose exec frontend ps aux | grep node

# Clear browser cache and reload
# Or try in incognito mode
```

### Ollama Model Issues

```bash
# Check if Ollama is running
docker-compose ps | grep ollama

# List available models
curl http://localhost:11434/api/tags

# Create custom SOCIS model
docker-compose exec ollama ollama create socis-pentest -f /modelfiles/socis-pentest.Modelfile
```

---

## Backup & Recovery

### Automated Backups

```bash
# Set up backup script
bash deploy/scripts/setup-backup.sh

# Manual backup
bash deploy/scripts/backup.sh

# Restore from backup
bash deploy/scripts/restore.sh backup_date_here
```

### Database Restoration

```bash
# Restore from SQL dump
cat /backup/socis_db_20260414.sql | \
  docker-compose exec -T postgres psql -U socis socis_db

# Run migrations after restore
docker-compose exec backend alembic upgrade head
```

---

## Scaling

### Horizontal Scaling

```bash
# Scale backend replicas
docker-compose up -d --scale backend=3

# Or with Kubernetes
kubectl -n socis-ai-pt scale deployment socis-backend --replicas=3
```

### Performance Tuning

```bash
# Increase database pool size
DATABASE_POOL_SIZE=30

# Increase Redis cache
REDIS_MAXMEMORY=2gb

# Tune frontend caching
FRONTEND_CACHE_TTL=3600
```

---

## Security Hardening

### Firewall Rules

```bash
# Allow SSH only from specific IPs
sudo ufw allow from 192.168.1.0/24 to any port 22

# Allow HTTPS
sudo ufw allow 443/tcp

# Block HTTP (redirect to HTTPS)
sudo ufw allow 80/tcp

# Enable firewall
sudo ufw enable
```

### API Key Management

```bash
# Generate strong JWT secret
openssl rand -base64 32 > jwt_secret.txt

# Rotate keys regularly
# Update JWT_SECRET and restart services
docker-compose restart backend
```

### Regular Updates

```bash
# Update base images
docker pull ubuntu:20.04
docker pull postgres:15
docker pull redis:7

# Rebuild applications
docker-compose build --no-cache

# Apply security patches
sudo apt-get update && sudo apt-get upgrade -y
```

---

## Performance Optimization

### Database Optimization

```sql
-- Create indexes
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_cve_id ON vulnerabilities(cve_id);

-- Analyze query plans
EXPLAIN ANALYZE SELECT * FROM scans WHERE status = 'completed';

-- Vacuum regularly
VACUUM ANALYZE;
```

### Frontend Optimization

```bash
# Enable compression
COMPRESSION=gzip

# Cache static assets
CACHE_STATIC=31536000  # 1 year

# Use CDN for images
CDN_URL=https://cdn.your-domain.com
```

---

## Support & Resources

- **Documentation**: https://docs.socis-ai-pt.com
- **GitHub Issues**: https://github.com/0x4hm3d/SOCIS-AI-PT/issues
- **Community Forum**: https://forum.socis-ai-pt.com
- **Email Support**: support@socis-ai-pt.com
