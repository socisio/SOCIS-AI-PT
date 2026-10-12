# Frontend Deployment Guide

## Overview

This guide covers deploying the SOCIS-AI-PT frontend (Next.js 15 application) to various environments.

---

## Frontend Stack

- **Framework**: Next.js 15.0.3
- **Runtime**: Node.js 20
- **Package Manager**: npm
- **Build Tool**: Next.js built-in builder
- **Styling**: Tailwind CSS 3.4.15 + Custom CSS
- **HTTP Client**: Axios 1.15.0
- **Icons**: Lucide React 1.8.0

---

## Prerequisites

### System Requirements

- **Node.js**: 18.17.0 or higher
- **npm**: 9.0.0 or higher
- **Memory**: 2GB minimum
- **Storage**: 500MB for dependencies

### Environment Variables

**Required**:
```
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
```

**Optional**:
```
NEXT_PUBLIC_ANALYTICS_ID=          # For analytics
NEXT_PUBLIC_SENTRY_DSN=             # For error tracking
APP_ENV=production|development|staging
```

---

## Local Development

### 1. Install Dependencies

```bash
cd frontend
npm install
```

### 2. Configure Environment

Create `.env.local`:

```bash
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
```

### 3. Start Development Server

```bash
npm run dev
```

Visit http://localhost:3000

### 4. Available Scripts

```bash
npm run dev      # Development server with hot reload
npm run build    # Production build
npm run start    # Production server
npm run lint     # Run ESLint
npm run lint:fix # Fix linting issues
npm run type-check  # TypeScript check
```

---

## Production Build

### 1. Build Application

```bash
npm run build
```

This creates:
- `.next/` - Compiled application
- `public/` - Static assets
- `.next/standalone` - Self-contained bundle

### 2. Verify Build

```bash
npm run build
npm run start

# Visit http://localhost:3000
```

### 3. Build Artifacts

The build produces:
- **JavaScript bundles** (~500KB gzipped)
- **CSS files** (~50KB gzipped)
- **Optimized images** (WebP, AVIF)
- **Source maps** (for debugging in staging)

---

## Docker Deployment

### Build Docker Image

```bash
# From project root
docker build -f frontend/Dockerfile -t socis-frontend:latest .

# Or with build args
docker build \
  -f frontend/Dockerfile \
  --build-arg NEXT_PUBLIC_API_URL=https://api.example.com/api/v1 \
  -t socis-frontend:latest \
  .
```

### Run Container

```bash
docker run -d \
  -p 3000:3000 \
  -e NEXT_PUBLIC_API_URL=http://backend:8000/api/v1 \
  --name socis-frontend \
  socis-frontend:latest
```

### Docker Compose

```yaml
services:
  frontend:
    build:
      context: .
      dockerfile: frontend/Dockerfile
      args:
        NEXT_PUBLIC_API_URL: http://backend:8000/api/v1
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_API_URL=http://backend:8000/api/v1
    depends_on:
      - backend
    restart: unless-stopped
```

---

## Nginx Configuration

### Behind Nginx Reverse Proxy

```nginx
upstream frontend {
    server frontend:3000;
}

server {
    listen 80;
    server_name _;

    client_max_body_size 100M;

    # Gzip compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    gzip_vary on;
    gzip_comp_level 6;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Cache static assets
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Proxy to Next.js
    location / {
        proxy_pass http://frontend;
        proxy_http_version 1.1;
        
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $server_name;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
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

## Environment Configuration

### API Endpoint Configuration

The API URL can be set via:

1. **Build-time** (in Dockerfile):
```dockerfile
ARG NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
```

2. **Runtime** (in container):
```bash
docker run \
  -e NEXT_PUBLIC_API_URL=https://api.example.com/api/v1 \
  socis-frontend:latest
```

3. **Nginx rewrite** (for dynamic endpoints):
```javascript
// frontend/src/lib/api.ts
const API_URL = process.env.NEXT_PUBLIC_API_URL || '/api/v1';
```

---

## Performance Optimization

### Build Optimization

```bash
# Analyze bundle size
npm run build
npx next-bundle-analyzer

# Check for unused imports
npm run lint -- --fix
```

### Runtime Optimization

**In `next.config.ts`**:

```typescript
const config: NextConfig = {
  // Compress
  compress: true,

  // Image optimization
  images: {
    formats: ['image/avif', 'image/webp'],
  },

  // Minification
  swcMinify: true,

  // Output
  output: 'standalone',
};
```

### Caching Strategy

```nginx
# Cache static files 1 year
location ~* \.(js|css)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
}

# Cache HTML (don't cache - always get latest)
location ~* \.html$ {
    add_header Cache-Control "public, max-age=0, must-revalidate";
}
```

---

## Monitoring

### Health Checks

**Container health check**:
```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1
```

**Custom health endpoint**:
```typescript
// frontend/src/pages/api/health.ts
export default function handler(req, res) {
  res.status(200).json({ status: 'healthy' });
}
```

### Logging

**Docker logs**:
```bash
docker logs -f socis-frontend
```

**Nginx logs**:
```bash
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log
```

### Error Tracking

Set up Sentry for production:

```bash
# Install Sentry
npm install --save @sentry/nextjs

# Configure in .env.production
NEXT_PUBLIC_SENTRY_DSN=https://your-sentry-dsn@sentry.io/project-id
```

---

## Deployment Scenarios

### Scenario 1: Local Development

```bash
npm install
npm run dev
# Open http://localhost:3000
```

### Scenario 2: Docker on Single Server

```bash
docker run -d \
  -p 3000:3000 \
  -e NEXT_PUBLIC_API_URL=http://api.example.com/api/v1 \
  socis-frontend:latest
```

### Scenario 3: Docker Compose (Dev/Staging)

```bash
cd deploy/docker
docker-compose up -d
# Frontend at http://localhost:3000
```

### Scenario 4: Kubernetes Deployment

```bash
kubectl apply -f deploy/kubernetes/
kubectl port-forward svc/socis-frontend 3000:3000
```

### Scenario 5: Vercel/Netlify Platform

1. Connect GitHub repository
2. Set environment variables:
   ```
   NEXT_PUBLIC_API_URL=https://api.example.com/api/v1
   ```
3. Deploy (automatically triggered on push)

---

## Troubleshooting

### Build Fails

```bash
# Clear cache
rm -rf .next node_modules
npm install
npm run build

# Check for errors
npm run lint
npm run type-check
```

### Container Won't Start

```bash
# Check logs
docker logs socis-frontend

# Test locally
npm run build
npm run start

# Check environment variables
docker run -e NEXT_PUBLIC_API_URL=... socis-frontend:latest
```

### Page Not Loading

1. **Check API connectivity**:
   ```bash
   curl http://localhost:8000/api/v1/health
   ```

2. **Browser console errors**:
   - Open DevTools (F12)
   - Check Console tab for errors
   - Check Network tab for failed requests

3. **Check API URL**:
   ```javascript
   // In browser console
   console.log(process.env.NEXT_PUBLIC_API_URL)
   ```

### Slow Performance

```bash
# Check bundle size
npm run build
npx next-bundle-analyzer

# Identify slow pages
npm run build --profile

# Check metrics in Lighthouse
```

---

## Security Best Practices

1. **Keep dependencies updated**:
   ```bash
   npm update
   npm audit
   ```

2. **Use HTTPS in production**:
   - Configure SSL certificate
   - Redirect HTTP to HTTPS

3. **Set security headers**:
   ```
   Content-Security-Policy: default-src 'self'
   X-Frame-Options: DENY
   X-Content-Type-Options: nosniff
   ```

4. **Protect sensitive data**:
   - Never commit secrets
   - Use environment variables
   - Rotate tokens regularly

5. **Monitor logs**:
   - Review access logs for suspicious activity
   - Monitor error rates
   - Set up alerts for anomalies

---

## Deployment Checklist

- [ ] Dependencies installed and locked
- [ ] Environment variables configured
- [ ] Build completes without errors
- [ ] Linting passes (`npm run lint`)
- [ ] TypeScript checks pass
- [ ] Health checks endpoint responds
- [ ] API connectivity verified
- [ ] SSL/TLS certificates installed (if HTTPS)
- [ ] Nginx/reverse proxy configured
- [ ] Monitoring and logging enabled
- [ ] Backup/recovery plan documented
- [ ] Security headers configured
- [ ] Performance optimizations applied
- [ ] Documentation updated

---

## Support

- **Next.js Docs**: https://nextjs.org
- **Deployment Docs**: https://nextjs.org/docs/deployment/static-exports
- **GitHub Issues**: https://github.com/0x4hm3d/SOCIS-AI-PT/issues
- **Community**: https://github.com/vercel/next.js/discussions
