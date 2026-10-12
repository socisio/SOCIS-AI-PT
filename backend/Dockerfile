FROM python:3.12-slim AS base

LABEL maintainer="SOCIS" \
      description="SOCIS-AI-PT Backend — AI-Powered Penetration Testing Platform"

# ─── System Tools ─────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Basic utilities
    curl \
    wget \
    # Build tools
    gcc \
    libpq-dev \
    # PDF generation (WeasyPrint)
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    shared-mime-info \
    # Git for MCP servers
    git \
    && rm -rf /var/lib/apt/lists/*

# ─── Python App ───────────────────────────────────────────────
WORKDIR /app

COPY requirements.txt .
# --retries/--timeout make the install resilient to transient network drops
# (BrokenPipe mid-download), which are common when pulling many/large wheels.
# Dropped the unnecessary `pip install --upgrade pip` self-upgrade step (it was
# the step that failed on a flaky connection and isn't needed for the install).
RUN pip install --no-cache-dir --retries 5 --timeout 120 -r requirements.txt

COPY . .

# ─── Create directories ───────────────────────────────────────
RUN mkdir -p /app/reports /app/uploads /app/logs /projects

# ─── Non-root user ───────────────────────────────────────────
# APP_UID (build arg): prod passes a FIXED uid (10001) so the installer can chown
# the host bind-mount directories (/projects, reports, plugins, logs) to match.
# Left empty (dev), the uid is allocated dynamically exactly as before, so
# existing dev named volumes keep working.
ARG APP_UID=
RUN if [ -n "$APP_UID" ]; then \
        groupadd -r -g "$APP_UID" socis && useradd -r -u "$APP_UID" -g socis socis; \
    else \
        groupadd -r socis && useradd -r -g socis socis; \
    fi && \
    chown -R socis:socis /app /projects
USER socis

# Liveness: backend exposes /health (app/main.py). curl is installed above.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

# UVICORN_WORKERS is injected at runtime via the compose environment block.
# Defaults to 1 (safe for development/single-host); override in compose for production.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers ${UVICORN_WORKERS:-1} --loop uvloop --http httptools"]
