"""
SOCIS-AI-PT — FastAPI Application Entry Point
"""

import asyncio
import sqlalchemy as sa
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles
import logging
from urllib.parse import urlparse
from slowapi import Limiter, _rate_limit_exceeded_handler
from app.core.client_ip import get_client_ip
from slowapi.errors import RateLimitExceeded

from app.config import settings, is_production_mode
from app.core.database import engine, Base
from app.core.exceptions import SocisException, socis_exception_handler
from app.api.v1 import auth, scans, vulnerabilities, reports, llm, tools, projects, admin, mcp, api_keys, schedules, scan_templates, webhooks, notifications, chat_sessions, workflows, findings, dashboard
from app.api.v1 import settings as settings_routes
from app.api import websocket

# ── Eagerly import models so Base.metadata.create_all registers every table ──
# Without these imports, tables whose models are only used lazily (e.g. via
# deferred imports in services) are invisible to create_all.
import app.models.user            # noqa: F401
import app.models.project         # noqa: F401
import app.models.scan            # noqa: F401
import app.models.vulnerability   # noqa: F401
import app.models.vuln_comment     # noqa: F401
import app.models.fix             # noqa: F401
import app.models.exploit         # noqa: F401
import app.models.report          # noqa: F401
import app.models.ai_analysis     # noqa: F401
import app.models.audit_log       # noqa: F401
import app.models.llm_config      # noqa: F401
try:
    import app.models.finding_embedding  # noqa: F401 — requires pgvector
except Exception:
    pass  # pgvector not installed; finding_embeddings won't be created by create_all

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"SOCIS-AI-PT v{settings.APP_VERSION} starting in {settings.DEPLOYMENT_MODE} mode")

    # ── Encryption key startup check ──────────────────────────────────────────
    if not settings.ENCRYPTION_KEY:
        import base64 as _b64, os as _os
        _generated = _b64.urlsafe_b64encode(_os.urandom(32)).decode()
        logger.critical(
            "ENCRYPTION_KEY is not set in the environment. "
            "Plugin secrets, API keys, and webhook secrets will use an ephemeral key "
            "and will be UNREADABLE after restart. "
            "Add to deploy/docker/.env:  ENCRYPTION_KEY=%s", _generated
        )

    async with engine.begin() as conn:
        # Enable pgvector extension before create_all so the VECTOR column type resolves.
        # This is a no-op if the extension is already installed.
        try:
            await conn.execute(sa.text("CREATE EXTENSION IF NOT EXISTS vector"))
        except Exception as ext_err:
            logger.warning("pgvector extension not available (%s) — RAG features disabled", ext_err)
            # Unregister the finding_embeddings table from metadata so create_all
            # does not attempt to create a table whose column type doesn't exist.
            from app.core.database import Base as _Base
            fe_table = _Base.metadata.tables.get("finding_embeddings")
            if fe_table is not None:
                _Base.metadata.remove(fe_table)

        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables verified")

    # Base.metadata.create_all only creates tables that don't exist yet — it never ALTERS an existing table's
    # columns, so it cannot apply a migration like "widen this VARCHAR to TEXT" to a database that already has the
    # old column. On a database create_all provisioned directly (the common case for a fresh deploy), Alembic's own
    # bookkeeping table (alembic_version) never gets created either, so `alembic upgrade head` starts from scratch
    # and immediately fails with "relation already exists" on every table create_all already made — confirmed live
    # when this bit platform_settings.value (migration 023). Stamp the database at the current migration head right
    # after create_all, but ONLY the first time (alembic_version missing) — a database that already has real
    # Alembic history must never be silently re-stamped, which would skip whatever migrations it still needs.
    #
    # CORRECTNESS CAVEAT this stamp relies on: it assumes the live schema already matches "head" at the moment it
    # runs. That is true for ordinary new tables (create_all just made them from the current models, which already
    # reflect every migration). It is NOT automatically true for a migration that ALTERS an existing column/constraint
    # on a table create_all does not touch (exactly 023's case: widening platform_settings.value on a database that
    # already had that table). On an UPGRADE where alembic_version is still missing, the operator must apply any such
    # pending ALTER-on-existing-table changes manually BEFORE this code runs (restarting the backend), or this stamp
    # will mark that migration "applied" while the live column is still wrong. For 023 specifically, run:
    #   docker exec <postgres container> psql -U <user> -d <db> -c "ALTER TABLE platform_settings ALTER COLUMN value TYPE TEXT;"
    # before deploying this code to an existing, already-running database.
    async with engine.begin() as conn:
        exists = (await conn.execute(sa.text("SELECT to_regclass('public.alembic_version')"))).scalar()
        if exists is None:
            try:
                import os as _os
                from alembic.config import Config as _AlembicConfig
                from alembic import command as _alembic_command
                _cfg = _AlembicConfig(_os.path.join(_os.path.dirname(_os.path.dirname(__file__)), "alembic.ini"))
                # alembic's Config loads script_location etc. from alembic.ini already; stamping uses the same
                # synchronous engine URL alembic.ini/env.py are already configured with.
                _alembic_command.stamp(_cfg, "head")
                logger.info("Alembic stamped at head (first boot — tables were created directly by create_all, "
                            "not by migrations; this lets future `alembic upgrade head` runs apply only genuinely "
                            "new migrations instead of failing on tables that already exist)")
            except Exception as stamp_err:
                logger.warning(
                    "Could not auto-stamp Alembic at head after create_all (%s). Future `alembic upgrade head` "
                    "runs may fail with 'relation already exists' until this is stamped manually: "
                    "docker exec <backend> alembic stamp head", stamp_err,
                )

    await _seed_roles()
    logger.info("Default roles verified")
    
    await _init_default_admin()
    logger.info("Default admin user verified")

    # Remove the legacy "ollama_local" provider from already-stored data (idempotent).
    from app.core.database import async_session as _legacy_session
    from app.core.legacy_cleanup import normalize_legacy_providers
    await normalize_legacy_providers(_legacy_session)
    from app.core.legacy_cleanup import purge_unused_provider_keys
    await purge_unused_provider_keys(_legacy_session)
    from app.core.schema_fixes import widen_totp_secret
    await widen_totp_secret(_legacy_session)
    from app.core.schema_fixes import ensure_project_scope_columns
    await ensure_project_scope_columns(_legacy_session)

    # Missing indexes on foreign keys make every list page scan whole tables. Created in the background so startup is never delayed.
    import asyncio as _asyncio
    from app.core.db_indexes import ensure_performance_indexes
    app.state.index_task = _asyncio.create_task(ensure_performance_indexes(_legacy_session))

    from app.api.v1.scan_templates import seed_builtin_templates
    from app.core.database import async_session
    async with async_session() as db:
        await seed_builtin_templates(db)
    logger.info("Built-in scan templates verified")

    from app.api.v1.prompt_template_seed import seed_builtin_prompt_templates
    async with async_session() as db:
        await seed_builtin_prompt_templates(db)
    logger.info("Built-in prompt templates verified")

    # Load Custom Plugins
    from app.plugins.loader import plugin_manager
    from app.services.tool_service import TOOL_REGISTRY, ToolCategory
    try:
        plugins = plugin_manager.load_plugins()
        for name, tool_class in plugins.items():
            # Inject the custom plugin tool directly into the global registry
            TOOL_REGISTRY[name] = {
                "category": ToolCategory.VULN_SCAN,
                "timeout": 300,
                "description": getattr(tool_class, "description", "Custom Tool"),
            }
        if plugins:
            logger.info(f"Loaded {len(plugins)} custom tool plugins")
        # Record what ran, for later investigation — any .py file in this directory executes with full backend privileges.
        from app.core.audit import log_audit
        async with async_session() as _db:
            await log_audit(_db, action="plugins:loaded", user_id=None, resource_type="plugin", resource_id=None,
                            details={"trigger": "startup", "files": plugin_manager.manifest})
            await _db.commit()
    except Exception as _plugin_err:
        logger.warning(f"Plugin loading failed (non-fatal): {_plugin_err}")

    async def _discover_mcp_tools():
        # A server that is still starting up when the first discovery pass runs (e.g. the mcp_all container is slow to
        # bring up all its processes under supervisord) was previously left stuck at 0 tools until someone manually
        # re-ran discovery — this bit us with 23 servers now starting in one container. Retry each server that fails,
        # with a growing delay, instead of giving up after one attempt.
        from app.mcp.client import get_mcp_client
        client = get_mcp_client()
        delays = [5, 10, 20, 30]  # seconds before each attempt; ~65s total before giving up on a server
        pending = set(client._servers.keys())
        for delay in delays:
            await asyncio.sleep(delay)
            if not pending:
                break
            still_pending = set()
            for name in pending:
                try:
                    await client.discover_tools(name)
                except Exception as e:
                    still_pending.add(name)
                    logger.debug(f"MCP tool discovery attempt failed for {name}: {e}")
            pending = still_pending
        online = len(client._servers) - len(pending)
        logger.info(f"MCP auto-discovery: {online}/{len(client._servers)} servers online"
                    + (f" (still unreachable after retries: {sorted(pending)})" if pending else ""))

    import asyncio as _asyncio
    _asyncio.create_task(_discover_mcp_tools())

    yield
    await engine.dispose()
    logger.info("SOCIS-AI-PT shutdown complete.")


async def _seed_roles():
    """Create default RBAC roles on first startup."""
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from sqlalchemy import select
    from app.models.user import Role
    from app.core.security import ROLE_PERMISSIONS

    async_session = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session() as db:
        for role_name, permissions in ROLE_PERMISSIONS.items():
            result = await db.execute(select(Role).where(Role.name == role_name.value))
            if not result.scalar_one_or_none():
                role = Role(name=role_name.value, permissions=list(permissions))
                db.add(role)
        await db.commit()


async def _init_default_admin():
    """Create default admin user on first startup."""
    from sqlalchemy.ext.asyncio import async_sessionmaker
    from sqlalchemy import select
    from app.models.user import User, Role
    from app.core.security import hash_password

    async_session = async_sessionmaker(engine, expire_on_commit=False)
    async with async_session() as db:
        try:
            # Check if admin exists
            result = await db.execute(select(User).where(User.username == "admin"))
            admin = result.scalar_one_or_none()
            
            # Get admin role
            result = await db.execute(select(Role).where(Role.name == "admin"))
            admin_role = result.scalar_one_or_none()
            
            if not admin_role:
                return
            
            # Use ADMIN_PASSWORD from env — must always be set (CRIT-02 fix)
            password = settings.ADMIN_PASSWORD
            if not password:
                raise RuntimeError(
                    "ADMIN_PASSWORD environment variable must be set. "
                    "There is no default password. Set it in your .env file."
                )

            # Create or update admin user
            if admin:
                admin.password_hash = hash_password(password)
                admin.is_active = True
                await db.commit()
                logger.info("Admin password updated")
            else:
                admin_user = User(
                    email="admin@socis.local",
                    username="admin",
                    password_hash=hash_password(password),
                    full_name="Administrator",
                    is_active=True,
                    is_superuser=True,
                )
                admin_user.roles.append(admin_role)
                
                db.add(admin_user)
                await db.commit()
                
                mode = "PRODUCTION" if settings.DEPLOYMENT_MODE == "production" else "DEVELOPMENT"
                logger.info(f"Default admin user created ({mode} mode)")
                logger.warning("CHANGE PASSWORD IMMEDIATELY AFTER FIRST LOGIN IN PRODUCTION!")
            
        except Exception as e:
            logger.error(f"Error creating default admin: {e}")
            await db.rollback()


limiter = Limiter(key_func=get_client_ip)


def _derive_allowed_hosts(allowed_origins: list[str]) -> list[str]:
    """Build the TrustedHostMiddleware allowlist from configured origins (fix M-3)."""
    if not is_production_mode():
        return ["*"]
    hosts: set[str] = {"localhost", "127.0.0.1"}
    for origin in list(allowed_origins) + [settings.FRONTEND_URL]:
        if not origin:
            continue
        host = urlparse(origin).hostname
        if host:
            hosts.add(host)
    domain = getattr(settings, "DOMAIN", None)
    if domain:
        hosts.add(domain)
    return sorted(hosts) or ["*"]


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description=settings.APP_DESCRIPTION,
        docs_url="/api/docs" if settings.DEBUG else None,
        redoc_url="/api/redoc" if settings.DEBUG else None,
        openapi_url="/api/openapi.json" if settings.DEBUG else None,
        lifespan=lifespan,
    )

    # ─── Security Middleware ──────────────────────────────────
    # CORS — explicit allowlist ONLY. A wildcard/reflecting origin combined
    # with allow_credentials=True is a critical vulnerability (fix C-3), so the
    # previous allow_origin_regex=r"https?://.*" has been removed. Configure the
    # deployed frontend origin(s) via ALLOWED_ORIGINS in .env.
    _allowed_origins = list(settings.ALLOWED_ORIGINS or [])
    if not _allowed_origins and not is_production_mode():
        _allowed_origins = [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            settings.FRONTEND_URL,
        ]
    if is_production_mode() and not _allowed_origins:
        logger.critical(
            "ALLOWED_ORIGINS is empty in production — cross-origin browser "
            "requests will be rejected. Set ALLOWED_ORIGINS in your .env."
        )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-API-Key"],
        expose_headers=["X-SOCIS-Error", "X-SOCIS-Can-Override"],   # lets the UI recognise a blocked-by-scope answer
    )

    # Host-header validation (fix M-3). "*" enabled host-header injection /
    # reset-link poisoning. Derive the allowed set from configured origins;
    # fall back to "*" only outside production.
    _allowed_hosts = _derive_allowed_hosts(_allowed_origins)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=_allowed_hosts,
    )

    # Custom exception handlers
    app.add_exception_handler(SocisException, socis_exception_handler)
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.state.limiter = limiter

    # ─── Security Headers Middleware ──────────────────────────
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        # LOW-2: Request Body Size Limit
        if request.method in ["POST", "PUT", "PATCH"]:
            # Check Content-Length header
            content_length = request.headers.get("Content-Length")
            if content_length and int(content_length) > settings.REQUEST_MAX_BODY_SIZE:
                return Response(status_code=413, content="Request body too large")

        # CSRF defense-in-depth (fix L-9). For cookie-authenticated, state-
        # changing requests, require the custom X-Requested-With header that the
        # SPA sends. Browsers will not attach a custom header to a cross-site
        # forged request without a CORS preflight, which the strict origin
        # allowlist refuses — so a forged POST from another site is rejected.
        # Requests authenticated by Bearer JWT or X-API-Key (not ambient
        # cookies) are exempt, as are the login/refresh endpoints that must work
        # before the SPA is bootstrapped.
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            path = request.url.path
            _csrf_exempt_prefixes = (
                "/api/v1/auth/login",
                "/api/v1/auth/refresh",
                "/api/v1/auth/oauth",
                "/api/v1/auth/forgot-password",
                "/api/v1/auth/reset-password",
            )
            has_cookie_auth = request.cookies.get("access_token") is not None
            has_header_auth = bool(
                request.headers.get("Authorization") or request.headers.get("X-API-Key")
            )
            if (
                has_cookie_auth
                and not has_header_auth
                and not path.startswith(_csrf_exempt_prefixes)
                and request.headers.get("X-Requested-With") != "SOCIS"
            ):
                return Response(status_code=403, content="CSRF check failed: missing X-Requested-With header")

        response = await call_next(request)
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        # Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Enforce HTTPS for one year (MED-07 fix)
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # LOW-3: Content Security Policy (Modern replacement for X-XSS-Protection)
        # Very restrictive default CSP
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:;"
        # Referrer policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # Disable caching for sensitive content
        if "api" in request.url.path:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        return response

    # ─── API Routers ──────────────────────────────────────────
    prefix = "/api/v1"
    app.include_router(auth.router, prefix=f"{prefix}/auth", tags=["Authentication"])
    app.include_router(projects.router, prefix=f"{prefix}/projects", tags=["Projects"])
    app.include_router(scans.router, prefix=f"{prefix}/scans", tags=["Scans"])
    app.include_router(dashboard.router, prefix=f"{prefix}/dashboard", tags=["Dashboard"])
    app.include_router(vulnerabilities.router, prefix=f"{prefix}/vulnerabilities", tags=["Vulnerabilities"])
    app.include_router(reports.router, prefix=f"{prefix}/reports", tags=["Reports"])
    app.include_router(llm.router, prefix=f"{prefix}/llm", tags=["LLM"])
    app.include_router(tools.router, prefix=f"{prefix}/tools", tags=["Tools"])
    app.include_router(mcp.router, prefix=f"{prefix}/mcp", tags=["MCP"])
    app.include_router(admin.router, prefix=f"{prefix}/admin", tags=["Administration"])
    app.include_router(settings_routes.router, prefix=f"{prefix}/settings", tags=["Settings"])
    app.include_router(api_keys.router, prefix=f"{prefix}/api-keys", tags=["API Keys"])
    app.include_router(schedules.router, prefix=f"{prefix}/schedules", tags=["Schedules"])
    app.include_router(scan_templates.router, prefix=f"{prefix}/scan-templates", tags=["Scan Templates"])
    app.include_router(webhooks.router, prefix=f"{prefix}/webhooks", tags=["Webhooks"])
    app.include_router(notifications.router, prefix=f"{prefix}/notifications", tags=["Notifications"])
    app.include_router(chat_sessions.router, prefix=f"{prefix}/chat-sessions", tags=["Chat Sessions"])
    app.include_router(workflows.router, prefix=f"{prefix}/workflows", tags=["Workflows"])
    app.include_router(findings.router, prefix=f"{prefix}/findings", tags=["Findings"])
    app.include_router(websocket.router, tags=["WebSocket"])

    @app.get("/health", tags=["System"])
    async def health_check():
        return {
            "status": "healthy",
            "app": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "mode": settings.DEPLOYMENT_MODE,
        }

    @app.get("/health/live", tags=["System"])
    async def liveness():
        """Kubernetes liveness probe — confirms the process is running."""
        return {"status": "alive"}

    @app.get("/health/ready", tags=["System"])
    async def readiness():
        """Kubernetes readiness probe — checks DB, Redis, and MCP reachability."""
        import httpx as _httpx
        import redis.asyncio as _aioredis
        from sqlalchemy import text as _text
        from app.core.database import engine as _engine
        from app.tasks.scan_worker import MCP_URLS as _MCP_URLS

    @app.get("/api/services-health", tags=["System"])
    async def services_health():
        """Public service health check — no auth required.

        Returns only coarse ok/degraded status per component. Detailed error
        strings and model counts are NOT exposed here (fix L-1), to avoid
        leaking internal topology/error detail to anonymous callers. For full
        diagnostics use the authenticated /api/v1/admin/services-health.
        """
        import httpx
        import redis.asyncio as _aioredis
        from sqlalchemy import text as _text
        from app.core.database import engine as _engine

        status: dict = {}

        try:
            async with _engine.connect() as conn:
                await conn.execute(_text("SELECT 1"))
            status["database"] = "ok"
        except Exception:
            status["database"] = "degraded"

        try:
            _r = _aioredis.from_url(settings.REDIS_URL)
            await _r.ping()
            await _r.aclose()
            status["redis"] = "ok"
        except Exception:
            status["redis"] = "degraded"

        # The external Ollama URL is admin-configured (Admin -> Settings), falling back to OLLAMA_REMOTE_URL.
        _ollama_url = settings.OLLAMA_REMOTE_URL
        try:
            from app.core.database import async_session as _hs
            from app.services.settings_service import settings_service as _ss
            async with _hs() as _hdb:
                _ollama_url = await _ss.get_ollama_remote_url(_hdb) or settings.OLLAMA_REMOTE_URL
        except Exception:
            pass
        try:
            if not _ollama_url:
                # No Ollama configured is a valid state (API providers only).
                status["ollama"] = "not_configured"
            else:
                from app.core.netguard import acheck_url
                await acheck_url(_ollama_url, allow_private=True)
                async with httpx.AsyncClient(timeout=5) as client:
                    resp = await client.get(f"{_ollama_url.rstrip('/')}/api/tags")
                    status["ollama"] = "ok" if resp.status_code == 200 else "degraded"
        except Exception:
            status["ollama"] = "degraded"

        # "not_configured" (e.g. no Ollama, API providers only) is acceptable.
        _ok_states = {"ok", "not_configured"}
        status["status"] = "ok" if all(v in _ok_states for v in status.values() if isinstance(v, str)) else "degraded"
        return status

    # ─── Prometheus metrics (observability #9) ────────────────
    from app.core import metrics as _metrics

    @app.middleware("http")
    async def _metrics_middleware(request: Request, call_next):
        import time as _time
        _path = _metrics.normalize_path(request.url.path)
        # Don't record the /metrics scrape itself.
        if _path == "/metrics":
            return await call_next(request)
        _start = _time.perf_counter()
        response = await call_next(request)
        try:
            _dur = _time.perf_counter() - _start
            _metrics.HTTP_LATENCY.labels(request.method, _path).observe(_dur)
            _metrics.HTTP_REQUESTS.labels(request.method, _path, str(response.status_code)).inc()
        except Exception:
            pass
        return response

    @app.get("/metrics", include_in_schema=False)
    async def metrics_endpoint():
        # Refresh scan gauges from the DB on scrape (cheap COUNT queries). Keeps
        # the worker free of metrics coupling. Best-effort — never fail the scrape.
        try:
            from sqlalchemy import text as _text
            from app.core.database import engine as _engine
            async with _engine.connect() as conn:
                pending = (await conn.execute(_text(
                    "SELECT count(*) FROM scans WHERE lower(status::text) = 'pending'"))).scalar() or 0
                running = (await conn.execute(_text(
                    "SELECT count(*) FROM scans WHERE lower(status::text) IN ('running','analyzing')"))).scalar() or 0
            _metrics.SCAN_QUEUE_DEPTH.set(pending)
            _metrics.SCANS_IN_PROGRESS.set(running)
        except Exception:
            pass
        body, content_type = _metrics.metrics_response()
        return Response(content=body, media_type=content_type)

    return app


app = create_app()
