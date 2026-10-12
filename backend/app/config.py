"""
SOCIS-AI-PT — Configuration
Centralized settings via pydantic-settings with .env support.
"""

from typing import Optional, List
from pathlib import Path
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator
import os
import warnings

# Resolve the project-root .env regardless of where uvicorn/pytest is invoked from.
# config.py lives at:  <project_root>/backend/app/config.py
# .env lives at:       <project_root>/.env
_PROJECT_ROOT_ENV = Path(__file__).resolve().parent.parent.parent / ".env"

# Deployment modes that must be treated as production. The compose files and
# install-prod.sh set "production", while some validators historically checked
# "saas"/"onprem" — unify them so the hardening guards fire consistently.
PRODUCTION_MODES = frozenset({"production", "saas", "onprem"})


def is_production_mode() -> bool:
    """True when DEPLOYMENT_MODE denotes a production deployment.

    Read from the environment so it is independent of Settings field
    declaration order and usable at module import time (e.g. by main.py).
    """
    return os.getenv("DEPLOYMENT_MODE", "").strip().lower() in PRODUCTION_MODES


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    # ─── Application ──────────────────────────────────────────
    APP_NAME: str = "SOCIS-AI-PT"
    APP_VERSION: str = "1.0.0"
    APP_DESCRIPTION: str = "AI-Powered Penetration Testing Platform"
    DEBUG: bool = False
    SECRET_KEY: Optional[str] = Field(default=None)
    ALLOWED_ORIGINS: Optional[List[str]] = None
    FRONTEND_URL: str = "http://localhost:3000"
    DOMAIN: Optional[str] = None

    # ─── Database (PostgreSQL) ────────────────────────────────
    DATABASE_URL: Optional[str] = Field(default=None)
    # Per-PROCESS pool. Total connections = (pool_size + max_overflow) ×
    # (uvicorn workers + worker procs), which must stay under Postgres
    # max_connections (raised to 200 in compose). Defaults sized for ~4 API
    # workers + 1 arq worker (perf #2). Lower if you run many workers.
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 10
    DATABASE_POOL_TIMEOUT: int = 30  # seconds to wait for a free connection

    # ─── Redis ────────────────────────────────────────────────
    REDIS_URL: Optional[str] = Field(default=None)
    # Separate logical DB for cacheable data (threat-intel lookups, etc.) so
    # cache growth never evicts the durable queue / security tokens on REDIS_URL
    # (perf #4/#6). Defaults to DB 1 on the same Redis instance if unset.
    REDIS_CACHE_URL: Optional[str] = None
    CACHE_TTL_SECONDS: int = 21600  # 6h default TTL for intel caches

    # ─── JWT Auth ─────────────────────────────────────────────
    JWT_SECRET_KEY: Optional[str] = Field(default=None)
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ─── OAuth / SSO ──────────────────────────────────────────
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    MICROSOFT_CLIENT_ID: Optional[str] = None
    MICROSOFT_CLIENT_SECRET: Optional[str] = None
    MICROSOFT_TENANT_ID: Optional[str] = None

    # ─── Cookie Security ──────────────────────────────────────
    # Set to false when running over plain HTTP (LAN/dev without HTTPS).
    # MUST be true in production (HTTPS required for Secure + SameSite=none).
    SECURE_COOKIES: bool = True

    # ─── Registration Policy (fix H-3) ────────────────────────
    # Open self-registration is DISABLED by default. When enabled, new users
    # are assigned DEFAULT_USER_ROLE (viewer by default) rather than analyst,
    # so a self-registered account cannot drive offensive tooling until an
    # admin elevates it.
    ALLOW_OPEN_REGISTRATION: bool = False
    DEFAULT_USER_ROLE: str = "viewer"

    # ─── Admin User ───────────────────────────────────────────
    ADMIN_PASSWORD: Optional[str] = Field(default=None)
    
    @field_validator('ADMIN_PASSWORD')
    @classmethod
    def validate_admin_password(cls, v, info):
        if is_production_mode() and not v:
            raise ValueError('ADMIN_PASSWORD must be set in production mode')
        return v

    # ─── Ollama (external server only) ───────────────────────
    # There is no bundled Ollama container. Point OLLAMA_REMOTE_URL at an external Ollama
    # host (or set it in Admin -> Settings -> Remote Ollama, which takes precedence).
    OLLAMA_DEFAULT_MODEL: str = "socis-pentest"
    OLLAMA_TIMEOUT: int = 600

    # ─── Ollama (Remote) ──────────────────────────────────────
    OLLAMA_REMOTE_URL: Optional[str] = None
    OLLAMA_REMOTE_MODEL: Optional[str] = None

    # ─── External LLMs ───────────────────────────────────────
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o"
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"

    ANTHROPIC_API_KEY: Optional[str] = None
    ANTHROPIC_MODEL: str = "claude-sonnet-4-20250514"

    # ─── OpenRouter ───────────────────────────────────────────
    OPENROUTER_API_KEY: Optional[str] = None
    OPENROUTER_MODEL: str = "openai/gpt-4o"
    OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"

    # ─── xAI Grok ─────────────────────────────────────────────
    GROK_API_KEY: Optional[str] = None
    GROK_MODEL: str = "grok-beta"
    GROK_BASE_URL: str = "https://api.x.ai/v1"

    # ─── Mistral ──────────────────────────────────────────────
    MISTRAL_API_KEY: Optional[str] = None
    MISTRAL_MODEL: str = "mistral-large-latest"
    MISTRAL_BASE_URL: str = "https://api.mistral.ai/v1"

    # ─── MinIO / S3 Storage ──────────────────────────────────
    MINIO_ENDPOINT: str = "localhost:9000"
    MINIO_ACCESS_KEY: Optional[str] = Field(default=None)
    MINIO_SECRET_KEY: Optional[str] = Field(default=None)
    MINIO_BUCKET: str = "socis-reports"
    # Auto-expire stored reports after this many days (0 = keep forever).
    # Applied as a MinIO/S3 bucket lifecycle rule so old reports don't grow disk
    # unbounded. Override with REPORT_RETENTION_DAYS in .env.
    REPORT_RETENTION_DAYS: int = 90
    MINIO_SECURE: bool = True

    # ─── MCP Servers ─────────────────────────────────────────
    MCP_NMAP_ENABLED: bool = True
    MCP_MASSCAN_ENABLED: bool = True
    MCP_NUCLEI_ENABLED: bool = True
    MCP_NIKTO_ENABLED: bool = True
    MCP_WPSCAN_ENABLED: bool = False
    MCP_CVE_ENABLED: bool = True
    MCP_CVE_LITE_ENABLED: bool = True
    MCP_OSINT_ENABLED: bool = True
    MCP_METASPLOIT_ENABLED: bool = False
    MCP_METASPLOIT_MSF_PASSWORD: Optional[str] = None
    MCP_METASPLOIT_MSF_SERVER: str = "127.0.0.1"
    MCP_METASPLOIT_MSF_PORT: int = 55553
    MCP_WAF_DETECTION_ENABLED: bool = True
    MCP_FFUF_ENABLED: bool = True
    MCP_GOBUSTER_ENABLED: bool = True
    MCP_SQLMAP_ENABLED: bool = True
    MCP_SSL_ENABLED: bool = True
    MCP_JWT_ENABLED: bool = True
    MCP_POC_ENABLED: bool = True
    MCP_EPSS_ENABLED: bool = True
    MCP_CISA_KEV_ENABLED: bool = True
    MCP_ANOMALY_ENABLED: bool = False
    MCP_PAYLOAD_GENERATOR_ENABLED: bool = False
    MCP_MITRE_ENABLED: bool = True

    # ─── Agentic Safety (fix H-4) ────────────────────────────
    # When False (default), the AI chat agent may NOT autonomously invoke
    # exploitation-class tools (metasploit, sqlmap dump/shell, jwt forge,
    # payload generation) parsed out of model-generated text. This blocks
    # prompt-injection -> autonomous-exploitation. Operators who want fully
    # autonomous offense must opt in explicitly.
    SOCIS_AGENT_ALLOW_OFFENSIVE: bool = False

    # Allow registering stdio MCP servers (arbitrary commands) through the API.
    # Off by default: it is remote code execution inside the backend container.
    MCP_ALLOW_STDIO_SERVERS: bool = False

    # Max simultaneous AI-chat SSE streams across all backend workers (perf #7).
    # Each stream holds a worker coroutine + an LLM slot for its whole duration,
    # so this prevents a flood of chats from exhausting the pool. 0 = unlimited.
    MAX_CONCURRENT_CHAT_SESSIONS: int = 20

    # ─── Security Tools ──────────────────────────────────────
    TOOL_TIMEOUT_DEFAULT: int = 120
    TOOL_TIMEOUT_NMAP: int = 300
    TOOL_TIMEOUT_NIKTO: int = 600
    TOOL_TIMEOUT_NUCLEI: int = 600

    # ─── Report Generation ───────────────────────────────────
    REPORT_BRAND_NAME: str = "SOCIS-AI-PT"
    REPORT_BRAND_TAGLINE: str = "AI-Powered Penetration Testing Platform"
    REPORT_BRAND_COLOR: str = "#0ff0fc"
    REPORT_BRAND_LOGO_PATH: Optional[str] = None
    REPORT_OUTPUT_DIR: str = "./reports"

    # ─── Deployment ──────────────────────────────────────────
    DEPLOYMENT_MODE: str = "development"  # development | saas | onprem

    # ─── Rate Limiting & Security ────────────────────────────
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60
    REQUEST_MAX_BODY_SIZE: int = 10_485_760  # 10MB

    # ─── Encryption (for secrets stored in DB) ───────────────
    ENCRYPTION_KEY: Optional[str] = Field(default=None)

    model_config = {
        "env_file": str(_PROJECT_ROOT_ENV),
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",  # ignore .env fields not declared in this class
    }

    @field_validator('SECRET_KEY', mode='after')
    @classmethod
    def validate_secret_key(cls, v):
        """Ensure SECRET_KEY is set and secure in production."""
        if not v:
            if is_production_mode():
                raise ValueError('SECRET_KEY must be set in production')
            raise ValueError('SECRET_KEY must be set - generate with: openssl rand -hex 32')
        if len(v) < 32:
            if is_production_mode():
                raise ValueError('SECRET_KEY must be at least 32 characters long')
            warnings.warn('SECRET_KEY should be at least 32 characters long')
        return v

    @field_validator('JWT_SECRET_KEY', mode='after')
    @classmethod
    def validate_jwt_secret(cls, v):
        """Ensure JWT_SECRET_KEY is set and secure in production."""
        if not v:
            if is_production_mode():
                raise ValueError('JWT_SECRET_KEY must be set in production')
            raise ValueError('JWT_SECRET_KEY must be set - generate with: openssl rand -hex 32')
        if len(v) < 32:
            if is_production_mode():
                raise ValueError('JWT_SECRET_KEY must be at least 32 characters long')
            warnings.warn('JWT_SECRET_KEY should be at least 32 characters long')
        return v

    @field_validator('DATABASE_URL', mode='after')
    @classmethod
    def validate_database_url(cls, v):
        """Ensure DATABASE_URL is set."""
        if not v:
            raise ValueError('DATABASE_URL must be set')
        return v

    @field_validator('REDIS_URL', mode='after')
    @classmethod
    def validate_redis_url(cls, v):
        """Ensure REDIS_URL is set."""
        if not v:
            raise ValueError('REDIS_URL must be set')
        return v

    @field_validator('ENCRYPTION_KEY', mode='after')
    @classmethod
    def validate_encryption_key(cls, v):
        """Require a persistent ENCRYPTION_KEY in production (fix M-5).

        Without it, an ephemeral key is generated per process and all stored
        secrets become unreadable after restart. Fail fast instead of warning.
        """
        if is_production_mode() and not v:
            raise ValueError(
                'ENCRYPTION_KEY must be set in production — generate with: '
                'python -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"'
            )
        return v

    def _enforce_production_posture(self) -> "Settings":
        """Reject insecure defaults when running in a production mode (fix C-4).

        The previous build shipped DEBUG=true, RATE_LIMIT_ENABLED=false and
        weak dev-* secrets. We now hard-fail on the dangerous combinations when
        DEPLOYMENT_MODE is a production mode.
        """
        if not is_production_mode():
            return self

        problems: list[str] = []
        if self.DEBUG:
            problems.append("DEBUG must be false in production")
        if not self.RATE_LIMIT_ENABLED:
            problems.append("RATE_LIMIT_ENABLED must be true in production")
        if not self.SECURE_COOKIES:
            problems.append("SECURE_COOKIES must be true in production (HTTPS)")

        _weak = {
            "dev-secret-change-in-production",
            "dev-jwt-secret-change-in-production",
            "change-this-password",
            "changeme",
        }
        if self.SECRET_KEY in _weak:
            problems.append("SECRET_KEY is a known default — generate a strong random value")
        if self.JWT_SECRET_KEY in _weak:
            problems.append("JWT_SECRET_KEY is a known default — generate a strong random value")
        if self.ADMIN_PASSWORD in {"Admin123!", "admin", "changeme", "password"}:
            problems.append("ADMIN_PASSWORD is a known/weak default — set a strong unique password")
        if not self.ALLOWED_ORIGINS:
            problems.append("ALLOWED_ORIGINS must be set in production (explicit CORS allowlist)")

        if problems:
            raise ValueError(
                "Insecure production configuration detected:\n  - "
                + "\n  - ".join(problems)
            )
        return self

    def model_post_init(self, __context) -> None:  # pydantic v2 hook
        self._enforce_production_posture()


settings = Settings()
