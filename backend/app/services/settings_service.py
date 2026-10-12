"""
SOCIS-AI-PT — Settings Services
Manages global platform configuration and user-specific settings
"""

import json
from uuid import UUID, uuid4
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from app.models.settings import PlatformSettings, UserSettings
from app.config import settings as app_settings
from app.core.encryption import encrypt_secret, decrypt_secret


class SettingsService:
    """Service for managing platform settings."""

    async def get_setting(self, db: AsyncSession, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a setting value from database, fallback to default."""
        try:
            result = await db.execute(
                select(PlatformSettings).where(
                    PlatformSettings.key == key,
                    PlatformSettings.is_active == True
                )
            )
            setting = result.scalar_one_or_none()
            return setting.value if setting else default
        except Exception:
            return default

    async def set_setting(self, db: AsyncSession, key: str, value: str, description: Optional[str] = None) -> PlatformSettings:
        """Set or update a setting value."""
        # Try to find existing setting
        result = await db.execute(
            select(PlatformSettings).where(PlatformSettings.key == key)
        )
        setting = result.scalar_one_or_none()

        if setting:
            # Update existing
            setting.value = value
            if description:
                setting.description = description
        else:
            # Create new
            setting = PlatformSettings(
                key=key,
                value=value,
                description=description or f"Platform setting: {key}"
            )
            db.add(setting)

        await db.commit()
        await db.refresh(setting)
        return setting

    async def get_ollama_remote_url(self, db: AsyncSession) -> Optional[str]:
        """Get remote Ollama URL from database or environment."""
        # Try database first
        db_value = await self.get_setting(db, "ollama_remote_url")
        if db_value:
            return db_value
        # Fallback to environment variable
        return app_settings.OLLAMA_REMOTE_URL

    async def set_ollama_remote_url(self, db: AsyncSession, url: str) -> PlatformSettings:
        """Set remote Ollama URL in database."""
        return await self.set_setting(
            db,
            "ollama_remote_url",
            url.rstrip('/'),
            "Remote Ollama Server URL (e.g., http://192.168.20.13:11434)"
        )

    async def get_ollama_remote_model(self, db: AsyncSession) -> Optional[str]:
        """Get remote Ollama default model from database or environment."""
        # Try database first
        db_value = await self.get_setting(db, "ollama_remote_model")
        if db_value:
            return db_value
        # Fallback to environment variable
        return app_settings.OLLAMA_REMOTE_MODEL

    async def set_ollama_remote_model(self, db: AsyncSession, model: str) -> PlatformSettings:
        """Set remote Ollama default model in database."""
        return await self.set_setting(
            db,
            "ollama_remote_model",
            model,
            "Default remote Ollama model name"
        )

    async def get_all_settings(self, db: AsyncSession) -> dict:
        """Get all platform settings."""
        result = await db.execute(
            select(PlatformSettings).where(PlatformSettings.is_active == True)
        )
        settings = result.scalars().all()
        return {s.key: s.value for s in settings}

    async def get_sso_settings(self, db: AsyncSession, include_secrets: bool = False) -> dict:
        """Get SSO settings from DB with secure fallback to env vars.

        Secrets are never returned unless include_secrets=True.
        """
        raw = await self.get_setting(db, "sso_settings")
        db_data: dict = {}
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    db_data = parsed
            except Exception:
                db_data = {}

        merged = {
            "google_enabled": bool(db_data.get("google_enabled", bool(app_settings.GOOGLE_CLIENT_ID))),
            "microsoft_enabled": bool(db_data.get("microsoft_enabled", bool(app_settings.MICROSOFT_CLIENT_ID))),
            "google_client_id": db_data.get("google_client_id") or app_settings.GOOGLE_CLIENT_ID or "",
            "microsoft_client_id": db_data.get("microsoft_client_id") or app_settings.MICROSOFT_CLIENT_ID or "",
            "microsoft_tenant_id": db_data.get("microsoft_tenant_id") or app_settings.MICROSOFT_TENANT_ID or "common",
            # Who may sign in through SSO (core/sso_policy.py): e-mail domains, and whether first-time sign-ins may create an account (default: no).
            "sso_allowed_domains": str(db_data.get("sso_allowed_domains") or ""),
            "sso_auto_provision": bool(db_data.get("sso_auto_provision", False)),
        }

        google_secret_encrypted = db_data.get("google_client_secret_encrypted", "")
        microsoft_secret_encrypted = db_data.get("microsoft_client_secret_encrypted", "")

        merged["google_client_secret_configured"] = bool(google_secret_encrypted or app_settings.GOOGLE_CLIENT_SECRET)
        merged["microsoft_client_secret_configured"] = bool(microsoft_secret_encrypted or app_settings.MICROSOFT_CLIENT_SECRET)

        if include_secrets:
            merged["google_client_secret"] = ""
            merged["microsoft_client_secret"] = ""
            if google_secret_encrypted:
                try:
                    merged["google_client_secret"] = decrypt_secret(google_secret_encrypted)
                except Exception:
                    merged["google_client_secret"] = ""
            elif app_settings.GOOGLE_CLIENT_SECRET:
                merged["google_client_secret"] = app_settings.GOOGLE_CLIENT_SECRET

            if microsoft_secret_encrypted:
                try:
                    merged["microsoft_client_secret"] = decrypt_secret(microsoft_secret_encrypted)
                except Exception:
                    merged["microsoft_client_secret"] = ""
            elif app_settings.MICROSOFT_CLIENT_SECRET:
                merged["microsoft_client_secret"] = app_settings.MICROSOFT_CLIENT_SECRET

        return merged

    async def save_sso_settings(self, db: AsyncSession, payload: dict) -> dict:
        """Save SSO settings with encryption for client secrets."""
        current = await self.get_sso_settings(db, include_secrets=False)

        data = {
            "google_enabled": bool(payload.get("google_enabled", current.get("google_enabled", False))),
            "microsoft_enabled": bool(payload.get("microsoft_enabled", current.get("microsoft_enabled", False))),
            "google_client_id": str(payload.get("google_client_id", current.get("google_client_id", ""))).strip(),
            "microsoft_client_id": str(payload.get("microsoft_client_id", current.get("microsoft_client_id", ""))).strip(),
            "microsoft_tenant_id": str(payload.get("microsoft_tenant_id", current.get("microsoft_tenant_id", "common"))).strip() or "common",
            "sso_allowed_domains": ", ".join(sorted(__import__("app.core.sso_policy", fromlist=["parse_domains"]).parse_domains(payload.get("sso_allowed_domains", current.get("sso_allowed_domains", ""))))),
            "sso_auto_provision": bool(payload.get("sso_auto_provision", current.get("sso_auto_provision", False))),
        }

        raw_current = await self.get_setting(db, "sso_settings")
        previous: dict = {}
        if raw_current:
            try:
                parsed = json.loads(raw_current)
                if isinstance(parsed, dict):
                    previous = parsed
            except Exception:
                previous = {}

        google_secret = payload.get("google_client_secret")
        microsoft_secret = payload.get("microsoft_client_secret")

        if isinstance(google_secret, str) and google_secret.strip():
            data["google_client_secret_encrypted"] = encrypt_secret(google_secret.strip())
        elif previous.get("google_client_secret_encrypted"):
            data["google_client_secret_encrypted"] = previous["google_client_secret_encrypted"]

        if isinstance(microsoft_secret, str) and microsoft_secret.strip():
            data["microsoft_client_secret_encrypted"] = encrypt_secret(microsoft_secret.strip())
        elif previous.get("microsoft_client_secret_encrypted"):
            data["microsoft_client_secret_encrypted"] = previous["microsoft_client_secret_encrypted"]

        await self.set_setting(
            db,
            "sso_settings",
            json.dumps(data),
            "Global SSO provider configuration (Google/Microsoft)"
        )
        return await self.get_sso_settings(db, include_secrets=False)

    async def get_notification_delivery_settings(self, db: AsyncSession, include_secrets: bool = False) -> dict:
        """Get notification delivery provider settings with secure defaults."""
        raw = await self.get_setting(db, "notification_delivery_settings")
        db_data: dict = {}
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    db_data = parsed
            except Exception:
                db_data = {}

        merged = {
            "enabled": bool(db_data.get("enabled", False)),
            "provider": str(db_data.get("provider", "disabled") or "disabled"),
            "sender_email": str(db_data.get("sender_email", "") or "").strip(),
            "reply_to_email": str(db_data.get("reply_to_email", "") or "").strip(),
            "graph_tenant_id": str(db_data.get("graph_tenant_id", "common") or "common").strip() or "common",
            "graph_client_id": str(db_data.get("graph_client_id", "") or "").strip(),
            "smtp_host": str(db_data.get("smtp_host", "") or "").strip(),
            "smtp_port": int(db_data.get("smtp_port", 587) or 587),
            "smtp_username": str(db_data.get("smtp_username", "") or "").strip(),
            "smtp_use_starttls": bool(db_data.get("smtp_use_starttls", True)),
            "smtp_use_ssl": bool(db_data.get("smtp_use_ssl", False)),
            "webhook_parallel_enabled": bool(db_data.get("webhook_parallel_enabled", True)),
        }

        graph_secret_encrypted = db_data.get("graph_client_secret_encrypted", "")
        smtp_password_encrypted = db_data.get("smtp_password_encrypted", "")
        merged["graph_client_secret_configured"] = bool(graph_secret_encrypted)
        merged["smtp_password_configured"] = bool(smtp_password_encrypted)

        if include_secrets:
            merged["graph_client_secret"] = ""
            merged["smtp_password"] = ""
            if graph_secret_encrypted:
                try:
                    merged["graph_client_secret"] = decrypt_secret(graph_secret_encrypted)
                except Exception:
                    merged["graph_client_secret"] = ""
            if smtp_password_encrypted:
                try:
                    merged["smtp_password"] = decrypt_secret(smtp_password_encrypted)
                except Exception:
                    merged["smtp_password"] = ""

        return merged

    async def save_notification_delivery_settings(self, db: AsyncSession, payload: dict) -> dict:
        """Save delivery provider settings with encrypted credentials."""
        current = await self.get_notification_delivery_settings(db, include_secrets=False)

        data = {
            "enabled": bool(payload.get("enabled", current.get("enabled", False))),
            "provider": str(payload.get("provider", current.get("provider", "disabled")) or "disabled").strip(),
            "sender_email": str(payload.get("sender_email", current.get("sender_email", "")) or "").strip(),
            "reply_to_email": str(payload.get("reply_to_email", current.get("reply_to_email", "")) or "").strip(),
            "graph_tenant_id": str(payload.get("graph_tenant_id", current.get("graph_tenant_id", "common")) or "common").strip() or "common",
            "graph_client_id": str(payload.get("graph_client_id", current.get("graph_client_id", "")) or "").strip(),
            "smtp_host": str(payload.get("smtp_host", current.get("smtp_host", "")) or "").strip(),
            "smtp_port": int(payload.get("smtp_port", current.get("smtp_port", 587)) or 587),
            "smtp_username": str(payload.get("smtp_username", current.get("smtp_username", "")) or "").strip(),
            "smtp_use_starttls": bool(payload.get("smtp_use_starttls", current.get("smtp_use_starttls", True))),
            "smtp_use_ssl": bool(payload.get("smtp_use_ssl", current.get("smtp_use_ssl", False))),
            "webhook_parallel_enabled": bool(payload.get("webhook_parallel_enabled", current.get("webhook_parallel_enabled", True))),
        }

        raw_current = await self.get_setting(db, "notification_delivery_settings")
        previous: dict = {}
        if raw_current:
            try:
                parsed = json.loads(raw_current)
                if isinstance(parsed, dict):
                    previous = parsed
            except Exception:
                previous = {}

        graph_secret = payload.get("graph_client_secret")
        smtp_password = payload.get("smtp_password")

        if isinstance(graph_secret, str) and graph_secret.strip():
            data["graph_client_secret_encrypted"] = encrypt_secret(graph_secret.strip())
        elif previous.get("graph_client_secret_encrypted"):
            data["graph_client_secret_encrypted"] = previous["graph_client_secret_encrypted"]

        if isinstance(smtp_password, str) and smtp_password.strip():
            data["smtp_password_encrypted"] = encrypt_secret(smtp_password.strip())
        elif previous.get("smtp_password_encrypted"):
            data["smtp_password_encrypted"] = previous["smtp_password_encrypted"]

        await self.set_setting(
            db,
            "notification_delivery_settings",
            json.dumps(data),
            "Global notification delivery provider settings"
        )
        return await self.get_notification_delivery_settings(db, include_secrets=False)


class UserSettingsService:
    """Service for managing user-specific settings."""

    @staticmethod
    def default_tool_settings() -> dict:
        """Default tool and MCP settings used as a stable schema baseline."""
        return {
            "tool_timeout_default": 120,
            "tool_timeout_nmap": 300,
            "tool_timeout_nuclei": 600,
            # Scanners
            "mcp_nmap_enabled": True,
            "mcp_masscan_enabled": True,
            "mcp_nuclei_enabled": True,
            "mcp_nikto_enabled": True,
            "mcp_wpscan_enabled": False,
            # Web / Fuzzing
            "mcp_ffuf_enabled": True,
            "mcp_gobuster_enabled": True,
            "mcp_sqlmap_enabled": True,
            "mcp_waf_detection_enabled": True,
            # TLS / Auth
            "mcp_ssl_enabled": True,
            "mcp_jwt_enabled": True,
            # Exploitation
            "mcp_metasploit_enabled": False,
            "mcp_poc_enabled": True,
            # Intelligence
            "mcp_cve_enabled": True,
            "mcp_cve_lite_enabled": True,
            "mcp_epss_enabled": True,
            "mcp_cisa_kev_enabled": True,
            "mcp_osint_enabled": True,
            "mcp_mitre_enabled": True,
            "mcp_exploitdb_enabled": True,
            # New AI-powered tools (opt-in, default disabled)
            "mcp_anomaly_enabled": False,
            "mcp_payload_generator_enabled": False,
            # Active Directory (NetExec/kerbrute) — offensive-capable, opt-in like Metasploit
            "mcp_ad_enabled": False,
            "mcp_cloud_enabled": True,  # safe, read-only recon — no opt-in needed
            "mcp_container_enabled": True,  # safe, read-only recon — no opt-in needed
            "mcp_api_security_enabled": True,  # safe, read-only recon — no opt-in needed
            "mcp_secrets_enabled": True,  # pure pattern-matching over supplied content — no opt-in needed
            "mcp_dns_deep_enabled": True,  # safe, read-only recon — no opt-in needed
            "mcp_crack_enabled": False,  # offensive (cracking hashes) — opt-in like Metasploit/AD
            "mcp_compliance_enabled": True,  # pure data lookup — no opt-in needed
            "enable_anomaly_detection": False,
            "enable_ai_payloads": False,
            "waf_auto_bypass": False,
        }

    async def get_or_create_user_settings(self, db: AsyncSession, user_id: UUID) -> UserSettings:
        """Get or create user settings record."""
        result = await db.execute(
            select(UserSettings)
            .where(UserSettings.user_id == user_id)
            .order_by(UserSettings.updated_at.desc(), UserSettings.created_at.desc())
        )
        rows = result.scalars().all()

        if rows:
            user_settings = rows[0]

            # Historical race conditions can create duplicates. Keep the newest row,
            # merge missing sections from older rows, and delete the extras.
            if len(rows) > 1:
                for duplicate in rows[1:]:
                    if not user_settings.llm_settings and duplicate.llm_settings:
                        user_settings.llm_settings = duplicate.llm_settings
                    if not user_settings.tool_settings and duplicate.tool_settings:
                        user_settings.tool_settings = duplicate.tool_settings
                    if not user_settings.report_settings and duplicate.report_settings:
                        user_settings.report_settings = duplicate.report_settings
                    if not user_settings.notification_settings and duplicate.notification_settings:
                        user_settings.notification_settings = duplicate.notification_settings
                    await db.delete(duplicate)

                await db.commit()
                await db.refresh(user_settings)

            return user_settings

        # Create defaults for first-time users. Handle concurrent insert races by
        # retrying as a read if another request created the row first.
        user_settings = UserSettings(user_id=user_id)
        db.add(user_settings)
        try:
            await db.commit()
        except IntegrityError:
            await db.rollback()
            result = await db.execute(
                select(UserSettings)
                .where(UserSettings.user_id == user_id)
                .order_by(UserSettings.updated_at.desc(), UserSettings.created_at.desc())
            )
            existing = result.scalars().first()
            if existing:
                return existing
            raise

        await db.refresh(user_settings)
        return user_settings

    async def get_llm_settings(self, db: AsyncSession, user_id: UUID) -> dict:
        """Get user's LLM settings."""
        from app.core.llm_providers import sanitize_user_llm_settings
        user_settings = await self.get_or_create_user_settings(db, user_id)
        if user_settings.llm_settings:
            return sanitize_user_llm_settings(user_settings.llm_settings)
        return {
            "ollama_default_model": "socis-pentest",
            "ollama_timeout": 600,
            "use_openai": False,
            "openai_api_key": "",
            "openai_model": "gpt-4o",
            "use_anthropic": False,
            "anthropic_api_key": "",
            "anthropic_model": "claude-sonnet-4-20250514",
        }

    async def save_llm_settings(self, db: AsyncSession, user_id: UUID, settings: dict) -> UserSettings:
        """Save user's LLM settings."""
        from app.core.llm_providers import sanitize_user_llm_settings
        user_settings = await self.get_or_create_user_settings(db, user_id)
        # The Ollama endpoint is admin-only; never persist a user-supplied URL (SSRF) or the legacy provider.
        user_settings.llm_settings = sanitize_user_llm_settings(settings)
        await db.commit()
        await db.refresh(user_settings)
        return user_settings

    async def get_tool_settings(self, db: AsyncSession, user_id: UUID) -> dict:
        """Get effective tool settings with default+user+global merge."""
        user_settings = await self.get_or_create_user_settings(db, user_id)
        defaults = self.default_tool_settings()
        user_values = user_settings.tool_settings or {}

        # Admin-managed global policy lives in platform settings as JSON.
        result = await db.execute(
            select(PlatformSettings).where(
                PlatformSettings.key == "tool_settings_global",
                PlatformSettings.is_active == True,
            )
        )
        global_setting = result.scalar_one_or_none()
        global_values: dict = {}
        if global_setting and global_setting.value:
            try:
                parsed = json.loads(global_setting.value)
                if isinstance(parsed, dict):
                    global_values = parsed
            except Exception:
                global_values = {}

        merged = {**defaults, **user_values, **global_values}
        return merged

    async def save_global_tool_settings(self, db: AsyncSession, settings: dict, catalog_keys: Optional[set] = None) -> dict:
        """Save admin-managed global tool settings policy. `tool_overrides` (per-tool, e.g. {"nmap_mcp.nmap_scan": false}) is
        validated here too (core/ai_tool_policy.py) even though the API router already does — a caller that reaches this
        method directly must not be able to skip the offensive-tool floor or store malformed entries."""
        from app.core.ai_tool_policy import sanitize_overrides
        defaults = self.default_tool_settings()
        sanitized = {**defaults, **(settings or {})}
        clean_overrides, _problems = sanitize_overrides(sanitized.get("tool_overrides"), catalog_keys or set())
        sanitized["tool_overrides"] = clean_overrides

        result = await db.execute(
            select(PlatformSettings).where(PlatformSettings.key == "tool_settings_global")
        )
        row = result.scalar_one_or_none()
        payload = json.dumps(sanitized)

        if row:
            row.value = payload
            row.description = "Global admin policy for tool and MCP enablement"
            row.is_active = True
        else:
            row = PlatformSettings(
                key="tool_settings_global",
                value=payload,
                description="Global admin policy for tool and MCP enablement",
                is_active=True,
            )
            db.add(row)

        await db.commit()
        return sanitized

    async def save_tool_settings(self, db: AsyncSession, user_id: UUID, settings: dict) -> UserSettings:
        """Save user's tool settings."""
        user_settings = await self.get_or_create_user_settings(db, user_id)
        user_settings.tool_settings = settings
        await db.commit()
        await db.refresh(user_settings)
        return user_settings

    async def get_report_settings(self, db: AsyncSession, user_id: UUID) -> dict:
        """Get user's report settings."""
        user_settings = await self.get_or_create_user_settings(db, user_id)
        return user_settings.report_settings or {
            "brand_name": "SOCIS-AI-PT",
            "brand_tagline": "AI-Powered Penetration Testing Platform",
            "brand_color": "#0ff0fc",
            "brand_logo_url": "",
            "customer_name": "",
            "customer_logo_url": "",
            "report_theme": "light",
            "report_classification": "Confidential",
        }

    async def save_report_settings(self, db: AsyncSession, user_id: UUID, settings: dict) -> UserSettings:
        """Save user's report settings."""
        user_settings = await self.get_or_create_user_settings(db, user_id)
        user_settings.report_settings = settings
        await db.commit()
        await db.refresh(user_settings)
        return user_settings

    async def get_notification_settings(self, db: AsyncSession, user_id: UUID) -> dict:
        """Get user's notification settings."""
        user_settings = await self.get_or_create_user_settings(db, user_id)
        return user_settings.notification_settings or {
            "email_on_scan_complete": True,
            "email_on_vulnerability": True,
            "email_on_critical_finding": True,
        }

    async def save_notification_settings(self, db: AsyncSession, user_id: UUID, settings: dict) -> UserSettings:
        """Save user's notification settings."""
        user_settings = await self.get_or_create_user_settings(db, user_id)
        user_settings.notification_settings = settings
        await db.commit()
        await db.refresh(user_settings)
        return user_settings


# Singleton instances
settings_service = SettingsService()
user_settings_service = UserSettingsService()
