"""
notification_delivery_service.py — enterprise notification delivery adapters.

Supports:
- Microsoft 365 Graph API (client credentials)
- Microsoft/enterprise SMTP relay
- Parallel webhook dispatch for SOC workflows
"""

import asyncio
import json
import logging
import smtplib
import ssl
import time
import uuid
from email.message import EmailMessage
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.user import User
from app.services.settings_service import settings_service
from app.services.webhook_service import webhook_service, _validate_webhook_url

logger = logging.getLogger(__name__)


class NotificationDeliveryService:
    """Deliver notification events using configured enterprise providers."""

    @staticmethod
    def _as_bool(raw: Any, default: bool = False) -> bool:
        if raw is None:
            return default
        if isinstance(raw, bool):
            return raw
        text = str(raw).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off"):
            return False
        return default

    async def _effective_toggles(self, db: AsyncSession) -> dict[str, bool]:
        return {
            "email_on_scan_complete": self._as_bool(await settings_service.get_setting(db, "email_on_scan_complete", "true"), True),
            "email_on_vulnerability": self._as_bool(await settings_service.get_setting(db, "email_on_vulnerability", "true"), True),
            "email_on_critical_finding": self._as_bool(await settings_service.get_setting(db, "email_on_critical_finding", "true"), True),
        }

    async def _send_via_graph(self, cfg: dict, recipient_email: str, subject: str, body_text: str) -> bool:
        tenant = cfg.get("graph_tenant_id") or "common"
        client_id = (cfg.get("graph_client_id") or "").strip()
        client_secret = (cfg.get("graph_client_secret") or "").strip()
        sender = (cfg.get("sender_email") or "").strip()

        if not client_id or not client_secret or not sender:
            logger.warning("Notification delivery skipped (graph missing credentials)")
            return False

        token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        send_url = f"https://graph.microsoft.com/v1.0/users/{sender}/sendMail"

        async with httpx.AsyncClient(timeout=15) as client:
            token_res = await client.post(
                token_url,
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
            )
            if token_res.status_code != 200:
                # Do not log the response body — token endpoints can echo
                # sensitive material. Log only the status code (fix M-6).
                logger.warning("Graph token request failed: HTTP %s", token_res.status_code)
                return False

            access_token = token_res.json().get("access_token")
            if not access_token:
                logger.warning("Graph token response missing access_token")
                return False

            payload = {
                "message": {
                    "subject": subject,
                    "body": {"contentType": "Text", "content": body_text},
                    "toRecipients": [{"emailAddress": {"address": recipient_email}}],
                },
                "saveToSentItems": "false",
            }
            reply_to = (cfg.get("reply_to_email") or "").strip()
            if reply_to:
                payload["message"]["replyTo"] = [{"emailAddress": {"address": reply_to}}]

            send_res = await client.post(
                send_url,
                json=payload,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if send_res.status_code not in (200, 202):
                logger.warning("Graph sendMail failed: %s", send_res.text[:200])
                return False

        return True

    @staticmethod
    def _send_smtp_blocking(cfg: dict, recipient_email: str, subject: str, body_text: str) -> bool:
        host = (cfg.get("smtp_host") or "").strip()
        port = int(cfg.get("smtp_port") or 587)
        username = (cfg.get("smtp_username") or "").strip()
        password = (cfg.get("smtp_password") or "").strip()
        sender = (cfg.get("sender_email") or username).strip()

        if not host or not sender:
            logger.warning("Notification delivery skipped (smtp missing host/sender)")
            return False

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = recipient_email
        reply_to = (cfg.get("reply_to_email") or "").strip()
        if reply_to:
            msg["Reply-To"] = reply_to
        msg.set_content(body_text)

        use_ssl = bool(cfg.get("smtp_use_ssl", False))
        use_starttls = bool(cfg.get("smtp_use_starttls", True))

        if use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, timeout=15, context=context) as server:
                if username and password:
                    server.login(username, password)
                server.send_message(msg)
            return True

        with smtplib.SMTP(host, port, timeout=15) as server:
            if use_starttls:
                context = ssl.create_default_context()
                server.starttls(context=context)
            if username and password:
                server.login(username, password)
            server.send_message(msg)
        return True

    async def _send_via_smtp(self, cfg: dict, recipient_email: str, subject: str, body_text: str) -> bool:
        return await asyncio.to_thread(self._send_smtp_blocking, cfg, recipient_email, subject, body_text)

    async def _send_email(self, cfg: dict, recipient_email: str, subject: str, body_text: str) -> bool:
        if not cfg.get("enabled"):
            return False

        provider = str(cfg.get("provider") or "disabled").strip().lower()
        try:
            if provider == "microsoft_graph":
                return await self._send_via_graph(cfg, recipient_email, subject, body_text)
            if provider == "microsoft_smtp":
                return await self._send_via_smtp(cfg, recipient_email, subject, body_text)
            return False
        except Exception as exc:
            logger.warning("Notification email send failed via %s: %s", provider, exc)
            return False

    async def send_password_reset_email(
        self, db: AsyncSession, recipient_email: str, subject: str, body_text: str
    ) -> bool:
        """Send a password-reset link via the configured provider (fix C-2).

        Unlike _send_email, this does not require the general-notification
        toggle to be enabled. Returns True only if actually dispatched.
        """
        cfg = await settings_service.get_notification_delivery_settings(db, include_secrets=True)
        provider = str(cfg.get("provider") or "disabled").strip().lower()
        try:
            if provider == "microsoft_graph":
                return await self._send_via_graph(cfg, recipient_email, subject, body_text)
            if provider == "microsoft_smtp":
                return await self._send_via_smtp(cfg, recipient_email, subject, body_text)
            return False
        except Exception as exc:
            logger.warning("Password reset email send failed via %s: %s", provider, exc)
            return False

    @staticmethod
    def _severity_counts(vulns: list[dict]) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulns:
            sev = str(vuln.get("severity", "info")).lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["info"] += 1
        return counts

    async def dispatch_scan_notifications(
        self,
        db: AsyncSession,
        user_id: str,
        target: str,
        risk_level: str,
        vulnerabilities: list[dict],
        scan_id: str,
    ) -> dict:
        """Dispatch email + webhook notifications based on configured providers and toggles."""
        user = await db.get(User, uuid.UUID(user_id))
        if not user or not user.email:
            return {"email_sent": 0, "webhooks_triggered": 0}

        cfg = await settings_service.get_notification_delivery_settings(db, include_secrets=True)
        toggles = await self._effective_toggles(db)

        critical_or_high = [
            v for v in vulnerabilities
            if str(v.get("severity", "")).lower() in ("critical", "high")
        ]
        counts = self._severity_counts(vulnerabilities)

        tasks: list[asyncio.Task] = []

        if toggles["email_on_scan_complete"]:
            subject = f"[SOCIS] Scan completed for {target}"
            body = (
                f"Scan ID: {scan_id}\n"
                f"Target: {target}\n"
                f"Risk Level: {risk_level}\n"
                f"Total Vulnerabilities: {len(vulnerabilities)}\n"
                f"Critical: {counts['critical']} | High: {counts['high']} | Medium: {counts['medium']} | Low: {counts['low']}\n\n"
                f"Open the platform for details: {settings.FRONTEND_URL}/scans/{scan_id}\n"
            )
            tasks.append(asyncio.create_task(self._send_email(cfg, user.email, subject, body)))

        # Note: Slack / Teams / webhook channel notifications are fired by the
        # Builtin Plugin system (SlackPlugin, TeamsPlugin, CustomWebhookPlugin)
        # which runs in the scan_worker hook pipeline — no duplication here.

        if toggles["email_on_vulnerability"] and vulnerabilities:
            subject = f"[SOCIS] Vulnerabilities found on {target}"
            body = (
                f"Scan ID: {scan_id}\n"
                f"Target: {target}\n"
                f"Detected vulnerabilities: {len(vulnerabilities)}\n"
                f"Critical: {counts['critical']} | High: {counts['high']} | Medium: {counts['medium']} | Low: {counts['low']}\n\n"
                f"Review findings: {settings.FRONTEND_URL}/vulnerabilities\n"
            )
            tasks.append(asyncio.create_task(self._send_email(cfg, user.email, subject, body)))

        if toggles["email_on_critical_finding"] and critical_or_high:
            lines = []
            for vuln in critical_or_high[:10]:
                name = str(vuln.get("name") or "Unknown vulnerability")
                sev = str(vuln.get("severity") or "unknown").upper()
                cve = str(vuln.get("cve_id") or "")
                suffix = f" ({cve})" if cve else ""
                lines.append(f"- [{sev}] {name}{suffix}")
            subject = f"[SOCIS] Critical findings on {target}"
            body = (
                f"Scan ID: {scan_id}\n"
                f"Target: {target}\n"
                f"Critical/High findings: {len(critical_or_high)}\n\n"
                + "\n".join(lines)
                + "\n\n"
                + f"Investigate immediately: {settings.FRONTEND_URL}/vulnerabilities\n"
            )
            tasks.append(asyncio.create_task(self._send_email(cfg, user.email, subject, body)))

        results = await asyncio.gather(*tasks, return_exceptions=True) if tasks else []

        email_sent = sum(1 for r in results if isinstance(r, bool) and r)

        return {"email_sent": email_sent, "webhooks_triggered": 0}

    async def send_test_notification(
        self,
        db: AsyncSession,
        user_id: str,
        recipient_email: str,
        include_webhook: bool = True,
    ) -> dict:
        """Send a test notification through configured providers."""
        cfg = await settings_service.get_notification_delivery_settings(db, include_secrets=True)
        subject = "[SOCIS] Test Notification"
        body = (
            "This is a test notification from SOCIS enterprise delivery settings.\n\n"
            f"Configured provider: {cfg.get('provider', 'disabled')}\n"
            "If you received this, provider credentials and routing are working.\n"
        )
        email_ok = await self._send_email(cfg, recipient_email, subject, body)

        return {
            "email_sent": email_ok,
            "webhooks_triggered": 0,
            "provider": cfg.get("provider", "disabled"),
        }


notification_delivery_service = NotificationDeliveryService()
