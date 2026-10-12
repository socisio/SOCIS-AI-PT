"""
webhook_service.py — Fire webhooks with HMAC-SHA256 signatures.
"""

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import socket
import time
import uuid
from typing import List, Optional
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.webhook import Webhook

logger = logging.getLogger(__name__)
_BACKGROUND: set = set()   # keeps fire-and-forget delivery tasks alive until they finish

def _validate_webhook_url(url: str) -> None:
    """Raise ValueError if the URL (or ANY address it resolves to) is internal/non-public.

    Delegates to app.core.netguard: stdlib address classification (not a hand-written
    network list), IPv4-mapped IPv6 unwrapped, every resolved record checked.
    """
    from app.core.netguard import check_url
    check_url(url, allow_private=False)


class WebhookService:
    """Dispatch signed HTTP POST payloads to registered webhook URLs."""

    def _sign(self, secret: str, payload: bytes) -> str:
        """Return HMAC-SHA256 hex digest of payload."""
        return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()

    async def _select(self, db: AsyncSession, event: str, user_id: Optional[str]) -> List[dict]:
        """Active webhooks subscribed to `event`, as plain dicts (so delivery needs no database session)."""
        query = select(Webhook).where(Webhook.is_active == True, Webhook.events.any(event))  # type: ignore[arg-type]
        if user_id:
            query = query.where(Webhook.user_id == uuid.UUID(user_id))
        rows = (await db.execute(query)).scalars().all()
        return [{"id": str(w.id), "url": w.url, "secret": w.secret} for w in rows]

    async def _deliver(self, items: List[dict], event: str, payload: dict) -> List[dict]:
        """POST the signed payload to each target. Never raises; one bad URL does not stop the others."""
        if not items:
            return []
        body = json.dumps({"event": event, "timestamp": int(time.time()), "data": payload}, default=str).encode()
        results = []
        async with httpx.AsyncClient(timeout=10.0) as client:       # redirects are NOT followed (SSRF)
            for wh in items:
                headers = {"Content-Type": "application/json", "X-SOCIS-Event": event, "X-SOCIS-Delivery": str(uuid.uuid4())}
                if wh["secret"]:
                    from app.core.encryption import decrypt_secret
                    try:
                        headers["X-SOCIS-Signature-256"] = f"sha256={self._sign(decrypt_secret(wh['secret']), body)}"
                    except Exception as e:
                        logger.error(f"Error decrypting webhook secret for {wh['id']}: {e}")
                try:
                    _validate_webhook_url(wh["url"])
                    resp = await client.post(wh["url"], content=body, headers=headers)
                    results.append({"webhook_id": wh["id"], "status": resp.status_code, "ok": resp.is_success})
                    logger.info("Webhook %s -> %s: %s", wh["id"], wh["url"], resp.status_code)
                except ValueError as ve:
                    results.append({"webhook_id": wh["id"], "error": f"Blocked: {ve}", "ok": False})
                    logger.warning("Webhook %s blocked (SSRF protection): %s", wh["id"], ve)
                except Exception as exc:
                    results.append({"webhook_id": wh["id"], "error": str(exc)[:200], "ok": False})
                    logger.warning("Webhook %s delivery failed: %s", wh["id"], exc)
        return results

    async def fire(self, db: AsyncSession, event: str, payload: dict, user_id: Optional[str] = None) -> List[dict]:
        """Deliver to every active webhook subscribed to `event` and WAIT for the results."""
        return await self._deliver(await self._select(db, event, user_id), event, payload)

    def fire_background(self, items: List[dict], event: str, payload: dict) -> None:
        """Deliver without making the caller (the scan worker) wait for slow receivers."""
        if not items:
            return
        task = asyncio.create_task(self._deliver(items, event, payload))
        _BACKGROUND.add(task)
        task.add_done_callback(_BACKGROUND.discard)

    async def test_one(self, wh_id: str, url: str, secret: Optional[str], payload: dict) -> List[dict]:
        """Send a test event to ONE webhook regardless of which events it is subscribed to (the old ping only reached webhooks
        subscribed to the literal event "ping", so testing a normal webhook showed nothing)."""
        return await self._deliver([{"id": wh_id, "url": url, "secret": secret}], "ping", payload)


webhook_service = WebhookService()


async def emit_scan_event(db: AsyncSession, scan, event: str, error: Optional[str] = None) -> None:
    """Called by the scan worker / cancel endpoint right after a scan reaches a terminal state.
    Never raises (a webhook problem must never affect a scan) and never waits on a receiver."""
    try:
        from sqlalchemy import func
        from app.core.webhook_events import build_scan_payload, critical_items, severity_counts
        from app.models.vulnerability import Vulnerability, Severity
        user_id = str(scan.initiated_by)
        counts = None
        crit: list = []
        if event in ("scan.completed", "finding.critical"):
            rows = (await db.execute(
                select(Vulnerability.severity, func.count()).where(Vulnerability.scan_id == scan.id).group_by(Vulnerability.severity)
            )).all()
            counts = severity_counts(rows)
            if event == "finding.critical":
                vs = (await db.execute(
                    select(Vulnerability).where(Vulnerability.scan_id == scan.id, Vulnerability.severity == Severity.CRITICAL).limit(10)
                )).scalars().all()
                crit = critical_items([{"name": v.vuln_name, "cve_id": v.cve_id, "port": v.port} for v in vs])
        payload = build_scan_payload(
            event=event, scan_id=scan.id, target=scan.target, scan_type=scan.scan_type, project_id=scan.project_id,
            status=scan.status, risk_level=scan.risk_level, started_at=scan.started_at, completed_at=scan.completed_at,
            counts=counts, error=error, critical=crit,
        )
        webhook_service.fire_background(await webhook_service._select(db, event, user_id), event, payload)
        if event == "scan.completed" and counts and counts.get("critical"):
            await emit_scan_event(db, scan, "finding.critical")
    except Exception as exc:                                   # noqa: BLE001
        logger.warning("Could not emit %s webhook event: %s", event, exc)
