"""
SOCIS-AI-PT — Built-in Plugin: Custom Webhook
Posts JSON payloads to any HTTP endpoint on any scan lifecycle event.

Config fields:
  url              (enc) — Webhook endpoint URL
  secret           (enc) — Optional HMAC-SHA256 secret for signature header
  events                 — Comma-separated events to fire on: scan_start, tool_complete, scan_complete, critical_vuln
  payload_template       — Optional Jinja2-style template (unused in v1; sends full payload)
"""

import hashlib
import hmac
import json
import logging
import httpx
from datetime import datetime, timezone
from app.services.tools.base import BaseSecurityTool

log = logging.getLogger("plugin.custom_webhook")

PLUGIN_ID = "custom_webhook"
PLUGIN_META = {
    "id": PLUGIN_ID,
    "name": "Custom Webhook",
    "description": "Posts structured JSON payloads to any HTTP endpoint on configurable scan lifecycle events.",
    "category": "Communication",
    "icon": "🔗",
    "version": "1.0.0",
    "author": "SOCIS-AI-PT",
    "hooks": ["on_scan_start", "on_tool_complete", "on_scan_complete", "on_critical_vuln"],
    "fields": [
        {"key": "url",    "label": "Webhook URL", "placeholder": "https://your-service.com/webhook", "required": True,  "sensitive": True},
        {"key": "secret", "label": "HMAC Secret", "placeholder": "optional signing secret",          "required": False, "sensitive": True},
        {"key": "events", "label": "Events",       "placeholder": "scan_complete,critical_vuln",     "required": False, "sensitive": False,
         "options": ["scan_start", "tool_complete", "scan_complete", "critical_vuln"],
         "multiselect": True},
    ],
}


def _sign_body(body_bytes: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()


class CustomWebhookPlugin(BaseSecurityTool):
    id = PLUGIN_ID
    name = PLUGIN_META["name"]
    description = PLUGIN_META["description"]

    def __init__(self, config: dict | None = None):
        super().__init__(log)
        self._cfg = config or {}

    async def run(self, target: str, **kwargs) -> dict:
        return self.get_results()

    def _allowed(self, event: str) -> bool:
        raw = self._cfg.get("events", "")
        if not raw:
            return True  # default: fire on all events
        return event in [e.strip() for e in raw.split(",")]

    async def on_scan_start(self, scan_id: str, target: str, tool_config: dict):
        if self._allowed("scan_start"):
            await self._post({"event": "scan_start", "scan_id": scan_id, "target": target})

    async def on_tool_complete(self, scan_id: str, tool_name: str, result: dict):
        if self._allowed("tool_complete"):
            await self._post({"event": "tool_complete", "scan_id": scan_id, "tool": tool_name,
                              "finding_count": len(result.get("findings", []))})

    async def on_scan_complete(self, scan_id: str, findings: list, risk_level: str):
        if self._allowed("scan_complete"):
            await self._post({"event": "scan_complete", "scan_id": scan_id, "risk_level": risk_level,
                              "finding_count": len(findings)})

    async def on_critical_vuln(self, scan_id: str, vuln_name: str, severity: str):
        if self._allowed("critical_vuln"):
            await self._post({"event": "critical_vuln", "scan_id": scan_id,
                              "vulnerability": vuln_name, "severity": severity})

    async def _post(self, data: dict):
        url = self._cfg.get("url", "")
        if not url:
            return
        data["timestamp"] = datetime.now(timezone.utc).isoformat()
        body_bytes = json.dumps(data).encode()
        headers = {"Content-Type": "application/json"}
        secret = self._cfg.get("secret", "")
        if secret:
            sig = _sign_body(body_bytes, secret)
            headers["X-SOCIS-Signature"] = f"sha256={sig}"
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.post(url, content=body_bytes, headers=headers)
            if resp.status_code not in range(200, 300):
                log.error(f"Custom webhook error {resp.status_code}: {resp.text[:100]}")
        except Exception as exc:
            log.error(f"Custom webhook exception: {exc}")

    async def test_connection(self) -> dict:
        url = self._cfg.get("url", "")
        if not url:
            return {"ok": False, "message": "Webhook URL not configured"}
        try:
            await self._post({"event": "test", "message": "SOCIS-AI-PT plugin connection test"})
            return {"ok": True, "message": "Test payload sent to webhook"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
