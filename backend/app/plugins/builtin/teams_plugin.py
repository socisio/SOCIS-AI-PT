"""
SOCIS-AI-PT — Built-in Plugin: Microsoft Teams
Posts Adaptive Card alerts to a Teams channel via Incoming Webhook.

Config fields:
  webhook_url (enc) — Teams Incoming Webhook URL
  min_severity    — "critical" | "high" (default: "high")
"""

import logging
import httpx
from app.services.tools.base import BaseSecurityTool

log = logging.getLogger("plugin.teams")

PLUGIN_ID = "teams"
PLUGIN_META = {
    "id": PLUGIN_ID,
    "name": "Microsoft Teams",
    "description": "Sends Adaptive Card alerts to a Microsoft Teams channel for scan findings.",
    "category": "Communication",
    "icon": "🟣",
    "version": "1.0.0",
    "author": "SOCIS-AI-PT",
    "hooks": ["on_critical_vuln", "on_scan_complete"],
    "fields": [
        {"key": "webhook_url",  "label": "Teams Webhook URL", "placeholder": "https://outlook.office.com/webhook/...", "required": True,  "sensitive": True},
        {"key": "min_severity", "label": "Min Severity",      "placeholder": "high",                                  "required": False, "sensitive": False,
         "options": ["critical", "high"]},
    ],
}

_SEV_COLOR = {"critical": "attention", "high": "warning", "medium": "accent", "low": "good"}


class TeamsPlugin(BaseSecurityTool):
    id = PLUGIN_ID
    name = PLUGIN_META["name"]
    description = PLUGIN_META["description"]

    def __init__(self, config: dict | None = None):
        super().__init__(log)
        self._cfg = config or {}

    async def run(self, target: str, **kwargs) -> dict:
        return self.get_results()

    async def on_critical_vuln(self, scan_id: str, vuln_name: str, severity: str):
        min_sev = self._cfg.get("min_severity", "high")
        sev_order = ["info", "low", "medium", "high", "critical"]
        if sev_order.index(severity.lower()) < sev_order.index(min_sev):
            return
        body = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard", "version": "1.4",
                    "body": [
                        {"type": "TextBlock", "size": "Large", "weight": "Bolder",
                         "text": f"🚨 {severity.upper()}: {vuln_name}", "color": _SEV_COLOR.get(severity.lower(), "default")},
                        {"type": "FactSet", "facts": [
                            {"title": "Scan ID", "value": scan_id[:8]},
                            {"title": "Severity", "value": severity.upper()},
                        ]},
                    ],
                },
            }],
        }
        await self._post(body)

    async def on_scan_complete(self, scan_id: str, findings: list, risk_level: str):
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        body = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard", "version": "1.4",
                    "body": [
                        {"type": "TextBlock", "size": "Large", "weight": "Bolder",
                         "text": f"✅ Scan Complete — Risk: {risk_level.upper()}"},
                        {"type": "FactSet", "facts": [
                            {"title": "Scan ID", "value": scan_id[:8]},
                            {"title": "Risk", "value": risk_level.upper()},
                            {"title": "Critical", "value": str(critical)},
                            {"title": "High", "value": str(high)},
                            {"title": "Total Findings", "value": str(len(findings))},
                        ]},
                    ],
                },
            }],
        }
        await self._post(body)

    async def _post(self, body: dict):
        url = self._cfg.get("webhook_url", "")
        if not url:
            return
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.post(url, json=body)
            if resp.status_code not in (200, 202):
                log.error(f"Teams error {resp.status_code}: {resp.text[:100]}")
        except Exception as exc:
            log.error(f"Teams plugin exception: {exc}")

    async def test_connection(self) -> dict:
        url = self._cfg.get("webhook_url", "")
        if not url:
            return {"ok": False, "message": "Webhook URL not configured"}
        body = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard", "version": "1.4",
                    "body": [{"type": "TextBlock", "text": "✅ SOCIS-AI-PT plugin test — connection OK"}],
                },
            }],
        }
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.post(url, json=body)
            if resp.status_code in (200, 202):
                return {"ok": True, "message": "Test card sent to Teams"}
            return {"ok": False, "message": f"HTTP {resp.status_code}: {resp.text[:100]}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
