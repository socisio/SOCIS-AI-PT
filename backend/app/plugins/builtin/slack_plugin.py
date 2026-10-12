"""
SOCIS-AI-PT — Built-in Plugin: Slack
Posts Block Kit alert cards to a Slack channel on critical/high vulnerabilities.

Config fields:
  webhook_url (enc) — Slack Incoming Webhook URL
  channel         — override channel, e.g. #security-alerts (optional)
  min_severity    — "critical" | "high" (default: "high")
"""

import logging
import httpx
from app.services.tools.base import BaseSecurityTool

log = logging.getLogger("plugin.slack")

PLUGIN_ID = "slack"
PLUGIN_META = {
    "id": PLUGIN_ID,
    "name": "Slack",
    "description": "Posts rich Block Kit alert messages to a Slack channel when vulnerabilities are found.",
    "category": "Communication",
    "icon": "💬",
    "version": "1.0.0",
    "author": "SOCIS-AI-PT",
    "hooks": ["on_critical_vuln", "on_scan_complete"],
    "fields": [
        {"key": "webhook_url",  "label": "Slack Webhook URL",  "placeholder": "https://hooks.slack.com/services/...", "required": True,  "sensitive": True},
        {"key": "channel",      "label": "Channel Override",   "placeholder": "#security-alerts",                    "required": False, "sensitive": False},
        {"key": "min_severity", "label": "Min Severity",       "placeholder": "high",                                "required": False, "sensitive": False,
         "options": ["critical", "high"]},
    ],
}

_SEV_COLOR = {"critical": "#ff3366", "high": "#f97316", "medium": "#f59e0b", "low": "#22c55e"}


class SlackPlugin(BaseSecurityTool):
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
        await self._post({
            "text": f"🚨 *{severity.upper()} Finding*: {vuln_name}",
            "attachments": [{
                "color": _SEV_COLOR.get(severity.lower(), "#94a3b8"),
                "blocks": [
                    {"type": "header", "text": {"type": "plain_text", "text": f"🚨 {severity.upper()}: {vuln_name}"}},
                    {"type": "section", "fields": [
                        {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id[:8]}`"},
                        {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                    ]},
                ],
            }],
        })

    async def on_scan_complete(self, scan_id: str, findings: list, risk_level: str):
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        await self._post({
            "text": f"✅ Scan `{scan_id[:8]}` complete — Risk: *{risk_level.upper()}*",
            "attachments": [{
                "color": _SEV_COLOR.get(risk_level.lower(), "#94a3b8"),
                "blocks": [
                    {"type": "header", "text": {"type": "plain_text", "text": f"Scan Complete — {risk_level.upper()} Risk"}},
                    {"type": "section", "fields": [
                        {"type": "mrkdwn", "text": f"*Critical:*\n{critical}"},
                        {"type": "mrkdwn", "text": f"*High:*\n{high}"},
                        {"type": "mrkdwn", "text": f"*Total Findings:*\n{len(findings)}"},
                        {"type": "mrkdwn", "text": f"*Scan ID:*\n`{scan_id[:8]}`"},
                    ]},
                ],
            }],
        })

    async def _post(self, body: dict):
        url = self._cfg.get("webhook_url", "")
        if not url:
            return
        channel = self._cfg.get("channel")
        if channel:
            body["channel"] = channel
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.post(url, json=body)
            if resp.status_code != 200:
                log.error(f"Slack error {resp.status_code}: {resp.text[:100]}")
        except Exception as exc:
            log.error(f"Slack plugin exception: {exc}")

    async def test_connection(self) -> dict:
        url = self._cfg.get("webhook_url", "")
        if not url:
            return {"ok": False, "message": "Webhook URL not configured"}
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.post(url, json={"text": "✅ SOCIS-AI-PT plugin test — connection OK"})
            if resp.status_code == 200:
                return {"ok": True, "message": "Test message delivered to Slack"}
            return {"ok": False, "message": f"HTTP {resp.status_code}: {resp.text[:100]}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
