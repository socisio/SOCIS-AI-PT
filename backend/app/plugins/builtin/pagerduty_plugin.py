"""
SOCIS-AI-PT — Built-in Plugin: PagerDuty
Triggers PagerDuty incidents for critical/high findings via Events API v2.

Config fields:
  routing_key (enc) — PagerDuty integration key (Events API v2)
  min_severity      — "critical" | "high" (default: "critical")
"""

import logging
import httpx
from app.services.tools.base import BaseSecurityTool

log = logging.getLogger("plugin.pagerduty")

PLUGIN_ID = "pagerduty"
PLUGIN_META = {
    "id": PLUGIN_ID,
    "name": "PagerDuty",
    "description": "Triggers PagerDuty incidents for critical vulnerabilities using Events API v2.",
    "category": "Incident Response",
    "icon": "🔔",
    "version": "1.0.0",
    "author": "SOCIS-AI-PT",
    "hooks": ["on_critical_vuln"],
    "fields": [
        {"key": "routing_key",  "label": "Routing Key (Integration Key)", "placeholder": "R01234ABCDEF...", "required": True,  "sensitive": True},
        {"key": "min_severity", "label": "Min Severity",                   "placeholder": "critical",        "required": False, "sensitive": False,
         "options": ["critical", "high"]},
    ],
}

_PD_SEV = {"critical": "critical", "high": "error", "medium": "warning", "low": "info"}


class PagerDutyPlugin(BaseSecurityTool):
    id = PLUGIN_ID
    name = PLUGIN_META["name"]
    description = PLUGIN_META["description"]

    def __init__(self, config: dict | None = None):
        super().__init__(log)
        self._cfg = config or {}

    async def run(self, target: str, **kwargs) -> dict:
        return self.get_results()

    async def on_critical_vuln(self, scan_id: str, vuln_name: str, severity: str):
        min_sev = self._cfg.get("min_severity", "critical")
        sev_order = ["info", "low", "medium", "high", "critical"]
        if sev_order.index(severity.lower()) < sev_order.index(min_sev):
            return

        key = self._cfg.get("routing_key", "")
        if not key:
            return

        payload = {
            "routing_key": key,
            "event_action": "trigger",
            "dedup_key": f"socis-{scan_id}-{vuln_name}",
            "payload": {
                "summary": f"[{severity.upper()}] {vuln_name}",
                "source": f"SOCIS-AI-PT scan {scan_id[:8]}",
                "severity": _PD_SEV.get(severity.lower(), "error"),
                "custom_details": {
                    "scan_id": scan_id,
                    "vulnerability": vuln_name,
                    "severity": severity,
                },
            },
        }
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.post("https://events.pagerduty.com/v2/enqueue", json=payload)
            if resp.status_code in (200, 202):
                log.info(f"PagerDuty incident triggered for {vuln_name}")
            else:
                log.error(f"PagerDuty error {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            log.error(f"PagerDuty plugin exception: {exc}")

    async def test_connection(self) -> dict:
        key = self._cfg.get("routing_key", "")
        if not key:
            return {"ok": False, "message": "Routing key not configured"}
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.post(
                    "https://events.pagerduty.com/v2/enqueue",
                    json={
                        "routing_key": key,
                        "event_action": "trigger",
                        "dedup_key": "socis-test-connection",
                        "payload": {
                            "summary": "SOCIS-AI-PT plugin test — please acknowledge and resolve",
                            "source": "SOCIS-AI-PT",
                            "severity": "info",
                        },
                    },
                )
            if resp.status_code in (200, 202):
                return {"ok": True, "message": "Test incident created in PagerDuty"}
            return {"ok": False, "message": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
