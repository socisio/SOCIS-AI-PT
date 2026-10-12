"""
SOCIS-AI-PT — Built-in Plugin: Splunk HEC
Ships scan findings and events to Splunk via HTTP Event Collector.

Config fields:
  hec_url   (enc) — e.g. https://splunk.yourorg.com:8088/services/collector
  hec_token (enc) — Splunk HEC token
  index           — target index, e.g. "main"
  source          — e.g. "socis-ai-pt"
"""

import json
import logging
import httpx
from app.services.tools.base import BaseSecurityTool

log = logging.getLogger("plugin.splunk_hec")

PLUGIN_ID = "splunk_hec"
PLUGIN_META = {
    "id": PLUGIN_ID,
    "name": "Splunk HEC",
    "description": "Forwards scan findings and events to Splunk via HTTP Event Collector (HEC).",
    "category": "SIEM",
    "icon": "🟠",
    "version": "1.0.0",
    "author": "SOCIS-AI-PT",
    "hooks": ["on_scan_start", "on_scan_complete"],
    "fields": [
        {"key": "hec_url",   "label": "HEC Endpoint URL", "placeholder": "https://splunk.yourorg.com:8088/services/collector", "required": True,  "sensitive": True},
        {"key": "hec_token", "label": "HEC Token",        "placeholder": "••••••••",                                           "required": True,  "sensitive": True},
        {"key": "index",     "label": "Index",            "placeholder": "main",                                               "required": False, "sensitive": False},
        {"key": "source",    "label": "Source",           "placeholder": "socis-ai-pt",                                        "required": False, "sensitive": False},
        {"key": "verify_ssl", "label": "Verify TLS certificate (true/false)", "placeholder": "true",                                    "required": False, "sensitive": False},
    ],
}


class SplunkPlugin(BaseSecurityTool):
    id = PLUGIN_ID
    name = PLUGIN_META["name"]
    description = PLUGIN_META["description"]

    def __init__(self, config: dict | None = None):
        super().__init__(log)
        self._cfg = config or {}

    def _verify_tls(self) -> bool:
        """Verify the Splunk HEC certificate unless the operator explicitly opts out
        (config key `verify_ssl` = false, e.g. a lab Splunk with a self-signed cert)."""
        v = self._cfg.get("verify_ssl", True)
        if isinstance(v, str):
            return v.strip().lower() not in ("false", "0", "no", "off")
        return bool(v)

    async def run(self, target: str, **kwargs) -> dict:
        return self.get_results()

    async def on_scan_start(self, scan_id: str, target: str, tool_config: dict):
        await self._send_event({
            "event_type": "scan_started",
            "scan_id": scan_id,
            "target": target,
        })

    async def on_scan_complete(self, scan_id: str, findings: list, risk_level: str):
        await self._send_event({
            "event_type": "scan_complete",
            "scan_id": scan_id,
            "risk_level": risk_level,
            "finding_count": len(findings),
            "critical_count": sum(1 for f in findings if f.get("severity") == "critical"),
            "high_count": sum(1 for f in findings if f.get("severity") == "high"),
        })

    async def _send_event(self, data: dict):
        url = self._cfg.get("hec_url", "")
        token = self._cfg.get("hec_token", "")
        if not url or not token:
            return

        body = {"event": data, "sourcetype": "_json"}
        idx = self._cfg.get("index")
        src = self._cfg.get("source", "socis-ai-pt")
        if idx:
            body["index"] = idx
        if src:
            body["source"] = src

        try:
            async with httpx.AsyncClient(timeout=8, verify=self._verify_tls()) as client:
                resp = await client.post(url, json=body, headers={"Authorization": f"Splunk {token}"})
            if resp.status_code not in (200, 201):
                log.error(f"Splunk HEC error {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            log.error(f"Splunk plugin exception: {exc}")

    async def test_connection(self) -> dict:
        url = self._cfg.get("hec_url", "")
        token = self._cfg.get("hec_token", "")
        if not url or not token:
            return {"ok": False, "message": "Missing config"}
        try:
            async with httpx.AsyncClient(timeout=8, verify=self._verify_tls()) as client:
                resp = await client.post(
                    url,
                    json={"event": "SOCIS-AI-PT plugin test", "sourcetype": "_json"},
                    headers={"Authorization": f"Splunk {token}"},
                )
            if resp.status_code in (200, 201):
                return {"ok": True, "message": "Test event sent to Splunk"}
            return {"ok": False, "message": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
