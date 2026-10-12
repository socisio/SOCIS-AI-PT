"""
SOCIS-AI-PT — Built-in Plugin: TheHive
Creates TheHive alerts for critical/high vulnerabilities via TheHive REST API.

Config fields:
  base_url (enc) — e.g. https://thehive.yourorg.com
  api_key  (enc) — TheHive API key
  org            — TheHive organisation (optional, leave blank for default)
"""

import logging
import httpx
from datetime import datetime, timezone
from app.services.tools.base import BaseSecurityTool

log = logging.getLogger("plugin.thehive")

PLUGIN_ID = "thehive"
PLUGIN_META = {
    "id": PLUGIN_ID,
    "name": "TheHive",
    "description": "Creates TheHive alerts for critical and high severity vulnerabilities.",
    "category": "Incident Response",
    "icon": "🐝",
    "version": "1.0.0",
    "author": "SOCIS-AI-PT",
    "hooks": ["on_critical_vuln"],
    "fields": [
        {"key": "base_url", "label": "TheHive URL", "placeholder": "https://thehive.yourorg.com", "required": True,  "sensitive": True},
        {"key": "api_key",  "label": "API Key",     "placeholder": "••••••••",                    "required": True,  "sensitive": True},
        {"key": "org",      "label": "Organisation","placeholder": "MyOrg",                       "required": False, "sensitive": False},
    ],
}

_SEV_MAP = {"critical": 3, "high": 2, "medium": 1, "low": 0}


class TheHivePlugin(BaseSecurityTool):
    id = PLUGIN_ID
    name = PLUGIN_META["name"]
    description = PLUGIN_META["description"]

    def __init__(self, config: dict | None = None):
        super().__init__(log)
        self._cfg = config or {}

    async def run(self, target: str, **kwargs) -> dict:
        return self.get_results()

    async def on_critical_vuln(self, scan_id: str, vuln_name: str, severity: str):
        url = self._cfg.get("base_url", "").rstrip("/")
        key = self._cfg.get("api_key", "")
        if not url or not key:
            return

        headers = {"Authorization": f"Bearer {key}"}
        org = self._cfg.get("org")
        if org:
            headers["X-Organisation"] = org

        payload = {
            "type": "socis-ai-pt",
            "source": "SOCIS-AI-PT",
            "sourceRef": f"socis-{scan_id[:8]}-{vuln_name[:30]}",
            "title": f"[{severity.upper()}] {vuln_name}",
            "description": f"Severity: **{severity.upper()}**\n\nScan ID: `{scan_id}`\n\nVulnerability: {vuln_name}",
            "severity": _SEV_MAP.get(severity.lower(), 1),
            "tags": ["socis-ai-pt", "pentest", severity],
            "date": int(datetime.now(timezone.utc).timestamp() * 1000),
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(f"{url}/api/v1/alert", json=payload, headers=headers)
            if resp.status_code in (200, 201):
                alert_id = resp.json().get("_id", "?")
                log.info(f"TheHive alert created: {alert_id}")
            else:
                log.error(f"TheHive error {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            log.error(f"TheHive plugin exception: {exc}")

    async def test_connection(self) -> dict:
        url = self._cfg.get("base_url", "").rstrip("/")
        key = self._cfg.get("api_key", "")
        if not url or not key:
            return {"ok": False, "message": "Missing config"}
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.get(f"{url}/api/v1/user/current",
                                        headers={"Authorization": f"Bearer {key}"})
            if resp.status_code == 200:
                name = resp.json().get("name", "?")
                return {"ok": True, "message": f"Connected as {name}"}
            return {"ok": False, "message": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
