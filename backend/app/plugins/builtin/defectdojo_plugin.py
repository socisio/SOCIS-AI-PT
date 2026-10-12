"""
SOCIS-AI-PT — Built-in Plugin: DefectDojo
Imports scan findings into a DefectDojo engagement via REST API v2.

Config fields:
  base_url      (enc) — e.g. https://defectdojo.yourorg.com
  api_key       (enc) — DefectDojo API v2 token
  engagement_id       — numeric engagement ID to import into
"""

import logging
import httpx
from datetime import date
from app.services.tools.base import BaseSecurityTool

log = logging.getLogger("plugin.defectdojo")

PLUGIN_ID = "defectdojo"
PLUGIN_META = {
    "id": PLUGIN_ID,
    "name": "DefectDojo",
    "description": "Imports scan findings into a DefectDojo engagement for vulnerability lifecycle management.",
    "category": "Vuln Management",
    "icon": "🛡️",
    "version": "1.0.0",
    "author": "SOCIS-AI-PT",
    "hooks": ["on_scan_complete"],
    "fields": [
        {"key": "base_url",      "label": "DefectDojo URL",   "placeholder": "https://defectdojo.yourorg.com", "required": True,  "sensitive": True},
        {"key": "api_key",       "label": "API Key",          "placeholder": "Token xxxxxxxx",                 "required": True,  "sensitive": True},
        {"key": "engagement_id", "label": "Engagement ID",   "placeholder": "1",                              "required": True,  "sensitive": False},
    ],
}


class DefectDojoPlugin(BaseSecurityTool):
    id = PLUGIN_ID
    name = PLUGIN_META["name"]
    description = PLUGIN_META["description"]

    def __init__(self, config: dict | None = None):
        super().__init__(log)
        self._cfg = config or {}

    async def run(self, target: str, **kwargs) -> dict:
        return self.get_results()

    async def on_scan_complete(self, scan_id: str, findings: list, risk_level: str):
        base_url = self._cfg.get("base_url", "").rstrip("/")
        api_key = self._cfg.get("api_key", "")
        eng_id = self._cfg.get("engagement_id", "")
        if not base_url or not api_key or not eng_id:
            return

        headers = {"Authorization": f"Token {api_key.removeprefix('Token ').strip()}"}

        for finding in findings:
            sev = (finding.get("severity") or "info").capitalize()
            if sev not in ("Critical", "High", "Medium", "Low", "Info"):
                sev = "Info"
            payload = {
                "title": finding.get("name", "Unknown Finding"),
                "severity": sev,
                "description": finding.get("description", "") or f"Finding from SOCIS-AI-PT scan {scan_id[:8]}",
                "engagement": int(eng_id),
                "active": True,
                "verified": False,
                "date": date.today().isoformat(),
            }
            try:
                async with httpx.AsyncClient(timeout=10) as client:
                    resp = await client.post(f"{base_url}/api/v2/findings/", json=payload, headers=headers)
                if resp.status_code in (200, 201):
                    log.info(f"DefectDojo: finding '{payload['title']}' created")
                else:
                    log.error(f"DefectDojo error {resp.status_code}: {resp.text[:200]}")
            except Exception as exc:
                log.error(f"DefectDojo plugin exception: {exc}")

    async def test_connection(self) -> dict:
        base_url = self._cfg.get("base_url", "").rstrip("/")
        api_key = self._cfg.get("api_key", "")
        if not base_url or not api_key:
            return {"ok": False, "message": "Missing config"}
        headers = {"Authorization": f"Token {api_key.removeprefix('Token ').strip()}"}
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.get(f"{base_url}/api/v2/users/?limit=1", headers=headers)
            if resp.status_code == 200:
                return {"ok": True, "message": "DefectDojo connection successful"}
            return {"ok": False, "message": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
