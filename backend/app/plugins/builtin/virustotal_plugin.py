"""
SOCIS-AI-PT — Built-in Plugin: VirusTotal
Looks up target IPs/domains against VirusTotal before a scan starts to provide threat intel context.

Config fields:
  api_key (enc) — VirusTotal v3 API key
"""

import logging
import httpx
from app.services.tools.base import BaseSecurityTool

log = logging.getLogger("plugin.virustotal")

PLUGIN_ID = "virustotal"
PLUGIN_META = {
    "id": PLUGIN_ID,
    "name": "VirusTotal",
    "description": "Queries VirusTotal for threat intelligence on target IP/domain before each scan.",
    "category": "Intel",
    "icon": "🔍",
    "version": "1.0.0",
    "author": "SOCIS-AI-PT",
    "hooks": ["on_scan_start"],
    "fields": [
        {"key": "api_key", "label": "VirusTotal API Key", "placeholder": "••••••••", "required": True, "sensitive": True},
    ],
}

_VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalPlugin(BaseSecurityTool):
    id = PLUGIN_ID
    name = PLUGIN_META["name"]
    description = PLUGIN_META["description"]

    def __init__(self, config: dict | None = None):
        super().__init__(log)
        self._cfg = config or {}

    async def run(self, target: str, **kwargs) -> dict:
        return self.get_results()

    async def on_scan_start(self, scan_id: str, target: str, tool_config: dict):
        key = self._cfg.get("api_key", "")
        if not key:
            return
        headers = {"x-apikey": key}
        # Determine resource type: IP vs domain
        import re
        is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
        endpoint = f"{_VT_BASE}/ip_addresses/{target}" if is_ip else f"{_VT_BASE}/domains/{target}"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(endpoint, headers=headers)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                malicious = data.get("last_analysis_stats", {}).get("malicious", 0)
                reputation = data.get("reputation", 0)
                log.info(
                    f"VirusTotal [{target}]: malicious detections={malicious}, reputation={reputation}"
                )
            elif resp.status_code == 404:
                log.info(f"VirusTotal: {target} not found in database")
            else:
                log.warning(f"VirusTotal API returned {resp.status_code}")
        except Exception as exc:
            log.error(f"VirusTotal plugin exception: {exc}")

    async def test_connection(self) -> dict:
        key = self._cfg.get("api_key", "")
        if not key:
            return {"ok": False, "message": "API key not configured"}
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.get(f"{_VT_BASE}/users/current", headers={"x-apikey": key})
            if resp.status_code == 200:
                email = resp.json().get("data", {}).get("attributes", {}).get("email", "?")
                return {"ok": True, "message": f"Connected as {email}"}
            return {"ok": False, "message": f"HTTP {resp.status_code}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
