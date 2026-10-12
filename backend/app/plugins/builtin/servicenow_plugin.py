"""
SOCIS-AI-PT — Built-in Plugin: ServiceNow
Creates ServiceNow incidents for critical/high vulnerabilities via Table API.

Config fields:
  instance_url     (enc) — e.g. https://yourorg.service-now.com
  username         (enc) — ServiceNow username
  password         (enc) — ServiceNow password
  assignment_group       — e.g. "Information Security"
  min_severity           — "critical" | "high" (default: "high")
"""

import logging
import httpx
from app.services.tools.base import BaseSecurityTool

log = logging.getLogger("plugin.servicenow")

PLUGIN_ID = "servicenow"
PLUGIN_META = {
    "id": PLUGIN_ID,
    "name": "ServiceNow",
    "description": "Creates ServiceNow incidents for critical and high severity vulnerabilities via Table API.",
    "category": "Ticketing",
    "icon": "🟢",
    "version": "1.0.0",
    "author": "SOCIS-AI-PT",
    "hooks": ["on_critical_vuln"],
    "fields": [
        {"key": "instance_url",      "label": "Instance URL",      "placeholder": "https://yourorg.service-now.com", "required": True,  "sensitive": True},
        {"key": "username",          "label": "Username",          "placeholder": "svc_pentest",                     "required": True,  "sensitive": True},
        {"key": "password",          "label": "Password",          "placeholder": "••••••••",                        "required": True,  "sensitive": True},
        {"key": "assignment_group",  "label": "Assignment Group",  "placeholder": "Information Security",            "required": False, "sensitive": False},
        {"key": "min_severity",      "label": "Min Severity",      "placeholder": "high",                            "required": False, "sensitive": False,
         "options": ["critical", "high"]},
    ],
}

_SNOW_URGENCY = {"critical": "1", "high": "2", "medium": "3"}
_SNOW_IMPACT  = {"critical": "1", "high": "2", "medium": "3"}


class ServiceNowPlugin(BaseSecurityTool):
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

        url = self._cfg.get("instance_url", "").rstrip("/")
        user = self._cfg.get("username", "")
        pw = self._cfg.get("password", "")
        grp = self._cfg.get("assignment_group", "")

        if not all([url, user, pw]):
            return

        body = {
            "short_description": f"[{severity.upper()}] {vuln_name} — Scan {scan_id[:8]}",
            "description": f"SOCIS-AI-PT detected a {severity.upper()} vulnerability.\n\nVulnerability: {vuln_name}\nScan ID: {scan_id}",
            "urgency": _SNOW_URGENCY.get(severity.lower(), "2"),
            "impact": _SNOW_IMPACT.get(severity.lower(), "2"),
            "category": "Security",
            "subcategory": "Penetration Test",
        }
        if grp:
            body["assignment_group"] = grp

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{url}/api/now/table/incident",
                    json=body,
                    auth=(user, pw),
                    headers={"Accept": "application/json"},
                )
            if resp.status_code in (200, 201):
                sys_id = resp.json().get("result", {}).get("sys_id", "?")
                log.info(f"ServiceNow incident created: {sys_id}")
            else:
                log.error(f"ServiceNow error {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            log.error(f"ServiceNow plugin exception: {exc}")

    async def test_connection(self) -> dict:
        url = self._cfg.get("instance_url", "").rstrip("/")
        user = self._cfg.get("username", "")
        pw = self._cfg.get("password", "")
        if not all([url, user, pw]):
            return {"ok": False, "message": "Missing config"}
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.get(f"{url}/api/now/table/sys_user?sysparm_limit=1",
                                        auth=(user, pw),
                                        headers={"Accept": "application/json"})
            if resp.status_code == 200:
                return {"ok": True, "message": "ServiceNow connection successful"}
            return {"ok": False, "message": f"HTTP {resp.status_code}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
