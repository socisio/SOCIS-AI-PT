"""
SOCIS-AI-PT — Built-in Plugin: Jira
Creates Jira issues for critical/high vulnerabilities found during scans.

Config fields:
  jira_url        — e.g. https://yourorg.atlassian.net
  project_key     — e.g. SEC
  api_token (enc) — Jira API token (Basic auth with email)
  email    (enc)  — Jira account email
  issue_type      — defaults to "Bug"
  min_severity    — "critical" | "high" (default: "high")
"""

import json
import logging
import httpx
from app.services.tools.base import BaseSecurityTool

log = logging.getLogger("plugin.jira")

PLUGIN_ID = "jira"
PLUGIN_META = {
    "id": PLUGIN_ID,
    "name": "Jira",
    "description": "Automatically creates Jira issues for critical and high severity vulnerabilities.",
    "category": "Ticketing",
    "icon": "🔵",
    "version": "1.0.0",
    "author": "SOCIS-AI-PT",
    "hooks": ["on_critical_vuln"],
    "fields": [
        {"key": "jira_url",    "label": "Jira Base URL",    "placeholder": "https://yourorg.atlassian.net", "required": True,  "sensitive": False},
        {"key": "project_key", "label": "Project Key",      "placeholder": "SEC",                          "required": True,  "sensitive": False},
        {"key": "email",       "label": "Jira Email",       "placeholder": "user@company.com",             "required": True,  "sensitive": True},
        {"key": "api_token",   "label": "API Token",        "placeholder": "••••••••",                     "required": True,  "sensitive": True},
        {"key": "issue_type",  "label": "Issue Type",       "placeholder": "Bug",                          "required": False, "sensitive": False},
        {"key": "min_severity","label": "Min Severity",     "placeholder": "high",                         "required": False, "sensitive": False,
         "options": ["critical", "high"]},
    ],
}


class JiraPlugin(BaseSecurityTool):
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

        url = self._cfg.get("jira_url", "").rstrip("/")
        project = self._cfg.get("project_key", "")
        email = self._cfg.get("email", "")
        token = self._cfg.get("api_token", "")
        issue_type = self._cfg.get("issue_type", "Bug")

        if not all([url, project, email, token]):
            log.warning("Jira plugin: missing config, skipping.")
            return

        payload = {
            "fields": {
                "project": {"key": project},
                "summary": f"[{severity.upper()}] {vuln_name} — Scan {scan_id[:8]}",
                "description": {
                    "type": "doc", "version": 1,
                    "content": [{"type": "paragraph", "content": [
                        {"type": "text", "text": f"Severity: {severity.upper()}\nScan ID: {scan_id}\nVulnerability: {vuln_name}"}
                    ]}]
                },
                "issuetype": {"name": issue_type},
                "priority": {"name": "Critical" if severity == "critical" else "High"},
                "labels": ["socis-ai-pt", "pentest", severity],
            }
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{url}/rest/api/3/issue",
                    json=payload,
                    auth=(email, token),
                    headers={"Accept": "application/json"},
                )
            if resp.status_code in (200, 201):
                issue_key = resp.json().get("key", "?")
                log.info(f"Jira issue created: {issue_key} for {vuln_name}")
            else:
                log.error(f"Jira API error {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            log.error(f"Jira plugin exception: {exc}")

    async def test_connection(self) -> dict:
        url = self._cfg.get("jira_url", "").rstrip("/")
        email = self._cfg.get("email", "")
        token = self._cfg.get("api_token", "")
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.get(f"{url}/rest/api/3/myself", auth=(email, token))
            if resp.status_code == 200:
                data = resp.json()
                return {"ok": True, "message": f"Connected as {data.get('displayName', email)}"}
            return {"ok": False, "message": f"HTTP {resp.status_code}: {resp.text[:100]}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
