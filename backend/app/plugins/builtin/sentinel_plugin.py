"""
SOCIS-AI-PT — Built-in Plugin: Microsoft Sentinel
Sends scan data to Azure Sentinel (Log Analytics Workspace) via Data Collector API.

Config fields:
  workspace_id (enc) — Log Analytics Workspace ID
  shared_key   (enc) — Primary or Secondary key from Log Analytics
  log_type           — Custom log type name, e.g. SocisAIPT
"""

import base64
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
import httpx
from app.services.tools.base import BaseSecurityTool

log = logging.getLogger("plugin.sentinel")

PLUGIN_ID = "sentinel"
PLUGIN_META = {
    "id": PLUGIN_ID,
    "name": "Microsoft Sentinel",
    "description": "Sends scan findings and events to Azure Sentinel via the Log Analytics Data Collector API.",
    "category": "SIEM",
    "icon": "🔷",
    "version": "1.0.0",
    "author": "SOCIS-AI-PT",
    "hooks": ["on_scan_complete"],
    "fields": [
        {"key": "workspace_id", "label": "Workspace ID",  "placeholder": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "required": True,  "sensitive": True},
        {"key": "shared_key",   "label": "Shared Key",   "placeholder": "base64-encoded-key",                   "required": True,  "sensitive": True},
        {"key": "log_type",     "label": "Log Type Name","placeholder": "SocisAIPT",                            "required": False, "sensitive": False},
    ],
}


def _build_signature(workspace_id: str, shared_key: str, date: str, content_length: int, method: str,
                     content_type: str, resource: str) -> str:
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    bytes_to_hash = string_to_hash.encode("utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    return f"SharedKey {workspace_id}:{encoded_hash}"


class SentinelPlugin(BaseSecurityTool):
    id = PLUGIN_ID
    name = PLUGIN_META["name"]
    description = PLUGIN_META["description"]

    def __init__(self, config: dict | None = None):
        super().__init__(log)
        self._cfg = config or {}

    async def run(self, target: str, **kwargs) -> dict:
        return self.get_results()

    async def on_scan_complete(self, scan_id: str, findings: list, risk_level: str):
        ws_id = self._cfg.get("workspace_id", "")
        key = self._cfg.get("shared_key", "")
        log_type = self._cfg.get("log_type", "SocisAIPT")
        if not ws_id or not key:
            return

        body = json.dumps([{
            "TimeGenerated": datetime.now(timezone.utc).isoformat(),
            "ScanId": scan_id,
            "RiskLevel": risk_level,
            "FindingCount": len(findings),
            "CriticalCount": sum(1 for f in findings if f.get("severity") == "critical"),
            "HighCount": sum(1 for f in findings if f.get("severity") == "high"),
            "Source": "SOCIS-AI-PT",
        }])

        rfc1123_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        resource = "/api/logs"
        content_type = "application/json"
        signature = _build_signature(ws_id, key, rfc1123_date, len(body), "POST", content_type, resource)

        url = f"https://{ws_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    url, data=body,
                    headers={
                        "Content-Type": content_type,
                        "Log-Type": log_type,
                        "x-ms-date": rfc1123_date,
                        "Authorization": signature,
                    },
                )
            if resp.status_code in (200, 202):
                log.info(f"Sentinel: data sent for scan {scan_id[:8]}")
            else:
                log.error(f"Sentinel error {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            log.error(f"Sentinel plugin exception: {exc}")

    async def test_connection(self) -> dict:
        ws_id = self._cfg.get("workspace_id", "")
        key = self._cfg.get("shared_key", "")
        if not ws_id or not key:
            return {"ok": False, "message": "Missing config"}
        # Attempt a minimal POST with a test event
        log_type = self._cfg.get("log_type", "SocisAIPT")
        body = json.dumps([{"TimeGenerated": datetime.now(timezone.utc).isoformat(),
                            "Source": "SOCIS-AI-PT", "EventType": "connection_test"}])
        rfc1123_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        resource = "/api/logs"
        content_type = "application/json"
        signature = _build_signature(ws_id, key, rfc1123_date, len(body), "POST", content_type, resource)
        url = f"https://{ws_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    url, data=body,
                    headers={
                        "Content-Type": content_type,
                        "Log-Type": log_type,
                        "x-ms-date": rfc1123_date,
                        "Authorization": signature,
                    },
                )
            if resp.status_code in (200, 202):
                return {"ok": True, "message": "Test event sent to Sentinel"}
            return {"ok": False, "message": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
