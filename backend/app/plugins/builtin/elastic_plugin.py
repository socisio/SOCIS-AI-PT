"""
SOCIS-AI-PT — Built-in Plugin: Elastic Security (Elasticsearch)
Indexes scan findings into Elasticsearch / Elastic Security via REST API.

Config fields:
  endpoint_url (enc) — e.g. https://my-deployment.es.us-east-1.aws.elastic.cloud
  api_key      (enc) — Elastic API key (id:api_key format)
  index_name         — e.g. socis-pentest-findings
"""

import logging
import httpx
from datetime import datetime, timezone
from app.services.tools.base import BaseSecurityTool

log = logging.getLogger("plugin.elastic")

PLUGIN_ID = "elastic"
PLUGIN_META = {
    "id": PLUGIN_ID,
    "name": "Elastic Security",
    "description": "Indexes scan findings and events into Elasticsearch / Elastic Security SIEM.",
    "category": "SIEM",
    "icon": "🔶",
    "version": "1.0.0",
    "author": "SOCIS-AI-PT",
    "hooks": ["on_scan_complete"],
    "fields": [
        {"key": "endpoint_url", "label": "Elasticsearch URL", "placeholder": "https://my-cluster.es.io:9243",   "required": True,  "sensitive": True},
        {"key": "api_key",      "label": "API Key",           "placeholder": "id:api_key_value",                "required": True,  "sensitive": True},
        {"key": "index_name",   "label": "Index Name",        "placeholder": "socis-pentest-findings",          "required": False, "sensitive": False},
    ],
}


class ElasticPlugin(BaseSecurityTool):
    id = PLUGIN_ID
    name = PLUGIN_META["name"]
    description = PLUGIN_META["description"]

    def __init__(self, config: dict | None = None):
        super().__init__(log)
        self._cfg = config or {}

    async def run(self, target: str, **kwargs) -> dict:
        return self.get_results()

    async def on_scan_complete(self, scan_id: str, findings: list, risk_level: str):
        url = self._cfg.get("endpoint_url", "").rstrip("/")
        key = self._cfg.get("api_key", "")
        index = self._cfg.get("index_name", "socis-pentest-findings")
        if not url or not key:
            return

        doc = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": scan_id,
            "risk_level": risk_level,
            "finding_count": len(findings),
            "critical_count": sum(1 for f in findings if f.get("severity") == "critical"),
            "high_count": sum(1 for f in findings if f.get("severity") == "high"),
            "findings": [
                {"name": f.get("name"), "severity": f.get("severity"), "host": f.get("host")}
                for f in findings[:50]  # cap at 50 to avoid oversized docs
            ],
            "source": "socis-ai-pt",
        }

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{url}/{index}/_doc",
                    json=doc,
                    headers={"Authorization": f"ApiKey {key}", "Content-Type": "application/json"},
                )
            if resp.status_code in (200, 201):
                log.info(f"Elastic: indexed scan {scan_id[:8]}")
            else:
                log.error(f"Elastic error {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            log.error(f"Elastic plugin exception: {exc}")

    async def test_connection(self) -> dict:
        url = self._cfg.get("endpoint_url", "").rstrip("/")
        key = self._cfg.get("api_key", "")
        if not url or not key:
            return {"ok": False, "message": "Missing config"}
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.get(url, headers={"Authorization": f"ApiKey {key}"})
            if resp.status_code == 200:
                data = resp.json()
                return {"ok": True, "message": f"Connected: cluster '{data.get('cluster_name', '?')}'"}
            return {"ok": False, "message": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        except Exception as exc:
            return {"ok": False, "message": str(exc)}
