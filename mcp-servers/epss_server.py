#!/usr/bin/env python3
"""
SOCIS-AI-PT — EPSS MCP Server (HTTP transport)
Exploit Prediction Scoring System — FIRST.org public API.
https://www.first.org/epss/
"""

import httpx
import json
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any
from mcp_auth import verify_mcp_auth, mcp_auth_error

app = FastAPI(title="SOCIS EPSS MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "epss_mcp"
PORT = 8115
EPSS_API = "https://api.first.org/data/v1/epss"


TOOLS = [
    {
        "name": "get_epss_score",
        "description": (
            "Get the EPSS (Exploit Prediction Scoring System) score for a CVE. "
            "EPSS estimates the probability that a CVE will be exploited in the wild "
            "within the next 30 days. Score range: 0.0–1.0 (higher = more likely exploited). "
            "Also returns the percentile rank among all CVEs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE identifier (e.g. CVE-2021-44228)"
                }
            },
            "required": ["cve_id"]
        }
    },
    {
        "name": "get_epss_scores_bulk",
        "description": "Get EPSS scores for multiple CVE IDs in a single call.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_ids": {
                    "type": "string",
                    "description": "Comma-separated CVE IDs (max 100, e.g. CVE-2021-44228,CVE-2022-12345)"
                }
            },
            "required": ["cve_ids"]
        }
    },
    {
        "name": "get_high_epss_cves",
        "description": (
            "Get CVEs with the highest EPSS scores (most likely to be exploited). "
            "Useful for prioritizing patching and remediation work."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "min_score": {
                    "type": "number",
                    "description": "Minimum EPSS score threshold (0.0-1.0, default 0.5)",
                    "default": 0.5
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (default 20, max 100)",
                    "default": 20
                }
            }
        }
    },
    {
        "name": "epss_priority_analysis",
        "description": "Given a list of CVE IDs (comma-separated), return them ranked by EPSS score with exploitation likelihood and remediation priority recommendations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_ids": {
                    "type": "string",
                    "description": "Comma-separated CVE IDs (e.g. CVE-2021-44228,CVE-2022-12345)"
                }
            },
            "required": ["cve_ids"]
        }
    },
]


def _risk_label(score: float) -> str:
    if score >= 0.7:
        return "CRITICAL — Extremely High Exploitation Probability"
    if score >= 0.4:
        return "HIGH — High Exploitation Probability"
    if score >= 0.1:
        return "MEDIUM — Moderate Exploitation Probability"
    if score >= 0.01:
        return "LOW — Low Exploitation Probability"
    return "VERY LOW — Unlikely to be Exploited"


def _priority(score: float) -> str:
    if score >= 0.5:
        return "P1 — Patch immediately"
    if score >= 0.1:
        return "P2 — Patch within 7 days"
    if score >= 0.01:
        return "P3 — Patch within 30 days"
    return "P4 — Schedule for next maintenance window"


async def _fetch_epss(params: dict) -> dict:
    # Cache-aside on the shared intel cache (perf #6). EPSS scores change at most
    # daily, so a 6h TTL massively cuts calls to the rate-limited FIRST API
    # under concurrent scans. Falls back to a direct fetch if cache is absent.
    async def _do_fetch() -> dict:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get(EPSS_API, params=params)
            r.raise_for_status()
            return r.json()

    try:
        from intel_cache import cached
        cache_key = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
        return await cached("epss", cache_key, _do_fetch)
    except Exception:
        # Any cache error must not break the lookup.
        return await _do_fetch()


def _require(arguments: dict, *keys: str) -> None:
    """Raise ValueError with a clear message if any required key is missing."""
    for k in keys:
        if not arguments.get(k):
            raise ValueError(f"Missing required argument: '{k}'")


async def handle_tool(tool_name: str, arguments: dict) -> Any:
    if tool_name == "get_epss_score":
        _require(arguments, "cve_id")
        cve_id = arguments["cve_id"].upper().strip()
        data = await _fetch_epss({"cve": cve_id})
        items = data.get("data", [])
        if not items:
            return {
                "cve_id": cve_id,
                "found": False,
                "message": f"No EPSS score found for {cve_id}. It may be too new or not yet scored."
            }
        item = items[0]
        score = float(item.get("epss", 0))
        percentile = float(item.get("percentile", 0))
        return {
            "cve_id": cve_id,
            "found": True,
            "epss_score": round(score, 6),
            "epss_score_pct": f"{score * 100:.3f}%",
            "percentile": round(percentile, 4),
            "percentile_pct": f"{percentile * 100:.1f}%",
            "risk_label": _risk_label(score),
            "priority": _priority(score),
            "date": item.get("date"),
            "interpretation": (
                f"This CVE has a {score * 100:.2f}% probability of being exploited "
                f"in the wild within 30 days. It ranks higher than "
                f"{percentile * 100:.1f}% of all scored CVEs."
            ),
        }

    elif tool_name == "get_epss_scores_bulk":
        # Accept comma-separated string or array
        cve_input = arguments.get("cve_ids", "")
        if isinstance(cve_input, str):
            cve_ids = [c.strip().upper() for c in cve_input.split(",") if c.strip()][:100]
        else:
            cve_ids = [c.upper().strip() for c in cve_input[:100]]
        
        if not cve_ids:
            return {"error": "No CVE IDs provided", "count": 0, "scores": []}
            
        data = await _fetch_epss({"cve": ",".join(cve_ids)})
        items = data.get("data", [])
        scored = {item["cve"]: item for item in items}
        results = []
        for cve_id in cve_ids:
            item = scored.get(cve_id)
            if item:
                score = float(item.get("epss", 0))
                results.append({
                    "cve_id": cve_id,
                    "epss_score": round(score, 6),
                    "percentile": round(float(item.get("percentile", 0)), 4),
                    "risk_label": _risk_label(score),
                    "priority": _priority(score),
                })
            else:
                results.append({"cve_id": cve_id, "epss_score": None, "found": False})
        results.sort(key=lambda x: x.get("epss_score") or 0, reverse=True)
        return {"count": len(results), "scores": results}

    elif tool_name == "get_high_epss_cves":
        min_score = float(arguments.get("min_score", 0.5))
        # Clamp to 0-1 range
        min_score = max(0.0, min(1.0, min_score))
        limit = min(int(arguments.get("limit", 20)), 100)
        data = await _fetch_epss({"epss-gte": min_score, "order": "!epss", "limit": limit})
        items = data.get("data", [])
        results = []
        for item in items:
            score = float(item.get("epss", 0))
            results.append({
                "cve_id": item.get("cve"),
                "epss_score": round(score, 6),
                "percentile": round(float(item.get("percentile", 0)), 4),
                "risk_label": _risk_label(score),
                "priority": _priority(score),
                "date": item.get("date"),
            })
        return {
            "min_score_threshold": min_score,
            "total_returned": len(results),
            "cves": results,
        }

    elif tool_name == "epss_priority_analysis":
        # Accept comma-separated string or array
        cve_input = arguments.get("cve_ids", "")
        if isinstance(cve_input, str):
            cve_ids = [c.strip().upper() for c in cve_input.split(",") if c.strip()][:100]
        else:
            cve_ids = [c.upper().strip() for c in cve_input[:100]]
        
        if not cve_ids:
            return {"error": "No CVE IDs provided", "count": 0, "scores": []}
            
        data = await _fetch_epss({"cve": ",".join(cve_ids)})
        items = data.get("data", [])
        scored = {item["cve"]: item for item in items}
        results = []
        for cve_id in cve_ids:
            item = scored.get(cve_id)
            if item:
                score = float(item.get("epss", 0))
                results.append({
                    "cve_id": cve_id,
                    "epss_score": round(score, 6),
                    "risk_label": _risk_label(score),
                    "remediation_priority": _priority(score),
                })
            else:
                results.append({"cve_id": cve_id, "epss_score": 0, "risk_label": "UNKNOWN — Not yet scored", "remediation_priority": "P4 — Score unavailable"})

        results.sort(key=lambda x: x.get("epss_score") or 0, reverse=True)
        p1 = [r for r in results if r["remediation_priority"].startswith("P1")]
        p2 = [r for r in results if r["remediation_priority"].startswith("P2")]
        p3 = [r for r in results if r["remediation_priority"].startswith("P3")]
        p4 = [r for r in results if r["remediation_priority"].startswith("P4")]
        return {
            "total_analyzed": len(results),
            "priority_breakdown": {
                "P1_immediate": len(p1),
                "P2_7_days": len(p2),
                "P3_30_days": len(p3),
                "P4_scheduled": len(p4),
            },
            "ranked_cves": results,
        }

    raise ValueError(f"Unknown tool: {tool_name}")


# ─── MCP JSON-RPC Endpoint ────────────────────────────────────

@app.post("/mcp")
async def mcp_endpoint(request: Request):
    if not verify_mcp_auth(request):
        return mcp_auth_error()
    try:
        body = await request.json()
        method = body.get("method", "")
        req_id = body.get("id")
        params = body.get("params", {})

        if method == "initialize":
            return JSONResponse({
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "protocolVersion": MCP_VERSION,
                    "serverInfo": {"name": SERVER_NAME, "version": "1.0.0"},
                    "capabilities": {"tools": {}},
                }
            })

        elif method == "tools/list":
            return JSONResponse({
                "jsonrpc": "2.0", "id": req_id,
                "result": {"tools": TOOLS}
            })

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            try:
                result = await handle_tool(tool_name, arguments)
            except ValueError as ve:
                return JSONResponse({
                    "jsonrpc": "2.0", "id": req_id,
                    "error": {"code": -32602, "message": str(ve)}
                }, status_code=400)
            return JSONResponse({
                "jsonrpc": "2.0", "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}
            })

        else:
            return JSONResponse({
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"}
            })

    except Exception as e:
        return JSONResponse({
            "jsonrpc": "2.0", "id": None,
            "error": {"code": -32603, "message": str(e)}
        }, status_code=500)


@app.get("/health")
async def health():
    return {"status": "ok", "server": SERVER_NAME}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)
