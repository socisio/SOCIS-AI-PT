#!/usr/bin/env python3
"""
SOCIS-AI-PT — CISA KEV MCP Server (HTTP transport)
Provides access to CISA's Known Exploited Vulnerabilities (KEV) catalog.
Public API: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
"""

import httpx
import json
import uvicorn
import logging
from datetime import datetime, timezone
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any
from mcp_auth import verify_mcp_auth, mcp_auth_error

logger = logging.getLogger(__name__)

app = FastAPI(title="SOCIS CISA KEV MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "cisa_kev_mcp"
PORT = 8114
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Simple in-process cache — refreshed every 6 hours
_cache: dict = {"data": None, "fetched_at": None}
CACHE_TTL_SECONDS = 6 * 3600


TOOLS = [
    {
        "name": "check_kev",
        "description": (
            "Check whether a specific CVE is listed in the CISA Known Exploited "
            "Vulnerabilities (KEV) catalog. Returns full KEV entry if found, including "
            "required remediation date and ransomware campaign association."
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
        "name": "search_kev",
        "description": (
            "Search the CISA KEV catalog by keyword (vendor, product, vulnerability name). "
            "Returns matching entries with remediation deadlines."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "keyword": {
                    "type": "string",
                    "description": "Search term: vendor name, product, or vulnerability name"
                },
                "ransomware_only": {
                    "type": "boolean",
                    "description": "Filter to only CVEs associated with ransomware campaigns",
                    "default": False
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results to return (default 15, max 50)",
                    "default": 15
                }
            },
            "required": ["keyword"]
        }
    },
    {
        "name": "get_kev_stats",
        "description": (
            "Get summary statistics of the current CISA KEV catalog: total count, "
            "most recent additions, top vendors, ransomware-associated count."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "top_n": {
                    "type": "integer",
                    "description": "Number of top vendors to return",
                    "default": 10
                }
            }
        }
    },
    {
        "name": "get_recent_kev",
        "description": "Get the most recently added CVEs to the CISA KEV catalog.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "days": {
                    "type": "integer",
                    "description": "How many days back to look (default 30)",
                    "default": 30
                },
                "limit": {
                    "type": "integer",
                    "description": "Max entries to return",
                    "default": 20
                }
            }
        }
    }
]


async def _get_kev_data() -> list[dict]:
    """Fetch KEV catalog with caching."""
    now = datetime.now(timezone.utc).timestamp()
    if (
        _cache["data"] is not None
        and _cache["fetched_at"] is not None
        and (now - _cache["fetched_at"]) < CACHE_TTL_SECONDS
    ):
        return _cache["data"]

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(KEV_URL)
        r.raise_for_status()
        catalog = r.json()

    vulns = catalog.get("vulnerabilities", [])
    _cache["data"] = vulns
    _cache["fetched_at"] = now
    return vulns


def _format_entry(entry: dict) -> dict:
    return {
        "cve_id": entry.get("cveID"),
        "vendor": entry.get("vendorProject"),
        "product": entry.get("product"),
        "name": entry.get("vulnerabilityName"),
        "description": entry.get("shortDescription"),
        "date_added": entry.get("dateAdded"),
        "due_date": entry.get("dueDate"),
        "action_required": entry.get("requiredAction", "N/A"),
        "ransomware_campaign": entry.get("knownRansomwareCampaignUse", "Unknown"),
        "cwe": entry.get("cweID", "N/A"),
        "notes": entry.get("notes", ""),
        "cisa_url": f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{entry.get('cveID')}",
    }


def _require(arguments: dict, *keys: str) -> None:
    """Raise ValueError with a clear message if any required key is missing."""
    for k in keys:
        if not arguments.get(k):
            raise ValueError(f"Missing required argument: '{k}'")


async def handle_tool(tool_name: str, arguments: dict) -> Any:
    if tool_name == "check_kev":
        _require(arguments, "cve_id")
        cve_id = arguments["cve_id"].upper().strip()
        vulns = await _get_kev_data()
        entry = next((v for v in vulns if v.get("cveID", "").upper() == cve_id), None)
        if entry:
            return {
                "in_kev": True,
                "message": f"{cve_id} IS in the CISA KEV catalog — active exploitation confirmed.",
                **_format_entry(entry),
            }
        return {
            "in_kev": False,
            "cve_id": cve_id,
            "message": f"{cve_id} is NOT currently listed in the CISA KEV catalog.",
        }

    elif tool_name == "search_kev":
        _require(arguments, "keyword")
        keyword = arguments["keyword"].lower()
        ransomware_only = arguments.get("ransomware_only", False)
        limit = min(int(arguments.get("limit", 15)), 50)
        vulns = await _get_kev_data()

        matches = [
            v for v in vulns
            if (
                keyword in (v.get("vendorProject") or "").lower()
                or keyword in (v.get("product") or "").lower()
                or keyword in (v.get("vulnerabilityName") or "").lower()
                or keyword in (v.get("shortDescription") or "").lower()
                or keyword in (v.get("cveID") or "").lower()
            ) and (
                not ransomware_only
                or v.get("knownRansomwareCampaignUse", "").lower() == "known"
            )
        ]
        # Sort by date_added descending (most recent first)
        matches.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
        
        results = []
        for v in matches[:limit]:
            due = v.get("dueDate", "")
            date_added = v.get("dateAdded", "")
            
            # Calculate days remaining
            days_remaining = "N/A"
            status = "UNKNOWN"
            if due:
                try:
                    due_date = datetime.strptime(due, "%Y-%m-%d").date()
                    now_date = datetime.now(timezone.utc).date()
                    delta = (due_date - now_date).days
                    if delta < 0:
                        status = "OVERDUE"
                        days_remaining = f"{abs(delta)} days overdue"
                    elif delta == 0:
                        status = "DUE TODAY"
                        days_remaining = "Due today"
                    else:
                        status = "ACTIVE"
                        days_remaining = f"{delta} days remaining"
                except Exception as e:
                    logger.warning(f"Error calculating KEV date: {e}")
                    status = "UNKNOWN"
            
            results.append({
                "cve_id": v.get("cveID"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "name": v.get("vulnerabilityName"),
                "description": v.get("shortDescription"),
                "date_added": date_added,
                "due_date": due,
                "status": status if 'status' in locals() else "UNKNOWN",
                "days_remaining": days_remaining,
                "action_required": v.get("requiredAction", "N/A"),
                "ransomware_campaign": v.get("knownRansomwareCampaignUse", "Unknown"),
                "cwe": v.get("cweID", "N/A"),
                "notes": v.get("notes", ""),
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}",
            })
        
        return {
            "total_matches": len(matches),
            "results": results,
        }

    elif tool_name == "get_kev_stats":
        top_n = int(arguments.get("top_n", 10))
        vulns = await _get_kev_data()
        vendor_counts: dict[str, int] = {}
        ransomware_count = 0
        recent_additions = sorted(vulns, key=lambda v: v.get("dateAdded", ""), reverse=True)[:5]
        for v in vulns:
            vendor = v.get("vendorProject", "Unknown")
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
            if v.get("knownRansomwareCampaignUse", "").lower() == "known":
                ransomware_count += 1

        top_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:top_n]
        return {
            "total_kev_entries": len(vulns),
            "ransomware_associated": ransomware_count,
            "ransomware_pct": round(ransomware_count / max(len(vulns), 1) * 100, 1),
            "top_vendors": [{"vendor": k, "count": v} for k, v in top_vendors],
            "most_recent_additions": [_format_entry(v) for v in recent_additions],
        }

    elif tool_name == "get_recent_kev":
        days = int(arguments.get("days", 30))
        limit = min(int(arguments.get("limit", 20)), 100)
        cutoff = datetime.now(timezone.utc).date()
        from datetime import timedelta
        cutoff = cutoff - timedelta(days=days)
        vulns = await _get_kev_data()
        recent = [
            v for v in vulns
            if v.get("dateAdded", "") >= str(cutoff)
        ]
        recent.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
        return {
            "period_days": days,
            "total_added": len(recent),
            "entries": [_format_entry(v) for v in recent[:limit]],
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

        return JSONResponse({
            "jsonrpc": "2.0", "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"}
        }, status_code=404)

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
