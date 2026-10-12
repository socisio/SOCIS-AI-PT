#!/usr/bin/env python3
"""
SOCIS-AI-PT — CVE/NVD MCP Server (HTTP transport)
FastAPI-based MCP server for CVE and NVD lookups.
"""

import httpx
import json
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any
from mcp_auth import verify_mcp_auth, mcp_auth_error
import re

app = FastAPI(title="SOCIS CVE MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "cve-mcp"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

TOOLS = [
    {
        "name": "lookup_cve",
        "description": "Look up a specific CVE by ID from the National Vulnerability Database (NVD). Returns severity, CVSS score, description, references, and affected software.",
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
        "name": "search_cves",
        "description": "Search CVEs by keyword, product, or vendor. Returns up to 20 matching CVEs sorted by severity.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keyword": {
                    "type": "string",
                    "description": "Search term (product name, vendor, or technology)"
                },
                "severity": {
                    "type": "string",
                    "description": "Filter by severity: CRITICAL, HIGH, MEDIUM, LOW",
                    "default": ""
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results to return",
                    "default": 10
                }
            },
            "required": ["keyword"]
        }
    },
    {
        "name": "get_severity",
        "description": "Get the CVSS severity and score for a CVE ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string"}
            },
            "required": ["cve_id"]
        }
    },
    {
        "name": "cpe_search",
        "description": "Search CVEs affecting a specific CPE (Common Platform Enumeration) product.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cpe": {
                    "type": "string",
                    "description": "CPE string (e.g. 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*')"
                }
            },
            "required": ["cpe"]
        }
    }
]


def normalize_cve_id(cve_id: str) -> str:
    cve_id = cve_id.upper().strip()
    if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
        raise ValueError(f"Invalid CVE ID format: {cve_id}")
    return cve_id


def parse_nvd_item(item: dict) -> dict:
    cve = item.get("cve", {})
    metrics = cve.get("metrics", {})

    # Extract CVSS score + attack vector (prefer v3.1 → v3.0 → v2)
    cvss_score = None
    severity = None
    attack_vector = None
    cvss_vector_string = None
    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics and metrics[version]:
            m = metrics[version][0]
            cvss_data = m.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore") or cvss_data.get("score")
            severity = cvss_data.get("baseSeverity") or m.get("baseSeverity")
            attack_vector = cvss_data.get("attackVector") or cvss_data.get("accessVector")
            cvss_vector_string = cvss_data.get("vectorString")
            break

    # CWE
    weaknesses = cve.get("weaknesses", [])
    cwes = []
    for w in weaknesses:
        for desc in w.get("description", []):
            val = desc.get("value", "")
            if val and val != "NVD-CWE-noinfo" and val != "NVD-CWE-Other":
                cwes.append(val)

    # Description
    descriptions = cve.get("descriptions", [])
    desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

    # References — include all, categorised
    refs_raw = cve.get("references", [])
    refs = []
    patch_urls = []
    for r in refs_raw:
        url = r.get("url", "")
        if not url:
            continue
        tags = r.get("tags", [])
        if any(t in tags for t in ("Patch", "Vendor Advisory", "Mitigation")):
            patch_urls.append(url)
        refs.append(url)

    # Affected CPE — parse into human-readable product + version
    conf = cve.get("configurations", [])
    affected_cpe = []
    affected_products = []
    for node_group in conf:
        for node in node_group.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable"):
                    cpe = cpe_match.get("criteria", "")
                    affected_cpe.append(cpe)
                    # Parse cpe:2.3:a:vendor:product:version:...
                    parts = cpe.split(":")
                    if len(parts) >= 6:
                        vendor = parts[3]
                        product = parts[4]
                        version = parts[5]
                        ver_start = cpe_match.get("versionStartIncluding") or cpe_match.get("versionStartExcluding")
                        ver_end = cpe_match.get("versionEndIncluding") or cpe_match.get("versionEndExcluding")
                        if version and version != "*":
                            affected_products.append(f"{vendor} {product} {version}")
                        elif ver_start or ver_end:
                            rng = []
                            if ver_start:
                                rng.append(f">= {ver_start}")
                            if ver_end:
                                rng.append(f"<= {ver_end}")
                            affected_products.append(f"{vendor} {product} ({', '.join(rng)})")

    cve_id = cve.get("id", "")
    return {
        "cve_id": cve_id,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": desc,
        "cvss_score": cvss_score,
        "severity": severity,
        "cvss_vector": cvss_vector_string,
        "attack_vector": attack_vector,
        "cwes": cwes if cwes else None,
        "references": refs[:15],
        "patch_references": patch_urls[:5],
        "affected_cpe": affected_cpe[:10],
        "affected_products": affected_products[:10],
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


async def nvd_request(params: dict) -> dict:
    # Cache-aside on the shared intel cache (perf #6). NVD is aggressively rate-
    # limited (5 req/30s unauthenticated); caching CVE lookups for 6h avoids 429s
    # and latency spikes when many scans look up the same CVEs. Falls back to a
    # direct request if the cache is unavailable.
    async def _do_fetch() -> dict:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get(NVD_API, params=params)
            r.raise_for_status()
            return r.json()

    try:
        from intel_cache import cached
        cache_key = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
        return await cached("nvd", cache_key, _do_fetch)
    except Exception:
        return await _do_fetch()


async def handle_tool(tool_name: str, arguments: dict) -> Any:
    if tool_name == "lookup_cve":
        cve_id = normalize_cve_id(arguments["cve_id"])
        data = await nvd_request({"cveId": cve_id})
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"error": f"CVE {cve_id} not found in NVD"}
        return parse_nvd_item(vulns[0])

    elif tool_name == "search_cves":
        keyword = arguments["keyword"]
        severity = arguments.get("severity", "")
        limit = min(arguments.get("limit", 10), 20)
        params = {"keywordSearch": keyword, "resultsPerPage": limit}
        if severity:
            params["cvssV3Severity"] = severity.upper()
        data = await nvd_request(params)
        items = data.get("vulnerabilities", [])
        return {
            "keyword": keyword,
            "total": data.get("totalResults", 0),
            "results": [parse_nvd_item(i) for i in items],
        }

    elif tool_name == "get_severity":
        cve_id = normalize_cve_id(arguments["cve_id"])
        data = await nvd_request({"cveId": cve_id})
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {"error": "Not found"}
        parsed = parse_nvd_item(vulns[0])
        return {
            "cve_id": cve_id,
            "cvss_score": parsed["cvss_score"],
            "severity": parsed["severity"],
        }

    elif tool_name == "cpe_search":
        cpe = arguments["cpe"]
        data = await nvd_request({"cpeName": cpe, "resultsPerPage": 10})
        items = data.get("vulnerabilities", [])
        return {
            "cpe": cpe,
            "total": data.get("totalResults", 0),
            "vulnerabilities": [parse_nvd_item(i) for i in items],
        }

    else:
        raise ValueError(f"Unknown tool: {tool_name}")


@app.post("/mcp")
async def mcp_endpoint(request: Request):
    if not verify_mcp_auth(request):
        return mcp_auth_error()
    try:
        body = await request.json()
        req_id = body.get("id")
        method = body.get("method")
        params = body.get("params", {})

        if method == "initialize":
            return JSONResponse({
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": MCP_VERSION},
                }
            })

        elif method == "tools/list":
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            result = await handle_tool(tool_name, arguments)
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
    uvicorn.run(app, host="0.0.0.0", port=8100)
