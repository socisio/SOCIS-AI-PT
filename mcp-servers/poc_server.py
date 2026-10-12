#!/usr/bin/env python3
"""
SOCIS-AI-PT — PoC Index MCP Server (HTTP transport)
Searches public Proof-of-Concept exploit indexes:
  - ExploitDB via their public CSV feed
  - GitHub search for PoC repos by CVE
"""

import csv
import httpx
from urllib.parse import quote_plus
import io
import json
import re
import time
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any
from mcp_auth import verify_mcp_auth, mcp_auth_error

app = FastAPI(title="SOCIS PoC Index MCP Server", docs_url=None)

MCP_VERSION = "1.1"  # Updated: uses ExploitDB + GitHub search
SERVER_NAME = "poc_mcp"
PORT = 8116

# ExploitDB publishes their full database as a public CSV on GitLab — no auth, no rate limits
_EDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
_edb_cache: dict = {"rows": [], "fetched_at": 0.0}
_EDB_CACHE_TTL = 86400  # 24 hours


TOOLS = [
    {
        "name": "search_poc",
        "description": (
            "Search for public Proof-of-Concept (PoC) exploits for a CVE ID or keyword. "
            "Queries ExploitDB (official CSV) and GitHub for PoC repositories. "
            "Returns exploit titles, types, links, and publication dates."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "CVE ID (e.g. CVE-2021-44228) or vulnerability keyword"
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (default 10, max 25)",
                    "default": 10
                }
            },
            "required": ["query"]
        }
    },
    {
        "name": "search_github_poc",
        "description": (
            "Search GitHub for public PoC exploit repositories for a CVE ID. "
            "Returns repo name, stars, description, and URL. "
            "High star counts indicate widely-used/reliable PoCs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE ID (e.g. CVE-2021-44228)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Max repos to return (default 10)",
                    "default": 10
                }
            },
            "required": ["cve_id"]
        }
    },
    {
        "name": "get_exploitdb_entry",
        "description": (
            "Look up an ExploitDB entry by EDB ID or search by CVE/keyword. "
            "Returns exploit title, type, platform, author, and direct link."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "CVE ID, EDB ID (e.g. EDB-51574), or keyword"
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results (default 10)",
                    "default": 10
                }
            },
            "required": ["query"]
        }
    },
    {
        "name": "poc_risk_summary",
        "description": (
            "Generate a PoC risk summary for a CVE: checks ExploitDB and GitHub "
            "for public exploits, then returns a combined risk assessment with "
            "exploitation difficulty rating."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve_id": {
                    "type": "string",
                    "description": "CVE ID to assess"
                }
            },
            "required": ["cve_id"]
        }
    }
]


_EDB_CACHE_TTL = 86400  # 24 hours


async def _fetch_edb_rows() -> list[dict]:
    """Download and cache the ExploitDB CSV database from GitLab (public, no auth)."""
    now = time.time()
    if _edb_cache["rows"] and (now - _edb_cache["fetched_at"]) < _EDB_CACHE_TTL:
        return _edb_cache["rows"]
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            r = await client.get(_EDB_CSV_URL, headers={"User-Agent": "SOCIS-AI-PT/1.0"})
            r.raise_for_status()
        rows = list(csv.DictReader(io.StringIO(r.text)))
        _edb_cache["rows"] = rows
        _edb_cache["fetched_at"] = now
        return rows
    except Exception:
        return _edb_cache["rows"]  # return stale cache on error


def _normalize_cve(cve_id: str) -> str:
    cve_id = cve_id.upper().strip()
    if not re.match(r'^CVE-\d{4}-\d+$', cve_id):
        raise ValueError(f"Invalid CVE ID format: {cve_id}")
    return cve_id


async def _exploitdb_search(query: str, limit: int = 10) -> list[dict]:
    """
    Search ExploitDB using their official public CSV database hosted on GitLab.
    No API keys, no rate limits. CSV is cached in-memory for 24 hours.
    """
    cve_match = re.match(r'^CVE-(\d{4})-(\d+)$', query.upper())
    fallback_url = (
        f"https://www.exploit-db.com/search?cve={query.upper()}"
        if cve_match else f"https://www.exploit-db.com/search?q={query}"
    )

    # Direct EDB-ID lookup — find in CSV by id field
    is_edb_id = re.match(r'^EDB-?(\d+)$', query.upper())
    rows = await _fetch_edb_rows()

    if not rows:
        return [{"error": "ExploitDB CSV unavailable", "fallback_url": fallback_url}]

    results = []
    q_upper = query.upper().strip()

    for row in rows:
        edb_id = row.get("id", "").strip()
        codes = row.get("codes", "").upper()
        desc = row.get("description", "")

        if is_edb_id:
            if edb_id != is_edb_id.group(1):
                continue
        elif cve_match:
            if q_upper not in codes:
                continue
        else:
            # keyword match against description or codes
            if q_upper not in desc.upper() and q_upper not in codes:
                continue

        cve_list = [c.strip() for c in codes.split(";") if c.strip().startswith("CVE-")]
        results.append({
            "edb_id": f"EDB-{edb_id}",
            "title": desc,
            "date": row.get("date_published", row.get("date_added", "")),
            "type": row.get("type", ""),
            "platform": row.get("platform", ""),
            "verified": row.get("verified", "0") == "1",
            "url": f"https://www.exploit-db.com/exploits/{edb_id}",
            "cve": cve_list,
        })
        if len(results) >= limit:
            break

    if results:
        return results

    # EDB-ID direct link even if not in cache yet
    if is_edb_id:
        return [{"edb_id": f"EDB-{is_edb_id.group(1)}", "url": f"https://www.exploit-db.com/exploits/{is_edb_id.group(1)}", "note": "Entry not found in local CSV"}]

    return [{"message": f"No ExploitDB entries found for '{query}'", "search_url": fallback_url}]


GITHUB_SEARCH_API = "https://api.github.com/search/repositories"


async def _github_poc_search(query: str, limit: int = 10) -> list[dict]:
    """Search GitHub for PoC repos by CVE or keyword."""
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "SOCIS-AI-PT/1.0",
    }
    # Search for PoC exploits - works with CVE ID or keyword
    search_term = f"{query} poc exploit" if query.upper().startswith("CVE-") else f"{query} exploit poc"
    params = {
        "q": search_term,
        "sort": "stars",
        "order": "desc",
        "per_page": min(limit, 30),
    }
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(GITHUB_SEARCH_API, params=params, headers=headers)
            if r.status_code == 403:
                return [{"error": "GitHub rate limited", "fallback_url": f"https://github.com/search?q={quote_plus(query)}+poc&type=repositories"}]
            r.raise_for_status()
            data = r.json()
        results = []
        for item in data.get("items", [])[:limit]:
            results.append({
                "repo": item.get("full_name", ""),
                "description": item.get("description", ""),
                "stars": item.get("stargazers_count", 0),
                "url": item.get("html_url", ""),
                "pushed_at": item.get("pushed_at", ""),
            })
        return results
    except Exception as e:
        return [{"error": f"GitHub search failed: {str(e)}", "fallback_url": f"https://github.com/search?q={quote_plus(query)}+poc&type=repositories"}]


def _exploitation_difficulty(edb_count: int, github_stars_max: int) -> str:
    if edb_count >= 5 or github_stars_max >= 500:
        return "TRIVIAL — Widely available, weaponized PoCs exist. Exploit kits likely."
    if edb_count >= 2 or github_stars_max >= 100:
        return "EASY — Multiple public PoCs available. Low technical barrier."
    if edb_count >= 1 or github_stars_max >= 10:
        return "MODERATE — PoC exists but may require adaptation."
    return "HARD — No known public PoC. Research-grade exploitation required."


def _require(arguments: dict, *keys: str) -> None:
    """Raise ValueError with a clear message if any required key is missing."""
    for k in keys:
        if not arguments.get(k):
            raise ValueError(f"Missing required argument: '{k}'")


async def handle_tool(tool_name: str, arguments: dict) -> Any:
    if tool_name == "search_poc":
        _require(arguments, "query")
        query = arguments["query"].strip()
        limit = min(int(arguments.get("limit", 10)), 25)

        # Use ExploitDB + GitHub directly
        import asyncio

        async def _empty() -> list:
            return []

        edb_results, gh_results = await asyncio.gather(
            _exploitdb_search(query, limit),
            _github_poc_search(query, limit),
        )
        edb_ok = [r for r in edb_results if "error" not in r and "message" not in r]
        gh_ok = [r for r in gh_results if "error" not in r]

        combined = edb_ok + [
            {
                "title": r["repo"],
                "type": "GitHub PoC",
                "source": "GitHub",
                "date": r.get("pushed_at", ""),
                "url": r["url"],
                "stars": r.get("stars", 0),
                "description": r.get("description", ""),
            }
            for r in gh_ok
        ]

        sources = []
        if edb_ok:
            sources.append("ExploitDB")
        if gh_ok:
            sources.append("GitHub")
        source_str = " + ".join(sources) if sources else "No results found"

        return {
            "query": query,
            "source": source_str,
            "count": len(combined),
            "exploits": combined,
        }

    elif tool_name == "search_github_poc":
        _require(arguments, "cve_id")
        # Accept CVE ID or keyword
        query = arguments["cve_id"].strip()
        limit = min(int(arguments.get("limit", 10)), 30)
        repos = await _github_poc_search(query, limit)
        return {
            "query": query,
            "github_poc_repos": repos,
            "total_found": len(repos),
            "note": "Sorted by star count — higher stars indicate more widely used PoCs.",
        }

    elif tool_name == "get_exploitdb_entry":
        _require(arguments, "query")
        query = arguments["query"].strip()
        limit = min(int(arguments.get("limit", 10)), 25)
        results = await _exploitdb_search(query, limit)
        return {
            "query": query,
            "source": "Exploit-DB (https://www.exploit-db.com)",
            "count": len(results),
            "exploits": results,
        }

    elif tool_name == "poc_risk_summary":
        _require(arguments, "cve_id")
        # Accept CVE ID or keyword
        query = arguments["cve_id"].strip()
        
        # Use ExploitDB + GitHub
        import asyncio
        edb_results, github_results = await asyncio.gather(
            _exploitdb_search(query, 5),
            _github_poc_search(query, 5),
        )
        valid_edb = [r for r in edb_results if "error" not in r and "message" not in r]
        valid_github = [r for r in github_results if "error" not in r]
        max_stars = max((r.get("stars", 0) for r in valid_github), default=0)
        has_poc = bool(valid_edb or valid_github)
        
        return {
            "query": query,
            "public_poc_exists": has_poc,
            "exploitdb_count": len(valid_edb),
            "github_poc_repos": len(valid_github),
            "highest_starred_github_repo": max_stars,
            "exploitation_difficulty": _exploitation_difficulty(len(valid_edb), max_stars),
            "risk_level": "CRITICAL" if has_poc and (len(valid_edb) >= 3 or max_stars >= 200) else
                          "HIGH" if has_poc else "MEDIUM",
            "top_exploits": valid_edb[:3],
            "top_github_repos": sorted(valid_github, key=lambda x: x.get("stars", 0), reverse=True)[:3],
            "recommendations": [
                "Patch immediately — public PoC exploits exist and are in circulation." if has_poc else
                "No public PoC currently found. Monitor threat intelligence feeds.",
                "Check CISA KEV catalog to confirm if actively exploited.",
                "Review EPSS score to assess exploitation probability.",
            ],
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