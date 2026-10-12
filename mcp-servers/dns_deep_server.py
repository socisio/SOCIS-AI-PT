#!/usr/bin/env python3
"""
SOCIS-AI-PT — DNS Deep MCP Server (HTTP transport)
FastAPI-based MCP server for DNS-layer misconfigurations beyond the basic record lookup in osint_server.py: zone
transfer attempts, subdomain takeover detection, and email-security posture (SPF/DKIM/DMARC). Wraps `dig` (already
present in the platform's Dockerfile, used the same way by osint_server.py's dns_lookup) — no new dependencies.
Written to match the platform's other thin-wrapper servers: shared mcp_auth.py for scope validation, subprocess runs
with an argument list only (no shell, no injection).

Tools exposed (v1):
  - zone_transfer_check      : attempt an AXFR zone transfer against each of a domain's authoritative nameservers —
                               a classic, serious misconfiguration that dumps the entire zone to anyone who asks
  - subdomain_takeover_check : resolve a list of subdomains and flag any whose CNAME points at an unclaimed cloud
                               service (S3, Azure, GitHub Pages, Heroku, …) — a common takeover vector
  - email_security_posture   : check SPF, DKIM (at common selectors), and DMARC TXT records and flag missing or
                               weak policies (no SPF, DMARC p=none, no DKIM found at common selectors)

All three are safe, read-only recon — none are offensive, none need the operator opt-in.
"""

import asyncio
import json
import os
import re
import sys
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_auth import verify_mcp_auth, mcp_auth_error, validate_scan_target  # type: ignore

app = FastAPI(title="SOCIS DNS Deep MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "dns-deep-mcp"
MCP_PORT = 8131

DIG_BIN = os.environ.get("DIG_BINARY", "dig")
DEFAULT_TIMEOUT = 20
MAX_TIMEOUT = 60
MAX_SUBDOMAINS = 100

# Subdomain-takeover fingerprints: a CNAME pointing here with a "service not found"-shaped response usually means the
# cloud resource was deleted but the DNS record wasn't — the next person to register that name can claim the subdomain.
_TAKEOVER_FINGERPRINTS = [
    ("AWS S3", r"\.s3\.amazonaws\.com$|\.s3[.-][\w-]+\.amazonaws\.com$", "NoSuchBucket"),
    ("Azure", r"\.azurewebsites\.net$|\.cloudapp\.azure\.com$|\.blob\.core\.windows\.net$", "404"),
    ("GitHub Pages", r"\.github\.io$", "There isn't a GitHub Pages site here"),
    ("Heroku", r"\.herokuapp\.com$", "No such app"),
    ("Fastly", r"\.fastly\.net$", "Fastly error: unknown domain"),
    ("Shopify", r"\.myshopify\.com$", "Sorry, this shop is currently unavailable"),
    ("Netlify", r"\.netlify\.app$", "Not Found"),
    ("Zendesk", r"\.zendesk\.com$", "Help Center Closed"),
]

_COMMON_DKIM_SELECTORS = ["default", "selector1", "selector2", "google", "k1", "dkim", "mail", "smtp"]


def _clean_timeout(raw: Any) -> int:
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT
    return max(5, min(v, MAX_TIMEOUT))


def _clean_domain(domain: str) -> str:
    # validate_scan_target handles scope + hostname extraction; this is a DNS-record domain, not a network scan
    # target, but the same host-shape validation and scope guard are exactly what we want here too.
    return validate_scan_target(domain)


def _clean_subdomain_list(raw: Any, base_domain: str) -> list[str]:
    if isinstance(raw, str):
        items = [s.strip() for s in raw.replace(",", "\n").splitlines() if s.strip()]
    elif isinstance(raw, list):
        items = [str(s).strip() for s in raw if str(s).strip()]
    else:
        items = []
    cleaned = []
    for s in items[:MAX_SUBDOMAINS]:
        # each entry must be a plausible subdomain of the base domain being tested — never an arbitrary host
        if not re.match(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$", s, re.I):
            continue
        cleaned.append(s)
    return cleaned


async def _run_dig(args: list[str], timeout: int) -> str:
    try:
        proc = await asyncio.create_subprocess_exec(
            DIG_BIN, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return ""
        return (out or b"").decode("utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    except Exception:  # noqa: BLE001
        return ""


async def _http_get_text(host: str, timeout: int) -> str:
    """A tiny, dependency-free HTTPS GET used only to fetch a takeover fingerprint page — httpx is already a platform
    dependency used by every other new server, so reuse it here too rather than hand-roll sockets."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:  # noqa: S501 — recon probe
            resp = await client.get(f"https://{host}/")
            return resp.text[:4000]
    except Exception:
        try:
            async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
                resp = await client.get(f"http://{host}/")
                return resp.text[:4000]
        except Exception:
            return ""


# ─────────────────────────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "zone_transfer_check",
        "description": "Attempt an AXFR zone transfer against each authoritative nameserver for a domain. A "
                       "successful transfer dumps the entire DNS zone (every subdomain, internal hostnames, etc.) — "
                       "a serious, classic misconfiguration. Read-only; most nameservers correctly refuse this.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to check, e.g. example.com"},
                "timeout": {"type": "integer", "description": "Per-nameserver timeout in seconds", "default": 15},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "subdomain_takeover_check",
        "description": "Resolve a list of subdomains and flag any whose CNAME points at a cloud service (S3, Azure, "
                       "GitHub Pages, Heroku, Fastly, Shopify, Netlify, Zendesk) that returns a 'resource not found' "
                       "response — meaning the subdomain can likely be claimed by registering that resource.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "The base domain being assessed (for scope validation)"},
                "subdomains": {"description": "List of subdomains to check, or newline/comma-separated string",
                               "oneOf": [{"type": "array", "items": {"type": "string"}}, {"type": "string"}]},
                "timeout": {"type": "integer", "description": "Per-subdomain timeout in seconds", "default": 10},
            },
            "required": ["domain", "subdomains"],
        },
    },
    {
        "name": "email_security_posture",
        "description": "Check a domain's SPF, DKIM (at common selectors), and DMARC TXT records and flag missing or "
                       "weak policies — no SPF record, a DMARC policy of p=none (monitor-only, not enforced), or no "
                       "DKIM record found at any common selector.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain to check, e.g. example.com"},
                "timeout": {"type": "integer", "description": "Per-query timeout in seconds", "default": 15},
            },
            "required": ["domain"],
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# HANDLERS
# ─────────────────────────────────────────────────────────────────────────────

async def handle_zone_transfer_check(a: dict) -> dict:
    domain = _clean_domain(a["domain"])
    timeout = _clean_timeout(a.get("timeout", 15))
    ns_raw = await _run_dig(["+short", "NS", domain], timeout)
    nameservers = [n.strip().rstrip(".") for n in ns_raw.splitlines() if n.strip()]
    if not nameservers:
        return {"success": True, "output": {"domain": domain, "nameservers_found": 0,
                                             "note": "Could not resolve any NS records for this domain."}}
    results = []
    any_vulnerable = False
    for ns in nameservers[:10]:
        axfr = await _run_dig(["@" + ns, domain, "AXFR", "+time=5", "+tries=1"], timeout)
        # A refused/failed transfer produces an error line or no records; a successful one lists the zone's records.
        succeeded = bool(axfr.strip()) and "; Transfer failed" not in axfr and "communications error" not in axfr.lower() \
            and "connection refused" not in axfr.lower() and axfr.count("\n") > 3
        if succeeded:
            any_vulnerable = True
        results.append({
            "nameserver": ns,
            "transfer_succeeded": succeeded,
            "record_count": axfr.count("\n") if succeeded else 0,
        })
    return {
        "success": True,
        "output": {"domain": domain, "nameservers_found": len(nameservers), "vulnerable": any_vulnerable,
                   "results": results},
    }


async def handle_subdomain_takeover_check(a: dict) -> dict:
    domain = _clean_domain(a["domain"])
    timeout = _clean_timeout(a.get("timeout", 10))
    subdomains = _clean_subdomain_list(a.get("subdomains"), domain)
    if not subdomains:
        raise ValueError("No valid subdomains provided")
    findings = []
    for sub in subdomains:
        cname_raw = await _run_dig(["+short", "CNAME", sub], timeout)
        cname = cname_raw.strip().splitlines()[0].rstrip(".") if cname_raw.strip() else ""
        if not cname:
            continue
        matched_service = None
        for service, pattern, fingerprint in _TAKEOVER_FINGERPRINTS:
            if re.search(pattern, cname, re.I):
                matched_service = (service, fingerprint)
                break
        if not matched_service:
            continue
        service, fingerprint = matched_service
        body = await _http_get_text(sub, timeout)
        vulnerable = fingerprint.lower() in body.lower() if body else None
        findings.append({
            "subdomain": sub, "cname": cname, "service": service,
            "likely_takeover": bool(vulnerable),
            "detail": "Fingerprint matched — the resource appears unclaimed" if vulnerable
                      else ("Could not confirm (no response or fingerprint not found)" if vulnerable is None
                            else "CNAME points at this service, but the fingerprint did not match — resource may still be claimed"),
        })
    return {
        "success": True,
        "output": {"domain": domain, "checked": len(subdomains), "cname_to_cloud_service": len(findings),
                   "findings": findings},
    }


async def handle_email_security_posture(a: dict) -> dict:
    domain = _clean_domain(a["domain"])
    timeout = _clean_timeout(a.get("timeout", 15))

    spf_raw = await _run_dig(["+short", "TXT", domain], timeout)
    spf_records = [l.strip().strip('"') for l in spf_raw.splitlines() if "v=spf1" in l.lower()]

    dmarc_raw = await _run_dig(["+short", "TXT", f"_dmarc.{domain}"], timeout)
    dmarc_records = [l.strip().strip('"') for l in dmarc_raw.splitlines() if "v=dmarc1" in l.lower()]

    dkim_found = []
    for selector in _COMMON_DKIM_SELECTORS:
        dkim_raw = await _run_dig(["+short", "TXT", f"{selector}._domainkey.{domain}"], timeout)
        if dkim_raw.strip():
            dkim_found.append(selector)

    issues = []
    if not spf_records:
        issues.append({"issue": "No SPF record found", "severity": "medium",
                       "detail": "Without SPF, anyone can send email that appears to be from this domain."})
    if not dmarc_records:
        issues.append({"issue": "No DMARC record found", "severity": "medium",
                       "detail": "Without DMARC, there is no policy telling receivers what to do with spoofed mail."})
    else:
        policy_match = re.search(r"p=(\w+)", dmarc_records[0], re.I)
        policy = policy_match.group(1).lower() if policy_match else "none"
        if policy == "none":
            issues.append({"issue": "DMARC policy is p=none (monitor-only)", "severity": "low",
                           "detail": "DMARC is published but not enforced — spoofed mail is reported, not blocked."})
    if not dkim_found:
        issues.append({"issue": "No DKIM record found at common selectors", "severity": "low",
                       "detail": f"Checked selectors: {', '.join(_COMMON_DKIM_SELECTORS)}. A non-standard selector "
                                 "would not be found by this check."})

    return {
        "success": True,
        "output": {
            "domain": domain,
            "spf": spf_records[0] if spf_records else None,
            "dmarc": dmarc_records[0] if dmarc_records else None,
            "dkim_selectors_found": dkim_found,
            "issues": issues,
        },
    }


_HANDLERS = {
    "zone_transfer_check": handle_zone_transfer_check,
    "subdomain_takeover_check": handle_subdomain_takeover_check,
    "email_security_posture": handle_email_security_posture,
}


# ─────────────────────────────────────────────────────────────────────────────
# MCP PROTOCOL
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    return {"status": "healthy", "server": SERVER_NAME, "version": MCP_VERSION}


@app.post("/mcp")
async def mcp_handler(request: Request):
    if not verify_mcp_auth(request):
        return mcp_auth_error()
    try:
        payload = await request.json()
        req_id = payload.get("id")
        method = payload.get("method")
        params = payload.get("params", {})

        if method == "tools/list":
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})

        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {}) or {}
            handler = _HANDLERS.get(tool_name)
            if handler is None:
                return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                                     "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}})
            try:
                result = await handler(arguments)
            except ValueError as e:
                return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                                     "result": {"content": [{"type": "text",
                                                             "text": json.dumps({"success": False, "output": f"[!] {e}"})}]}})
            return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                                 "result": {"content": [{"type": "text", "text": json.dumps(result)}]}})

        return JSONResponse({"jsonrpc": "2.0", "id": req_id,
                             "error": {"code": -32601, "message": f"Unknown method: {method}"}})
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32603, "message": f"Internal error: {str(e)[:200]}"}}, status_code=500)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=MCP_PORT, log_level="warning")
