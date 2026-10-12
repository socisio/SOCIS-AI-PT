#!/usr/bin/env python3
"""
SOCIS-AI-PT — Anomaly Detection MCP Server (HTTP transport)
ML-based HTTP response anomaly detection using Isolation Forest.

Trains on baseline HTTP responses for a target and flags statistically
anomalous responses during scans. Opt-in feature (disabled by default).

Port: 8123
"""

import json
import logging
import os
import hashlib
import asyncio
import time
from typing import Any

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# Optional heavy deps — fall back gracefully if not installed
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    import joblib
    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False

from mcp_auth import verify_mcp_auth, mcp_auth_error, validate_url_target

# ───────────────────────────────────────────────────────────
# CONFIGURATION
# ───────────────────────────────────────────────────────────

TOOL_NAME = "anomaly"
MCP_PORT = 8123
SERVER_NAME = f"{TOOL_NAME}-mcp"
MODEL_DIR = os.environ.get("ANOMALY_MODEL_DIR", "/tmp/anomaly_models")

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

os.makedirs(MODEL_DIR, exist_ok=True)

# ───────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# ───────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "anomaly_train",
        "description": (
            "Train an Isolation Forest anomaly detector on baseline HTTP responses for a target. "
            "Fetches each sample URL, extracts features (status_code, body_length, header_count, "
            "response_time_ms), and saves a model file. Run this before anomaly_score."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target hostname/URL used as model identifier (e.g., https://example.com)"
                },
                "sample_urls": {
                    "type": "array",
                    "description": "List of URLs to sample for baseline training (recommend 20-100 URLs)",
                    "items": {"type": "string"}
                },
                "timeout": {
                    "type": "integer",
                    "description": "Per-request timeout in seconds",
                    "default": 10
                }
            },
            "required": ["target", "sample_urls"]
        }
    },
    {
        "name": "anomaly_score",
        "description": (
            "Score a list of URLs against a trained anomaly model. "
            "Returns anomaly scores and flags responses that deviate significantly "
            "from the trained baseline (is_anomalous=true means suspicious)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target identifier used during anomaly_train"
                },
                "urls": {
                    "type": "array",
                    "description": "List of URLs to score for anomalies",
                    "items": {"type": "string"}
                },
                "timeout": {
                    "type": "integer",
                    "description": "Per-request timeout in seconds",
                    "default": 10
                },
                "threshold": {
                    "type": "number",
                    "description": "Anomaly score threshold (lower = more anomalous). Default: -0.1",
                    "default": -0.1
                }
            },
            "required": ["target", "urls"]
        }
    },
    {
        "name": "anomaly_status",
        "description": "Check whether a trained model exists for a target and return its metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target identifier to check"
                }
            },
            "required": ["target"]
        }
    },
]

# FastAPI app
app = FastAPI(title=f"SOCIS {TOOL_NAME} MCP Server", docs_url=None)


# ───────────────────────────────────────────────────────────
# HELPERS
# ───────────────────────────────────────────────────────────

def _model_id(target: str) -> str:
    return hashlib.sha256(target.encode()).hexdigest()[:16]


def _model_path(target: str) -> str:
    return os.path.join(MODEL_DIR, f"anomaly_{_model_id(target)}.pkl")


def _meta_path(target: str) -> str:
    return os.path.join(MODEL_DIR, f"anomaly_{_model_id(target)}.meta.json")


async def _fetch_features(url: str, timeout: int) -> dict:
    """Fetch URL and extract [status_code, body_length, header_count, response_time_ms]."""
    t0 = time.monotonic()
    try:
        # Validate URL against SSRF blocklist before fetching
        validate_url_target(url)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url)
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return {
            "url": url,
            "status_code": resp.status_code,
            "body_length": len(resp.content),
            "header_count": len(resp.headers),
            "response_time_ms": elapsed_ms,
            "error": None,
        }
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        return {
            "url": url,
            "status_code": 0,
            "body_length": 0,
            "header_count": 0,
            "response_time_ms": elapsed_ms,
            "error": str(exc),
        }


def _to_feature_vector(feat: dict) -> list:
    return [
        float(feat["status_code"]),
        float(feat["body_length"]),
        float(feat["header_count"]),
        float(feat["response_time_ms"]),
    ]


# ───────────────────────────────────────────────────────────
# TOOL HANDLERS
# ───────────────────────────────────────────────────────────

async def handle_anomaly_train(args: dict) -> dict:
    if not _ML_AVAILABLE:
        return {
            "error": "scikit-learn and numpy are not installed. Run: pip install scikit-learn numpy joblib",
            "ml_available": False,
        }

    target = str(args.get("target") or "")
    sample_urls = args.get("sample_urls") or []
    timeout = int(args.get("timeout") or 10)

    if not target:
        raise ValueError("'target' parameter is required")
    if not sample_urls:
        raise ValueError("'sample_urls' must be a non-empty list")

    log.info(f"[anomaly_train] Fetching {len(sample_urls)} URLs for target={target}")

    # Fetch all sample URLs concurrently
    tasks = [_fetch_features(url, timeout) for url in sample_urls[:200]]
    raw = await asyncio.gather(*tasks)

    # Only use successful responses for training
    good = [r for r in raw if r["error"] is None]
    if len(good) < 5:
        return {
            "error": f"Too few successful responses ({len(good)}/{len(sample_urls)}) to train a model. Need at least 5.",
            "target": target,
            "attempted": len(sample_urls),
            "successful": len(good),
        }

    X = np.array([_to_feature_vector(r) for r in good])

    model = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
    model.fit(X)

    model_path = _model_path(target)
    joblib.dump(model, model_path)

    meta = {
        "target": target,
        "model_id": _model_id(target),
        "samples_trained": len(good),
        "attempted": len(sample_urls),
        "trained_at": int(time.time()),
        "features": ["status_code", "body_length", "header_count", "response_time_ms"],
    }
    with open(_meta_path(target), "w") as f:
        json.dump(meta, f)

    log.info(f"[anomaly_train] Model saved: {model_path}")
    return {**meta, "model_path": model_path}


async def handle_anomaly_score(args: dict) -> dict:
    if not _ML_AVAILABLE:
        return {
            "error": "scikit-learn and numpy are not installed.",
            "ml_available": False,
        }

    target = str(args.get("target") or "")
    urls = args.get("urls") or []
    timeout = int(args.get("timeout") or 10)
    threshold = float(args.get("threshold") if args.get("threshold") is not None else -0.1)

    if not target:
        raise ValueError("'target' parameter is required")
    if not urls:
        raise ValueError("'urls' must be a non-empty list")

    model_path = _model_path(target)
    if not os.path.exists(model_path):
        return {
            "error": f"No trained model found for target '{target}'. Run anomaly_train first.",
            "target": target,
            "model_id": _model_id(target),
        }

    model = joblib.load(model_path)

    log.info(f"[anomaly_score] Scoring {len(urls)} URLs for target={target}")
    tasks = [_fetch_features(url, timeout) for url in urls[:500]]
    raw = await asyncio.gather(*tasks)

    scored = []
    anomalous_count = 0

    for feat in raw:
        if feat["error"]:
            scored.append({**feat, "anomaly_score": None, "is_anomalous": False})
            continue

        X = np.array([_to_feature_vector(feat)])
        score = float(model.score_samples(X)[0])
        is_anomalous = score < threshold

        if is_anomalous:
            anomalous_count += 1

        scored.append({
            "url": feat["url"],
            "status_code": feat["status_code"],
            "body_length": feat["body_length"],
            "header_count": feat["header_count"],
            "response_time_ms": feat["response_time_ms"],
            "anomaly_score": round(score, 4),
            "is_anomalous": is_anomalous,
        })

    return {
        "target": target,
        "model_id": _model_id(target),
        "threshold": threshold,
        "total": len(scored),
        "anomalous_count": anomalous_count,
        "normal_count": len(scored) - anomalous_count,
        "scored_responses": scored,
        "summary": (
            f"{anomalous_count} anomalous responses detected out of {len(scored)} scored URLs."
        ),
    }


def handle_anomaly_status(args: dict) -> dict:
    target = str(args.get("target") or "")
    if not target:
        raise ValueError("'target' parameter is required")

    model_path = _model_path(target)
    meta_path = _meta_path(target)

    if not os.path.exists(model_path):
        return {
            "target": target,
            "model_id": _model_id(target),
            "model_exists": False,
            "message": "No model trained for this target. Run anomaly_train first.",
        }

    meta = {}
    if os.path.exists(meta_path):
        with open(meta_path) as f:
            meta = json.load(f)

    return {
        "target": target,
        "model_id": _model_id(target),
        "model_exists": True,
        "model_path": model_path,
        "ml_available": _ML_AVAILABLE,
        **meta,
    }


# ───────────────────────────────────────────────────────────
# MCP PROTOCOL HANDLER
# ───────────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    return {"status": "healthy", "server": SERVER_NAME, "ml_available": _ML_AVAILABLE}


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
                "result": {"protocolVersion": "2024-11-05", "serverInfo": {"name": SERVER_NAME, "version": "1.0"}, "capabilities": {"tools": {}}}
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
                if tool_name == "anomaly_train":
                    result = await handle_anomaly_train(arguments)
                elif tool_name == "anomaly_score":
                    result = await handle_anomaly_score(arguments)
                elif tool_name == "anomaly_status":
                    result = handle_anomaly_status(arguments)
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
    log.info(f"Starting {SERVER_NAME} on port {MCP_PORT} (ML available: {_ML_AVAILABLE})")
    uvicorn.run(app, host="0.0.0.0", port=MCP_PORT, log_level="info")
