"""
SOCIS-AI-PT — WebSocket Handlers
Real-time streaming for scan progress, AI chat, and notifications.
"""

import asyncio
import json
import logging
import os
import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from typing import Dict, Optional, Set
import jwt
from jwt import PyJWTError as JWTError
import httpx
from sqlalchemy import select
from uuid import UUID

from app.config import settings
from app.core.database import async_session
from app.models.scan import Scan
from app.services.llm_service import llm_service
from app.services.system_prompt import build_system_prompt

router = APIRouter()
log = logging.getLogger(__name__)

_MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN", "")
_METASPLOIT_MCP_URL = os.environ.get("METASPLOIT_MCP_URL", "http://mcp_all:8104/mcp")


async def _authenticate_ws(websocket: WebSocket, token: Optional[str] = None) -> Optional[dict]:
    """Validate JWT token from query parameter or HttpOnly cookie before accepting WebSocket.
    Returns decoded payload on success, or None (and closes WS) on failure.
    """
    # Cross-site WebSocket hijacking guard: browsers send cookies on cross-origin
    # handshakes, so a hostile page could otherwise ride the victim's session.
    from app.core.ws_origin import origin_allowed
    _allowed = list(settings.ALLOWED_ORIGINS or [])
    if settings.FRONTEND_URL:
        _allowed.append(settings.FRONTEND_URL)
    if not origin_allowed(websocket.headers.get("origin"), websocket.headers.get("host"), _allowed):
        log.warning("WebSocket rejected: disallowed Origin %r", websocket.headers.get("origin"))
        await websocket.close(code=4003, reason="Origin not allowed")
        return None
    # Fall back to the access_token cookie when no query param supplied
    if not token:
        token = websocket.cookies.get("access_token")
    if not token:
        await websocket.close(code=4001, reason="Missing authentication token")
        return None
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        if payload.get("type") == "refresh":
            await websocket.close(code=4001, reason="Refresh tokens are not valid for WebSocket auth")
            return None
        # Enforce the revocation blocklist (fix H-2).
        from app.core.token_blocklist import is_token_blocked, is_user_session_revoked
        from app.core.token_policy import access_token_problem
        if access_token_problem(payload):
            await websocket.close(code=4001, reason="Not an access token")
            return None
        jti = payload.get("jti")
        if jti and await is_token_blocked(jti):
            await websocket.close(code=4001, reason="Token has been revoked")
            return None
        if await is_user_session_revoked(payload.get("sub"), payload.get("iat")):
            await websocket.close(code=4001, reason="Session ended")
            return None
        return payload
    except JWTError:
        await websocket.close(code=4001, reason="Invalid or expired token")
        return None


async def _user_can_access_scan(user: dict, scan_id: str) -> bool:
    """Authorize websocket terminal attach to a scan context."""
    role = str(user.get("role") or "").lower()
    user_id = str(user.get("sub") or "")
    if not user_id:
        return False
    if role == "admin":
        return True

    try:
        scan_uuid = UUID(str(scan_id))
    except Exception:
        return False

    async with async_session() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_uuid))
        scan = result.scalar_one_or_none()
        if not scan:
            return False
        return str(scan.initiated_by) == user_id


async def _call_metasploit_tool(tool_name: str, arguments: dict, timeout: int = 60) -> dict:
    """Call metasploit MCP tool via JSON-RPC and parse JSON text payload."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    headers = {"Content-Type": "application/json"}
    if _MCP_AUTH_TOKEN:
        headers["Authorization"] = f"Bearer {_MCP_AUTH_TOKEN}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(_METASPLOIT_MCP_URL, json=payload, headers=headers)
            data = resp.json()
    except Exception as e:
        return {"success": False, "error": f"Metasploit MCP call failed: {e}"}

    if "error" in data:
        return {"success": False, "error": str(data["error"])}

    try:
        content = (((data.get("result") or {}).get("content") or [])[0] or {}).get("text", "{}")
        parsed = json.loads(content) if isinstance(content, str) else content
        if isinstance(parsed, dict):
            return parsed
        return {"success": True, "data": parsed}
    except Exception:
        return {"success": False, "error": "Failed to parse metasploit MCP response"}

# Active WebSocket connections
active_connections: Dict[str, Set[WebSocket]] = {}


class ConnectionManager:
    """Manage WebSocket connections for real-time updates."""

    def __init__(self):
        self.connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, channel: str):
        await websocket.accept()
        if channel not in self.connections:
            self.connections[channel] = set()
        self.connections[channel].add(websocket)

    def disconnect(self, websocket: WebSocket, channel: str):
        if channel in self.connections:
            self.connections[channel].discard(websocket)

    async def send_to_channel(self, channel: str, message: dict):
        if channel in self.connections:
            for ws in self.connections[channel].copy():
                try:
                    await ws.send_json(message)
                except Exception:
                    self.connections[channel].discard(ws)

    async def send_to_ws(self, websocket: WebSocket, message: dict):
        await websocket.send_json(message)


manager = ConnectionManager()


@router.websocket("/ws/scan/{scan_id}")
async def scan_progress(websocket: WebSocket, scan_id: str, token: Optional[str] = Query(None)):
    """WebSocket endpoint for real-time scan progress updates.

    Subscribes to a Redis pub/sub channel that the ARQ worker publishes to.
    This bridges the cross-process gap (worker container → API container).
    """
    # Authenticate before accepting
    user = await _authenticate_ws(websocket, token)
    if user is None:
        return

    channel = f"scan:{scan_id}"
    await websocket.accept()

    redis_url = settings.REDIS_URL or "redis://redis:6379"
    r = aioredis.from_url(redis_url)
    pubsub = r.pubsub()
    await pubsub.subscribe(channel)

    stop_event = asyncio.Event()

    async def _forward_redis():
        """Read Redis messages and push to WebSocket."""
        try:
            async for message in pubsub.listen():
                if stop_event.is_set():
                    break
                if message["type"] == "message":
                    data = message["data"]
                    if isinstance(data, bytes):
                        data = data.decode()
                    try:
                        await websocket.send_text(data)
                    except Exception as e:
                        log.warning(f"Failed to send WebSocket message: {e}")
                        break
                    # Close the connection once the scan is finished
                    try:
                        parsed = json.loads(data)
                        if parsed.get("type") in ("complete", "cancelled") or (
                            parsed.get("type") == "status"
                            and parsed.get("status") in ("completed", "failed")
                        ):
                            stop_event.set()
                            break
                    except Exception:
                        pass
        except Exception as e:
            log.error(f"Redis pubsub error in scan progress WebSocket: {e}")
        finally:
            stop_event.set()

    fwd_task = asyncio.create_task(_forward_redis())
    try:
        while not stop_event.is_set():
            try:
                # Poll for client messages (e.g. cancel) with a short timeout
                data = await asyncio.wait_for(websocket.receive_text(), timeout=1.0)
                msg = json.loads(data)
                if msg.get("action") == "cancel":
                    cancel_msg = json.dumps({"type": "cancelled", "scan_id": scan_id})
                    await r.publish(channel, cancel_msg)
            except asyncio.TimeoutError:
                continue
            except (WebSocketDisconnect, Exception):
                break
    finally:
        stop_event.set()
        fwd_task.cancel()
        try:
            await fwd_task
        except (asyncio.CancelledError, Exception):
            pass
        try:
            await pubsub.unsubscribe(channel)
            await pubsub.aclose()
        except Exception:
            pass
        try:
            await r.aclose()
        except Exception:
            pass


@router.websocket("/ws/chat")
async def chat_stream(websocket: WebSocket, token: Optional[str] = Query(None)):
    """WebSocket endpoint for streaming AI chat responses."""
    user = await _authenticate_ws(websocket, token)
    if user is None:
        return
    await websocket.accept()
    
    from app.api.v1.llm import _get_user_llm_config
    
    try:
        user_id = user.get("sub")
        llm_config = await _get_user_llm_config(user_id) if user_id else None
        provider = llm_config.get("provider", "ollama_remote") if llm_config else "ollama_remote"
        model = llm_config.get("model") if llm_config else None
        base_url = llm_config.get("base_url") if llm_config else None
        api_key = llm_config.get("api_key") if llm_config else None
        
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            content = msg.get('content', '')
            
            if msg.get('action') == 'ping':
                await websocket.send_json({"type": "pong"})
                continue
            
            await websocket.send_json({
                "type": "status",
                "content": "Processing request...",
            })
            
            try:
                async for token in llm_service.chat(
                    prompt=content,
                    provider=provider,
                    model=model,
                    base_url=base_url,
                    api_key=api_key,
                    system_prompt=build_system_prompt() if msg.get('use_system_prompt', True) else None,
                ):
                    await websocket.send_json({
                        "type": "token",
                        "content": token,
                        "done": False,
                    })
                
                await websocket.send_json({
                    "type": "token",
                    "content": "",
                    "done": True,
                })
            except Exception as e:
                log.error(f"LLM streaming error: {e}")
                await websocket.send_json({
                    "type": "error",
                    "content": f"Error processing request: {str(e)}",
                    "done": True,
                })
    except WebSocketDisconnect:
        pass
    except Exception as e:
        log.error(f"WebSocket chat error: {e}")
        try:
            await websocket.close(code=1011, reason=str(e))
        except Exception:
            pass


@router.websocket("/ws/notifications")
async def notifications(websocket: WebSocket, token: Optional[str] = Query(None)):
    """WebSocket endpoint for system notifications."""
    user = await _authenticate_ws(websocket, token)
    if user is None:
        return
    channel = "notifications:global"
    await manager.connect(websocket, channel)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, channel)


@router.websocket("/ws/metasploit/session/{session_id}")
async def metasploit_terminal(
    websocket: WebSocket,
    session_id: int,
    scan_id: str = Query(...),
    token: Optional[str] = Query(None),
):
    """Interactive Metasploit terminal bridge for a specific session.

    Client protocol:
      - send {"action":"command","command":"whoami"}
      - send {"action":"ping"}
      - send {"action":"disconnect"}
    """
    user = await _authenticate_ws(websocket, token)
    if user is None:
        return

    if not await _user_can_access_scan(user, scan_id):
        await websocket.close(code=4003, reason="Forbidden scan access")
        return

    await websocket.accept()

    # Validate session exists (best effort)
    sessions = await _call_metasploit_tool("list_active_sessions", {})
    if not sessions.get("error"):
        metasploit_sessions = (sessions.get("metasploit") or {}) if isinstance(sessions, dict) else {}
        if str(session_id) not in metasploit_sessions and session_id not in metasploit_sessions:
            await websocket.send_json({
                "type": "warning",
                "content": f"Session {session_id} not found in active session list; attach may fail.",
            })

    await websocket.send_json({
        "type": "connected",
        "session_id": session_id,
        "scan_id": scan_id,
        "message": "Metasploit terminal connected",
    })

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except Exception:
                # Support plain text command fallback.
                msg = {"action": "command", "command": raw}

            action = str(msg.get("action") or "command").lower()
            if action == "ping":
                await websocket.send_json({"type": "pong"})
                continue

            if action == "disconnect":
                await websocket.send_json({"type": "closed", "message": "Terminal disconnected"})
                await websocket.close(code=1000)
                return

            if action != "command":
                await websocket.send_json({"type": "error", "content": f"Unsupported action: {action}"})
                continue

            command = str(msg.get("command") or "").strip()
            if not command:
                continue

            result = await _call_metasploit_tool(
                "send_session_command",
                {
                    "session_id": session_id,
                    "command": command,
                    "wait_ms": int(msg.get("wait_ms") or 300),
                    "max_reads": int(msg.get("max_reads") or 8),
                },
                timeout=90,
            )
            if result.get("success") is False:
                await websocket.send_json({
                    "type": "error",
                    "content": result.get("error") or "Command failed",
                    "command": command,
                })
                continue

            await websocket.send_json({
                "type": "output",
                "command": command,
                "session_id": session_id,
                "session_type": result.get("session_type"),
                "content": str(result.get("output") or ""),
            })
    except WebSocketDisconnect:
        return
    except Exception as e:
        log.error("Metasploit terminal websocket error: %s", e)
        try:
            await websocket.close(code=1011, reason=str(e))
        except Exception:
            pass
