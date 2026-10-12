"""
SOCIS-AI-PT — Settings Routes
User settings management for LLM, tools, reports, and system configuration.
"""

import logging
from fastapi import APIRouter, Depends, HTTPException
from app.core.security import require_permission
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from uuid import UUID
from app.services.settings_service import user_settings_service
from app.core.audit import log_audit

logger = logging.getLogger(__name__)
router = APIRouter()


# ─── LLM Settings ─────────────────────────────────────────────

@router.get("/llm")
async def get_llm_settings(
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get user's LLM settings."""
    user_id = UUID(token["sub"])
    
    settings = await user_settings_service.get_llm_settings(db, user_id)
    return settings


@router.post("/llm")
async def save_llm_settings(
    data: dict,
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Save user's LLM settings."""
    user_id = UUID(token["sub"])
    
    # Validate data
    if not data:
        raise HTTPException(status_code=400, detail="Settings data is required")
    
    # Store settings in database for the user
    await user_settings_service.save_llm_settings(db, user_id, data)
    logger.info(f"LLM settings saved for user: {user_id}")
    return {"detail": "LLM settings saved successfully"}


# ─── Tool Settings ────────────────────────────────────────────

@router.get("/tools")
async def get_tool_settings(
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get effective tool settings (global admin policy applied)."""
    user_id = UUID(token["sub"])
    
    settings = await user_settings_service.get_tool_settings(db, user_id)
    return settings


@router.get("/ai-chat-tools")
async def get_ai_chat_tool_catalog(
    token: dict = Depends(require_permission("admin:settings")),
    db: AsyncSession = Depends(get_db),
):
    """Every MCP server and tool the AI chat could call, with its current effective state (server switch + any per-tool
    override) and whether it is exploitation-class (locked: needs SOCIS_AGENT_ALLOW_OFFENSIVE, never admin-settable here)."""
    from app.core.ai_tool_policy import build_catalog, effective_enabled
    from app.mcp.client import get_mcp_client
    from app.api.v1.llm import _MCP_SETTING_TO_SERVER
    from app.services.settings_service import settings_service
    import json as _json

    raw = await settings_service.get_setting(db, "tool_settings_global")
    server_settings: dict = {}
    tool_overrides: dict = {}
    if raw:
        try:
            parsed = _json.loads(raw)
            if isinstance(parsed, dict):
                server_settings = parsed
                ov = parsed.get("tool_overrides")
                tool_overrides = ov if isinstance(ov, dict) else {}
        except Exception:
            pass

    catalog = build_catalog(get_mcp_client()._servers.values())
    for entry in catalog:
        server = entry["server"]
        setting_key = next((k for k, v in _MCP_SETTING_TO_SERVER.items() if v == server), None)
        entry["setting_key"] = setting_key
        entry["server_enabled"] = bool(server_settings.get(setting_key, True)) if setting_key else True
        for t in entry["tools"]:
            key = f"{server}.{t['name']}"
            t["override"] = tool_overrides.get(key)  # True / False / absent (None = inherits the server switch)
            t["effective"] = effective_enabled(server, t["name"], server_settings, tool_overrides, _MCP_SETTING_TO_SERVER)
    return {"servers": catalog}


@router.post("/tools")
async def save_tool_settings(
    data: dict,
    token: dict = Depends(require_permission("admin:settings")),
    db: AsyncSession = Depends(get_db),
):
    """Save global tool settings (admin only). `tool_overrides` (per-tool allow/deny for the AI chat) is validated against the
    live tool catalog and the exploitation-class floor (core/ai_tool_policy.py); invalid entries are dropped, not fatal."""
    if not data:
        raise HTTPException(status_code=400, detail="Settings data is required")

    from app.core.ai_tool_policy import build_catalog, sanitize_overrides, tool_key
    from app.mcp.client import get_mcp_client
    from app.services.settings_service import settings_service
    import json as _json
    catalog = build_catalog(get_mcp_client()._servers.values())
    catalog_keys = {tool_key(s["server"], t["name"]) for s in catalog for t in s["tools"]}
    if "tool_overrides" in data:
        # An explicit value (even an empty object) REPLACES the stored overrides.
        clean_overrides, problems = sanitize_overrides(data.get("tool_overrides"), catalog_keys)
    else:
        # A save that does not mention tool_overrides (the per-server switches alone, an older client) must leave the stored
        # per-tool choices exactly as they are — it used to be impossible to tell "unchanged" from "clear everything".
        problems = []
        clean_overrides = {}
        raw = await settings_service.get_setting(db, "tool_settings_global")
        if raw:
            try:
                prev = _json.loads(raw)
                if isinstance(prev, dict) and isinstance(prev.get("tool_overrides"), dict):
                    clean_overrides = prev["tool_overrides"]
            except Exception:
                pass
    data = {**data, "tool_overrides": clean_overrides}

    saved = await user_settings_service.save_global_tool_settings(db, data, catalog_keys=catalog_keys)
    await log_audit(db, action="admin:tool_policy_update", user_id=UUID(token["sub"]), resource_type="platform_settings",
                    resource_id="tool_settings_global", details={"tool_overrides": clean_overrides, "rejected": problems})
    await db.commit()
    logger.info(f"Global tool settings saved by admin: {token.get('sub')}")
    resp = {"detail": "Global tool settings saved successfully", "settings": saved}
    if problems:
        resp["warnings"] = problems
    return resp


# ─── Report Settings ──────────────────────────────────────────

@router.get("/reports")
async def get_report_settings(
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get user's report settings."""
    user_id = UUID(token["sub"])
    
    settings = await user_settings_service.get_report_settings(db, user_id)
    return settings


@router.post("/reports")
async def save_report_settings(
    data: dict,
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Save user's report settings."""
    user_id = UUID(token["sub"])
    
    if not data:
        raise HTTPException(status_code=400, detail="Settings data is required")
    
    # Validate color format
    if "brand_color" in data:
        color = data["brand_color"]
        if not color.startswith("#") or len(color) not in (4, 7):
            raise HTTPException(status_code=400, detail="Invalid color format")
    
    # Validate logo addresses (the report server fetches these, so internal / non-http addresses are refused)
    from app.core.report_safety import validate_logo_url_for_save
    for _key in ("brand_logo_url", "customer_logo_url"):
        if _key in data:
            _problem = validate_logo_url_for_save(data[_key])
            if _problem:
                raise HTTPException(status_code=400, detail=_problem)

    # Validate report theme
    if "report_theme" in data:
        theme = data["report_theme"]
        if theme not in ("dark", "light"):
            raise HTTPException(status_code=400, detail="Invalid theme. Must be 'dark' or 'light'")
    
    # Store settings in database for the user
    await user_settings_service.save_report_settings(db, user_id, data)
    logger.info(f"Report settings saved for user: {user_id}")
    return {"detail": "Report settings saved successfully"}


# ─── System Settings ──────────────────────────────────────────

@router.get("/system")
async def get_system_settings(
    token: dict = Depends(require_permission("admin:settings")),
    db: AsyncSession = Depends(get_db),
):
    """Get system settings (admin only)."""
    # System settings are platform-wide, fetched from PlatformSettings
    from app.services.settings_service import settings_service
    all_settings = await settings_service.get_all_settings(db)
    
    return {
        "rate_limit_enabled": all_settings.get("rate_limit_enabled", "true").lower() == "true",
        "rate_limit_requests": int(all_settings.get("rate_limit_requests", 100)),
        "rate_limit_window": int(all_settings.get("rate_limit_window", 60)),
        "deployment_mode": all_settings.get("deployment_mode", "development"),
        "email_on_scan_complete": all_settings.get("email_on_scan_complete", "true").lower() == "true",
        "email_on_vulnerability": all_settings.get("email_on_vulnerability", "true").lower() == "true",
        "email_on_critical_finding": all_settings.get("email_on_critical_finding", "true").lower() == "true",
    }


@router.post("/system")
async def save_system_settings(
    data: dict,
    token: dict = Depends(require_permission("admin:settings")),
    db: AsyncSession = Depends(get_db),
):
    """Save system settings (admin only)."""
    if not data:
        raise HTTPException(status_code=400, detail="Settings data is required")
    
    # Validate rate limit settings
    if "rate_limit_requests" in data:
        if not isinstance(data["rate_limit_requests"], int) or data["rate_limit_requests"] < 1:
            raise HTTPException(status_code=400, detail="rate_limit_requests must be a positive integer")
    
    if "rate_limit_window" in data:
        if not isinstance(data["rate_limit_window"], int) or data["rate_limit_window"] < 1:
            raise HTTPException(status_code=400, detail="rate_limit_window must be a positive integer")
    
    # Store settings in database
    from app.services.settings_service import settings_service
    for key, value in data.items():
        await settings_service.set_setting(db, key, str(value), f"System setting: {key}")
    
    logger.info("System settings updated")
    return {"detail": "System settings saved successfully"}


# ─── Notification Settings ────────────────────────────────────

@router.get("/notifications")
async def get_notification_settings(
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get user's notification settings."""
    user_id = UUID(token["sub"])
    
    settings = await user_settings_service.get_notification_settings(db, user_id)
    return settings


@router.post("/notifications")
async def save_notification_settings(
    data: dict,
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Save user's notification settings."""
    user_id = UUID(token["sub"])
    
    if not data:
        raise HTTPException(status_code=400, detail="Settings data is required")
    
    # Store settings in database for the user
    await user_settings_service.save_notification_settings(db, user_id, data)
    logger.info(f"Notification settings saved for user: {user_id}")
    return {"detail": "Notification settings saved successfully"}
