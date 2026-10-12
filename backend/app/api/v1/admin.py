"""
SOCIS-AI-PT — Admin Routes (Full Implementation)
User management, system settings, LLM config, audit logs.
"""

import re
from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr, Field, field_validator, HttpUrl
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.security import require_permission, hash_password, ROLE_PERMISSIONS, UserRole
from app.core.admin_safety import ASSIGNABLE_ROLES, check_admin_safety, describe_delete_blockers, is_effective_admin, validate_username
from app.core.password_policy import generate_temp_password, validate_password_strength
from app.core.token_blocklist import revoke_user_sessions
from app.core.llm_providers import normalize_provider
from sqlalchemy.exc import IntegrityError
from app.core.audit import log_audit
from app.models.user import User, Role
from app.models.audit_log import AuditLog
from app.models.llm_config import LLMConfig

router = APIRouter()


# ─── Service Health ──────────────────────────────────────────

@router.get("/services-health")
async def services_health(
    token: dict = Depends(require_permission("admin:access")),
    db: AsyncSession = Depends(get_db),
):
    """Service health (admin only). Ollama is the EXTERNAL server configured under
    Admin -> Settings -> Remote Ollama (or OLLAMA_REMOTE_URL)."""
    import httpx
    from app.config import settings
    from app.core.netguard import acheck_url
    from app.services.settings_service import settings_service

    status = {}
    url = await settings_service.get_ollama_remote_url(db) or settings.OLLAMA_REMOTE_URL
    if not url:
        status["ollama"] = {"configured": False, "connected": False}
    else:
        try:
            await acheck_url(url, allow_private=True)
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(f"{url.rstrip('/')}/api/tags")
            ok = resp.status_code == 200
            status["ollama"] = {"configured": True, "connected": ok,
                                "models": len(resp.json().get("models", [])) if ok else 0}
        except Exception:
            status["ollama"] = {"configured": True, "connected": False}
    return status


# ─── Dashboard Stats ──────────────────────────────────────────

@router.get("/dashboard")
async def admin_dashboard(
    token: dict = Depends(require_permission("admin:access")),
    db: AsyncSession = Depends(get_db),
):
    """Get admin dashboard stats."""
    from app.models.scan import Scan
    from app.models.vulnerability import Vulnerability
    from app.models.project import Project

    user_count = (await db.execute(select(func.count()).select_from(User))).scalar()
    project_count = (await db.execute(select(func.count()).select_from(Project))).scalar()
    scan_count = (await db.execute(select(func.count()).select_from(Scan))).scalar()
    vuln_count = (await db.execute(select(func.count()).select_from(Vulnerability))).scalar()

    return {
        "users": user_count,
        "projects": project_count,
        "scans": scan_count,
        "vulnerabilities": vuln_count,
    }


# ─── User Management ─────────────────────────────────────────

class UserUpdateAdmin(BaseModel):
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None
    role: Optional[str] = None
    full_name: Optional[str] = Field(default=None, max_length=255)


class AdminUserCreate(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    full_name: Optional[str] = Field(default=None, max_length=255)
    role: str = "viewer"
    # Leave empty to generate a one-time temporary password (returned once in the response).
    password: Optional[str] = None
    is_active: bool = True


class PasswordReset(BaseModel):
    password: Optional[str] = None


def _role_name(user: User) -> Optional[str]:
    return user.roles[0].name if user.roles else None


def _is_admin(user: User) -> bool:
    # Permissions come from the role, not the is_superuser flag (see core/admin_safety.is_effective_admin).
    return is_effective_admin(r.name for r in user.roles)


def _user_out(u: User) -> dict:
    return {
        "id": str(u.id),
        "email": u.email,
        "username": u.username,
        "full_name": u.full_name,
        "role": _role_name(u),
        "is_active": u.is_active,
        "is_superuser": u.is_superuser,
        "mfa_enabled": bool(u.totp_enabled),
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "last_login": u.last_login.isoformat() if u.last_login else None,
    }


async def _active_admin_ids(db: AsyncSession) -> set:
    rows = (await db.execute(select(User).where(User.is_active == True))).scalars().all()  # noqa: E712
    return {str(u.id) for u in rows if _is_admin(u)}


async def _get_assignable_role(db: AsyncSession, name: str) -> Role:
    if name not in ASSIGNABLE_ROLES:
        raise HTTPException(status_code=400, detail=f"Role must be one of: {', '.join(ASSIGNABLE_ROLES)}")
    role = (await db.execute(select(Role).where(Role.name == name))).scalar_one_or_none()
    if not role:
        raise HTTPException(status_code=400, detail=f"Role '{name}' is not set up on this server")
    return role


@router.get("/users")
async def list_users(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    q: Optional[str] = Query(None, max_length=100),
    token: dict = Depends(require_permission("users:read")),
    db: AsyncSession = Depends(get_db),
):
    """List users with their role (admin only). `q` filters by email, username or name."""
    stmt = select(User)
    count_stmt = select(func.count()).select_from(User)
    if q and q.strip():
        like = f"%{q.strip()}%"
        cond = (User.email.ilike(like)) | (User.username.ilike(like)) | (User.full_name.ilike(like))
        stmt, count_stmt = stmt.where(cond), count_stmt.where(cond)
    total = (await db.execute(count_stmt)).scalar()
    result = await db.execute(stmt.order_by(User.created_at.desc()).offset((page - 1) * per_page).limit(per_page))
    return {"users": [_user_out(u) for u in result.scalars().all()], "total": total}


@router.get("/roles")
async def list_roles(
    token: dict = Depends(require_permission("users:read")),
    db: AsyncSession = Depends(get_db),
):
    """Roles an admin can assign, with their permissions and how many users hold each."""
    users = (await db.execute(select(User))).scalars().all()
    counts: dict = {}
    for u in users:
        n = _role_name(u)
        counts[n] = counts.get(n, 0) + 1
    out = []
    for name in ASSIGNABLE_ROLES:
        role = (await db.execute(select(Role).where(Role.name == name))).scalar_one_or_none()
        out.append({
            "name": name,
            "description": role.description if role else None,
            "permissions": sorted(ROLE_PERMISSIONS.get(UserRole(name), set())),
            "user_count": counts.get(name, 0),
        })
    return {"roles": out}


@router.post("/users", status_code=201)
async def create_user(
    data: AdminUserCreate,
    token: dict = Depends(require_permission("users:write")),
    db: AsyncSession = Depends(get_db),
):
    """Create a user account (admin only). Self-registration is closed by default, so this is how accounts are added."""
    email = data.email.strip()
    err = validate_username(data.username)
    if err:
        raise HTTPException(status_code=400, detail=err)
    role = await _get_assignable_role(db, data.role)

    generated = not (data.password or "").strip()
    password = generate_temp_password() if generated else data.password
    if not generated:
        try:
            validate_password_strength(password)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

    if (await db.execute(select(User).where(func.lower(User.email) == email.lower()))).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A user with this email already exists")
    if (await db.execute(select(User).where(func.lower(User.username) == data.username.lower()))).scalar_one_or_none():
        raise HTTPException(status_code=409, detail="That username is already taken")

    user = User(
        email=email, username=data.username, full_name=(data.full_name or None),
        password_hash=hash_password(password), is_active=data.is_active,
    )
    user.roles.append(role)
    db.add(user)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="A user with this email or username already exists")
    await log_audit(
        db, action="admin:user_create", user_id=UUID(token["sub"]),
        resource_type="user", resource_id=str(user.id),
        details={"username": user.username, "email": user.email, "role": role.name, "password_generated": generated},
    )
    await db.commit()
    await db.refresh(user)
    out = _user_out(user)
    if generated:
        out["temporary_password"] = password   # shown once; never stored in clear text or in the audit log
    return out


@router.patch("/users/{user_id}")
async def update_user(
    user_id: UUID,
    data: UserUpdateAdmin,
    token: dict = Depends(require_permission("users:write")),
    db: AsyncSession = Depends(get_db),
):
    """Change a user's role, status or name. Deactivating or changing the role signs them out immediately."""
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    new_role = await _get_assignable_role(db, data.role) if data.role else None
    new_active = data.is_active if data.is_active is not None else user.is_active
    new_superuser = data.is_superuser if data.is_superuser is not None else user.is_superuser
    role_after = new_role.name if new_role else _role_name(user)

    err = check_admin_safety(
        actor_id=token["sub"], target_id=user.id,
        target_is_admin_now=_is_admin(user),
        target_will_be_admin=role_after == "admin",
        target_will_be_active=bool(new_active),
        active_admin_ids=await _active_admin_ids(db),
    )
    if err:
        raise HTTPException(status_code=400, detail=err)

    access_changed = (new_active != user.is_active) or (new_superuser != user.is_superuser) or (
        new_role is not None and role_after != _role_name(user))
    user.is_active = new_active
    user.is_superuser = new_superuser
    if new_role:
        user.roles = [new_role]
    if data.full_name is not None:
        user.full_name = data.full_name or None

    await log_audit(
        db, action="admin:user_update", user_id=UUID(token["sub"]),
        resource_type="user", resource_id=str(user_id), details=data.model_dump(exclude_none=True),
    )
    await db.commit()
    if access_changed:
        await revoke_user_sessions(str(user_id))
    return {"message": "User updated", "user_id": str(user_id)}


@router.post("/users/{user_id}/reset-password")
async def reset_user_password(
    user_id: UUID,
    data: Optional[PasswordReset] = None,
    token: dict = Depends(require_permission("users:write")),
    db: AsyncSession = Depends(get_db),
):
    """Set a new password (or generate a one-time temporary one) and sign the user out everywhere."""
    data = data or PasswordReset()
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    generated = not (data.password or "").strip()
    password = generate_temp_password() if generated else data.password
    if not generated:
        try:
            validate_password_strength(password)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    user.password_hash = hash_password(password)
    await log_audit(
        db, action="admin:user_password_reset", user_id=UUID(token["sub"]),
        resource_type="user", resource_id=str(user_id), details={"password_generated": generated},
    )
    await db.commit()
    await revoke_user_sessions(str(user_id), include_refresh=True)
    out = {"message": "Password reset", "user_id": str(user_id)}
    if generated:
        out["temporary_password"] = password
    return out


@router.post("/users/{user_id}/reset-mfa")
async def reset_user_mfa(
    user_id: UUID,
    token: dict = Depends(require_permission("users:write")),
    db: AsyncSession = Depends(get_db),
):
    """Turn two-factor off for a user who lost their device, and sign them out everywhere. They sign in with their password
    and can enrol a new authenticator from Settings > Security."""
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    was_enabled = bool(user.totp_enabled)
    user.totp_enabled = False
    user.totp_secret = ""  # type: ignore[assignment]
    await log_audit(
        db, action="admin:user_mfa_reset", user_id=UUID(token["sub"]),
        resource_type="user", resource_id=str(user_id), details={"was_enabled": was_enabled, "username": user.username},
    )
    await db.commit()
    await revoke_user_sessions(str(user_id), include_refresh=True)
    return {"message": "Two-factor authentication was reset", "was_enabled": was_enabled}


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: UUID,
    token: dict = Depends(require_permission("users:delete")),
    db: AsyncSession = Depends(get_db),
):
    """Delete a user account.

    Refuses to delete yourself or the last active administrator. A user who owns projects, scans, reports or scan
    schedules cannot be deleted (it would orphan that work): the response explains and suggests deactivating.
    Audit history is kept: their audit rows are detached from the account, not deleted.
    """
    from sqlalchemy import update
    from app.models.project import Project
    from app.models.scan import Scan
    from app.models.report import Report
    from app.models.scan_schedule import ScanSchedule

    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    err = check_admin_safety(
        actor_id=token["sub"], target_id=user.id, target_is_admin_now=_is_admin(user),
        target_will_be_admin=False, target_will_be_active=False,
        active_admin_ids=await _active_admin_ids(db),
    )
    if err:
        raise HTTPException(status_code=400, detail=err)

    async def _count(model, column) -> int:
        return int((await db.execute(select(func.count()).select_from(model).where(column == user_id))).scalar() or 0)

    blocker = describe_delete_blockers(
        projects=await _count(Project, Project.owner_id),
        scans=await _count(Scan, Scan.initiated_by),
        reports=await _count(Report, Report.generated_by),
        schedules=await _count(ScanSchedule, ScanSchedule.created_by),
    )
    if blocker:
        raise HTTPException(status_code=409, detail=blocker)

    username = user.username
    # audit_logs.user_id is nullable but has no ON DELETE rule, so every user who ever signed in (each login is an
    # audit row) used to make the delete fail with a 500. Keep the history; just detach it from the deleted account.
    await db.execute(update(AuditLog).where(AuditLog.user_id == user_id).values(user_id=None))
    await log_audit(
        db, action="admin:user_delete", user_id=UUID(token["sub"]),
        resource_type="user", resource_id=str(user_id), details={"deleted_username": username},
    )
    await db.delete(user)
    try:
        await db.commit()
    except IntegrityError:
        # Some other table still references this user. Never answer 500 for that: explain and suggest deactivating.
        await db.rollback()
        raise HTTPException(
            status_code=409,
            detail="This user is still referenced by other records and can't be deleted. Deactivate the account instead.",
        )
    await revoke_user_sessions(str(user_id), include_refresh=True)


# ─── LLM Config Management ───────────────────────────────────

class LLMConfigCreate(BaseModel):
    name: str
    provider: str
    model_name: str
    api_url: Optional[str] = None
    api_key: Optional[str] = None
    parameters: Optional[dict] = None
    is_default: bool = False


@router.get("/llm-configs")
async def list_llm_configs(
    token: dict = Depends(require_permission("admin:settings")),
    db: AsyncSession = Depends(get_db),
):
    """List all LLM configurations."""
    result = await db.execute(select(LLMConfig))
    configs = result.scalars().all()
    return [
        {
            "id": str(c.id),
            "name": c.name,
            "provider": c.provider,
            "model_name": c.model_name,
            "is_default": c.is_default,
            "is_active": c.is_active,
            "parameters": c.parameters,
        }
        for c in configs
    ]


class LLMFetchModelsRequest(BaseModel):
    provider: str
    api_key: str
    api_url: Optional[str] = None


# Fixed, non-configurable endpoint per provider — never built from caller input, so a request can never be pointed
# at an arbitrary host via this field (the optional api_url override below is still SSRF-checked separately for
# providers that do allow a custom/proxy base URL).
_PROVIDER_MODELS_ENDPOINT = {
    "openai": "https://api.openai.com/v1/models",
    "openrouter": "https://openrouter.ai/api/v1/models",
    "grok": "https://api.x.ai/v1/models",
    "mistral": "https://api.mistral.ai/v1/models",
    "anthropic": "https://api.anthropic.com/v1/models",
}


@router.post("/llm-configs/fetch-models")
async def fetch_llm_models(
    body: LLMFetchModelsRequest,
    token: dict = Depends(require_permission("admin:settings")),
):
    """Live-probe a provider's real model list using a freshly-entered API key — called from the "Add LLM Provider"
    modal so the admin can pick a model from a real, current list instead of typing an exact model-name string from
    memory. Nothing here is persisted; this only tests connectivity and returns what the provider's API reports.
    The key is never logged.
    """
    import httpx
    provider = normalize_provider(body.provider)
    if provider not in _PROVIDER_MODELS_ENDPOINT:
        return {"reachable": False, "models": [], "error": f"Model listing isn't supported for provider '{provider}'."}
    if not body.api_key or not body.api_key.strip():
        return {"reachable": False, "models": [], "error": "An API key is required to fetch models."}

    url = (body.api_url or _PROVIDER_MODELS_ENDPOINT[provider]).strip()
    try:
        from app.core.netguard import acheck_url
        await acheck_url(url, allow_private=False)
    except ValueError as exc:
        return {"reachable": False, "models": [], "error": f"That URL is not allowed: {exc}"}

    if provider == "anthropic":
        headers = {"x-api-key": body.api_key, "anthropic-version": "2023-06-01"}
    else:
        headers = {"Authorization": f"Bearer {body.api_key}"}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers=headers)
    except httpx.TimeoutException:
        return {"reachable": False, "models": [], "error": "Timed out contacting the provider."}
    except httpx.HTTPError as exc:
        return {"reachable": False, "models": [], "error": f"Connection failed: {exc}"}

    if resp.status_code == 401:
        return {"reachable": False, "models": [], "error": "That API key was rejected (401 Unauthorized)."}
    if resp.status_code != 200:
        return {"reachable": False, "models": [], "error": f"Provider returned HTTP {resp.status_code}."}

    try:
        data = resp.json()
    except ValueError:
        return {"reachable": False, "models": [], "error": "The provider's response wasn't valid JSON."}

    raw_models = data.get("data", [])
    models = [
        {"id": m.get("id"), "label": m.get("display_name") or m.get("id")}
        for m in raw_models
        if isinstance(m, dict) and m.get("id")
    ]
    models.sort(key=lambda m: m["id"])
    return {"reachable": True, "models": models, "error": None}


@router.post("/llm-configs", status_code=201)
async def create_llm_config(
    data: LLMConfigCreate,
    token: dict = Depends(require_permission("llm:configure")),
    db: AsyncSession = Depends(get_db),
):
    """Add a new LLM provider configuration."""
    from app.core.encryption import encrypt_secret

    config = LLMConfig(
        name=data.name,
        provider=data.provider,
        model_name=data.model_name,
        api_url=data.api_url,
        parameters=data.parameters or {"temperature": 0.7, "max_tokens": 4096},
        is_default=data.is_default,
    )
    if data.api_key:
        config.api_key_encrypted = encrypt_secret(data.api_key)
    db.add(config)
    await db.flush()
    if data.is_default:
        # Exactly one config is ever the platform default — un-default every other existing row, same invariant
        # set-default enforces. Without this, creating a second "default" config left two rows both marked default,
        # making resolve_default_llm_config's ordering pick between them arbitrarily.
        others = (await db.execute(select(LLMConfig).where(LLMConfig.id != config.id))).scalars().all()
        for c in others:
            c.is_default = False
    await log_audit(
        db, action="admin:llm_config_create",
        user_id=UUID(token["sub"]),
        resource_type="llm_config", resource_id=str(config.id),
        details={"name": data.name, "provider": data.provider, "model_name": data.model_name},
    )
    await db.commit()
    await db.refresh(config)
    return {"id": str(config.id), "message": "LLM config created"}


@router.post("/llm-configs/{config_id}/set-default", status_code=200)
async def set_default_llm_config(
    config_id: UUID,
    token: dict = Depends(require_permission("llm:configure")),
    db: AsyncSession = Depends(get_db),
):
    """Mark one LLM config as THE platform default (the one an unattended feature — the automatic post-scan
    analysis, or any future feature that doesn't ask the user to choose — actually uses). Previously there was no
    way to change this after creation at all (only set at creation time, via create_llm_config's is_default flag,
    which never un-defaulted any other row either) — an admin with two saved providers had no way to switch which
    one was the default without deleting and recreating a config. This endpoint un-defaults every other row first,
    so exactly one config is ever marked default, matching what resolve_default_llm_config's ordering assumes.
    """
    result = await db.execute(select(LLMConfig).where(LLMConfig.id == config_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="LLM config not found")

    all_configs = (await db.execute(select(LLMConfig))).scalars().all()
    for c in all_configs:
        c.is_default = (c.id == config_id)

    await log_audit(
        db, action="admin:llm_config_set_default",
        user_id=UUID(token["sub"]),
        resource_type="llm_config", resource_id=str(config_id),
        details={"name": target.name, "provider": str(getattr(target.provider, "value", target.provider))},
    )
    await db.commit()
    return {"id": str(config_id), "message": "Platform default updated"}


@router.delete("/llm-configs/{config_id}", status_code=204)
async def delete_llm_config(
    config_id: UUID,
    token: dict = Depends(require_permission("llm:configure")),
    db: AsyncSession = Depends(get_db),
):
    """Delete an LLM configuration."""
    result = await db.execute(select(LLMConfig).where(LLMConfig.id == config_id))
    config = result.scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=404, detail="LLM config not found")
    await log_audit(
        db, action="admin:llm_config_delete",
        user_id=UUID(token["sub"]),
        resource_type="llm_config", resource_id=str(config_id),
        details={"name": config.name},
    )
    await db.delete(config)
    await db.commit()


# ─── Audit Logs ──────────────────────────────────────────────

@router.get("/audit-logs")
async def list_audit_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    token: dict = Depends(require_permission("admin:access")),
    db: AsyncSession = Depends(get_db),
):
    """List system audit logs."""
    total = (await db.execute(select(func.count()).select_from(AuditLog))).scalar()
    result = await db.execute(
        select(AuditLog).order_by(AuditLog.created_at.desc())
        .offset((page - 1) * per_page).limit(per_page)
    )
    logs = result.scalars().all()
    return {
        "logs": [
            {"id": str(l.id), "action": l.action, "user_id": str(l.user_id),
             "resource_type": l.resource_type, "ip_address": l.ip_address,
             "created_at": l.created_at.isoformat()}
            for l in logs
        ],
        "total": total,
    }


# ─── Platform Settings ──────────────────────────────────────────

class RemoteOllamaSettingsUpdate(BaseModel):
    """Settings for remote Ollama configuration."""
    url: str  # e.g., http://192.168.20.13:11434
    model: Optional[str] = None  # e.g., qwen3.5:4b


@router.get("/settings/remote-ollama")
async def get_remote_ollama_settings(
    token: dict = Depends(require_permission("admin:access")),
    db: AsyncSession = Depends(get_db),
):
    """Get remote Ollama configuration."""
    from app.services.settings_service import settings_service
    
    url = await settings_service.get_ollama_remote_url(db)
    model = await settings_service.get_ollama_remote_model(db)
    
    return {
        "url": url,
        "model": model,
    }


@router.post("/settings/remote-ollama")
async def update_remote_ollama_settings(
    data: RemoteOllamaSettingsUpdate,
    token: dict = Depends(require_permission("admin:access")),
    db: AsyncSession = Depends(get_db),
):
    """Save remote Ollama configuration. Does NOT block on connectivity — use /test to verify."""
    from app.services.settings_service import settings_service

    await settings_service.set_ollama_remote_url(db, data.url)
    if data.model:
        await settings_service.set_ollama_remote_model(db, data.model)

    return {
        "message": "Remote Ollama settings saved. Use the Test Connection button to verify reachability.",
        "url": data.url,
        "model": data.model,
    }


class TestRemoteOllamaRequest(BaseModel):
    url: Optional[str] = None  # If provided, test this URL instead of the DB-saved one


@router.post("/settings/remote-ollama/test")
async def test_remote_ollama_connection(
    req: Optional[TestRemoteOllamaRequest] = Body(default=None),
    token: dict = Depends(require_permission("admin:access")),
    db: AsyncSession = Depends(get_db),
):
    """Test connectivity to the configured remote Ollama server and return available models."""
    import httpx
    from app.services.settings_service import settings_service

    # Use URL from request body if provided, else fall back to DB-saved URL
    url = (req.url.rstrip('/') if req and req.url else None) or await settings_service.get_ollama_remote_url(db)
    if not url:
        raise HTTPException(status_code=400, detail="No remote Ollama URL configured. Save a URL first.")

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{url}/api/tags")
            if resp.status_code != 200:
                return {
                    "reachable": False,
                    "url": url,
                    "error": f"HTTP {resp.status_code}",
                    "models": [],
                }
            data = resp.json()
            models = sorted([m["name"] for m in data.get("models", [])])
            return {
                "reachable": True,
                "url": url,
                "models": models,
            }
    except httpx.ConnectError as e:
        return {"reachable": False, "url": url, "error": f"Connection refused: {e}", "models": []}
    except httpx.TimeoutException:
        return {"reachable": False, "url": url, "error": "Connection timed out (10s)", "models": []}
    except Exception as e:
        return {"reachable": False, "url": url, "error": str(e), "models": []}


class SSOSettingsUpdate(BaseModel):
    google_enabled: bool = False
    google_client_id: str = ""
    google_client_secret: Optional[str] = None
    microsoft_enabled: bool = False
    microsoft_client_id: str = ""
    microsoft_client_secret: Optional[str] = None
    microsoft_tenant_id: str = "common"
    sso_allowed_domains: str = ""
    sso_auto_provision: bool = False

    @field_validator("sso_allowed_domains")
    @classmethod
    def validate_allowed_domains(cls, v: str) -> str:
        from app.core.sso_policy import parse_domains
        typed = [t for t in re.split(r"[,\s;]+", (v or "").strip()) if t]
        good = parse_domains(v)
        if len(good) != len({t.lstrip("@").strip(".").lower() for t in typed}):
            raise ValueError("Allowed domains must look like example.com (comma-separated)")
        return ", ".join(sorted(good))

    @field_validator("google_client_id", "microsoft_client_id")
    @classmethod
    def validate_client_id(cls, v: str) -> str:
        v = (v or "").strip()
        if v and len(v) > 512:
            raise ValueError("Client ID is too long")
        return v

    @field_validator("google_client_secret", "microsoft_client_secret")
    @classmethod
    def validate_client_secret(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        vv = v.strip()
        if vv and len(vv) > 2048:
            raise ValueError("Client secret is too long")
        return vv or None

    @field_validator("microsoft_tenant_id")
    @classmethod
    def validate_tenant_id(cls, v: str) -> str:
        vv = (v or "common").strip() or "common"
        if vv == "common":
            return vv
        if not re.fullmatch(r"[A-Za-z0-9\-]{2,128}", vv):
            raise ValueError("Invalid tenant ID format")
        return vv


@router.get("/settings/sso")
async def get_sso_settings(
    token: dict = Depends(require_permission("admin:settings")),
    db: AsyncSession = Depends(get_db),
):
    """Get SSO provider configuration (without exposing secrets)."""
    from app.services.settings_service import settings_service
    return await settings_service.get_sso_settings(db, include_secrets=False)


@router.post("/settings/sso")
async def update_sso_settings(
    data: SSOSettingsUpdate,
    token: dict = Depends(require_permission("admin:settings")),
    db: AsyncSession = Depends(get_db),
):
    """Save SSO provider configuration with encrypted secret storage."""
    from app.services.settings_service import settings_service

    if data.google_enabled and not data.google_client_id:
        raise HTTPException(status_code=400, detail="Google Client ID is required when Google SSO is enabled")
    if data.microsoft_enabled and not data.microsoft_client_id:
        raise HTTPException(status_code=400, detail="Microsoft Client ID is required when Microsoft SSO is enabled")

    saved = await settings_service.save_sso_settings(db, data.model_dump())
    await log_audit(
        db,
        action="admin:sso_settings_update",
        user_id=UUID(token["sub"]),
        resource_type="platform_settings",
        resource_id="sso_settings",
        details={
            "google_enabled": saved.get("google_enabled", False),
            "microsoft_enabled": saved.get("microsoft_enabled", False),
            "microsoft_tenant_id": saved.get("microsoft_tenant_id", "common"),
            "sso_allowed_domains": saved.get("sso_allowed_domains", ""),
            "sso_auto_provision": saved.get("sso_auto_provision", False),
            "google_secret_configured": saved.get("google_client_secret_configured", False),
            "microsoft_secret_configured": saved.get("microsoft_client_secret_configured", False),
        },
    )
    await db.commit()
    return saved


class NotificationDeliverySettingsUpdate(BaseModel):
    enabled: bool = False
    provider: str = "disabled"  # disabled | microsoft_graph | microsoft_smtp
    sender_email: str = ""
    reply_to_email: str = ""

    graph_tenant_id: str = "common"
    graph_client_id: str = ""
    graph_client_secret: Optional[str] = None

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: Optional[str] = None
    smtp_use_starttls: bool = True
    smtp_use_ssl: bool = False

    webhook_parallel_enabled: bool = True

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        vv = (v or "disabled").strip().lower()
        if vv not in ("disabled", "microsoft_graph", "microsoft_smtp"):
            raise ValueError("provider must be one of: disabled, microsoft_graph, microsoft_smtp")
        return vv

    @field_validator("smtp_port")
    @classmethod
    def validate_smtp_port(cls, v: int) -> int:
        if v < 1 or v > 65535:
            raise ValueError("smtp_port must be between 1 and 65535")
        return v


@router.get("/settings/notification-delivery")
async def get_notification_delivery_settings(
    token: dict = Depends(require_permission("admin:settings")),
    db: AsyncSession = Depends(get_db),
):
    """Get notification delivery configuration (without exposing secrets)."""
    from app.services.settings_service import settings_service
    return await settings_service.get_notification_delivery_settings(db, include_secrets=False)


@router.post("/settings/notification-delivery")
async def update_notification_delivery_settings(
    data: NotificationDeliverySettingsUpdate,
    token: dict = Depends(require_permission("admin:settings")),
    db: AsyncSession = Depends(get_db),
):
    """Save enterprise notification delivery provider settings."""
    from app.services.settings_service import settings_service

    if data.enabled and data.provider == "microsoft_graph":
        if not data.sender_email.strip():
            raise HTTPException(status_code=400, detail="sender_email is required for Microsoft Graph provider")
        if not data.graph_client_id.strip():
            raise HTTPException(status_code=400, detail="graph_client_id is required for Microsoft Graph provider")

    if data.enabled and data.provider == "microsoft_smtp":
        if not data.sender_email.strip():
            raise HTTPException(status_code=400, detail="sender_email is required for SMTP provider")
        if not data.smtp_host.strip():
            raise HTTPException(status_code=400, detail="smtp_host is required for SMTP provider")

    saved = await settings_service.save_notification_delivery_settings(db, data.model_dump())
    await log_audit(
        db,
        action="admin:notification_delivery_settings_update",
        user_id=UUID(token["sub"]),
        resource_type="platform_settings",
        resource_id="notification_delivery_settings",
        details={
            "enabled": saved.get("enabled", False),
            "provider": saved.get("provider", "disabled"),
            "sender_email": bool(saved.get("sender_email")),
            "graph_secret_configured": saved.get("graph_client_secret_configured", False),
            "smtp_password_configured": saved.get("smtp_password_configured", False),
            "webhook_parallel_enabled": saved.get("webhook_parallel_enabled", True),
        },
    )
    await db.commit()
    return saved


class NotificationDeliveryTestRequest(BaseModel):
    recipient_email: Optional[str] = None
    include_webhook: bool = True


@router.post("/settings/notification-delivery/test")
async def test_notification_delivery_settings(
    data: NotificationDeliveryTestRequest,
    token: dict = Depends(require_permission("admin:settings")),
    db: AsyncSession = Depends(get_db),
):
    """Send a test notification using configured enterprise delivery settings."""
    from app.models.user import User
    from app.services.notification_delivery_service import notification_delivery_service

    recipient_email = (data.recipient_email or "").strip()
    if not recipient_email:
        user = await db.get(User, UUID(token["sub"]))
        recipient_email = (user.email if user and user.email else "").strip()

    if not recipient_email:
        raise HTTPException(status_code=400, detail="recipient_email is required when your profile has no email")

    result = await notification_delivery_service.send_test_notification(
        db=db,
        user_id=token["sub"],
        recipient_email=recipient_email,
        include_webhook=data.include_webhook,
    )
    return {
        "message": "Test notification dispatched",
        "recipient_email": recipient_email,
        **result,
    }


# ─── Prompt Template Management ─────────────────────────────

from app.models.prompt_template import PromptTemplate


class PromptTemplateCreate(BaseModel):
    name: str
    scan_type: Optional[str] = None
    system_prompt: str
    is_active: bool = True
    is_default: bool = False


class PromptTemplateUpdate(BaseModel):
    name: Optional[str] = None
    scan_type: Optional[str] = None
    system_prompt: Optional[str] = None
    is_active: Optional[bool] = None
    is_default: Optional[bool] = None


@router.get("/prompt-templates")
async def list_prompt_templates(
    token: dict = Depends(require_permission("admin:manage")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(PromptTemplate).order_by(PromptTemplate.scan_type, PromptTemplate.name))
    return result.scalars().all()


@router.post("/prompt-templates", status_code=201)
async def create_prompt_template(
    data: PromptTemplateCreate,
    token: dict = Depends(require_permission("admin:manage")),
    db: AsyncSession = Depends(get_db),
):
    # If this is set as default, unset others for the same scan_type
    if data.is_default:
        await db.execute(
            __import__("sqlalchemy").update(PromptTemplate).where(
                PromptTemplate.scan_type == data.scan_type,
                PromptTemplate.is_default == True,
            ).values(is_default=False)
        )

    tpl = PromptTemplate(**data.model_dump())
    db.add(tpl)
    await db.commit()
    await db.refresh(tpl)
    return {"id": str(tpl.id), "message": "Prompt template created"}


@router.patch("/prompt-templates/{tpl_id}")
async def update_prompt_template(
    tpl_id: UUID,
    data: PromptTemplateUpdate,
    token: dict = Depends(require_permission("admin:manage")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(PromptTemplate).where(PromptTemplate.id == tpl_id))
    tpl = result.scalar_one_or_none()
    if not tpl:
        raise HTTPException(status_code=404, detail="Prompt template not found")
    for field, value in data.model_dump(exclude_none=True).items():
        setattr(tpl, field, value)
    await db.commit()
    return {"id": str(tpl.id), "message": "Updated"}


@router.delete("/prompt-templates/{tpl_id}", status_code=204)
async def delete_prompt_template(
    tpl_id: UUID,
    token: dict = Depends(require_permission("admin:manage")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(PromptTemplate).where(PromptTemplate.id == tpl_id))
    tpl = result.scalar_one_or_none()
    if not tpl:
        raise HTTPException(status_code=404, detail="Prompt template not found")
    if tpl.is_builtin:
        raise HTTPException(status_code=403, detail="Built-in prompt templates cannot be deleted")
    await db.delete(tpl)
    await db.commit()


# ─── Plugin Management ────────────────────────────────────────────────────────

@router.get("/plugins")
async def list_plugins(
    token: dict = Depends(require_permission("admin:manage")),
):
    """List all loaded plugins and their metadata."""
    from app.plugins.loader import plugin_manager
    plugins = []
    for plugin_id, plugin_cls in plugin_manager.plugins.items():
        try:
            instance = plugin_cls()
            plugins.append({
                "id": plugin_id,
                "name": getattr(instance, "name", plugin_id),
                "description": getattr(instance, "description", ""),
                "version": getattr(instance, "version", "unknown"),
                "author": getattr(instance, "author", ""),
                "enabled": True,
            })
        except Exception as e:
            plugins.append({
                "id": plugin_id,
                "name": plugin_id,
                "enabled": False,
                "error": str(e),
            })
    return {"plugins": plugins, "count": len(plugins)}


@router.get("/plugins/manifest")
async def plugin_manifest(
    token: dict = Depends(require_permission("admin:manage")),
):
    """Every file the loader found last time it ran, with its sha256, size and mtime, and any error loading it. Any .py file
    here executes with full backend privileges — this lets an administrator notice a file that was not loaded on purpose."""
    from app.plugins.loader import plugin_manager
    return {"files": plugin_manager.manifest}


@router.post("/plugins/reload")
async def reload_plugins(
    token: dict = Depends(require_permission("admin:manage")),
    db: AsyncSession = Depends(get_db),
):
    """Reload all plugins from the plugins directory. Any .py file there runs with full backend privileges, so this is
    audited like any other administrative action."""
    from app.plugins.loader import plugin_manager
    try:
        old_count = len(plugin_manager.plugins)
        plugin_manager.load_plugins()
        new_count = len(plugin_manager.plugins)
        await log_audit(db, action="plugins:reloaded", user_id=UUID(token["sub"]), resource_type="plugin", resource_id=None,
                        details={"trigger": "manual", "before": old_count, "after": new_count, "files": plugin_manager.manifest})
        await db.commit()
        return {
            "message": "Plugins reloaded successfully",
            "before": old_count,
            "after": new_count,
            "loaded": list(plugin_manager.plugins.keys()),
            "files": plugin_manager.manifest,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Plugin reload failed: {str(e)}")


@router.get("/plugins/{plugin_id}/logs")
async def get_plugin_logs(
    plugin_id: str,
    limit: int = 100,
    token: dict = Depends(require_permission("admin:manage")),
):
    """Get recent log lines for a specific plugin."""
    import logging
    log_handler = None
    # Look for a MemoryHandler or similar attached to the plugin logger
    plugin_logger = logging.getLogger(f"plugin.{plugin_id}")
    records = []
    for handler in plugin_logger.handlers:
        if hasattr(handler, "buffer"):
            records = [
                {
                    "level": r.levelname,
                    "message": r.getMessage(),
                    "time": r.created,
                }
                for r in list(handler.buffer)[-limit:]
            ]
            break

    return {
        "plugin_id": plugin_id,
        "logs": records,
        "note": "Install a MemoryHandler on the plugin logger to capture logs.",
    }


# ─── Builtin Plugin Marketplace ───────────────────────────────────────────────

class BuiltinPluginConfigRequest(BaseModel):
    enabled: bool = False
    config: dict = {}


@router.get("/plugins/builtin")
async def list_builtin_plugins(
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(require_permission("admin:manage")),
):
    """List all 12 builtin plugins with their status and config schema."""
    from app.services.plugin_config_service import get_all_plugin_statuses
    statuses = await get_all_plugin_statuses(db)
    return {"plugins": statuses, "count": len(statuses)}


@router.get("/plugins/builtin/{plugin_id}")
async def get_builtin_plugin(
    plugin_id: str,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(require_permission("admin:manage")),
):
    """Get a single builtin plugin's metadata, config schema, and current status."""
    from app.plugins.builtin import get_plugin_meta
    from app.services.plugin_config_service import get_plugin_config_row

    meta = get_plugin_meta(plugin_id)
    if not meta:
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_id}' not found")

    row = await get_plugin_config_row(db, plugin_id)
    return {
        **meta,
        "enabled": row.enabled if row else False,
        "configured": row is not None and (bool(row.config_encrypted) or bool(row.config_plain)),
        "trigger_count": row.trigger_count if row else 0,
        "last_triggered_at": row.last_triggered_at.isoformat() if row and row.last_triggered_at else None,
        "config_preview": (
            {k: v for k, v in (row.config_plain or {}).items()} if row else {}
        ),
    }


@router.post("/plugins/builtin/{plugin_id}/configure")
async def configure_builtin_plugin(
    plugin_id: str,
    body: BuiltinPluginConfigRequest,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(require_permission("admin:manage")),
):
    """Save (encrypted) configuration for a builtin plugin and set its enable state."""
    from app.plugins.builtin import get_plugin_meta
    from app.services.plugin_config_service import save_plugin_config

    if not get_plugin_meta(plugin_id):
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_id}' not found")

    row = await save_plugin_config(db, plugin_id, body.config, body.enabled)
    await log_audit(db, action="plugin_configure", user_id=UUID(token["sub"]),
                    resource_type="plugin", resource_id=plugin_id,
                    details={"plugin_id": plugin_id, "enabled": body.enabled})
    return {"message": "Plugin configuration saved", "plugin_id": plugin_id, "enabled": row.enabled}


@router.post("/plugins/builtin/{plugin_id}/test")
async def test_builtin_plugin(
    plugin_id: str,
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(require_permission("admin:manage")),
):
    """Test the connection for a configured builtin plugin."""
    from app.plugins.builtin import get_plugin_meta
    from app.services.plugin_config_service import test_plugin_connection

    if not get_plugin_meta(plugin_id):
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_id}' not found")

    result = await test_plugin_connection(db, plugin_id)
    return result


@router.post("/plugins/builtin/{plugin_id}/toggle")
async def toggle_builtin_plugin(
    plugin_id: str,
    body: dict = Body(...),
    db: AsyncSession = Depends(get_db),
    token: dict = Depends(require_permission("admin:manage")),
):
    """Enable or disable a builtin plugin without changing its config."""
    from app.plugins.builtin import get_plugin_meta
    from app.services.plugin_config_service import toggle_plugin

    if not get_plugin_meta(plugin_id):
        raise HTTPException(status_code=404, detail=f"Plugin '{plugin_id}' not found")

    enabled = bool(body.get("enabled", False))
    row = await toggle_plugin(db, plugin_id, enabled)
    await log_audit(db, action="plugin_toggle", user_id=UUID(token["sub"]),
                    resource_type="plugin", resource_id=plugin_id,
                    details={"plugin_id": plugin_id, "enabled": enabled})
    return {"message": f"Plugin {'enabled' if enabled else 'disabled'}", "plugin_id": plugin_id, "enabled": row.enabled}
