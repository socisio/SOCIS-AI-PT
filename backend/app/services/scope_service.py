"""Authorized-scope decisions for scans (API paths and the worker) and the signed administrator override."""
from __future__ import annotations

import logging
import uuid
from typing import Optional, Tuple

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.scope import Decision, build_entries, decide, sign_override, verify_override
from app.core.scope_guard import ScanScope, audit_standalone
from app.models.project import Project

logger = logging.getLogger(__name__)
MIN_OVERRIDE_REASON = 10


def _secret() -> str:
    from app.config import settings
    return settings.JWT_SECRET_KEY


def evaluate(project: Project, target: str) -> Decision:
    """Is `target` allowed for this project? (A project that does not enforce a scope allows everything.)"""
    if not project.scope_enforced:
        return Decision(True, "this project does not enforce a scope", None, target)
    return decide(target, build_entries(project.scope_targets or []))


async def load_project_for_user(db: AsyncSession, project_id, token: dict) -> Project:
    """The project, or 404 when it does not exist or the caller does not own it (administrators see all)."""
    try:
        pid = project_id if isinstance(project_id, uuid.UUID) else uuid.UUID(str(project_id))
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid project id")
    q = select(Project).where(Project.id == pid)
    if token.get("role") != "admin":
        q = q.where(Project.owner_id == uuid.UUID(token["sub"]))
    project = (await db.execute(q)).scalar_one_or_none()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found or access denied")
    return project


async def authorize_scan_target(db: AsyncSession, project: Project, target: str, token: dict, source: str,
                                override_reason: Optional[str] = None) -> Optional[dict]:
    """Raise 403 when the target is outside the project's authorized scope. Returns None when allowed, or the override info
    ({by, reason}) when an administrator overrode it (the caller signs it onto the scan once the scan id exists)."""
    d = evaluate(project, target)
    if d.allowed:
        return None
    is_admin = token.get("role") == "admin"
    reason = (override_reason or "").strip()
    if is_admin and reason:
        if len(reason) < MIN_OVERRIDE_REASON:
            raise HTTPException(status_code=400, detail=f"An override needs a written reason of at least {MIN_OVERRIDE_REASON} characters.")
        await audit_standalone("scope:override", token["sub"], "project", str(project.id),
                               {"target": target, "reason": reason[:500], "source": source, "project_name": project.name})
        return {"by": token["sub"], "reason": reason[:500]}
    await audit_standalone("scope:blocked", token["sub"], "project", str(project.id),
                           {"target": target, "source": source, "why": d.reason, "project_name": project.name,
                            "override_attempted": bool(reason)})
    hint = ("Add it to the project's authorized scope, or run it as an administrator override with a written reason."
            if is_admin else "Ask an administrator to add it to the project's authorized scope.")
    raise HTTPException(status_code=403, detail=f"{d.reason} for project '{project.name}'. {hint}",
                        headers={"X-SOCIS-Error": "target_out_of_scope", "X-SOCIS-Can-Override": "1" if is_admin else "0"})


def attach_override(scan, override: Optional[dict]) -> None:
    """Sign an override onto the scan (call after the scan has an id, before commit). Always removes any user-supplied marker."""
    cfg = dict(scan.tool_config or {})
    cfg.pop("scope_override", None)
    if override:
        cfg["scope_override"] = sign_override(_secret(), str(scan.id), scan.target, override["by"], override["reason"])
    scan.tool_config = cfg


async def worker_gate(db: AsyncSession, scan) -> Tuple[Optional[str], Optional[ScanScope]]:
    """The authoritative check, run by the worker for EVERY scan however it was created (API, workflow, schedule, cron).
    Returns (message, None) when the scan must not run, else (None, the scope to enforce on its tool calls)."""
    try:
        project = (await db.execute(select(Project).where(Project.id == scan.project_id))).scalar_one_or_none()
    except Exception as exc:  # noqa: BLE001
        logger.error("Scope check could not load the project for scan %s: %s", scan.id, exc)
        return "The authorized-scope check could not run (database error), so the scan was not started.", None
    if project is None:
        return "The scan's project no longer exists.", None
    base = ScanScope(project_id=str(project.id), project_name=project.name, user_id=str(scan.initiated_by), scan_id=str(scan.id),
                     entries=build_entries(project.scope_targets or []), enforced=bool(project.scope_enforced))
    if not base.enforced:
        return None, base
    d = decide(scan.target, base.entries)
    if d.allowed:
        return None, base
    if verify_override(_secret(), str(scan.id), scan.target, (scan.tool_config or {}).get("scope_override")):
        base.override = True
        return None, base
    await audit_standalone("scope:blocked", str(scan.initiated_by), "project", str(project.id),
                           {"target": scan.target, "source": "worker", "why": d.reason, "scan_id": str(scan.id), "project_name": project.name})
    return f"Not started: {d.reason} for project '{project.name}'. An administrator can add it to the project's authorized scope.", None
