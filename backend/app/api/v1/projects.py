"""
SOCIS-AI-PT — Project Routes (Full Implementation)
"""

from typing import Optional, List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import noload
from sqlalchemy import select, func, delete as sa_delete

from app.core.database import get_db
from app.core.security import require_permission
from app.models.project import Project, ProjectStatus
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.models.ai_analysis import AIAnalysis
from app.models.report import Report
from app.models.exploit import Exploit
import logging
logger = logging.getLogger(__name__)

router = APIRouter()


class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    scope: Optional[str] = None

    @field_validator('name')
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError('Project name cannot be empty')
        if len(v.strip()) < 2:
            raise ValueError('Project name must be at least 2 characters')
        return v.strip()

    # The text a project owner writes is the REQUESTED scope (notes for the administrator). It is not enforced: the administrator
    # approves entries into the authorized allowlist (scope_targets), which is what scans are checked against.
    scope_targets: Optional[List[str]] = None     # administrators only (projects:scope)
    scope_enforced: Optional[bool] = None         # administrators only (projects:scope)

    @field_validator('scope')
    @classmethod
    def scope_notes_length(cls, v: Optional[str]) -> Optional[str]:
        if v and len(v) > 5000:
            raise ValueError('Scope notes are limited to 5000 characters')
        return v


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    scope: Optional[str] = None
    status: Optional[str] = None


class ProjectResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    scope: Optional[str]
    scope_targets: List[str] = []
    scope_enforced: bool = False
    status: str
    owner_id: UUID

    model_config = {"from_attributes": True}


class ProjectListResponse(BaseModel):
    projects: List[ProjectResponse]
    total: int
    page: int
    per_page: int


@router.get("/", response_model=ProjectListResponse)
async def list_projects(
    status: Optional[str] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    token: dict = Depends(require_permission("projects:read")),
    db: AsyncSession = Depends(get_db),
):
    """List all projects with optional status filter."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")
    
    query = select(Project).order_by(Project.created_at.desc())
    count_q = select(func.count()).select_from(Project)
    
    # Filter by owner unless admin
    if user_role != "admin":
        query = query.where(Project.owner_id == user_id)
        count_q = count_q.where(Project.owner_id == user_id)

    if status:
        query = query.where(Project.status == status)
        count_q = count_q.where(Project.status == status)

    total = (await db.execute(count_q)).scalar()

    # ProjectResponse exposes no scans: do not load them (each project used to drag in its entire scan history).
    query = query.options(noload(Project.scans)).offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    projects = result.scalars().all()

    return ProjectListResponse(projects=[ProjectResponse.model_validate(p) for p in projects], total=total or 0, page=page, per_page=per_page)


@router.post("/", response_model=ProjectResponse, status_code=201)
async def create_project(
    data: ProjectCreate,
    token: dict = Depends(require_permission("projects:write")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new project. It starts with scope enforcement ON: nothing can be scanned until an administrator authorizes targets."""
    from app.core.scope import ScopeError, normalize_entries
    from app.core.security import UserRole, check_permission
    can_scope = check_permission(UserRole(token.get("role", "viewer")), "projects:scope")
    targets: List[str] = []
    if data.scope_targets is not None or data.scope_enforced is not None:
        if not can_scope:
            raise HTTPException(status_code=403, detail="Only an administrator can set a project's authorized scope.")
        try:
            targets = normalize_entries(data.scope_targets or [])
        except ScopeError as e:
            raise HTTPException(status_code=422, detail=str(e))
    project = Project(
        owner_id=UUID(token["sub"]),
        name=data.name,
        description=data.description,
        scope=data.scope,
        scope_targets=targets,
        scope_enforced=True if data.scope_enforced is None else bool(data.scope_enforced),
    )
    db.add(project)
    await db.flush()
    await db.commit()
    await db.refresh(project)
    return project


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: UUID,
    token: dict = Depends(require_permission("projects:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific project by ID."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")
    
    query = select(Project).where(Project.id == project_id)
    if user_role != "admin":
        query = query.where(Project.owner_id == user_id)
        
    result = await db.execute(query)
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found or access denied")
    return project


@router.patch("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: UUID,
    data: ProjectUpdate,
    token: dict = Depends(require_permission("projects:write")),
    db: AsyncSession = Depends(get_db),
):
    """Update a project."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")
    
    query = select(Project).where(Project.id == project_id)
    if user_role != "admin":
        query = query.where(Project.owner_id == user_id)
        
    result = await db.execute(query)
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found or access denied")

    for field, value in data.model_dump(exclude_none=True).items():
        setattr(project, field, value)
    await db.commit()
    await db.refresh(project)
    return project


@router.delete("/{project_id}", status_code=204)
async def delete_project(
    project_id: UUID,
    token: dict = Depends(require_permission("projects:delete")),
    db: AsyncSession = Depends(get_db),
):
    """Delete a project and all its scans (cascaded)."""
    user_id = UUID(token["sub"])
    user_role = str(token.get("role", "viewer")).lower()
    
    query = select(Project).where(Project.id == project_id)
    if user_role != "admin":
        query = query.where(Project.owner_id == user_id)
        
    result = await db.execute(query)
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found or access denied")
    try:
        scan_ids = list((await db.execute(select(Scan.id).where(Scan.project_id == project_id))).scalars().all())
        if scan_ids:
            await db.execute(sa_delete(AIAnalysis).where(AIAnalysis.scan_id.in_(scan_ids)))
            await db.execute(sa_delete(Report).where(Report.scan_id.in_(scan_ids)))
            await db.execute(sa_delete(Exploit).where(Exploit.scan_id.in_(scan_ids)))
            await db.execute(sa_delete(Vulnerability).where(Vulnerability.scan_id.in_(scan_ids)))
            await db.execute(sa_delete(Scan).where(Scan.id.in_(scan_ids)))
        await db.execute(sa_delete(Project).where(Project.id == project_id))
        await db.commit()
    except Exception as e:
        await db.rollback()
        logger.warning("Failed to delete project", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to delete project")


# ─── Authorized scope ───────────────────────────────────────────────────────────

class ScopePut(BaseModel):
    targets: List[str]
    enforced: bool


class ScopeCheck(BaseModel):
    target: str


@router.get("/{project_id}/scope")
async def get_project_scope(
    project_id: UUID,
    token: dict = Depends(require_permission("projects:read")),
    db: AsyncSession = Depends(get_db),
):
    """The authorized allowlist, whether it is enforced, the owner's requested scope (with the valid entries not yet approved) and
    the recent blocked / overridden / changed events."""
    from app.core.scope import parse_scope_text
    from app.core.security import UserRole, check_permission
    from app.models.audit_log import AuditLog
    from app.models.user import User
    from app.services.scope_service import load_project_for_user
    project = await load_project_for_user(db, project_id, token)
    good, unreadable = parse_scope_text(project.scope)
    approved = set(project.scope_targets or [])
    rows = (await db.execute(
        select(AuditLog).where(AuditLog.resource_type == "project", AuditLog.resource_id == str(project.id), AuditLog.action.like("scope:%"))
        .order_by(AuditLog.created_at.desc()).limit(20)
    )).scalars().all()
    ids = {r.user_id for r in rows if r.user_id}
    names = {}
    if ids:
        names = {uid: name for uid, name in (await db.execute(select(User.id, User.username).where(User.id.in_(ids)))).all()}
    return {
        "targets": list(project.scope_targets or []),
        "enforced": bool(project.scope_enforced),
        "requested": project.scope or "",
        "suggested": [g for g in good if g not in approved],
        "unreadable": unreadable,
        "can_edit": check_permission(UserRole(token.get("role", "viewer")), "projects:scope"),
        "events": [{"action": r.action, "by": names.get(r.user_id, ""), "at": r.created_at.isoformat() if r.created_at else None,
                    "details": r.details or {}} for r in rows],
    }


@router.put("/{project_id}/scope")
async def set_project_scope(
    project_id: UUID,
    body: ScopePut,
    token: dict = Depends(require_permission("projects:scope")),
    db: AsyncSession = Depends(get_db),
):
    """Replace the authorized allowlist and the enforcement switch (administrators only). Every change is audited."""
    from app.core.audit import log_audit
    from app.core.scope import ScopeError, normalize_entries
    from app.services.scope_service import load_project_for_user
    project = await load_project_for_user(db, project_id, token)
    try:
        targets = normalize_entries(body.targets)
    except ScopeError as e:
        raise HTTPException(status_code=422, detail=str(e))
    before = list(project.scope_targets or [])
    was = bool(project.scope_enforced)
    project.scope_targets = targets
    project.scope_enforced = bool(body.enforced)
    await log_audit(
        db, action="scope:updated", user_id=UUID(token["sub"]), resource_type="project", resource_id=str(project.id),
        details={"added": [t for t in targets if t not in before][:50], "removed": [t for t in before if t not in targets][:50],
                 "count": len(targets), "enforced_before": was, "enforced_after": bool(body.enforced), "project_name": project.name},
    )
    await db.commit()
    return {"targets": targets, "enforced": bool(body.enforced)}


@router.post("/{project_id}/scope/check")
async def check_project_scope(
    project_id: UUID,
    body: ScopeCheck,
    token: dict = Depends(require_permission("projects:read")),
    db: AsyncSession = Depends(get_db),
):
    """Would this target be allowed? (Nothing is scanned.)"""
    from app.core.scope import build_entries, decide
    from app.services.scope_service import load_project_for_user
    project = await load_project_for_user(db, project_id, token)
    d = decide(body.target, build_entries(project.scope_targets or []))
    enforced = bool(project.scope_enforced)
    return {"allowed": (not enforced) or d.allowed, "in_list": d.allowed, "enforced": enforced, "reason": d.reason, "matched": d.matched}
