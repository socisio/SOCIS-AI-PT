"""
SOCIS-AI-PT — Scan Schedule Routes
CRUD + immediate-trigger for recurring scan schedules.
"""

import logging
import uuid
from datetime import timezone
from typing import Optional
from uuid import UUID

from croniter import croniter
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import require_permission
from app.models.scan_schedule import ScanSchedule

logger = logging.getLogger(__name__)
router = APIRouter()


# ─── Schemas ──────────────────────────────────────────────────

class ScanScheduleCreate(BaseModel):
    name: str
    project_id: UUID
    target: str
    cron_expression: str
    tool_config: dict = {}
    is_active: bool = True

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, v: str) -> str:
        if not croniter.is_valid(v):
            raise ValueError(f"Invalid cron expression: {v!r}")
        return v


class ScanScheduleUpdate(BaseModel):
    name: Optional[str] = None
    cron_expression: Optional[str] = None
    tool_config: Optional[dict] = None
    is_active: Optional[bool] = None

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not croniter.is_valid(v):
            raise ValueError(f"Invalid cron expression: {v!r}")
        return v


class ScanScheduleResponse(BaseModel):
    id: UUID
    project_id: UUID
    name: str
    target: str
    cron_expression: str
    tool_config: dict
    is_active: bool
    next_run_at: Optional[datetime]
    last_run_at: Optional[datetime]
    last_scan_id: Optional[UUID]
    created_at: datetime

    model_config = {"from_attributes": True}


def _compute_next_run(cron_expr: str) -> datetime:
    """Return the next UTC datetime for the given cron expression."""
    it = croniter(cron_expr, datetime.now(timezone.utc))
    return it.get_next(datetime)


# ─── Routes ───────────────────────────────────────────────────

@router.get("/", response_model=list[ScanScheduleResponse])
async def list_schedules(
    project_id: Optional[UUID] = Query(None),
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(ScanSchedule).order_by(ScanSchedule.created_at.desc())
    if project_id:
        stmt = stmt.where(ScanSchedule.project_id == project_id)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.post("/", response_model=ScanScheduleResponse, status_code=201)
async def create_schedule(
    data: ScanScheduleCreate,
    token: dict = Depends(require_permission("scans:execute")),
    db: AsyncSession = Depends(get_db),
):
    # Authorized scope: the caller must own the project and the target must be in its allowlist (a schedule cannot carry an override;
    # the worker checks again every time it runs).
    from app.services import scope_service
    _project = await scope_service.load_project_for_user(db, data.project_id, token)
    await scope_service.authorize_scan_target(db, _project, data.target, token, "schedule", None)
    _cfg = dict(data.tool_config or {})
    _cfg.pop("scope_override", None)
    schedule = ScanSchedule(
        project_id=data.project_id,
        created_by=uuid.UUID(token["sub"]),
        name=data.name,
        target=data.target,
        cron_expression=data.cron_expression,
        tool_config=_cfg,
        is_active=data.is_active,
        next_run_at=_compute_next_run(data.cron_expression) if data.is_active else None,
    )
    db.add(schedule)
    await db.commit()
    await db.refresh(schedule)
    return schedule


@router.get("/{schedule_id}", response_model=ScanScheduleResponse)
async def get_schedule(
    schedule_id: UUID,
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return schedule


@router.patch("/{schedule_id}", response_model=ScanScheduleResponse)
async def update_schedule(
    schedule_id: UUID,
    data: ScanScheduleUpdate,
    token: dict = Depends(require_permission("scans:execute")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    if data.name is not None:
        schedule.name = data.name
    if data.cron_expression is not None:
        schedule.cron_expression = data.cron_expression
        schedule.next_run_at = _compute_next_run(data.cron_expression) if schedule.is_active else None
    if data.tool_config is not None:
        _cfg = dict(data.tool_config)
        _cfg.pop("scope_override", None)
        schedule.tool_config = _cfg
    if data.is_active is not None:
        schedule.is_active = data.is_active
        if data.is_active and not schedule.next_run_at:
            schedule.next_run_at = _compute_next_run(schedule.cron_expression)
        elif not data.is_active:
            schedule.next_run_at = None

    await db.commit()
    await db.refresh(schedule)
    return schedule


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: UUID,
    token: dict = Depends(require_permission("scans:execute")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    await db.delete(schedule)
    await db.commit()


@router.post("/{schedule_id}/trigger", status_code=202)
async def trigger_schedule(
    schedule_id: UUID,
    token: dict = Depends(require_permission("scans:execute")),
    db: AsyncSession = Depends(get_db),
):
    """Immediately enqueue a scan for this schedule without waiting for the cron tick."""
    from app.models.scan import Scan, ScanStatus, ScanType
    from app.tasks.scan_worker import get_arq_pool

    result = await db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id))
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")

    from app.services import scope_service
    _project = await scope_service.load_project_for_user(db, schedule.project_id, token)
    await scope_service.authorize_scan_target(db, _project, schedule.target, token, "schedule", None)
    _cfg = dict(schedule.tool_config or {})
    _cfg.pop("scope_override", None)
    scan = Scan(
        project_id=schedule.project_id,
        initiated_by=uuid.UUID(token["sub"]),
        target=schedule.target,
        tool_config=_cfg,
        scan_type=ScanType.FULL,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    try:
        pool = await get_arq_pool()
        await pool.enqueue_job("run_scan", str(scan.id))
        await pool.aclose()
    except Exception as e:
        logger.warning("Redis unavailable", exc_info=True)
        raise HTTPException(status_code=503, detail="Redis unavailable")

    schedule.last_scan_id = scan.id
    await db.commit()
    return {"scan_id": str(scan.id), "message": "Scan enqueued"}
