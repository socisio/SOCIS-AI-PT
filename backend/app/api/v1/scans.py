"""
SOCIS-AI-PT — Scan Routes (Full Implementation with ARQ queuing)
"""

import logging
import re
from typing import Optional, List
from uuid import UUID
from ipaddress import ip_network, ip_address
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, join, delete as sa_delete
from sqlalchemy.orm import selectinload, noload
import validators
from app.models.project import Project
from app.models.ai_analysis import AIAnalysis
from app.models.report import Report
from app.models.exploit import Exploit

from app.core.database import get_db
from app.core.security import require_permission
from app.core.audit import log_audit
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.vulnerability import Vulnerability
from app.models.llm_config import LLMConfig
from app.schemas.scan import ScanCreate, ScanResponse, ScanListResponse, ScanListItem, ScanAIAnalysisRunRequest

logger = logging.getLogger(__name__)
router = APIRouter()

BLOCKED_HOSTNAMES = {
nname.lower()
for nname in [
"localhost", "127.0.0.1", "::1", "0.0.0.0",
"metadata.google.internal",
"169.254.169.254",
"metadata.azure.com",
"metadata.internal",
]
}

# Block only link-local and cloud metadata ranges to prevent SSRF.
# RFC1918 private ranges (10/8, 172.16/12, 192.168/16) are intentionally
# allowed — this is a pentest tool designed to scan internal networks.
BLOCKED_SUBNETS = [
    ip_network("169.254.0.0/16"),   # link-local / cloud metadata (AWS, GCP, Azure)
    ip_network("fc00::/7"),          # IPv6 ULA
    ip_network("fe80::/10"),         # IPv6 link-local
]

def _validate_target(target: str) -> tuple[bool, str]:
    target = target.strip().rstrip("/")
    if not target:
        return False, "Target cannot be empty"
    if target.lower() in BLOCKED_HOSTNAMES:
        return False, "Scanning internal/localhost targets is not allowed"
    parsed = urlparse(target if "://" in target else f"http://{target}")
    hostname = parsed.hostname or parsed.netloc
    if not hostname:
        return False, "Invalid target format"
    hostname = hostname.lower()
    if hostname in BLOCKED_HOSTNAMES:
        return False, "Scanning internal/localhost targets is not allowed"
    try:
        ip = ip_address(hostname)
        for subnet in BLOCKED_SUBNETS:
            if ip in subnet:
                return False, "Scanning this IP range is not allowed"
        return True, ""
    except ValueError:
        pass
    if not validators.domain(hostname):
        if not validators.url(target):
            return False, "Invalid target format. Must be a valid IP, domain, or URL"
    return True, ""


@router.get("/", response_model=ScanListResponse)
async def list_scans(
    project_id: Optional[UUID] = None,
    status: Optional[ScanStatus] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """List all scans with optional filters."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")
    
    try:
        query = select(Scan).join(Project).order_by(Scan.created_at.desc())
        count_q = select(func.count()).select_from(Scan).join(Project)
        
        # Filter by owner unless admin
        if user_role != "admin":
            query = query.where(Project.owner_id == user_id)
            count_q = count_q.where(Project.owner_id == user_id)

        if project_id:
            query = query.where(Scan.project_id == project_id)
            count_q = count_q.where(Scan.project_id == project_id)
        if status:
            query = query.where(Scan.status == status)
            count_q = count_q.where(Scan.status == status)

        total = (await db.execute(count_q)).scalar()

        # Lean list: never load tool output / analyses / vulnerabilities / reports here (they are the detail page's job).
        result = await db.execute(
            query.options(
                noload(Scan.tool_results), noload(Scan.ai_analyses), noload(Scan.vulnerabilities),
                noload(Scan.reports), noload(Scan.user),
            ).offset((page - 1) * per_page).limit(per_page)
        )
        scans = result.scalars().all()
        counts = {}
        if scans:
            rows = (await db.execute(
                select(Vulnerability.scan_id, func.count())
                .where(Vulnerability.scan_id.in_([s.id for s in scans]))
                .group_by(Vulnerability.scan_id)
            )).all()
            counts = {sid: int(n) for sid, n in rows}
        items = [ScanListItem.model_validate(s).model_copy(update={"vulnerability_count": counts.get(s.id, 0)}) for s in scans]
        return ScanListResponse(scans=items, total=total or 0, page=page, per_page=per_page)
    except Exception as e:
        logger.error(f"Failed to list scans: {e}")
        raise HTTPException(status_code=500, detail="Failed to list scans")


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(
    scan_data: ScanCreate,
    token: dict = Depends(require_permission("scans:execute")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new scan and queue it for background execution via ARQ."""
    valid, error_msg = _validate_target(scan_data.target)
    if not valid:
        raise HTTPException(status_code=400, detail=error_msg)

    # Authorized scope: the caller must own the project (administrators: any), and the target must be inside its allowlist
    # unless an administrator overrides it with a written reason. (Before this, any analyst could start a scan in ANY project.)
    from app.services import scope_service
    project = await scope_service.load_project_for_user(db, scan_data.project_id, token)
    override = await scope_service.authorize_scan_target(db, project, scan_data.target, token, "scan", scan_data.scope_override_reason)

    try:
        tool_config = dict(scan_data.tool_config or {})
        tool_config.pop("scope_override", None)          # only the server may set this (it is signed): never trust the request body
        tool_config.setdefault("auto_ai_analysis", False)
        scan = Scan(
            project_id=scan_data.project_id,
            initiated_by=UUID(token["sub"]),
            target=scan_data.target,
            scan_type=ScanType(scan_data.scan_type) if scan_data.scan_type else ScanType.FULL,
            tool_config=tool_config,
            status=ScanStatus.PENDING,
        )
        db.add(scan)
        await db.flush()
        await db.refresh(scan)
        scope_service.attach_override(scan, override)

        await log_audit(
            db, action="scan:create",
            user_id=UUID(token["sub"]),
            resource_type="scan", resource_id=str(scan.id),
            details={"target": scan_data.target, "scan_type": scan_data.scan_type},
        )

        # Commit first so the worker can see the scan row, then enqueue
        await db.commit()
        await db.refresh(scan)

        try:
            from app.tasks.scan_worker import get_arq_pool
            pool = await get_arq_pool()
            await pool.enqueue_job("run_scan", str(scan.id))
            await pool.aclose()
            logger.info(f"Scan {scan.id} queued for execution")
        except Exception as e:
            # If Redis is unavailable, just leave as PENDING — can be manually re-queued
            logger.warning(f"Failed to queue scan {scan.id}: {e}")

        return ScanResponse.model_validate(scan)
    except Exception as e:
        logger.error(f"Failed to create scan: {e}")
        raise HTTPException(status_code=500, detail="Failed to create scan")


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get detailed scan results including vulnerabilities, tool results, and AI analyses."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")
    
    query = select(Scan).join(Project).where(Scan.id == scan_id)
    if user_role != "admin":
        query = query.where(Project.owner_id == user_id)
        
    result = await db.execute(
        query.options(
            selectinload(Scan.vulnerabilities).selectinload(Vulnerability.fixes),
            selectinload(Scan.tool_results),
            selectinload(Scan.ai_analyses),
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found or access denied")
    return ScanResponse.model_validate(scan)


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(
    scan_id: UUID,
    token: dict = Depends(require_permission("scans:delete")),
    db: AsyncSession = Depends(get_db),
):
    """Delete a scan and all associated data."""
    user_id = UUID(token["sub"])
    user_role = str(token.get("role", "viewer")).lower()
    
    query = select(Scan).join(Project).where(Scan.id == scan_id)
    if user_role != "admin":
        query = query.where(Project.owner_id == user_id)
        
    result = await db.execute(query)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found or access denied")
    try:
        # Defensive explicit cleanup in case DB-level cascades are missing/misaligned.
        await db.execute(sa_delete(AIAnalysis).where(AIAnalysis.scan_id == scan_id))
        await db.execute(sa_delete(Report).where(Report.scan_id == scan_id))
        await db.execute(sa_delete(Exploit).where(Exploit.scan_id == scan_id))
        await db.execute(sa_delete(Vulnerability).where(Vulnerability.scan_id == scan_id))
        await db.execute(sa_delete(Scan).where(Scan.id == scan_id))
        await db.commit()
    except Exception as e:
        await db.rollback()
        logger.error(f"Failed to delete scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to delete scan")


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: UUID,
    token: dict = Depends(require_permission("scans:execute")),
    db: AsyncSession = Depends(get_db),
):
    """Cancel a pending or running scan."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")
    
    # Join with Project to verify ownership
    query = select(Scan).join(Project).where(Scan.id == scan_id)
    if user_role != "admin":
        query = query.where(Project.owner_id == user_id)
    
    result = await db.execute(query)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found or access denied")
    if scan.status not in (ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.ANALYZING):
        raise HTTPException(status_code=400, detail=f"Cannot cancel scan in '{scan.status}' state")
    scan.status = ScanStatus.CANCELLED
    await db.commit()
    from app.services.webhook_service import emit_scan_event
    await emit_scan_event(db, scan, "scan.cancelled")

    # Signal the background worker via Redis cancel flag (TTL 1 hour)
    try:
        import redis.asyncio as aioredis
        from app.config import settings as _settings
        r = aioredis.from_url(_settings.REDIS_URL or "redis://localhost:6379")
        await r.set(f"scan:cancel:{scan_id}", "1", ex=3600)
        await r.aclose()
    except Exception as e:
        logger.warning(f"Could not set Redis cancel flag for scan {scan_id}: {e}")

    return {"message": "Scan cancelled", "scan_id": str(scan_id)}


@router.post("/{scan_id}/requeue")
async def requeue_scan(
    scan_id: UUID,
    token: dict = Depends(require_permission("scans:execute")),
    db: AsyncSession = Depends(get_db),
):
    """Re-queue a failed or cancelled scan."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")
    
    # Join with Project to verify ownership
    query = select(Scan).join(Project).where(Scan.id == scan_id)
    if user_role != "admin":
        query = query.where(Project.owner_id == user_id)
    
    result = await db.execute(query)
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found or access denied")
    if scan.status not in (ScanStatus.FAILED, ScanStatus.CANCELLED):
        raise HTTPException(status_code=400, detail="Only failed or cancelled scans can be re-queued")

    scan.status = ScanStatus.PENDING
    await db.commit()
    try:
        from app.tasks.scan_worker import get_arq_pool
        pool = await get_arq_pool()
        await pool.enqueue_job("run_scan", str(scan.id))
        await pool.aclose()
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Redis unavailable: {str(e)}")

    return {"message": "Scan re-queued", "scan_id": str(scan_id)}


@router.post("/{scan_id}/ai-analysis")
async def run_ai_analysis(
    scan_id: UUID,
    body: ScanAIAnalysisRunRequest,
    token: dict = Depends(require_permission("scans:execute")),
    db: AsyncSession = Depends(get_db),
):
    """Run (or re-run) AI analysis for a completed scan using selected provider/model."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")

    query = select(Scan).join(Project).where(Scan.id == scan_id)
    if user_role != "admin":
        query = query.where(Project.owner_id == user_id)

    result = await db.execute(query.options(selectinload(Scan.tool_results)))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found or access denied")

    if scan.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(status_code=400, detail="Scan is still running. Wait until tool execution completes.")

    if not scan.tool_results:
        raise HTTPException(status_code=400, detail="No tool results available for AI analysis.")

    provider_key = (body.provider or "ollama_remote").strip()
    requested_model = (body.model or "").strip()

    active_cfgs = (
        await db.execute(
            select(LLMConfig)
            .where(LLMConfig.is_active == True, LLMConfig.provider == provider_key)
            .order_by(LLMConfig.is_default.desc(), LLMConfig.created_at.asc())
        )
    ).scalars().all()

    effective_model = requested_model
    if active_cfgs:
        allowed = {c.model_name for c in active_cfgs}
        if not effective_model:
            effective_model = active_cfgs[0].model_name
        if effective_model not in allowed:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Model '{effective_model}' is not allowed for provider '{provider_key}'. "
                    "Configure it in Admin → LLM Configs first."
                ),
            )

    try:
        from app.tasks.scan_worker import get_arq_pool
        pool = await get_arq_pool()
        await pool.enqueue_job(
            "run_scan_ai_analysis",
            str(scan.id),
            provider_key,
            effective_model,
            body.remote_url,
        )
        await pool.aclose()
    except Exception as e:
        logger.error(f"Failed to queue AI analysis for scan {scan_id}: {e}")
        raise HTTPException(status_code=503, detail=f"Could not queue AI analysis: {str(e)}")

    return {
        "message": "AI analysis queued",
        "scan_id": str(scan.id),
        "provider": provider_key,
        "model": effective_model,
    }


@router.get("/compare")
async def compare_scans(
    scan_a: UUID = Query(..., description="Baseline scan ID"),
    scan_b: UUID = Query(..., description="Comparison scan ID"),
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """
    Diff two completed scans. Returns new, resolved, and persisting vulnerabilities.
    Verifies user has access to both scans.
    """
    from app.models.vulnerability import Vulnerability
    
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")
    
    # Verify ownership of both scans
    for scan_id in (scan_a, scan_b):
        query = select(Scan).join(Project).where(Scan.id == scan_id)
        if user_role != "admin":
            query = query.where(Project.owner_id == user_id)
        result = await db.execute(query)
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found or access denied")

    # Fetch vulnerabilities for each scan (keyed by normalised name+port combo)
    async def _get_vuln_map(scan_id: UUID) -> dict:
        result = await db.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan_id)
        )
        vulns = result.scalars().all()
        return {
            f"{v.vuln_name}:{v.port}": {
                "id": str(v.id),
                "vuln_name": v.vuln_name,
                "severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
                "port": v.port,
                "service": v.service,
                "cve_id": v.cve_id,
            }
            for v in vulns
        }

    map_a = await _get_vuln_map(scan_a)
    map_b = await _get_vuln_map(scan_b)

    keys_a = set(map_a)
    keys_b = set(map_b)

    return {
        "scan_a": str(scan_a),
        "scan_b": str(scan_b),
        "new_vulnerabilities": [map_b[k] for k in (keys_b - keys_a)],
        "resolved_vulnerabilities": [map_a[k] for k in (keys_a - keys_b)],
        "persisting_vulnerabilities": [map_b[k] for k in (keys_a & keys_b)],
        "summary": {
            "new": len(keys_b - keys_a),
            "resolved": len(keys_a - keys_b),
            "persisting": len(keys_a & keys_b),
        },
    }
