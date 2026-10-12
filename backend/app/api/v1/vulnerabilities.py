"""
SOCIS-AI-PT — Vulnerability Routes (Full Implementation)
"""

import csv
import hashlib
import io
import logging
import re
from datetime import timezone, datetime, timedelta
from typing import Optional, List
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import noload
from sqlalchemy import select, func, join, and_, or_, cast
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

from app.core.database import get_db
from app.core.security import require_permission
from app.models.vulnerability import Vulnerability, Severity, VulnStatus
from app.models.vuln_comment import VulnComment
from app.models.scan import Scan
from app.models.ai_analysis import AIAnalysis
from app.models.project import Project
from app.models.user import User
from app.schemas.vulnerability import (
    VulnerabilityResponse, VulnerabilityListResponse,
    VulnManageRequest, VulnCommentResponse, VulnMetricsResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter()


def _vuln_to_response(vuln: Vulnerability) -> dict:
    """Serialize a Vulnerability ORM object to a dict for VulnerabilityResponse."""
    d = {}
    for col in [
        "id", "scan_id", "vuln_name", "severity", "port", "service", "description",
        "cve_id", "cvss_score", "epss_score", "epss_percentile", "cve_description",
        "cve_references", "owasp_category", "mitre_technique", "status", "source",
        "assigned_to", "priority", "due_date", "notes", "tags", "resolved_at",
        "created_at", "updated_at",
    ]:
        d[col] = getattr(vuln, col, None)
    # Hydrate assignee name/email from the lazy-loaded relationship
    if vuln.assignee:
        d["assigned_user_name"] = getattr(vuln.assignee, "full_name", None) or getattr(vuln.assignee, "username", None)
        d["assigned_user_email"] = getattr(vuln.assignee, "email", None)
    return d


# ─── Helper: build access-scoped base query ───────────────────

def _base_query(user_id: UUID, user_role: str):
    q = select(Vulnerability).join(Scan).join(Project).order_by(Vulnerability.created_at.desc())
    c = select(func.count()).select_from(Vulnerability).join(Scan).join(Project)
    if user_role != "admin":
        q = q.where(Project.owner_id == user_id)
        c = c.where(Project.owner_id == user_id)
    return q, c


@router.get("/", response_model=VulnerabilityListResponse)
async def list_vulnerabilities(
    scan_id: Optional[UUID] = None,
    severity: Optional[str] = None,
    cve_id: Optional[str] = None,
    search: Optional[str] = Query(None, description="Free-text search across name, CVE id, and OWASP category"),
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to: Optional[UUID] = None,
    tags: Optional[str] = Query(None, description="Comma-separated tag values"),
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    overdue: Optional[bool] = None,
    owasp: Optional[str] = None,
    mitre: Optional[str] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    token: dict = Depends(require_permission("vulns:read")),
    db: AsyncSession = Depends(get_db),
):
    """List vulnerabilities with advanced filters."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")

    query, count_q = _base_query(user_id, user_role)

    if scan_id:
        query = query.where(Vulnerability.scan_id == scan_id)
        count_q = count_q.where(Vulnerability.scan_id == scan_id)
    if severity:
        query = query.where(Vulnerability.severity == severity)
        count_q = count_q.where(Vulnerability.severity == severity)
    if cve_id:
        query = query.where(Vulnerability.cve_id.ilike(f"%{cve_id}%"))
        count_q = count_q.where(Vulnerability.cve_id.ilike(f"%{cve_id}%"))
    if search:
        # Free-text search the user types in the search box — matches name, CVE id, or OWASP category. Parameterized
        # via SQLAlchemy ilike (no string interpolation into SQL); the % wildcards are bound as a literal value.
        like = f"%{search.strip()}%"
        search_filter = or_(
            Vulnerability.vuln_name.ilike(like),
            Vulnerability.cve_id.ilike(like),
            Vulnerability.owasp_category.ilike(like),
        )
        query = query.where(search_filter)
        count_q = count_q.where(search_filter)
    if status:
        query = query.where(Vulnerability.status == status)
        count_q = count_q.where(Vulnerability.status == status)
    if priority:
        query = query.where(Vulnerability.priority == priority)
        count_q = count_q.where(Vulnerability.priority == priority)
    if assigned_to:
        query = query.where(Vulnerability.assigned_to == assigned_to)
        count_q = count_q.where(Vulnerability.assigned_to == assigned_to)
    if date_from:
        query = query.where(Vulnerability.created_at >= date_from)
        count_q = count_q.where(Vulnerability.created_at >= date_from)
    if date_to:
        query = query.where(Vulnerability.created_at <= date_to)
        count_q = count_q.where(Vulnerability.created_at <= date_to)
    if overdue is True:
        now = datetime.now(timezone.utc)
        query = query.where(
            and_(Vulnerability.due_date.isnot(None), Vulnerability.due_date < now,
                 Vulnerability.status.notin_(["resolved", "false_positive"]))
        )
        count_q = count_q.where(
            and_(Vulnerability.due_date.isnot(None), Vulnerability.due_date < now,
                 Vulnerability.status.notin_(["resolved", "false_positive"]))
        )
    if tags:
        for tag in [t.strip() for t in tags.split(",") if t.strip()]:
            query = query.where(Vulnerability.tags.contains([tag]))
            count_q = count_q.where(Vulnerability.tags.contains([tag]))
    if owasp:
        query = query.where(Vulnerability.owasp_category.ilike(f"%{owasp}%"))
        count_q = count_q.where(Vulnerability.owasp_category.ilike(f"%{owasp}%"))
    if mitre:
        query = query.where(Vulnerability.mitre_technique.ilike(f"%{mitre}%"))
        count_q = count_q.where(Vulnerability.mitre_technique.ilike(f"%{mitre}%"))

    total = (await db.execute(count_q)).scalar()
    # The list response exposes no fixes / exploits / comments: do not load them for every row.
    result = await db.execute(
        query.options(noload(Vulnerability.fixes), noload(Vulnerability.exploits), noload(Vulnerability.comments))
        .offset((page - 1) * per_page).limit(per_page)
    )
    vulns = result.scalars().all()

    return VulnerabilityListResponse(vulnerabilities=vulns, total=total)


# ─── CSV Export ───────────────────────────────────────────────────────────────

@router.get("/export", response_class=StreamingResponse)
async def export_vulnerabilities_csv(
    scan_id: Optional[UUID] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to: Optional[UUID] = None,
    overdue: Optional[bool] = None,
    token: dict = Depends(require_permission("vulns:read")),
    db: AsyncSession = Depends(get_db),
):
    """Export vulnerability list as a streaming CSV download."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")

    query, _ = _base_query(user_id, user_role)
    if scan_id:
        query = query.where(Vulnerability.scan_id == scan_id)
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if status:
        query = query.where(Vulnerability.status == status)
    if priority:
        query = query.where(Vulnerability.priority == priority)
    if assigned_to:
        query = query.where(Vulnerability.assigned_to == assigned_to)
    if overdue is True:
        now = datetime.now(timezone.utc)
        query = query.where(
            and_(Vulnerability.due_date.isnot(None), Vulnerability.due_date < now,
                 Vulnerability.status.notin_(["resolved", "false_positive"]))
        )

    result = await db.execute(query.limit(5000))
    vulns = result.scalars().all()

    def _csv_safe(value):
        """Neutralize CSV formula injection (CWE-1236). Vuln names, tags, services etc. originate from scanner
        output and user input; a cell beginning with = + - @ (or tab/CR) is executed as a formula when the file is
        opened in Excel / Google Sheets. Prefix any such cell with a single quote so it's treated as text."""
        if value is None:
            return ""
        s = str(value)
        if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
            return "'" + s
        return s

    def generate():
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "id", "vuln_name", "severity", "status", "priority",
            "assigned_to", "due_date", "cve_id", "cvss_score", "epss_score",
            "port", "service", "owasp_category", "mitre_technique",
            "tags", "source", "created_at", "resolved_at",
        ])
        buf.seek(0)
        yield buf.read()
        buf.seek(0); buf.truncate(0)
        for v in vulns:
            writer.writerow([_csv_safe(x) for x in [
                str(v.id), v.vuln_name, v.severity, v.status or "open",
                v.priority or "", str(v.assigned_to) if v.assigned_to else "",
                v.due_date.isoformat() if v.due_date else "",
                v.cve_id or "", v.cvss_score or "", v.epss_score or "",
                v.port or "", v.service or "",
                v.owasp_category or "", v.mitre_technique or "",
                ",".join(v.tags or []), v.source or "",
                v.created_at.isoformat() if v.created_at else "",
                v.resolved_at.isoformat() if v.resolved_at else "",
            ]])
            buf.seek(0)
            yield buf.read()
            buf.seek(0); buf.truncate(0)

    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities.csv"},
    )


# ─── Metrics ──────────────────────────────────────────────────────────────────

@router.get("/metrics", response_model=VulnMetricsResponse)
async def get_vuln_metrics(
    token: dict = Depends(require_permission("vulns:read")),
    db: AsyncSession = Depends(get_db),
):
    """Return vulnerability management metrics: MTTR, SLA compliance, trend, counts."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")

    query = select(Vulnerability).join(Scan).join(Project)
    if user_role != "admin":
        query = query.where(Project.owner_id == user_id)
    result = await db.execute(query)
    vulns = result.scalars().all()

    now = datetime.now(timezone.utc)
    thirty_days_ago = now - timedelta(days=30)

    by_severity: dict = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
    by_status: dict = {s: 0 for s in ["open", "in_progress", "resolved", "accepted_risk", "false_positive"]}
    by_priority: dict = {p: 0 for p in ["p1", "p2", "p3", "p4", "none"]}
    overdue_count = 0
    mttr_acc: dict = {s: [] for s in ["critical", "high", "medium", "low", "info"]}
    sla_days = {"critical": 7, "high": 14, "medium": 30, "low": 90}
    sla_total = 0
    sla_compliant = 0
    trend_buckets: dict = {}

    for v in vulns:
        sev = (v.severity or "info").lower()
        st = (v.status or "open").lower()
        prio = (v.priority or "none").lower()
        if prio not in by_priority:
            prio = "none"

        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_status[st] = by_status.get(st, 0) + 1
        by_priority[prio] = by_priority.get(prio, 0) + 1

        if v.due_date and st not in ("resolved", "false_positive"):
            due = v.due_date.replace(tzinfo=timezone.utc) if v.due_date.tzinfo is None else v.due_date
            if due < now:
                overdue_count += 1

        if st == "resolved" and v.resolved_at and v.created_at:
            created = v.created_at.replace(tzinfo=timezone.utc) if v.created_at.tzinfo is None else v.created_at
            resolved = v.resolved_at.replace(tzinfo=timezone.utc) if v.resolved_at.tzinfo is None else v.resolved_at
            days = (resolved - created).days
            if sev in mttr_acc:
                mttr_acc[sev].append(max(0, days))

        if v.due_date and sev in sla_days:
            sla_total += 1
            due = v.due_date.replace(tzinfo=timezone.utc) if v.due_date.tzinfo is None else v.due_date
            created = v.created_at.replace(tzinfo=timezone.utc) if v.created_at and v.created_at.tzinfo is None else v.created_at
            if st == "resolved" and v.resolved_at:
                resolved = v.resolved_at.replace(tzinfo=timezone.utc) if v.resolved_at.tzinfo is None else v.resolved_at
                if resolved <= due:
                    sla_compliant += 1
            elif st not in ("resolved", "false_positive") and due >= now:
                sla_compliant += 1

        if v.created_at:
            created = v.created_at.replace(tzinfo=timezone.utc) if v.created_at.tzinfo is None else v.created_at
            if created >= thirty_days_ago:
                day_key = created.strftime("%Y-%m-%d")
                trend_buckets[day_key] = trend_buckets.get(day_key, 0) + 1

    mttr_by_severity = {
        sev: round(sum(days) / len(days), 1) if days else None
        for sev, days in mttr_acc.items()
    }
    open_trend_30d = [{"date": k, "count": v} for k, v in sorted(trend_buckets.items())]
    sla_compliance_pct = round((sla_compliant / sla_total * 100) if sla_total else 100.0, 1)

    return VulnMetricsResponse(
        total=len(vulns),
        by_severity=by_severity,
        by_status=by_status,
        by_priority=by_priority,
        overdue_count=overdue_count,
        sla_compliance_pct=sla_compliance_pct,
        mttr_by_severity=mttr_by_severity,
        open_trend_30d=open_trend_30d,
    )



@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_vulnerability(
    vuln_id: UUID,
    token: dict = Depends(require_permission("vulns:read")),
    db: AsyncSession = Depends(get_db),
):
    """Get detailed vulnerability info including fixes and exploits."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")
    
    query = select(Vulnerability).join(Scan).join(Project).where(Vulnerability.id == vuln_id)
    if user_role != "admin":
        query = query.where(Project.owner_id == user_id)
        
    result = await db.execute(query)
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found or access denied")
    return VulnerabilityResponse(**_vuln_to_response(vuln))


@router.post("/{vuln_id}/lookup-cve")
async def lookup_cve_for_vuln(
    vuln_id: UUID,
    token: dict = Depends(require_permission("vulns:read")),
    db: AsyncSession = Depends(get_db),
):
    """Fetch CVE details from NVD for a vulnerability."""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    if not vuln.cve_id:
        raise HTTPException(status_code=400, detail="This vulnerability has no CVE ID assigned")

    from app.services.search_service import search_service
    cve_data = await search_service.lookup_cve(vuln.cve_id)

    # Update CVSS score if we got it
    if cve_data.get("cvss_score"):
        vuln.cvss_score = cve_data["cvss_score"]

    # Persist CVE description and references
    if cve_data.get("description"):
        vuln.cve_description = cve_data["description"]
    if cve_data.get("references"):
        vuln.cve_references = cve_data["references"]

    await db.commit()
    return {"vulnerability_id": str(vuln_id), "cve": cve_data}


# ─── Lifecycle status update ─────────────────────────────────

class StatusUpdate(BaseModel):
    status: VulnStatus


@router.patch("/{vuln_id}/status")
async def update_vuln_status(
    vuln_id: UUID,
    data: StatusUpdate,
    token: dict = Depends(require_permission("vulns:write")),
    db: AsyncSession = Depends(get_db),
):
    """Update the lifecycle status of a vulnerability."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")
    
    query = select(Vulnerability).join(Scan).join(Project).where(Vulnerability.id == vuln_id)
    if user_role != "admin":
        query = query.where(Project.owner_id == user_id)
        
    result = await db.execute(query)
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found or access denied")
    vuln.status = data.status
    vuln.updated_at = datetime.now(timezone.utc)
    # Auto-set resolved_at when transitioning to resolved for MTTR tracking
    if data.status == VulnStatus.RESOLVED and not vuln.resolved_at:
        vuln.resolved_at = datetime.now(timezone.utc)
    elif data.status != VulnStatus.RESOLVED:
        vuln.resolved_at = None
    await db.commit()
    return {"id": str(vuln_id), "status": vuln.status}


# ─── Vulnerability Management: manage endpoint ───────────────────────────────

@router.patch("/{vuln_id}/manage", response_model=VulnerabilityResponse)
async def manage_vulnerability(
    vuln_id: UUID,
    data: VulnManageRequest,
    token: dict = Depends(require_permission("vulns:write")),
    db: AsyncSession = Depends(get_db),
):
    """Update management fields: status, priority, assignee, due_date, notes, tags."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")

    query = select(Vulnerability).join(Scan).join(Project).where(Vulnerability.id == vuln_id)
    if user_role != "admin":
        query = query.where(Project.owner_id == user_id)
    result = await db.execute(query)
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found or access denied")

    if data.status is not None:
        vuln.status = data.status
        if data.status == "resolved" and not vuln.resolved_at:
            vuln.resolved_at = datetime.now(timezone.utc)
        elif data.status != "resolved":
            vuln.resolved_at = None

    if data.priority is not None:
        vuln.priority = data.priority
    if data.assigned_to is not None:
        assignee = await db.get(User, data.assigned_to)
        if not assignee:
            raise HTTPException(status_code=400, detail="Assigned user not found")
        vuln.assigned_to = data.assigned_to
    if data.due_date is not None:
        vuln.due_date = data.due_date
    if data.notes is not None:
        vuln.notes = data.notes
    if data.tags is not None:
        vuln.tags = data.tags

    vuln.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(vuln)
    return VulnerabilityResponse(**_vuln_to_response(vuln))


# ─── Vulnerability Management: bulk update ───────────────────────────────────

class VulnBulkUpdateRequest(BaseModel):
    ids: List[UUID]
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[UUID] = None


@router.post("/bulk-update")
async def bulk_update_vulnerabilities(
    data: VulnBulkUpdateRequest,
    token: dict = Depends(require_permission("vulns:write")),
    db: AsyncSession = Depends(get_db),
):
    """Apply the same status/priority/assignee change to many vulnerabilities in one transaction.

    Replaces the frontend's previous N-parallel-PATCH workaround. CRITICAL: every id is filtered through the same
    per-row ownership check the single-row endpoints use, so a non-admin cannot mutate a vulnerability in a project
    they don't own by passing its id here — only rows they're actually allowed to see are updated. Ids outside their
    scope are silently skipped (not an error), and the response reports how many were actually updated.
    """
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")

    if not data.ids:
        raise HTTPException(status_code=400, detail="No vulnerability ids provided")
    if len(data.ids) > 1000:
        raise HTTPException(status_code=400, detail="Too many ids in one request (max 1000)")
    if data.status is None and data.priority is None and data.assigned_to is None:
        raise HTTPException(status_code=400, detail="Nothing to update: provide status, priority, or assigned_to")

    # Validate the assignee once, up front, rather than per row.
    if data.assigned_to is not None:
        assignee = await db.get(User, data.assigned_to)
        if not assignee:
            raise HTTPException(status_code=400, detail="Assigned user not found")

    # Fetch only the rows this user is allowed to touch — same ownership filter as _base_query / manage.
    query = select(Vulnerability).join(Scan).join(Project).where(Vulnerability.id.in_(data.ids))
    if user_role != "admin":
        query = query.where(Project.owner_id == user_id)
    rows = (await db.execute(query)).scalars().all()

    now = datetime.now(timezone.utc)
    for vuln in rows:
        if data.status is not None:
            vuln.status = data.status
            if data.status == "resolved" and not vuln.resolved_at:
                vuln.resolved_at = now
            elif data.status != "resolved":
                vuln.resolved_at = None
        if data.priority is not None:
            vuln.priority = data.priority
        if data.assigned_to is not None:
            vuln.assigned_to = data.assigned_to
        vuln.updated_at = now

    await db.commit()
    return {"updated": len(rows), "requested": len(data.ids)}


# ─── Vulnerability Management: unassign ──────────────────────────────────────

@router.delete("/{vuln_id}/assign", status_code=200)
async def unassign_vulnerability(
    vuln_id: UUID,
    token: dict = Depends(require_permission("vulns:write")),
    db: AsyncSession = Depends(get_db),
):
    """Remove assignee from a vulnerability."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")

    query = select(Vulnerability).join(Scan).join(Project).where(Vulnerability.id == vuln_id)
    if user_role != "admin":
        query = query.where(Project.owner_id == user_id)
    result = await db.execute(query)
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found or access denied")
    vuln.assigned_to = None
    vuln.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"id": str(vuln_id), "assigned_to": None}


# ─── Comments ─────────────────────────────────────────────────────────────────

class CommentCreate(BaseModel):
    content: str


@router.get("/{vuln_id}/comments", response_model=List[VulnCommentResponse])
async def list_comments(
    vuln_id: UUID,
    token: dict = Depends(require_permission("vulns:read")),
    db: AsyncSession = Depends(get_db),
):
    """List comments for a vulnerability."""
    result = await db.execute(
        select(VulnComment).where(VulnComment.vuln_id == vuln_id).order_by(VulnComment.created_at)
    )
    comments = result.scalars().all()
    out = []
    for c in comments:
        out.append(VulnCommentResponse(
            id=c.id, vuln_id=c.vuln_id, user_id=c.user_id,
            author_name=(getattr(c.author, "full_name", None) or getattr(c.author, "username", None)) if c.author else None,
            author_email=getattr(c.author, "email", None) if c.author else None,
            content=c.content, created_at=c.created_at, updated_at=c.updated_at,
        ))
    return out


@router.post("/{vuln_id}/comments", response_model=VulnCommentResponse, status_code=201)
async def add_comment(
    vuln_id: UUID,
    data: CommentCreate,
    token: dict = Depends(require_permission("vulns:read")),
    db: AsyncSession = Depends(get_db),
):
    """Add a comment to a vulnerability."""
    content = (data.content or "").strip()
    if not content:
        raise HTTPException(status_code=400, detail="Comment content cannot be empty")
    if len(content) > 5000:
        raise HTTPException(status_code=400, detail="Comment too long (max 5000 chars)")

    comment = VulnComment(vuln_id=vuln_id, user_id=UUID(token["sub"]), content=content)
    db.add(comment)
    await db.commit()
    await db.refresh(comment)
    author = comment.author
    return VulnCommentResponse(
        id=comment.id, vuln_id=comment.vuln_id, user_id=comment.user_id,
        author_name=(getattr(author, "full_name", None) or getattr(author, "username", None)) if author else None,
        author_email=getattr(author, "email", None) if author else None,
        content=comment.content, created_at=comment.created_at, updated_at=comment.updated_at,
    )


@router.delete("/{vuln_id}/comments/{comment_id}", status_code=204)
async def delete_comment(
    vuln_id: UUID,
    comment_id: UUID,
    token: dict = Depends(require_permission("vulns:read")),
    db: AsyncSession = Depends(get_db),
):
    """Delete a comment (own comments, or admin can delete any)."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")

    result = await db.execute(
        select(VulnComment).where(VulnComment.id == comment_id, VulnComment.vuln_id == vuln_id)
    )
    comment = result.scalar_one_or_none()
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    if user_role != "admin" and comment.user_id != user_id:
        raise HTTPException(status_code=403, detail="Cannot delete another user's comment")
    await db.delete(comment)
    await db.commit()


# ─── EPSS score enrichment ───────────────────────────────────

@router.post("/{vuln_id}/enrich-epss")
async def enrich_epss(
    vuln_id: UUID,
    token: dict = Depends(require_permission("vulns:write")),
    db: AsyncSession = Depends(get_db),
):
    """Fetch EPSS score from FIRST.org for the vulnerability's CVE ID."""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    if not vuln.cve_id:
        raise HTTPException(status_code=400, detail="Vulnerability has no CVE ID")

    import httpx
    cve = vuln.cve_id.upper()
    url = f"https://api.first.org/data/v1/epss?cve={cve}"
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
        items = data.get("data", [])
        if not items:
            raise HTTPException(status_code=404, detail=f"No EPSS data found for {cve}")
        item = items[0]
        vuln.epss_score = float(item.get("epss", 0))
        vuln.epss_percentile = float(item.get("percentile", 0))
        vuln.epss_updated_at = datetime.now(timezone.utc)
        await db.commit()
        return {"cve_id": cve, "epss_score": vuln.epss_score, "epss_percentile": vuln.epss_percentile}
    except httpx.HTTPError as e:
        logger.warning("EPSS API error", exc_info=True)
        raise HTTPException(status_code=502, detail="EPSS API error")


# ─── Deduplication fingerprinting ────────────────────────────

def _vuln_fingerprint(vuln_name: str, port: str | None, service: str | None) -> str:
    """Compute a stable SHA-256 fingerprint for deduplication."""
    raw = f"{vuln_name.lower().strip()}:{port or ''}:{(service or '').lower().strip()}"
    return hashlib.sha256(raw.encode()).hexdigest()


@router.post("/deduplicate")
async def deduplicate_vulnerabilities(
    scan_id: UUID = Query(..., description="Scan whose vulnerabilities to deduplicate"),
    token: dict = Depends(require_permission("vulns:write")),
    db: AsyncSession = Depends(get_db),
):
    """
    Compute fingerprints and mark duplicate vulnerabilities within a scan.
    Returns counts of unique and duplicate entries.
    """
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    )
    vulns = result.scalars().all()

    seen: dict[str, str] = {}  # fingerprint → first vuln id
    duplicates = []
    for vuln in vulns:
        fp = _vuln_fingerprint(vuln.vuln_name, vuln.port, vuln.service)
        vuln.fingerprint = fp
        if fp in seen:
            duplicates.append(str(vuln.id))
        else:
            seen[fp] = str(vuln.id)

    await db.commit()
    return {
        "scan_id": str(scan_id),
        "total": len(vulns),
        "unique": len(seen),
        "duplicates": len(duplicates),
        "duplicate_ids": duplicates,
    }


# ─── Bulk CVSS + EPSS enrichment ─────────────────────────────

_CVE_RE = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
_SEVERITY_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}


def _extract_refs(obj: dict) -> list[str] | None:
    """Extract a flat list of reference URLs from a CVE tool output dict."""
    refs_raw = obj.get("references") or obj.get("reference_urls") or []
    if isinstance(refs_raw, list):
        urls = []
        for r in refs_raw:
            if isinstance(r, str) and r.startswith("http"):
                urls.append(r)
            elif isinstance(r, dict):
                u = r.get("url") or r.get("href") or r.get("link")
                if u and isinstance(u, str) and u.startswith("http"):
                    urls.append(u)
        return urls[:10] if urls else None
    return None


@router.post("/enrich-all")
async def enrich_all_vulnerabilities(
    token: dict = Depends(require_permission("vulns:write")),
    page: int = Query(1, ge=1),
    per_page: int = Query(500, ge=1, le=2000),
    db: AsyncSession = Depends(get_db),
):
    """
    Bulk-enrich vulnerabilities with CVSS (NVD) and EPSS (FIRST.org) data.
    - Detects CVE IDs embedded in vuln_name when cve_id is unset.
    - Fetches CVSS from NVD for each unique CVE.
    - Fetches EPSS scores in bulk from FIRST.org.
    - Falls back to severity-based CVSS estimate for vulns without a CVE ID.
    - Paginated to prevent timeouts.
    """
    import httpx
    import asyncio

    # ── Backfill from AI analyses ──────────────────────────────────────────────
    # Load ALL existing fingerprints from DB first — this is the dedup key.
    # Without this check, every enrich-all call re-inserts the same AI vulns.
    existing_fps: set[str] = set(
        (await db.execute(
            select(Vulnerability.fingerprint).where(Vulnerability.fingerprint.isnot(None))
        )).scalars().all()
    )

    ai_rows = (
        await db.execute(
            select(AIAnalysis)
            .order_by(AIAnalysis.scan_id, AIAnalysis.generated_at.desc())
        )
    ).scalars().all()

    # Keep only the most-recent analysis per scan
    latest_by_scan: dict[str, AIAnalysis] = {}
    for a in ai_rows:
        sid = str(a.scan_id)
        if sid not in latest_by_scan:
            latest_by_scan[sid] = a

    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }

    new_from_ai = 0
    for analysis in latest_by_scan.values():
        parsed = analysis.parsed_data or {}
        pv = parsed.get("vulnerabilities", [])
        if not isinstance(pv, list):
            continue
        for item in pv:
            if not isinstance(item, dict):
                continue
            vuln_name = str(item.get("vuln_name") or item.get("name") or item.get("title") or "Unknown")
            port = item.get("port")
            service = item.get("service")
            fp = _vuln_fingerprint(
                vuln_name,
                str(port) if port is not None else None,
                str(service) if service is not None else None,
            )
            # Skip if already in DB (prevents re-insertion on every enrich-all call)
            if fp in existing_fps:
                continue
            existing_fps.add(fp)  # mark as seen so we don't double-insert within this call
            sev_key = str(item.get("severity", "medium")).lower()
            sev = severity_map.get(sev_key, Severity.MEDIUM)
            db.add(Vulnerability(
                scan_id=analysis.scan_id,
                vuln_name=vuln_name,
                severity=sev,
                port=str(port)[:20] if port is not None else None,
                service=str(service)[:200] if service is not None else None,
                description=item.get("description"),
                cve_id=item.get("cve_id"),
                cvss_score=item.get("cvss_score") if isinstance(item.get("cvss_score"), (int, float)) else None,
                epss_score=item.get("epss_score") if isinstance(item.get("epss_score"), (int, float)) else None,
                fingerprint=fp,
                source="ai_analysis",
            ))
            new_from_ai += 1

    await db.commit()

    # ── Backfill rich CVE data from ScanToolResult (cve/cisa_kev/cve_lite) ──
    # These tool results contain NVD description, references, severity that the AI
    # may not have included.  We only ENRICH existing rows — we do NOT insert new
    # Vulnerability rows from CVE-tool results to avoid phantom entries unrelated to
    # actual target assets.
    from app.models.scan import ScanToolResult
    cve_tool_rows = (await db.execute(
        select(ScanToolResult)
        .where(ScanToolResult.tool_name.in_(["cve", "cisa_kev", "cve_lite"]))
        .where(ScanToolResult.parsed_output.isnot(None))
    )).scalars().all()

    # Build lookup: normalised_cve_id → {description, cvss_score, references, severity}
    cve_tool_data: dict[str, dict] = {}
    for tr in cve_tool_rows:
        po = tr.parsed_output or {}
        if not isinstance(po, dict):
            continue
        # Single CVE result
        raw_cve_id = po.get("cve_id") or po.get("id")
        if raw_cve_id:
            cid = str(raw_cve_id).upper()
            if cid not in cve_tool_data:
                cve_tool_data[cid] = {
                    "description": po.get("description"),
                    "cvss_score": po.get("cvss_v3_score") or po.get("cvss_score"),
                    "references": _extract_refs(po),
                    "severity": po.get("severity"),
                }
        # Bulk result (list of CVEs inside "results" / "cves" key)
        for entry in (po.get("results") or po.get("cves") or []):
            if not isinstance(entry, dict):
                continue
            cid2 = str(entry.get("cve_id") or entry.get("id") or "").upper()
            if cid2 and cid2 not in cve_tool_data:
                cve_tool_data[cid2] = {
                    "description": entry.get("description"),
                    "cvss_score": entry.get("cvss_v3_score") or entry.get("cvss_score"),
                    "references": _extract_refs(entry),
                    "severity": entry.get("severity"),
                }

    # Apply cached CVE tool data to existing vulns that are missing info
    if cve_tool_data:
        existing_vulns_for_enrich = (await db.execute(select(Vulnerability))).scalars().all()
        for v in existing_vulns_for_enrich:
            if not v.cve_id:
                continue
            data = cve_tool_data.get(v.cve_id.upper())
            if not data:
                continue
            changed = False
            if data["description"] and not v.cve_description:
                v.cve_description = str(data["description"])
                changed = True
            if data["references"] and not v.cve_references:
                v.cve_references = data["references"]
                changed = True
            if data["cvss_score"] is not None and v.cvss_score is None:
                try:
                    v.cvss_score = float(data["cvss_score"])
                    changed = True
                except (TypeError, ValueError):
                    pass
            # Tag source if not already set
            if not v.source:
                v.source = "cve_tool"
                changed = True
            if changed:
                v.updated_at = datetime.now(timezone.utc)
        await db.commit()

    total = (await db.execute(select(func.count()).select_from(Vulnerability))).scalar() or 0
    result = await db.execute(
        select(Vulnerability)
        .order_by(Vulnerability.id)
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    vulns = result.scalars().all()

    # ── Step 1: set cve_id from vuln_name where missing ──────
    for v in vulns:
        if not v.cve_id:
            m = _CVE_RE.search(v.vuln_name)
            if m:
                v.cve_id = m.group(0).upper()

    # ── Step 2: gather unique CVE IDs ───────────────────────
    cve_ids = list({v.cve_id for v in vulns if v.cve_id})
    # Re-fetch NVD data for any CVE missing score OR missing description
    cve_ids_need_nvd = list({v.cve_id for v in vulns if v.cve_id and (v.cvss_score is None or not v.cve_description)})

    # ── Step 3: fetch full NVD details (score + description + refs) ──
    # Returns (cve_id, score | None, description | None, references | None)
    NVDDetail = tuple[str, float | None, str | None, list | None]
    cvss_map: dict[str, float] = {}
    nvd_details_map: dict[str, tuple[str | None, list | None]] = {}  # cve_id → (desc, refs)

    async def _fetch_nvd(client: httpx.AsyncClient, cve_id: str) -> NVDDetail:
        try:
            resp = await client.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            )
            if resp.status_code == 200:
                for item in resp.json().get("vulnerabilities", []):
                    cve_obj = item.get("cve", {})
                    # CVSS score
                    score: float | None = None
                    metrics = cve_obj.get("metrics", {})
                    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if key in metrics:
                            s = metrics[key][0].get("cvssData", {}).get("baseScore")
                            if s is not None:
                                score = float(s)
                                break
                    # Description (English preferred)
                    desc: str | None = None
                    for d in cve_obj.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc = d.get("value")
                            break
                    if desc is None and cve_obj.get("descriptions"):
                        desc = cve_obj["descriptions"][0].get("value")
                    # References
                    refs: list[str] = [
                        r["url"] for r in cve_obj.get("references", []) if r.get("url")
                    ][:10]
                    return cve_id, score, desc, refs or None
        except Exception as exc:
            logger.warning("NVD lookup failed for %s: %s", cve_id, exc)
        return cve_id, None, None, None

    # NVD public rate-limit: 5 req/30s without API key — batch in groups of 5
    async with httpx.AsyncClient(timeout=15, headers={"User-Agent": "SOCIS-AI-PT/1.0"}) as client:
        for batch_start in range(0, len(cve_ids_need_nvd), 5):
            batch = cve_ids_need_nvd[batch_start:batch_start + 5]
            results = await asyncio.gather(*[_fetch_nvd(client, c) for c in batch])
            for cve_id, score, desc, refs in results:
                if score is not None:
                    cvss_map[cve_id] = score
                if desc or refs:
                    nvd_details_map[cve_id] = (desc, refs)
            if batch_start + 5 < len(cve_ids_need_nvd):
                await asyncio.sleep(6)  # stay within 5-req/30s window between batches

    # ── Step 4: fetch EPSS in bulk from FIRST.org ────────────
    epss_map: dict[str, tuple[float, float]] = {}  # cve_id → (score, percentile)
    cve_ids_need_epss = [v.cve_id for v in vulns if v.cve_id and v.epss_score is None]
    if cve_ids_need_epss:
        try:
            cve_param = ",".join(cve_ids_need_epss)
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(
                    f"https://api.first.org/data/v1/epss?cve={cve_param}"
                )
                if resp.status_code == 200:
                    for item in resp.json().get("data", []):
                        epss_map[item["cve"].upper()] = (
                            float(item.get("epss", 0)),
                            float(item.get("percentile", 0)),
                        )
        except Exception as exc:
            logger.warning("EPSS bulk lookup failed: %s", exc)

    # ── Step 5: apply all enrichment to each vulnerability ───
    enriched = 0
    now = datetime.now(timezone.utc)
    for v in vulns:
        changed = False
        if v.cve_id:
            # CVSS score
            if v.cve_id in cvss_map and v.cvss_score is None:
                v.cvss_score = cvss_map[v.cve_id]
                changed = True
            # EPSS
            if v.cve_id in epss_map:
                v.epss_score, v.epss_percentile = epss_map[v.cve_id]
                v.epss_updated_at = now
                changed = True
            # NVD description + references
            if v.cve_id in nvd_details_map:
                desc, refs = nvd_details_map[v.cve_id]
                if desc and not v.cve_description:
                    v.cve_description = desc
                    changed = True
                if refs and not v.cve_references:
                    v.cve_references = refs
                    changed = True
        # Severity-based CVSS fallback for vulns with no CVE and no CVSS yet
        if v.cvss_score is None:
            v.cvss_score = _SEVERITY_CVSS.get(v.severity.lower() if v.severity else "medium", 5.0)
            changed = True
        if changed:
            enriched += 1

    await db.commit()
    return {
        "page": page,
        "per_page": per_page,
        "total": total,
        "processed": len(vulns),
        "enriched": enriched,
        "new_from_ai": new_from_ai,
        "cves_found": len(cve_ids),
        "cvss_fetched": len(cvss_map),
        "epss_fetched": len(epss_map),
        "nvd_descriptions_fetched": len(nvd_details_map),
    }
