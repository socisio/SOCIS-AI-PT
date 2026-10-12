"""Dashboard summary for every signed-in user.

The previous dashboard called /admin/dashboard, which requires the admin permission, and swallowed the
403: analysts and viewers saw all zeros (and its "Reports" tile actually showed the scan count). This
endpoint returns real numbers with the ordinary read permission.
"""
from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import require_permission
from app.models.enums import ScanStatus
from app.models.project import Project
from app.models.report import Report, ReportStatus
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability, Severity, VulnStatus

router = APIRouter()

# A vulnerability counts as "open" until it is resolved, accepted or marked a false positive.
_OPEN_STATUSES = (VulnStatus.OPEN, VulnStatus.IN_PROGRESS)
# A scan is "active" until it completes, fails or is cancelled.
_ACTIVE_STATUSES = (ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.ANALYZING)
_SEVERITIES = ("critical", "high", "medium", "low", "info")


def shape_summary(*, scans_total, scans_active, projects, reports, vulns_total, severity_rows) -> dict:
    """Pure shaping of the query results (unit-tested without a database).

    severity_rows: iterable of (severity, count) for OPEN vulnerabilities; severity may be an enum or a string.
    """
    by_sev = {s: 0 for s in _SEVERITIES}
    for sev, n in severity_rows:
        key = str(getattr(sev, "value", sev)).lower()
        if key in by_sev:
            by_sev[key] += int(n or 0)
    return {
        "scans_total": int(scans_total or 0),
        "scans_active": int(scans_active or 0),
        "projects": int(projects or 0),
        "reports": int(reports or 0),
        "vulns_total": int(vulns_total or 0),
        "vulns_open": sum(by_sev.values()),
        "open_by_severity": by_sev,
    }


async def _count(db: AsyncSession, stmt) -> int:
    return int((await db.execute(stmt)).scalar() or 0)


@router.get("/summary")
async def dashboard_summary(
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Counts shown on the dashboard (scans, open vulnerabilities by severity, reports, projects)."""
    scans_total = await _count(db, select(func.count()).select_from(Scan))
    scans_active = await _count(db, select(func.count()).select_from(Scan).where(Scan.status.in_(_ACTIVE_STATUSES)))
    projects = await _count(db, select(func.count()).select_from(Project))
    reports = await _count(db, select(func.count()).select_from(Report).where(Report.status == ReportStatus.COMPLETED))
    vulns_total = await _count(db, select(func.count()).select_from(Vulnerability))
    rows = (
        await db.execute(
            select(Vulnerability.severity, func.count())
            .where(Vulnerability.status.in_(_OPEN_STATUSES))
            .group_by(Vulnerability.severity)
        )
    ).all()
    return shape_summary(
        scans_total=scans_total, scans_active=scans_active, projects=projects,
        reports=reports, vulns_total=vulns_total, severity_rows=rows,
    )
