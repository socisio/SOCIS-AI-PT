"""
SOCIS-AI-PT — Report API Routes (Updated with report_service)
"""

import json
import os
import asyncio
from uuid import UUID
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import require_permission
from app.core.audit import log_audit
from app.models.report import Report, ReportFormat, ReportStatus
from app.models.scan import Scan
from app.services.report_service import (
    generate_html_report,
    generate_pdf_report,
    generate_json_report,
    generate_csv_report,
    generate_docx_report,
    generate_sarif_report,
    generate_markdown_report,
    get_scan_with_relations,
    REPORTS_DIR,
    _build_branding,
    DEFAULT_REPORT_BRANDING,
)
from app.services.storage_service import storage_service
from app.services.settings_service import UserSettingsService

router = APIRouter()


@router.get("/")
async def list_reports(
    scan_id: Optional[UUID] = None,
    token: dict = Depends(require_permission("reports:read")),
    db: AsyncSession = Depends(get_db),
):
    """List all generated reports."""
    q = select(Report).order_by(Report.generated_at.desc())
    if scan_id:
        q = q.where(Report.scan_id == scan_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.post("/generate")
async def generate_report(
    data: dict,
    background_tasks: BackgroundTasks,
    token: dict = Depends(require_permission("reports:write")),
    db: AsyncSession = Depends(get_db),
):
    """Queue report generation. For PDF, runs in background. HTML/JSON/CSV return immediately."""
    scan_id = data.get("scan_id")
    fmt = data.get("format", "pdf").lower()
    
    if not scan_id:
        raise HTTPException(status_code=400, detail="scan_id required")

    scan = await get_scan_with_relations(scan_id, db)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get user's report settings
    user_id = UUID(token["sub"])
    settings_service = UserSettingsService()
    user_settings = await settings_service.get_report_settings(db, user_id)
    
    # Build branding: default → user settings → request overrides
    request_branding = {
        "brand_name": data.get("brand_name"),
        "brand_tagline": data.get("brand_tagline"),
        "brand_color": data.get("brand_color"),
        "brand_logo_url": data.get("brand_logo_url"),
        "customer_name": data.get("customer_name"),
        "customer_logo_url": data.get("customer_logo_url"),
        "report_theme": data.get("report_theme"),
        "report_classification": data.get("report_classification"),
    }
    request_branding = {k: v for k, v in request_branding.items() if v is not None}
    branding = _build_branding(DEFAULT_REPORT_BRANDING, user_settings, request_branding)
    # Logos come from a user: fetch them here with the network guard and hand the template a data: URI, never a URL it would fetch.
    from app.core.report_safety import embed_logos
    branding = await embed_logos(branding)
    
    # Create report record
    report = Report(
        scan_id=UUID(scan_id),
        generated_by=user_id,
        format=ReportFormat(fmt),
        brand_name=branding.get("brand_name", "SOCIS-AI-PT"),
        brand_logo_url=branding.get("brand_logo_url", ""),
        status=ReportStatus.PENDING,
    )
    db.add(report)
    await db.flush()
    await log_audit(
        db, action="report:generate",
        user_id=user_id,
        resource_type="report", resource_id=str(report.id),
        details={"scan_id": str(scan_id), "format": fmt},
    )
    await db.commit()
    report_id = report.id

    if fmt == "pdf":
        background_tasks.add_task(_generate_pdf_bg, str(report_id), str(scan_id), branding, db)
        return {"message": "PDF report generation started", "report_id": str(report_id)}

    # For other formats — generate immediately
    try:
        if fmt == "html":
            content = await generate_html_report(scan, branding)
            ext = "html"
            content_bytes = content.encode("utf-8")
        elif fmt == "json":
            content = generate_json_report(scan, branding)
            ext = "json"
            content_bytes = content.encode("utf-8")
        elif fmt == "csv":
            content = generate_csv_report(scan, branding)
            ext = "csv"
            content_bytes = content.encode("utf-8")
        elif fmt == "docx":
            content_bytes = await generate_docx_report(scan, branding)
            ext = "docx"
        elif fmt == "sarif":
            sarif_data = generate_sarif_report(scan, branding)
            content_bytes = json.dumps(sarif_data, indent=2).encode("utf-8")
            ext = "sarif"
        elif fmt == "markdown":
            content = generate_markdown_report(scan, branding)
            ext = "md"
            content_bytes = content.encode("utf-8")
        else:
            raise HTTPException(status_code=400, detail=f"Unknown format: {fmt}")

        out_path = REPORTS_DIR / f"report_{report_id}.{ext}"
        out_path.write_bytes(content_bytes)
        
        # Upload to MinIO if enabled
        object_name = f"reports/{scan_id}/report_{report_id}.{ext}"
        await asyncio.to_thread(storage_service.upload_file, object_name, out_path)

        report.status = ReportStatus.COMPLETED
        report.file_url = f"/api/v1/reports/{report_id}/download"
        report.file_size_bytes = len(content_bytes)
        report.error_message = None
        report.generated_at = datetime.now(timezone.utc)
        await db.commit()
    except Exception as e:
        report.status = ReportStatus.FAILED
        report.error_message = str(e)[:1000]
        report.generated_at = datetime.now(timezone.utc)
        await db.commit()
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

    return {
        "report_id": str(report_id),
        "format": fmt,
        "file_url": report.file_url,
        "file_size_bytes": report.file_size_bytes,
    }


async def _generate_pdf_bg(report_id: str, scan_id: str, branding: dict, db: AsyncSession):
    """Background task for PDF generation."""
    from app.core.database import async_session
    async with async_session() as db_session:
        scan = await get_scan_with_relations(scan_id, db_session)
        result = await db_session.execute(select(Report).where(Report.id == UUID(report_id)))
        report = result.scalar_one_or_none()
        if not report or not scan:
            return

        try:
            out_path = await generate_pdf_report(scan, branding, REPORTS_DIR / f"report_{report_id}.pdf")
            
            # Upload to MinIO
            object_name = f"reports/{scan_id}/report_{report_id}.pdf"
            await asyncio.to_thread(storage_service.upload_file, object_name, out_path)
            
            report.status = ReportStatus.COMPLETED
            report.file_url = f"/api/v1/reports/{report_id}/download"
            report.file_size_bytes = out_path.stat().st_size
            report.error_message = None
            report.generated_at = datetime.now(timezone.utc)
        except Exception as e:
            report.status = ReportStatus.FAILED
            report.error_message = str(e)[:1000]
            report.generated_at = datetime.now(timezone.utc)
        await db_session.commit()


@router.get("/{report_id}/download")
async def download_report(
    report_id: UUID,
    token: dict = Depends(require_permission("reports:read")),
    db: AsyncSession = Depends(get_db),
):
    """Download a generated report file."""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if report.status != ReportStatus.COMPLETED:
        raise HTTPException(status_code=409, detail=f"Report is {report.status}")

    MEDIA_TYPES = {
        "pdf": "application/pdf",
        "html": "text/html",
        "json": "application/json",
        "csv": "text/csv",
        "md": "text/markdown",
        "markdown": "text/markdown",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "sarif": "application/sarif+json",
    }
    format_value = str(getattr(report.format, "value", report.format))
    format_to_ext = {
        "pdf": "pdf",
        "html": "html",
        "json": "json",
        "csv": "csv",
        "docx": "docx",
        "sarif": "sarif",
        "markdown": "md",
    }
    primary_ext = format_to_ext.get(format_value, "pdf")
    fallback_exts = ["html", "json", "csv", "pdf", "docx", "sarif", "md", "markdown"]
    try_exts = [primary_ext] + [ext for ext in fallback_exts if ext != primary_ext]

    for try_ext in try_exts:
        file_path = REPORTS_DIR / f"report_{report_id}.{try_ext}"
        object_name = f"reports/{report.scan_id}/report_{report_id}.{try_ext}"
        
        # Check local disk
        if file_path.exists():
            return FileResponse(
                path=str(file_path),
                media_type=MEDIA_TYPES.get(try_ext, "application/octet-stream"),
                filename=f"socis_report_{report_id}.{try_ext}",
            )
            
        # Check MinIO
        if storage_service.enabled:
            data = storage_service.get_object_data(object_name)
            if data:
                # Write to disk temporarily to stream back
                file_path.write_bytes(data)
                return FileResponse(
                    path=str(file_path),
                    media_type=MEDIA_TYPES.get(try_ext, "application/octet-stream"),
                    filename=f"socis_report_{report_id}.{try_ext}",
                )

    raise HTTPException(status_code=404, detail="Report file not found on disk or storage")


@router.delete("/{report_id}", status_code=204)
async def delete_report(
    report_id: UUID,
    token: dict = Depends(require_permission("reports:write")),
    db: AsyncSession = Depends(get_db),
):
    """Delete a report record and remove associated files from storage."""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    ext_candidates = ["pdf", "html", "json", "csv", "docx", "sarif", "md", "markdown"]
    for ext in ext_candidates:
        file_path = REPORTS_DIR / f"report_{report_id}.{ext}"
        if file_path.exists():
            try:
                file_path.unlink()
            except Exception:
                # Keep deletion resilient: record removal should still proceed.
                pass

        object_name = f"reports/{report.scan_id}/report_{report_id}.{ext}"
        if storage_service.enabled and storage_service.client:
            try:
                storage_service.client.remove_object(storage_service.bucket, object_name)
            except Exception:
                # Ignore missing object/errors to avoid blocking DB cleanup.
                pass

    await db.delete(report)
    await db.commit()


@router.get("/{report_id}/sarif")
async def download_sarif(
    report_id: UUID,
    token: dict = Depends(require_permission("reports:read")),
    db: AsyncSession = Depends(get_db),
):
    """Stream the SARIF report directly."""
    from fastapi.responses import Response
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    scan = await get_scan_with_relations(str(report.scan_id), db)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    sarif_data = generate_sarif_report(scan, report.brand_name or "SOCIS-AI-PT")
    return Response(
        content=json.dumps(sarif_data, indent=2),
        media_type="application/sarif+json",
        headers={"Content-Disposition": f"attachment; filename=report_{report_id}.sarif"},
    )


@router.get("/scan/{scan_id}/executive")
async def executive_report(
    scan_id: UUID,
    brand_name: str = "SOCIS-AI-PT",
    token: dict = Depends(require_permission("reports:read")),
    db: AsyncSession = Depends(get_db),
):
    """Render the executive HTML summary report (no raw tool output)."""
    from fastapi.responses import HTMLResponse
    from app.services.report_service import jinja_env, _build_context

    scan = await get_scan_with_relations(str(scan_id), db)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    context = _build_context(scan, brand_name)
    template = jinja_env.get_template("report_executive.html.j2")
    return HTMLResponse(content=template.render(**context))


@router.get("/trends")
async def vuln_trends(
    days: int = 30,
    token: dict = Depends(require_permission("reports:read")),
    db: AsyncSession = Depends(get_db),
):
    """Return daily new vulnerability counts for trend charts."""
    from datetime import timedelta
    from sqlalchemy import cast, Date, func
    from app.models.vulnerability import Vulnerability

    since = datetime.now(timezone.utc) - timedelta(days=days)
    result = await db.execute(
        select(
            cast(Vulnerability.created_at, Date).label("date"),
            func.count().label("count"),
        )
        .where(Vulnerability.created_at >= since)
        .group_by(cast(Vulnerability.created_at, Date))
        .order_by(cast(Vulnerability.created_at, Date))
    )
    rows = result.fetchall()
    return [{"date": str(r.date), "count": r.count} for r in rows]
