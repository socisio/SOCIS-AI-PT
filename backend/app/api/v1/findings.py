"""
SOCIS-AI-PT — Findings Routes
Aggregates all ScanToolResult records across scans with filtering and stats.
"""

import logging
import json as _json
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Any, Dict
from uuid import UUID

from fastapi import APIRouter, Depends, Query, HTTPException, Body
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, cast, Date

from app.core.database import get_db
from app.core.security import require_permission
from app.models.scan import Scan, ScanToolResult
from app.models.project import Project
from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)
router = APIRouter()

# ── Tools that belong to the Vulnerabilities page, not Findings ─────────────
# These are CVE-intelligence enrichment tools (cve lookup, kev, epss, poc).
# The Findings endpoint excludes them by default so they don't duplicate
# what the Vulnerabilities page already shows.
CVE_INTELLIGENCE_TOOLS: set = {"cve", "cisa_kev", "epss", "poc_index", "cve_lite"}

# ── Tool → category mapping (mirrors frontend TOOL_META) ─────────────────────
TOOL_CATEGORIES: Dict[str, str] = {
    "nmap":         "Discovery",
    "masscan":      "Discovery",
    "waf":          "Discovery",
    "whatweb":      "Discovery",
    "curl_headers": "Discovery",
    "nuclei":       "Vulnerability",
    "cve":          "Intelligence",
    "cisa_kev":     "Intelligence",
    "epss":         "Intelligence",
    "poc_index":    "Intelligence",
    "metasploit":   "Exploitation",
    "sqlmap":       "Web",
    "ffuf":         "Web",
    "gobuster":     "Web",
    "nikto":        "Web",
    "wpscan":       "Web",
    "jwt":          "Web",
    "osint":        "Recon",
    "whois":        "Recon",
    "subfinder":    "Recon",
    "dig":          "Recon",
    "ssl":          "Crypto",
    "testssl":      "Crypto",
    "cve_lite":     "Code",
}


def _tool_category(tool_name: str) -> str:
    base = tool_name.split("_")[0] if "_" in tool_name else tool_name
    return TOOL_CATEGORIES.get(tool_name) or TOOL_CATEGORIES.get(base, "Other")


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class ScanSummary(BaseModel):
    id: str
    target: str
    scan_type: str
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingResponse(BaseModel):
    id: str
    tool_name: str
    category: str
    raw_output: Optional[str] = None
    parsed_output: Optional[Any] = None
    duration_ms: Optional[int] = None
    exit_code: Optional[int] = None
    executed_at: datetime
    scan: ScanSummary
    # Set when this finding has already been promoted to a tracked vulnerability (drives the "tracked" badge).
    promoted_vuln_id: Optional[str] = None


class FindingsListResponse(BaseModel):
    findings: List[FindingResponse]
    total: int
    page: int
    per_page: int


class ToolCount(BaseModel):
    tool_name: str
    category: str
    count: int


class CategoryCount(BaseModel):
    category: str
    count: int


class DayCount(BaseModel):
    date: str
    count: int


class TargetCount(BaseModel):
    target: str
    count: int


class FindingsStats(BaseModel):
    total_findings: int
    unique_scans: int
    unique_targets: int
    unique_tools: int
    by_tool: List[ToolCount]
    by_category: List[CategoryCount]
    recent_days: List[DayCount]
    top_targets: List[TargetCount]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ownership_filters(user_id: UUID, user_role: str):
    """Return list of WHERE clause conditions for ownership."""
    if user_role == "admin":
        return []
    return [Project.owner_id == user_id]


# ── List findings ─────────────────────────────────────────────────────────────

@router.get("/", response_model=FindingsListResponse)
async def list_findings(
    tool_name: Optional[str] = None,
    category: Optional[str] = None,
    target: Optional[str] = None,
    scan_id: Optional[UUID] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """List all tool findings across scans with optional filters."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")
    own_filters = _ownership_filters(user_id, user_role)

    base = (
        select(ScanToolResult, Scan)
        .join(Scan, ScanToolResult.scan_id == Scan.id)
        .join(Project, Scan.project_id == Project.id)
        .where(*own_filters)
        .order_by(ScanToolResult.executed_at.desc())
    )
    count_base = (
        select(func.count())
        .select_from(ScanToolResult)
        .join(Scan, ScanToolResult.scan_id == Scan.id)
        .join(Project, Scan.project_id == Project.id)
        .where(*own_filters)
    )

    if scan_id:
        base       = base.where(ScanToolResult.scan_id == scan_id)
        count_base = count_base.where(ScanToolResult.scan_id == scan_id)
    if tool_name:
        # Explicit tool filter — honour it even if it's a CVE-intelligence tool
        base       = base.where(ScanToolResult.tool_name == tool_name)
        count_base = count_base.where(ScanToolResult.tool_name == tool_name)
    elif category:
        tools_in_cat = [t for t, c in TOOL_CATEGORIES.items() if c == category]
        if not tools_in_cat:
            return FindingsListResponse(findings=[], total=0, page=page, per_page=per_page)
        base       = base.where(ScanToolResult.tool_name.in_(tools_in_cat))
        count_base = count_base.where(ScanToolResult.tool_name.in_(tools_in_cat))
    else:
        # No category / tool filter → exclude CVE-intelligence tools by default.
        # Those live on the Vulnerabilities page, not here.
        base       = base.where(ScanToolResult.tool_name.not_in(CVE_INTELLIGENCE_TOOLS))
        count_base = count_base.where(ScanToolResult.tool_name.not_in(CVE_INTELLIGENCE_TOOLS))
    if target:
        base       = base.where(Scan.target.ilike(f"%{target}%"))
        count_base = count_base.where(Scan.target.ilike(f"%{target}%"))
    if date_from:
        base       = base.where(ScanToolResult.executed_at >= date_from)
        count_base = count_base.where(ScanToolResult.executed_at >= date_from)
    if date_to:
        base       = base.where(ScanToolResult.executed_at <= date_to)
        count_base = count_base.where(ScanToolResult.executed_at <= date_to)

    total = (await db.execute(count_base)).scalar() or 0
    rows  = (await db.execute(base.offset((page - 1) * per_page).limit(per_page))).all()

    # Which of the findings on this page have already been promoted to a tracked vulnerability?
    page_ids = [row[0].id for row in rows]
    promoted_map: dict = {}
    if page_ids:
        prom = await db.execute(
            select(Vulnerability.source_finding_id, Vulnerability.id)
            .where(Vulnerability.source_finding_id.in_(page_ids))
        )
        promoted_map = {str(fid): str(vid) for fid, vid in prom.all()}

    findings: List[FindingResponse] = []
    for row in rows:
        tr: ScanToolResult = row[0]
        sc: Scan = row[1]
        findings.append(FindingResponse(
            id=str(tr.id),
            tool_name=tr.tool_name,
            category=_tool_category(tr.tool_name),
            raw_output=tr.raw_output,
            parsed_output=tr.parsed_output,
            duration_ms=tr.duration_ms,
            exit_code=tr.exit_code,
            executed_at=tr.executed_at,
            scan=ScanSummary(
                id=str(sc.id),
                target=sc.target,
                scan_type=sc.scan_type,
                status=sc.status,
                created_at=sc.created_at,
            ),
            promoted_vuln_id=promoted_map.get(str(tr.id)),
        ))

    return FindingsListResponse(findings=findings, total=total, page=page, per_page=per_page)


# ── Stats ─────────────────────────────────────────────────────────────────────

@router.get("/stats", response_model=FindingsStats)
async def findings_stats(
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Aggregate dashboard stats for all tool findings."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")
    own_filters = _ownership_filters(user_id, user_role)

    def _joined(stmt):
        return (
            stmt
            .select_from(ScanToolResult)
            .join(Scan, ScanToolResult.scan_id == Scan.id)
            .join(Project, Scan.project_id == Project.id)
            .where(*own_filters)
            # Exclude CVE-intelligence tools — those belong to the Vulnerabilities page
            .where(ScanToolResult.tool_name.not_in(CVE_INTELLIGENCE_TOOLS))
        )

    total_findings: int = (
        await db.execute(_joined(select(func.count())))
    ).scalar() or 0

    unique_scans: int = (
        await db.execute(
            _joined(select(func.count(func.distinct(ScanToolResult.scan_id))))
        )
    ).scalar() or 0

    unique_targets: int = (
        await db.execute(
            _joined(select(func.count(func.distinct(Scan.target))))
        )
    ).scalar() or 0

    unique_tools: int = (
        await db.execute(
            _joined(select(func.count(func.distinct(ScanToolResult.tool_name))))
        )
    ).scalar() or 0

    # Per-tool counts (sorted desc)
    by_tool_rows = (await db.execute(
        _joined(
            select(ScanToolResult.tool_name, func.count().label("cnt"))
            .group_by(ScanToolResult.tool_name)
            .order_by(func.count().desc())
        )
    )).all()
    by_tool = [
        ToolCount(tool_name=r[0], category=_tool_category(r[0]), count=r[1])
        for r in by_tool_rows
    ]

    # Per-category (computed from by_tool — avoids extra query)
    cat_counts: Dict[str, int] = {}
    for t in by_tool:
        cat_counts[t.category] = cat_counts.get(t.category, 0) + t.count
    by_category = sorted(
        [CategoryCount(category=k, count=v) for k, v in cat_counts.items()],
        key=lambda x: x.count,
        reverse=True,
    )

    # Last 30 days daily counts
    thirty_ago = datetime.now(timezone.utc) - timedelta(days=30)
    daily_rows = (await db.execute(
        _joined(
            select(
                cast(ScanToolResult.executed_at, Date).label("day"),
                func.count().label("cnt"),
            )
            .where(ScanToolResult.executed_at >= thirty_ago)
            .group_by(cast(ScanToolResult.executed_at, Date))
            .order_by(cast(ScanToolResult.executed_at, Date))
        )
    )).all()
    recent_days = [DayCount(date=str(r[0]), count=r[1]) for r in daily_rows]

    # Top 10 targets by finding count
    top_target_rows = (await db.execute(
        _joined(
            select(Scan.target, func.count().label("cnt"))
            .group_by(Scan.target)
            .order_by(func.count().desc())
            .limit(10)
        )
    )).all()
    top_targets = [TargetCount(target=r[0], count=r[1]) for r in top_target_rows]

    return FindingsStats(
        total_findings=total_findings,
        unique_scans=unique_scans,
        unique_targets=unique_targets,
        unique_tools=unique_tools,
        by_tool=by_tool,
        by_category=by_category,
        recent_days=recent_days,
        top_targets=top_targets,
    )


# ── AI Enrichment ─────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    provider: Optional[str] = "ollama_remote"
    model: Optional[str] = None
    remote_url: Optional[str] = None


class AnalyzeResponse(BaseModel):
    finding_id: str
    tool_name: str
    analysis: str


@router.post("/{finding_id}/analyze", response_model=AnalyzeResponse)
async def analyze_finding(
    finding_id: UUID,
    req: AnalyzeRequest = Body(default=AnalyzeRequest()),
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Run AI security analysis on a specific tool finding."""
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")
    own_filters = _ownership_filters(user_id, user_role)

    result = await db.execute(
        select(ScanToolResult, Scan)
        .join(Scan, ScanToolResult.scan_id == Scan.id)
        .join(Project, Scan.project_id == Project.id)
        .where(ScanToolResult.id == finding_id)
        .where(*own_filters)
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found or access denied")

    tr: ScanToolResult = row[0]
    sc: Scan = row[1]

    # Format output for analysis (cap raw at 8 KB)
    if tr.parsed_output:
        output_text = _json.dumps(tr.parsed_output, indent=2)[:8000]
    elif tr.raw_output:
        output_text = tr.raw_output[:8000]
    else:
        output_text = "(no output recorded)"

    prompt = (
        f"You are a cybersecurity expert reviewing a penetration test tool result.\n\n"
        f"Tool: {tr.tool_name}\n"
        f"Category: {_tool_category(tr.tool_name)}\n"
        f"Target: {sc.target}\n"
        f"Exit code: {tr.exit_code}  Duration: {tr.duration_ms}ms\n\n"
        f"Tool output:\n{output_text}\n\n"
        f"Provide a concise security analysis with these sections:\n"
        f"• What was found or confirmed\n"
        f"• Security implications and risk level\n"
        f"• Recommended next steps or remediation\n\n"
        f"Be specific and actionable. Limit to 5-8 bullet points total."
    )

    # Resolve the ADMIN-SAVED provider/model/URL the same way scans' manual AI analysis does (scan_worker.py's
    # run_scan_ai_analysis), instead of only trusting whatever this one request happened to pass in: previously this
    # endpoint never consulted the database-backed config at all (only req.* or a bare env var), so it failed for
    # every finding regardless of what was actually configured on Admin -> AI providers.
    from app.services.llm_service import llm_service
    from app.services.settings_service import SettingsService
    from app.core.llm_providers import normalize_provider
    from app.models.llm_config import LLMProvider

    settings_service = SettingsService()
    selected_provider = req.provider or "ollama_remote"
    selected_model = req.model
    selected_remote_url = req.remote_url
    selected_api_key: str | None = None

    if selected_provider == "ollama_remote":
        if not selected_model:
            selected_model = await settings_service.get_ollama_remote_model(db) or "qwen2.5:7b"
        if not selected_remote_url:
            selected_remote_url = await settings_service.get_ollama_remote_url(db)
    else:
        # Resolve the admin-saved API key/URL for this provider, and its own default model — not the Ollama
        # default model, which is a different provider's model name.
        from app.core.llm_providers import resolve_llm_credentials
        selected_api_key, _resolved_api_url = await resolve_llm_credentials(db, selected_provider)
        if not selected_remote_url:
            selected_remote_url = _resolved_api_url
        if not selected_model:
            from sqlalchemy import select as _select
            from app.models.llm_config import LLMConfig as _LLMConfig
            _default_cfg = (
                await db.execute(
                    _select(_LLMConfig)
                    .where(_LLMConfig.is_active == True, _LLMConfig.provider == selected_provider)  # noqa: E712
                    .order_by(_LLMConfig.is_default.desc(), _LLMConfig.created_at.asc())
                )
            ).scalars().first()
            if _default_cfg:
                selected_model = _default_cfg.model_name
            else:
                from app.config import settings as _settings
                selected_model = _settings.OLLAMA_DEFAULT_MODEL or "qwen2.5:7b"

    try:
        provider = LLMProvider(normalize_provider(selected_provider))
    except ValueError:
        provider = LLMProvider.OLLAMA_REMOTE

    chunks: list[str] = []
    async for chunk in llm_service.chat(
        prompt,
        provider=provider,
        model=selected_model,
        remote_url=selected_remote_url,
        api_key=selected_api_key,
        stream=False,
    ):
        chunks.append(chunk)

    analysis = "".join(chunks).strip() or "No analysis generated."
    return AnalyzeResponse(finding_id=str(tr.id), tool_name=tr.tool_name, analysis=analysis)


# ── Promote a finding to a tracked vulnerability ──────────────────────────────

class PromoteRequest(BaseModel):
    vuln_name: Optional[str] = None
    severity: Optional[str] = None
    priority: Optional[str] = None


_SEVERITY_BY_CATEGORY = {
    "Exploitation": "critical",
    "Vulnerability": "high",
    "Web": "high",
    "Crypto": "medium",
    "Code": "medium",
    "Discovery": "low",
    "Recon": "low",
}


@router.post("/{finding_id}/promote", status_code=201)
async def promote_finding(
    finding_id: UUID,
    req: PromoteRequest = Body(default=PromoteRequest()),
    token: dict = Depends(require_permission("vulns:write")),
    db: AsyncSession = Depends(get_db),
):
    """Create a managed vulnerability from a raw tool finding, linking the two.

    This is the bridge the Findings page was missing — it turns raw scan output into tracked, triageable work. The
    finding is resolved through the same per-row ownership filter the rest of this module uses (a non-admin can only
    promote findings in projects they own), and a finding that's already been promoted returns its existing
    vulnerability rather than creating a duplicate.
    """
    user_id = UUID(token["sub"])
    user_role = token.get("role", "viewer")
    own_filters = _ownership_filters(user_id, user_role)

    # Resolve the finding with ownership enforced.
    result = await db.execute(
        select(ScanToolResult, Scan)
        .join(Scan, ScanToolResult.scan_id == Scan.id)
        .join(Project, Scan.project_id == Project.id)
        .where(ScanToolResult.id == finding_id, *own_filters)
    )
    row = result.first()
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found or access denied")
    finding, scan = row

    # Idempotent: if this finding was already promoted, return the existing vulnerability.
    existing = (await db.execute(
        select(Vulnerability).where(Vulnerability.source_finding_id == finding_id)
    )).scalar_one_or_none()
    if existing:
        return {"id": str(existing.id), "already_promoted": True, "vuln_name": existing.vuln_name}

    category = finding.category if hasattr(finding, "category") else None
    # ScanToolResult has no stored category column in all deployments — derive from tool if absent.
    severity = (req.severity or _SEVERITY_BY_CATEGORY.get(category or "", "medium")).lower()
    name = (req.vuln_name or "").strip() or f"{finding.tool_name} finding on {scan.target}"

    # Build an evidence description from the finding's parsed output (compact, not the full raw dump).
    evidence_bits = []
    po = finding.parsed_output or {}
    if isinstance(po, dict):
        for k in ("summary", "description", "vulnerable", "injectable", "dbms", "cve_id", "matched"):
            if k in po and po[k] not in (None, "", [], {}):
                evidence_bits.append(f"{k}: {po[k]}")
    description = (
        f"Promoted from {finding.tool_name} finding (scan target {scan.target}).\n"
        + ("\n".join(evidence_bits[:8]) if evidence_bits else "")
    ).strip()

    vuln = Vulnerability(
        scan_id=scan.id,
        vuln_name=name[:500],
        severity=severity if severity in ("critical", "high", "medium", "low", "info") else "medium",
        status="open",
        description=description,
        source="promoted_finding",
        source_finding_id=finding.id,
        priority=(req.priority or None),
    )
    db.add(vuln)
    await db.commit()
    await db.refresh(vuln)
    return {"id": str(vuln.id), "already_promoted": False, "vuln_name": vuln.vuln_name}
