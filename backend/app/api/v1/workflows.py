"""
SOCIS-AI-PT — Workflow Definitions API Router
CRUD for visual (n8n-style) workflow graphs + run dispatch.
"""

import logging
import uuid
from app.core.llm_providers import normalize_provider_fields as _npf
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.core.database import get_db
from app.core.security import require_permission
from app.models.workflow_definition import WorkflowDefinition
from app.models.scan import Scan, ScanStatus, ScanType
from app.schemas.workflow import (
    WorkflowDefinitionCreate,
    WorkflowDefinitionUpdate,
    WorkflowDefinitionOut,
    WorkflowListResponse,
    WorkflowRunRequest,
)
from app.schemas.scan import ScanResponse
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _to_out(wf: WorkflowDefinition) -> WorkflowDefinitionOut:
    return WorkflowDefinitionOut(
        id=wf.id,
        name=wf.name,
        description=wf.description,
        project_id=wf.project_id,
        created_by=wf.created_by,
        nodes=wf.nodes or [],
        edges=wf.edges or [],
        default_llm=wf.default_llm,
        created_at=wf.created_at,
        updated_at=wf.updated_at,
    )


async def _get_or_404(db: AsyncSession, wf_id: UUID, user_id: str) -> WorkflowDefinition:
    result = await db.execute(
        select(WorkflowDefinition).where(WorkflowDefinition.id == wf_id)
    )
    wf = result.scalar_one_or_none()
    if not wf:
        raise HTTPException(status_code=404, detail="Workflow not found")
    # Ownership check — admins bypass via permission; here we just check creator
    if str(wf.created_by) != user_id:
        raise HTTPException(status_code=403, detail="Not your workflow")
    return wf


# ── CRUD ──────────────────────────────────────────────────────────────────────

@router.get("/", response_model=WorkflowListResponse)
async def list_workflows(
    project_id: Optional[UUID] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """List all workflows created by the current user."""
    user_id = UUID(token["sub"])
    q = select(WorkflowDefinition).where(WorkflowDefinition.created_by == user_id)
    if project_id:
        q = q.where(WorkflowDefinition.project_id == project_id)
    q = q.order_by(WorkflowDefinition.updated_at.desc())

    count_q = select(func.count()).select_from(WorkflowDefinition).where(
        WorkflowDefinition.created_by == user_id
    )
    if project_id:
        count_q = count_q.where(WorkflowDefinition.project_id == project_id)
    total = (await db.execute(count_q)).scalar() or 0

    result = await db.execute(q.offset((page - 1) * per_page).limit(per_page))
    workflows = result.scalars().all()
    return WorkflowListResponse(
        workflows=[_to_out(w) for w in workflows],
        total=total,
    )


@router.post("/", response_model=WorkflowDefinitionOut, status_code=201)
async def create_workflow(
    body: WorkflowDefinitionCreate,
    token: dict = Depends(require_permission("scans:execute")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new workflow definition."""
    wf = WorkflowDefinition(
        name=body.name,
        description=body.description,
        project_id=body.project_id,
        created_by=UUID(token["sub"]),
        nodes=_npf(body.nodes)[0],
        edges=body.edges,
        default_llm=_npf(body.default_llm.model_dump())[0] if body.default_llm else None,
    )
    db.add(wf)
    await db.flush()
    await db.refresh(wf)
    await db.commit()
    return _to_out(wf)


@router.get("/{workflow_id}", response_model=WorkflowDefinitionOut)
async def get_workflow(
    workflow_id: UUID,
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    wf = await _get_or_404(db, workflow_id, token["sub"])
    return _to_out(wf)


@router.patch("/{workflow_id}", response_model=WorkflowDefinitionOut)
async def update_workflow(
    workflow_id: UUID,
    body: WorkflowDefinitionUpdate,
    token: dict = Depends(require_permission("scans:execute")),
    db: AsyncSession = Depends(get_db),
):
    """Save canvas changes (nodes/edges) or rename a workflow."""
    wf = await _get_or_404(db, workflow_id, token["sub"])
    if body.name is not None:
        wf.name = body.name
    if body.description is not None:
        wf.description = body.description
    if body.project_id is not None:
        wf.project_id = body.project_id
    if body.nodes is not None:
        wf.nodes = _npf(body.nodes)[0]
    if body.edges is not None:
        wf.edges = body.edges
    if body.default_llm is not None:
        wf.default_llm = _npf(body.default_llm.model_dump())[0]
    wf.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(wf)
    return _to_out(wf)


@router.delete("/{workflow_id}", status_code=204)
async def delete_workflow(
    workflow_id: UUID,
    token: dict = Depends(require_permission("scans:execute")),
    db: AsyncSession = Depends(get_db),
):
    wf = await _get_or_404(db, workflow_id, token["sub"])
    await db.delete(wf)
    await db.commit()


# ── Run ───────────────────────────────────────────────────────────────────────

@router.post("/{workflow_id}/run", response_model=ScanResponse, status_code=201)
async def run_workflow(
    workflow_id: UUID,
    body: WorkflowRunRequest = WorkflowRunRequest(),
    token: dict = Depends(require_permission("scans:execute")),
    db: AsyncSession = Depends(get_db),
):
    """
    Dispatch a workflow run: create a Scan row with scan_type=workflow and
    tool_config containing the graph JSON, then queue it as an ARQ job.
    Returns the created Scan (the caller can poll /scans/{id} or subscribe
    to the WebSocket channel scan:{id} for live node events).
    """
    wf = await _get_or_404(db, workflow_id, token["sub"])

    # Resolve target from body override or start node
    target = body.target
    if not target:
        for node in (wf.nodes or []):
            if node.get("type") == "start":
                target = (node.get("data") or {}).get("target", "")
                break
    if not target:
        raise HTTPException(status_code=422, detail="No target specified. Set a target in the Start node or pass it in the request body.")

    project_id = body.project_id or wf.project_id
    if not project_id:
        # Fall back to first project owned by user
        from app.models.project import Project
        res = await db.execute(
            select(Project).where(Project.owner_id == UUID(token["sub"])).limit(1)
        )
        proj = res.scalar_one_or_none()
        if not proj:
            raise HTTPException(status_code=422, detail="No project found. Create a project first or specify project_id.")
        project_id = proj.id

    # Authorized scope (same rules as a plain scan; the worker checks again when the run starts)
    from app.services import scope_service
    _project = await scope_service.load_project_for_user(db, project_id, token)
    override = await scope_service.authorize_scan_target(db, _project, target, token, "workflow", body.scope_override_reason)

    scan = Scan(
        project_id=project_id,
        initiated_by=UUID(token["sub"]),
        target=target,
        scan_type=ScanType.WORKFLOW,
        status=ScanStatus.PENDING,
        tool_config={
            "graph": {
                "nodes": wf.nodes or [],
                "edges": wf.edges or [],
            },
            "default_llm": wf.default_llm,
            "workflow_definition_id": str(wf.id),
            "auto_ai_analysis": False,
        },
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    scope_service.attach_override(scan, override)

    # Commit first so the worker can see the scan row, then enqueue
    await db.commit()
    await db.refresh(scan)

    try:
        from app.tasks.scan_worker import get_arq_pool
        pool = await get_arq_pool()
        await pool.enqueue_job("run_scan", str(scan.id))
        await pool.aclose()
    except Exception as e:
        logger.warning("Failed to queue graph workflow scan %s: %s", scan.id, e)

    return ScanResponse.model_validate(scan)


# ── Past runs ─────────────────────────────────────────────────────────────────

@router.get("/{workflow_id}/runs")
async def list_workflow_runs(
    workflow_id: UUID,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """List all scan runs for a given workflow definition."""
    wf = await _get_or_404(db, workflow_id, token["sub"])
    q = (
        select(Scan)
        .where(Scan.tool_config["workflow_definition_id"].as_string() == str(wf.id))
        .order_by(Scan.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    result = await db.execute(q)
    scans = result.scalars().all()
    return {"runs": [ScanResponse.model_validate(s) for s in scans], "total": len(scans)}


# ── Export / Import ───────────────────────────────────────────────────────────

@router.get("/{workflow_id}/export")
async def export_workflow(
    workflow_id: UUID,
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Return workflow definition as downloadable JSON."""
    wf = await _get_or_404(db, workflow_id, token["sub"])
    payload = {
        "socis_workflow_version": "1.0",
        "name": wf.name,
        "description": wf.description,
        "nodes": wf.nodes,
        "edges": wf.edges,
        "default_llm": wf.default_llm,
        "exported_at": datetime.now(timezone.utc).isoformat(),
    }
    return JSONResponse(
        content=payload,
        headers={"Content-Disposition": f'attachment; filename="{wf.name}.socis-workflow.json"'},
    )


@router.post("/import", response_model=WorkflowDefinitionOut, status_code=201)
async def import_workflow(
    body: dict,
    token: dict = Depends(require_permission("scans:execute")),
    db: AsyncSession = Depends(get_db),
):
    """Import a previously exported workflow JSON."""
    if body.get("socis_workflow_version") != "1.0":
        raise HTTPException(status_code=422, detail="Unsupported workflow format version")
    wf = WorkflowDefinition(
        name=body.get("name", "Imported Workflow"),
        description=body.get("description"),
        created_by=UUID(token["sub"]),
        nodes=_npf(body.get("nodes", []))[0],
        edges=body.get("edges", []),
        default_llm=_npf(body.get("default_llm"))[0],
    )
    db.add(wf)
    await db.flush()
    await db.refresh(wf)
    await db.commit()
    return _to_out(wf)


# ─── Workflow Generator ──────────────────────────────────────────

_TOOL_MAP: dict[str, dict] = {
    "nmap": {"tool": "nmap", "nmap_action": "nmap_scan", "nmap_flags": "-sV"},
    "nuclei": {"tool": "nuclei", "nuclei_action": "nuclei_scan"},
    "osint": {"tool": "osint", "osint_tool": "whois_lookup"},
    "whois": {"tool": "osint", "osint_tool": "whois_lookup"},
    "ssl": {"tool": "ssl", "ssl_host": ""},
    "cve": {"tool": "cve", "cve_action": "search_cves"},
    "cisa": {"tool": "cisa_kev", "kev_action": "check_kev"},
    "cisa_kev": {"tool": "cisa_kev", "kev_action": "check_kev"},
    "epss": {"tool": "epss", "epss_action": "get_epss_score"},
    "poc": {"tool": "poc", "poc_action": "poc_risk_summary"},
    "metasploit": {"tool": "metasploit", "msf_action": "run_exploit"},
    "msf": {"tool": "metasploit", "msf_action": "run_exploit"},
    "waf": {"tool": "waf", "waf_action": "fingerprint_waf"},
    "ffuf": {"tool": "ffuf", "ffuf_url": ""},
    "sqlmap": {"tool": "sqlmap", "sqlmap_url": ""},
}


def _generate_workflow(prompt: str, target: str = "") -> dict:
    """Simple rule-based workflow generator."""
    prompt_lower = prompt.lower()
    nodes = []
    edges = []
    y_pos = 180
    
    # Start node
    start_id = "start_1"
    nodes.append({
        "id": start_id,
        "type": "start",
        "position": {"x": 200, "y": 60},
        "data": {"target": target}
    })
    
    # Find requested tools in order
    found_tools = []
    for tool_name in _TOOL_MAP:
        if tool_name in prompt_lower:
            found_tools.append(tool_name)
    
    # Add tool nodes
    prev_id = start_id
    for i, tool_name in enumerate(found_tools):
        tool_data = dict(_TOOL_MAP[tool_name])
        node_id = f"{tool_name}_{i+1}"
        
        # Fill in target
        if tool_name in ("nmap", "nuclei", "osint", "whois", "ssl", "ffuf", "sqlmap", "metasploit", "msf"):
            tool_data["target"] = target
        elif tool_name in ("cve", "cisa", "cisa_kev", "epss", "poc"):
            tool_data["cve_id"] = target or "CVE-2021-44228"
        
        nodes.append({
            "id": node_id,
            "type": "tool",
            "position": {"x": 200, "y": y_pos},
            "data": tool_data
        })
        edges.append({
            "id": f"e{i+1}",
            "source": prev_id,
            "target": node_id
        })
        prev_id = node_id
        y_pos += 120
    
    # If no tools, default to nmap
    if not found_tools:
        nodes.append({
            "id": "nmap_1",
            "type": "tool",
            "position": {"x": 200, "y": 180},
            "data": {"tool": "nmap", "nmap_action": "nmap_scan", "nmap_flags": "-sV", "target": target}
        })
        edges.append({"id": "e1", "source": start_id, "target": "nmap_1"})
    
    return {
        "name": f"Generated: {prompt[:40]}",
        "nodes": nodes,
        "edges": edges
    }


class GenerateRequest(BaseModel):
    prompt: str
    target: str = ""


@router.post("/generate", response_model=dict)
async def generate_workflow(
    request: GenerateRequest,
    token: dict = Depends(require_permission("scans:execute")),
):
    """Generate workflow JSON from natural language prompt."""
    wf = _generate_workflow(request.prompt, request.target)
    return wf
