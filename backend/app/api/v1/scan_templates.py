"""
SOCIS-AI-PT — Scan Template Routes
CRUD for reusable scan configurations, including seeded built-in templates.
"""

import logging
import uuid
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime

from app.core.database import get_db
from app.core.security import require_permission
from app.models.scan_template import ScanTemplate

logger = logging.getLogger(__name__)
router = APIRouter()


# ─── Built-in templates seeded on startup ────────────────────

BUILTIN_TEMPLATES = [
    {
        "name": "Quick Recon",
        "description": "Fast host discovery: Nmap, WHOIS, HTTP headers, DNS lookup.",
        "tool_config": {
            "tools": ["nmap", "whois", "curl_headers", "dig"],
            "nmap_flags": "-sV -T4 --open -F",
        },
    },
    {
        "name": "Full Web Assessment",
        "description": "Comprehensive web scan: Nmap, Nuclei, OWASP ZAP baseline, WAF detection.",
        "tool_config": {
            "tools": ["nmap", "nuclei", "nikto", "waf"],
            "nmap_flags": "-sV -sC -T4 --open",
        },
    },
    {
        "name": "OSINT Only",
        "description": "Passive intelligence gathering: WHOIS, DNS, HTTP headers.",
        "tool_config": {
            "tools": ["whois", "dig", "curl_headers"],
        },
    },
    {
        "name": "Vulnerability Scan",
        "description": "Nuclei template scan with CVE enrichment.",
        "tool_config": {
            "tools": ["nuclei", "cve"],
            "nuclei_templates": "cves,exposures,vulnerabilities",
        },
    },
    {
        "name": "Full Pentest",
        "description": "All available tools — maximum coverage.",
        "tool_config": {
            "tools": ["nmap", "whois", "curl_headers", "dig", "nuclei", "nikto", "waf"],
            "nmap_flags": "-sV -sC -T4 --open -p-",
        },
    },
]


async def seed_builtin_templates(db: AsyncSession) -> None:
    """Insert built-in templates if they do not already exist."""
    for tpl in BUILTIN_TEMPLATES:
        result = await db.execute(
            select(ScanTemplate).where(ScanTemplate.name == tpl["name"])
        )
        if result.scalar_one_or_none() is None:
            db.add(ScanTemplate(
                name=tpl["name"],
                description=tpl.get("description"),
                tool_config=tpl["tool_config"],
                is_builtin=True,
            ))
    await db.commit()


# ─── Schemas ──────────────────────────────────────────────────

class ScanTemplateCreate(BaseModel):
    name: str
    description: Optional[str] = None
    tool_config: dict = {}


class ScanTemplateUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    tool_config: Optional[dict] = None


class ScanTemplateResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    tool_config: dict
    is_builtin: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Routes ───────────────────────────────────────────────────

@router.get("/", response_model=list[ScanTemplateResponse])
async def list_templates(
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ScanTemplate).order_by(ScanTemplate.is_builtin.desc(), ScanTemplate.name))
    return result.scalars().all()


@router.get("/{template_id}", response_model=ScanTemplateResponse)
async def get_template(
    template_id: UUID,
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ScanTemplate).where(ScanTemplate.id == template_id))
    template = result.scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    return template


@router.post("/", response_model=ScanTemplateResponse, status_code=201)
async def create_template(
    data: ScanTemplateCreate,
    token: dict = Depends(require_permission("scans:execute")),
    db: AsyncSession = Depends(get_db),
):
    # Prevent duplicate names
    result = await db.execute(select(ScanTemplate).where(ScanTemplate.name == data.name))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Template named {data.name!r} already exists")

    template = ScanTemplate(
        name=data.name,
        description=data.description,
        tool_config=data.tool_config,
        created_by=uuid.UUID(token["sub"]),
    )
    db.add(template)
    await db.commit()
    await db.refresh(template)
    return template


@router.patch("/{template_id}", response_model=ScanTemplateResponse)
async def update_template(
    template_id: UUID,
    data: ScanTemplateUpdate,
    token: dict = Depends(require_permission("scans:execute")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ScanTemplate).where(ScanTemplate.id == template_id))
    template = result.scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    if template.is_builtin:
        raise HTTPException(status_code=403, detail="Built-in templates cannot be modified")

    if data.name is not None:
        template.name = data.name
    if data.description is not None:
        template.description = data.description
    if data.tool_config is not None:
        template.tool_config = data.tool_config

    await db.commit()
    await db.refresh(template)
    return template


@router.delete("/{template_id}", status_code=204)
async def delete_template(
    template_id: UUID,
    token: dict = Depends(require_permission("admin:manage")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ScanTemplate).where(ScanTemplate.id == template_id))
    template = result.scalar_one_or_none()
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    if template.is_builtin:
        raise HTTPException(status_code=403, detail="Built-in templates cannot be deleted")
    await db.delete(template)
    await db.commit()
