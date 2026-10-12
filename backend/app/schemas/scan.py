"""SOCIS-AI-PT — Scan Schemas"""

from typing import Optional, List, Any
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, Field, field_validator
import ipaddress
import re


class ScanCreate(BaseModel):
    project_id: UUID
    target: str = Field(min_length=3, max_length=255)
    scan_type: Optional[str] = "full"
    tool_config: Optional[dict] = None
    # Administrators only: authorize a target that is outside the project's authorized scope, with a written reason (audited).
    scope_override_reason: Optional[str] = Field(default=None, max_length=500)

    @field_validator('target')
    @classmethod
    def validate_target(cls, v):
        """Validate that target is a valid IP, hostname, or domain."""
        v = v.strip()
        
        # Try to parse as IP address
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass
        
        # Try to parse as hostname/domain
        hostname_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if re.match(hostname_pattern, v):
            return v
        
        # Allow localhost
        if v in ('localhost', '127.0.0.1', '::1'):
            return v
        
        raise ValueError('target must be a valid IP address, hostname, or domain')

    @field_validator('scan_type')
    @classmethod
    def validate_scan_type(cls, v):
        """Validate scan type."""
        allowed_types = ('full', 'quick', 'recon_only', 'vuln_scan', 'custom', 'vuln', 'web', 'workflow', 'agent')
        if v not in allowed_types:
            raise ValueError(f'scan_type must be one of: {", ".join(allowed_types)}')
        return v


class ScanAIAnalysisRunRequest(BaseModel):
    provider: Optional[str] = "ollama_remote"
    model: Optional[str] = None
    remote_url: Optional[str] = None


class ScanToolResultResponse(BaseModel):
    id: UUID
    tool_name: str
    raw_output: Optional[str]
    parsed_output: Optional[dict]
    duration_ms: Optional[int]
    exit_code: Optional[int]
    executed_at: Optional[datetime]

    model_config = {"from_attributes": True}


class AIAnalysisResponse(BaseModel):
    id: UUID
    response: Optional[str]
    risk_level: Optional[str]
    parsed_data: Optional[dict]
    duration_ms: Optional[float]
    generated_at: Optional[datetime]

    model_config = {"from_attributes": True}


class FixBriefResponse(BaseModel):
    fix_text: str
    priority: str

    model_config = {"from_attributes": True}


class VulnerabilityBriefResponse(BaseModel):
    id: UUID
    vuln_name: str
    severity: str
    port: Optional[str]
    service: Optional[str]
    description: Optional[str]
    cve_id: Optional[str]
    fixes: List["FixBriefResponse"] = []

    model_config = {"from_attributes": True}


class ScanResponse(BaseModel):
    id: UUID
    project_id: UUID
    initiated_by: UUID
    target: str
    scan_type: str
    status: str
    risk_level: Optional[str]
    tool_config: dict
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    tool_results: List[ScanToolResultResponse] = []
    ai_analyses: List[AIAnalysisResponse] = []
    vulnerabilities: List[VulnerabilityBriefResponse] = []

    model_config = {"from_attributes": True}


class ScanListItem(BaseModel):
    """One row of the scan LIST: everything the list/dashboard/notification views show, and nothing heavy.

    The full ScanResponse (used by GET /scans/{id}) embeds every tool's raw_output, every AI analysis and every
    vulnerability with its fixes. Embedding that for 20 scans on every list load and every poll made the dashboard,
    the scans page and the notification bell very slow. The list carries a vulnerability COUNT instead.
    """
    id: UUID
    project_id: UUID
    initiated_by: UUID
    target: str
    scan_type: str
    status: str
    risk_level: Optional[str]
    tool_config: dict
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    vulnerability_count: int = 0
    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    scans: List[ScanListItem]
    total: int
    page: int
    per_page: int
