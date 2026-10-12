"""SOCIS-AI-PT — Report Schemas"""

from typing import Optional
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel


class ReportCreate(BaseModel):
    scan_id: UUID
    format: str = "pdf"
    brand_name: Optional[str] = None
    brand_logo_url: Optional[str] = None


class ReportResponse(BaseModel):
    id: UUID
    scan_id: UUID
    format: str
    file_url: Optional[str]
    file_size_bytes: Optional[int]
    generated_at: datetime

    model_config = {"from_attributes": True}
