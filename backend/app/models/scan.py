"""
SOCIS-AI-PT — Scan & ScanToolResult Models
"""

import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import Optional
from sqlalchemy import String, Text, DateTime, Integer, Float, ForeignKey, Enum, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.core.database import Base


from app.models.enums import ScanStatus, ScanType

class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("projects.id"), nullable=False)
    initiated_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    scan_type: Mapped[str] = mapped_column(
        Enum(ScanType, name="scan_type"), default=ScanType.FULL
    )
    status: Mapped[str] = mapped_column(
        Enum(ScanStatus, name="scan_status"), default=ScanStatus.PENDING
    )
    tool_config: Mapped[dict] = mapped_column(JSONB, default=dict)  # Tool selection & params
    risk_level: Mapped[str] = mapped_column(String(20), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    project = relationship("Project", back_populates="scans")
    user = relationship("User", lazy="selectin")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")
    tool_results = relationship("ScanToolResult", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")
    ai_analyses = relationship("AIAnalysis", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")

    def __repr__(self):
        return f"<Scan {self.target} [{self.status}]>"


class ScanToolResult(Base):
    __tablename__ = "scan_tool_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    raw_output: Mapped[str] = mapped_column(Text, nullable=True)
    parsed_output: Mapped[dict] = mapped_column(JSONB, nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=True)
    exit_code: Mapped[int] = mapped_column(Integer, nullable=True)
    anomaly_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan = relationship("Scan", back_populates="tool_results")

    def __repr__(self):
        return f"<ScanToolResult {self.tool_name} for scan {self.scan_id}>"
