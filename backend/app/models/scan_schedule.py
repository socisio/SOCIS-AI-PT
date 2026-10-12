"""
SOCIS-AI-PT — ScanSchedule Model
Recurring scan definitions driven by cron expressions.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.core.database import Base


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    # Standard cron expression, e.g. "0 3 * * 1" = every Monday at 03:00 UTC
    cron_expression: Mapped[str] = mapped_column(String(100), nullable=False)
    tool_config: Mapped[dict] = mapped_column(JSONB, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    project = relationship("Project", lazy="selectin")
    creator = relationship("User", lazy="selectin")

    def __repr__(self) -> str:
        return f"<ScanSchedule {self.name!r} cron={self.cron_expression!r}>"
