"""
SOCIS-AI-PT — Report Model
"""

import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import String, DateTime, ForeignKey, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


from app.models.enums import ReportFormat, ReportStatus

class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    generated_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    format: Mapped[str] = mapped_column(
        Enum(ReportFormat, name="report_format"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        Enum(ReportStatus, name="report_status"), nullable=False, default=ReportStatus.PENDING
    )
    file_path: Mapped[str] = mapped_column(String(500), nullable=True)
    file_url: Mapped[str] = mapped_column(String(1000), nullable=True)
    file_size_bytes: Mapped[int] = mapped_column(nullable=True)
    error_message: Mapped[str] = mapped_column(String(1000), nullable=True)

    # White-label branding
    brand_name: Mapped[str] = mapped_column(String(255), nullable=True)
    brand_logo_url: Mapped[str] = mapped_column(String(500), nullable=True)

    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan = relationship("Scan", back_populates="reports")
    user = relationship("User", lazy="selectin")

    def __repr__(self):
        return f"<Report {self.format} for scan {self.scan_id}>"
