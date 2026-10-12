"""
SOCIS-AI-PT — Fix Model
"""

import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import String, Text, DateTime, ForeignKey, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class FixSource(str, PyEnum):
    AI = "ai"
    MANUAL = "manual"
    NVD = "nvd"
    VENDOR = "vendor"


class FixPriority(str, PyEnum):
    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Fix(Base):
    __tablename__ = "fixes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vuln_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False)
    fix_text: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(
        Enum(FixSource, name="fix_source"), default=FixSource.AI
    )
    priority: Mapped[str] = mapped_column(
        Enum(FixPriority, name="fix_priority"), default=FixPriority.MEDIUM
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="fixes")

    def __repr__(self):
        return f"<Fix for vuln {self.vuln_id}>"
