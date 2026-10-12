"""
SOCIS-AI-PT — ScanTemplate Model
Pre-defined scan configurations (tool selections, flags) for reuse.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.core.database import Base


class ScanTemplate(Base):
    __tablename__ = "scan_templates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # tool_config mirrors Scan.tool_config (tools list, flags, etc.)
    tool_config: Mapped[dict] = mapped_column(JSONB, default=dict)
    # builtin = seeded defaults that users cannot delete
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    creator = relationship("User", lazy="selectin")

    def __repr__(self) -> str:
        return f"<ScanTemplate {self.name!r}>"
