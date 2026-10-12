"""
SOCIS-AI-PT — Project Model
Projects group scans and provide organizational context.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import String, Text, DateTime, ForeignKey, Enum, Boolean, text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.core.database import Base


class ProjectStatus(str, PyEnum):
    ACTIVE = "active"
    COMPLETED = "completed"
    ARCHIVED = "archived"
    PAUSED = "paused"


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    scope: Mapped[str] = mapped_column(Text, nullable=True)  # the REQUESTED scope (free text written by the project owner)
    # The AUTHORIZED allowlist (normalised entries, see core/scope.py). Only an administrator edits it. Existing projects get
    # scope_enforced = false at migration (behaviour unchanged until an admin turns it on); new projects are created enforced.
    scope_targets: Mapped[list] = mapped_column(JSONB, default=list, server_default=text("'[]'::jsonb"), nullable=False)
    scope_enforced: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("false"), nullable=False)
    status: Mapped[str] = mapped_column(
        Enum(ProjectStatus, name="project_status"),
        default=ProjectStatus.ACTIVE,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    owner = relationship("User", back_populates="projects")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan", lazy="selectin")

    def __repr__(self):
        return f"<Project {self.name}>"
