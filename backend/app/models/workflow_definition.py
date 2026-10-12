"""
SOCIS-AI-PT — WorkflowDefinition Model
Stores user-built visual (n8n-style) workflow graphs: nodes + edges as JSONB.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.core.database import Base


class WorkflowDefinition(Base):
    __tablename__ = "workflow_definitions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)

    # Optional project scoping (None = personal/global workflow)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="SET NULL"), nullable=True
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # ReactFlow graph: list of node objects
    # Each node: {id, type, position: {x,y}, data: {tool?, provider?, model?, prompt?, ...}}
    nodes: Mapped[list] = mapped_column(JSONB, default=list)

    # ReactFlow graph: list of edge objects
    # Each edge: {id, source, target, sourceHandle?, targetHandle?}
    edges: Mapped[list] = mapped_column(JSONB, default=list)

    # Default LLM for this workflow's LLM nodes (can be overridden per-node)
    # {provider: "ollama_remote"|"openai"|"anthropic"|..., model: str, remote_url?: str}  (legacy "ollama_local" is migrated at startup)
    default_llm: Mapped[dict] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    project = relationship("Project", foreign_keys=[project_id], lazy="selectin")
    creator = relationship("User", foreign_keys=[created_by], lazy="selectin")

    def __repr__(self):
        return f"<WorkflowDefinition {self.name!r} by {self.created_by}>"
