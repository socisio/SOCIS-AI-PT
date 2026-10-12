"""
SOCIS-AI-PT — ChatSessionArtifact Model
Stores enterprise AI chat artifacts (pins, report queue, tasks, timeline) per session.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.core.database import Base


class ChatSessionArtifact(Base):
    __tablename__ = "chat_session_artifacts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("chat_sessions.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    pinned_message_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    report_message_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    action_tasks: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    activity_events: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    session = relationship("ChatSession", lazy="selectin")

    def __repr__(self):
        return f"<ChatSessionArtifact session={self.session_id}>"
