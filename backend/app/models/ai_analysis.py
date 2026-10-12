"""
SOCIS-AI-PT — AI Analysis Model
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Text, Float, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.core.database import Base


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    llm_config_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("llm_configs.id"), nullable=True)
    prompt: Mapped[str] = mapped_column(Text, nullable=True)
    response: Mapped[str] = mapped_column(Text, nullable=True)
    risk_level: Mapped[str] = mapped_column(String(20), nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=True)
    parsed_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    tokens_used: Mapped[float] = mapped_column(Float, nullable=True)
    duration_ms: Mapped[float] = mapped_column(Float, nullable=True)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    scan = relationship("Scan", back_populates="ai_analyses")
    llm_config = relationship("LLMConfig", back_populates="ai_analyses", lazy="selectin")

    def __repr__(self):
        return f"<AIAnalysis for scan {self.scan_id} [risk: {self.risk_level}]>"
