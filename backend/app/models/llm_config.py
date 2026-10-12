"""
SOCIS-AI-PT — LLM Configuration Model
"""

import uuid
from datetime import datetime, timezone
from enum import Enum as PyEnum
from sqlalchemy import String, Text, Boolean, DateTime, Enum
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, JSONB

from app.core.database import Base


class LLMProvider(str, PyEnum):
    # DB-COMPATIBILITY ONLY. The `llm_provider` column is a native PostgreSQL enum that may
    # already contain this label, and removing the member would break reading old rows.
    # Never written or exposed: the startup migration (core/legacy_cleanup.py) rewrites
    # stored rows to "ollama_remote" and the API normalises the value.
    OLLAMA_LOCAL = "ollama_local"
    OLLAMA_REMOTE = "ollama_remote"
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    CUSTOM = "custom"
    OPENROUTER = "openrouter"
    GROK = "grok"
    MISTRAL = "mistral"


class LLMConfig(Base):
    __tablename__ = "llm_configs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str] = mapped_column(
        Enum(LLMProvider, name="llm_provider"), nullable=False
    )
    model_name: Mapped[str] = mapped_column(String(255), nullable=False)
    api_url: Mapped[str] = mapped_column(String(500), nullable=True)
    api_key_encrypted: Mapped[str] = mapped_column(Text, nullable=True)
    parameters: Mapped[dict] = mapped_column(JSONB, default=lambda: {
        "temperature": 0.7,
        "top_p": 0.9,
        "max_tokens": 4096,
        "top_k": 10,
    })
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    ai_analyses = relationship("AIAnalysis", back_populates="llm_config")

    def __repr__(self):
        return f"<LLMConfig {self.name} ({self.provider}/{self.model_name})>"
