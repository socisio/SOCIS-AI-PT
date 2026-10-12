"""
SOCIS-AI-PT — Plugin Config ORM Model
Stores per-plugin enable state and encrypted configuration.
"""

from __future__ import annotations
from datetime import datetime
from typing import Optional
from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class PluginConfig(Base):
    __tablename__ = "plugin_configs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    plugin_id: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Fernet-encrypted JSON string for sensitive fields (API keys, tokens)
    config_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # Plaintext JSONB for non-sensitive fields (project key, channel name, etc.)
    config_plain: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True, default=dict)
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    trigger_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
