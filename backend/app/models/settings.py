"""
SOCIS-AI-PT — Settings Models
Stores platform-wide and user-specific configuration
"""

import uuid
from datetime import datetime
from sqlalchemy import String, Text, Boolean, DateTime, func, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class PlatformSettings(Base):
    """Global platform settings stored in database."""
    
    __tablename__ = "platform_settings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    # Text, not String(N): this column stores the whole tool-settings-policy JSON blob (every mcp_*_enabled switch +
    # tool_overrides), which grows every time a new MCP server is added — a fixed VARCHAR cap here has already been
    # hit once (1063 chars vs. a 1024 limit, right after Phase C's three new servers) and would keep recurring as
    # the platform grows. Postgres TEXT has no length limit and no storage penalty over varchar for this size of data.
    value: Mapped[str] = mapped_column(Text, nullable=True)
    description: Mapped[str] = mapped_column(String(512), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<PlatformSettings(key='{self.key}', value='{self.value}')>"


class UserSettings(Base):
    """User-specific settings for LLM, tools, reports, notifications, etc."""
    
    __tablename__ = "user_settings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Settings stored as JSON for flexibility
    llm_settings: Mapped[dict] = mapped_column(JSON, default=dict)
    tool_settings: Mapped[dict] = mapped_column(JSON, default=dict)
    report_settings: Mapped[dict] = mapped_column(JSON, default=dict)
    notification_settings: Mapped[dict] = mapped_column(JSON, default=dict)
    
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())

    def __repr__(self):
        return f"<UserSettings(user_id='{self.user_id}')>"
