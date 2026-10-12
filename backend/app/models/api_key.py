"""
SOCIS-AI-PT — API Key Model
Hashed API keys for machine-to-machine authentication.
"""

import uuid
import hashlib
import secrets
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    prefix: Mapped[str] = mapped_column(String(12), nullable=False)  # first 12 chars for display
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    user = relationship("User", lazy="selectin")

    @staticmethod
    def generate() -> tuple[str, str]:
        """Generate a new API key. Returns (raw_key, sha256_hash).
        Only the hash is stored — the raw_key is shown to the user once.
        """
        raw = "socis_" + secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw.encode()).hexdigest()
        return raw, key_hash

    def __repr__(self):
        return f"<APIKey {self.prefix}... ({self.name})>"
