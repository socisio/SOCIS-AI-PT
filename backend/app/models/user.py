"""
SOCIS-AI-PT — User, Role, and UserRole Models
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, DateTime, ForeignKey, Table, Column, JSON, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base


# Association table for many-to-many user-role relationship
user_roles_table = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=True)  # Nullable for OAuth users
    full_name: Mapped[str] = mapped_column(String(255), nullable=True)
    avatar_url: Mapped[str] = mapped_column(String(500), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False)

    # OAuth provider info
    oauth_provider: Mapped[str] = mapped_column(String(50), nullable=True)  # google, microsoft
    oauth_id: Mapped[str] = mapped_column(String(255), nullable=True)

    # MFA / TOTP
    # Stores the ENCRYPTED authenticator secret: a Fernet token for a 16-character secret is ~120 characters, so this must not be
    # a short VARCHAR (with String(64) every two-factor enrolment failed with a database error / HTTP 500).
    totp_secret: Mapped[str] = mapped_column(Text, nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    last_login: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    roles = relationship("Role", secondary=user_roles_table, back_populates="users", lazy="selectin")
    projects = relationship("Project", back_populates="owner", lazy="noload")
    # ^ was lazy="selectin": loading ANY user (login, /auth/me on every page, admin lists, assignees) then eagerly loaded
    #   every project -> scan -> vulnerability -> fix/exploit/comment -> tool_result (raw output) -> analysis -> report.
    #   Nothing in the backend reads user.projects, so it is never loaded now.
    audit_logs = relationship("AuditLog", back_populates="user", lazy="noload")
    webhooks = relationship("Webhook", back_populates="user", lazy="noload")
    notifications = relationship("Notification", back_populates="user", lazy="noload")

    def __repr__(self):
        return f"<User {self.username} ({self.email})>"


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(255), nullable=True)
    permissions: Mapped[dict] = mapped_column(JSON, default=dict)

    # Relationships
    users = relationship("User", secondary=user_roles_table, back_populates="roles", lazy="noload")

    def __repr__(self):
        return f"<Role {self.name}>"


# Re-export for convenience
UserRole = user_roles_table
