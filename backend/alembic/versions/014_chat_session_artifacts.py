"""Create chat_session_artifacts table

Revision ID: 014_chat_session_artifacts
Revises: 013_workflow_scan_type_uppercase, 004_chat_sessions
Create Date: 2026-05-01 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "014_chat_session_artifacts"
down_revision = ("013_workflow_scan_type_uppercase", "004_chat_sessions")
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "chat_session_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("pinned_message_ids", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("report_message_ids", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("action_tasks", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("activity_events", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["session_id"], ["chat_sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("session_id", name="uq_chat_session_artifacts_session_id"),
    )
    op.create_index("ix_chat_session_artifacts_session_id", "chat_session_artifacts", ["session_id"])


def downgrade():
    op.drop_index("ix_chat_session_artifacts_session_id", table_name="chat_session_artifacts")
    op.drop_table("chat_session_artifacts")
