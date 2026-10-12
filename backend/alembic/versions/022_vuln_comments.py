"""022 — vuln_comments table (per-vulnerability comment threads with user attribution)

Revision ID: 022_vuln_comments
Revises: 021_vuln_management_fields
Create Date: 2026-05-05
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "022_vuln_comments"
down_revision = "021_vuln_management_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vuln_comments",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "vuln_id",
            UUID(as_uuid=True),
            sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=True,
        ),
    )
    op.create_index("ix_vuln_comments_vuln_id", "vuln_comments", ["vuln_id"])
    op.create_index("ix_vuln_comments_user_id", "vuln_comments", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_vuln_comments_user_id", "vuln_comments")
    op.drop_index("ix_vuln_comments_vuln_id", "vuln_comments")
    op.drop_table("vuln_comments")
