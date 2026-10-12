"""021 — vulnerability management fields (assignment, priority, due date, notes, tags, resolved_at)

Revision ID: 021_vuln_management_fields
Revises: 020_plugin_configs
Create Date: 2026-05-05
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "021_vuln_management_fields"
down_revision = "020_plugin_configs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # assigned_to — FK to users, nullable, SET NULL on delete
    op.add_column(
        "vulnerabilities",
        sa.Column("assigned_to", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_index("ix_vulnerabilities_assigned_to", "vulnerabilities", ["assigned_to"])

    # priority — p1 / p2 / p3 / p4 stored as VARCHAR (no DB enum — easy to extend)
    op.add_column(
        "vulnerabilities",
        sa.Column("priority", sa.String(20), nullable=True),
    )
    op.create_index("ix_vulnerabilities_priority", "vulnerabilities", ["priority"])

    # due_date — analyst-set SLA target
    op.add_column(
        "vulnerabilities",
        sa.Column("due_date", sa.DateTime(timezone=True), nullable=True),
    )

    # notes — free-text analyst notes
    op.add_column(
        "vulnerabilities",
        sa.Column("notes", sa.Text(), nullable=True),
    )

    # tags — JSONB array of string labels
    op.add_column(
        "vulnerabilities",
        sa.Column("tags", JSONB, nullable=False, server_default="[]"),
    )

    # resolved_at — set automatically when status transitions to resolved (for MTTR)
    op.add_column(
        "vulnerabilities",
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_assigned_to", "vulnerabilities")
    op.drop_index("ix_vulnerabilities_priority", "vulnerabilities")
    op.drop_column("vulnerabilities", "assigned_to")
    op.drop_column("vulnerabilities", "priority")
    op.drop_column("vulnerabilities", "due_date")
    op.drop_column("vulnerabilities", "notes")
    op.drop_column("vulnerabilities", "tags")
    op.drop_column("vulnerabilities", "resolved_at")
