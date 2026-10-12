"""024 — vulnerabilities.source_finding_id (links a promoted vuln back to its /findings ScanToolResult)

Adds the finding→vulnerability link used by the Findings page's "promote to vulnerability" action and "tracked"
badge. Nullable FK to scan_tool_results, SET NULL on delete so a promoted vulnerability survives removal of the raw
finding it came from.

Revision ID: 024_vuln_source_finding
Revises: 023_platform_settings_value_text
Create Date: 2026-10-11
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "024_vuln_source_finding"
down_revision = "023_platform_settings_value_text"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column("source_finding_id", UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_vulnerabilities_source_finding_id",
        "vulnerabilities", "scan_tool_results",
        ["source_finding_id"], ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_vulnerabilities_source_finding_id",
        "vulnerabilities", ["source_finding_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_source_finding_id", table_name="vulnerabilities")
    op.drop_constraint("fk_vulnerabilities_source_finding_id", "vulnerabilities", type_="foreignkey")
    op.drop_column("vulnerabilities", "source_finding_id")
