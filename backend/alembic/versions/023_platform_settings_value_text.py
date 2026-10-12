"""023 — widen platform_settings.value from VARCHAR(1024) to TEXT

The tool-settings-policy JSON blob stored under key="tool_settings_global" grows every time a new MCP server is
added (one mcp_<name>_enabled switch per server, plus tool_overrides). Phase C's three new servers pushed the
serialized payload to 1063 chars against the old 1024-char cap, causing every "Save Global Policy" to fail with
asyncpg.exceptions.StringDataRightTruncationError. TEXT has no length limit and no storage penalty over varchar for
values this size in Postgres.

Revision ID: 023_platform_settings_value_text
Revises: 022_vuln_comments
Create Date: 2026-10-10
"""

from alembic import op
import sqlalchemy as sa

revision = "023_platform_settings_value_text"
down_revision = "022_vuln_comments"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "platform_settings",
        "value",
        existing_type=sa.String(length=1024),
        type_=sa.Text(),
        existing_nullable=True,
    )


def downgrade() -> None:
    # Reverting to VARCHAR(1024) would truncate any value saved since the upgrade that exceeds 1024 chars — those
    # rows are left as TEXT-length data Postgres will reject on the ALTER unless they're first shortened. Rather than
    # silently truncate real settings data, downgrade requires the operator to shrink any oversized rows first.
    op.alter_column(
        "platform_settings",
        "value",
        existing_type=sa.Text(),
        type_=sa.String(length=1024),
        existing_nullable=True,
    )
