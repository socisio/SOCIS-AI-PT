"""Add 'workflow' value to scan_type enum

Revision ID: 003_workflow_scan_type
Revises: 002_user_settings
Create Date: 2026-04-18 00:00:00.000000

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '003_workflow_scan_type'
down_revision = '002_user_settings'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TYPE scan_type ADD VALUE IF NOT EXISTS 'workflow'")


def downgrade():
    # PostgreSQL does not support removing enum values without recreating the type.
    pass
