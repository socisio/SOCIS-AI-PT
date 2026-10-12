"""Add 'WORKFLOW' (uppercase) value to scan_type enum

SQLAlchemy uses enum member *names* (FULL, QUICK, …) as the PostgreSQL enum
values.  The earlier migration 004_workflow_scan_type added the lowercase
'workflow' value, which SQLAlchemy cannot match.  This migration adds the
uppercase variant that SQLAlchemy actually writes.

Revision ID: 013_workflow_scan_type_uppercase
Revises: 012_workflow_definitions
Create Date: 2026-04-21 00:00:00.000000

"""
from alembic import op

revision = '013_workflow_scan_type_uppercase'
down_revision = '012_workflow_definitions'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TYPE scan_type ADD VALUE IF NOT EXISTS 'WORKFLOW'")


def downgrade():
    # PostgreSQL does not support removing enum values without recreating the type.
    pass
