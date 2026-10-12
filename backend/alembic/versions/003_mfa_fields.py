"""Add TOTP/MFA fields to users table

Revision ID: 003_mfa_fields
Revises: 002_user_settings
Create Date: 2026-04-19 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '003_mfa_fields'
down_revision = '002_user_settings'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(64)")
    op.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT false")


def downgrade():
    op.drop_column('users', 'totp_enabled')
    op.drop_column('users', 'totp_secret')
