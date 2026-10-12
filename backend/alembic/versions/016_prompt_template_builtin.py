"""Add is_builtin column to prompt_templates

Revision ID: 016_prompt_template_builtin
Revises: 015_schema_reconcile
Create Date: 2026-05-03 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '016_prompt_template_builtin'
down_revision = '015_schema_reconcile'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'prompt_templates',
        sa.Column('is_builtin', sa.Boolean(), server_default='false', nullable=False),
    )


def downgrade():
    op.drop_column('prompt_templates', 'is_builtin')
