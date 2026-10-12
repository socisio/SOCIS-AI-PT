"""Create prompt_templates table

Revision ID: 009_prompt_templates
Revises: 008_finding_embeddings
Create Date: 2026-04-19 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '009_prompt_templates'
down_revision = '008_finding_embeddings'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'prompt_templates',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('scan_type', sa.String(50), nullable=True),
        sa.Column('system_prompt', sa.Text(), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('is_default', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    op.create_index('ix_prompt_templates_scan_type', 'prompt_templates', ['scan_type', 'is_active', 'is_default'])


def downgrade():
    op.drop_index('ix_prompt_templates_scan_type', table_name='prompt_templates')
    op.drop_table('prompt_templates')
