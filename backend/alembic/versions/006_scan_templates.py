"""Create scan_templates table

Revision ID: 006_scan_templates
Revises: 005_scan_schedules
Create Date: 2026-04-19 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '006_scan_templates'
down_revision = '005_scan_schedules'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'scan_templates',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('tool_config', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('is_builtin', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    op.create_index('ix_scan_templates_name', 'scan_templates', ['name'], unique=True)


def downgrade():
    op.drop_index('ix_scan_templates_name', table_name='scan_templates')
    op.drop_table('scan_templates')
