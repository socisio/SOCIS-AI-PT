"""Create scan_schedules table

Revision ID: 005_scan_schedules
Revises: 004_api_keys
Create Date: 2026-04-19 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '005_scan_schedules'
down_revision = '004_api_keys'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'scan_schedules',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('project_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('target', sa.String(500), nullable=False),
        sa.Column('cron_expression', sa.String(100), nullable=False),
        sa.Column('tool_config', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_scan_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_scan_schedules_next_run_at', 'scan_schedules', ['next_run_at'], unique=False)
    op.create_index('ix_scan_schedules_project_id', 'scan_schedules', ['project_id'], unique=False)


def downgrade():
    op.drop_index('ix_scan_schedules_project_id', table_name='scan_schedules')
    op.drop_index('ix_scan_schedules_next_run_at', table_name='scan_schedules')
    op.drop_table('scan_schedules')
