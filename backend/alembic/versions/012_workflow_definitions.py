"""
012_workflow_definitions

Revision ID: 012_workflow_definitions
Revises: 011_notifications
Create Date: 2026-04-20 00:00:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = '012_workflow_definitions'
down_revision = '011_notifications'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'workflow_definitions',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text, nullable=True),
        sa.Column('project_id', UUID(as_uuid=True), sa.ForeignKey('projects.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_by', UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('nodes', JSONB, nullable=False, server_default='[]'),
        sa.Column('edges', JSONB, nullable=False, server_default='[]'),
        sa.Column('default_llm', JSONB, nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()')),
    )
    op.create_index('ix_workflow_definitions_created_by', 'workflow_definitions', ['created_by'])
    op.create_index('ix_workflow_definitions_project_id', 'workflow_definitions', ['project_id'])
    op.create_index('ix_workflow_definitions_created_at', 'workflow_definitions', ['created_at'])


def downgrade():
    op.drop_index('ix_workflow_definitions_created_at', table_name='workflow_definitions')
    op.drop_index('ix_workflow_definitions_project_id', table_name='workflow_definitions')
    op.drop_index('ix_workflow_definitions_created_by', table_name='workflow_definitions')
    op.drop_table('workflow_definitions')
