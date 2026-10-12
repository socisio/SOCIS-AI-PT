"""
010_webhooks

Revision ID: 010_webhooks
Revises: 009_prompt_templates
Create Date: 2025-01-01 00:00:00
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, ARRAY

revision = '010_webhooks'
down_revision = '009_prompt_templates'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'webhooks',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('user_id', UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('url', sa.String(2048), nullable=False),
        sa.Column('secret', sa.String(256), nullable=True),
        sa.Column('events', ARRAY(sa.String), nullable=False, server_default='{}'),
        sa.Column('is_active', sa.Boolean, nullable=False, server_default='true'),
        sa.Column('description', sa.String(512), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('NOW()')),
    )
    op.create_index('ix_webhooks_user_id', 'webhooks', ['user_id'])


def downgrade():
    op.drop_index('ix_webhooks_user_id', table_name='webhooks')
    op.drop_table('webhooks')
