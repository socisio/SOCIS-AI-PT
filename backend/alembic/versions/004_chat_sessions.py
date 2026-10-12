"""Create chat_sessions table

Revision ID: 004_chat_sessions
Revises: 002_user_settings
Create Date: 2026-04-19 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '004_chat_sessions'
down_revision = '002_user_settings'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'chat_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('title', sa.String(255), nullable=False, server_default='New Chat'),
        sa.Column('provider', sa.String(50), nullable=False, server_default='ollama_local'),
        sa.Column('model_name', sa.String(150), nullable=True),
        sa.Column('messages', postgresql.JSONB(), nullable=False, server_default='[]'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_chat_sessions_user_id', 'chat_sessions', ['user_id'])
    op.create_index('ix_chat_sessions_updated_at', 'chat_sessions', ['updated_at'])


def downgrade():
    op.drop_index('ix_chat_sessions_updated_at', table_name='chat_sessions')
    op.drop_index('ix_chat_sessions_user_id', table_name='chat_sessions')
    op.drop_table('chat_sessions')
