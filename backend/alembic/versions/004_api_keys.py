"""Create api_keys table for API key authentication

Revision ID: 004_api_keys
Revises: 003_mfa_fields
Create Date: 2026-04-19 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '004_api_keys'
down_revision = '003_mfa_fields'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('key_hash', sa.String(64), nullable=False),
        sa.Column('prefix', sa.String(12), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key_hash'),
    )
    op.create_index('ix_api_keys_key_hash', 'api_keys', ['key_hash'], unique=True)
    op.create_index('ix_api_keys_user_id', 'api_keys', ['user_id'], unique=False)


def downgrade():
    op.drop_index('ix_api_keys_user_id', table_name='api_keys')
    op.drop_index('ix_api_keys_key_hash', table_name='api_keys')
    op.drop_table('api_keys')
