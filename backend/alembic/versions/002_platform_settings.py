"""Create platform_settings table

Revision ID: 001_platform_settings
Revises: 
Create Date: 2026-04-17 08:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '001_platform_settings'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'platform_settings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('key', sa.String(255), nullable=False),
        sa.Column('value', sa.String(1024), nullable=True),
        sa.Column('description', sa.String(512), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(), server_default=sa.func.now(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key')
    )
    op.create_index(op.f('ix_platform_settings_key'), 'platform_settings', ['key'], unique=True)


def downgrade():
    op.drop_index(op.f('ix_platform_settings_key'), table_name='platform_settings')
    op.drop_table('platform_settings')
