"""Add pgvector extension and finding_embeddings table

Revision ID: 008_finding_embeddings
Revises: 007_vuln_enhancements
Create Date: 2026-04-19 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '008_finding_embeddings'
down_revision = '007_vuln_enhancements'
branch_labels = None
depends_on = None


def upgrade():
    # Enable pgvector extension (requires pgvector/pgvector postgres image)
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    op.create_table(
        'finding_embeddings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('vuln_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('embedding', sa.Text(), nullable=False),  # stored as vector type
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['vuln_id'], ['vulnerabilities.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    # Use raw SQL for the vector column type and its index
    op.execute(
        "ALTER TABLE finding_embeddings ALTER COLUMN embedding TYPE vector(768) USING embedding::vector(768)"
    )
    op.execute(
        "CREATE INDEX ix_finding_embeddings_ivfflat ON finding_embeddings "
        "USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100)"
    )


def downgrade():
    op.execute("DROP INDEX IF EXISTS ix_finding_embeddings_ivfflat")
    op.drop_table('finding_embeddings')
