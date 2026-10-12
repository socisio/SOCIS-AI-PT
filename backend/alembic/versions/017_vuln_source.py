"""Add source column to vulnerabilities; ensure finding_embeddings table exists.

Revision ID: 017_vuln_source
Revises: 016_prompt_template_builtin
Create Date: 2026-05-04 00:00:00.000000

Tracks origin of each vulnerability record:
  scan_tool   – inserted directly by a scan tool (nuclei, etc.)
  ai_analysis – extracted from LLM post-analysis of scan results
  cve_tool    – backfilled from CVE intelligence tool result (cve/cisa_kev/cve_lite)

Also idempotently creates the finding_embeddings table (was skipped in some
deployment branches when migration 008 was not in the active chain).
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "017_vuln_source"
down_revision = "016_prompt_template_builtin"
branch_labels = None
depends_on = None


def upgrade():
    # ── 1. Add source column ─────────────────────────────────────────────────
    op.add_column(
        "vulnerabilities",
        sa.Column("source", sa.String(50), nullable=True),
    )

    # ── 2. Ensure finding_embeddings table exists ────────────────────────────
    # Migration 008 created this table but may not have been applied in all
    # deployment paths (it was outside the 015-merge branch).  Using raw SQL
    # with CREATE TABLE IF NOT EXISTS keeps this fully idempotent.
    conn = op.get_bind()
    conn.execute(sa.text("CREATE EXTENSION IF NOT EXISTS vector"))
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS finding_embeddings (
            id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            vuln_id     UUID NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
            content     TEXT NOT NULL,
            embedding   TEXT NOT NULL,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """))
    # Convert TEXT → vector(768) only when the column is still TEXT
    conn.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'finding_embeddings'
                  AND column_name = 'embedding'
                  AND data_type = 'text'
            ) THEN
                ALTER TABLE finding_embeddings
                    ALTER COLUMN embedding TYPE vector(768)
                    USING embedding::vector(768);
            END IF;
        END$$
    """))
    # Index — harmless if already present
    conn.execute(sa.text("""
        CREATE INDEX IF NOT EXISTS ix_finding_embeddings_ivfflat
            ON finding_embeddings
            USING ivfflat (embedding vector_cosine_ops)
            WITH (lists = 100)
    """))


def downgrade():
    op.drop_column("vulnerabilities", "source")
    # Do NOT drop finding_embeddings here — it may have been created by 008.
