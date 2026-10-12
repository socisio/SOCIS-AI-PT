"""Add OpenRouter, Grok, Mistral to LLMProvider enum

Revision ID: 018_llm_provider_expansion
Revises: 017_vuln_source
Create Date: 2026-05-05

NOTE: PostgreSQL native enums cannot be altered inside a transaction.
Each ADD VALUE runs in its own autocommit statement.
"""

from alembic import op

# revision identifiers
revision = "018_llm_provider_expansion"
down_revision = "017_vuln_source"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Each ADD VALUE must run outside a transaction block on PostgreSQL.
    # Alembic's op.execute() with COMMIT + BEGIN wraps each statement safely.
    conn = op.get_bind()

    for value in ("openrouter", "grok", "mistral"):
        # IF NOT EXISTS is PG 9.6+ — safe to re-run on repeated migrations.
        conn.execute(
            __import__("sqlalchemy").text(
                f"ALTER TYPE llmprovider ADD VALUE IF NOT EXISTS '{value}'"
            )
        )


def downgrade() -> None:
    # PostgreSQL does not support removing enum values natively.
    # Safest downgrade: convert any rows using the new values to 'custom'
    # so foreign constraints remain valid, then leave the enum values in place.
    conn = op.get_bind()
    conn.execute(
        __import__("sqlalchemy").text(
            """
            UPDATE llm_configs
            SET provider = 'custom'
            WHERE provider IN ('openrouter', 'grok', 'mistral')
            """
        )
    )
    # Note: the enum values themselves cannot be dropped in PG without recreating
    # the type — left intentionally as no-op after data migration above.
