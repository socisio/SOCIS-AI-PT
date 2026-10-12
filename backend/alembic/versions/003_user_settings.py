"""Create user_settings table for storing per-user configuration

Revision ID: 002_user_settings
Revises: 001_platform_settings
Create Date: 2026-04-17 12:00:00.000000

"""
from alembic import op


def _ensure_core_schema(bind):
    # Import models so all required metadata is registered.
    from app.core.database import Base
    import app.models.user  # noqa: F401
    import app.models.project  # noqa: F401
    import app.models.scan  # noqa: F401
    import app.models.vulnerability  # noqa: F401
    import app.models.fix  # noqa: F401
    import app.models.exploit  # noqa: F401
    import app.models.report  # noqa: F401
    import app.models.ai_analysis  # noqa: F401
    import app.models.audit_log  # noqa: F401
    import app.models.llm_config  # noqa: F401
    import app.models.settings  # noqa: F401
    try:
        import app.models.finding_embedding  # noqa: F401 — needs pgvector
    except Exception:
        pass

    # Ensure foundational tables exist before later revisions that reference them.
    table_names = [
        "users",
        "roles",
        "user_roles",
        "projects",
        "llm_configs",
        "scans",
        "scan_tool_results",
        "vulnerabilities",
        "fixes",
        "exploits",
        "reports",
        "ai_analyses",
        "audit_logs",
        "user_settings",
    ]

    for table_name in table_names:
        table = Base.metadata.tables.get(table_name)
        if table is None:
            raise RuntimeError(f"Expected table metadata not found: {table_name}")
        table.create(bind=bind, checkfirst=True)

# revision identifiers, used by Alembic.
revision = '002_user_settings'
down_revision = '001_platform_settings'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    _ensure_core_schema(bind)


def downgrade():
    # Keep downgrade non-destructive for baseline migration behavior.
    pass
