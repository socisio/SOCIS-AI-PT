"""Reconcile schema coverage and merge Alembic heads.

Revision ID: 015_schema_reconcile
Revises: 003_workflow_scan_type, 014_chat_session_artifacts
Create Date: 2026-05-01 00:30:00.000000
"""

from alembic import op


revision = "015_schema_reconcile"
down_revision = (
    "003_workflow_scan_type",
    "014_chat_session_artifacts",
)
branch_labels = None
depends_on = None


def _ensure_core_tables(bind):
    # Import models so all table metadata is registered before create/check.
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
    try:
        import app.models.finding_embedding  # noqa: F401 — needs pgvector
    except Exception:
        pass

    # These tables currently exist in live DB and models, but were missing from
    # migration history. checkfirst=True keeps this safe on already-provisioned DBs.
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
    ]

    for table_name in table_names:
        table = Base.metadata.tables.get(table_name)
        if table is None:
            raise RuntimeError(f"Expected table metadata not found: {table_name}")
        table.create(bind=bind, checkfirst=True)


def upgrade():
    bind = op.get_bind()
    _ensure_core_tables(bind)


def downgrade():
    # Reconciliation/merge revision: no destructive downgrade.
    pass
