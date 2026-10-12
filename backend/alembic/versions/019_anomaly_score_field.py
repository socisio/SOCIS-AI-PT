"""019 anomaly score field

Revision ID: 019_anomaly_score
Revises: 018_llm_provider_expansion
Create Date: 2025-01-01 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "019_anomaly_score"
down_revision = "018_llm_provider_expansion"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "scan_tool_results",
        sa.Column("anomaly_score", sa.Float(), nullable=True),
    )


def downgrade():
    op.drop_column("scan_tool_results", "anomaly_score")
