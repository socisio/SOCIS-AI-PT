"""020 plugin configs table

Revision ID: 020_plugin_configs
Revises: 019_anomaly_score
Create Date: 2026-05-05 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "020_plugin_configs"
down_revision = "019_anomaly_score"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "plugin_configs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("plugin_id", sa.String(), nullable=False, unique=True, index=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, default=False, server_default="false"),
        # Encrypted JSON blob: {"api_key_enc": "...", "url": "...", ...}
        sa.Column("config_encrypted", sa.Text(), nullable=True),
        # Non-sensitive config stored plaintext: {"project_key": "SEC", ...}
        sa.Column("config_plain", JSONB, nullable=True, server_default="{}"),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("trigger_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()"),
                  onupdate=sa.text("NOW()")),
    )


def downgrade():
    op.drop_table("plugin_configs")
