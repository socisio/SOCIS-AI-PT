"""Add vulnerability lifecycle, EPSS, dedup, OWASP/MITRE columns

Revision ID: 007_vuln_enhancements
Revises: 006_scan_templates
Create Date: 2026-04-19 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '007_vuln_enhancements'
down_revision = '006_scan_templates'
branch_labels = None
depends_on = None

VULN_STATUS = sa.Enum(
    'open', 'in_progress', 'resolved', 'accepted_risk', 'false_positive',
    name='vuln_status',
)


def upgrade():
    VULN_STATUS.create(op.get_bind(), checkfirst=True)

    op.execute("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS status vuln_status NOT NULL DEFAULT 'open'")
    op.execute("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS epss_score DOUBLE PRECISION")
    op.execute("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS epss_percentile DOUBLE PRECISION")
    op.execute("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS epss_updated_at TIMESTAMPTZ")
    op.execute("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64)")
    op.execute("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS owasp_category VARCHAR(100)")
    op.execute("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(100)")
    op.execute("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cve_description TEXT")
    op.execute("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS cve_references JSONB DEFAULT '[]'::jsonb")
    op.execute("ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ")
    op.execute("CREATE INDEX IF NOT EXISTS ix_vulnerabilities_fingerprint ON vulnerabilities (fingerprint)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_vulnerabilities_status ON vulnerabilities (status)")


def downgrade():
    op.drop_index('ix_vulnerabilities_status', table_name='vulnerabilities')
    op.drop_index('ix_vulnerabilities_fingerprint', table_name='vulnerabilities')
    op.drop_column('vulnerabilities', 'updated_at')
    op.drop_column('vulnerabilities', 'cve_references')
    op.drop_column('vulnerabilities', 'cve_description')
    op.drop_column('vulnerabilities', 'mitre_technique')
    op.drop_column('vulnerabilities', 'owasp_category')
    op.drop_column('vulnerabilities', 'fingerprint')
    op.drop_column('vulnerabilities', 'epss_updated_at')
    op.drop_column('vulnerabilities', 'epss_percentile')
    op.drop_column('vulnerabilities', 'epss_score')
    op.drop_column('vulnerabilities', 'status')
    VULN_STATUS.drop(op.get_bind(), checkfirst=True)
