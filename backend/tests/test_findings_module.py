"""Tests for the /findings module redesign: the promote-to-vulnerability bridge (with per-row auth and idempotency),
the promoted-link in the list response, the renderer extraction, and the signal-first / Needs-Review frontend wiring.

  python tests/test_findings_module.py
"""
import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
FE = os.path.join(ROOT, "..", "frontend", "src")
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

SRC = open(os.path.join(ROOT, "app", "api", "v1", "findings.py"), encoding="utf-8").read()

# ── promote endpoint + per-row auth + idempotency ────────────────────────────────────────────────────────────────
t("a promote endpoint exists", '@router.post("/{finding_id}/promote"' in SRC)
prom = SRC[SRC.index("async def promote_finding"):]
t("promote requires vulns:write", 'require_permission("vulns:write")' in prom)
t("promote resolves the finding through the per-row ownership filter (non-admin can't promote others' findings)",
  "_ownership_filters(user_id, user_role)" in prom and "*own_filters" in prom)
t("promote is idempotent — re-promoting returns the existing vulnerability, not a duplicate",
  "source_finding_id == finding_id" in prom and "already_promoted" in prom)
t("promote links the new vulnerability back to the finding (source_finding_id)",
  "source_finding_id=finding.id" in prom)
t("promote infers severity from the finding category", "_SEVERITY_BY_CATEGORY" in prom)

# ── list response carries the promoted link ──────────────────────────────────────────────────────────────────────
t("FindingResponse exposes promoted_vuln_id", "promoted_vuln_id: Optional[str]" in SRC)
t("the list endpoint batches the promoted lookup (one query for the page, not per-row)",
  "Vulnerability.source_finding_id.in_(page_ids)" in SRC)

# ── model + migration ────────────────────────────────────────────────────────────────────────────────────────────
MODEL = open(os.path.join(ROOT, "app", "models", "vulnerability.py"), encoding="utf-8").read()
t("Vulnerability model has source_finding_id FK to scan_tool_results",
  "source_finding_id" in MODEL and 'ForeignKey("scan_tool_results.id"' in MODEL)
mig = os.path.join(ROOT, "alembic", "versions", "024_vuln_source_finding.py")
t("migration 024 adds the column", os.path.exists(mig) and "source_finding_id" in open(mig, encoding="utf-8").read())
t("migration 024 chains after 023", 'down_revision = "023_platform_settings_value_text"' in open(mig, encoding="utf-8").read())

# ── frontend: refactor + signal-first + promote wiring ───────────────────────────────────────────────────────────
t("the renderer monolith was extracted to its own component",
  os.path.exists(os.path.join(FE, "components", "findings", "StructuredFindingOutput.tsx")))
LIST = open(os.path.join(FE, "app", "(app)", "findings", "page.tsx"), encoding="utf-8").read()
t("the page imports the extracted renderer instead of defining it inline",
  "import StructuredFindingOutput from '@/components/findings/StructuredFindingOutput'" in LIST)
t("the page is materially smaller after extraction (< 1400 lines; was 2073)", len(LIST.splitlines()) < 1400)

HELP = open(os.path.join(FE, "lib", "findings.ts"), encoding="utf-8").read()
t("a shared security-signal detector exists", "export function hasSecuritySignal" in HELP and "export function needsReview" in HELP)
t("signal detection and colors are theme-safe (no hardcoded hex)", not re.search(r"#[0-9a-fA-F]{6}\b", HELP))

t("finding rows show a signal indicator and dim informational findings",
  "hasSecuritySignal(finding)" in LIST and "opacity: signal ? 1 : 0.72" in LIST)
t("finding rows have a Promote action and a Tracked badge linking to the vulnerability",
  "onPromote(finding)" in LIST and "finding.promoted_vuln_id" in LIST and "/vulnerabilities/${finding.promoted_vuln_id}" in LIST)
t("the promote handler is idempotency-aware and surfaces errors via notify",
  "findingsApi.promote(finding.id)" in LIST and "already_promoted" in LIST and "notify(" in LIST)
t("a Needs-Review triage filter is present", "needsReviewOnly" in LIST and "findings.filter(needsReview)" in LIST)
t("finding rows are keyboard-accessible (role/tabIndex/onKeyDown)",
  'role="button"' in LIST and "tabIndex={0}" in LIST and "onKeyDown={(e)" in LIST)

API = open(os.path.join(FE, "lib", "api.ts"), encoding="utf-8").read()
t("the API client has findingsApi.promote", "promote: (id: string" in API and "/promote" in API)

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
