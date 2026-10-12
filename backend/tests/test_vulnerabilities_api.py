"""Tests for the /vulnerabilities module hardening (roadmap batch 1): server-side search, the new bulk-update
endpoint's per-row access control, and CSV formula-injection neutralization. Static/structural checks plus functional
tests of the self-contained logic (CSV escaping), since the full endpoints need a live DB.

  python tests/test_vulnerabilities_api.py
"""
import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

SRC = open(os.path.join(ROOT, "app", "api", "v1", "vulnerabilities.py"), encoding="utf-8").read()

# ── server-side search ────────────────────────────────────────────────────────────────────────────────────────
t("the list endpoint accepts a `search` query param", "search: Optional[str] = Query(" in SRC)
t("search matches across name, CVE id, and OWASP category",
  "Vulnerability.vuln_name.ilike(like)" in SRC and "Vulnerability.cve_id.ilike(like)" in SRC and
  "Vulnerability.owasp_category.ilike(like)" in SRC)
t("search is parameterized (ilike bind), not string-interpolated into SQL",
  'like = f"%{search.strip()}%"' in SRC and ".ilike(like)" in SRC)
t("search filters BOTH the result query and the count query (so pagination total is correct)",
  "query = query.where(search_filter)" in SRC and "count_q = count_q.where(search_filter)" in SRC)

# ── bulk-update endpoint + per-row auth (the security-critical one) ──────────────────────────────────────────────
t("a bulk-update endpoint exists", '@router.post("/bulk-update")' in SRC)
bulk = SRC[SRC.index("async def bulk_update_vulnerabilities"):SRC.index("# ─── Vulnerability Management: unassign")]
t("bulk-update requires vulns:write permission", 'require_permission("vulns:write")' in bulk)
t("bulk-update applies the SAME per-row ownership filter as the single-row endpoints (non-admin can't touch others' vulns)",
  'if user_role != "admin":' in bulk and "query.where(Project.owner_id == user_id)" in bulk)
t("bulk-update only updates rows returned by the access-filtered query (never the raw id list)",
  "rows = (await db.execute(query)).scalars().all()" in bulk and "for vuln in rows:" in bulk)
t("bulk-update reports updated vs requested counts (so silently-skipped out-of-scope ids are visible)",
  '"updated": len(rows), "requested": len(data.ids)' in bulk)
t("bulk-update bounds the id list (no unbounded request)", "max 1000" in bulk)
t("bulk-update validates the assignee once up front", "Assigned user not found" in bulk)

# ── CSV formula injection ───────────────────────────────────────────────────────────────────────────────────────
t("the CSV export neutralizes formula-injection characters", "_csv_safe" in SRC and 'CWE-1236' in SRC)
t("every exported cell runs through the escaper", "[_csv_safe(x) for x in [" in SRC)

# functional check of the escaper logic itself (extract and run it)
m = re.search(r"def _csv_safe\(value\):.*?return s\n", SRC, re.S)
ns = {}
exec("def _csv_safe(value):\n" + m.group(0)[m.group(0).index("\n")+1:], ns)
_csv_safe = ns["_csv_safe"]
cases = {"=cmd": "'=cmd", "+1": "'+1", "-1": "'-1", "@x": "'@x", "safe": "safe",
         "CVE-2024-1": "CVE-2024-1", "": "", None: ""}
all_ok = all(_csv_safe(k) == v for k, v in cases.items())
t("escaper prefixes = + - @ (and leaves normal text, incl. CVE ids, untouched)", all_ok,
  {k: _csv_safe(k) for k, v in cases.items() if _csv_safe(k) != v})

# ── shared frontend module (dedup) ──────────────────────────────────────────────────────────────────────────────
FE = os.path.join(ROOT, "..", "frontend", "src")
t("the shared lib/vulns.ts exists", os.path.exists(os.path.join(FE, "lib", "vulns.ts")))
t("the shared VulnDetail component exists", os.path.exists(os.path.join(FE, "components", "VulnDetail.tsx")))
vulns_ts = open(os.path.join(FE, "lib", "vulns.ts"), encoding="utf-8").read()
t("shared constants use CSS variables (theme-safe), never hardcoded hex",
  not re.search(r"#[0-9a-fA-F]{3,6}\b", vulns_ts))
LIST = open(os.path.join(FE, "app", "(app)", "vulnerabilities", "page.tsx"), encoding="utf-8").read()
t("the list page no longer defines its own SEV_COLORS/STATUS_META (uses the shared source)",
  "const SEV_COLORS" not in LIST and "const STATUS_META" not in LIST)
t("the list page sends search to the server and debounces it",
  "search: search.trim() || undefined" in LIST and "setTimeout(() =>" in LIST)
t("status counts come from the aggregate metrics, not just the loaded page",
  "metricsData?.by_status?.[s.id]" in LIST)
t("bulk apply uses the single bulk endpoint, not N parallel manage() calls",
  "vulnsApi.bulkUpdate(" in LIST and "Promise.all([...selectedIds].map(id => vulnsApi.manage" not in LIST)
DETAIL = open(os.path.join(FE, "app", "(app)", "vulnerabilities", "[id]", "page.tsx"), encoding="utf-8").read()
t("the detail page delegates to the shared VulnDetail (no duplicated manage/comments logic)",
  "<VulnDetail" in DETAIL and "handleSaveManage" not in DETAIL and "handlePostComment" not in DETAIL)

# ── route ordering: static GET routes must precede /{vuln_id} or they 422 (this is why metrics was empty) ──────────
import re as _re
route_lines = [(i, ln) for i, ln in enumerate(SRC.splitlines()) if ln.startswith("@router.get(")]
def _line_of(path):
    for i, ln in enumerate(SRC.splitlines()):
        if ln.startswith("@router.get(") and f'"{path}"' in ln:
            return i
    return None
vuln_id_line = _line_of("/{vuln_id}")
metrics_line = _line_of("/metrics")
export_line = _line_of("/export")
t("GET /metrics is declared BEFORE GET /{vuln_id} (else 'metrics' is parsed as a UUID and 422s — the empty-metrics bug)",
  metrics_line is not None and vuln_id_line is not None and metrics_line < vuln_id_line,
  f"metrics@{metrics_line} vuln_id@{vuln_id_line}")
t("GET /export is declared BEFORE GET /{vuln_id} (same shadowing bug)",
  export_line is not None and vuln_id_line is not None and export_line < vuln_id_line,
  f"export@{export_line} vuln_id@{vuln_id_line}")

# ── Batch 2: visual + a11y + full dedup ──────────────────────────────────────────────────────────────────────────
t("list rows are keyboard-accessible (role=button + tabIndex + onKeyDown), not a bare clickable div",
  'role="button"' in LIST and "tabIndex={0}" in LIST and "onKeyDown={(e) =>" in LIST)
t("list shows loading skeletons (distinct from the empty state)", "sk-${i}" in LIST or "`sk-" in LIST)
t("list distinguishes load-error (with retry) from empty (with clear-filters)",
  "loadError ?" in LIST and "Retry" in LIST and "Clear filters" in LIST)
t("icon-only buttons have aria-labels", 'aria-label="Generate attack payloads"' in LIST)
t("the list page has no hardcoded rgba()/hex colors (theme-safe — both light and dark)",
  not _re.search(r"rgba\([0-9]|#[0-9a-fA-F]{6}\b", LIST))

HEATMAP = open(os.path.join(FE, "components", "VulnRiskHeatmap.tsx"), encoding="utf-8").read()
KANBAN = open(os.path.join(FE, "components", "RemediationKanban.tsx"), encoding="utf-8").read()
t("heatmap uses the shared SEV_COLORS (no local duplicate color map)",
  "SEV_COLORS" in HEATMAP and "from '@/lib/vulns'" in HEATMAP and "critical: 'var(--red)'" not in HEATMAP)
t("kanban uses the shared SEV_COLORS (no local duplicate color map)",
  "import { SEV_COLORS } from '@/lib/vulns'" in KANBAN and "const SEV_COLOR = SEV_COLORS;" in KANBAN)
t("neither visual component carries a hardcoded semantic hex color (modal scrim rgba(0,0,0) excepted)",
  not _re.search(r"#[0-9a-fA-F]{6}\b", HEATMAP) and not _re.search(r"#[0-9a-fA-F]{6}\b", KANBAN))

# ── Batch 3: left sub-nav + Direction-B redesign ─────────────────────────────────────────────────────────────────
t("the view switcher is a left <nav> sub-navigation, not the old top-right button row",
  '<nav aria-label="Vulnerability views"' in LIST and 'View switcher moved to the left' in LIST)
t("the sub-nav lists all four views with the requested labels",
  "'Vulnerability List'" in LIST and "'Heatmap'" in LIST and "'Metrics'" in LIST and "'Kanban'" in LIST)
t("the active sub-nav item is marked for accessibility (aria-current)", "aria-current={active ? 'page'" in LIST)
t("the sub-nav carries an always-visible open-by-severity mini summary", "Open by severity" in LIST)
t("Metrics is the Direction-B ops console: composite risk score + priority queue",
  "Risk score" in LIST and "Priority queue" in LIST and "riskScore" in LIST)
t("the priority queue is ranked by severity then CVSS and is clickable through to the finding",
  "(rank[b.severity] ?? 0) - (rank[a.severity] ?? 0)" in LIST and "setViewMode('list'); handleSelect(v)" in LIST)
t("the metrics view no longer depends on recharts (replaced with lightweight inline SVG)",
  "from 'recharts'" not in LIST)

HEATMAP = open(os.path.join(FE, "components", "VulnRiskHeatmap.tsx"), encoding="utf-8").read()
t("the heatmap is a density grid (severity x EPSS bands shaded by count), not a recharts scatter",
  "Risk density" in HEATMAP and "from 'recharts'" not in HEATMAP and "EPSS_ROWS" in HEATMAP and "SEV_COLS" in HEATMAP)
t("the heatmap density cells shade by finding count via color-mix (theme-safe, no hardcoded hex)",
  "color-mix(in srgb" in HEATMAP and not _re.search(r"rgba\([0-9]|#[0-9a-fA-F]{6}\b", HEATMAP))
t("the heatmap uses keyed React.Fragment rows (no key-on-shorthand-fragment bug)",
  "Fragment key={`row-" in HEATMAP)

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
