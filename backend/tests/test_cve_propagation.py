"""Node-to-node CVE propagation in a graph workflow: a CVE found by one node (CVE Lookup's keyword search, or CVE Lite's
dependency scan) should flow into a LATER node that needs a CVE (CISA KEV, EPSS, PoC Search, another CVE Lookup) when
that later node's own field is left blank — the same inheritance principle already applied to the Start node, extended
node-to-node. Extracts the real logic from scan_worker.py (no DB/MCP needed) and checks it against real tool-output
shapes, not a reimplementation.

  python tests/test_cve_propagation.py
"""
import os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
P = F = 0
def t(name, ok, extra=""):
    global P, F
    if ok: P += 1; print("PASS ", name)
    else: F += 1; print("FAIL ", name, extra)

SRC = open(os.path.join(ROOT, "app", "tasks", "scan_worker.py"), encoding="utf-8").read()

# ── the real extractor, run against real output shapes from the actual MCP servers ──────────────────
i = SRC.index("_CVE_ID_RE"); j = SRC.index("def _looks_like_only_cve_list")
ns = {"_re_nmap": re}
exec(SRC[i:j], ns)
_extract_cve_ids = ns["_extract_cve_ids"]

import json
t("search_cves output (Threat Intel's keyword path): CVE IDs extracted from results[].cve_id",
  _extract_cve_ids(json.dumps({"keyword": "log4j", "total": 2, "results": [{"cve_id": "CVE-2021-44228"}, {"cve_id": "CVE-2021-45046"}]}))
  == ["CVE-2021-44228", "CVE-2021-45046"])
t("bulk lookup output: CVE IDs extracted from the cve_ids list",
  _extract_cve_ids(json.dumps({"mode": "bulk", "cve_ids": ["CVE-2023-0386", "CVE-2023-1234"]})) == ["CVE-2023-0386", "CVE-2023-1234"])
t("single lookup_cve output: the bare cve_id is extracted",
  _extract_cve_ids(json.dumps({"cve_id": "CVE-2024-3400", "severity": "CRITICAL"})) == ["CVE-2024-3400"])
t("CVE Lite findings (an EXTERNAL tool's own JSON schema we don't control): CVE IDs still found via pattern match, "
  "whatever the field name (cve, aliases, etc.)",
  set(_extract_cve_ids(json.dumps({"findings": [{"cve": "CVE-2020-8203"}, {"aliases": ["CVE-2023-45857"]}]})))
  == {"CVE-2020-8203", "CVE-2023-45857"})
t("de-duplicates and preserves first-seen order",
  _extract_cve_ids("CVE-2021-44228 ... CVE-2021-44228 ... CVE-2023-0386") == ["CVE-2021-44228", "CVE-2023-0386"])

# ── the two wiring points exist exactly once in the real worker, with the right field mapping ──────
t("the graph executor accumulates CVE IDs into a running cve_ctx (mirrors the existing nmap_ctx pattern)",
  SRC.count("cve_ctx: list[str] = []") == 1)
t("a CVE-producing node's findings are added to cve_ctx right after it runs",
  SRC.count('if tool_name in ("cve", "cve_lite"):\n                    _found = _extract_cve_ids') == 1)
t("a CVE-consuming node's blank field is filled from cve_ctx, with the correct field name per tool",
  SRC.count('cve_ctx and tool_name in ("cisa_kev", "epss", "poc_index", "cve")') == 1 and
  '{"cisa_kev": "kev_cve_id", "epss": "epss_cve_id", "poc_index": "poc_cve_id", "cve": "cve_cve_id"}' in SRC)
t("an explicit value the node already set is never overwritten (inheritance only fills BLANK fields)",
  'if not str(node_tool_config.get(_field, "")).strip():' in SRC)
t("cve_ctx is bounded so a very large dependency scan can't grow it without limit",
  "cve_ctx[:] = cve_ctx[:50]" in SRC)

# ── workflow-type review: the two input/chain mismatches are fixed in the builder ───────────────────
BUILDER = open(os.path.join(ROOT, "..", "frontend", "src", "app", "(app)", "workflows", "builder", "page.tsx"), encoding="utf-8").read()
if os.path.exists(os.path.join(ROOT, "..", "frontend")):
    t("OSINT Recon no longer invites a Company name (no OSINT action or downstream tool can use one)",
      "Company" not in BUILDER.split("workflow_type === 'osint'")[1][:400] if "workflow_type === 'osint'" in BUILDER else False)
    t("Network Scan's suggested chain no longer presents FFUF/SQLMap as an unconditional default on a bare IP",
      "add FFUF / SQLMap only if Nmap finds an HTTP" in BUILDER)

print(f"\nRESULT: {P} passed, {F} failed")
sys.exit(1 if F else 0)
