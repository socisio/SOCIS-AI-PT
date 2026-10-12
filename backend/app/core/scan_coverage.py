"""Did the scan actually cover what its own type promises? (pure: unit-tested, no database)

A scan's type is just a label chosen at creation time (e.g. "full"); which tools run is driven entirely by `tool_config["tools"]`,
set by whatever created the scan (the UI, a script, the AI chat). Nothing enforces that a "full" scan's tools match what "Full Scan"
is advertised as ("Recon + Vuln Scan + AI Analysis") — a scan can be labelled Full and genuinely only run port discovery, and a
report showing just that one category's results, with no indication anything was skipped, reads as a complete assessment. This
states a fact: which of the scan type's own methodology categories never had a single tool attempt to run.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional, Tuple

# Mirrors frontend/src/app/(app)/scans/new/page.tsx: SCAN_TYPES descriptions and the tool groups shown there. Keep in step with it.
# Each entry: scan_type -> ordered [(category label, [tool names])]. A scan_type absent here (workflow, custom, agent, unknown) has
# no fixed methodology: the caller chose exactly which tools run, so there is nothing to compare against.
METHODOLOGY: Dict[str, List[Tuple[str, List[str]]]] = {
    "full": [
        ("Recon", ["nmap", "osint", "waf", "ssl"]),
        ("Vulnerability Scanning", ["nuclei", "cve", "cve_lite", "nikto"]),
        ("Threat Intelligence", ["cisa_kev", "epss", "poc_index"]),
        ("Web Attacks", ["ffuf", "sqlmap"]),
        ("Exploitation", ["metasploit"]),
    ],
    "quick": [("Port Discovery", ["nmap"])],
    # "nmap, whois, DNS, headers": WHOIS, DNS and header lookups are all actions of the single "osint" tool, not separate tool names.
    "recon_only": [("Reconnaissance", ["nmap", "osint"])],
    "vuln_scan": [("Vulnerability Scanning", ["nikto", "nuclei", "cve", "cve_lite"])],
}


def _norm(scan_type: object) -> str:
    return str(getattr(scan_type, "value", scan_type) or "").strip().lower()


def missing_categories(scan_type: object, tool_names_ran: Iterable[str]) -> List[str]:
    """Methodology categories of this scan type with NOT EVEN ONE tool attempted (ran, failed or skipped all count as attempted;
    only total absence counts as missing). Empty when the scan type has no fixed methodology, or nothing is missing."""
    plan = METHODOLOGY.get(_norm(scan_type))
    if not plan:
        return []
    ran = {str(t).strip().lower() for t in tool_names_ran}
    return [label for label, tools in plan if not (ran & {t.lower() for t in tools})]


def coverage_note(scan_type: object, tool_names_ran: Iterable[str]) -> Optional[str]:
    """A sentence naming what a reader of this report should know did not run, or None when there is nothing to add."""
    missing = missing_categories(scan_type, tool_names_ran)
    if not missing:
        return None
    label = str(scan_type).replace("_", " ").title() if not hasattr(scan_type, "value") else str(scan_type.value).replace("_", " ").title()
    return (f"This was labelled a {label} scan, but {', '.join(missing)} did not run — no tool from "
            f"{'that category' if len(missing) == 1 else 'those categories'} was attempted. Findings are limited to what the tools that did run cover.")
