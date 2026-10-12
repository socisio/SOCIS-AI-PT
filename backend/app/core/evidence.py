"""What does the scan's own tool output say about an AI-written finding? (pure: unit-tested)

The AI analysis names findings, ports and CVE ids from service banners and its own knowledge. A reader of a report needs to tell what a TOOL
saw from what the AI inferred: in one real report the AI rated SMB "CRITICAL: EternalBlue (CVE-2017-0144)" from a Recon_Only scan that never
checked for it, and cited that SMB CVE as the reason port 135 (RPC) was exploitable. This module states facts only: was the port seen open, and is
each cited CVE id present in any tool output of this scan. It does not decide whether a finding is true.
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
RECON_ONLY_NOTE = ("This was a reconnaissance-only assessment: it identifies exposed services and versions. No vulnerability check or exploitation was "
                   "run, so the findings below are inferred from service information and are not confirmed.")


def recon_note(scan_type: object) -> str:
    st = str(getattr(scan_type, "value", scan_type) or "").lower()
    return RECON_ONLY_NOTE if st == "recon_only" else ""


def cves_in(text: object) -> List[str]:
    seen: List[str] = []
    for m in _CVE.finditer(str(text or "")):
        c = m.group(0).upper()
        if c not in seen:
            seen.append(c)
    return seen


def finding_evidence(name: object, port: object, description: object, open_ports: Optional[Iterable[int]], tool_text_upper: str) -> Dict:
    """open_ports is None when no port scan result exists. tool_text_upper is every tool output of the scan, upper-cased."""
    notes: List[str] = []
    state = "unknown"
    p = str(port or "").strip()
    if p.isdigit() and open_ports is not None:
        ports = set(open_ports)
        state = "open" if int(p) in ports else "not_seen"
        notes.append(f"Port {p}/tcp was open in the port scan." if state == "open" else f"Port {p} was not seen open in the port scan.")
    cited = cves_in(f"{name} {description}")
    unconfirmed = [c for c in cited if c not in (tool_text_upper or "")]
    confirmed = [c for c in cited if c in (tool_text_upper or "")]
    for c in confirmed:
        notes.append(f"{c} also appears in this scan's tool output.")
    for c in unconfirmed:
        notes.append(f"{c} was cited by the AI and does not appear in any tool output of this scan.")
    return {"port_state": state, "cves_cited": cited, "cves_confirmed": confirmed, "cves_unconfirmed": unconfirmed, "notes": notes, "text": " ".join(notes)}
