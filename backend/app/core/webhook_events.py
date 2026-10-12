"""The webhook event catalog and payload shapes (pure: unit-tested without a database or network).

Before this module the webhook screen could not exist honestly: nothing in the platform ever fired a webhook except the "test ping"
button, and an event name could be anything (a typo silently never fired). Now the platform emits these events when scans finish
(see services/webhook_service.emit_scan_event) and creating a webhook with any other name is rejected.
"""
from __future__ import annotations

from typing import Dict, Iterable, List, Optional

EVENTS: Dict[str, str] = {
    "scan.completed": "A scan finished",
    "scan.failed": "A scan failed",
    "scan.cancelled": "A scan was cancelled",
    "finding.critical": "A finished scan found critical vulnerabilities",
}
ALLOWED = frozenset(EVENTS) | {"ping"}


def validate_events(events: Iterable[str]) -> List[str]:
    """Normalise (trim, lowercase, de-duplicate keeping order) and reject unknown or empty selections. Raises ValueError."""
    out: List[str] = []
    for e in events or []:
        name = str(e).strip().lower()
        if not name:
            continue
        if name not in ALLOWED:
            raise ValueError(f"Unknown event '{name}'. Choose from: {', '.join(sorted(EVENTS))}")
        if name not in out:
            out.append(name)
    if not out:
        raise ValueError("Select at least one event")
    return out


def severity_counts(rows: Iterable) -> Dict[str, int]:
    """(severity, count) rows -> {critical, high, medium, low, info, total}. Enum or string severities; unknown ones ignored."""
    c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for sev, n in rows:
        key = str(getattr(sev, "value", sev)).lower()
        if key in c:
            c[key] += int(n or 0)
    c["total"] = sum(c.values())
    return c


def build_scan_payload(*, event: str, scan_id, target: str, scan_type, project_id, status, risk_level: Optional[str],
                       started_at, completed_at, counts: Optional[Dict[str, int]] = None, error: Optional[str] = None,
                       critical: Optional[List[dict]] = None) -> dict:
    """The `data` object of a scan event. Everything is a plain string/number so it serialises without surprises."""
    s = lambda v: None if v is None else str(getattr(v, "value", v))
    d = {
        "scan_id": s(scan_id), "project_id": s(project_id), "target": target, "scan_type": s(scan_type), "status": s(status),
        "risk_level": risk_level, "started_at": s(started_at), "completed_at": s(completed_at),
    }
    if counts is not None:
        d["vulnerabilities"] = counts
    if error:
        d["error"] = str(error)[:300]            # enough to diagnose; never a full traceback
    if event == "finding.critical":
        d["critical"] = (critical or [])[:10]
    return d


def critical_items(vulns: Iterable[dict], limit: int = 10) -> List[dict]:
    """Trim critical vulnerabilities to what a receiver needs."""
    out = []
    for v in vulns:
        out.append({"name": v.get("name"), "cve_id": v.get("cve_id"), "port": v.get("port")})
        if len(out) >= limit:
            break
    return out
