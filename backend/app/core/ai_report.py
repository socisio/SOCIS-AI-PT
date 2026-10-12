"""Turn the AI's structured analysis text into something a report can present (pure: unit-tested, no database).

The analysis is stored as the model wrote it:
    VULN: <name> | SEVERITY: HIGH | PORT: 445 | SERVICE: microsoft-ds
    DESC: ...            (may continue on following lines)
    FIX: ...             (may continue on following lines)
    ... more VULN blocks ...
    RISK_LEVEL: HIGH
    SUMMARY: ...         (may continue on following lines)
The report used to print that text raw (and cut the first 1,000 characters of it, mid-word, as the executive summary). This module
extracts the summary, the risk level and each finding with its remediation so the report can show them properly.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

_LABEL = re.compile(r"^\s*(?:[-*]\s*)?\**\s*(VULN|DESCRIPTION|DESC|FIX|REMEDIATION|RISK_LEVEL|SUMMARY)\s*\**\s*:\s*\**\s*(.*)$", re.I)
_SEV = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium", "low": "low", "info": "info", "informational": "info"}
_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _tidy(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").replace("**", "")).strip()


def _header(val: str) -> Dict:
    parts = [p.strip() for p in val.split("|")]
    f = {"name": _tidy(parts[0]), "severity": "", "severity_key": "info", "port": "", "service": "", "description": "", "fix": ""}
    for p in parts[1:]:
        k, _, v = p.partition(":")
        k, v = k.strip().lower(), _tidy(v)
        if k == "severity":
            f["severity"] = v.upper()
            f["severity_key"] = _SEV.get(v.lower(), "info")
        elif k in ("port", "service"):
            f[k] = v
    return f


def parse_ai_analysis(text: Optional[str]) -> Dict:
    """-> {parsed, risk_level, summary, findings (most severe first), preamble}. `parsed` is False for free-form text."""
    findings: List[Dict] = []
    cur: Optional[Dict] = None
    field: Optional[str] = None
    risk: Optional[str] = None
    summary: List[str] = []
    preamble: List[str] = []
    for raw in (text or "").replace("\r", "").split("\n"):
        m = _LABEL.match(raw)
        if m:
            key, val = m.group(1).upper(), m.group(2).strip()
            if key == "VULN":
                cur = _header(val); findings.append(cur); field = None
            elif key in ("DESC", "DESCRIPTION") and cur is not None:
                cur["description"] = _tidy(val); field = "description"
            elif key in ("FIX", "REMEDIATION") and cur is not None:
                cur["fix"] = _tidy(val); field = "fix"
            elif key == "RISK_LEVEL":
                risk = (_tidy(val).split() or [""])[0].upper() or None; field = None
            elif key == "SUMMARY":
                summary = [val]; field = "summary"
            continue
        if not raw.strip():
            if field == "summary":
                summary.append("")
            else:
                field = None if field in ("description", "fix") else field
            continue
        if field == "summary":
            summary.append(raw.strip())
        elif field and cur is not None:
            cur[field] = _tidy(cur[field] + " " + raw)
        elif cur is None:
            preamble.append(raw.strip())
    findings.sort(key=lambda f: _ORDER.get(f["severity_key"], 9))
    summ = "\n\n".join(_tidy(p) for p in "\n".join(summary).split("\n\n") if _tidy(p))
    return {"parsed": bool(findings or summ), "risk_level": risk, "summary": summ, "findings": findings, "preamble": _tidy(" ".join(preamble))}


def clean_excerpt(text: Optional[str], limit: int = 600) -> str:
    """A readable excerpt that ends on a sentence (or at least a word) boundary, never mid-word."""
    t = _tidy(re.sub(r"[#>`]+", " ", text or ""))
    if len(t) <= limit:
        return t
    cut = t[:limit]
    end = max(cut.rfind(". "), cut.rfind("! "), cut.rfind("? "))
    if end >= limit * 0.4:
        return cut[:end + 1]
    return cut[:cut.rfind(" ")].rstrip(",;:") + "…" if " " in cut else cut + "…"


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def fix_for(findings: List[Dict], vuln_name: str) -> str:
    """The AI's FIX text for a stored vulnerability (exact name match first, then one name containing the other)."""
    n = _norm(vuln_name)
    if not n:
        return ""
    for f in findings:
        if f.get("fix") and _norm(f["name"]) == n:
            return f["fix"]
    for f in findings:
        fn = _norm(f["name"])
        if f.get("fix") and fn and (fn in n or n in fn):
            return f["fix"]
    return ""
