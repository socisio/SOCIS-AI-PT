"""
SOCIS-AI-PT — Report Generation Service (Jinja2 + WeasyPrint + DOCX + SARIF)
Renders professional HTML/PDF/DOCX/SARIF reports.
"""

from __future__ import annotations

import asyncio
import csv
import io
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.models.scan import Scan
from app.models.report import Report
from app.models.vulnerability import Vulnerability

# Templates directory
from app.core.report_safety import only_data_image, safe_color
from app.core.tool_outcome import failure_reason, skip_reason, summarize as summarize_outcomes, tool_failed, tool_skipped
from app.core.evidence import finding_evidence, recon_note as _recon_note
from app.core.scan_coverage import coverage_note as _coverage_note
from app.core.report_export import csv_cell, md_block, md_fence, md_inline
from app.core.ai_report import clean_excerpt, fix_for, parse_ai_analysis
from app.core.nmap_ports import parse_open_ports
from sqlalchemy import inspect as sa_inspect

TEMPLATES_DIR = Path(__file__).parent.parent.parent / "templates"
REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "/app/reports"))
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Jinja2 environment
jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "xml"]),
)

RISK_COLORS = {
    "CRITICAL": "#ff3366",
    "HIGH": "#f97316",
    "MEDIUM": "#f59e0b",
    "LOW": "#22c55e",
}
RISK_PCT = {"CRITICAL": 95, "HIGH": 70, "MEDIUM": 45, "LOW": 20}

DEFAULT_REPORT_BRANDING = {
    "brand_name": "SOCIS-AI-PT",
    "brand_tagline": "AI-Powered Penetration Testing Platform",
    "brand_color": "#0ff0fc",
    "brand_logo_url": "",
    "customer_name": "",
    "customer_logo_url": "",
    "report_theme": "light",
    "report_classification": "Confidential",
}


def _count_by_severity(vulns: list) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for v in vulns:
        sev = (v.severity or "info").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


def _duration(scan: Scan) -> str:
    if scan.started_at and scan.completed_at:
        delta = scan.completed_at - scan.started_at
        minutes = int(delta.total_seconds() // 60)
        seconds = int(delta.total_seconds() % 60)
        return f"{minutes}m {seconds}s" if minutes else f"{seconds}s"
    return "—"


def _enum_value(enum_obj) -> str:
    """Extract string value from enum."""
    if enum_obj is None:
        return ""
    return str(enum_obj.value) if hasattr(enum_obj, "value") else str(enum_obj)


def _severity_key(severity) -> str:
    """Get severity key for CSS classes (lowercase)."""
    sev = (severity or "info").lower()
    return sev if sev in ["critical", "high", "medium", "low", "info"] else "info"


def _severity_label(severity) -> str:
    """Get human-readable severity label."""
    labels = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }
    sev = (severity or "info").lower()
    return labels.get(sev, "Info")


def _scan_type_label(scan_type) -> str:
    """Get human-readable scan type label."""
    scan_str = _enum_value(scan_type).lower()
    labels = {
        "reconnaissance": "Reconnaissance",
        "vulnerability_scan": "Vulnerability Scan",
        "penetration_test": "Penetration Test",
        "network_scan": "Network Scan",
        "web_scan": "Web Scan",
    }
    return labels.get(scan_str, scan_str.title())


def _risk_level_label(risk_level) -> str:
    """Get human-readable risk level label."""
    risk_str = (risk_level or "LOW").upper()
    labels = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
    }
    return labels.get(risk_str, "Unknown")


def _build_branding(default: dict, user_settings: dict, request_overrides: dict) -> dict:
    """Merge branding from default, user settings, and request overrides."""
    branding = DEFAULT_REPORT_BRANDING.copy()
    branding.update(user_settings or {})
    branding.update(request_overrides or {})
    return branding


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _clean_text(value: str) -> str:
    text = _ANSI_RE.sub("", value or "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # Keep output readable by collapsing excessive blank lines.
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _extract_tool_summary(tool_name: str, parsed_output: dict | None, raw_output: str, payload: dict | None = None) -> str:
    # The structured payload (decoded from the tool's JSON text) is what carries open_ports etc.; without it the fallback below used
    # the first line of the JSON, which is just "{".
    if isinstance(payload, dict) and isinstance(payload.get("open_ports"), list):
        return f"Open ports found: {len(_repaired_open_ports(payload))}"
    if isinstance(parsed_output, dict):
        if "waf_detected" in parsed_output:
            waf_name = parsed_output.get("waf_name") or "Unknown"
            detected = "detected" if parsed_output.get("waf_detected") else "not detected"
            return f"WAF {detected}: {waf_name}"
        if "open_ports" in parsed_output and isinstance(parsed_output.get("open_ports"), list):
            return f"Open ports found: {len(parsed_output.get('open_ports', []))}"
        if "total" in parsed_output and tool_name.lower() in {"cve", "poc_index", "cisa_kev"}:
            return f"Matches found: {parsed_output.get('total', 0)}"
        if "status" in parsed_output and isinstance(parsed_output.get("status"), str):
            return f"Status: {parsed_output.get('status')}"
    if raw_output:
        for line in raw_output.splitlines():
            first = line.strip()
            if any(ch.isalnum() for ch in first):          # skip "{", "[", "}," and blank lines
                return first[:120]
    return "No summary available"


def _extract_structured_payload(parsed_output: dict | None, raw_output: str) -> dict:
    """Best-effort extraction of structured tool payload from parsed/raw output."""
    if isinstance(parsed_output, dict):
        # Some workers store parsed result directly.
        known_keys = {
            "open_ports", "waf_detected", "waf_name", "grade", "status",
            "security_details", "ip", "host_up", "response_headers",
        }
        if known_keys.intersection(parsed_output.keys()):
            return parsed_output

        # Many workers place useful JSON payload inside "output" string.
        nested = parsed_output.get("output")
        if isinstance(nested, dict):
            return nested
        if isinstance(nested, str):
            nested_clean = _clean_text(nested)
            try:
                obj = json.loads(nested_clean)
                if isinstance(obj, dict):
                    return obj
            except Exception:
                pass

    # Raw output may be JSON.
    try:
        obj = json.loads(raw_output)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    return {}


def _repaired_open_ports(payload: dict) -> list:
    """The open ports of an nmap result. Scans stored before the port parser was fixed lost a port after any service without a version
    (the next port was swallowed into its "version"); the raw nmap text is stored with the result, so re-read it with the line-safe
    parser and use that when it finds more ports than were saved."""
    saved_obj = payload.get("open_ports")
    saved = saved_obj if isinstance(saved_obj, list) else []
    raw = payload.get("raw")
    if isinstance(raw, str) and raw.strip():
        again = parse_open_ports(raw)
        if len(again) > len(saved):
            return again
    return saved


def _build_nmap_presenter(payload: dict) -> dict:
    open_ports = _repaired_open_ports(payload)
    rows = []
    for item in open_ports:
        if isinstance(item, dict):
            rows.append({
                "port": item.get("port", "—"),
                "protocol": item.get("protocol", "—"),
                "service": item.get("service", "—"),
                "version": item.get("version", "—"),
            })
    return {
        "cards": [
            {"k": "Target", "v": str(payload.get("target", "—"))},
            {
                "k": "Host Status",
                "v": "UP" if payload.get("host_up") is True else ("DOWN" if payload.get("host_up") is False else "N/A"),
            },
            {"k": "Open Ports", "v": str(len(rows))},
        ],
        "table": {
            "columns": ["Port", "Protocol", "Service", "Version"],
            "rows": [[str(r["port"]), str(r["protocol"]), str(r["service"]), str(r["version"])] for r in rows[:100]],
        } if rows else None,
        "items": [],
    }


def _build_waf_presenter(payload: dict) -> dict:
    recs_obj = payload.get("recommendations")
    recs = recs_obj if isinstance(recs_obj, list) else []
    safe_recs = [str(r) for r in recs[:8]]
    return {
        "badge": {
            "text": "WAF Detected" if bool(payload.get("waf_detected", False)) else "No WAF Detected",
            "variant": "bad" if bool(payload.get("waf_detected", False)) else "good",
        },
        "cards": [
            {"k": "WAF Name", "v": str(payload.get("waf_name", "Unknown") or "Unknown")},
            {"k": "Confidence", "v": str(payload.get("detection_confidence", "N/A") or "N/A")},
            {"k": "Server Header", "v": str(payload.get("server_header", "N/A") or "N/A")},
        ],
        "items": safe_recs,
    }


def _build_ssl_presenter(payload: dict, normalized_text: str) -> dict:
    # Prefer structured payload if available.
    if payload:
        details_obj = payload.get("security_details")
        details = details_obj if isinstance(details_obj, dict) else {}
        return {
            "cards": [
                {"k": "Target", "v": str(payload.get("target", "—") or "—")},
                {"k": "IP", "v": str(payload.get("ip", "—") or "—")},
                {"k": "Grade", "v": str(payload.get("grade", "N/A") or "N/A")},
                {"k": "Status", "v": str(payload.get("status", "N/A") or "N/A")},
                {"k": "Protocol", "v": str(details.get("protocol", "N/A") or "N/A")},
                {"k": "Forward Secrecy", "v": str(details.get("forward_secrecy", "N/A") or "N/A")},
                {"k": "HSTS", "v": str(details.get("hsts", "N/A") or "N/A")},
                {"k": "RC4 / Ticketbleed", "v": f"{details.get('rc4', 'N/A') or 'N/A'} / {details.get('ticketbleed', 'N/A') or 'N/A'}"},
            ],
            "items": [],
        }

    # Fallback parser for text-style SSL summary.
    def _val(prefix: str) -> str:
        for line in normalized_text.splitlines():
            if line.lower().startswith(prefix.lower()):
                return line.split(":", 1)[1].strip() if ":" in line else line.strip()
        return "N/A"

    return {
        "cards": [
            {"k": "Target", "v": _val("SSL Labs Assessment for") or "—"},
            {"k": "IP", "v": _val("IP")},
            {"k": "Grade", "v": _val("Grade")},
            {"k": "Status", "v": _val("Status")},
            {"k": "Protocol", "v": _val("protocol")},
            {"k": "Forward Secrecy", "v": _val("forward secrecy")},
            {"k": "HSTS", "v": _val("hsts")},
            {"k": "RC4 / Ticketbleed", "v": f"{_val('rc4')} / {_val('ticketbleed')}"},
        ],
        "items": [],
    }


def _build_generic_presenter(tool_name: str, payload: dict, normalized_text: str) -> dict:
    cards = []
    items = []
    table = None
    used_keys = set()

    if payload:
        priority_keys = [
            "target", "status", "total", "count", "total_matches", "waf_name", "grade",
            "source", "query", "provider", "mode", "risk_label", "priority",
        ]
        for key in priority_keys:
            if key in payload and payload.get(key) not in (None, "", [], {}):
                cards.append({"k": key.replace("_", " ").title(), "v": str(payload.get(key))})
                used_keys.add(key)
            if len(cards) >= 6:
                break

        # Detect a useful list-like field and render as table or bullets.
        list_fields = ["results", "findings", "matches", "exploits", "cves", "runs", "open_ports"]
        for field in list_fields:
            value = payload.get(field)
            if isinstance(value, list) and value:
                first = value[0]
                if isinstance(first, dict):
                    cols = list(first.keys())[:6]
                    rows = []
                    for row in value[:25]:
                        if isinstance(row, dict):
                            rows.append([str(row.get(c, "—")) for c in cols])
                    table = {"columns": [c.replace("_", " ").title() for c in cols], "rows": rows}
                else:
                    items = [str(v) for v in value[:12]]
                break

    if not cards:
        cards = [{"k": "Tool", "v": tool_name.upper()}]

    if not items and not table:
        if payload:
            # Show the meaningful fields as "name: value" (long text cut, with a pointer to the JSON export). The old fallback listed the first
            # six LINES OF RAW JSON, which printed a lone "{", repeated the target and put a whole WHOIS record in as one "line".
            for k, v in payload.items():
                if k in used_keys or v in (None, "", [], {}):
                    continue
                label = str(k).replace("_", " ").title()
                if isinstance(v, (dict, list)):
                    items.append(f"{label}: {len(v)} entr{'y' if len(v) == 1 else 'ies'}")
                else:
                    sv = re.sub(r"\s+", " ", str(v)).strip()
                    items.append(f"{label}: {sv[:160]}" + (f"… ({len(sv)} characters; the full text is in the JSON export)" if len(sv) > 160 else ""))
                if len(items) >= 8:
                    break
        elif normalized_text:
            items = [line.strip()[:200] for line in normalized_text.splitlines() if line.strip()][:6]

    return {"cards": cards, "table": table, "items": items}


def _build_cve_presenter(payload: dict, normalized_text: str) -> dict:
    presenter = _build_generic_presenter("cve", payload, normalized_text)
    total = payload.get("total")
    if total is not None:
        presenter["cards"] = [{"k": "Matches", "v": str(total)}] + presenter["cards"][:5]
    return presenter


def _build_epss_presenter(payload: dict, normalized_text: str) -> dict:
    presenter = _build_generic_presenter("epss", payload, normalized_text)
    cves = payload.get("cves")
    if isinstance(cves, list) and cves and isinstance(cves[0], dict):
        cols = ["cve_id", "epss_score", "percentile", "risk_label", "priority"]
        rows = []
        for row in cves[:25]:
            rows.append([str(row.get(c, "—")) for c in cols])
        presenter["table"] = {
            "columns": ["CVE", "EPSS", "Percentile", "Risk", "Priority"],
            "rows": rows,
        }
    return presenter


def _build_masscan_presenter(payload: dict, normalized_text: str) -> dict:
    return _build_generic_presenter("masscan", payload, normalized_text)


def _build_metasploit_presenter(payload: dict, normalized_text: str) -> dict:
    presenter = _build_generic_presenter("metasploit", payload, normalized_text)
    runs = payload.get("runs")
    if isinstance(runs, list) and runs and isinstance(runs[0], dict):
        cols = ["phase", "module", "success", "session_id"]
        rows = []
        for row in runs[:25]:
            rows.append([str(row.get(c, "—")) for c in cols])
        presenter["table"] = {
            "columns": ["Phase", "Module", "Success", "Session"],
            "rows": rows,
        }
    return presenter


def _build_tool_presenter(tool_name: str, payload: dict, normalized_text: str) -> tuple[str, dict | None]:
    key = (tool_name or "").lower()

    aliases = {
        "sqlmap_full": "sqlmap",
        "whatweb": "waf",
        "testssl": "ssl",
        "whois": "osint",
        "curl_headers": "osint",
        "dig": "osint",
        "subfinder": "osint",
    }
    key = aliases.get(key, key)

    if key == "nmap":
        return key, _build_nmap_presenter(payload)
    if key in {"waf", "waf_detection"}:
        return key, _build_waf_presenter(payload)
    if key == "ssl":
        return key, _build_ssl_presenter(payload, normalized_text)
    if key == "cve":
        return key, _build_cve_presenter(payload, normalized_text)
    if key == "epss":
        return key, _build_epss_presenter(payload, normalized_text)
    if key == "metasploit":
        return key, _build_metasploit_presenter(payload, normalized_text)
    if key == "masscan":
        return key, _build_masscan_presenter(payload, normalized_text)

    # All remaining configured tools receive a normalized structured presenter.
    supported = {
        "nuclei", "osint", "ffuf", "sqlmap", "cisa_kev", "poc_index",
        "nikto", "wpscan", "jwt", "gobuster",
    }
    if key in supported:
        return key, _build_generic_presenter(key, payload, normalized_text)

    return "generic", _build_generic_presenter(key or "tool", payload, normalized_text)


def _shorten_long_strings(obj, limit: int = 800):
    """For the JSON shown in a report: a long text field (a full WHOIS record, a whole nmap transcript) is cut with an explicit note, so one tool
    cannot fill pages. The complete output is still stored and is in the JSON export."""
    if isinstance(obj, str):
        return obj if len(obj) <= limit else obj[:limit].rstrip() + f"… [{len(obj) - limit} more characters not shown]"
    if isinstance(obj, dict):
        return {k: _shorten_long_strings(v, limit) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_shorten_long_strings(v, limit) for v in obj[:200]]
    return obj


def _normalize_tool_result(tool_result) -> dict:
    parsed = tool_result.parsed_output if isinstance(tool_result.parsed_output, dict) else None
    raw = _clean_text(tool_result.raw_output or "")
    payload = _extract_structured_payload(parsed, raw)
    presenter_type, presenter_data = _build_tool_presenter(tool_result.tool_name or "", payload, raw)

    if parsed is not None:
        try:
            formatted = json.dumps(_shorten_long_strings(parsed), indent=2, ensure_ascii=False)
        except Exception:
            formatted = raw
    else:
        # Some tools return JSON in raw text without parsed_output populated.
        try:
            parsed_from_raw = json.loads(raw)
            formatted = json.dumps(_shorten_long_strings(parsed_from_raw), indent=2, ensure_ascii=False)
        except Exception:
            formatted = raw

    max_chars = 12000
    if len(formatted) > max_chars:
        formatted = formatted[:max_chars] + "\n... [truncated for report readability]"

    skipped = tool_skipped(tool_result.raw_output, parsed)
    failed = tool_failed(tool_result.raw_output, parsed, tool_result.exit_code)
    reason = skip_reason(tool_result.raw_output) if skipped else (failure_reason(tool_result.raw_output) if failed else "")
    summary = _extract_tool_summary(tool_result.tool_name or "", parsed, raw, payload)
    if skipped or failed:
        # A tool that did not produce a result gets one clear line, not a table of "N/A" cells or a JSON error object.
        presenter_type, presenter_data = None, None
        formatted = ("Skipped: " if skipped else "Did not complete: ") + (reason or "no reason given")
        summary = formatted
    return {
        "tool_name": tool_result.tool_name,
        "duration_ms": tool_result.duration_ms,
        "exit_code": (tool_result.exit_code or 1) if failed else tool_result.exit_code,
        "failed": failed,
        "skipped": skipped,
        "skip_reason": reason if skipped else "",
        "failure_reason": reason if failed else "",
        "summary": summary,
        "presenter_type": presenter_type,
        "presenter_data": presenter_data,
        "formatted_output": formatted or "No output",
    }


def _scan_open_ports(scan) -> Optional[set]:
    """Every port a port-scan tool of this scan saw open (None when the scan has no port-scan result)."""
    found = None
    for t in (scan.tool_results or []):
        parsed = t.parsed_output if isinstance(t.parsed_output, dict) else None
        payload = _extract_structured_payload(parsed, _clean_text(t.raw_output or ""))
        if isinstance(payload, dict) and isinstance(payload.get("open_ports"), list):
            ports = {int(p["port"]) for p in _repaired_open_ports(payload) if isinstance(p, dict) and str(p.get("port", "")).isdigit()}
            found = (found or set()) | ports
    return found


def _export_view(scan) -> dict:
    """What every output format shows: findings (most severe first) each with remediation and evidence, the AI summary and actions, the tool
    results as they really ended (ok / skipped / did not complete) and the assessment status. Built once so the formats cannot drift apart."""
    vulns = scan.vulnerabilities or []
    ai_analyses = scan.ai_analyses or []
    tool_results = [_normalize_tool_result(t) for t in (scan.tool_results or [])]
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns_sorted = sorted(vulns, key=lambda v: SEV_ORDER.get(v.severity or "info", 9))

    # The AI analysis is structured text (VULN:/DESC:/FIX:/RISK_LEVEL:/SUMMARY:). Parse it so every format shows a clean summary and a
    # prioritised action list instead of the raw text.
    ai_reports = []
    for a in ai_analyses:
        pr = parse_ai_analysis(a.response)
        pr["risk_level"] = pr["risk_level"] or (a.risk_level or "")
        pr["raw"] = a.response or ""
        ai_reports.append(pr)
    ai_summary = None
    if ai_analyses:
        first = ai_analyses[0]
        stored = (first.summary or "").strip()
        ai_summary = (stored if stored and "VULN:" not in stored else "") or ai_reports[0]["summary"] or clean_excerpt(first.response)
    all_ai_findings = [f for r in ai_reports for f in r["findings"]]

    open_ports = _scan_open_ports(scan)
    tool_text = " ".join((t.raw_output or "") for t in (scan.tool_results or [])).upper()
    for v in vulns_sorted:
        v.severity_key = _severity_key(v.severity)
        v.severity_label = _severity_label(v.severity)
        # Remediation: a saved fix when there is one, otherwise the AI's own FIX line for the same finding.
        saved = ""
        if "fixes" not in sa_inspect(v).unloaded:
            saved = next((f.fix_text for f in (v.fixes or []) if getattr(f, "fix_text", None)), "")
        v.remediation = saved or fix_for(all_ai_findings, v.vuln_name)
        # Facts only: was the port seen open, is each CVE the AI cited present in any tool output of this scan.
        v.evidence = finding_evidence(v.vuln_name, v.port, v.description, open_ports, tool_text)
        v.evidence_text = v.evidence["text"]
    ran_tools = [t.tool_name for t in (scan.tool_results or [])]
    return {
        "vulns": vulns_sorted, "tool_results": tool_results, "outcome": summarize_outcomes(tool_results), "ai_analyses": ai_analyses,
        "ai_reports": ai_reports, "ai_summary": ai_summary, "recon_note": _recon_note(scan.scan_type),
        "coverage_note": _coverage_note(scan.scan_type, ran_tools),
    }


def _build_context(scan: Scan, branding: dict) -> dict:
    view = _export_view(scan)
    vulns = scan.vulnerabilities or []
    vulns_sorted, tool_results, ai_analyses = view["vulns"], view["tool_results"], view["ai_analyses"]
    ai_reports, ai_summary, outcome = view["ai_reports"], view["ai_summary"], view["outcome"]
    risk_level = (scan.risk_level or "LOW").upper()
    return {
        "scan": scan,
        # A scan whose tools did not run must not read as a clean result (see core/tool_outcome.py).
        "scan_incomplete": outcome["any_failed"],
        "all_tools_failed": outcome["all_failed"],
        "tools_total": outcome["applicable"],
        "tools_skipped": outcome["skipped"],
        "skipped_reasons": outcome["skipped_reasons"],
        "recon_note": view["recon_note"],
        "coverage_note": view["coverage_note"],
        "tools_failed": outcome["failed"],
        "failure_reasons": outcome["reasons"],
        "cover_risk": "INCOMPLETE" if outcome["all_failed"] else (scan.risk_level or "N/A"),
        "cover_risk_class": "incomplete" if outcome["all_failed"] else (scan.risk_level or "low").lower(),
        "scan_type_label": _scan_type_label(scan.scan_type),
        "brand_name": branding.get("brand_name", "SOCIS-AI-PT"),
        "brand_tagline": branding.get("brand_tagline", ""),
        "brand_color": safe_color(branding.get("brand_color")),
        "brand_logo_url": only_data_image(branding.get("brand_logo_url")),
        "customer_name": branding.get("customer_name", ""),
        "customer_logo_url": only_data_image(branding.get("customer_logo_url")),
        "report_theme": branding.get("report_theme", "light"),
        "report_classification": branding.get("report_classification", "Confidential"),
        "generated_at": datetime.now(timezone.utc).strftime("%B %d, %Y"),
        "vulnerabilities": vulns_sorted,
        "vuln_counts": _count_by_severity(vulns),
        "tool_results": tool_results,
        "ai_analyses": ai_analyses,
        "ai_summary": ai_summary,
        "ai_reports": ai_reports,
        "risk_color": RISK_COLORS.get(risk_level, "#94a3b8"),
        "risk_pct": RISK_PCT.get(risk_level, 20),
        "risk_level_label": _risk_level_label(risk_level),
        "duration": _duration(scan),
    }


async def generate_html_report(
    scan: Scan,
    branding: dict = None,
) -> str:
    """Render the HTML report template and return as string."""
    if branding is None:
        branding = DEFAULT_REPORT_BRANDING
    template = jinja_env.get_template("report.html.j2")
    context = _build_context(scan, branding)
    return template.render(**context)


async def generate_pdf_report(
    scan: Scan,
    branding: dict = None,
    output_path: Optional[Path] = None,
) -> Path:
    """Render HTML → PDF via WeasyPrint. Returns the output path."""
    try:
        from weasyprint import HTML, CSS
    except ImportError:
        raise RuntimeError("WeasyPrint is not installed. Install with: pip install weasyprint")

    if branding is None:
        branding = DEFAULT_REPORT_BRANDING
    html_content = await generate_html_report(scan, branding)

    if not output_path:
        output_path = REPORTS_DIR / f"report_{scan.id}.pdf"

    # WeasyPrint rendering is CPU/IO heavy and blocks; run it in a worker thread.
    def _render_pdf() -> None:
        HTML(string=html_content, base_url=str(TEMPLATES_DIR)).write_pdf(
            str(output_path),
            optimize_images=True,
            jpeg_quality=90,
            dpi=150,
            srgb=True,
            presentational_hints=True,
        )

    await asyncio.to_thread(_render_pdf)
    return output_path


def generate_json_report(scan: Scan, branding: dict = None) -> str:
    """Serialize the full scan to structured JSON for machine-readable export."""
    if branding is None:
        branding = DEFAULT_REPORT_BRANDING
    view = _export_view(scan)
    outcome = view["outcome"]
    vulns = [
        {
            "id": str(v.id),
            "name": v.vuln_name,
            "severity": v.severity,
            "port": v.port,
            "service": v.service,
            "cve_id": v.cve_id,
            "cvss_score": v.cvss_score,
            "description": v.description,
            "remediation": v.remediation or None,
            "evidence": {k: v.evidence[k] for k in ("port_state", "cves_cited", "cves_confirmed", "cves_unconfirmed", "notes")},
            "created_at": v.created_at.isoformat() if v.created_at else None,
        }
        for v in view["vulns"]
    ]
    norm = {n["tool_name"]: n for n in view["tool_results"]}
    tool_results = [
        {
            "tool_name": t.tool_name,
            "status": "skipped" if norm[t.tool_name]["skipped"] else ("failed" if norm[t.tool_name]["failed"] else "ok"),
            "reason": norm[t.tool_name]["skip_reason"] or norm[t.tool_name]["failure_reason"] or None,
            "exit_code": t.exit_code,
            "duration_ms": t.duration_ms,
            "raw_output": t.raw_output,
        }
        for t in (scan.tool_results or [])
    ]
    ai_analyses = [
        {
            "risk_level": a.risk_level,
            "summary": a.summary or rep["summary"] or None,
            "findings": [{k: f[k] for k in ("name", "severity", "port", "service", "description", "fix")} for f in rep["findings"]],
            "response": a.response[:5000],
        }
        for a, rep in zip(view["ai_analyses"], view["ai_reports"])
    ]
    report = {
        "meta": {
            "brand": branding.get("brand_name", "SOCIS-AI-PT"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "platform": "SOCIS-AI-PT",
            "version": "1.0",
        },
        "scan": {
            "id": str(scan.id),
            "target": scan.target,
            "scan_type": _enum_value(scan.scan_type) if scan.scan_type else None,
            "status": _enum_value(scan.status) if scan.status else None,
            "risk_level": scan.risk_level,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        },
        # Machine consumers must not read "vulnerabilities": [] as "clean" when tools did not run, nor an inferred finding as a confirmed one.
        "assessment": {
            "complete": not outcome["any_failed"], "tools_total": outcome["applicable"], "tools_failed": outcome["failed"],
            "tools_skipped": outcome["skipped"], "failures": outcome["reasons"], "skipped": outcome["skipped_reasons"],
            "note": view["recon_note"] or None,
            "coverage_note": view["coverage_note"],
        },
        "summary": _count_by_severity(scan.vulnerabilities or []),
        "vulnerabilities": vulns,
        "tool_results": tool_results,
        "ai_analyses": ai_analyses,
    }
    return json.dumps(report, indent=2, default=str)


def generate_csv_report(scan: Scan, branding: dict = None) -> str:
    """Export vulnerabilities as CSV. Text cells are neutralised so a spreadsheet shows them as text and never runs them as a formula."""
    if branding is None:
        branding = DEFAULT_REPORT_BRANDING
    view = _export_view(scan)
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "ID", "Name", "Severity", "CVSS Score", "CVE ID",
        "Port", "Service", "Description", "Remediation", "Evidence", "Date Found",
    ])
    writer.writeheader()
    for v in view["vulns"]:
        writer.writerow({
            "ID": str(v.id),
            "Name": csv_cell(v.vuln_name),
            "Severity": (v.severity or "").upper(),
            "CVSS Score": v.cvss_score or "",
            "CVE ID": csv_cell(v.cve_id or ""),
            "Port": csv_cell(v.port or ""),
            "Service": csv_cell(v.service or ""),
            "Description": csv_cell(v.description or "")[:600],
            "Remediation": csv_cell(v.remediation or "")[:600],
            "Evidence": csv_cell(v.evidence_text or ""),
            "Date Found": v.created_at.strftime("%Y-%m-%d") if v.created_at else "",
        })
    return output.getvalue()


def generate_markdown_report(scan: Scan, branding: dict = None) -> str:
    """Generate a Markdown report. Text that came from the scan or the AI is escaped (table pipes, HTML, links, code fences)."""
    if branding is None:
        branding = DEFAULT_REPORT_BRANDING
    view = _export_view(scan)
    outcome = view["outcome"]
    brand_name = md_inline(branding.get("brand_name", "SOCIS-AI-PT"))
    brand_tagline = md_inline(branding.get("brand_tagline", ""))
    report_classification = md_inline(branding.get("report_classification", "Confidential"))
    customer_name = md_inline(branding.get("customer_name", ""))
    lines = []
    lines.append(f"# {brand_name} — Security Assessment Report")
    if brand_tagline:
        lines.append(f"*{brand_tagline}*\n")
    lines.append("---\n")
    lines.append(f"**Classification:** {report_classification}\n")
    lines.append(f"**Target:** {md_inline(scan.target)}")
    lines.append(f"**Report Date:** {datetime.now(timezone.utc).strftime('%B %d, %Y')}")
    lines.append(f"**Scan Type:** {md_inline(_scan_type_label(scan.scan_type))}")
    risk = "INCOMPLETE" if outcome["all_failed"] else _risk_level_label(scan.risk_level)
    lines.append(f"**Risk Level:** {risk}")
    lines.append(f"**Scan Duration:** {_duration(scan)}\n")
    if customer_name:
        lines.append(f"**Assessment Conducted For:** {customer_name}\n")

    # Executive Summary
    lines.append("## Executive Summary\n")
    if outcome["any_failed"]:
        what = "This assessment did not run." if outcome["all_failed"] else "This assessment is incomplete."
        lines.append(f"> **{what}** {outcome['failed']} of {outcome['applicable']} tool(s) did not complete, so an empty findings list is **not** evidence that the target is secure.")
        for r in outcome["reasons"]:
            lines.append(f"> - {md_inline(r)}")
        lines.append("")
    if view["recon_note"]:
        lines.append(f"> {view['recon_note']}\n")
    if view["coverage_note"]:
        lines.append(f"> {md_inline(view['coverage_note'])}\n")
    if outcome["skipped"]:
        lines.append(f"> Not applicable to this target and skipped: {md_inline('; '.join(outcome['skipped_reasons']))}\n")
    counts = _count_by_severity(scan.vulnerabilities or [])
    for label in ("critical", "high", "medium", "low", "info"):
        lines.append(f"- **{label.capitalize()}:** {counts[label]}")
    lines.append("")
    lines.append(md_block(view["ai_summary"]) if view["ai_summary"] else "No AI analysis available for this scan.")
    lines.append("")

    # Vulnerability Summary
    lines.append("## Vulnerability Summary\n")
    lines.append("| # | Vulnerability | Severity | Port / Service | CVE | CVSS |")
    lines.append("|---|---|---|---|---|---|")
    vulns_sorted = view["vulns"]
    for idx, v in enumerate(vulns_sorted, 1):
        port_service = f"{v.port}/{v.service}" if v.port and v.service else (v.port or v.service or "—")
        lines.append(f"| {idx} | {md_inline(v.vuln_name)} | {_severity_label(v.severity)} | {md_inline(port_service)} | {md_inline(v.cve_id or '—')} | {md_inline(v.cvss_score or '—')} |")
    lines.append("")

    # Detailed Findings
    lines.append("## Detailed Findings\n")
    for idx, v in enumerate(vulns_sorted, 1):
        lines.append(f"### {idx}. {md_inline(v.vuln_name)}")
        lines.append(f"**Severity:** {_severity_label(v.severity)}")
        lines.append(f"**Port:** {md_inline(v.port or '—')}")
        lines.append(f"**Service:** {md_inline(v.service or '—')}")
        if v.cve_id:
            lines.append(f"**CVE:** {md_inline(v.cve_id)}")
        if v.cvss_score:
            lines.append(f"**CVSS Score:** {md_inline(v.cvss_score)}")
        lines.append("")
        lines.append(md_block(v.description) or "No description available.")
        lines.append("")
        if v.remediation:
            lines.append(f"**Remediation:** {md_block(v.remediation)}\n")
        if v.evidence_text:
            lines.append(f"*Evidence: {md_block(v.evidence_text)}*\n")

    # Tool Output
    if view["tool_results"]:
        lines.append("## Tool Output\n")
        for tr in view["tool_results"]:
            lines.append(f"### {md_inline(tr['tool_name'])}")
            status = f"SKIPPED — {md_inline(tr['skip_reason'])}" if tr["skipped"] else (f"FAILED — {md_inline(tr['failure_reason'])}" if tr["failed"] else f"Exit code {tr['exit_code']}")
            lines.append(f"**Duration:** {tr['duration_ms']}ms | **Status:** {status}\n")
            pd = tr.get("presenter_data")
            if tr["skipped"] or tr["failed"]:
                continue
            if pd and pd.get("table") and pd["table"].get("rows"):
                for card in pd.get("cards") or []:
                    lines.append(f"- **{md_inline(card.get('k'))}:** {md_inline(card.get('v'))}")
                lines.append("")
                cols = pd["table"]["columns"]
                lines.append("| " + " | ".join(md_inline(c) for c in cols) + " |")
                lines.append("|" + "---|" * len(cols))
                for row in pd["table"]["rows"]:
                    lines.append("| " + " | ".join((md_inline(c) or "—") for c in row) + " |")
                lines.append("")
            else:
                lines.append(md_fence(tr["formatted_output"]) + "\n")

    # AI Analysis
    if view["ai_reports"]:
        lines.append("## AI Analysis & Recommendations\n")
        for rep in view["ai_reports"]:
            if rep["risk_level"]:
                lines.append(f"**Risk Level:** {md_inline(_risk_level_label(rep['risk_level']))}\n")
            if rep["parsed"]:
                if rep["summary"]:
                    lines.append(md_block(rep["summary"]) + "\n")
                if rep["findings"]:
                    lines.append("**Recommended actions, most severe first:**\n")
                    for n, f in enumerate(rep["findings"], 1):
                        where = f" (port {md_inline(f['port'])}{'/' + md_inline(f['service']) if f['service'] else ''})" if f["port"] else ""
                        lines.append(f"{n}. **{md_inline(f['severity'] or f['severity_key'].upper())}** — {md_inline(f['name'])}{where}: {md_block(f['fix'])}")
                    lines.append("")
            else:
                lines.append(md_block(rep["raw"]) + "\n")

    # Footer
    lines.append("---\n")
    lines.append(f"*Generated by {brand_name} on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*")
    lines.append(f"*Classification: {report_classification}*")
    return "\n".join(lines)


async def get_scan_with_relations(scan_id: str, db: AsyncSession) -> Optional[Scan]:
    """Fetch scan with all needed relations eager-loaded."""
    result = await db.execute(
        select(Scan)
        .where(Scan.id == scan_id)
        .options(
            selectinload(Scan.vulnerabilities).selectinload(Vulnerability.fixes),
            selectinload(Scan.tool_results),
            selectinload(Scan.ai_analyses),
        )
    )
    return result.scalar_one_or_none()


# ─── OWASP / MITRE Mapping ────────────────────────────────────

OWASP_MAPPING = {
    "sql injection": "A03:2021 – Injection",
    "xss": "A03:2021 – Injection",
    "cross-site scripting": "A03:2021 – Injection",
    "broken authentication": "A07:2021 – Identification and Authentication Failures",
    "default credentials": "A07:2021 – Identification and Authentication Failures",
    "sensitive data exposure": "A02:2021 – Cryptographic Failures",
    "ssl": "A02:2021 – Cryptographic Failures",
    "tls": "A02:2021 – Cryptographic Failures",
    "outdated": "A06:2021 – Vulnerable and Outdated Components",
    "unpatched": "A06:2021 – Vulnerable and Outdated Components",
    "misconfiguration": "A05:2021 – Security Misconfiguration",
    "directory traversal": "A01:2021 – Broken Access Control",
    "path traversal": "A01:2021 – Broken Access Control",
    "open redirect": "A01:2021 – Broken Access Control",
    "xxe": "A05:2021 – Security Misconfiguration",
    "ssrf": "A10:2021 – Server-Side Request Forgery",
    "deserialization": "A08:2021 – Software and Data Integrity Failures",
}


def map_owasp(vuln_name: str, description: str = "") -> str:
    text = (vuln_name + " " + (description or "")).lower()
    for keyword, category in OWASP_MAPPING.items():
        if keyword in text:
            return category
    return "A05:2021 – Security Misconfiguration"


# ─── DOCX Generation ─────────────────────────────────────────

async def generate_docx_report(scan: Scan, branding: dict = None) -> bytes:
    """Generate a Microsoft Word DOCX report."""
    if branding is None:
        branding = DEFAULT_REPORT_BRANDING
    try:
        from docx import Document
        from docx.shared import Pt, RGBColor
        from docx.enum.text import WD_ALIGN_PARAGRAPH
    except ImportError:
        raise RuntimeError("python-docx is not installed")

    brand_name = branding.get("brand_name", "SOCIS-AI-PT")
    doc = Document()

    # Title
    title = doc.add_heading(f"{brand_name} — Penetration Test Report", 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    # Metadata
    doc.add_paragraph(f"Target: {scan.target}   |   Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}   |   Risk: {scan.risk_level or 'N/A'}")

    # Executive Summary
    doc.add_heading("Executive Summary", 1)
    ai_analyses = scan.ai_analyses or []
    if ai_analyses:
        first = ai_analyses[0]
        summary_text = (getattr(first, "summary", None) or (first.response or "")[:2000])
        doc.add_paragraph(summary_text)
    else:
        doc.add_paragraph("No AI analysis available for this scan.")

    # Vulnerability counts
    doc.add_heading("Vulnerability Summary", 1)
    counts = _count_by_severity(scan.vulnerabilities or [])
    for sev, cnt in counts.items():
        doc.add_paragraph(f"{sev.capitalize()}: {cnt}", style="List Bullet")

    # Vulnerability Table
    doc.add_heading("Vulnerabilities", 1)
    table = doc.add_table(rows=1, cols=5)
    table.style = "Table Grid"
    hdr = table.rows[0].cells
    hdr[0].text = "Name"
    hdr[1].text = "Severity"
    hdr[2].text = "Port"
    hdr[3].text = "CVE"
    hdr[4].text = "OWASP"

    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for vuln in sorted(scan.vulnerabilities or [], key=lambda v: SEV_ORDER.get(v.severity or "info", 9)):
        row = table.add_row().cells
        row[0].text = vuln.vuln_name
        row[1].text = (vuln.severity or "").upper()
        row[2].text = vuln.port or "—"
        row[3].text = vuln.cve_id or "—"
        row[4].text = getattr(vuln, "owasp_category", None) or map_owasp(vuln.vuln_name, vuln.description or "")

    # Tool Results (truncated)
    doc.add_heading("Tool Output", 1)
    for tr in (scan.tool_results or []):
        doc.add_heading(tr.tool_name, 2)
        raw = (tr.raw_output or "No output")[:3000]
        p = doc.add_paragraph(raw)
        for run in p.runs:
            run.font.size = Pt(8)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# ─── SARIF Generation ─────────────────────────────────────────

def generate_sarif_report(scan: Scan, branding: dict = None) -> dict:
    """Generate a SARIF 2.1.0 report for consumption by security tooling."""
    if branding is None:
        branding = DEFAULT_REPORT_BRANDING
    brand_name = branding.get("brand_name", "SOCIS-AI-PT")
    rules: dict[str, dict] = {}
    results = []

    LEVEL_MAP = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}

    for vuln in (scan.vulnerabilities or []):
        rule_id = vuln.cve_id or f"SOCIS-{vuln.vuln_name[:20].upper().replace(' ', '-')}"
        level = LEVEL_MAP.get((vuln.severity or "info").lower(), "warning")

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": vuln.vuln_name,
                "shortDescription": {"text": vuln.vuln_name},
                "fullDescription": {"text": vuln.description or vuln.vuln_name},
                "defaultConfiguration": {"level": level},
                "properties": {"tags": ["security"], "cvss": vuln.cvss_score},
            }

        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": vuln.description or vuln.vuln_name},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f"network://{scan.target}:{vuln.port or '0'}"
                    }
                }
            }],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": brand_name,
                    "version": "1.0.0",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
