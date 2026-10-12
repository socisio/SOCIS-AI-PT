"""
SOCIS-AI-PT — LLM Routes (Full Implementation)
Multi-model chat with SSE streaming, model management, and status checks.
"""

import json
import re
import uuid
import asyncio
from typing import Any, Optional, List, AsyncGenerator
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.llm_providers import normalize_provider
from app.core.database import get_db
from app.core.security import require_permission, oauth2_scheme
from app.services.llm_service import llm_service, LLMProvider
from app.services.system_prompt import build_system_prompt, build_synthesis_prompt
from app.models.llm_config import LLMConfig

router = APIRouter()


async def _get_user_llm_config(user_id: Optional[str]) -> dict[str, Any]:
    """Return persisted chat provider/model preferences for a user.

    This helper is intentionally lightweight and import-safe because
    websocket handlers call it directly.
    """
    if not user_id:
        return {"provider": "ollama_remote", "model": None, "base_url": None, "api_key": None}

    try:
        from app.core.database import async_session
        from app.services.settings_service import user_settings_service

        parsed_user_id = uuid.UUID(str(user_id))
        async with async_session() as db:
            row = await user_settings_service.get_or_create_user_settings(db, parsed_user_id)
            llm_settings = row.llm_settings or {}
            provider = normalize_provider(llm_settings.get("chat_provider"))
            model = (llm_settings.get("chat_model") or llm_settings.get("ollama_default_model") or "").strip() or None
            # No per-user Ollama URL: the endpoint is admin-only (a user-typed URL would be SSRF).
            base_url = None
            api_key = None
            if provider == "ollama_remote":
                from app.services.settings_service import settings_service
                base_url = await settings_service.get_ollama_remote_url(db)
            else:
                # Resolve the admin-saved API key/URL (Admin -> AI providers -> Add LLM Provider) for this provider —
                # previously the WebSocket chat never consulted this at all, only the .env variable.
                from app.core.llm_providers import resolve_llm_credentials
                api_key, base_url = await resolve_llm_credentials(db, provider)
            return {"provider": provider, "model": model, "base_url": base_url, "api_key": api_key}
    except Exception:
        return {"provider": "ollama_remote", "model": None, "base_url": None, "api_key": None}


# ─── Agentic Tool Dispatch ────────────────────────────────────

# Human-readable labels for each MCP server
_SERVER_LABELS: dict[str, tuple[str, str]] = {
    "cve_mcp":              ("🔎", "CVE Database (NVD)"),
    "cisa_kev_mcp":         ("🚨", "CISA KEV Catalog"),
    "epss_mcp":             ("📊", "EPSS Scoring (FIRST.org)"),
    "poc_mcp":              ("💣", "PoC Index (Sploitus/GitHub/ExploitDB)"),
    "nmap_mcp":             ("🖧",  "Network Scanner (Nmap)"),
    "nuclei_mcp":           ("⚡", "Vulnerability Scanner (Nuclei)"),
    "osint_mcp":            ("🕵️",  "OSINT Intelligence"),
    "metasploit_mcp":       ("🎯", "Metasploit Framework"),
    "waf_detection_mcp":    ("🔥", "WAF Detection & Obfuscation"),
    "ffuf_mcp":             ("📂", "Directory Fuzzer (FFUF)"),
    "sqlmap_mcp":           ("🗃️",  "SQLMap"),
    "ssl_mcp":              ("🔒", "SSL/TLS Analyzer"),
    "cve_lite_mcp":         ("📦", "CVE Lite Dependency Scanner"),
    "anomaly_mcp":          ("📈", "ML Anomaly Detection"),
    "payload_generator_mcp":("🧪", "CVE-Aware Payload Generator"),
    "nikto_mcp":            ("🌐", "Web Server Scanner (Nikto)"),
    "masscan_mcp":          ("📡", "Fast Port Scanner (Masscan)"),
    "wpscan_mcp":           ("🔑", "WordPress Scanner (WPScan)"),
    "jwt_mcp":              ("🪙", "JWT Security Tester"),
    "gobuster_mcp":         ("💨", "Directory Brute-Forcer (Gobuster)"),
    "mitre_mcp":            ("🛡️", "MITRE ATT&CK Framework"),
    "exploitdb_mcp":        ("📚", "Exploit-DB Intelligence"),
}

_MCP_SETTING_TO_SERVER: dict[str, str] = {
    "mcp_nmap_enabled": "nmap_mcp",
    "mcp_nuclei_enabled": "nuclei_mcp",
    "mcp_cve_enabled": "cve_mcp",
    "mcp_osint_enabled": "osint_mcp",
    "mcp_metasploit_enabled": "metasploit_mcp",
    "mcp_waf_detection_enabled": "waf_detection_mcp",
    "mcp_ffuf_enabled": "ffuf_mcp",
    "mcp_sqlmap_enabled": "sqlmap_mcp",
    "mcp_ssl_enabled": "ssl_mcp",
    "mcp_cisa_kev_enabled": "cisa_kev_mcp",
    "mcp_epss_enabled": "epss_mcp",
    "mcp_poc_enabled": "poc_mcp",
    "mcp_nikto_enabled": "nikto_mcp",
    "mcp_masscan_enabled": "masscan_mcp",
    "mcp_wpscan_enabled": "wpscan_mcp",
    "mcp_jwt_enabled": "jwt_mcp",
    "mcp_gobuster_enabled": "gobuster_mcp",
    "mcp_cve_lite_enabled": "cve_lite_mcp",
    "mcp_anomaly_enabled": "anomaly_mcp",
    "mcp_payload_generator_enabled": "payload_generator_mcp",
    "mcp_mitre_enabled": "mitre_mcp",
    "mcp_exploitdb_enabled": "exploitdb_mcp",
    "mcp_ad_enabled": "ad_mcp",
    "mcp_cloud_enabled": "cloud_mcp",
    "mcp_container_enabled": "container_mcp",
    "mcp_api_security_enabled": "api_security_mcp",
    "mcp_secrets_enabled": "secrets_mcp",
    "mcp_dns_deep_enabled": "dns_deep_mcp",
    "mcp_crack_enabled": "crack_mcp",
    "mcp_compliance_enabled": "compliance_mcp",
}


def _deduplicate_report(text: str) -> str:
    """
    Remove duplicate lines produced when a model builds a list cumulatively
    (e.g. outputs ◆A, then ◆A ◆B, then ◆A ◆B ◆C instead of just ◆A ◆B ◆C).
    Preserves blank lines but collapses consecutive blank lines to one.
    """
    lines = text.split("\n")
    seen: set[str] = set()
    result: list[str] = []
    prev_blank = False
    for line in lines:
        stripped = line.strip()
        if not stripped:
            if not prev_blank:
                result.append("")
            prev_blank = True
            continue
        prev_blank = False
        if stripped in seen:
            continue
        seen.add(stripped)
        result.append(line)
    return "\n".join(result)


def _iter_unique_tag_values(pattern: str, text: str) -> list[str]:
    """Extract unique tag payloads while preserving first-seen order."""
    seen: set[str] = set()
    ordered: list[str] = []
    for match in re.finditer(pattern, text, re.IGNORECASE):
        value = (match.group(1) or "").strip()
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(value)
    return ordered


def _build_tool_fallback_report(tool_results: list[dict], user_query: str = "") -> str:
    """Render a deterministic final report if LLM synthesis output is empty."""
    cve_report = _build_cve_report_from_tool_results(tool_results)
    if cve_report:
        return cve_report

    lines = ["### Findings", "", "Live intelligence was collected successfully."]
    if user_query.strip():
        lines.extend(["", f"Query: {user_query.strip()}"])

    for idx, tr in enumerate(tool_results, start=1):
        tag = tr.get("tag", f"TOOL-{idx}")
        output = str(tr.get("output", "")).strip()
        snippet = output[:1500].strip() if output else "No data returned."
        lines.extend(["", f"{idx}. {tag}", snippet])

    lines.extend([
        "",
        "### Next Steps",
        "- Re-run the same query to verify consistency.",
        "- If you need a stricter report format, ask for CVSS/KEV/EPSS-only output.",
    ])
    return "\n".join(lines).strip()


def _extract_section_map(text: str) -> dict[str, str]:
    sections: dict[str, str] = {}
    pattern = re.compile(r"---\s*(.+?)\s*---\n(.*?)(?=\n---\s*.+?\s*---\n|\Z)", re.DOTALL)
    for m in pattern.finditer(text or ""):
        sections[m.group(1).strip()] = m.group(2).strip()
    return sections


def _parse_json_block(text: str) -> Optional[dict[str, Any]]:
    if not text:
        return None
    start = text.find("{")
    if start == -1:
        return None
    decoder = json.JSONDecoder()
    try:
        obj, _ = decoder.raw_decode(text[start:])
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _first_url(text: str) -> Optional[str]:
    m = re.search(r"https?://\S+", text or "")
    return m.group(0).rstrip(").,]") if m else None


def _reference_label(url: str) -> str:
    u = (url or "").lower()
    if "packetstormsecurity.com" in u:
        return "Packetstorm Security Advisory"
    if "nvd.nist.gov" in u:
        return "NVD Detail"
    if "cisa.gov" in u:
        return "CISA KEV Catalog"
    if "openwall.com" in u:
        return "Openwall OSS-Security"
    if "vmware.com" in u:
        return "VMware Security Advisory"
    if "apache.org" in u:
        return "Apache Security Advisory"
    if "github.com" in u:
        return "GitHub PoC Reference"
    m = re.search(r"https?://([^/]+)", url or "")
    return m.group(1) if m else "Security Reference"


def _extract_cve_reference_labels(tool_results: list[dict], max_items: int = 10) -> list[str]:
    """Return deduplicated, human-friendly reference labels for CVE tool output."""
    cve_result = next((tr for tr in tool_results if str(tr.get("tag", "")).startswith("SEARCH: CVE-")), None)
    if not cve_result:
        return []

    sections = _extract_section_map(str(cve_result.get("output", "")))
    cve_json = _parse_json_block(sections.get("CVE Details (NVD)", "") or "") or {}
    raw_refs = cve_json.get("references")
    refs: list = raw_refs if isinstance(raw_refs, list) else []

    labels: list[str] = []
    for r in refs[: max_items * 2]:
        if not isinstance(r, str):
            continue
        label = _reference_label(r)
        if label not in labels:
            labels.append(label)
        if len(labels) >= max_items:
            break

    if not labels:
        kev_text = sections.get("CISA KEV Status", "")
        epss_text = sections.get("EPSS Score", "")
        poc_text = sections.get("PoC Risk Assessment", "")
        maybe_ref = _first_url(kev_text) or _first_url(epss_text) or _first_url(poc_text)
        if maybe_ref:
            labels = [_reference_label(maybe_ref)]

    return labels[:max_items]


def _replace_references_section(text: str, ref_labels: list[str]) -> str:
    """Replace the References section body with canonical deduplicated labels."""
    if not text or not ref_labels:
        return text

    lines = text.splitlines()
    ref_idx = -1
    for i, line in enumerate(lines):
        normalized = line.strip().lower()
        if normalized == "references" or re.fullmatch(r"#{1,6}\s*references", normalized):
            ref_idx = i
            break
    if ref_idx == -1:
        return text

    prefix = lines[: ref_idx + 1]
    new_body = [""] + [f"    ◆{label}" for label in ref_labels]
    return "\n".join(prefix + new_body).strip()


def _normalize_references_section(text: str, fallback_labels: Optional[list[str]] = None) -> str:
    """Normalize and deduplicate the References section from model output.

    This is resilient when the model emits bare domains/URLs repeatedly.
    """
    if not text:
        return text

    lines = text.splitlines()
    ref_idx = -1
    for i, line in enumerate(lines):
        normalized = line.strip().lower()
        if normalized == "references" or re.fullmatch(r"#{1,6}\s*references", normalized):
            ref_idx = i
            break
    if ref_idx == -1:
        return text

    before = lines[: ref_idx + 1]
    after = lines[ref_idx + 1 :]

    labels: list[str] = []
    seen: set[str] = set()

    for raw in after:
        s = raw.strip()
        if not s:
            continue
        # Skip decorative separators.
        if set(s) <= {"=", "-", "*"}:
            continue

        # Try URL first.
        url_match = re.search(r"https?://[^\s)]+", s, re.IGNORECASE)
        if url_match:
            label = _reference_label(url_match.group(0))
        else:
            # Try domain-only lines like packetstormsecurity.com.
            host_match = re.search(r"\b([a-z0-9.-]+\.[a-z]{2,})\b", s, re.IGNORECASE)
            if host_match:
                label = _reference_label(f"https://{host_match.group(1)}")
            else:
                # Keep meaningful descriptive labels as-is.
                cleaned = re.sub(r"^[\-•◆*\s]+", "", s).strip()
                label = cleaned

        key = label.lower()
        if key in seen:
            continue
        seen.add(key)
        labels.append(label)
        if len(labels) >= 10:
            break

    if not labels and fallback_labels:
        for item in fallback_labels:
            key = item.lower()
            if key in seen:
                continue
            seen.add(key)
            labels.append(item)
            if len(labels) >= 10:
                break

    if not labels:
        return text

    normalized_section = [""] + [f"    ◆{label}" for label in labels]
    return "\n".join(before + normalized_section).strip()


def _build_cve_report_from_tool_results(tool_results: list[dict]) -> Optional[str]:
    cve_result = next((tr for tr in tool_results if str(tr.get("tag", "")).startswith("SEARCH: CVE-")), None)
    if not cve_result:
        return None

    sections = _extract_section_map(str(cve_result.get("output", "")))
    cve_json = _parse_json_block(sections.get("CVE Details (NVD)", "") or "") or {}

    cve_id = str(cve_json.get("cve_id") or str(cve_result.get("tag", "")).replace("SEARCH:", "").strip() or "Unknown CVE")
    severity = str(cve_json.get("severity") or "Not available")
    cvss = cve_json.get("cvss_score", "Not available")
    epss_text = sections.get("EPSS Score", "Not available in current data")
    kev_text = sections.get("CISA KEV Status", "Not available in current data")
    poc_text = sections.get("PoC Risk Assessment", "Not available in current data")
    description = str(cve_json.get("description") or "Not available in current data")
    attack_vector = str(cve_json.get("attack_vector") or "Not available")
    cvss_vector = str(cve_json.get("cvss_vector") or "Not available")

    raw_refs = cve_json.get("references")
    refs: list = raw_refs if isinstance(raw_refs, list) else []

    ref_items: list[tuple[str, str]] = []
    seen_ref_urls: set[str] = set()
    seen_ref_labels: set[str] = set()
    for r in refs[:30]:
        if not isinstance(r, str):
            continue
        url = r.strip()
        if not url:
            continue
        key = url.lower()
        if key in seen_ref_urls:
            continue
        seen_ref_urls.add(key)
        label = _reference_label(url)
        # Keep one entry per label to avoid repeated Packetstorm lines.
        if label.lower() in seen_ref_labels:
            continue
        seen_ref_labels.add(label.lower())
        ref_items.append((label, url))
        if len(ref_items) >= 10:
            break
    if not ref_items:
        maybe_ref = _first_url(kev_text) or _first_url(epss_text) or _first_url(poc_text)
        if maybe_ref:
            ref_items = [(_reference_label(maybe_ref), maybe_ref)]

    # Parse KEV JSON
    kev_json = _parse_json_block(kev_text) or {}
    if kev_json.get("in_kev") is True:
        kev_status = "yes"
    elif kev_json.get("in_kev") is False:
        kev_status = "no"
    else:
        kev_status = "Not available"

    # Parse EPSS JSON
    epss_json = _parse_json_block(epss_text) or {}
    epss_score = str(epss_json.get("epss_score_pct") or "Not available")

    # Parse PoC JSON
    poc_json = _parse_json_block(poc_text) or {}
    exploit_db_count = poc_json.get("exploitdb_count", "n")
    github_poc_count = poc_json.get("github_poc_repos", "n")
    difficulty = str(poc_json.get("exploitation_difficulty") or "Not available")
    top_exploits = poc_json.get("top_exploits") or []
    top_github = poc_json.get("top_github_pocs") or []

    # CWE lines
    cwes = cve_json.get("cwes") or []
    cwe_list = [str(c) for c in cwes[:6]] if cwes else []

    # Affected products
    affected = cve_json.get("affected_products") or []
    affected_rows: list[str] = []
    for prod in affected:
        if isinstance(prod, dict):
            vendor = str(prod.get("vendor", "")).strip()
            product = str(prod.get("product", "")).strip()
            versions = str(prod.get("versions", "")).strip()
            row = f"{vendor} {product}".strip()
            if versions:
                row = f"{row} ({versions})".strip()
            if row:
                affected_rows.append(row)
        elif isinstance(prod, str) and prod.strip():
            affected_rows.append(prod.strip())

    # Prefer rows relevant to the vulnerability family (e.g. log4j for Log4Shell)
    preferred = [r for r in affected_rows if any(k in r.lower() for k in ["log4j", "apache"])]
    selected_affected = preferred[:6] if preferred else affected_rows[:6]

    mitigation_links = cve_json.get("patch_references") or []
    patch_refs = [u for u in mitigation_links if isinstance(u, str) and u.strip()][:3]

    lines: list[str] = [
        f"# {cve_id}",
        "",
        f"**SEVERITY:** {severity} | **CVSS:** {cvss}",
        "",
        "## Executive Summary",
        description,
        "",
        "## Technical Details",
        f"- **Attack Vector:** {attack_vector}",
        f"- **CVSS Vector:** {cvss_vector}",
        f"- **CWE:** {', '.join(cwe_list) if cwe_list else 'Not available'}",
        "",
        "## Exploitation Intelligence",
        f"- **KEV Status:** {kev_status}",
        f"- **EPSS Score:** {epss_score}",
        f"- **Exploitation Difficulty:** {difficulty}",
        f"- **PoC Count:** ExploitDB {exploit_db_count} | GitHub {github_poc_count}",
    ]

    if top_exploits:
        lines.extend(["", "### Top Exploits"])
        for ex in top_exploits[:3]:
            if isinstance(ex, dict):
                edb = ex.get("edb_id", "N/A")
                title = ex.get("title", "Exploit")
                date = ex.get("date", "N/A")
                lines.append(f"- **{edb}**: {title} ({date})")

    if top_github:
        lines.extend(["", "### Top GitHub PoCs"])
        for gh in top_github[:3]:
            if isinstance(gh, dict):
                repo = gh.get("repo", "repo")
                stars = gh.get("stars", 0)
                url = gh.get("url") or ""
                if isinstance(url, str) and url.startswith("http"):
                    lines.append(f"- [{repo}]({url}) — ⭐ {stars}")
                else:
                    lines.append(f"- {repo} — ⭐ {stars}")

    if selected_affected:
        lines.extend(["", "## Affected Systems"])
        for row in selected_affected:
            lines.append(f"- {row}")

    lines.extend(["", "## Mitigation"])
    lines.append("- Patch affected systems immediately to vendor-fixed versions.")
    lines.append("- Prioritize internet-facing and business-critical systems first.")
    if patch_refs:
        lines.append("- Official patch references:")
        for url in patch_refs:
            lines.append(f"  - [{_reference_label(url)}]({url})")

    lines.extend(["", "## References"])
    if ref_items:
        for label, url in ref_items[:10]:
            lines.append(f"- [{label}]({url})")
    else:
        lines.append("- Not available in current data")

    return "\n".join(lines).strip()


def _build_process_block(response: str) -> str:
    """
    Build a visible markdown block showing which tools the AI decided to call
    and why, so the user can see the reasoning process before results arrive.
    """
    lines = ["> 🧠 **SOCIS-AI — Analyzing request, querying live data sources...**\n>"]

    for query in _iter_unique_tag_values(r'\[SEARCH:\s*([^\]]+)\]', response):
        cve_m = re.search(r'CVE-\d{4}-\d+', query, re.IGNORECASE)
        if cve_m:
            cve = cve_m.group(0).upper()
            lines.append(
                f"> 🔎 **CVE Lookup** → `{cve}` "
                f"*(NVD · CISA KEV · EPSS · PoC Index)*"
            )
        else:
            lines.append(f"> 🔎 **Threat Search** → `{query}`")

    for call_str in _iter_unique_tag_values(r'\[MCP:\s*([^\]]+)\]', response):
        parts = call_str.split(".", 1)
        server = parts[0] if len(parts) > 1 else call_str.split()[0]
        emoji, label = _SERVER_LABELS.get(server, ("🔧", server))
        lines.append(f"> {emoji} **{label}** → `{call_str}`")

    for cmd in _iter_unique_tag_values(r'\[TOOL:\s*([^\]]+)\]', response):
        lines.append(f"> 🖥️ **CLI Tool** → `{cmd}`")

    lines.append(">\n")
    return "\n".join(lines) + "\n\n"

def _extract_mcp_output(result: dict) -> str:
    """Flatten the MCP result dict into a readable string."""
    if not result:
        return "(empty result)"
    # Standard MCP content array
    content = result.get("content", [])
    if isinstance(content, list):
        parts = [c.get("text", "") for c in content if isinstance(c, dict) and c.get("text")]
        if parts:
            return "\n".join(parts)
    # Direct text field
    if "text" in result:
        return str(result["text"])
    # Fallback: dump JSON
    return json.dumps(result, indent=2)[:3000]


async def _execute_tool_tags(response: str, disabled_servers: Optional[set[str]] = None,
                              tool_server_settings: Optional[dict] = None, tool_overrides: Optional[dict] = None) -> list[dict]:
    """
    Parse [SEARCH: ...], [MCP: ...], [TOOL: ...] tags from the LLM response
    and execute them via the MCP client. Returns a list of
    {"tag": str, "output": str, "sources": list[str]} dicts.
    """
    from app.mcp.client import get_mcp_client
    import asyncio
    import logging
    log = logging.getLogger(__name__)

    mcp = get_mcp_client()
    results = []
    # tool_server_settings/tool_overrides (core/ai_tool_policy.py) are the live policy; disabled_servers is accepted for any
    # older caller but is otherwise unused now that per-server AND per-tool decisions both flow through tool_server_settings.
    tool_server_settings = tool_server_settings if tool_server_settings is not None else (
        {k: False for k in _MCP_SETTING_TO_SERVER if _MCP_SETTING_TO_SERVER[k] in (disabled_servers or set())}
    )
    tool_overrides = tool_overrides or {}

    # ── Agentic offensive-tool policy (fix H-4), and the admin per-server / per-tool allowlist ──────────────
    # Exploitation-class tools must not be driven autonomously by text the LLM generated (which can be steered by prompt
    # injection from scanned pages, CVE text, OSINT output, or uploaded files). Blocked from tag-driven execution unless an
    # operator opts in via SOCIS_AGENT_ALLOW_OFFENSIVE — this floor is defined once in core/ai_tool_policy.py and cannot be
    # raised by the admin per-tool switches below, which only narrow what is already allowed.
    from app.config import settings as _settings
    from app.core.ai_tool_policy import effective_enabled as _tool_effective_enabled, is_offensive as _is_offensive

    async def _call_tool(server_name: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if not _tool_effective_enabled(server_name, tool_name, tool_server_settings, tool_overrides, _MCP_SETTING_TO_SERVER):
            return {
                "content": [
                    {"text": f"Tool disabled by admin policy: {server_name}.{tool_name}"}
                ]
            }
        if _is_offensive(server_name, tool_name) and not _settings.SOCIS_AGENT_ALLOW_OFFENSIVE:
            log.warning(
                "[Agentic] Blocked autonomous offensive tool call %s.%s "
                "(SOCIS_AGENT_ALLOW_OFFENSIVE is disabled)", server_name, tool_name,
            )
            return {
                "content": [
                    {"text": (
                        f"\u26d4 Blocked for safety: '{server_name}.{tool_name}' is an "
                        "exploitation-class tool and cannot be run autonomously by the "
                        "AI assistant. Run it from the Tools/MCP console with an "
                        "authorized target, or an administrator can enable "
                        "SOCIS_AGENT_ALLOW_OFFENSIVE."
                    )}
                ]
            }
        from app.core.scope_guard import ScopeViolation, set_source
        set_source("ai_chat")
        try:
            return await mcp.call_tool(server_name, tool_name, arguments)
        except ScopeViolation as _sv:
            # Tell the model (and so the user) plainly why nothing ran, instead of an anonymous tool error.
            return {"content": [{"text": f"\u26d4 {_sv} No scan was started."}]}

    # ── [SEARCH: query] ──────────────────────────────────────
    for query in _iter_unique_tag_values(r'\[SEARCH:\s*([^\]]+)\]', response):
        tag = f"SEARCH: {query}"
        try:
            cve_match = re.search(r'CVE-\d{4}-\d+', query, re.IGNORECASE)
            if cve_match:
                # Auto-enrich: query all 4 intel sources in parallel
                cve_id = cve_match.group(0).upper()
                cve_r, kev_r, epss_r, poc_r = await asyncio.gather(
                    _call_tool("cve_mcp", "lookup_cve", {"cve_id": cve_id}),
                    _call_tool("cisa_kev_mcp", "check_kev", {"cve_id": cve_id}),
                    _call_tool("epss_mcp", "get_epss_score", {"cve_id": cve_id}),
                    _call_tool("poc_mcp", "poc_risk_summary", {"cve_id": cve_id}),
                    return_exceptions=True,
                )
                combined = ""
                for label, r in [
                    ("CVE Details (NVD)", cve_r),
                    ("CISA KEV Status", kev_r),
                    ("EPSS Score", epss_r),
                    ("PoC Risk Assessment", poc_r),
                ]:
                    if not isinstance(r, Exception):
                        combined += f"\n--- {label} ---\n{_extract_mcp_output(r)}\n"
                    else:
                        combined += f"\n--- {label} ---\n(unavailable: {r})\n"
                results.append({
                    "tag": tag,
                    "output": combined,
                    "sources": ["CVE Database (NVD)", "CISA KEV", "EPSS", "PoC Index"],
                })
            else:
                result = await _call_tool("cve_mcp", "search_cves", {"keyword": query, "limit": 5})
                results.append({
                    "tag": tag,
                    "output": _extract_mcp_output(result),
                    "sources": ["CVE Database (NVD)"],
                })
        except Exception as e:
            log.warning(f"[Agentic] SEARCH tag failed for '{query}': {e}")
            results.append({"tag": tag, "output": f"Search failed: {e}", "sources": []})

    # ── [MCP: server.tool_name {args}] or [MCP: tool_name target] ──
    for call_str in _iter_unique_tag_values(r'\[MCP:\s*([^\]]+)\]', response):
        tag = f"MCP: {call_str}"
        try:
            parts = call_str.split(None, 1)
            tool_ref = parts[0]
            arg_str = parts[1] if len(parts) > 1 else ""

            # Intercept [MCP: SEARCH: CVE-xxx] — LLM used wrong prefix, route to SEARCH logic
            if tool_ref.upper().rstrip(":") == "SEARCH":
                query = arg_str.strip()
                cve_m = re.search(r'CVE-\d{4}-\d+', query, re.IGNORECASE)
                if cve_m:
                    cve_id = cve_m.group(0).upper()
                    cve_r, kev_r, epss_r, poc_r = await asyncio.gather(
                        _call_tool("cve_mcp", "lookup_cve", {"cve_id": cve_id}),
                        _call_tool("cisa_kev_mcp", "check_kev", {"cve_id": cve_id}),
                        _call_tool("epss_mcp", "get_epss_score", {"cve_id": cve_id}),
                        _call_tool("poc_mcp", "poc_risk_summary", {"cve_id": cve_id}),
                        return_exceptions=True,
                    )
                    combined = ""
                    for label, r in [
                        ("CVE Details (NVD)", cve_r),
                        ("CISA KEV Status", kev_r),
                        ("EPSS Score", epss_r),
                        ("PoC Risk Assessment", poc_r),
                    ]:
                        if not isinstance(r, Exception):
                            combined += f"\n--- {label} ---\n{_extract_mcp_output(r)}\n"
                        else:
                            combined += f"\n--- {label} ---\n(unavailable: {r})\n"
                    results.append({
                        "tag": tag,
                        "output": combined,
                        "sources": ["CVE Database (NVD)", "CISA KEV", "EPSS", "PoC Index"],
                    })
                else:
                    r = await _call_tool("cve_mcp", "search_cves", {"keyword": query, "limit": 5})
                    results.append({
                        "tag": tag,
                        "output": _extract_mcp_output(r),
                        "sources": ["CVE Database (NVD)"],
                    })
                continue

            if "." in tool_ref:
                server_name, tool_name = tool_ref.split(".", 1)
            else:
                server_name = None
                tool_name = tool_ref
                for srv in mcp.list_servers():
                    if any(t["name"] == tool_name for t in srv.get("tools", [])):
                        server_name = srv["name"]
                        break
                if not server_name:
                    raise ValueError(f"Cannot find server for tool '{tool_name}'")

            arguments: dict[str, Any] = {}
            if arg_str:
                try:
                    arguments = json.loads(arg_str)
                except json.JSONDecodeError:
                    server_obj = mcp.get_server(server_name)
                    if server_obj:
                        for t in server_obj.tools:
                            if t.name == tool_name:
                                required = t.input_schema.get("required", [])
                                if required:
                                    arguments = {required[0]: arg_str}
                                    break
                    if not arguments:
                        arguments = {"target": arg_str}

            result = await _call_tool(server_name, tool_name, arguments)
            _, label = _SERVER_LABELS.get(server_name, ("🔧", server_name))
            results.append({
                "tag": tag,
                "output": _extract_mcp_output(result),
                "sources": [label],
                "server": server_name,
            })
        except Exception as e:
            log.warning(f"[Agentic] MCP tag failed for '{call_str}': {e}")
            results.append({"tag": tag, "output": f"Tool call failed: {e}", "sources": []})

    # ── [TOOL: command] ──────────────────────────────────────
    for cmd_str in _iter_unique_tag_values(r'\[TOOL:\s*([^\]]+)\]', response):
        tag = f"TOOL: {cmd_str}"
        try:
            tokens = cmd_str.split()
            tool_bin = tokens[0].lower() if tokens else ""
            if tool_bin == "nmap" and len(tokens) > 1:
                target = tokens[-1]
                flags = " ".join(tokens[1:-1]) if len(tokens) > 2 else "-sV"
                result = await _call_tool("nmap_mcp", "nmap_scan", {"target": target, "flags": flags})
                results.append({"tag": tag, "output": _extract_mcp_output(result), "sources": ["Nmap"]})
            else:
                results.append({"tag": tag, "output": f"[TOOL] '{tool_bin}' not mapped to an MCP tool yet.", "sources": []})
        except Exception as e:
            log.warning(f"[Agentic] TOOL tag failed for '{cmd_str}': {e}")
            results.append({"tag": tag, "output": f"Tool execution failed: {e}", "sources": []})

    return results


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage]
    model_id: Optional[str] = None
    scan_context_id: Optional[str] = None
    provider: Optional[str] = "ollama_remote"
    model_name: Optional[str] = None
    stream: bool = True

    @field_validator('messages')
    @classmethod
    def validate_messages(cls, v: List[ChatMessage]) -> List[ChatMessage]:
        if not v:
            raise ValueError('At least one message is required')
        if len(v) > 100:
            raise ValueError('Message history limited to 100 messages')
        total_size = sum(len(m.content) for m in v)
        if total_size > 100_000:
            raise ValueError('Message history too large (max 100KB)')
        return v


class SearchRequest(BaseModel):
    query: str
    max_results: int = 5

    @field_validator('query')
    @classmethod
    def validate_query(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError('Query cannot be empty')
        if len(v) > 500:
            raise ValueError('Query too long (max 500 characters)')
        return v


async def _allowed_models_by_provider(db: AsyncSession) -> dict[str, set[str]]:
    """Return active admin-configured allowlist of models per provider."""
    db_configs = (
        await db.execute(select(LLMConfig).where(LLMConfig.is_active == True))
    ).scalars().all()
    allowed: dict[str, set[str]] = {}
    for c in db_configs:
        provider = str(getattr(c.provider, "value", c.provider))
        allowed.setdefault(provider, set()).add(c.model_name)
    return allowed


async def _ai_tool_policy(db: AsyncSession) -> tuple[dict, dict]:
    """The admin AI-chat tool policy: (server-level settings e.g. {"mcp_nmap_enabled": True, ...}, per-tool overrides e.g.
    {"nmap_mcp.nmap_vuln_scan": False}). See core/ai_tool_policy.py for how the two combine."""
    from app.services.settings_service import settings_service

    raw = await settings_service.get_setting(db, "tool_settings_global")
    if not raw:
        return {}, {}
    try:
        policy = json.loads(raw)
        if not isinstance(policy, dict):
            return {}, {}
    except Exception:
        return {}, {}
    overrides = policy.get("tool_overrides")
    return policy, (overrides if isinstance(overrides, dict) else {})


# ─── Streaming Chat ───────────────────────────────────────────

@router.post("/chat")
async def chat(
    request: ChatRequest,
    token: dict = Depends(require_permission("llm:chat")),
    db: AsyncSession = Depends(get_db),
):
    """Chat with the AI assistant. Returns SSE stream if stream=True."""
    from app.services.settings_service import settings_service, user_settings_service
    
    # Build full prompt with system context
    messages = [{"role": "system", "content": build_system_prompt()}]

    # Optionally inject scan context
    if request.scan_context_id:
        from app.models.project import Project
        from app.models.scan import Scan
        from sqlalchemy.orm import selectinload
        _scan_q = select(Scan).where(Scan.id == uuid.UUID(request.scan_context_id)).options(
            selectinload(Scan.vulnerabilities), selectinload(Scan.tool_results)
        )
        if token.get("role") != "admin":
            # Before this check, ANY signed-in user could read ANY scan's raw tool output and vulnerabilities by passing its id
            # here — scan_context_id was never checked against the caller's own projects.
            _scan_q = _scan_q.join(Project, Project.id == Scan.project_id).where(Project.owner_id == uuid.UUID(token["sub"]))
        result = await db.execute(_scan_q)
        scan = result.scalar_one_or_none()
        if scan:
            from app.services.tool_service import tool_service as ts
            tool_data = {t.tool_name: {"output": t.raw_output} for t in scan.tool_results}
            ctx_text = ts.format_for_llm(tool_data)
            # The scanned target chose this text (banners, headers, page content): wrap it so the model never mistakes it for
            # an instruction (see services/system_prompt.wrap_untrusted_data).
            from app.services.system_prompt import wrap_untrusted_data
            messages.append({"role": "system", "content": wrap_untrusted_data(f"Scan results for {scan.target}", ctx_text)})

    for msg in request.messages:
        messages.append({"role": msg.role, "content": msg.content})

    # Determine provider (a legacy "ollama_local" value is mapped to the external Ollama server)
    try:
        provider = LLMProvider(normalize_provider(request.provider))
    except ValueError:
        provider = LLMProvider.OLLAMA_REMOTE

    # Enforce the admin-configured model allowlist when configs exist for this provider.
    allowed_models = await _allowed_models_by_provider(db)
    provider_key = provider.value if hasattr(provider, "value") else str(provider)
    provider_allowlist = allowed_models.get(provider_key, set())
    requested_model = (request.model_name or "").strip()
    if provider_allowlist:
        if requested_model and requested_model not in provider_allowlist:
            raise HTTPException(
                status_code=400,
                detail=f"Model '{requested_model}' is not allowed for provider '{provider_key}'. Configure it in Admin → LLM Configs first.",
            )

    # Get remote Ollama URL (and default model) from database if needed
    remote_ollama_url = None
    remote_ollama_model = request.model_name  # may be None
    if provider == LLMProvider.OLLAMA_REMOTE:
        remote_ollama_url = await settings_service.get_ollama_remote_url(db)
        if not remote_ollama_url:
            raise HTTPException(
                status_code=400,
                detail="Remote Ollama server not configured. Please configure it in Admin → Settings tab first."
            )
        # If caller didn't specify a model, use the admin-configured remote default
        if not remote_ollama_model:
            remote_ollama_model = await settings_service.get_ollama_remote_model(db)


    # If no explicit model was provided, prefer provider default from allowlist configs.
    if not remote_ollama_model and provider_allowlist:
        default_cfg = (
            await db.execute(
                select(LLMConfig)
                .where(LLMConfig.is_active == True, LLMConfig.provider == provider_key)
                .order_by(LLMConfig.is_default.desc(), LLMConfig.created_at.asc())
            )
        ).scalars().first()
        if default_cfg:
            remote_ollama_model = default_cfg.model_name

    # Resolve the admin-saved API key/URL for a non-Ollama provider (Admin -> AI providers -> Add LLM Provider).
    # Previously nothing ever read this back — every chat_<provider>() call used only the .env variable, so a
    # provider configured here looked saved but had no effect on what was actually used.
    from app.core.llm_providers import resolve_llm_credentials
    chat_api_key, chat_api_base_url = await resolve_llm_credentials(db, provider_key)

    # Final guard after fallback/default selection.
    if provider_allowlist and remote_ollama_model and remote_ollama_model not in provider_allowlist:
        raise HTTPException(
            status_code=400,
            detail=f"Model '{remote_ollama_model}' is not allowed for provider '{provider_key}'.",
        )

    # Build the prompt string for Ollama (uses single prompt, not messages list)
    prompt = "\n".join(f"[{m['role'].upper()}]: {m['content']}" for m in messages)
    tool_server_settings, tool_overrides = await _ai_tool_policy(db)

    # ── Determine if the user's latest message is a pure analytical request ──
    # These queries should NEVER trigger MCP tool calls — the LLM should just
    # write text.  No CVE IDs → no SEARCH injection.  No scan target → no MCP.
    _analytical_phrases = (
        "remediation plan", "remediation steps", "how to fix", "how to remediate",
        "mitigation", "patch", "explain", "describe", "summarize", "what is",
        "what are", "tell me about", "write a report", "generate a report",
        "prioritize", "prioritization", "risk ranking", "analysis of",
        "analyze the", "based on the findings", "based on the results",
        "based on the scan", "based on the output", "from the scan",
        "recommend", "recommendation", "best practices", "next steps",
    )
    _last_user_msg = next(
        (m.content.strip().lower() for m in reversed(request.messages) if m.role == "user"), ""
    )
    _has_cve_in_last_msg = bool(re.search(r'CVE-\d{4}-\d+', _last_user_msg, re.IGNORECASE))
    _has_scan_target = bool(re.search(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b'   # IPv4
        r'|(?:[a-z0-9-]+\.)+[a-z]{2,}'   # domain-like
        r'|\blocalhost\b|\b127\.0\.0\.1\b',
        _last_user_msg, re.IGNORECASE,
    ))
    _is_analytical_query = (
        not _has_cve_in_last_msg
        and not _has_scan_target
        and any(phrase in _last_user_msg for phrase in _analytical_phrases)
    )

    async def event_stream() -> AsyncGenerator[str, None]:
        """
        Two-pass agentic SSE generator.

        Pass 1  — buffer the LLM response silently (tool-planning pass).
        Process — show the user which tools were selected and why.
        Execute — dispatch all tool tags in parallel, stream a source summary.
        Pass 2  — stream a clean synthesis using real tool data.
                  If no tools fired, stream the cleaned first response directly.
        """
        _TAG_RE = re.compile(r'\[(SEARCH|MCP|TOOL):[^\]]*\]', re.IGNORECASE)

        def _clean(text: str) -> str:
            return _TAG_RE.sub('', text).strip()

        try:
            # Send an immediate heartbeat so reverse proxies do not treat the
            # SSE stream as idle before the first model token arrives.
            yield ": keepalive\n\n"

            # ── Pass 1: buffer silently ─────────────────────────────────────────
            first_response = ""
            pass1_stream = llm_service.chat(
                prompt=prompt,
                provider=provider,
                model=remote_ollama_model,
                messages=messages,
                stream=True,
                remote_url=remote_ollama_url,
                # For Ollama: pass the full SOCIS tool-calling system prompt as
                # the dedicated `system` API field. This overrides the shorter
                # Modelfile system and ensures [SEARCH:] / [MCP:] syntax is used.
                system_prompt=build_system_prompt() if provider == LLMProvider.OLLAMA_REMOTE else None,
                api_key=chat_api_key,
                base_url=chat_api_base_url,
            )
            pass1_iter = pass1_stream.__aiter__()
            while True:
                try:
                    token = await asyncio.wait_for(pass1_iter.__anext__(), timeout=20)
                    first_response += token
                except asyncio.TimeoutError:
                    # Keep SSE connection active while waiting for long-running
                    # local/remote model calls.
                    yield ": keepalive\n\n"
                    continue
                except StopAsyncIteration:
                    break

            # ── Safety net: inject SEARCH tags for any CVE IDs in the user ───────
            # message that the LLM missed (model may produce VULN:/plain format).
            # Skip entirely for pure analytical queries — they have no CVE IDs
            # in the last message anyway, and we do not want spurious tool calls.
            _cve_re = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
            last_user_content = next(
                (m.content for m in reversed(request.messages) if m.role == "user"), ""
            )
            if not _is_analytical_query:
                for cve_id in {m.group(0).upper() for m in _cve_re.finditer(last_user_content)}:
                    tag = f"[SEARCH: {cve_id}]"
                    # Only inject if not already present (large remote models often emit plain CVE text
                    # without a tool tag — this guarantees MCP always fires regardless of provider).
                    if not re.search(r'\[SEARCH:\s*' + re.escape(cve_id) + r'[^\]]*\]', first_response, re.IGNORECASE):
                        first_response += f"\n{tag}"

            # ── Strip any MCP/SEARCH/TOOL tags the model emitted for analytical ─
            # queries — they should never trigger real tool calls.
            if _is_analytical_query and _TAG_RE.search(first_response):
                first_response = _clean(first_response)

            # ── Process visibility: show which tools were selected ──────────────
            if not _is_analytical_query and _TAG_RE.search(first_response):
                process_block = _build_process_block(first_response)
                yield f"data: {json.dumps({'type': 'token', 'content': process_block})}\n\n"

            # ── Tool dispatch (skipped entirely for analytical queries) ─────────
            tool_results = [] if _is_analytical_query else await _execute_tool_tags(first_response, tool_server_settings=tool_server_settings, tool_overrides=tool_overrides)

            if tool_results:
                # Collect unique source names
                all_sources: list[str] = []
                for tr in tool_results:
                    for s in tr.get("sources", []):
                        if s not in all_sources:
                            all_sources.append(s)
                sources_str = " · ".join(all_sources) if all_sources else "external tools"
                done_badge = f"> ✅ **Live data retrieved from:** {sources_str}\n\n---\n\n"
                yield f"data: {json.dumps({'type': 'token', 'content': done_badge})}\n\n"

                # Enterprise-grade deterministic CVE rendering for both local and
                # remote providers so output quality is consistent.
                direct_cve_report = _build_cve_report_from_tool_results(tool_results)
                if direct_cve_report:
                    cleaned_direct = _deduplicate_report(direct_cve_report)
                    chunk = 80
                    for i in range(0, len(cleaned_direct), chunk):
                        yield f"data: {json.dumps({'type': 'token', 'content': cleaned_direct[i:i+chunk]})}\n\n"
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    return

                # Build the full tool context for the synthesis pass.
                tool_context = "\n\n".join(
                    f"=== {tr['tag']} ===\n{tr['output']}" for tr in tool_results
                )
                # The tool output above can contain text the SCANNED TARGET chose (banners, HTTP headers, page bodies, DNS
                # records): build_synthesis_prompt wraps it so the model treats it strictly as data to report, never as
                # instructions to follow.

                # Use one synthesis behavior for both remote and local models.
                synth_system = build_synthesis_prompt(tool_context)

                followup_messages = messages + [{"role": "system", "content": synth_system}]
                # For Ollama providers: pass synth_system (which already contains the
                # trimmed tool data + report instructions) as the dedicated Ollama
                # `system` API field, and use a minimal prompt containing only the
                # user question. This prevents the original SOCIS tool-calling system
                # prompt from appearing as a conflicting [SYSTEM]: block in Pass 2,
                # which caused the local model to re-emit [SEARCH:] tags instead of
                # writing the report.
                # OpenAI / Anthropic use the full messages array with proper roles.
                if provider == LLMProvider.OLLAMA_REMOTE:
                    followup_prompt = f"[USER]: {last_user_content}"
                    pass2_system_prompt: str | None = synth_system
                else:
                    followup_prompt = "\n".join(
                        f"[{m['role'].upper()}]: {m['content']}" for m in followup_messages
                    )
                    pass2_system_prompt = None
                pass2_buffer = ""
                pass2_stream = llm_service.chat(
                    prompt=followup_prompt,
                    provider=provider,
                    model=remote_ollama_model,
                    messages=followup_messages,
                    stream=True,
                    remote_url=remote_ollama_url,
                    system_prompt=pass2_system_prompt,
                    api_key=chat_api_key,
                    base_url=chat_api_base_url,
                )
                pass2_iter = pass2_stream.__aiter__()
                while True:
                    try:
                        token = await asyncio.wait_for(pass2_iter.__anext__(), timeout=20)
                        pass2_buffer += token
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
                        continue
                    except StopAsyncIteration:
                        break
                cleaned = _deduplicate_report(pass2_buffer)
                # Enforce canonical deduplicated references for CVE syntheses.
                canonical_refs = _extract_cve_reference_labels(tool_results)
                if canonical_refs:
                    cleaned = _replace_references_section(cleaned, canonical_refs)
                cleaned = _normalize_references_section(cleaned, canonical_refs)
                if not cleaned.strip():
                    # Pass 2 produced nothing (context overflow, timeout, or model
                    # refusal). Render a deterministic structured report instead —
                    # this always produces visible output for the user.
                    cleaned = _build_tool_fallback_report(tool_results, last_user_content)
                chunk = 60
                for i in range(0, len(cleaned), chunk):
                    yield f"data: {json.dumps({'type': 'token', 'content': cleaned[i:i+chunk]})}\n\n"

            else:
                # No tools needed — stream the first response with tags stripped
                display = _clean(first_response)
                chunk = 40
                for i in range(0, len(display), chunk):
                    yield f"data: {json.dumps({'type': 'token', 'content': display[i:i+chunk]})}\n\n"

            yield f"data: {json.dumps({'type': 'done'})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    if request.stream:
        # Concurrency cap (perf #7): hold a shared slot for the stream's whole
        # lifetime. Over the limit, emit a clean SSE error instead of piling up
        # streams that exhaust workers / the LLM endpoint.
        from app.core.token_blocklist import concurrency_slot, ConcurrencyLimitExceeded
        from app.config import settings as _cfg
        async def _limited_stream():
            from app.core import metrics as _m
            try:
                async with concurrency_slot(
                    "chat_sessions", _cfg.MAX_CONCURRENT_CHAT_SESSIONS
                ):
                    _m.CHAT_SESSIONS_ACTIVE.inc()
                    try:
                        async for chunk in event_stream():
                            yield chunk
                    finally:
                        _m.CHAT_SESSIONS_ACTIVE.dec()
            except ConcurrencyLimitExceeded as e:
                yield f"data: {json.dumps({'type': 'error', 'message': f'The assistant is busy ({e.limit} concurrent sessions in use). Please retry shortly.'})}\n\n"
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
        return StreamingResponse(_limited_stream(), media_type="text/event-stream")
    else:
        # Collect full response
        full_response = ""
        base_system_prompt = build_system_prompt() if provider == LLMProvider.OLLAMA_REMOTE else None
        async for chunk in llm_service.chat(
            prompt=prompt,
            provider=provider,
            model=remote_ollama_model,
            messages=messages,
            stream=False,
            remote_url=remote_ollama_url,
            system_prompt=base_system_prompt,
            api_key=chat_api_key,
            base_url=chat_api_base_url,
        ):
            full_response += str(chunk)
        return {"role": "assistant", "content": full_response}


# ─── Model Management ────────────────────────────────────────

@router.get("/models")
async def list_models(
    provider: Optional[str] = None,
    remote_url: Optional[str] = None,
    configured_only: bool = Query(False, description="Return only admin-configured models when true"),
    token: dict = Depends(require_permission("llm:chat")),
    db: AsyncSession = Depends(get_db),
):
    """List all available LLM models. Optionally filter by provider.
    
    Args:
        provider: Optional filter - 'ollama_remote', 'openai', 'anthropic', ...
                 If not specified, returns models from all available providers.
        remote_url: Optional override for remote Ollama URL (e.g., from workflow node config)
    """
    import httpx
    from app.config import settings
    from app.services.settings_service import settings_service

    db_configs = (await db.execute(select(LLMConfig).where(LLMConfig.is_active == True))).scalars().all()
    cfg_by_provider: dict[str, list[LLMConfig]] = {}
    for c in db_configs:
        p = normalize_provider(getattr(c.provider, "value", c.provider))
        cfg_by_provider.setdefault(p, []).append(c)

    def _is_embedding_model(model_name: str) -> bool:
        """Hide embedding-only models from chat model pickers."""
        n = (model_name or "").strip().lower()
        if not n:
            return False
        embedding_markers = (
            "embed",
            "embedding",
            "nomic-embed",
            "bge-",
            "e5-",
            "mxbai-embed",
            "snowflake-arctic-embed",
        )
        return any(marker in n for marker in embedding_markers)

    # Get live Ollama models (remote) - from parameter, database or environment
    ollama_remote_models = []
    live_remote_names: set[str] = set()
    if not provider or provider == "ollama_remote":
        # Use provided remote_url if given, otherwise get from database
        if remote_url:
            # Caller-supplied override (e.g. a workflow node): validate it, because the backend
            # will fetch it. Private ranges are fine (internal Ollama); loopback/metadata are not.
            from app.core.netguard import acheck_url
            try:
                await acheck_url(remote_url, allow_private=True)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=f"remote_url not allowed: {exc}")
        use_remote_url = remote_url or await settings_service.get_ollama_remote_url(db) or settings.OLLAMA_REMOTE_URL
        if use_remote_url:
            try:
                async with httpx.AsyncClient(timeout=15) as client:
                    resp = await client.get(f"{use_remote_url.rstrip('/')}/api/tags")
                    if resp.status_code == 200:
                        data = resp.json()
                        remote_model = await settings_service.get_ollama_remote_model(db)
                        ollama_remote_models = sorted(
                            [
                                {
                                    "id": f"ollama_remote:{m['name']}",
                                    "name": m["name"],
                                    "provider": "ollama_remote",
                                    "model_name": m["name"],
                                    "is_default": m["name"] == remote_model,
                                    "is_active": True,
                                    "size_gb": round(m.get("size", 0) / 1e9, 2),
                                }
                                for m in data.get("models", [])
                                if not _is_embedding_model(str(m.get("name", "")))
                            ],
                            key=lambda x: x["name"],
                        )
                        live_remote_names = {
                            m.get("name", "")
                            for m in data.get("models", [])
                            if m.get("name") and not _is_embedding_model(str(m.get("name", "")))
                        }
            except Exception:
                pass

    def _cfg_models_for(p: str, live_names: set[str]) -> list[dict]:
        rows = cfg_by_provider.get(p, [])
        out: list[dict] = []
        for c in rows:
            out.append(
                {
                    "id": str(c.id),
                    "name": c.model_name,
                    "provider": p,
                    "model_name": c.model_name,
                    "is_default": c.is_default,
                    "is_active": c.is_active,
                    "configured": True,
                    "available": (c.model_name in live_names) if live_names else None,
                }
            )
        return out

    if configured_only:
        if (not provider) or provider == "ollama_remote":
            ollama_remote_models = _cfg_models_for("ollama_remote", live_remote_names)

    db_models = [
        {
            "id": str(c.id),
            "name": c.name,
            "provider": normalize_provider(getattr(c.provider, "value", c.provider)),
            "model_name": c.model_name,
            "is_default": c.is_default,
            "is_active": c.is_active,
        }
        for c in db_configs
    ]

    provider_models: dict[str, list[str]] = {}
    for p, rows in cfg_by_provider.items():
        if p == "ollama_remote":
            provider_models[p] = [c.model_name for c in rows if not _is_embedding_model(c.model_name)]
        else:
            provider_models[p] = [c.model_name for c in rows]

    return {
        "ollama_remote_models": ollama_remote_models,
        "configured_models": db_models,
        "provider_models": provider_models,
        "configured_only": configured_only,
    }


# ─── LLM Status ──────────────────────────────────────────────

@router.get("/status")
async def llm_status(
    token: dict = Depends(require_permission("llm:chat")),
    db: AsyncSession = Depends(get_db),
):
    """Check connectivity to all configured LLM providers."""
    import httpx
    from app.config import settings
    from app.services.settings_service import settings_service

    status = {}

    # Ollama remote — read URL from DB (set via Admin → Settings), fall back to env var
    remote_url = await settings_service.get_ollama_remote_url(db) or settings.OLLAMA_REMOTE_URL
    if remote_url:
        try:
            async with httpx.AsyncClient(timeout=4) as client:
                resp = await client.get(f"{remote_url}/api/tags")
                if resp.status_code == 200:
                    models = [m["name"] for m in resp.json().get("models", [])]
                    status["ollama_remote"] = {"connected": True, "models": models, "url": remote_url}
                else:
                    status["ollama_remote"] = {"connected": False, "url": remote_url}
        except Exception:
            status["ollama_remote"] = {"connected": False, "configured": True, "url": remote_url}
    else:
        status["ollama_remote"] = {"connected": False, "configured": False}

    # A provider is "configured" if EITHER its .env variable is set OR an admin has saved an active LLMConfig row for
    # it (Admin -> AI providers -> Add LLM Provider) — previously this only ever checked .env, so a DB-saved provider
    # incorrectly showed as not configured even when it was genuinely usable.
    db_configured_providers: set[str] = set()
    db_models_by_provider: dict[str, list[str]] = {}
    try:
        db_configs = (await db.execute(select(LLMConfig).where(LLMConfig.is_active == True))).scalars().all()  # noqa: E712
        for c in db_configs:
            p = str(getattr(c.provider, "value", c.provider))
            db_configured_providers.add(p)
            db_models_by_provider.setdefault(p, []).append(c.model_name)
    except Exception:
        pass

    def _provider_status(key: str, env_key: str, env_model: str, env_base_url: str | None = None) -> dict:
        from_db = key in db_configured_providers
        entry = {
            "configured": bool(env_key) or from_db,
            "model": env_model,
            "configured_via": "database" if from_db else ("env" if env_key else None),
        }
        if env_base_url is not None:
            entry["base_url"] = env_base_url
        if from_db:
            entry["db_models"] = db_models_by_provider.get(key, [])
        return entry

    # OpenAI
    status["openai"] = _provider_status("openai", settings.OPENAI_API_KEY, settings.OPENAI_MODEL)

    # Anthropic
    status["anthropic"] = _provider_status("anthropic", settings.ANTHROPIC_API_KEY, settings.ANTHROPIC_MODEL)

    # OpenRouter
    status["openrouter"] = _provider_status("openrouter", settings.OPENROUTER_API_KEY, settings.OPENROUTER_MODEL, settings.OPENROUTER_BASE_URL)

    # Grok (xAI)
    status["grok"] = _provider_status("grok", settings.GROK_API_KEY, settings.GROK_MODEL, settings.GROK_BASE_URL)

    # Mistral
    status["mistral"] = _provider_status("mistral", settings.MISTRAL_API_KEY, settings.MISTRAL_MODEL, settings.MISTRAL_BASE_URL)

    return status


# ─── Web Search ───────────────────────────────────────────────

@router.post("/search")
async def web_search(
    request: SearchRequest,
    token: dict = Depends(require_permission("llm:chat")),
):
    """Perform a web search (DuckDuckGo) for the AI assistant."""
    from app.services.search_service import search_service
    results = search_service.search_web(request.query, max_results=request.max_results)
    formatted = search_service.format_search_results(results)
    return {"query": request.query, "results": results, "formatted": formatted}


# ─── CVE Lookup ───────────────────────────────────────────────

@router.get("/cve/{cve_id}")
async def lookup_cve(
    cve_id: str,
    token: dict = Depends(require_permission("llm:chat")),
):
    """Look up a CVE from the NVD API."""
    from app.services.search_service import search_service
    return await search_service.lookup_cve(cve_id)
