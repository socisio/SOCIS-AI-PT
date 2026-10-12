#!/usr/bin/env python3
"""
SOCIS-AI-PT — MITRE ATT&CK MCP Server (HTTP transport)
FastAPI-based MCP server providing full MITRE ATT&CK framework access
via the official mitreattack-python library (STIX 2.0 data).

Domains loaded: Enterprise ATT&CK, Mobile ATT&CK, ICS ATT&CK
Port: 8105
"""

import json
import logging
import os
import re
import threading
import uvicorn
from pathlib import Path
from typing import Any, Optional
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from mcp_auth import verify_mcp_auth, mcp_auth_error

logger = logging.getLogger(__name__)

app = FastAPI(title="SOCIS MITRE ATT&CK MCP Server", docs_url=None)

MCP_VERSION = "1.0"
SERVER_NAME = "mitre-mcp"

# ─── ATT&CK Data Layer ────────────────────────────────────────
# Supports three domains: enterprise, mobile, ics.
# Each domain's STIX bundle is downloaded once and cached on disk.

_DATA_DIR = Path(os.environ.get("MITRE_DATA_DIR", "/tmp/mitre-mcp-data"))

_DOMAIN_META: dict = {
    "enterprise": {
        "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "file": "enterprise-attack.json",
        "label": "Enterprise ATT&CK",
        "navigator_domain": "enterprise-attack",
        "version": "18",
    },
    "mobile": {
        "url": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
        "file": "mobile-attack.json",
        "label": "Mobile ATT&CK",
        "navigator_domain": "mobile-attack",
        "version": "18",
    },
    "ics": {
        "url": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
        "file": "ics-attack.json",
        "label": "ICS ATT&CK",
        "navigator_domain": "ics-attack",
        "version": "18",
    },
}

_attack_cache: dict = {}
_load_locks: dict = {d: threading.Lock() for d in _DOMAIN_META}
_load_errors: dict = {}


def _ensure_stix_data(domain: str) -> Path:
    """Return the path to the pre-downloaded STIX bundle; raise if missing."""
    meta = _DOMAIN_META[domain]
    stix_file = _DATA_DIR / meta["file"]
    if not stix_file.exists():
        raise RuntimeError(
            f"{meta['label']} STIX bundle not found at {stix_file}. "
            "The file should have been baked into the Docker image during build. "
            f"Expected MITRE_DATA_DIR={_DATA_DIR}"
        )
    return stix_file


def _get_attack(domain: str = "enterprise") -> Any:
    """Return the MitreAttackData instance for the given domain, loading it on demand."""
    if domain not in _DOMAIN_META:
        raise ValueError(f"Unknown domain '{domain}'. Use: enterprise, mobile, ics")
    if domain in _attack_cache:
        return _attack_cache[domain]
    with _load_locks[domain]:
        if domain in _attack_cache:
            return _attack_cache[domain]
        try:
            from mitreattack.stix20 import MitreAttackData
            stix_file = _ensure_stix_data(domain)
            logger.info(f"[MITRE] Loading {_DOMAIN_META[domain]['label']} from {stix_file}…")
            _attack_cache[domain] = MitreAttackData(str(stix_file))
            logger.info(f"[MITRE] {_DOMAIN_META[domain]['label']} loaded successfully.")
        except Exception as e:
            _load_errors[domain] = str(e)
            logger.error(f"[MITRE] Failed to load {domain}: {e}")
            raise RuntimeError(f"ATT&CK data unavailable ({domain}): {e}")
    return _attack_cache[domain]


def _stix_to_dict(obj) -> dict:
    """Convert a STIX2 object to a plain serialisable dict.
    mitreattack-python v3 wraps relationship results as {"object": ..., "relationship": ...}.
    If that pattern is detected, unwrap the technique/software object.
    """
    if obj is None:
        return {}
    # Unwrap v3 relationship wrapper dicts — the inner value is the real STIX object
    # mitreattack-python v3 returns {"object": <STIXobj>, "relationships": [...]}
    if isinstance(obj, dict) and "object" in obj and ("relationship" in obj or "relationships" in obj):
        return _stix_to_dict(obj["object"])
    # Already a plain dict (e.g. already deserialised)
    if isinstance(obj, dict):
        return obj
    # STIX2 object — serialise via its built-in method
    try:
        return json.loads(obj.serialize())  # type: ignore[union-attr]
    except Exception:
        return dict(obj)


# MITRE STIX descriptions contain markdown-style citation links such as
# [Group Name](https://attack.mitre.org/groups/G0001) and (Citation: xyz).
# Strip these so the frontend displays clean plain text with no external URLs.
_MD_LINK_RE = re.compile(r'\[([^\]]+)\]\([^)]+\)')
_CITATION_RE = re.compile(r'\s*\(Citation:[^)]+\)', re.IGNORECASE)


def _strip_description(text: str) -> str:
    """Remove markdown links and citation markers from MITRE STIX descriptions."""
    text = _MD_LINK_RE.sub(r'\1', text)   # [Label](url) → Label
    text = _CITATION_RE.sub('', text)      # (Citation: ...) → removed
    return text.strip()


def _clean_technique(t: dict) -> dict:
    """Extract a concise, LLM-friendly technique summary."""
    ext_refs = t.get("external_references", [])
    attack_id = next(
        (r.get("external_id") for r in ext_refs if r.get("source_name") == "mitre-attack"),
        None,
    )
    url = next(
        (r.get("url") for r in ext_refs if r.get("source_name") == "mitre-attack"),
        None,
    )
    kill_chain = t.get("kill_chain_phases", [])
    tactics = [k.get("phase_name", "").replace("-", " ").title() for k in kill_chain]
    platforms = t.get("x_mitre_platforms", [])
    is_sub = bool(t.get("x_mitre_is_subtechnique"))
    detection = t.get("x_mitre_detection", "")
    data_sources = t.get("x_mitre_data_sources", [])
    permissions = t.get("x_mitre_permissions_required", [])
    revoked = t.get("revoked", False)
    deprecated = t.get("x_mitre_deprecated", False)

    return {
        "id": attack_id,
        "stix_id": t.get("id"),
        "name": t.get("name"),
        "description": _strip_description((t.get("description") or "")[:1200]),
        "tactics": tactics,
        "platforms": platforms,
        "is_subtechnique": is_sub,
        "detection": _strip_description(detection[:600]) if detection else None,
        "data_sources": data_sources,
        "permissions_required": permissions,
        "revoked": revoked,
        "deprecated": deprecated,
    }


def _clean_group(g: dict) -> dict:
    ext_refs = g.get("external_references", [])
    attack_id = next(
        (r.get("external_id") for r in ext_refs if r.get("source_name") == "mitre-attack"),
        None,
    )
    url = next(
        (r.get("url") for r in ext_refs if r.get("source_name") == "mitre-attack"),
        None,
    )
    return {
        "id": attack_id,
        "stix_id": g.get("id"),
        "name": g.get("name"),
        "description": _strip_description((g.get("description") or "")[:800]),
        "aliases": g.get("aliases", []),
    }


def _clean_software(s: dict) -> dict:
    ext_refs = s.get("external_references", [])
    attack_id = next(
        (r.get("external_id") for r in ext_refs if r.get("source_name") == "mitre-attack"),
        None,
    )
    url = next(
        (r.get("url") for r in ext_refs if r.get("source_name") == "mitre-attack"),
        None,
    )
    return {
        "id": attack_id,
        "stix_id": s.get("id"),
        "name": s.get("name"),
        "type": s.get("type"),  # tool / malware
        "description": _strip_description((s.get("description") or "")[:600]),
        "platforms": s.get("x_mitre_platforms", []),
        "aliases": s.get("x_mitre_aliases", []),
    }


def _clean_mitigation(m: dict) -> dict:
    ext_refs = m.get("external_references", [])
    attack_id = next(
        (r.get("external_id") for r in ext_refs if r.get("source_name") == "mitre-attack"),
        None,
    )
    return {
        "id": attack_id,
        "stix_id": m.get("id"),
        "name": m.get("name"),
        "description": (m.get("description") or "")[:500],
    }


def _clean_campaign(c: dict) -> dict:
    ext_refs = c.get("external_references", [])
    attack_id = next(
        (r.get("external_id") for r in ext_refs if r.get("source_name") == "mitre-attack"),
        None,
    )
    return {
        "id": attack_id,
        "stix_id": c.get("id"),
        "name": c.get("name"),
        "description": (c.get("description") or "")[:500],
        "aliases": c.get("aliases", []),
        "first_seen": c.get("first_seen"),
        "last_seen": c.get("last_seen"),
    }


def _clean_tactic(t: dict) -> dict:
    ext_refs = t.get("external_references", [])
    attack_id = next(
        (r.get("external_id") for r in ext_refs if r.get("source_name") == "mitre-attack"),
        None,
    )
    url = next(
        (r.get("url") for r in ext_refs if r.get("source_name") == "mitre-attack"),
        None,
    )
    shortname = t.get("x_mitre_shortname", "")
    return {
        "id": attack_id,
        "stix_id": t.get("id"),
        "name": t.get("name"),
        "shortname": shortname,
        "description": (t.get("description") or "")[:400],
        "url": url,
    }


# ─── Tool Definitions ─────────────────────────────────────────

TOOLS = [
    # ── General ────────────────────────────────────────────
    {
        "name": "get_data_stats",
        "description": "Return statistics about a loaded ATT&CK dataset. Use domain to select: 'enterprise' (default), 'mobile', or 'ics'.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise", "description": "ATT&CK domain: enterprise, mobile, or ics"},
            },
            "required": [],
        },
    },
    {
        "name": "get_all_tactics",
        "description": "Return all ATT&CK tactics (kill-chain phases). Enterprise has 14, Mobile has 14, ICS has 12. Use the domain parameter to select.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": [],
        },
    },

    # ── Techniques ─────────────────────────────────────────
    {
        "name": "get_technique_by_id",
        "description": "Get full details of a technique or sub-technique by its ATT&CK ID. Works across enterprise, mobile, and ics domains.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "technique_id": {"type": "string", "description": "ATT&CK technique ID, e.g. T1055, T1055.001, T0802"},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["technique_id"],
        },
    },
    {
        "name": "search_techniques",
        "description": "Search techniques by name or description keyword across the selected ATT&CK domain (enterprise, mobile, or ics).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search keyword"},
                "limit": {"type": "integer", "default": 20},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_all_techniques",
        "description": "Return all parent techniques with ID, name, tactics, and platforms. Supports enterprise, mobile, and ics domains.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": [],
        },
    },
    {
        "name": "get_all_subtechniques",
        "description": "Return all sub-techniques across all parent techniques for the selected domain.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": [],
        },
    },
    {
        "name": "get_techniques_by_tactic",
        "description": "Return all techniques belonging to a specific tactic shortname (e.g. 'initial-access', 'impact', 'inhibit-response-function' for ICS). Specify domain to search mobile or ICS tactics.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tactic": {"type": "string", "description": "Tactic shortname"},
                "include_subtechniques": {"type": "boolean", "default": True},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["tactic"],
        },
    },
    {
        "name": "get_techniques_by_platform",
        "description": "Return techniques targeting a platform. Enterprise: Windows/macOS/Linux/Cloud etc. Mobile: Android/iOS. ICS: Field Controller/Engineering Workstation/Historian/HMI etc.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "platform": {"type": "string", "description": "Platform name"},
                "include_subtechniques": {"type": "boolean", "default": False},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["platform"],
        },
    },
    {
        "name": "get_subtechniques_of_technique",
        "description": "Return all sub-techniques of a parent technique by ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "technique_id": {"type": "string", "description": "Parent technique ID, e.g. T1055"},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["technique_id"],
        },
    },
    {
        "name": "get_technique_tactics",
        "description": "Return the list of tactics that a given technique belongs to.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "technique_id": {"type": "string"},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["technique_id"],
        },
    },

    # ── Groups ─────────────────────────────────────────────
    {
        "name": "get_all_groups",
        "description": "Return all ATT&CK groups (threat actors) with IDs, names, aliases. Enterprise and Mobile domains have groups; ICS groups are limited.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": [],
        },
    },
    {
        "name": "get_group_by_name",
        "description": "Find a group by exact name or alias (e.g. 'APT29', 'Cozy Bear', 'Lazarus Group').",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Group name or alias"},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["name"],
        },
    },
    {
        "name": "search_groups",
        "description": "Search groups by a keyword in name, aliases, or description.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": 20},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_groups_using_technique",
        "description": "Return all groups known to use a specific technique ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "technique_id": {"type": "string"},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["technique_id"],
        },
    },
    {
        "name": "get_techniques_used_by_group",
        "description": "Return all techniques used by a group, identified by ATT&CK group ID (e.g. G0016) or name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group_id": {"type": "string", "description": "ATT&CK group ID (G0016) or group name (APT29)"},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["group_id"],
        },
    },
    {
        "name": "get_software_used_by_group",
        "description": "Return all software (malware/tools) used by a group.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group_id": {"type": "string", "description": "ATT&CK group ID or name"},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["group_id"],
        },
    },

    # ── Software ───────────────────────────────────────────
    {
        "name": "get_all_software",
        "description": "Return all ATT&CK software (malware and tools). Supports enterprise, mobile, and ics domains.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": [],
        },
    },
    {
        "name": "search_software",
        "description": "Search software by name or description keyword.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "default": 20},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_software_using_technique",
        "description": "Return all software known to use a specific technique.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "technique_id": {"type": "string"},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["technique_id"],
        },
    },

    # ── Mitigations ────────────────────────────────────────
    {
        "name": "get_all_mitigations",
        "description": "Return all ATT&CK mitigations. Supports enterprise, mobile, and ics domains.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": [],
        },
    },
    {
        "name": "get_mitigations_for_technique",
        "description": "Return all mitigations that address a specific technique.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "technique_id": {"type": "string"},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["technique_id"],
        },
    },
    {
        "name": "get_techniques_mitigated_by",
        "description": "Return all techniques mitigated by a given mitigation ID (e.g. M1036).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "mitigation_id": {"type": "string", "description": "ATT&CK mitigation ID, e.g. M1036"},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["mitigation_id"],
        },
    },

    # ── Campaigns ──────────────────────────────────────────
    {
        "name": "get_all_campaigns",
        "description": "Return all ATT&CK campaigns. Enterprise domain has the most campaigns; mobile/ics may have fewer.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": [],
        },
    },
    {
        "name": "get_campaigns_using_technique",
        "description": "Return all campaigns that used a specific technique.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "technique_id": {"type": "string"},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["technique_id"],
        },
    },

    # ── Data Sources ───────────────────────────────────────
    {
        "name": "get_all_datasources",
        "description": "Return all ATT&CK data sources and data components used for detection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": [],
        },
    },
    {
        "name": "get_datasources_detecting_technique",
        "description": "Return the data sources and components that can detect a specific technique.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "technique_id": {"type": "string"},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["technique_id"],
        },
    },

    # ── Navigator Layer ────────────────────────────────────
    {
        "name": "generate_layer",
        "description": "Generate an ATT&CK Navigator JSON layer for enterprise, mobile, or ics domain. Scope: 'all', 'group', 'tactic', 'platform'. Upload to https://mitre-attack.github.io/attack-navigator/.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "enum": ["all", "group", "tactic", "platform"],
                },
                "value": {
                    "type": "string",
                    "description": "Scope value (group name/ID, tactic shortname, or platform name). Ignored for 'all'.",
                    "default": "",
                },
                "name": {"type": "string", "default": "SOCIS Layer"},
                "color": {"type": "string", "default": "#0ff0fc"},
                "domain": {"type": "string", "enum": ["enterprise", "mobile", "ics"], "default": "enterprise"},
            },
            "required": ["scope"],
        },
    },
]


# ─── Tool Handlers ────────────────────────────────────────────

def _resolve_group_stix_id(attack: Any, group_id: str) -> Optional[str]:
    """Accept G0016, 'APT29', or any alias — return STIX ID."""
    groups = [_stix_to_dict(g) for g in attack.get_groups()]
    # Exact ATT&CK ID
    for g in groups:
        for ref in g.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").upper() == group_id.upper():
                return g["id"]
    # Name or alias
    q = group_id.lower()
    for g in groups:
        if g.get("name", "").lower() == q:
            return g["id"]
        if any(a.lower() == q for a in g.get("aliases", [])):
            return g["id"]
    return None


def _resolve_technique_stix_id(attack: Any, technique_id: str) -> Optional[str]:
    techniques = [_stix_to_dict(t) for t in attack.get_techniques(include_subtechniques=True)]
    tid = technique_id.upper()
    for t in techniques:
        for ref in t.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").upper() == tid:
                return t["id"]
    return None


async def handle_tool(tool_name: str, arguments: dict) -> Any:
    domain = arguments.get("domain", "enterprise")
    attack = _get_attack(domain)
    domain_meta = _DOMAIN_META[domain]

    # ── General ──────────────────────────────────────────────
    if tool_name == "get_data_stats":
        techniques = list(attack.get_techniques(include_subtechniques=False))
        subtechs = list(attack.get_techniques(include_subtechniques=True))
        groups = list(attack.get_groups())
        software = list(attack.get_software())
        mitigations = list(attack.get_mitigations())
        tactics = list(attack.get_tactics())
        campaigns = []
        try:
            campaigns = list(attack.get_campaigns())
        except Exception:
            pass
        return {
            "domain": domain_meta["label"],
            "navigator_domain": domain_meta["navigator_domain"],
            "techniques": len(techniques),
            "subtechniques": len(subtechs) - len(techniques),
            "groups": len(groups),
            "software": len(software),
            "mitigations": len(mitigations),
            "campaigns": len(campaigns),
            "tactics": len(tactics),
        }

    elif tool_name == "get_all_tactics":
        tactics = [_clean_tactic(_stix_to_dict(t)) for t in attack.get_tactics()]
        return {"tactics": tactics, "count": len(tactics)}

    # ── Techniques ───────────────────────────────────────────
    elif tool_name == "get_technique_by_id":
        tid = arguments["technique_id"].upper()
        all_t = [_stix_to_dict(t) for t in attack.get_techniques(include_subtechniques=True)]
        for t in all_t:
            for ref in t.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").upper() == tid:
                    return _clean_technique(t)
        return {"error": f"Technique {tid} not found"}

    elif tool_name == "search_techniques":
        query = arguments["query"].lower()
        limit = min(int(arguments.get("limit", 20)), 50)
        all_t = [_stix_to_dict(t) for t in attack.get_techniques(include_subtechniques=True)]
        results = []
        for t in all_t:
            name = t.get("name", "").lower()
            desc = (t.get("description") or "").lower()
            if query in name or query in desc:
                results.append(_clean_technique(t))
        results.sort(key=lambda x: (0 if query in x["name"].lower() else 1))
        return {"query": arguments["query"], "results": results[:limit], "total": len(results)}

    elif tool_name == "get_all_techniques":
        techniques = [_clean_technique(_stix_to_dict(t)) for t in attack.get_techniques(include_subtechniques=False)]
        techniques.sort(key=lambda x: x.get("id") or "")
        return {"techniques": techniques, "count": len(techniques)}

    elif tool_name == "get_all_subtechniques":
        all_t = [_stix_to_dict(t) for t in attack.get_techniques(include_subtechniques=True)]
        subs = [_clean_technique(t) for t in all_t if t.get("x_mitre_is_subtechnique")]
        subs.sort(key=lambda x: x.get("id") or "")
        return {"subtechniques": subs, "count": len(subs)}

    elif tool_name == "get_techniques_by_tactic":
        tactic = arguments["tactic"].lower().replace(" ", "-")
        include_subs = bool(arguments.get("include_subtechniques", True))
        all_t = [_stix_to_dict(t) for t in attack.get_techniques(include_subtechniques=include_subs)]
        results = []
        for t in all_t:
            phases = [k.get("phase_name", "").lower() for k in t.get("kill_chain_phases", [])]
            if tactic in phases:
                results.append(_clean_technique(t))
        results.sort(key=lambda x: x.get("id") or "")
        return {"tactic": tactic, "techniques": results, "count": len(results)}

    elif tool_name == "get_techniques_by_platform":
        platform = arguments["platform"]
        include_subs = bool(arguments.get("include_subtechniques", False))
        all_t = [_stix_to_dict(t) for t in attack.get_techniques(include_subtechniques=include_subs)]
        results = []
        for t in all_t:
            plats = [p.lower() for p in t.get("x_mitre_platforms", [])]
            if platform.lower() in plats:
                results.append(_clean_technique(t))
        results.sort(key=lambda x: x.get("id") or "")
        return {"platform": platform, "techniques": results, "count": len(results)}

    elif tool_name == "get_subtechniques_of_technique":
        tid = arguments["technique_id"].upper()
        stix_id = _resolve_technique_stix_id(attack, tid)
        if not stix_id:
            return {"error": f"Technique {tid} not found"}
        subs = [_clean_technique(_stix_to_dict(t)) for t in attack.get_subtechniques_of_technique(stix_id)]
        return {"parent_id": tid, "subtechniques": subs, "count": len(subs)}

    elif tool_name == "get_technique_tactics":
        tid = arguments["technique_id"].upper()
        all_t = [_stix_to_dict(t) for t in attack.get_techniques(include_subtechniques=True)]
        for t in all_t:
            for ref in t.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").upper() == tid:
                    phases = [k.get("phase_name", "").replace("-", " ").title() for k in t.get("kill_chain_phases", [])]
                    return {"technique_id": tid, "tactics": phases}
        return {"error": f"Technique {tid} not found"}

    # ── Groups ────────────────────────────────────────────────
    elif tool_name == "get_all_groups":
        groups = [_clean_group(_stix_to_dict(g)) for g in attack.get_groups()]
        groups.sort(key=lambda x: x.get("name") or "")
        return {"groups": groups, "count": len(groups)}

    elif tool_name == "get_group_by_name":
        name = arguments["name"]
        stix_id = _resolve_group_stix_id(attack, name)
        if not stix_id:
            return {"error": f"Group '{name}' not found"}
        groups = [_stix_to_dict(g) for g in attack.get_groups()]
        g = next((g for g in groups if g["id"] == stix_id), None)
        return _clean_group(g) if g else {"error": "Not found"}

    elif tool_name == "search_groups":
        query = arguments["query"].lower()
        limit = min(int(arguments.get("limit", 20)), 50)
        groups = [_clean_group(_stix_to_dict(g)) for g in attack.get_groups()]
        results = [
            g for g in groups
            if query in g.get("name", "").lower()
            or any(query in a.lower() for a in g.get("aliases", []))
            or query in g.get("description", "").lower()
        ]
        return {"query": arguments["query"], "results": results[:limit], "total": len(results)}

    elif tool_name == "get_groups_using_technique":
        tid = arguments["technique_id"].upper()
        stix_id = _resolve_technique_stix_id(attack, tid)
        if not stix_id:
            return {"error": f"Technique {tid} not found"}
        groups = [_clean_group(_stix_to_dict(g)) for g in attack.get_groups_using_technique(stix_id)]
        return {"technique_id": tid, "groups": groups, "count": len(groups)}

    elif tool_name == "get_techniques_used_by_group":
        group_ref = arguments["group_id"]
        stix_id = _resolve_group_stix_id(attack, group_ref)
        if not stix_id:
            return {"error": f"Group '{group_ref}' not found"}
        techniques = [_clean_technique(_stix_to_dict(t)) for t in attack.get_techniques_used_by_group(stix_id)]
        techniques.sort(key=lambda x: x.get("id") or "")
        return {"group": group_ref, "techniques": techniques, "count": len(techniques)}

    elif tool_name == "get_software_used_by_group":
        group_ref = arguments["group_id"]
        stix_id = _resolve_group_stix_id(attack, group_ref)
        if not stix_id:
            return {"error": f"Group '{group_ref}' not found"}
        software = [_clean_software(_stix_to_dict(s)) for s in attack.get_software_used_by_group(stix_id)]
        return {"group": group_ref, "software": software, "count": len(software)}

    # ── Software ──────────────────────────────────────────────
    elif tool_name == "get_all_software":
        software = [_clean_software(_stix_to_dict(s)) for s in attack.get_software()]
        software.sort(key=lambda x: x.get("name") or "")
        return {"software": software, "count": len(software)}

    elif tool_name == "search_software":
        query = arguments["query"].lower()
        limit = min(int(arguments.get("limit", 20)), 50)
        software = [_clean_software(_stix_to_dict(s)) for s in attack.get_software()]
        results = [
            s for s in software
            if query in s.get("name", "").lower()
            or any(query in a.lower() for a in s.get("aliases", []))
            or query in s.get("description", "").lower()
        ]
        return {"query": arguments["query"], "results": results[:limit], "total": len(results)}

    elif tool_name == "get_software_using_technique":
        tid = arguments["technique_id"].upper()
        stix_id = _resolve_technique_stix_id(attack, tid)
        if not stix_id:
            return {"error": f"Technique {tid} not found"}
        software = [_clean_software(_stix_to_dict(s)) for s in attack.get_software_using_technique(stix_id)]
        return {"technique_id": tid, "software": software, "count": len(software)}

    # ── Mitigations ────────────────────────────────────────────
    elif tool_name == "get_all_mitigations":
        mitigations = [_clean_mitigation(_stix_to_dict(m)) for m in attack.get_mitigations()]
        mitigations.sort(key=lambda x: x.get("id") or "")
        return {"mitigations": mitigations, "count": len(mitigations)}

    elif tool_name == "get_mitigations_for_technique":
        tid = arguments["technique_id"].upper()
        stix_id = _resolve_technique_stix_id(attack, tid)
        if not stix_id:
            return {"error": f"Technique {tid} not found"}
        mitigations = [_clean_mitigation(_stix_to_dict(m)) for m in attack.get_mitigations_mitigating_technique(stix_id)]
        return {"technique_id": tid, "mitigations": mitigations, "count": len(mitigations)}

    elif tool_name == "get_techniques_mitigated_by":
        mid = arguments["mitigation_id"].upper()
        all_m = [_stix_to_dict(m) for m in attack.get_mitigations()]
        stix_id = None
        for m in all_m:
            for ref in m.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").upper() == mid:
                    stix_id = m["id"]
                    break
        if not stix_id:
            return {"error": f"Mitigation {mid} not found"}
        techniques = [_clean_technique(_stix_to_dict(t)) for t in attack.get_techniques_mitigated_by_mitigation(stix_id)]
        return {"mitigation_id": mid, "techniques": techniques, "count": len(techniques)}

    # ── Campaigns ─────────────────────────────────────────────
    elif tool_name == "get_all_campaigns":
        try:
            campaigns = [_clean_campaign(_stix_to_dict(c)) for c in attack.get_campaigns()]
        except Exception:
            campaigns = []
        campaigns.sort(key=lambda x: x.get("name") or "")
        return {"campaigns": campaigns, "count": len(campaigns), "domain": domain_meta["label"]}

    elif tool_name == "get_campaigns_using_technique":
        tid = arguments["technique_id"].upper()
        stix_id = _resolve_technique_stix_id(attack, tid)
        if not stix_id:
            return {"error": f"Technique {tid} not found"}
        try:
            campaigns = [_clean_campaign(_stix_to_dict(c)) for c in attack.get_campaigns_using_technique(stix_id)]
        except Exception:
            campaigns = []
        return {"technique_id": tid, "campaigns": campaigns, "count": len(campaigns)}

    # ── Data Sources ───────────────────────────────────────────
    elif tool_name == "get_all_datasources":
        datasources = attack.get_datasources()
        result = []
        for ds in datasources:
            d = _stix_to_dict(ds)
            result.append({
                "stix_id": d.get("id"),
                "name": d.get("name"),
                "description": (d.get("description") or "")[:300],
                "platforms": d.get("x_mitre_platforms", []),
                "collection_layers": d.get("x_mitre_collection_layers", []),
            })
        result.sort(key=lambda x: x.get("name") or "")
        return {"datasources": result, "count": len(result)}

    elif tool_name == "get_datasources_detecting_technique":
        tid = arguments["technique_id"].upper()
        stix_id = _resolve_technique_stix_id(attack, tid)
        if not stix_id:
            return {"error": f"Technique {tid} not found"}
        # Get the technique and extract x_mitre_data_sources
        all_t = [_stix_to_dict(t) for t in attack.get_techniques(include_subtechniques=True)]
        tech = next((t for t in all_t if t["id"] == stix_id), None)
        if not tech:
            return {"error": "Technique STIX object not found"}
        data_sources = tech.get("x_mitre_data_sources", [])
        detection = tech.get("x_mitre_detection", "")
        return {
            "technique_id": tid,
            "data_sources": data_sources,
            "detection_notes": detection[:600] if detection else None,
        }

    # ── Navigator Layer ────────────────────────────────────────
    elif tool_name == "generate_layer":
        scope = arguments.get("scope", "all")
        value = arguments.get("value", "")
        layer_name = arguments.get("name", "SOCIS Layer")
        color = arguments.get("color", "#0ff0fc")

        techniques_to_highlight = []

        if scope == "all":
            all_t = [_clean_technique(_stix_to_dict(t)) for t in attack.get_techniques(include_subtechniques=True)]
            techniques_to_highlight = [t for t in all_t if t.get("id")]

        elif scope == "group":
            stix_id = _resolve_group_stix_id(attack, value)
            if not stix_id:
                return {"error": f"Group '{value}' not found"}
            techniques_to_highlight = [
                _clean_technique(_stix_to_dict(t))
                for t in attack.get_techniques_used_by_group(stix_id)
            ]

        elif scope == "tactic":
            tactic = value.lower().replace(" ", "-")
            all_t = [_stix_to_dict(t) for t in attack.get_techniques(include_subtechniques=True)]
            techniques_to_highlight = [
                _clean_technique(t) for t in all_t
                if any(k.get("phase_name", "").lower() == tactic for k in t.get("kill_chain_phases", []))
            ]

        elif scope == "platform":
            all_t = [_stix_to_dict(t) for t in attack.get_techniques(include_subtechniques=True)]
            techniques_to_highlight = [
                _clean_technique(t) for t in all_t
                if value.lower() in [p.lower() for p in t.get("x_mitre_platforms", [])]
            ]

        layer = {
            "name": layer_name,
            "versions": {"attack": domain_meta["version"], "navigator": "5", "layer": "4.5"},
            "domain": domain_meta["navigator_domain"],
            "description": f"Generated by SOCIS-AI-PT — scope: {scope}" + (f" ({value})" if value else ""),
            "techniques": [
                {
                    "techniqueID": t["id"],
                    "color": color,
                    "comment": t.get("name", ""),
                    "enabled": True,
                    "showSubtechniques": t.get("is_subtechnique", False),
                }
                for t in techniques_to_highlight if t.get("id")
            ],
            "gradient": {
                "colors": ["#ffffff", color],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [{"label": scope + (f": {value}" if value else ""), "color": color}],
            "metadata": [],
            "links": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#1a1a2e",
            "hideDisabled": False,
        }
        return {
            "layer": layer,
            "technique_count": len(layer["techniques"]),
            "navigator_url": "https://mitre-attack.github.io/attack-navigator/",
            "instructions": "Copy the 'layer' JSON and upload it to the ATT&CK Navigator URL above.",
        }

    else:
        raise ValueError(f"Unknown tool: {tool_name}")


# ─── MCP JSON-RPC Endpoint ────────────────────────────────────

@app.post("/mcp")
async def mcp_endpoint(request: Request):
    if not verify_mcp_auth(request):
        return mcp_auth_error()
    try:
        body = await request.json()
        req_id = body.get("id")
        method = body.get("method")
        params = body.get("params", {})

        if method == "initialize":
            return JSONResponse({
                "jsonrpc": "2.0", "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": MCP_VERSION},
                },
            })

        elif method == "tools/list":
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}})

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            result = await handle_tool(tool_name, arguments)
            return JSONResponse({
                "jsonrpc": "2.0", "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2, default=str)}]},
            })

        else:
            return JSONResponse({
                "jsonrpc": "2.0", "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            })

    except Exception as e:
        logger.exception(f"[MITRE MCP] Error: {e}")
        return JSONResponse({
            "jsonrpc": "2.0", "id": None,
            "error": {"code": -32603, "message": str(e)},
        }, status_code=500)


@app.get("/health")
async def health():
    domains_status = {}
    for d in _DOMAIN_META:
        if d in _attack_cache:
            domains_status[d] = "ok"
        elif d in _load_errors:
            domains_status[d] = f"error: {_load_errors[d][:80]}"
        else:
            domains_status[d] = "not loaded"
    overall = "ok" if any(v == "ok" for v in domains_status.values()) else "error"
    return {"status": overall, "server": SERVER_NAME, "domains": domains_status}


@app.on_event("startup")
async def startup():
    """Pre-load all three ATT&CK domains in background threads so startup is non-blocking."""
    import asyncio
    loop = asyncio.get_event_loop()
    for domain in _DOMAIN_META:
        loop.run_in_executor(None, lambda d=domain: _get_attack(d))


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8105, log_level="info")
