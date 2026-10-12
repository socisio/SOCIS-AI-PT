"""Shared access to the tool manifest (tool_manifest.json) — the single source of truth for which MCP tools exist,
what inputs each takes, and how risky each is. The workflow builder renders its tool picker and per-tool forms from
this (served via the API), and the scan worker dispatches from it. Keeping both sides on one file is what makes
"the builder covers every tool" true and keeps it true (enforced by tests/test_tool_manifest.py).

The manifest is generated from the real MCP server schemas, so its field names and required flags are authoritative.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any, Dict, List, Optional

_MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "tool_manifest.json")


@lru_cache(maxsize=1)
def _load() -> Dict[str, Any]:
    with open(_MANIFEST_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def all_tools() -> List[Dict[str, Any]]:
    """Every tool entry: {server, action, label, category, needs, risk, offensive, hint, fields:[...]}."""
    return list(_load().get("tools", []))


def manifest_version() -> int:
    return int(_load().get("version", 0))


def native_actions() -> Dict[str, Any]:
    """Per server short-name, the actions its hand-written builder panel already renders natively. The builder appends
    every OTHER action the server has (from the tools list) to that panel's dropdown, driven by the manifest."""
    return dict(_load().get("native_actions", {}))


def tool_for(server: str, action: str) -> Optional[Dict[str, Any]]:
    for t in _load().get("tools", []):
        if t["server"] == server and t["action"] == action:
            return t
    return None


def is_known_action(server: str, action: str) -> bool:
    return tool_for(server, action) is not None


def required_fields(server: str, action: str) -> List[str]:
    t = tool_for(server, action)
    return [f["name"] for f in (t or {}).get("fields", []) if f.get("required")]


def field_names(server: str, action: str) -> List[str]:
    t = tool_for(server, action)
    return [f["name"] for f in (t or {}).get("fields", [])]


def is_offensive(server: str, action: str) -> bool:
    t = tool_for(server, action)
    return bool(t and t.get("offensive"))


def tools_by_server() -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for t in _load().get("tools", []):
        out.setdefault(t["server"], []).append(t)
    return out
