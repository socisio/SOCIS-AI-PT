"""Did a tool actually run? (pure: unit-tested, no database)

A scan stores each tool's output. When a tool could NOT run (the MCP server refused the target, timed out, was unreachable, or the
scope guard blocked it) the worker's helper returns {"output": "[!] ...", "success": False}, but the save code used to record
exit_code 0 regardless, and the report then said "No vulnerabilities identified" with a risk level of N/A: a scan that never ran
read like a clean result. These helpers classify the outcome from what is stored, so the worker records a failure as a failure and
the report can say so, including for scans stored before this fix.
"""
from __future__ import annotations

import json
from typing import Iterable, List, Optional

# the exact markers the worker's tool helper puts at the start of the output when the tool did not run
FAILURE_PREFIXES = (
    "[!] MCP error", "[!] Timed out", "[!] Failed to call MCP", "[!] BLOCKED", "[!] Tool call failed",
)


_DATA_KEYS = ("open_ports", "exploits", "results", "findings", "count", "vulnerabilities", "grade", "endpoints")


def _json_obj(raw: object) -> Optional[dict]:
    text = str(raw or "").lstrip()
    if not text.startswith("{"):
        return None
    try:
        d = json.loads(text)
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


def tool_skipped(raw_output: object, parsed_output: object = None) -> bool:
    """A tool that decided, on purpose and at once, that it does not apply to this target ({"skipped": true, "reason": ...}). Not a failure."""
    d = _json_obj(raw_output)
    return bool(d and d.get("skipped") is True)


def skip_reason(raw_output: object, limit: int = 220) -> str:
    d = _json_obj(raw_output)
    return str(d.get("reason", ""))[:limit] if d else ""


def exit_code_for(result_data: Optional[dict]) -> int:
    """The exit code to store for a tool result: the tool's own, else 0 for success and 1 for a failed call."""
    d = result_data or {}
    code = d.get("exit_code")
    if isinstance(code, int):
        return code
    return 1 if (d.get("success") is False or str(d.get("output") or "").lstrip().startswith(FAILURE_PREFIXES)) else 0


def tool_failed(raw_output: object, parsed_output: object = None, exit_code: object = None) -> bool:
    """True when the tool did not complete (works on results stored before the exit code was recorded correctly)."""
    if tool_skipped(raw_output, parsed_output):
        return False
    if isinstance(exit_code, int) and exit_code != 0:
        return True
    if isinstance(parsed_output, dict) and parsed_output.get("success") is False:
        return True
    if str(raw_output or "").lstrip().startswith(FAILURE_PREFIXES):
        return True
    # a tool can "succeed" (exit 0) and still only return an error object, e.g. {"error": "Assessment still in progress", "host": ...}
    d = _json_obj(raw_output)
    return bool(d and d.get("error") and not any(k in d for k in _DATA_KEYS))


def failure_reason(raw_output: object, limit: int = 220) -> str:
    """One readable line: the error, without the [!] marker."""
    d = _json_obj(raw_output)
    if d and d.get("error"):
        return str(d["error"])[:limit]
    first = str(raw_output or "").strip().splitlines()[0] if str(raw_output or "").strip() else ""
    return first.replace("[!]", "", 1).strip()[:limit]


def summarize(results: Iterable[dict]) -> dict:
    """results: dicts with 'tool_name', 'failed', 'failure_reason' and optionally 'skipped', 'skip_reason'.
    Skipped tools are neither failures nor successes: "did not run" means every tool that APPLIED failed."""
    rs: List[dict] = list(results)
    skipped = [r for r in rs if r.get("skipped")]
    failed = [r for r in rs if r.get("failed") and not r.get("skipped")]
    applicable = len(rs) - len(skipped)
    return {
        "total": len(rs), "applicable": applicable, "failed": len(failed), "skipped": len(skipped),
        "any_failed": bool(failed), "all_failed": applicable > 0 and len(failed) == applicable,
        "reasons": [f"{r.get('tool_name')}: {r.get('failure_reason')}" for r in failed[:5]],
        "skipped_reasons": [f"{r.get('tool_name')}: {r.get('skip_reason')}" for r in skipped[:5]],
    }
