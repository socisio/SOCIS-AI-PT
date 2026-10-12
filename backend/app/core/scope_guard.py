"""The tool-call scope guard: one function that every path to the MCP tool servers calls before it touches a network target.

Who is the "scope" for a call?
  * inside a scan / workflow run (the worker sets a ScanScope): the project's authorized list, if the project enforces one;
  * otherwise (AI chat, MCP console, other API calls): the union of the authorized lists of the caller's projects that enforce
    one (an administrator: all projects). If the caller has no enforcing project, nothing is restricted.
A tool call with no target argument (CVE / EPSS / KEV lookups) is never blocked. See core/scope.py for what counts as a target.
"""
from __future__ import annotations

import logging
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import List, Optional

from app.core.scope import Entry, build_entries, decide, extract_targets

logger = logging.getLogger(__name__)


class ScopeViolation(Exception):
    """A tool call aimed at a target outside the authorized scope. str(exc) is safe to show to the user."""

    def __init__(self, target: str, message: str):
        super().__init__(message)
        self.target = target
        self.message = message


@dataclass
class ScanScope:
    project_id: Optional[str] = None
    project_name: str = ""
    entries: List[Entry] = field(default_factory=list)
    enforced: bool = True
    override: bool = False          # an administrator authorized this scan with a written reason (verified signature)
    user_id: Optional[str] = None
    scan_id: Optional[str] = None


_scan_scope: ContextVar[Optional[ScanScope]] = ContextVar("socis_scan_scope", default=None)
_identity: ContextVar[Optional[dict]] = ContextVar("socis_identity", default=None)
_source: ContextVar[str] = ContextVar("socis_scope_source", default="api")


def set_identity(payload: dict) -> None:
    _identity.set({"user_id": str(payload.get("sub") or ""), "role": str(payload.get("role") or "viewer")})


def set_source(name: str) -> None:
    _source.set(name)


def set_scan_scope(scope: Optional[ScanScope]):
    return _scan_scope.set(scope)


async def audit_standalone(action: str, user_id: Optional[str], resource_type: str, resource_id: Optional[str], details: dict) -> None:
    """Write an audit row in its OWN session and commit it. (A blocked request raises an HTTP error, which rolls the request's
    session back: the record of the attempt must survive that.) Never raises."""
    try:
        from app.core.audit import log_audit
        from app.core.database import async_session
        async with async_session() as s:
            uid = uuid.UUID(user_id) if user_id else None
            await log_audit(s, action=action, user_id=uid, resource_type=resource_type, resource_id=resource_id, details=details)
            await s.commit()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not write audit entry %s: %s", action, exc)


async def workspace_scope(user_id: str, role: str):
    """(any project enforces a scope, the union of those projects' entries) for a caller outside a scan."""
    from sqlalchemy import select
    from app.core.database import async_session
    from app.models.project import Project
    async with async_session() as s:
        q = select(Project.scope_targets).where(Project.scope_enforced.is_(True))
        if role != "admin":
            q = q.where(Project.owner_id == uuid.UUID(user_id))
        rows = (await s.execute(q)).scalars().all()
    return bool(rows), build_entries(t for lst in rows for t in (lst or []))


async def check_tool_call(tool_name: str, arguments: dict) -> None:
    """Raise ScopeViolation when a tool call targets something outside the authorized scope. Cheap when there is no target."""
    targets = extract_targets(arguments or {})
    if not targets:
        return
    ss = _scan_scope.get()
    ident = _identity.get()
    if ss is not None:
        if not ss.enforced or ss.override:
            return
        entries, project_id, project_name, uid, scan_id = ss.entries, ss.project_id, ss.project_name, ss.user_id, ss.scan_id
        where = f"project '{ss.project_name}'" if ss.project_name else "this project"
    else:
        if ident is None or not ident.get("user_id"):
            return                                   # internal call with no acting user (nothing to scope it to)
        try:
            enforced, entries = await workspace_scope(ident["user_id"], ident["role"])
        except Exception as exc:  # noqa: BLE001  -- a scope check that cannot run must not silently allow
            logger.error("Scope lookup failed, refusing the tool call: %s", exc)
            raise ScopeViolation(targets[0], "The authorized-scope check could not run, so this tool call was refused. Try again.")
        if not enforced:
            return
        project_id = project_name = scan_id = None
        uid = ident["user_id"]
        where = "your projects"
    for t in targets:
        d = decide(t, entries)
        if not d.allowed:
            msg = f"Blocked: {d.reason} for {where}. Ask an administrator to add it to the project's authorized scope."
            await audit_standalone("scope:blocked", uid, "project" if project_id else "tool", project_id or tool_name,
                                   {"target": d.target or t, "tool": tool_name, "source": _source.get() if ss is None else "scan",
                                    "scan_id": scan_id, "project_name": project_name})
            raise ScopeViolation(d.target or t, msg)
