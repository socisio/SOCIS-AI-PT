"""
SOCIS-AI-PT — Audit Log Helper
"""

from __future__ import annotations

import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog


async def log_audit(
    db: AsyncSession,
    action: str,
    user_id: Optional[uuid.UUID] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[dict] = None,
    ip_address: Optional[str] = None,
) -> None:
    """
    Add an audit log entry to the current DB session.
    The caller's session commit (via get_db) will persist it automatically.
    """
    entry = AuditLog(
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details or {},
        ip_address=ip_address,
    )
    db.add(entry)
