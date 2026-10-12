"""
notifications.py — In-app notification endpoints.
"""

import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import require_permission
from app.models.notification import Notification

router = APIRouter()


# ── Pydantic schemas ─────────────────────────────────────────────

class NotificationResponse(BaseModel):
    id: uuid.UUID
    type: str
    title: str
    message: Optional[str]
    resource_type: Optional[str]
    resource_id: Optional[str]
    is_read: bool
    created_at: str

    model_config = {"from_attributes": True}


# ── Endpoints ────────────────────────────────────────────────────

@router.get("/", response_model=List[NotificationResponse])
async def list_notifications(
    unread_only: bool = False,
    limit: int = 50,
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """List notifications for the current user."""
    user_id = uuid.UUID(token["sub"])
    query = (
        select(Notification)
        .where(Notification.user_id == user_id)
        .order_by(Notification.created_at.desc())
        .limit(limit)
    )
    if unread_only:
        query = query.where(Notification.is_read == False)

    result = await db.execute(query)
    notifications = result.scalars().all()
    return [
        NotificationResponse(
            id=n.id,
            type=n.type,
            title=n.title,
            message=n.message,
            resource_type=n.resource_type,
            resource_id=n.resource_id,
            is_read=n.is_read,
            created_at=n.created_at.isoformat(),
        )
        for n in notifications
    ]


@router.get("/unread-count")
async def unread_count(
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Return the count of unread notifications."""
    from sqlalchemy import func
    user_id = uuid.UUID(token["sub"])
    result = await db.execute(
        select(func.count())
        .select_from(Notification)
        .where(Notification.user_id == user_id, Notification.is_read == False)
    )
    return {"unread": result.scalar() or 0}


@router.post("/{notification_id}/read", status_code=status.HTTP_200_OK)
async def mark_read(
    notification_id: uuid.UUID,
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Mark a single notification as read."""
    user_id = uuid.UUID(token["sub"])
    await db.execute(
        update(Notification)
        .where(Notification.id == notification_id, Notification.user_id == user_id)
        .values(is_read=True)
    )
    await db.commit()
    return {"status": "ok"}


@router.post("/read-all", status_code=status.HTTP_200_OK)
async def mark_all_read(
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Mark all notifications as read for the current user."""
    user_id = uuid.UUID(token["sub"])
    await db.execute(
        update(Notification)
        .where(Notification.user_id == user_id, Notification.is_read == False)
        .values(is_read=True)
    )
    await db.commit()
    return {"status": "ok"}
