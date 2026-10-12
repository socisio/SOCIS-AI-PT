"""
webhooks.py — CRUD endpoints for managing outbound webhooks.
"""

import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, HttpUrl
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import require_permission
from app.models.webhook import Webhook
from app.services.webhook_service import webhook_service
from app.core.encryption import encrypt_secret

router = APIRouter()


# ── Pydantic schemas ─────────────────────────────────────────────

class WebhookCreate(BaseModel):
    url: HttpUrl
    events: List[str]
    secret: Optional[str] = None
    description: Optional[str] = None
    is_active: bool = True


class WebhookUpdate(BaseModel):
    url: Optional[HttpUrl] = None
    events: Optional[List[str]] = None
    secret: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None


def _checked_url(url: str) -> str:
    """Refuse internal / non-public destinations when the webhook is SAVED, so the mistake is visible now (they are also
    re-checked at send time)."""
    from app.services.webhook_service import _validate_webhook_url
    try:
        _validate_webhook_url(url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"That URL is not allowed: {exc}")
    return url


def _checked_events(events):
    from app.core.webhook_events import validate_events
    try:
        return validate_events(events)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


class WebhookResponse(BaseModel):
    id: uuid.UUID
    url: str
    events: List[str]
    is_active: bool
    description: Optional[str]
    user_id: uuid.UUID

    model_config = {"from_attributes": True}


# ── Endpoints ────────────────────────────────────────────────────

@router.get("/", response_model=List[WebhookResponse])
async def list_webhooks(
    token: dict = Depends(require_permission("webhooks:read")),
    db: AsyncSession = Depends(get_db),
):
    """List all webhooks owned by the current user."""
    user_id = uuid.UUID(token["sub"])
    result = await db.execute(select(Webhook).where(Webhook.user_id == user_id))
    return [WebhookResponse.model_validate(wh) for wh in result.scalars().all()]


@router.post("/", response_model=WebhookResponse, status_code=status.HTTP_201_CREATED)
async def create_webhook(
    body: WebhookCreate,
    token: dict = Depends(require_permission("webhooks:write")),
    db: AsyncSession = Depends(get_db),
):
    """Register a new webhook endpoint."""
    user_id = uuid.UUID(token["sub"])
    wh = Webhook(
        user_id=user_id,
        url=_checked_url(str(body.url)),
        events=_checked_events(body.events),
        secret=encrypt_secret(body.secret) if body.secret else None,
        description=body.description,
        is_active=body.is_active,
    )
    db.add(wh)
    await db.commit()
    await db.refresh(wh)
    return WebhookResponse.model_validate(wh)


@router.get("/events")
async def list_webhook_events(token: dict = Depends(require_permission("webhooks:read"))):
    """The events the platform emits (declared before /{webhook_id} so "events" is not parsed as an id)."""
    from app.core.webhook_events import EVENTS
    return {"events": [{"name": n, "description": d} for n, d in EVENTS.items()]}


@router.get("/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(
    webhook_id: uuid.UUID,
    token: dict = Depends(require_permission("webhooks:read")),
    db: AsyncSession = Depends(get_db),
):
    wh = await _get_owned(db, webhook_id, token)
    return WebhookResponse.model_validate(wh)


@router.patch("/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(
    webhook_id: uuid.UUID,
    body: WebhookUpdate,
    token: dict = Depends(require_permission("webhooks:write")),
    db: AsyncSession = Depends(get_db),
):
    wh = await _get_owned(db, webhook_id, token)
    for field, value in body.model_dump(exclude_none=True).items():
        if field == "url":
            value = _checked_url(str(value))
        if field == "events":
            value = _checked_events(value)
        if field == "secret":
            value = encrypt_secret(value) if value else None
        setattr(wh, field, value)
    await db.commit()
    await db.refresh(wh)
    return WebhookResponse.model_validate(wh)


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(
    webhook_id: uuid.UUID,
    token: dict = Depends(require_permission("webhooks:write")),
    db: AsyncSession = Depends(get_db),
):
    wh = await _get_owned(db, webhook_id, token)
    await db.delete(wh)
    await db.commit()


@router.post("/{webhook_id}/ping", status_code=status.HTTP_200_OK)
async def ping_webhook(
    webhook_id: uuid.UUID,
    token: dict = Depends(require_permission("webhooks:write")),
    db: AsyncSession = Depends(get_db),
):
    """Send a test ping event to verify the webhook URL is reachable."""
    wh = await _get_owned(db, webhook_id, token)
    results = await webhook_service.test_one(
        str(wh.id), wh.url, wh.secret, {"message": "SOCIS-AI-PT webhook test ping", "webhook_id": str(wh.id)},
    )
    return {"results": results}


# ── Helpers ──────────────────────────────────────────────────────

async def _get_owned(db: AsyncSession, webhook_id: uuid.UUID, token: dict) -> Webhook:
    user_id = uuid.UUID(token["sub"])
    result = await db.execute(
        select(Webhook).where(Webhook.id == webhook_id, Webhook.user_id == user_id)
    )
    wh = result.scalar_one_or_none()
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return wh
