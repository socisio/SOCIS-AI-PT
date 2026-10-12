"""
SOCIS-AI-PT — API Key Management Routes
Create / list / revoke API keys for machine-to-machine access.
"""

import logging
from datetime import datetime, timezone
from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import require_permission
from app.models.api_key import APIKey

logger = logging.getLogger(__name__)
router = APIRouter()


# ─── Schemas ──────────────────────────────────────────────────

class APIKeyCreate(BaseModel):
    name: str
    expires_at: Optional[datetime] = None


class APIKeyResponse(BaseModel):
    id: UUID
    name: str
    prefix: str
    is_active: bool
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class APIKeyCreatedResponse(APIKeyResponse):
    """Returned only on creation — includes the raw key (shown once)."""
    raw_key: str


# ─── Endpoints ────────────────────────────────────────────────

@router.post("/", response_model=APIKeyCreatedResponse, status_code=201)
async def create_api_key(
    data: APIKeyCreate,
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new API key. The raw key is returned only once — store it securely."""
    # Hardening (M-4): an API key must not be able to mint/revoke API keys,
    # otherwise one stolen key could create persistent backdoor keys.
    if token.get("via_api_key"):
        raise HTTPException(status_code=403, detail="API keys cannot manage API keys; use an interactive login")
    raw_key, key_hash = APIKey.generate()
    api_key = APIKey(
        user_id=UUID(token["sub"]),
        name=data.name,
        key_hash=key_hash,
        prefix=raw_key[:12],
        expires_at=data.expires_at,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    logger.info(f"API key created: {api_key.prefix}... by user {token['sub']}")
    return APIKeyCreatedResponse(
        id=api_key.id,
        name=api_key.name,
        prefix=api_key.prefix,
        is_active=api_key.is_active,
        last_used_at=api_key.last_used_at,
        expires_at=api_key.expires_at,
        created_at=api_key.created_at,
        raw_key=raw_key,
    )


@router.get("/", response_model=List[APIKeyResponse])
async def list_api_keys(
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """List all API keys for the authenticated user (raw keys never shown)."""
    result = await db.execute(
        select(APIKey).where(APIKey.user_id == UUID(token["sub"])).order_by(APIKey.created_at.desc())
    )
    return result.scalars().all()


@router.post("/{key_id}/regenerate", response_model=APIKeyCreatedResponse)
async def regenerate_api_key(
    key_id: UUID,
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Rotate an existing key in place: same name/expiry/row, a brand-new secret. The old secret stops working
    immediately; the new raw key is returned once (same shown-once model as creation — the raw key is never stored,
    only its hash, so it can't be re-displayed later).

    This is "regenerate", not "create new": the key keeps its identity (id, name, created_at), so anything referencing
    it by name/id in your records stays coherent — you just swap the secret. Reactivates the key if it was revoked.
    """
    if token.get("via_api_key"):
        raise HTTPException(status_code=403, detail="API keys cannot manage API keys; use an interactive login")
    result = await db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.user_id == UUID(token["sub"]))
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    raw_key, key_hash = APIKey.generate()
    api_key.key_hash = key_hash
    api_key.prefix = raw_key[:12]
    api_key.is_active = True           # regenerating a revoked key brings it back with a fresh secret
    api_key.last_used_at = None        # usage history doesn't carry across a secret rotation
    await db.commit()
    await db.refresh(api_key)
    logger.info(f"API key regenerated: {api_key.prefix}... by user {token['sub']}")
    return APIKeyCreatedResponse(
        id=api_key.id,
        name=api_key.name,
        prefix=api_key.prefix,
        is_active=api_key.is_active,
        last_used_at=api_key.last_used_at,
        expires_at=api_key.expires_at,
        created_at=api_key.created_at,
        raw_key=raw_key,
    )


@router.delete("/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: UUID,
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Revoke (deactivate) an API key."""
    # Hardening (M-4): an API key must not be able to mint/revoke API keys,
    # otherwise one stolen key could create persistent backdoor keys.
    if token.get("via_api_key"):
        raise HTTPException(status_code=403, detail="API keys cannot manage API keys; use an interactive login")
    result = await db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.user_id == UUID(token["sub"]))
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    api_key.is_active = False
    await db.commit()
    logger.info(f"API key revoked: {api_key.prefix}... by user {token['sub']}")
