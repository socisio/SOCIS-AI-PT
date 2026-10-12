"""
SOCIS-AI-PT — Chat Session Routes
CRUD for AI Security Assistant conversations, persisted per user in the DB.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete

from app.core.database import get_db
from app.core.security import require_permission
from app.models.chat_session import ChatSession
from app.models.chat_session_artifact import ChatSessionArtifact

router = APIRouter()


# ─── Pydantic Schemas ────────────────────────────────────────

class MessageSchema(BaseModel):
    id: str
    role: str
    content: str
    timestamp: str


class ChatSessionCreate(BaseModel):
    title: Optional[str] = "New Chat"
    provider: Optional[str] = "ollama_remote"
    model_name: Optional[str] = None
    messages: List[dict] = Field(default_factory=list)


class ChatSessionUpdate(BaseModel):
    title: Optional[str] = None
    provider: Optional[str] = None
    model_name: Optional[str] = None
    messages: Optional[List[dict]] = None


class ChatSessionResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    title: str
    provider: str
    model_name: Optional[str]
    messages: List[dict]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ChatSessionListResponse(BaseModel):
    sessions: List[ChatSessionResponse]
    total: int


class ChatSessionArtifactsUpdate(BaseModel):
    pinned_message_ids: List[str] = Field(default_factory=list)
    report_message_ids: List[str] = Field(default_factory=list)
    action_tasks: List[dict] = Field(default_factory=list)
    activity_events: List[dict] = Field(default_factory=list)


class ChatSessionArtifactsResponse(ChatSessionArtifactsUpdate):
    session_id: uuid.UUID
    updated_at: datetime


# ─── Helpers ─────────────────────────────────────────────────

def _user_id(token: dict) -> uuid.UUID:
    return uuid.UUID(str(token["sub"]))


def _derive_title(messages: List[dict]) -> str:
    """Use the first user message (truncated) as the session title."""
    for msg in messages:
        if msg.get("role") == "user" and msg.get("content", "").strip():
            text = msg["content"].strip()
            return (text[:60] + "…") if len(text) > 60 else text
    return "New Chat"


async def _get_owned_session_or_404(
    db: AsyncSession,
    session_id: uuid.UUID,
    uid: uuid.UUID,
) -> ChatSession:
    result = await db.execute(
        select(ChatSession).where(
            ChatSession.id == session_id,
            ChatSession.user_id == uid,
        )
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Chat session not found")
    return session


async def _get_or_create_artifacts(db: AsyncSession, session_id: uuid.UUID) -> ChatSessionArtifact:
    result = await db.execute(
        select(ChatSessionArtifact).where(ChatSessionArtifact.session_id == session_id)
    )
    artifacts = result.scalar_one_or_none()
    if artifacts:
        return artifacts

    artifacts = ChatSessionArtifact(
        session_id=session_id,
        pinned_message_ids=[],
        report_message_ids=[],
        action_tasks=[],
        activity_events=[],
    )
    db.add(artifacts)
    await db.flush()
    return artifacts


# ─── Routes ──────────────────────────────────────────────────

@router.get("/", response_model=ChatSessionListResponse)
async def list_sessions(
    token: dict = Depends(require_permission("llm:chat")),
    db: AsyncSession = Depends(get_db),
):
    """Return all chat sessions for the authenticated user, newest first."""
    uid = _user_id(token)
    result = await db.execute(
        select(ChatSession)
        .where(ChatSession.user_id == uid)
        .order_by(ChatSession.updated_at.desc())
    )
    sessions = result.scalars().all()
    return {"sessions": sessions, "total": len(sessions)}


@router.post("/", response_model=ChatSessionResponse, status_code=201)
async def create_session(
    body: ChatSessionCreate,
    token: dict = Depends(require_permission("llm:chat")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new chat session."""
    uid = _user_id(token)
    title = body.title or _derive_title(body.messages or [])
    session = ChatSession(
        id=uuid.uuid4(),
        user_id=uid,
        title=title,
        provider=body.provider or "ollama_remote",
        model_name=body.model_name,
        messages=body.messages or [],
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)
    return session


@router.get("/{session_id}", response_model=ChatSessionResponse)
async def get_session(
    session_id: uuid.UUID,
    token: dict = Depends(require_permission("llm:chat")),
    db: AsyncSession = Depends(get_db),
):
    """Get a single chat session (must belong to the authenticated user)."""
    uid = _user_id(token)
    session = await _get_owned_session_or_404(db, session_id, uid)
    return session


@router.put("/{session_id}", response_model=ChatSessionResponse)
async def update_session(
    session_id: uuid.UUID,
    body: ChatSessionUpdate,
    token: dict = Depends(require_permission("llm:chat")),
    db: AsyncSession = Depends(get_db),
):
    """Update messages, title, provider, or model for an existing session."""
    uid = _user_id(token)
    session = await _get_owned_session_or_404(db, session_id, uid)

    if body.messages is not None:
        session.messages = body.messages
        # Auto-update title from first user message if still default
        if session.title in ("New Chat", "") or body.title:
            session.title = body.title or _derive_title(body.messages)
    if body.title is not None:
        session.title = body.title
    if body.provider is not None:
        session.provider = body.provider
    if body.model_name is not None:
        session.model_name = body.model_name

    session.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(session)
    return session


@router.delete("/{session_id}", status_code=204)
async def delete_session(
    session_id: uuid.UUID,
    token: dict = Depends(require_permission("llm:chat")),
    db: AsyncSession = Depends(get_db),
):
    """Delete a chat session."""
    uid = _user_id(token)
    session = await _get_owned_session_or_404(db, session_id, uid)
    await db.delete(session)
    await db.commit()


@router.get("/{session_id}/artifacts", response_model=ChatSessionArtifactsResponse)
async def get_session_artifacts(
    session_id: uuid.UUID,
    token: dict = Depends(require_permission("llm:chat")),
    db: AsyncSession = Depends(get_db),
):
    """Get persisted enterprise artifacts for a chat session."""
    uid = _user_id(token)
    await _get_owned_session_or_404(db, session_id, uid)
    artifacts = await _get_or_create_artifacts(db, session_id)
    await db.commit()
    await db.refresh(artifacts)
    return ChatSessionArtifactsResponse(
        session_id=artifacts.session_id,
        pinned_message_ids=artifacts.pinned_message_ids or [],
        report_message_ids=artifacts.report_message_ids or [],
        action_tasks=artifacts.action_tasks or [],
        activity_events=artifacts.activity_events or [],
        updated_at=artifacts.updated_at,
    )


@router.put("/{session_id}/artifacts", response_model=ChatSessionArtifactsResponse)
async def update_session_artifacts(
    session_id: uuid.UUID,
    body: ChatSessionArtifactsUpdate,
    token: dict = Depends(require_permission("llm:chat")),
    db: AsyncSession = Depends(get_db),
):
    """Persist enterprise artifacts for a chat session."""
    uid = _user_id(token)
    await _get_owned_session_or_404(db, session_id, uid)
    artifacts = await _get_or_create_artifacts(db, session_id)
    artifacts.pinned_message_ids = body.pinned_message_ids
    artifacts.report_message_ids = body.report_message_ids
    artifacts.action_tasks = body.action_tasks
    artifacts.activity_events = body.activity_events
    artifacts.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(artifacts)
    return ChatSessionArtifactsResponse(
        session_id=artifacts.session_id,
        pinned_message_ids=artifacts.pinned_message_ids or [],
        report_message_ids=artifacts.report_message_ids or [],
        action_tasks=artifacts.action_tasks or [],
        activity_events=artifacts.activity_events or [],
        updated_at=artifacts.updated_at,
    )
