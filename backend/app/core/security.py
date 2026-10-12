"""
SOCIS-AI-PT — Security Module
JWT token management, password hashing, RBAC, and OAuth helpers.
"""

import logging
import uuid as _uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Any
from enum import Enum

import jwt
from jwt import PyJWTError as JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Request, Cookie
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from app.config import settings

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    cookie_token: Optional[str] = Cookie(None, alias="access_token"),
) -> dict:
    """Resolve current user from Bearer header OR HttpOnly cookie.

    Enforces the Redis token blocklist (fix H-2): previously this dependency
    skipped the revocation check that require_permission performs, so tokens
    invalidated at logout still authenticated against /me, /profile,
    /change-password and /logout until natural expiry.
    """
    from app.core.token_blocklist import is_token_blocked, is_user_session_revoked

    tok = token or cookie_token
    if not tok:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(tok)
    _problem = access_token_problem(payload)
    if _problem:
        raise HTTPException(status_code=401, detail=_problem)
    jti = payload.get("jti")
    if jti and await is_token_blocked(jti):
        raise HTTPException(status_code=401, detail="Token has been revoked")
    if await is_user_session_revoked(payload.get("sub"), payload.get("iat")):
        raise HTTPException(status_code=401, detail="Session ended. Sign in again.")
    return payload


def require_permission(permission: str):
    """Dependency factory for route-level permission checks.
    Accepts Bearer JWT, HttpOnly cookie, or X-API-Key header.
    """
    async def permission_checker(
        bearer_token: Optional[str] = Depends(oauth2_scheme),
        cookie_token: Optional[str] = Cookie(None, alias="access_token"),
        api_key: Optional[str] = Depends(api_key_header),
    ):
        from app.core.token_blocklist import is_token_blocked, is_user_session_revoked

        def _check_payload(payload: dict, perm: str) -> dict:
            role = UserRole(payload.get("role", "viewer"))
            # Remember who is calling, so the tool-call scope guard can find their projects (see core/scope_guard.py).
            from app.core.scope_guard import set_identity
            set_identity(payload)
            if not check_permission(role, perm):
                raise HTTPException(status_code=403, detail=f"Insufficient permissions. Required: {perm}")
            return payload

        # Try Bearer JWT first
        if bearer_token:
            payload = decode_token(bearer_token)
            _problem = access_token_problem(payload)
            if _problem:
                raise HTTPException(status_code=401, detail=_problem)
            jti = payload.get("jti")
            if jti and await is_token_blocked(jti):
                raise HTTPException(status_code=401, detail="Token has been revoked")
            if await is_user_session_revoked(payload.get("sub"), payload.get("iat")):
                raise HTTPException(status_code=401, detail="Session ended. Sign in again.")
            return _check_payload(payload, permission)

        # Try HttpOnly cookie
        if cookie_token:
            try:
                payload = decode_token(cookie_token)
                _problem = access_token_problem(payload)
                if _problem:
                    raise HTTPException(status_code=401, detail=_problem)
                jti = payload.get("jti")
                if jti and await is_token_blocked(jti):
                    raise HTTPException(status_code=401, detail="Token has been revoked")
                if await is_user_session_revoked(payload.get("sub"), payload.get("iat")):
                    raise HTTPException(status_code=401, detail="Session ended. Sign in again.")
                return _check_payload(payload, permission)
            except JWTError:
                pass

        # Try X-API-Key
        if api_key:
            import hashlib
            from app.core.database import get_db as _get_db
            from sqlalchemy import select
            from app.models.api_key import APIKey
            from app.models.user import User

            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            async for session in _get_db():
                result = await session.execute(
                    select(APIKey).where(
                        APIKey.key_hash == key_hash,
                        APIKey.is_active == True,
                    )
                )
                key_obj = result.scalar_one_or_none()
                if not key_obj:
                    raise HTTPException(status_code=401, detail="Invalid API key")
                if key_obj.expires_at and key_obj.expires_at < datetime.now(timezone.utc):
                    raise HTTPException(status_code=401, detail="API key expired")
                key_obj.last_used_at = datetime.now(timezone.utc)
                await session.commit()
                user = await session.get(User, key_obj.user_id)
                if not user or not user.is_active:
                    raise HTTPException(status_code=401, detail="API key owner not found")
                role_name = user.roles[0].name if user.roles else "api_user"
                return _check_payload({
                    "sub": str(user.id),
                    "email": user.email,
                    "username": user.username,
                    "role": role_name,
                    "via_api_key": True,
                }, permission)

        raise HTTPException(
            status_code=401,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return permission_checker


# ─── Roles ────────────────────────────────────────────────────
class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    API_USER = "api_user"


# ─── Role Permissions ────────────────────────────────────────
ROLE_PERMISSIONS = {
    UserRole.ADMIN: {
        "users:read", "users:write", "users:delete",
        "projects:read", "projects:write", "projects:delete", "projects:scope",   # only admins change what a project is authorized to test
        "scans:read", "scans:write", "scans:execute", "scans:delete",
        "vulns:read", "vulns:write", "vulns:delete",
        "reports:read", "reports:write", "reports:delete",
        "llm:chat", "llm:configure",
        "tools:read", "tools:execute",
        "mcp:read", "mcp:write", "mcp:configure",
        "admin:access", "admin:settings", "admin:read", "admin:write", "admin:manage",
        "webhooks:read", "webhooks:write",
    },
    UserRole.ANALYST: {
        "projects:read", "projects:write", "projects:delete",
        "scans:read", "scans:write", "scans:execute", "scans:delete",
        "vulns:read", "vulns:write",
        "reports:read", "reports:write",
        "llm:chat",
        "tools:read", "tools:execute",
        "mcp:read",
        "webhooks:read", "webhooks:write",
    },
    UserRole.VIEWER: {
        "projects:read",
        "scans:read",
        "vulns:read",
        "reports:read",
    },
    UserRole.API_USER: {
        "scans:read", "scans:write", "scans:execute",
        "vulns:read",
        "reports:read", "reports:write",
        "tools:execute",
    },
}


# ─── Password Functions ──────────────────────────────────────
def hash_password(password: str) -> str:
    """Hash a password using argon2."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


from app.core.token_policy import access_token_problem


# ─── JWT Token Functions ─────────────────────────────────────
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token (includes unique jti for revocation)."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "type": "access", "jti": str(_uuid.uuid4()), "iat": int(datetime.now(timezone.utc).timestamp())})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_mfa_token(user_id: str, minutes: int = 5) -> str:
    """The short-lived token issued after a correct PASSWORD when MFA is on. It is NOT an access token (type "mfa"): the only
    thing it can do is be exchanged, together with a valid authenticator code, at /auth/mfa/verify-login."""
    now = datetime.now(timezone.utc)
    payload = {"sub": user_id, "type": "mfa", "mfa_pending": True, "jti": str(_uuid.uuid4()),
               "iat": int(now.timestamp()), "exp": now + timedelta(minutes=minutes)}
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(data: dict) -> str:
    """Create a JWT refresh token with JTI for revocation support."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh", "jti": str(_uuid.uuid4()), "iat": int(datetime.now(timezone.utc).timestamp())})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT token."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except JWTError as e:
        logger.warning(f"Invalid token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ─── Permission Check ────────────────────────────────────────
def check_permission(user_role: UserRole, required_permission: str) -> bool:
    """Check if a role has the required permission."""
    permissions = ROLE_PERMISSIONS.get(user_role, set())
    return required_permission in permissions
