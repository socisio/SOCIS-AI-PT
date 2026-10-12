from typing import Optional
"""
SOCIS-AI-PT — JWT Token Blocklist
Redis-backed store for revoked token JTIs.
"""

import redis.asyncio as aioredis
from app.config import settings

_redis: aioredis.Redis | None = None


async def get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.REDIS_URL or "redis://localhost:6379", decode_responses=True)
    return _redis


async def block_token(jti: str, expires_in_seconds: int) -> None:
    """Mark a JWT JTI as revoked until its natural expiry."""
    r = await get_redis()
    await r.setex(f"blocked_jwt:{jti}", expires_in_seconds, "1")


async def is_token_blocked(jti: str) -> bool:
    """Return True if the JTI has been revoked."""
    r = await get_redis()
    return await r.exists(f"blocked_jwt:{jti}") > 0


# ─── Per-user session revocation (admin deactivate / role change / delete / password reset) ───
async def revoke_user_sessions(user_id: str, include_refresh: bool = False, now: Optional[int] = None) -> None:
    """Sign a user out everywhere: their existing access tokens (and, optionally, refresh tokens) stop working now."""
    from app.core import session_revocation as sr
    r = await get_redis()
    await sr.revoke_user_sessions(
        r, str(user_id),
        access_ttl=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60 + 60,
        refresh_ttl=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60 if include_refresh else None,
        now=now,
    )


async def is_user_session_revoked(user_id, issued_at, refresh: bool = False) -> bool:
    from app.core import session_revocation as sr
    r = await get_redis()
    return await sr.user_session_revoked(r, str(user_id) if user_id else "", issued_at, refresh=refresh)


# ─── Login lockout (fix L-7) ─────────────────────────────────
# Per-identifier failed-login throttling to complement IP rate limiting.
_LOCKOUT_THRESHOLD = 5          # failed attempts before lockout
_LOCKOUT_WINDOW_SECONDS = 900   # 15 minutes rolling window / lockout duration


async def record_failed_login(identifier: str) -> int:
    """Increment the failed-login counter for an identifier. Returns the count."""
    r = await get_redis()
    key = f"login_fail:{(identifier or '').lower()}"
    count = await r.incr(key)
    if count == 1:
        await r.expire(key, _LOCKOUT_WINDOW_SECONDS)
    return int(count)


async def is_login_locked(identifier: str) -> bool:
    """Return True if the identifier has exceeded the failed-login threshold."""
    r = await get_redis()
    key = f"login_fail:{(identifier or '').lower()}"
    val = await r.get(key)
    try:
        return int(val) >= _LOCKOUT_THRESHOLD if val is not None else False
    except (TypeError, ValueError):
        return False


async def clear_failed_logins(identifier: str) -> None:
    """Reset the failed-login counter after a successful login."""
    r = await get_redis()
    await r.delete(f"login_fail:{(identifier or '').lower()}")


# ─── Concurrency limiter (fix PERF-7) ────────────────────────
# Caps simultaneous long-lived operations (e.g. AI chat SSE streams) across all
# backend workers using a shared Redis counter, so a flood of concurrent chats
# can't exhaust the worker pool / overwhelm the LLM endpoint.
import contextlib


class ConcurrencyLimitExceeded(Exception):
    def __init__(self, limit: int):
        self.limit = limit
        super().__init__(f"Concurrency limit of {limit} reached")


@contextlib.asynccontextmanager
async def concurrency_slot(key: str, limit: int, ttl: int = 900):
    """Acquire one slot under `key` (max `limit`), releasing on exit.

    Uses a Redis counter with a TTL safety-net so a crashed request can't leak a
    slot forever. Raises ConcurrencyLimitExceeded if no slot is free.
    """
    if limit <= 0:
        # Disabled → no limiting.
        yield
        return
    r = await get_redis()
    rkey = f"concurrency:{key}"
    current = await r.incr(rkey)
    if current == 1:
        await r.expire(rkey, ttl)
    try:
        if current > limit:
            await r.decr(rkey)
            raise ConcurrencyLimitExceeded(limit)
        yield
    finally:
        # Only decrement if we actually held a slot (not the over-limit case,
        # which already decremented before raising).
        if current <= limit:
            try:
                await r.decr(rkey)
            except Exception:
                pass
