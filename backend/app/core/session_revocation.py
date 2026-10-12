"""Per-user session revocation ("sign this user out now").

JWT access tokens carry their role and are valid for JWT_ACCESS_TOKEN_EXPIRE_MINUTES (60 by default), and the
permission check reads the role from the token. Without this, deactivating, demoting or deleting a user took
effect only when their token expired. An admin action now writes a Redis marker holding the revocation time;
a token issued at or before that moment is rejected.

Pure logic lives here (testable without Redis); redis is passed in. token_blocklist.py wraps these helpers.
"""
from __future__ import annotations

import time
from typing import Optional

ACCESS_KEY = "user_access_revoked:{uid}"
REFRESH_KEY = "user_refresh_revoked:{uid}"


def is_revoked(issued_at, revoked_at) -> bool:
    """True if a revocation marker exists and the token was issued at or before it.

    A token with no `iat` (issued before this feature existed) counts as issued at 0, so it is revoked too.
    """
    if revoked_at is None:
        return False
    try:
        iat = int(issued_at or 0)
    except (TypeError, ValueError):
        iat = 0
    return iat <= int(revoked_at)


async def revoke_user_sessions(redis, user_id, *, access_ttl: int, refresh_ttl: Optional[int] = None,
                               now: Optional[int] = None) -> int:
    """Revoke the user's access tokens (and refresh tokens when refresh_ttl is given). Returns the marker."""
    marker = int(now if now is not None else time.time())
    await redis.setex(ACCESS_KEY.format(uid=user_id), int(access_ttl), str(marker))
    if refresh_ttl:
        await redis.setex(REFRESH_KEY.format(uid=user_id), int(refresh_ttl), str(marker))
    return marker


async def user_session_revoked(redis, user_id, issued_at, *, refresh: bool = False) -> bool:
    if not user_id:
        return False
    raw = await redis.get((REFRESH_KEY if refresh else ACCESS_KEY).format(uid=user_id))
    return is_revoked(issued_at, int(raw) if raw is not None else None)
