"""Which JWTs may be used as an ACCESS token.

The login flow issues short-lived tokens that are NOT access tokens: a 5-minute "mfa" token that only proves the password was
right, and 7-day "refresh" tokens. decode_token() accepts any validly signed JWT, and the permission checks read `role` from the
payload (defaulting to "viewer"), so before this policy existed:
  * the mfa token worked as a viewer-level access token, and /auth/mfa/setup (needs only scans:read) would replace the user's
    authenticator secret even when MFA was already on => full MFA bypass with just the password;
  * a refresh token worked as a 7-day access token.
Every place that accepts a bearer or cookie token must call access_token_problem() first.
"""
from __future__ import annotations

from typing import Optional


def access_token_problem(payload: dict) -> Optional[str]:
    """Return a user-safe reason this token must NOT be accepted as an access token, or None if it may be."""
    t = payload.get("type")
    if payload.get("mfa_pending") or t == "mfa":
        return "Two-step verification is not complete"
    if t is not None and t != "access":
        return "Invalid token type"           # e.g. a refresh token presented as a bearer token
    return None                               # "access", or a legacy token that predates the `type` claim
