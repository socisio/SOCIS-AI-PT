"""
SOCIS-AI-PT — Authentication Routes (Full Implementation)
JWT login/register + OAuth callbacks for Google and Microsoft AD.
"""

import hmac
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from slowapi import Limiter
from app.core.client_ip import get_client_ip
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.core.audit import log_audit
from app.core.database import get_db
from app.core.encryption import encrypt_secret, decrypt_secret
from app.core.security import (
    create_mfa_token,
    hash_password, verify_password,
    create_access_token, create_refresh_token, decode_token,
    oauth2_scheme, require_permission, get_current_user,
)
from app.models.user import User, Role
from app.schemas.auth import (
    MeResponse,
    UserCreate, UserResponse, TokenResponse, RefreshRequest,
    UserUpdate, ChangePasswordRequest, ForgotPasswordRequest, ResetPasswordRequest,
)
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class MFALoginRequest(BaseModel):
    """Second step of a sign-in: the temporary token from the password step plus the authenticator code (in the BODY, never the URL)."""
    mfa_token: str
    code: str


class MFACodeRequest(BaseModel):
    """Request body for MFA TOTP verification endpoints."""
    code: str
router = APIRouter()

COOKIE_DOMAIN = ""
ACCESS_COOKIE_MAX_AGE = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
REFRESH_COOKIE_MAX_AGE = settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60


def _set_token_cookies(response: Response, access_token: str, refresh_token: str) -> None:
    """Set access_token and refresh_token as HttpOnly cookies.

    The 'secure' flag is controlled by SECURE_COOKIES setting:
    - True  (default): required for production HTTPS deployments
    - False: allows cookies over plain HTTP for LAN/dev setups
    """
    _secure = settings.SECURE_COOKIES
    response.set_cookie(
        key="access_token", value=access_token,
        max_age=ACCESS_COOKIE_MAX_AGE,
        httponly=True, secure=_secure, samesite="lax",
        path="/",
    )
    response.set_cookie(
        key="refresh_token", value=refresh_token,
        max_age=REFRESH_COOKIE_MAX_AGE,
        httponly=True, secure=_secure, samesite="lax",
        path="/",
    )


def _clear_token_cookies(response: Response) -> None:
    """Clear both token cookies."""
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path="/")


def _build_json_response(content: dict, access_token: str, refresh_token: str) -> Response:
    """Build a JSON response with HttpOnly token cookies set."""
    from fastapi.responses import JSONResponse
    response = JSONResponse(content=content, media_type="application/json")
    _secure = settings.SECURE_COOKIES
    response.set_cookie(key="access_token", value=access_token, max_age=ACCESS_COOKIE_MAX_AGE, httponly=True, secure=_secure, samesite="lax", path="/")
    response.set_cookie(key="refresh_token", value=refresh_token, max_age=REFRESH_COOKIE_MAX_AGE, httponly=True, secure=_secure, samesite="lax", path="/")
    return response

# Rate limiter — uses the app-level limiter configured in main.py
limiter = Limiter(key_func=get_client_ip)


# ─── Registration ─────────────────────────────────────────────

@router.post("/register", response_model=UserResponse, status_code=201)
@limiter.limit("3/minute")
async def register(request: Request, user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    """Register a new local user account."""
    # Registration gate (fix H-3). Open self-registration is disabled unless
    # explicitly enabled by an operator.
    if not settings.ALLOW_OPEN_REGISTRATION:
        raise HTTPException(
            status_code=403,
            detail="Self-registration is disabled. Contact an administrator for an account.",
        )
    try:
        existing = await db.execute(select(User).where(User.email == user_data.email))
        if existing.scalar_one_or_none():
            logger.warning(f"Registration attempt with existing email: {user_data.email}")
            raise HTTPException(status_code=400, detail="Email already registered")

        existing_u = await db.execute(select(User).where(User.username == user_data.username))
        if existing_u.scalar_one_or_none():
            logger.warning(f"Registration attempt with existing username: {user_data.username}")
            raise HTTPException(status_code=400, detail="Username already taken")

        user = User(
            email=user_data.email,
            username=user_data.username,
            password_hash=hash_password(user_data.password),
            full_name=user_data.full_name,
        )
        _default_role_name = (settings.DEFAULT_USER_ROLE or "viewer").strip().lower()
        result = await db.execute(select(Role).where(Role.name == _default_role_name))
        default_role = result.scalar_one_or_none()
        if not default_role:
            result = await db.execute(select(Role).where(Role.name == "viewer"))
            default_role = result.scalar_one_or_none()
        if default_role:
            user.roles.append(default_role)

        db.add(user)
        await db.flush()
        await log_audit(
            db, action="auth:register",
            user_id=user.id,
            resource_type="user", resource_id=str(user.id),
            details={"username": user.username, "email": user.email},
            ip_address=get_client_ip(request),
        )
        await db.commit()
        await db.refresh(user)
        logger.info(f"New user registered: {user_data.username}")
        return user
    except IntegrityError as e:
        logger.error(f"Registration failed due to integrity error: {e}")
        await db.rollback()
        raise HTTPException(status_code=400, detail="Username or email already exists")
    except Exception as e:
        logger.exception(f"Registration failed unexpectedly: {e}")
        raise HTTPException(status_code=500, detail="Registration failed due to server error")


# ─── Login ────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
@limiter.limit("30/minute")
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """Login with username/email and password. Tokens are set as HttpOnly cookies."""
    from app.core.token_blocklist import (
        record_failed_login, is_login_locked, clear_failed_logins,
    )
    try:
        # Account lockout (fix L-7): block after too many recent failures.
        if await is_login_locked(form_data.username):
            logger.warning(f"Login blocked (locked out): {form_data.username}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Try again later.",
            )
        result = await db.execute(
            select(User).where(
                (User.email == form_data.username) | (User.username == form_data.username)
            )
        )
        user = result.scalar_one_or_none()
        ip = get_client_ip(request)
        if not user or not user.password_hash or not verify_password(form_data.password, user.password_hash):
            attempts = await record_failed_login(form_data.username)
            logger.warning(f"Failed login attempt ({attempts}): {form_data.username}")
            await log_audit(
                db, action="auth:login_failed",
                details={"username": form_data.username, "attempts": attempts},
                ip_address=ip,
            )
            await db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        if not user.is_active:
            logger.warning(f"Login attempt for disabled account: {form_data.username}")
            raise HTTPException(status_code=403, detail="Account is disabled")

        if user.totp_enabled:
            mfa_token = create_mfa_token(str(user.id))
            return Response(
                status_code=status.HTTP_202_ACCEPTED,
                content=json.dumps({
                    "mfa_required": True,
                    "mfa_token": mfa_token,
                    "message": "MFA verification required"
                }),
                media_type="application/json"
            )

        await clear_failed_logins(form_data.username)
        user.last_login = datetime.now(timezone.utc)
        role_name = user.roles[0].name if user.roles else "viewer"
        token_data = {"sub": str(user.id), "email": user.email, "username": user.username, "role": role_name}

        access_token = create_access_token(token_data)
        refresh_token = create_refresh_token(token_data)

        await log_audit(
            db, action="auth:login",
            user_id=user.id,
            resource_type="user", resource_id=str(user.id),
            details={"username": user.username},
            ip_address=ip,
        )
        logger.info(f"User logged in: {user.username}")
        await db.commit()

        response = Response(
            content=json.dumps(TokenResponse(
                access_token=access_token,
                refresh_token=refresh_token,
                token_type="bearer",
                user=UserResponse.model_validate(user),
            ).model_dump(mode="json")),
            media_type="application/json"
        )
        _set_token_cookies(response, access_token, refresh_token)
        return response
    except HTTPException:
        raise
    except IntegrityError as e:
        logger.error(f"Login failed due to integrity error: {e}")
        raise HTTPException(status_code=500, detail="Login failed due to server error")
    except Exception as e:
        logger.exception(f"Login failed unexpectedly: {e}")
        raise HTTPException(status_code=500, detail="Login failed due to server error")


# ─── Logout ──────────────────────────────────────────────────────

@router.post("/logout")
async def logout(
    token: dict = Depends(get_current_user),
    refresh_token_cookie: Optional[str] = Cookie(None, alias="refresh_token"),
    db: AsyncSession = Depends(get_db),
):
    """Revoke the current JWT tokens (access + refresh) and clear cookies."""
    from app.core.token_blocklist import block_token
    from app.config import settings as _settings
    jti = token.get("jti")
    if jti:
        await block_token(jti, _settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    # Also block the refresh token (HIGH-02 fix)
    if refresh_token_cookie:
        try:
            refresh_payload = decode_token(refresh_token_cookie)
            refresh_jti = refresh_payload.get("jti")
            if refresh_jti:
                await block_token(refresh_jti, _settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60)
        except Exception:
            pass  # Invalid refresh token — still clear the cookie
    response = Response(content=json.dumps({"message": "Logged out successfully"}), media_type="application/json")
    _clear_token_cookies(response)
    return response



async def _totp_ok(user: User, code: str) -> bool:
    """Check an authenticator code. Five wrong codes in a row lock MFA for this account for a while, so the 6-digit code cannot be
    brute-forced by re-logging-in (the per-IP rate limit alone does not stop a distributed attempt)."""
    import pyotp
    from app.core.token_blocklist import record_failed_login, is_login_locked, clear_failed_logins
    key = f"mfa:{user.id}"
    if await is_login_locked(key):
        raise HTTPException(status_code=429, detail="Too many incorrect codes. Try again later.")
    try:
        secret = decrypt_secret(user.totp_secret)
    except Exception:
        raise HTTPException(status_code=500, detail="Error decrypting MFA secret")
    ok = bool(pyotp.TOTP(secret).verify(str(code).strip(), valid_window=1))
    if ok:
        await clear_failed_logins(key)
    else:
        await record_failed_login(key)
    return ok

# ─── MFA / TOTP ─────────────────────────────────────────────────

@router.post("/mfa/setup")
async def setup_mfa(
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Generate TOTP secret and return QR code data URI."""
    import pyotp, qrcode, io, base64
    from uuid import UUID

    user = await db.get(User, UUID(token["sub"]))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.totp_enabled:
        # Replacing the secret of an account that already has MFA would let anyone who reaches this endpoint swap the
        # authenticator. To re-enrol, disable MFA first (that needs a valid current code).
        raise HTTPException(status_code=400, detail="Two-factor authentication is already on. Turn it off first to set it up again.")

    secret = pyotp.random_base32()
    # Encrypt the secret before storing it in the DB
    user.totp_secret = encrypt_secret(secret)
    await db.commit()

    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user.email, issuer_name="SOCIS-AI-PT")

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return {
        "secret": secret,
        "qr_code": f"data:image/png;base64,{qr_b64}",
        "uri": uri,
    }


@router.post("/mfa/verify")
@limiter.limit("5/minute")
async def verify_mfa(
    request: Request,
    body: MFACodeRequest,
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Verify TOTP code and enable MFA on the account."""
    import pyotp
    from uuid import UUID

    user = await db.get(User, UUID(token["sub"]))
    if not user or not user.totp_secret:
        raise HTTPException(status_code=400, detail="MFA setup not initiated. Call /mfa/setup first.")
    
    if not await _totp_ok(user, body.code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")
    user.totp_enabled = True
    await log_audit(db, action="auth:mfa_enabled", user_id=user.id, resource_type="user", resource_id=str(user.id),
                    details={"username": user.username})
    await db.commit()
    return {"message": "MFA enabled successfully"}


@router.post("/mfa/disable")
@limiter.limit("5/minute")
async def disable_mfa(
    request: Request,
    body: MFACodeRequest,
    token: dict = Depends(require_permission("scans:read")),
    db: AsyncSession = Depends(get_db),
):
    """Disable MFA after verifying current TOTP code."""
    import pyotp
    from uuid import UUID

    user = await db.get(User, UUID(token["sub"]))
    if not user or not user.totp_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled on this account")
        
    if not await _totp_ok(user, body.code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")
    user.totp_enabled = False
    user.totp_secret = ""  # type: ignore[assignment]  # cleared intentionally
    await log_audit(db, action="auth:mfa_disabled", user_id=user.id, resource_type="user", resource_id=str(user.id),
                    details={"username": user.username})
    await db.commit()
    return {"message": "MFA disabled"}


@router.post("/mfa/verify-login")
@limiter.limit("5/minute")
async def verify_login_mfa(
    request: Request,
    body: MFALoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Second step of sign-in when two-factor is on: exchange the temporary token + a valid authenticator code for real tokens."""
    from uuid import UUID
    from app.core.token_blocklist import block_token, is_token_blocked

    payload = decode_token(body.mfa_token)
    if payload.get("type") != "mfa" or not payload.get("mfa_pending"):
        raise HTTPException(status_code=401, detail="Invalid MFA token")
    jti = payload.get("jti")
    if jti and await is_token_blocked(jti):
        raise HTTPException(status_code=401, detail="This sign-in step was already used. Sign in again.")

    user = await db.get(User, UUID(payload["sub"]))
    if not user or not user.is_active or not user.totp_enabled or not user.totp_secret:
        raise HTTPException(status_code=401, detail="MFA not active for this user")

    ip = get_client_ip(request)
    if not await _totp_ok(user, body.code):
        await log_audit(db, action="auth:mfa_failed", user_id=user.id, resource_type="user", resource_id=str(user.id),
                        details={"username": user.username}, ip_address=ip)
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    if jti:   # one sign-in step, one use
        await block_token(jti, 10 * 60)
    user.last_login = datetime.now(timezone.utc)
    role_name = user.roles[0].name if user.roles else "viewer"
    token_data = {"sub": str(user.id), "email": user.email, "username": user.username, "role": role_name}

    await log_audit(
        db, action="auth:login_mfa_success",
        user_id=user.id,
        resource_type="user", resource_id=str(user.id),
        details={"username": user.username}, ip_address=ip,
    )
    await db.commit()

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    response = Response(
        content=json.dumps(TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            user=UserResponse.model_validate(user),
        ).model_dump(mode="json")),
        media_type="application/json"
    )
    _set_token_cookies(response, access_token, refresh_token)
    return response


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    refresh_token_cookie: Optional[str] = Cookie(None),
    db: AsyncSession = Depends(get_db),
):
    """Refresh access token using the refresh_token HttpOnly cookie."""
    if not refresh_token_cookie:
        raise HTTPException(status_code=401, detail="Missing refresh_token cookie")
    payload = decode_token(refresh_token_cookie)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=400, detail="Invalid refresh token")
    # Reject refresh tokens that were revoked at logout (fix H-2).
    from app.core.token_blocklist import is_token_blocked, block_token, is_user_session_revoked
    old_jti = payload.get("jti")
    if old_jti and await is_token_blocked(old_jti):
        raise HTTPException(status_code=401, detail="Refresh token has been revoked")
    # An admin password reset signs the user out everywhere, refresh tokens included.
    if await is_user_session_revoked(payload.get("sub"), payload.get("iat"), refresh=True):
        raise HTTPException(status_code=401, detail="Session ended. Sign in again.")
    result = await db.execute(select(User).where(User.id == payload["sub"]))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or disabled")
    role_name = user.roles[0].name if user.roles else "viewer"
    token_data = {"sub": str(user.id), "email": user.email, "username": user.username, "role": role_name}

    new_access = create_access_token(token_data)
    new_refresh = create_refresh_token(token_data)
    # Refresh-token rotation (fix L-4): invalidate the just-used refresh token.
    if old_jti:
        await block_token(old_jti, settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60)
    return _build_json_response(
        TokenResponse(
            access_token=new_access,
            refresh_token=new_refresh,
            token_type="bearer",
            user=UserResponse.model_validate(user),
        ).model_dump(mode="json"),
        new_access,
        new_refresh,
    )


# ─── Current User ─────────────────────────────────────────────

@router.get("/me", response_model=MeResponse)
async def get_me(token: dict = Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    """Get the authenticated user's profile (with the role and whether two-factor is on)."""
    from uuid import UUID
    result = await db.execute(select(User).where(User.id == UUID(token["sub"])))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return MeResponse(
        **UserResponse.model_validate(user).model_dump(),
        role=(user.roles[0].name if user.roles else "viewer"),
        mfa_enabled=bool(user.totp_enabled),
    )


# ─── Update Profile ───────────────────────────────────────────

@router.patch("/profile", response_model=UserResponse)
async def update_profile(
    updates: UserUpdate,
    token: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update user profile (full_name, avatar_url)."""
    from uuid import UUID
    result = await db.execute(select(User).where(User.id == UUID(token["sub"])))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if updates.full_name is not None:
        user.full_name = updates.full_name
    if updates.avatar_url is not None:
        from urllib.parse import urlparse as _urlparse
        _parsed = _urlparse(updates.avatar_url)
        if _parsed.scheme not in ("http", "https"):
            raise HTTPException(status_code=400, detail="avatar_url must use http or https scheme")
        user.avatar_url = updates.avatar_url

    await db.commit()
    await db.refresh(user)
    logger.info(f"User profile updated: {user.username}")
    return user


# ─── Change Password ──────────────────────────────────────────

@router.post("/change-password")
async def change_password(
    data: ChangePasswordRequest,
    token: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change user password."""
    from uuid import UUID
    result = await db.execute(select(User).where(User.id == UUID(token["sub"])))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if not verify_password(data.current_password, user.password_hash or ""):
        logger.warning(f"Failed password change attempt for: {user.username}")
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    
    if verify_password(data.new_password, user.password_hash or ""):
        raise HTTPException(status_code=400, detail="Choose a password you have not used just now")
    user.password_hash = hash_password(data.new_password)
    await log_audit(db, action="auth:password_changed", user_id=user.id, resource_type="user", resource_id=str(user.id),
                    details={"username": user.username})
    await db.commit()
    logger.info(f"Password changed for user: {user.username}")

    # Sign every OTHER device out, but keep this one: the marker is set one second back so the tokens issued below survive,
    # and they replace this browser's cookies.
    import time as _time
    from app.core.token_blocklist import revoke_user_sessions
    await revoke_user_sessions(str(user.id), include_refresh=True, now=int(_time.time()) - 1)
    role_name = user.roles[0].name if user.roles else "viewer"
    token_data = {"sub": str(user.id), "email": user.email, "username": user.username, "role": role_name}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    response = Response(content=json.dumps({"detail": "Password changed successfully. Other devices were signed out."}), media_type="application/json")
    _set_token_cookies(response, access_token, refresh_token)
    return response


@router.post("/logout-all")
async def logout_all(
    token: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Sign this account out on EVERY device, this one included (access and refresh tokens alike)."""
    from uuid import UUID
    from app.core.token_blocklist import revoke_user_sessions
    await revoke_user_sessions(token["sub"], include_refresh=True)
    await log_audit(db, action="auth:logout_all", user_id=UUID(token["sub"]), resource_type="user", resource_id=token["sub"], details={})
    await db.commit()
    response = Response(content=json.dumps({"detail": "Signed out on all devices"}), media_type="application/json")
    _clear_token_cookies(response)
    return response


# ─── Forgot Password ──────────────────────────────────────────

_RESET_TOKEN_TTL = 1800  # 30 minutes


@router.post("/forgot-password")
@limiter.limit("5/minute")
async def forgot_password(
    request: Request,
    data: ForgotPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Request a password reset.

    If a matching active local account exists, a secure random token is stored
    in Redis for 30 minutes and the reset link is delivered OUT-OF-BAND via the
    configured email provider.

    SECURITY (fix C-2): the token and reset URL are NEVER returned in the HTTP
    response. The response is identical whether or not the email is registered,
    to prevent user enumeration.
    """
    from app.core.token_blocklist import get_redis

    generic_response = {
        "detail": "If that email is registered, a password reset link has been sent.",
    }

    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    if not user or not user.is_active or user.oauth_provider:
        return generic_response

    token = secrets.token_urlsafe(48)
    r = await get_redis()
    await r.setex(f"pw_reset:{token}", _RESET_TOKEN_TTL, str(user.id))

    await log_audit(
        db, action="auth:forgot_password",
        user_id=user.id,
        resource_type="user", resource_id=str(user.id),
        details={"email": user.email},
        ip_address=get_client_ip(request),
    )
    await db.commit()

    # Build the reset URL from the trusted FRONTEND_URL (not spoofable Host
    # headers, which would enable reset-link poisoning).
    base_url = (settings.FRONTEND_URL or "").rstrip("/")
    if not base_url:
        base_url = f"{request.url.scheme}://{request.headers.get('host', request.url.netloc)}"
    reset_url = f"{base_url}/reset-password?token={token}"

    try:
        from app.services.notification_delivery_service import notification_delivery_service
        subject = "[SOCIS-AI-PT] Password reset request"
        body = (
            "A password reset was requested for your SOCIS-AI-PT account.\n\n"
            f"Reset your password using the link below (valid for {_RESET_TOKEN_TTL // 60} minutes):\n"
            f"{reset_url}\n\n"
            "If you did not request this, you can safely ignore this email."
        )
        sent = await notification_delivery_service.send_password_reset_email(
            db, recipient_email=user.email, subject=subject, body_text=body
        )
        if not sent:
            # Do not log the token/URL (fix M-6). Configure an email provider
            # in admin settings so reset links can be delivered.
            logger.warning(
                "Password reset requested for %s but email delivery is not "
                "configured or failed — no reset link was delivered. Configure "
                "a notification email provider in admin settings.",
                user.email,
            )
    except Exception as exc:
        logger.error("Password reset email delivery error for %s: %s", user.email, exc)

    logger.info(f"Password reset link generated for: {user.email}")
    return generic_response


@router.post("/reset-password")
@limiter.limit("10/minute")
async def reset_password(
    request: Request,
    data: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Consume a password reset token and set a new password.
    The token is one-time-use and expires after 30 minutes.
    """
    from uuid import UUID
    from app.core.token_blocklist import get_redis

    r = await get_redis()
    user_id_str: str | None = await r.get(f"pw_reset:{data.token}")

    if not user_id_str:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    result = await db.execute(select(User).where(User.id == UUID(user_id_str)))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    # Invalidate the token immediately (one-time use)
    await r.delete(f"pw_reset:{data.token}")

    user.password_hash = hash_password(data.new_password)
    await log_audit(
        db, action="auth:password_reset",
        user_id=user.id,
        resource_type="user", resource_id=str(user.id),
        details={"email": user.email},
        ip_address=get_client_ip(request),
    )
    await db.commit()
    logger.info(f"Password reset completed for: {user.email}")
    return {"detail": "Password has been reset successfully. You can now log in."}


async def _get_effective_sso_settings(db: AsyncSession) -> dict:
    """Resolve SSO config from DB (preferred) with environment fallback."""
    from app.services.settings_service import settings_service
    return await settings_service.get_sso_settings(db, include_secrets=True)


@router.get("/sso/providers")
async def get_sso_provider_status(db: AsyncSession = Depends(get_db)):
    """Public status endpoint used by login page to render available SSO providers."""
    cfg = await _get_effective_sso_settings(db)

    google_configured = bool(cfg.get("google_client_id") and cfg.get("google_client_secret"))
    microsoft_configured = bool(cfg.get("microsoft_client_id") and cfg.get("microsoft_client_secret"))

    return {
        "google": {
            "enabled": bool(cfg.get("google_enabled", False)) and google_configured,
            "configured": google_configured,
        },
        "microsoft": {
            "enabled": bool(cfg.get("microsoft_enabled", False)) and microsoft_configured,
            "configured": microsoft_configured,
        },
    }


# ─── Google OAuth ─────────────────────────────────────────────

_CLEAR_OAUTH_STATE = {"Set-Cookie": "oauth_state=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"}


def _check_oauth_state(state: str, cookie: Optional[str]) -> None:
    """The state sent back by the provider must equal the one we put in this browser's cookie (constant-time). A state is single-use:
    the cookie is cleared on every outcome, including failures (it used to survive a failed attempt for its full ten minutes)."""
    if not cookie or not hmac.compare_digest(str(state).encode(), str(cookie).encode()):
        raise HTTPException(status_code=400, detail="Invalid OAuth state (CSRF detected)", headers=_CLEAR_OAUTH_STATE)


@router.get("/oauth/google")
async def google_oauth_start(response: Response, db: AsyncSession = Depends(get_db)):
    """Return the Google OAuth authorization URL with state CSRF protection."""
    cfg = await _get_effective_sso_settings(db)
    if not cfg.get("google_enabled"):
        raise HTTPException(status_code=403, detail="Google SSO is disabled by administrator")
    if not cfg.get("google_client_id") or not cfg.get("google_client_secret"):
        raise HTTPException(status_code=501, detail="Google OAuth not configured")
    from app.services.auth_service import google_oauth

    state = secrets.token_urlsafe(32)
    response.set_cookie(key="oauth_state", value=state, httponly=True, secure=settings.SECURE_COOKIES, samesite="lax", max_age=600)

    redirect_uri = f"{settings.FRONTEND_URL}/auth/callback/google"
    return {
        "auth_url": google_oauth.get_authorization_url(
            redirect_uri,
            state=state,
            client_id=cfg.get("google_client_id"),
        )
    }


@router.get("/oauth/google/callback")
async def google_oauth_callback(
    code: str, 
    state: str,
    oauth_state: Optional[str] = Cookie(None),
    db: AsyncSession = Depends(get_db)
):
    """Handle Google OAuth callback with state validation."""
    _check_oauth_state(state, oauth_state)

    cfg = await _get_effective_sso_settings(db)
    if not cfg.get("google_enabled"):
        raise HTTPException(status_code=403, detail="Google SSO is disabled by administrator")

    from app.services.auth_service import google_oauth
    if not cfg.get("google_client_id") or not cfg.get("google_client_secret"):
        raise HTTPException(status_code=501, detail="Google OAuth not configured")

    redirect_uri = f"{settings.FRONTEND_URL}/auth/callback/google"
    try:
        oauth_user = await google_oauth.authenticate(
            code,
            redirect_uri,
            client_id=cfg.get("google_client_id"),
            client_secret=cfg.get("google_client_secret"),
        )
    except Exception:
        raise HTTPException(status_code=400, detail="OAuth authentication failed", headers=_CLEAR_OAUTH_STATE)

    response = await _oauth_login_or_create(oauth_user, db, cfg)
    response.delete_cookie(key="oauth_state", path="/")
    return response


# ─── Microsoft OAuth ──────────────────────────────────────────

@router.get("/oauth/microsoft")
async def microsoft_oauth_start(response: Response, db: AsyncSession = Depends(get_db)):
    """Return the Microsoft AD OAuth authorization URL with state CSRF protection."""
    cfg = await _get_effective_sso_settings(db)
    if not cfg.get("microsoft_enabled"):
        raise HTTPException(status_code=403, detail="Microsoft SSO is disabled by administrator")
    if not cfg.get("microsoft_client_id") or not cfg.get("microsoft_client_secret"):
        raise HTTPException(status_code=501, detail="Microsoft OAuth not configured")
    from app.services.auth_service import microsoft_oauth

    state = secrets.token_urlsafe(32)
    response.set_cookie(key="oauth_state", value=state, httponly=True, secure=settings.SECURE_COOKIES, samesite="lax", max_age=600)

    redirect_uri = f"{settings.FRONTEND_URL}/auth/callback/microsoft"
    return {
        "auth_url": microsoft_oauth.get_authorization_url(
            redirect_uri,
            state=state,
            client_id=cfg.get("microsoft_client_id"),
            tenant_id=cfg.get("microsoft_tenant_id") or "common",
        )
    }


@router.get("/oauth/microsoft/callback")
async def microsoft_oauth_callback(
    code: str, 
    state: str,
    oauth_state: Optional[str] = Cookie(None),
    db: AsyncSession = Depends(get_db)
):
    """Handle Microsoft OAuth callback with state validation."""
    _check_oauth_state(state, oauth_state)

    cfg = await _get_effective_sso_settings(db)
    if not cfg.get("microsoft_enabled"):
        raise HTTPException(status_code=403, detail="Microsoft SSO is disabled by administrator")

    from app.services.auth_service import microsoft_oauth
    if not cfg.get("microsoft_client_id") or not cfg.get("microsoft_client_secret"):
        raise HTTPException(status_code=501, detail="Microsoft OAuth not configured")

    redirect_uri = f"{settings.FRONTEND_URL}/auth/callback/microsoft"
    try:
        oauth_user = await microsoft_oauth.authenticate(
            code,
            redirect_uri,
            client_id=cfg.get("microsoft_client_id"),
            client_secret=cfg.get("microsoft_client_secret"),
            tenant_id=cfg.get("microsoft_tenant_id") or "common",
        )
    except Exception:
        raise HTTPException(status_code=400, detail="OAuth authentication failed", headers=_CLEAR_OAUTH_STATE)

    response = await _oauth_login_or_create(oauth_user, db, cfg)
    response.delete_cookie(key="oauth_state", path="/")
    return response


# ─── OAuth Shared Helper ──────────────────────────────────────

async def _oauth_login_or_create(oauth_user: dict, db: AsyncSession, cfg: dict) -> Response:
    """Decide (core/sso_policy.py) whether this provider identity may sign in and as which local account, then issue tokens.

    Never links a provider identity to an existing account by e-mail, except a verified Google address on an allowed domain for a
    non-administrator; never signs in a deactivated account; creates accounts only when an administrator allowed it for the listed
    domains; and still asks for the local authenticator code when that account has two-factor on."""
    from app.core.scope_guard import audit_standalone
    from app.core.sso_policy import decide, normalize_email, parse_domains

    provider = str(oauth_user.get("provider") or "")
    oauth_id = str(oauth_user.get("oauth_id") or "")
    email = normalize_email(oauth_user.get("email"))
    oauth_user = {**oauth_user, "email": email}

    def _summary(u: Optional[User]) -> Optional[dict]:
        if u is None:
            return None
        return {"is_active": bool(u.is_active), "is_admin": bool(u.is_superuser) or any(r.name == "admin" for r in u.roles),
                "linked": bool(u.oauth_provider and u.oauth_id)}

    identity_user = None
    if oauth_id:
        identity_user = (await db.execute(select(User).where((User.oauth_provider == provider) & (User.oauth_id == oauth_id)))).scalar_one_or_none()
    email_user = None
    if identity_user is None and email:
        email_user = (await db.execute(select(User).where(func.lower(User.email) == email))).scalar_one_or_none()

    decision = decide(oauth_user, _summary(identity_user), _summary(email_user), parse_domains(cfg.get("sso_allowed_domains")),
                      bool(cfg.get("sso_auto_provision")), cfg.get("microsoft_tenant_id"))
    if decision.action == "deny":
        await audit_standalone("auth:sso_denied", None, "user", None, {"provider": provider, "email": email, "reason": decision.reason})
        raise HTTPException(status_code=403, detail=decision.message, headers=_CLEAR_OAUTH_STATE)

    if decision.action == "link":
        user = email_user
        user.oauth_provider, user.oauth_id = provider, oauth_id
        await log_audit(db, action="auth:sso_linked", user_id=user.id, resource_type="user", resource_id=str(user.id),
                        details={"provider": provider, "how": decision.reason})
    elif decision.action == "provision":
        username = email.split("@")[0]
        for i in range(100):
            candidate = username if i == 0 else f"{username}{i}"
            exists = await db.execute(select(User).where(User.username == candidate))
            if not exists.scalar_one_or_none():
                username = candidate
                break
        user = User(
            email=email,
            username=username,
            full_name=oauth_user.get("full_name", ""),
            avatar_url=oauth_user.get("avatar_url"),
            oauth_provider=provider,
            oauth_id=oauth_id,
        )
        # Least-privilege default role for SSO-provisioned users (fix L-8).
        _default_role_name = (settings.DEFAULT_USER_ROLE or "viewer").strip().lower()
        result = await db.execute(select(Role).where(Role.name == _default_role_name))
        default_role = result.scalar_one_or_none()
        if not default_role:
            result = await db.execute(select(Role).where(Role.name == "viewer"))
            default_role = result.scalar_one_or_none()
        if default_role:
            user.roles.append(default_role)
        db.add(user)
        await db.flush()
        await log_audit(db, action="auth:sso_provisioned", user_id=user.id, resource_type="user", resource_id=str(user.id),
                        details={"provider": provider, "email": email})
    else:
        user = identity_user
    if oauth_user.get("avatar_url"):
        user.avatar_url = oauth_user["avatar_url"]

    if user.totp_enabled:
        # The provider proved who they are, but this account asked for an authenticator code: still required (same second step as a password sign-in).
        return Response(
            status_code=status.HTTP_202_ACCEPTED,
            content=json.dumps({"mfa_required": True, "mfa_token": create_mfa_token(str(user.id)), "message": "MFA verification required"}),
            media_type="application/json",
        )

    user.last_login = datetime.now(timezone.utc)
    role_name = user.roles[0].name if user.roles else "viewer"
    token_data = {"sub": str(user.id), "email": user.email, "username": user.username, "role": role_name}

    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    await log_audit(db, action="auth:sso_login", user_id=user.id, resource_type="user", resource_id=str(user.id),
                    details={"provider": provider, "how": decision.reason})
    response = Response(
        content=json.dumps(TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            user=UserResponse.model_validate(user),
        ).model_dump(mode="json")),
        media_type="application/json"
    )
    _set_token_cookies(response, access_token, refresh_token)
    return response


# ─── User Directory (for assignee picker) ────────────────────

@router.get("/directory")
async def user_directory(
    token: dict = Depends(require_permission("vulns:read")),
    db: AsyncSession = Depends(get_db),
):
    """Return a minimal user list for the vulnerability assignee picker."""
    result = await db.execute(
        select(User).where(User.is_active.is_(True)).order_by(User.full_name, User.username)
    )
    users = result.scalars().all()
    return [
        {
            "id": str(u.id),
            "username": u.username,
            "email": u.email,
            "name": u.full_name or u.username,
        }
        for u in users
    ]
