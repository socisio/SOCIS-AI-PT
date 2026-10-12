"""SOCIS-AI-PT — Auth Schemas"""

import re
from typing import Optional, List
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, field_validator


class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=12)
    full_name: Optional[str] = None

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[^A-Za-z0-9]", v):
            raise ValueError("Password must contain at least one special character")
        return v


class UserResponse(BaseModel):
    id: UUID
    email: str
    username: str
    full_name: Optional[str]
    avatar_url: Optional[str]
    is_active: bool
    is_superuser: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class MeResponse(UserResponse):
    """GET /auth/me: the profile plus what the UI needs to decide what to show (the role comes from the role table, NOT from
    is_superuser: an admin created in the UI has role 'admin' and is_superuser false)."""
    role: str = "viewer"
    mfa_enabled: bool = False


class LoginRequest(BaseModel):
    username: str  # Can be email or username
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: Optional[UserResponse] = None


class RefreshRequest(BaseModel):
    refresh_token: str


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12)

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[^A-Za-z0-9]", v):
            raise ValueError("Password must contain at least one special character")
        return v


class ForgotPasswordRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        import re
        # Basic RFC 5322-compatible check; avoids rejecting .local / internal domains
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v) and "@" not in v:
            raise ValueError("Invalid email address")
        return v.lower().strip()


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=12)

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[^A-Za-z0-9]", v):
            raise ValueError("Password must contain at least one special character")
        return v
