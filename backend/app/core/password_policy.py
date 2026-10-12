"""Password policy shared by admin-created accounts (same rules as self-registration: schemas/auth.py UserCreate)."""
from __future__ import annotations

import re
import secrets

MIN_LENGTH = 12
_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"      # no I / O
_LOWER = "abcdefghijkmnpqrstuvwxyz"      # no l
_DIGIT = "23456789"                      # no 0 / 1
_SPECIAL = "!@#$%^&*-_=+"


def validate_password_strength(pw: str) -> None:
    """Raise ValueError with a user-readable message if the password breaks the policy."""
    if not isinstance(pw, str) or len(pw) < MIN_LENGTH:
        raise ValueError(f"Password must be at least {MIN_LENGTH} characters")
    if not re.search(r"[A-Z]", pw):
        raise ValueError("Password must contain at least one uppercase letter")
    if not re.search(r"[0-9]", pw):
        raise ValueError("Password must contain at least one digit")
    if not re.search(r"[^A-Za-z0-9]", pw):
        raise ValueError("Password must contain at least one special character")


def generate_temp_password(length: int = 16) -> str:
    """A random one-time password that always satisfies the policy (and avoids look-alike characters)."""
    length = max(length, MIN_LENGTH)
    chars = [secrets.choice(_UPPER), secrets.choice(_LOWER), secrets.choice(_DIGIT), secrets.choice(_SPECIAL)]
    pool = _UPPER + _LOWER + _DIGIT + _SPECIAL
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)
