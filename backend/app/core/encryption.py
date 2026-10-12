"""
SOCIS-AI-PT — Encryption Utilities
Fernet symmetric encryption for secrets stored in DB (e.g., LLM API keys).
"""

import os
import logging
from cryptography.fernet import Fernet, InvalidToken

log = logging.getLogger(__name__)

_fernet_instance: Fernet | None = None
_ephemeral_warned: bool = False


def _get_fernet() -> Fernet:
    global _fernet_instance, _ephemeral_warned
    if _fernet_instance is not None:
        return _fernet_instance

    from app.config import settings
    key = settings.ENCRYPTION_KEY

    if not key:
        import base64
        key = base64.urlsafe_b64encode(os.urandom(32)).decode()
        if not _ephemeral_warned:
            log.critical(
                "\n"
                "  ╔══════════════════════════════════════════════════════════════╗\n"
                "  ║  WARNING: ENCRYPTION_KEY is not set!                        ║\n"
                "  ║  An ephemeral key was generated for this session.            ║\n"
                "  ║  ALL encrypted secrets will be LOST on next restart.         ║\n"
                "  ║  Add this to deploy/docker/.env to persist encryption:       ║\n"
                "  ║  ENCRYPTION_KEY=%s  ║\n"
                "  ╚══════════════════════════════════════════════════════════════╝",
                key,
            )
            _ephemeral_warned = True

    _fernet_instance = Fernet(key.encode() if isinstance(key, str) else key)
    return _fernet_instance


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a plaintext string and return a URL-safe base64 token."""
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt a token produced by encrypt_secret."""
    try:
        return _get_fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        raise ValueError("Cannot decrypt: invalid or corrupted ciphertext (wrong ENCRYPTION_KEY?)")

