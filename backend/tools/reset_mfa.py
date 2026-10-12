"""Turn two-factor off for one account from the command line (run inside the backend container).

  python tools/reset_mfa.py USERNAME

For the case where the ONLY administrator loses their authenticator: with no other admin there is nobody to use
Administration > Users & roles > "Reset two-factor". The account then signs in with its password and can enrol a new
authenticator from Settings > Security. All of the account's sessions are ended. Anyone who can run this already has full access
to the database; the reset is written to the audit log.
"""
import asyncio
import importlib
import os
import pkgutil
import sys

# `python tools/reset_mfa.py` puts /app/tools (not /app) first on the import path: add /app so `import app...` works.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select  # noqa: E402

from app.core.audit import log_audit  # noqa: E402
from app.core.database import async_session  # noqa: E402
from app.core.token_blocklist import revoke_user_sessions  # noqa: E402
from app.models.user import User  # noqa: E402


def _load_all_models() -> None:
    """SQLAlchemy can only configure relationships once EVERY model is imported (main.py does this eagerly at startup)."""
    import app.models as pkg
    for m in pkgutil.iter_modules(pkg.__path__):
        try:
            importlib.import_module(f"app.models.{m.name}")
        except Exception:                                        # e.g. finding_embedding needs pgvector
            pass


_load_all_models()


async def main(username: str) -> int:
    async with async_session() as db:
        user = (await db.execute(select(User).where((User.username == username) | (User.email == username)))).scalar_one_or_none()
        if user is None:
            print(f"No user '{username}'.")
            return 1
        was = bool(user.totp_enabled)
        user.totp_enabled = False
        user.totp_secret = ""  # type: ignore[assignment]
        await log_audit(db, action="admin:user_mfa_reset", user_id=None, resource_type="user", resource_id=str(user.id),
                        details={"username": user.username, "was_enabled": was, "via": "command line"})
        await db.commit()
        uid = str(user.id)
    await revoke_user_sessions(uid, include_refresh=True)
    print(f"Two-factor {'was on and is now OFF' if was else 'was already off'} for '{username}'. Sessions ended. "
          "Sign in with the password, then set up two-factor again in Settings > Security.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(asyncio.run(main(sys.argv[1])))
