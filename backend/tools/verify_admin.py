"""Temporary administrator account for deploy/scripts/verify.sh (run inside the backend container).

  python tools/verify_admin.py create   -> prints:  VERIFYADMIN <username> <password>
  python tools/verify_admin.py delete   -> removes every verify_admin_* account

Why it exists: the live checks sign in as an administrator with a password. Once the real admin turns on two-factor (as it should),
that sign-in stops at the code step (HTTP 202) and no check can continue. Rather than ask you to switch two-factor off, verify.sh
makes its own short-lived admin (random password, no two-factor), uses it, and deletes it. Only someone who can already run commands
inside the backend container (that is, who already has full access to the database) can run this.
"""
import asyncio
import importlib
import os
import pkgutil
import secrets
import sys

# `python tools/verify_admin.py` puts /app/tools (not /app) first on the import path: add /app so `import app...` works.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select, text  # noqa: E402

from app.core.database import async_session  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.models.user import Role, User  # noqa: E402


def _load_all_models() -> None:
    """SQLAlchemy can only configure relationships once EVERY model is imported (main.py does this eagerly at startup)."""
    import app.models as pkg
    for m in pkgutil.iter_modules(pkg.__path__):
        try:
            importlib.import_module(f"app.models.{m.name}")
        except Exception:                                        # e.g. finding_embedding needs pgvector
            pass


_load_all_models()

PREFIX = "verify_admin_"


async def delete_all() -> int:
    n = 0
    async with async_session() as db:
        rows = (await db.execute(select(User).where(User.username.like("verify\\_admin\\_%", escape="\\")))).scalars().all()
        for u in rows:
            uid = u.id
            try:
                await db.execute(text("UPDATE audit_logs SET user_id = NULL WHERE user_id = :i"), {"i": uid})
                await db.delete(u)
                await db.commit()
            except Exception:                                    # still referenced somewhere: make it unusable instead
                await db.rollback()
                u2 = await db.get(User, uid)
                if u2 is not None:
                    u2.is_active = False
                    u2.password_hash = hash_password(secrets.token_urlsafe(32) + "Aa1!")
                    u2.totp_enabled = False
                    await db.commit()
            n += 1
    return n


async def create() -> None:
    await delete_all()                                           # leftovers from an interrupted run
    suffix = secrets.token_hex(3)
    password = "Vf" + secrets.token_urlsafe(18).replace("_", "x").replace("-", "y") + "9!"   # no spaces, meets the password policy
    async with async_session() as db:
        role = (await db.execute(select(Role).where(Role.name == "admin"))).scalar_one()
        user = User(email=f"verify-admin-{suffix}@socis-verify.com", username=f"{PREFIX}{suffix}", password_hash=hash_password(password),
                    full_name="Verification admin (temporary)", is_active=True, is_superuser=True)
        user.roles.append(role)
        db.add(user)
        await db.commit()
    print(f"VERIFYADMIN {PREFIX}{suffix} {password}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "create":
        asyncio.run(create())
    elif cmd == "delete":
        print(f"removed {asyncio.run(delete_all())} verification account(s)")
    else:
        print(__doc__)
        sys.exit(2)
