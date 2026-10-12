"""Small, idempotent schema corrections for databases created by older versions (the app builds tables with create_all, which never
alters an existing column). Never blocks startup."""
import logging

from sqlalchemy import text

logger = logging.getLogger(__name__)


async def widen_totp_secret(session_factory) -> bool:
    """users.totp_secret was VARCHAR(64) but holds a Fernet token (~120 characters), so enabling two-factor always failed with a
    database error. Make it TEXT. Returns True when it changed the column."""
    try:
        async with session_factory() as db:
            row = (await db.execute(text(
                "SELECT data_type, character_maximum_length FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'totp_secret'"))).first()
            if not row or row[1] is None:          # no such column, or already unbounded (text)
                return False
            await db.execute(text("ALTER TABLE users ALTER COLUMN totp_secret TYPE TEXT"))
            await db.commit()
            logger.info("Widened users.totp_secret from VARCHAR(%s) to TEXT (two-factor enrolment needs ~120 characters)", row[1])
            return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not widen users.totp_secret: %s", exc)
        return False


async def ensure_project_scope_columns(session_factory) -> bool:
    """Add projects.scope_targets / projects.scope_enforced to databases created before the authorized-scope feature (create_all
    never alters an existing table). Existing projects get enforced = false so nothing changes until an admin enables it. Idempotent."""
    try:
        async with session_factory() as db:
            await db.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS scope_targets JSONB NOT NULL DEFAULT '[]'::jsonb"))
            await db.execute(text("ALTER TABLE projects ADD COLUMN IF NOT EXISTS scope_enforced BOOLEAN NOT NULL DEFAULT FALSE"))
            await db.commit()
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not add the project scope columns: %s", exc)
        return False
