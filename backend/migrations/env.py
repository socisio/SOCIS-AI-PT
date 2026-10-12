"""
SOCIS-AI-PT — Alembic Async Migration Environment
Configured for async SQLAlchemy with PostgreSQL (asyncpg).
"""

import asyncio
import os
import sys
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# Add the parent backend dir to sys.path so we can import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import settings
from app.core.database import Base

# Import ALL models so they are registered with Base.metadata
import app.models.user          # noqa: F401
import app.models.project       # noqa: F401
import app.models.scan          # noqa: F401
import app.models.vulnerability  # noqa: F401
import app.models.fix           # noqa: F401
import app.models.exploit       # noqa: F401
import app.models.ai_analysis   # noqa: F401
import app.models.report        # noqa: F401
import app.models.llm_config    # noqa: F401
import app.models.audit_log     # noqa: F401
import app.models.chat_session  # noqa: F401
import app.models.chat_session_artifact  # noqa: F401
try:
    import app.models.finding_embedding  # noqa: F401 — needs pgvector
except Exception:
    pass

config = context.config

# Set sqlalchemy.url from our pydantic settings
# Convert asyncpg URL to psycopg2 for Alembic sync fallback
config.set_main_option("sqlalchemy.url", str(settings.DATABASE_URL))

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Run migrations using async engine."""
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = str(settings.DATABASE_URL)
    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
