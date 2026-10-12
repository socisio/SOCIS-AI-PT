"""
SOCIS-AI-PT — Database Engine & Session Management
Async SQLAlchemy 2.0 with PostgreSQL via asyncpg.
"""

import logging
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

logger = logging.getLogger(__name__)

# Validate DATABASE_URL is set
if not settings.DATABASE_URL:
    raise ValueError("DATABASE_URL must be set in environment variables")

# Create async engine with optimized pool settings
# Using QueuePool instead of NullPool for better connection reuse
engine = create_async_engine(
    settings.DATABASE_URL,  # type: ignore  # Already validated above
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_timeout=settings.DATABASE_POOL_TIMEOUT,  # perf #2: bound wait for a conn
    echo=settings.DEBUG,
    pool_pre_ping=True,  # Verify connections before using
    pool_recycle=3600,  # Recycle connections after 1 hour
    connect_args={
        "timeout": 10,
        "command_timeout": 60,
        "server_settings": {
            "application_name": "socis-ai-pt"
        }
    }
)

# Session factory
async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency injection for database sessions."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            await session.close()
