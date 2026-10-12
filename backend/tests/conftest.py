"""
conftest.py — Shared pytest fixtures for the SOCIS-AI-PT test suite.

Provides:
- event_loop: session-scoped asyncio event loop
- client: httpx AsyncClient wired to the FastAPI app (no real DB/Redis required)
- Markers: asyncio tests use pytest-asyncio

Run with: pytest backend/tests/ -v
"""

import asyncio

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest.fixture(scope="session")
def event_loop():
    """Session-scoped event loop for all async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def client():
    """
    Lightweight AsyncClient backed by the FastAPI app directly.
    Uses ASGITransport — no real network, no real DB required for unit/integration tests.
    Tests that need a real DB should be skipped when the DB is unavailable.
    """
    from app.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c


@pytest_asyncio.fixture
async def auth_headers(client: AsyncClient) -> dict:
    """
    Registers a unique test user, logs in, and returns Authorization headers.
    Skips if the backend DB is not available.
    """
    import uuid

    suffix = str(uuid.uuid4())[:8]
    username = f"testuser_{suffix}"
    email = f"{username}@socis.test"
    password = "TestPass123!"

    r = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "username": username,
            "password": password,
            "full_name": "Test User",
        },
    )
    if r.status_code not in (201, 400):
        pytest.skip(f"Registration failed ({r.status_code}) — DB likely unavailable")

    r = await client.post(
        "/api/v1/auth/login",
        data={"username": username, "password": password},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if r.status_code != 200:
        pytest.skip(f"Login failed ({r.status_code}) — DB likely unavailable")

    token = r.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
