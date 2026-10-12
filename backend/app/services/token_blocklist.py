"""
SOCIS-AI-PT — Token Blocklist Service
Uses Redis to store revoked JTIs (JWT IDs) for access and refresh tokens.
"""

import redis.asyncio as aioredis
from datetime import timedelta
from app.config import settings

class TokenBlocklistService:
    def __init__(self):
        self.redis = aioredis.from_url(settings.REDIS_URL)

    async def block_jti(self, jti: str, expires_in: timedelta):
        """Store a JTI in Redis with an expiration time."""
        await self.redis.setex(f"jti:{jti}", expires_in, "revoked")

    async def is_jti_blocked(self, jti: str) -> bool:
        """Check if a JTI exists in the Redis blocklist."""
        return await self.redis.exists(f"jti:{jti}") > 0

token_blocklist = TokenBlocklistService()
