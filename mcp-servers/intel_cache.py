"""
Shared Redis-backed cache for MCP threat-intel servers (perf #6).

External intel APIs (NVD/CVE, FIRST EPSS, ExploitDB, CISA KEV) are rate-limited
and slow. Under concurrent scans the uncached servers re-fetch on every call,
causing latency spikes and upstream 429s. This module provides a tiny
cache-aside helper backed by a SEPARATE Redis logical DB (REDIS_CACHE_URL) so
cache entries are evictable and never share space with the durable arq queue or
security tokens on REDIS_URL.

Falls back to a safe in-process dict if Redis is unavailable, so a server never
breaks just because the cache is down.
"""
from __future__ import annotations

import os
import json
import time
import hashlib
import logging
from typing import Any, Awaitable, Callable, Optional

logger = logging.getLogger("intel_cache")

_DEFAULT_TTL = int(os.environ.get("CACHE_TTL_SECONDS", "21600"))  # 6h

# Resolve the cache Redis URL: explicit REDIS_CACHE_URL, else derive DB 1 from
# REDIS_URL, else None (in-process fallback).
def _cache_url() -> Optional[str]:
    url = os.environ.get("REDIS_CACHE_URL")
    if url:
        return url
    base = os.environ.get("REDIS_URL")
    if not base:
        return None
    # Swap/append the logical DB index to 1.
    if base.rstrip("/").split("/")[-1].isdigit():
        return base.rsplit("/", 1)[0] + "/1"
    return base.rstrip("/") + "/1"


_redis = None
_redis_init = False
_mem: dict[str, tuple[float, str]] = {}  # key -> (expires_at, json)


async def _get_redis():
    global _redis, _redis_init
    if _redis_init:
        return _redis
    _redis_init = True
    url = _cache_url()
    if not url:
        logger.info("intel_cache: no Redis URL; using in-process cache")
        return None
    try:
        import redis.asyncio as aioredis  # type: ignore
        _redis = aioredis.from_url(url, decode_responses=True)
        await _redis.ping()
        logger.info("intel_cache: connected to cache Redis")
    except Exception as exc:
        logger.warning("intel_cache: Redis unavailable (%s); using in-process cache", exc)
        _redis = None
    return _redis


def _norm_key(namespace: str, key: str) -> str:
    h = hashlib.sha256(key.encode()).hexdigest()[:40]
    return f"intel:{namespace}:{h}"


async def cache_get(namespace: str, key: str) -> Optional[Any]:
    k = _norm_key(namespace, key)
    r = await _get_redis()
    if r is not None:
        try:
            val = await r.get(k)
            return json.loads(val) if val else None
        except Exception:
            return None
    # in-process fallback
    item = _mem.get(k)
    if not item:
        return None
    expires_at, payload = item
    if time.time() > expires_at:
        _mem.pop(k, None)
        return None
    return json.loads(payload)


async def cache_set(namespace: str, key: str, value: Any, ttl: int = _DEFAULT_TTL) -> None:
    k = _norm_key(namespace, key)
    payload = json.dumps(value)
    r = await _get_redis()
    if r is not None:
        try:
            await r.setex(k, ttl, payload)
            return
        except Exception:
            pass
    _mem[k] = (time.time() + ttl, payload)


async def cached(
    namespace: str,
    key: str,
    producer: Callable[[], Awaitable[Any]],
    ttl: int = _DEFAULT_TTL,
) -> Any:
    """Cache-aside: return cached value or call producer(), cache, and return it.

    Only successful (non-None) results are cached, so a transient upstream error
    isn't frozen in the cache.
    """
    hit = await cache_get(namespace, key)
    if hit is not None:
        return hit
    result = await producer()
    if result is not None:
        try:
            await cache_set(namespace, key, result, ttl)
        except Exception:
            pass
    return result
