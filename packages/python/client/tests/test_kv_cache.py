"""Tests for starfish_sdk.kv_cache."""

import asyncio
from typing import Optional

import pytest

from starfish_sdk.kv_cache import KvPullCache, create_kv_pull_cache


# ── In-memory KvStore stub ────────────────────────────────────────────────────

class MemKv:
    def __init__(self):
        self.store: dict[str, str] = {}

    async def get(self, key: str) -> Optional[str]:
        return self.store.get(key)

    async def set(self, key: str, value: str) -> None:
        self.store[key] = value


class ErrorKv:
    """KvStore whose get and set always raise."""

    async def get(self, key: str) -> Optional[str]:
        raise RuntimeError("get failed")

    async def set(self, key: str, value: str) -> None:
        raise RuntimeError("set failed")


# ── Tests ─────────────────────────────────────────────────────────────────────

async def test_null_miss():
    cache = create_kv_pull_cache(MemKv())
    result = await cache.read("missing-key")
    assert result is None


async def test_round_trip():
    cache = create_kv_pull_cache(MemKv())
    payload = '{"data":{"x":1},"hash":"abc","timestamp":100}'
    await cache.write("my-key", payload)
    result = await cache.read("my-key")
    assert result == payload


async def test_prefix_isolation():
    kv = MemKv()
    cache_a = create_kv_pull_cache(kv, prefix="a:")
    cache_b = create_kv_pull_cache(kv, prefix="b:")

    await cache_a.write("key", "value-a")
    assert await cache_a.read("key") == "value-a"
    assert await cache_b.read("key") is None


async def test_ttl_expiry():
    cache = create_kv_pull_cache(MemKv(), max_age_ms=1)
    await cache.write("k", "v")
    # Wait for the 1 ms TTL to elapse.
    await asyncio.sleep(0.05)
    assert await cache.read("k") is None


async def test_ttl_not_yet_expired():
    cache = create_kv_pull_cache(MemKv(), max_age_ms=60_000)
    await cache.write("k", "fresh")
    assert await cache.read("k") == "fresh"


async def test_error_swallowing_get():
    """A KvStore whose get() raises → read() returns None, not an exception."""
    cache = create_kv_pull_cache(ErrorKv())
    result = await cache.read("any")
    assert result is None


async def test_error_swallowing_set():
    """A KvStore whose set() raises → write() is silent, no exception raised."""
    cache = create_kv_pull_cache(ErrorKv())
    await cache.write("any", "data")  # must not raise


async def test_no_prefix_default():
    kv = MemKv()
    cache = create_kv_pull_cache(kv)
    await cache.write("doc", "data")
    # Internal key must use the default prefix.
    assert "starfish.pullcache.doc" in kv.store


async def test_no_max_age_never_expires():
    cache = create_kv_pull_cache(MemKv())
    await cache.write("k", "v")
    await asyncio.sleep(0.05)
    assert await cache.read("k") == "v"
