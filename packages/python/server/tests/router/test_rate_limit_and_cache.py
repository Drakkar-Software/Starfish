"""Tests for per-collection rate limit overrides, cache duration, and object schema validation."""

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import (
    SyncConfig,
    CollectionConfig,
    CollectionRateLimitConfig,
    RateLimitConfig,
)
from starfish_server.router.route_builder import (
    create_sync_router,
    SyncRouterOptions,
    AuthResult,
)
from tests.helpers import MemoryObjectStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_app(
    collections: list[CollectionConfig],
    global_rate_limit: RateLimitConfig | None = None,
    identity: str = "user-1",
    roles: list[str] | None = None,
) -> tuple[FastAPI, MemoryObjectStore]:
    """Build a test app. ``roles`` defaults to empty list."""
    store = MemoryObjectStore()
    config = SyncConfig(
        version=1,
        collections=collections,
        rateLimit=global_rate_limit,
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=identity, roles=roles or [])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


def _col(
    name: str = "settings",
    rate_limit=None,
    cache_duration_ms: int | None = None,
) -> CollectionConfig:
    return CollectionConfig(
        name=name,
        storagePath=f"users/{{identity}}/{name}",
        readRoles=["self"],
        writeRoles=["self"],
        encryption="none",
        maxBodyBytes=65536,
        rateLimit=rate_limit,
        cacheDurationMs=cache_duration_ms,
    )


async def _push(client: AsyncClient, path: str, data: dict | None = None, base_hash=None):
    """Push helper that returns the response. Uses the given base_hash."""
    resp = await client.post(
        path,
        json={"data": data or {"v": 1}, "baseHash": base_hash},
        headers={"content-type": "application/json"},
    )
    return resp


async def _push_n(client: AsyncClient, path: str, n: int):
    """Push n times, chaining the hash from each successful push."""
    last_hash = None
    responses: list = []
    for i in range(n):
        resp = await _push(client, path, {"v": i}, base_hash=last_hash)
        responses.append(resp)
        if resp.status_code == 200:
            last_hash = resp.json().get("hash")
    return responses


# ---------------------------------------------------------------------------
# Schema: rateLimit coercion
# ---------------------------------------------------------------------------

class TestRateLimitCoercion:
    """The rateLimit field accepts true, false, null, or an object."""

    def test_true_becomes_empty_config(self):
        col = _col(rate_limit=True)
        assert isinstance(col.rate_limit, CollectionRateLimitConfig)
        assert col.rate_limit.window_ms is None
        assert col.rate_limit.max_requests is None

    def test_false_becomes_none(self):
        col = _col(rate_limit=False)
        assert col.rate_limit is None

    def test_none_stays_none(self):
        col = _col(rate_limit=None)
        assert col.rate_limit is None

    def test_object_is_parsed(self):
        col = CollectionConfig(
            name="x",
            storagePath="x",
            readRoles=["self"],
            writeRoles=["self"],
            encryption="none",
            maxBodyBytes=1024,
            rateLimit={"windowMs": 1000, "maxRequests": 5},
        )
        assert col.rate_limit is not None
        assert col.rate_limit.window_ms == 1000
        assert col.rate_limit.max_requests == 5

    def test_partial_object_is_parsed(self):
        col = CollectionConfig(
            name="x",
            storagePath="x",
            readRoles=["self"],
            writeRoles=["self"],
            encryption="none",
            maxBodyBytes=1024,
            rateLimit={"maxRequests": 3},
        )
        assert col.rate_limit is not None
        assert col.rate_limit.window_ms is None
        assert col.rate_limit.max_requests == 3


# ---------------------------------------------------------------------------
# Schema: cacheDurationMs
# ---------------------------------------------------------------------------

class TestCacheDurationSchema:
    def test_default_is_none(self):
        col = _col()
        assert col.cache_duration_ms is None

    def test_set_via_alias(self):
        col = _col(cache_duration_ms=30_000)
        assert col.cache_duration_ms == 30_000

    def test_rejects_zero(self):
        with pytest.raises(Exception):
            CollectionConfig(
                name="x",
                storagePath="x",
                readRoles=[],
                writeRoles=[],
                encryption="none",
                maxBodyBytes=1024,
                cacheDurationMs=0,
            )

    def test_rejects_negative(self):
        with pytest.raises(Exception):
            CollectionConfig(
                name="x",
                storagePath="x",
                readRoles=[],
                writeRoles=[],
                encryption="none",
                maxBodyBytes=1024,
                cacheDurationMs=-1,
            )


# ---------------------------------------------------------------------------
# Rate limiting: global defaults via rateLimit=true
# ---------------------------------------------------------------------------

PUSH_PATH = "/push/users/user-1/settings"
PULL_PATH = "/pull/users/user-1/settings"


@pytest.mark.asyncio
async def test_rate_limit_true_uses_global_defaults():
    """rateLimit: true on a collection + global config → uses global values."""
    global_rl = RateLimitConfig(windowMs=60_000, maxRequests=3)
    app, _ = _build_app([_col(rate_limit=True)], global_rate_limit=global_rl)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        responses = await _push_n(client, PUSH_PATH, 3)
        assert all(r.status_code == 200 for r in responses)

        resp = await _push(client, PUSH_PATH, {"v": 99}, responses[-1].json()["hash"])
        assert resp.status_code == 429


@pytest.mark.asyncio
async def test_rate_limit_true_without_global_config_is_noop():
    """rateLimit: true but no global rateLimit → no rate limiting."""
    app, _ = _build_app([_col(rate_limit=True)], global_rate_limit=None)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        responses = await _push_n(client, PUSH_PATH, 10)
        assert all(r.status_code == 200 for r in responses)


# ---------------------------------------------------------------------------
# Rate limiting: per-collection overrides
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_per_collection_max_requests_override():
    """Collection overrides maxRequests while inheriting windowMs from global."""
    global_rl = RateLimitConfig(windowMs=60_000, maxRequests=100)
    col = _col(rate_limit={"maxRequests": 2})
    app, _ = _build_app([col], global_rate_limit=global_rl)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        responses = await _push_n(client, PUSH_PATH, 2)
        assert all(r.status_code == 200 for r in responses)

        resp = await _push(client, PUSH_PATH, {"v": 99}, responses[-1].json()["hash"])
        assert resp.status_code == 429


@pytest.mark.asyncio
async def test_per_collection_full_override():
    """Collection overrides both windowMs and maxRequests."""
    global_rl = RateLimitConfig(windowMs=60_000, maxRequests=100)
    col = _col(rate_limit={"windowMs": 1000, "maxRequests": 1})
    app, _ = _build_app([col], global_rate_limit=global_rl)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, PUSH_PATH)
        assert resp.status_code == 200

        resp = await _push(client, PUSH_PATH, {"v": 2}, resp.json()["hash"])
        assert resp.status_code == 429


@pytest.mark.asyncio
async def test_rate_limit_disabled_allows_unlimited():
    """rateLimit: null (default) → no rate limiting even with global config."""
    global_rl = RateLimitConfig(windowMs=60_000, maxRequests=1)
    col = _col(rate_limit=None)
    app, _ = _build_app([col], global_rate_limit=global_rl)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        responses = await _push_n(client, PUSH_PATH, 10)
        assert all(r.status_code == 200 for r in responses)


@pytest.mark.asyncio
async def test_different_collections_have_independent_rate_limits():
    """Two collections with different rate limits are enforced independently."""
    global_rl = RateLimitConfig(windowMs=60_000, maxRequests=100)
    col_a = _col(name="settings", rate_limit={"maxRequests": 1})
    col_b = _col(name="prefs", rate_limit={"maxRequests": 3})
    app, _ = _build_app([col_a, col_b], global_rate_limit=global_rl)

    path_a = "/push/users/user-1/settings"
    path_b = "/push/users/user-1/prefs"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # col_a: 1 allowed, then blocked
        resp = await _push(client, path_a)
        assert resp.status_code == 200
        resp = await _push(client, path_a, {"v": 2}, resp.json()["hash"])
        assert resp.status_code == 429

        # col_b: still has its own budget of 3
        responses = await _push_n(client, path_b, 3)
        assert all(r.status_code == 200 for r in responses)
        resp = await _push(client, path_b, {"v": 99}, responses[-1].json()["hash"])
        assert resp.status_code == 429


# ---------------------------------------------------------------------------
# Rate limiting: only applies to push
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rate_limit_does_not_affect_pull():
    """Rate limiting only applies to push — pull is always allowed."""
    global_rl = RateLimitConfig(windowMs=60_000, maxRequests=1)
    app, _ = _build_app([_col(rate_limit=True)], global_rate_limit=global_rl)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for _ in range(5):
            resp = await client.get(PULL_PATH)
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Cache duration
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cache_duration_sets_header_on_pull():
    """cacheDurationMs adds a Cache-Control header to pull responses.

    Non-public collections (readRoles != ["public"]) get ``private, max-age=…``.
    """
    col = _col(cache_duration_ms=30_000)
    app, _ = _build_app([col])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(PULL_PATH)
        assert resp.status_code == 200
        assert resp.headers["cache-control"] == "private, max-age=30"


@pytest.mark.asyncio
async def test_cache_duration_public_collection():
    """Public collections get ``max-age=…`` without the ``private`` directive."""
    col = CollectionConfig(
        name="announcements",
        storagePath="announcements",
        readRoles=["public"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
        cacheDurationMs=60_000,
    )
    app, _ = _build_app([col], roles=["admin"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/announcements")
        assert resp.status_code == 200
        assert resp.headers["cache-control"] == "max-age=60"


@pytest.mark.asyncio
async def test_cache_duration_converts_ms_to_seconds():
    """Milliseconds are converted to whole seconds (truncated)."""
    col = _col(cache_duration_ms=1_500)
    app, _ = _build_app([col])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(PULL_PATH)
        assert resp.headers["cache-control"] == "private, max-age=1"


@pytest.mark.asyncio
async def test_no_cache_header_when_not_configured():
    """No Cache-Control header by default."""
    col = _col()
    app, _ = _build_app([col])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(PULL_PATH)
        assert resp.status_code == 200
        assert "cache-control" not in resp.headers


@pytest.mark.asyncio
async def test_cache_duration_does_not_affect_push():
    """Push responses never get Cache-Control, even if cacheDurationMs is set."""
    col = _col(cache_duration_ms=60_000)
    app, _ = _build_app([col])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, PUSH_PATH)
        assert resp.status_code == 200
        assert "cache-control" not in resp.headers


# ---------------------------------------------------------------------------
# Combined: rate limit + cache on the same collection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rate_limit_and_cache_together():
    """Both features work on the same collection."""
    global_rl = RateLimitConfig(windowMs=60_000, maxRequests=2)
    col = _col(rate_limit=True, cache_duration_ms=10_000)
    app, _ = _build_app([col], global_rate_limit=global_rl)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Pull has cache header (private because readRoles=["self"])
        resp = await client.get(PULL_PATH)
        assert resp.headers["cache-control"] == "private, max-age=10"

        # Push is rate-limited
        responses = await _push_n(client, PUSH_PATH, 2)
        assert all(r.status_code == 200 for r in responses)
        resp = await _push(client, PUSH_PATH, {"v": 99}, responses[-1].json()["hash"])
        assert resp.status_code == 429
