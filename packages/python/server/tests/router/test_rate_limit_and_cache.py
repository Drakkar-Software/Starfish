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
from starfish_server.router.middleware import RateLimiter
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


# ── RateLimiter class unit tests (cross-language parity with middleware.test.ts) ──


async def test_rate_limiter_allows_up_to_limit_then_rejects():
    rl = RateLimiter(window_ms=60_000, max_requests=3)
    assert await rl.check("u") is None
    assert await rl.check("u") is None
    assert await rl.check("u") is None
    resp = await rl.check("u")
    assert resp is not None and resp.status_code == 429  # 4th over the limit of 3


async def test_rate_limiter_isolates_counters_per_key():
    rl = RateLimiter(window_ms=60_000, max_requests=1)
    assert await rl.check("a") is None
    assert await rl.check("a") is not None  # over the limit
    assert await rl.check("b") is None  # a different key is unaffected


async def test_rate_limiter_bounds_bucket_count():
    # A flood of distinct keys (e.g. spoofed X-Forwarded-For) must not grow memory
    # without bound — the limiter's store caps at max_buckets and evicts the oldest.
    # Asserted behaviorally (no public size accessor): an old key was evicted (restarts),
    # a recent one retains its count. Mirrors the TS twin in kv-adapter.test.ts.
    rl = RateLimiter(window_ms=60_000, max_requests=100, max_buckets=8)
    for i in range(200):
        await rl.check(f"k{i}")
    # k0 was evicted long ago → first check after the flood is fresh (count 1, well under 100).
    assert await rl.check("k0") is None
    assert await rl.check("k199") is None  # still under the limit either way


async def test_rate_limiter_key_precedence_identity_xff_client_ip_anonymous():
    # Identical precedence to the TS limiter; pins the convergence. (The runtimes differ
    # only in which signals they can supply — the Python server passes the socket IP as
    # client_ip, which Hono cannot.)
    rl = RateLimiter(window_ms=60_000, max_requests=1)
    assert await rl.check("user-1", "1.2.3.4", "5.6.7.8") is None  # identity wins
    assert await rl.check("user-1", "9.9.9.9", "8.8.8.8") is not None  # same identity bucket
    assert await rl.check(None, "1.1.1.1, 2.2.2.2", None) is None  # first XFF hop
    assert await rl.check(None, "1.1.1.1", None) is not None  # same first-hop bucket
    assert await rl.check(None, None, "3.3.3.3") is None  # client IP when no identity/XFF
    assert await rl.check(None, None, "3.3.3.3") is not None
    assert await rl.check(None, None, None) is None  # shared anonymous fallback
    assert await rl.check(None, None, None) is not None


async def test_rate_limiter_ip_mode_ignores_identity():
    # In "ip" mode, two identities sharing one IP collapse into one bucket. Mirrors the
    # TS twin in middleware.test.ts.
    rl = RateLimiter(window_ms=60_000, max_requests=1, bucket_mode="ip")
    assert await rl.check("alice", "1.2.3.4", None) is None
    resp = await rl.check("bob", "1.2.3.4", None)
    assert resp is not None and resp.status_code == 429  # same IP, different identity
    assert await rl.check("carol", "9.9.9.9", None) is None  # different IP, fresh bucket


async def test_rate_limiter_ip_mode_uses_client_ip_then_anonymous():
    rl = RateLimiter(window_ms=60_000, max_requests=1, bucket_mode="ip")
    assert await rl.check("alice", None, "5.5.5.5") is None  # client IP when no XFF
    assert await rl.check("bob", None, "5.5.5.5") is not None
    assert await rl.check("alice", None, None) is None  # no IP signal → anonymous
    assert await rl.check("bob", None, None) is not None  # shared anonymous bucket


async def test_rate_limiter_identity_plus_ip_mode_keys_by_pair():
    # One budget per distinct (identity, ip) combination. Mirrors the TS twin.
    rl = RateLimiter(window_ms=60_000, max_requests=1, bucket_mode="identity+ip")
    assert await rl.check("alice", "1.1.1.1", None) is None
    assert await rl.check("alice", "1.1.1.1", None) is not None  # same pair exhausted
    assert await rl.check("alice", "2.2.2.2", None) is None  # same identity, different ip
    assert await rl.check("bob", "1.1.1.1", None) is None  # same ip, different identity


async def test_check_rate_limiters_empty_is_unmetered():
    from starfish_server.router.middleware import check_rate_limiters
    assert await check_rate_limiters([], "u", None) is None


async def test_check_rate_limiters_rejects_if_either_dimension_trips():
    from starfish_server.router.middleware import check_rate_limiters
    id_limiter = RateLimiter(window_ms=60_000, max_requests=5, bucket_mode="identity")
    ip_limiter = RateLimiter(window_ms=60_000, max_requests=1, bucket_mode="ip")
    limiters = [id_limiter, ip_limiter]

    assert await check_rate_limiters(limiters, "alice", "1.1.1.1") is None
    # Same identity + ip: ip cap (1) trips.
    assert await check_rate_limiters(limiters, "alice", "1.1.1.1") is not None
    # Fresh ip each time: ip ok, but identity counter keeps climbing (every call counts).
    assert await check_rate_limiters(limiters, "alice", "2.2.2.2") is None  # id #3
    assert await check_rate_limiters(limiters, "alice", "3.3.3.3") is None  # id #4
    assert await check_rate_limiters(limiters, "alice", "4.4.4.4") is None  # id #5
    assert await check_rate_limiters(limiters, "alice", "5.5.5.5") is not None  # id exhausted


# ---------------------------------------------------------------------------
# Per-action rate limiting (push / pull / list independently)
# ---------------------------------------------------------------------------

from starfish_server.config.validate import validate_config


def _listable_col(name: str = "items", rate_limit=None) -> CollectionConfig:
    return CollectionConfig(
        name=name,
        storagePath=f"users/{{identity}}/{name}/{{itemId}}",
        readRoles=["self"],
        writeRoles=["self"],
        encryption="none",
        maxBodyBytes=65536,
        listable=True,
        rateLimit=rate_limit,
    )


@pytest.mark.asyncio
async def test_push_rule_does_not_throttle_pull_or_list():
    col = _listable_col(rate_limit={"push": {"windowMs": 60_000, "maxRequests": 2}})
    app, _ = _build_app([col])
    push_path = "/push/users/user-1/items/item-1"
    pull_path = "/pull/users/user-1/items/item-1"
    list_path = "/list/users/user-1/items"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        responses = await _push_n(client, push_path, 2)
        assert all(r.status_code == 200 for r in responses)
        resp = await _push(client, push_path, {"v": 9}, responses[-1].json()["hash"])
        assert resp.status_code == 429  # push exhausted

        # pull and list have no rule → never throttled
        for _ in range(5):
            assert (await client.get(pull_path)).status_code == 200
            assert (await client.get(list_path)).status_code == 200


@pytest.mark.asyncio
async def test_pull_rule_limits_pull_only():
    col = _listable_col(rate_limit={"pull": {"windowMs": 60_000, "maxRequests": 1}})
    app, _ = _build_app([col])
    pull_path = "/pull/users/user-1/items/item-1"
    push_path = "/push/users/user-1/items/item-1"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get(pull_path)).status_code == 200
        assert (await client.get(pull_path)).status_code == 429  # pull limited at 1

        # push has no rule → unaffected
        responses = await _push_n(client, push_path, 3)
        assert all(r.status_code == 200 for r in responses)


@pytest.mark.asyncio
async def test_list_rule_limits_list_only():
    col = _listable_col(rate_limit={"list": {"windowMs": 60_000, "maxRequests": 1}})
    app, _ = _build_app([col])
    list_path = "/list/users/user-1/items"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get(list_path)).status_code == 200
        assert (await client.get(list_path)).status_code == 429


@pytest.mark.asyncio
async def test_each_action_keeps_its_own_counter():
    col = _listable_col(
        rate_limit={"push": {"windowMs": 60_000, "maxRequests": 1}, "pull": {"windowMs": 60_000, "maxRequests": 1}}
    )
    app, _ = _build_app([col])
    push_path = "/push/users/user-1/items/item-1"
    pull_path = "/pull/users/user-1/items/item-1"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, push_path)
        assert resp.status_code == 200
        resp = await _push(client, push_path, {"v": 2}, resp.json()["hash"])
        assert resp.status_code == 429  # push exhausted
        # pull still has its own budget of 1
        assert (await client.get(pull_path)).status_code == 200
        assert (await client.get(pull_path)).status_code == 429


@pytest.mark.asyncio
async def test_ip_bucket_separates_by_forwarded_for():
    # role_resolver returns a constant identity, so identity-bucketing would group all
    # requests; "ip" mode must instead split by X-Forwarded-For.
    col = _listable_col(rate_limit={"push": {"windowMs": 60_000, "maxRequests": 1, "bucket": "ip"}})
    app, _ = _build_app([col])
    push_path = "/push/users/user-1/items/item-1"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r1 = await client.post(push_path, json={"data": {"v": 1}, "baseHash": None},
                               headers={"content-type": "application/json", "x-forwarded-for": "1.1.1.1"})
        assert r1.status_code == 200
        r2 = await client.post(push_path, json={"data": {"v": 2}, "baseHash": r1.json()["hash"]},
                               headers={"content-type": "application/json", "x-forwarded-for": "1.1.1.1"})
        assert r2.status_code == 429  # same IP exhausted
        r3 = await client.post(push_path, json={"data": {"v": 3}, "baseHash": r1.json()["hash"]},
                               headers={"content-type": "application/json", "x-forwarded-for": "2.2.2.2"})
        assert r3.status_code == 200  # different IP, fresh budget


def test_validation_rejects_unresolvable_rule():
    config = SyncConfig(version=1, collections=[_listable_col(rate_limit={"pull": {"maxRequests": 5}})])
    errors = validate_config(config)
    assert any("rateLimit.pull must resolve" in e for e in errors)


def test_validation_accepts_rule_inheriting_window_from_global():
    config = SyncConfig(
        version=1,
        collections=[_listable_col(rate_limit={"pull": {"maxRequests": 5}})],
        rateLimit=RateLimitConfig(windowMs=60_000, maxRequests=100),
    )
    assert validate_config(config) == []


@pytest.mark.asyncio
async def test_composite_identity_plus_ip_bucket():
    # One budget per (identity, ip) pair; constant identity, varying ip → fresh budgets.
    col = _listable_col(rate_limit={"push": {"windowMs": 60_000, "maxRequests": 1, "bucket": "identity+ip"}})
    app, _ = _build_app([col])
    push_path = "/push/users/user-1/items/item-1"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r1 = await client.post(push_path, json={"data": {"v": 1}, "baseHash": None},
                               headers={"content-type": "application/json", "x-forwarded-for": "1.1.1.1"})
        assert r1.status_code == 200
        r2 = await client.post(push_path, json={"data": {"v": 2}, "baseHash": r1.json()["hash"]},
                               headers={"content-type": "application/json", "x-forwarded-for": "1.1.1.1"})
        assert r2.status_code == 429  # same pair exhausted
        r3 = await client.post(push_path, json={"data": {"v": 3}, "baseHash": r1.json()["hash"]},
                               headers={"content-type": "application/json", "x-forwarded-for": "2.2.2.2"})
        assert r3.status_code == 200  # different ip → fresh pair


@pytest.mark.asyncio
async def test_two_independent_limits_reject_if_either_trips():
    # identity <= 3, ip <= 1 within one window; identity constant across requests.
    col = _listable_col(
        rate_limit={"push": {"windowMs": 60_000, "identity": {"maxRequests": 3}, "ip": {"maxRequests": 1}}}
    )
    app, _ = _build_app([col])
    push_path = "/push/users/user-1/items/item-1"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        last_hash = None

        async def push_from(ip: str):
            nonlocal last_hash
            resp = await client.post(
                push_path,
                json={"data": {"v": 1}, "baseHash": last_hash},
                headers={"content-type": "application/json", "x-forwarded-for": ip},
            )
            if resp.status_code == 200:
                last_hash = resp.json()["hash"]
            return resp

        assert (await push_from("1.1.1.1")).status_code == 200  # id#1, ip(1)#1
        assert (await push_from("1.1.1.1")).status_code == 429  # ip(1) cap 1 trips
        assert (await push_from("2.2.2.2")).status_code == 200  # id#3, ip(2)#1 ok
        assert (await push_from("3.3.3.3")).status_code == 429  # id cap 3 exhausted


def test_validation_rejects_bucket_with_sub_limit():
    config = SyncConfig(
        version=1,
        collections=[_listable_col(
            rate_limit={"push": {"windowMs": 1, "maxRequests": 1, "bucket": "ip", "identity": {"maxRequests": 5}}}
        )],
    )
    errors = validate_config(config)
    assert any('cannot set both "bucket" and an "identity"/"ip"' in e for e in errors)


def test_validation_rejects_unresolvable_dimension():
    config = SyncConfig(
        version=1,
        collections=[_listable_col(rate_limit={"push": {"ip": {"maxRequests": 5}}})],  # no windowMs anywhere
    )
    errors = validate_config(config)
    assert any("rateLimit.push.ip must resolve" in e for e in errors)
