"""Tests for StoreContext construction, forwarding, and backward-compatible arity sniff."""

import functools
import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import SyncConfig, CollectionConfig
from starfish_server.router.route_builder import create_sync_router, SyncRouterOptions, AuthResult
from starfish_server.storage.base import StoreContext
from starfish_server.storage.memory import MemoryObjectStore, CustomObjectStore, _accepts_ctx
from starfish_server.encryption.encrypted_store import EncryptedObjectStore


# ---------------------------------------------------------------------------
# _accepts_ctx arity-sniff matrix
# ---------------------------------------------------------------------------

def test_accepts_ctx_1arg_lambda_returns_false():
    assert _accepts_ctx(lambda key: None, base_arity=1) is False


def test_accepts_ctx_2arg_lambda_returns_true():
    assert _accepts_ctx(lambda key, ctx: None, base_arity=1) is False or \
           _accepts_ctx(lambda key, ctx: None, base_arity=1) is True
    # Concrete check: 2 positional args >= base_arity(1)+1 = 2 → True
    assert _accepts_ctx(lambda key, ctx: None, base_arity=1) is True


def test_accepts_ctx_async_def_1arg():
    async def fn(key): ...
    assert _accepts_ctx(fn, base_arity=1) is False


def test_accepts_ctx_async_def_2arg():
    async def fn(key, ctx): ...
    assert _accepts_ctx(fn, base_arity=1) is True


def test_accepts_ctx_functools_partial_strips_arg():
    def fn(key, ctx): ...
    partial_fn = functools.partial(fn, "fixed_key")
    # After partial binds key, only ctx remains — base_arity 1 needs 2 positional → False
    assert _accepts_ctx(partial_fn, base_arity=1) is False


def test_accepts_ctx_bound_method():
    class Store:
        def on_get(self, key): ...
        def on_get_with_ctx(self, key, ctx): ...

    s = Store()
    assert _accepts_ctx(s.on_get, base_arity=1) is False
    assert _accepts_ctx(s.on_get_with_ctx, base_arity=1) is True


def test_accepts_ctx_callable_class_1arg():
    class CB:
        def __call__(self, key): ...
    assert _accepts_ctx(CB(), base_arity=1) is False


def test_accepts_ctx_callable_class_2arg():
    class CB:
        def __call__(self, key, ctx): ...
    assert _accepts_ctx(CB(), base_arity=1) is True


def test_accepts_ctx_var_positional():
    def fn(*args): ...
    assert _accepts_ctx(fn, base_arity=1) is True


def test_accepts_ctx_put_3arg_lambda():
    # put base_arity=2 → needs 3 args to accept ctx
    assert _accepts_ctx(lambda key, body: None, base_arity=2) is False
    assert _accepts_ctx(lambda key, body, ctx: None, base_arity=2) is True


def test_accepts_ctx_list_4arg_lambda():
    # list base_arity=3 → needs 4 args
    assert _accepts_ctx(lambda p, sa, lim: None, base_arity=3) is False
    assert _accepts_ctx(lambda p, sa, lim, ctx: None, base_arity=3) is True


# ---------------------------------------------------------------------------
# CustomObjectStore does not crash with old 1-arg callbacks (backward compat)
# ---------------------------------------------------------------------------

async def test_old_1arg_on_get_still_works():
    store = CustomObjectStore(on_get=lambda key: f"val:{key}")
    result = ctx_obj = None
    result = await store.get_string("k")
    assert result == "val:k"


async def test_old_1arg_on_delete_still_works():
    deleted = []
    store = CustomObjectStore(on_delete=lambda key: deleted.append(key))
    await store.delete("x")
    assert deleted == ["x"]


async def test_new_2arg_on_get_receives_ctx():
    received = []

    async def on_get(key, ctx):
        received.append((key, ctx))
        return None

    store = CustomObjectStore(on_get=on_get)
    ctx = StoreContext(
        collection="col",
        params={"identity": "alice"},
        identity="alice",
        roles=("self",),
        action="pull",
    )
    await store.get_string("k", context=ctx)
    assert len(received) == 1
    assert received[0][0] == "k"
    assert received[0][1] is ctx


async def test_new_3arg_on_put_receives_ctx():
    received = []

    async def on_put(key, body, ctx):
        received.append((key, body, ctx))

    store = CustomObjectStore(on_put=on_put)
    ctx = StoreContext(
        collection="col",
        params={},
        identity=None,
        roles=(),
        action="push",
    )
    await store.put("k", "v", context=ctx)
    assert len(received) == 1
    assert received[0][2] is ctx


async def test_no_ctx_passed_when_context_is_none():
    """Old 1-arg callback must not receive None as ctx — it should just not be called with it."""
    received = []
    store = CustomObjectStore(on_get=lambda key: received.append(key) or "ok")
    result = await store.get_string("mykey", context=None)
    assert result == "ok"
    assert received == ["mykey"]


# ---------------------------------------------------------------------------
# HTTP integration — ctx populated from route layer
# ---------------------------------------------------------------------------

def _make_app(captured: list, identity: str = "alice", roles: list[str] | None = None):
    mem = MemoryObjectStore(data={})

    async def on_get(key, ctx):
        captured.append(ctx)
        return mem._data.get(key)

    async def on_put(key, body, ctx):
        captured.append(ctx)
        mem._data[key] = body

    async def on_list(prefix, start_after, limit, ctx):
        captured.append(ctx)
        return []

    store = CustomObjectStore(on_get=on_get, on_put=on_put, on_list=on_list)
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="profile",
                storagePath="users/{identity}/profile",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=65536,
            ),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=identity, roles=roles or [])

    router = create_sync_router(SyncRouterOptions(store=store, config=config, role_resolver=role_resolver))
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.mark.asyncio
async def test_pull_ctx_fields():
    captured: list[StoreContext] = []
    app = _make_app(captured, identity="alice", roles=["self"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/users/alice/profile")
    assert resp.status_code == 200
    assert len(captured) >= 1
    ctx = captured[0]
    assert ctx.collection == "profile"
    assert ctx.params == {"identity": "alice"}
    assert ctx.identity == "alice"
    assert "self" in ctx.roles
    assert ctx.action == "pull"
    assert ctx.namespace is None


@pytest.mark.asyncio
async def test_push_ctx_fields():
    captured: list[StoreContext] = []
    app = _make_app(captured, identity="alice", roles=["self"])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/users/alice/profile",
            json={"data": {"x": 1}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
    assert resp.status_code == 200
    push_ctxs = [c for c in captured if c.action == "push"]
    assert len(push_ctxs) >= 1
    ctx = push_ctxs[0]
    assert ctx.collection == "profile"
    assert ctx.params == {"identity": "alice"}
    assert ctx.identity == "alice"
    assert ctx.action == "push"


@pytest.mark.asyncio
async def test_public_route_ctx_no_identity():
    captured: list[StoreContext] = []
    mem = MemoryObjectStore(data={})

    async def on_get(key, ctx):
        captured.append(ctx)
        return mem._data.get(key)

    store = CustomObjectStore(on_get=on_get)
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="announcements",
                storagePath="app/announcements",
                readRoles=["public"],
                writeRoles=["admin"],
                encryption="none",
                maxBodyBytes=65536,
            ),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=None, roles=[])

    router = create_sync_router(SyncRouterOptions(store=store, config=config, role_resolver=role_resolver))
    app = FastAPI()
    app.include_router(router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/app/announcements")
    assert resp.status_code == 200
    assert len(captured) >= 1
    ctx = captured[0]
    assert ctx.identity is None
    assert ctx.roles == ()
    assert ctx.action == "pull"


@pytest.mark.asyncio
async def test_namespace_route_ctx_namespace_field():
    captured: list[StoreContext] = []
    mem = MemoryObjectStore(data={})

    async def on_get(key, ctx):
        captured.append(ctx)
        return mem._data.get(key)

    async def on_put(key, body, ctx):
        captured.append(ctx)
        mem._data[key] = body

    store = CustomObjectStore(on_get=on_get, on_put=on_put)
    config = SyncConfig(
        version=1,
        collections=[],
        namespaces={
            "org": {
                "collections": [
                    CollectionConfig(
                        name="prefs",
                        storagePath="orgs/{identity}/prefs",
                        readRoles=["self"],
                        writeRoles=["self"],
                        encryption="none",
                        maxBodyBytes=65536,
                    ),
                ]
            }
        },
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="alice", roles=["self"])

    router = create_sync_router(SyncRouterOptions(store=store, config=config, role_resolver=role_resolver))
    app = FastAPI()
    app.include_router(router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/org/pull/orgs/alice/prefs")
    assert resp.status_code == 200
    assert len(captured) >= 1
    ctx = captured[0]
    assert ctx.namespace == "org"
    assert ctx.collection == "prefs"
    assert ctx.action == "pull"


@pytest.mark.asyncio
async def test_encrypted_store_forwards_same_ctx():
    """EncryptedObjectStore must pass the same StoreContext object to its inner store."""
    captured_inner: list[StoreContext] = []
    mem = MemoryObjectStore(data={})

    async def on_get(key, ctx):
        captured_inner.append(ctx)
        return mem._data.get(key)

    async def on_put(key, body, ctx):
        captured_inner.append(ctx)
        mem._data[key] = body

    inner = CustomObjectStore(on_get=on_get, on_put=on_put)
    encrypted = EncryptedObjectStore(inner, secret="secret", salt="salt", info="starfish-data")

    ctx = StoreContext(
        collection="profile",
        params={"identity": "alice"},
        identity="alice",
        roles=("self",),
        action="push",
    )
    await encrypted.put("k", '{"x":1}', context=ctx)
    await encrypted.get_string("k", context=ctx)

    push_ctxs = [c for c in captured_inner if c is ctx]
    assert len(push_ctxs) >= 2  # put + get both forwarded the same ctx object


@pytest.mark.asyncio
async def test_bundle_pull_ctx_collection_per_collection():
    """Bundle pull: each bundled collection gets its own ctx.collection."""
    captured: list[StoreContext] = []
    mem = MemoryObjectStore(data={})

    async def on_get(key, ctx):
        captured.append(ctx)
        return mem._data.get(key)

    store = CustomObjectStore(on_get=on_get)
    config = SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="alpha",
                storagePath="users/{identity}/data",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=65536,
                bundle="mybundle",
            ),
            CollectionConfig(
                name="beta",
                storagePath="users/{identity}/data",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=65536,
                bundle="mybundle",
            ),
        ],
    )

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="alice", roles=["self"])

    router = create_sync_router(SyncRouterOptions(store=store, config=config, role_resolver=role_resolver))
    app = FastAPI()
    app.include_router(router)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/users/alice/data")
    assert resp.status_code == 200
    collection_names = {c.collection for c in captured}
    assert "alpha" in collection_names
    assert "beta" in collection_names
