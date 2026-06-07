"""Integration tests: the restrictions plugin wired into a real router."""

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server import (
    CollectionConfig,
    NamespaceConfig,
    SyncConfig,
)
from starfish_server.router.route_builder import (
    AuthResult,
    SyncRouterOptions,
    create_sync_router,
)
from starfish_server.storage.memory import MemoryObjectStore
from starfish_protocol.plugins import AuthorizeContext, AuthorizeResult, ServerPlugin

from starfish_restrictions import (
    RestrictionRule,
    RestrictionScope,
    create_restrictions_plugin,
)


def _config() -> SyncConfig:
    return SyncConfig(
        version=1,
        collections=[
            CollectionConfig(
                name="settings",
                storagePath="users/{identity}/settings",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=65536,
            ),
            CollectionConfig(
                name="public-data",
                storagePath="public/data",
                readRoles=["public"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=65536,
            ),
            CollectionConfig(
                name="docs",
                storagePath="users/{identity}/docs/{doc_id}",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=65536,
                listable=True,
            ),
            CollectionConfig(
                name="prefs",
                storagePath="users/{identity}/bundle",
                bundle="userdata",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=65536,
            ),
            CollectionConfig(
                name="profile",
                storagePath="users/{identity}/bundle",
                bundle="userdata",
                readRoles=["self"],
                writeRoles=["self"],
                encryption="none",
                maxBodyBytes=65536,
            ),
        ],
    )


def _build(plugins=None, identity="blocked"):
    store = MemoryObjectStore(data={})
    config = _config()

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=identity, roles=["self"])

    router = create_sync_router(
        SyncRouterOptions(
            store=store,
            config=config,
            role_resolver=role_resolver,
            plugins=plugins,
        )
    )
    app = FastAPI()
    app.include_router(router)
    return app


async def _client(app):
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def test_pull_denied_when_rule_matches():
    app = _build(plugins=[create_restrictions_plugin(rules=[
        RestrictionRule(mode="deny", identities=["blocked"]),
    ])])
    async with await _client(app) as c:
        resp = await c.get("/pull/users/blocked/settings")
    assert resp.status_code == 403
    assert resp.json()["error"] == "identity restricted"


async def test_pull_allowed_without_plugin():
    app = _build()
    async with await _client(app) as c:
        resp = await c.get("/pull/users/blocked/settings")
    assert resp.status_code == 200


async def test_push_denied_by_action_scope():
    app = _build(plugins=[create_restrictions_plugin(rules=[
        RestrictionRule(mode="deny", identities=["blocked"], scope=RestrictionScope(action="push")),
    ])])
    async with await _client(app) as c:
        # pull still works
        assert (await c.get("/pull/users/blocked/settings")).status_code == 200
        resp = await c.post(
            "/push/users/blocked/settings",
            json={"data": {"theme": "dark"}, "baseHash": None},
        )
    assert resp.status_code == 403


async def test_list_denied():
    app = _build(plugins=[create_restrictions_plugin(rules=[
        RestrictionRule(mode="deny", identities=["blocked"], scope=RestrictionScope(action="list")),
    ])])
    async with await _client(app) as c:
        resp = await c.get("/list/users/blocked/docs")
    assert resp.status_code == 403


async def test_public_collection_restriction_applies():
    app = _build(plugins=[create_restrictions_plugin(rules=[
        RestrictionRule(mode="deny", identities=["blocked"]),
    ])])
    async with await _client(app) as c:
        resp = await c.get("/pull/public/data")
    assert resp.status_code == 403
    # without the plugin the public collection is anonymously readable
    open_app = _build()
    async with await _client(open_app) as c:
        assert (await c.get("/pull/public/data")).status_code == 200


async def test_batch_pull_member_denied():
    app = _build(plugins=[create_restrictions_plugin(rules=[
        RestrictionRule(mode="deny", identities=["blocked"], scope=RestrictionScope(collection="settings")),
    ])])
    async with await _client(app) as c:
        resp = await c.get("/batch/pull?collections=settings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["collections"]["settings"][0]["error"] == "identity restricted"


async def test_anonymous_identity_normalized_to_none_in_hook():
    # The default resolver represents anonymous as "" — the hook must see None
    # per the AuthorizeContext contract.
    seen: dict[str, AuthorizeContext] = {}

    async def authorize(ctx: AuthorizeContext) -> AuthorizeResult:
        seen["ctx"] = ctx
        return AuthorizeResult(action="proceed")

    capture = ServerPlugin(name="capture", authorize=authorize)
    app = _build(plugins=[capture], identity="")
    async with await _client(app) as c:
        resp = await c.get("/pull/public/data")
    assert resp.status_code == 200
    assert seen["ctx"].identity is None


async def test_anonymous_not_denied_by_deny_rule():
    app = _build(
        plugins=[create_restrictions_plugin(rules=[
            RestrictionRule(mode="deny", identities=["someone"]),
        ])],
        identity="",
    )
    async with await _client(app) as c:
        resp = await c.get("/pull/public/data")
    assert resp.status_code == 200


async def test_bundle_member_omitted_when_restricted():
    app = _build(plugins=[create_restrictions_plugin(rules=[
        RestrictionRule(mode="deny", identities=["blocked"], scope=RestrictionScope(collection="profile")),
    ])])
    async with await _client(app) as c:
        resp = await c.get("/pull/users/blocked/bundle")
    assert resp.status_code == 200
    body = resp.json()
    assert "prefs" in body["collections"]
    assert "profile" not in body["collections"]
