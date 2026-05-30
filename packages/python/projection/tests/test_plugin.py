"""Integration tests — the projection plugin maintains a materialized view on push."""

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import SyncConfig, CollectionConfig
from starfish_server.router.route_builder import (
    create_sync_router,
    SyncRouterOptions,
    AuthResult,
)
from starfish_projection import (
    Projection,
    ProjectionUpsert,
    ProjectionDelete,
    create_projection_server_plugin,
)
from starfish_protocol.plugins import WriteEvent

from tests.helpers import MemoryObjectStore


def _build_app(collections: list[CollectionConfig], projections: list[Projection]):
    store = MemoryObjectStore()
    config = SyncConfig(version=1, collections=collections)

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["self"])

    plugin = create_projection_server_plugin(store=store, projections=projections)
    router = create_sync_router(
        SyncRouterOptions(
            store=store, config=config, role_resolver=role_resolver, plugins=[plugin],
        ),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


def _col(name: str, storage_path: str, **overrides) -> CollectionConfig:
    return CollectionConfig(
        name=name,
        storagePath=storage_path,
        readRoles=["self"],
        writeRoles=["self"],
        encryption="none",
        maxBodyBytes=1_000_000,
        **overrides,
    )


async def _push(client: AsyncClient, path: str, data: dict) -> None:
    # Read the current hash first so an update to an existing key passes the
    # optimistic-concurrency check (a second push with baseHash:None would 409).
    pull_path = path.replace("/push/", "/pull/")
    cur = await client.get(pull_path)
    base_hash = (cur.json().get("hash") or None) if cur.status_code == 200 else None
    resp = await client.post(
        path,
        json={"data": data, "baseHash": base_hash},
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_upserts_target_from_source_write():
    app, _ = _build_app(
        collections=[
            _col("source", "src/{id}"),
            _col("view", "view/{id}", pullOnly=True, listable=True, listValues=True),
        ],
        projections=[
            Projection(
                source="source",
                project=lambda e: ProjectionUpsert(
                    key=f"view/{e.params['id']}",
                    data={"id": e.params["id"], "name": (e.body or {}).get("name", ""), "indexed": True},
                ),
            )
        ],
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/src/a1", {"name": "Alpha"})
        resp = await client.get("/pull/view/a1")
    assert resp.status_code == 200
    assert resp.json()["data"] == {"id": "a1", "name": "Alpha", "indexed": True}


@pytest.mark.asyncio
async def test_reprojects_on_update():
    app, _ = _build_app(
        collections=[_col("source", "src/{id}"), _col("view", "view/{id}", pullOnly=True)],
        projections=[
            Projection(
                source="source",
                project=lambda e: ProjectionUpsert(
                    key=f"view/{e.params['id']}", data={"name": (e.body or {}).get("name", "")}
                ),
            )
        ],
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/src/a1", {"name": "First"})
        await _push(client, "/push/src/a1", {"name": "Second"})
        resp = await client.get("/pull/view/a1")
    assert resp.json()["data"] == {"name": "Second"}


@pytest.mark.asyncio
async def test_deletes_target_on_delete_result():
    def project(e: WriteEvent):
        key = f"view/{e.params['id']}"
        if (e.body or {}).get("hidden") is True:
            return ProjectionDelete(key=key)
        return ProjectionUpsert(key=key, data={"name": (e.body or {}).get("name", "")})

    app, store = _build_app(
        collections=[_col("source", "src/{id}"), _col("view", "view/{id}", pullOnly=True)],
        projections=[Projection(source="source", project=project)],
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/src/a1", {"name": "Visible"})
        assert await store.get_string("view/a1") is not None
        await _push(client, "/push/src/a1", {"hidden": True})
        assert await store.get_string("view/a1") is None


@pytest.mark.asyncio
async def test_ignores_when_project_returns_none():
    app, store = _build_app(
        collections=[_col("source", "src/{id}"), _col("view", "view/{id}", pullOnly=True)],
        projections=[Projection(source="source", project=lambda e: None)],
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/src/a1", {"name": "Alpha"})
    assert await store.get_string("view/a1") is None


@pytest.mark.asyncio
async def test_only_fires_for_named_source():
    app, store = _build_app(
        collections=[
            _col("watched", "watched/{id}"),
            _col("other", "other/{id}"),
            _col("view", "view/{id}", pullOnly=True),
        ],
        projections=[
            Projection(
                source="watched",
                project=lambda e: ProjectionUpsert(key=f"view/{e.params['id']}", data={"ok": True}),
            )
        ],
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/other/a1", {"name": "x"})
        assert await store.get_string("view/a1") is None
        await _push(client, "/push/watched/a1", {"name": "x"})
        assert await store.get_string("view/a1") is not None


@pytest.mark.asyncio
async def test_supports_multiple_sources():
    app, _ = _build_app(
        collections=[
            _col("a", "a/{id}"),
            _col("b", "b/{id}"),
            _col("view", "view/{id}", pullOnly=True),
        ],
        projections=[
            Projection(
                source=["a", "b"],
                project=lambda e: ProjectionUpsert(key=f"view/{e.params['id']}", data={"from": e.collection}),
            )
        ],
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/a/k", {"v": 1})
        assert (await client.get("/pull/view/k")).json()["data"] == {"from": "a"}
        await _push(client, "/push/b/k", {"v": 2})
        assert (await client.get("/pull/view/k")).json()["data"] == {"from": "b"}


@pytest.mark.asyncio
async def test_view_enumerable_via_list_include_values():
    app, _ = _build_app(
        collections=[
            _col("source", "src/{id}"),
            _col("view", "view/{id}", pullOnly=True, listable=True, listValues=True),
        ],
        projections=[
            Projection(
                source="source",
                project=lambda e: ProjectionUpsert(
                    key=f"view/{e.params['id']}",
                    data={"id": e.params["id"], "name": (e.body or {}).get("name", "")},
                ),
            )
        ],
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/src/a1", {"name": "Alpha"})
        await _push(client, "/push/src/a2", {"name": "Beta"})
        body = (await client.get("/list/view?include=values")).json()
    assert [i["key"] for i in body["items"]] == ["a1", "a2"]
    assert [i["data"]["name"] for i in body["items"]] == ["Alpha", "Beta"]


@pytest.mark.asyncio
async def test_pullonly_view_rejects_client_writes():
    app, _ = _build_app(
        collections=[_col("source", "src/{id}"), _col("view", "view/{id}", pullOnly=True)],
        projections=[
            Projection(
                source="source",
                project=lambda e: ProjectionUpsert(key=f"view/{e.params['id']}", data={"ok": True}),
            )
        ],
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/src/a1", {"name": "x"})
        assert (await client.get("/pull/view/a1")).status_code == 200
        # pullOnly → no push route registered for the view.
        resp = await client.post(
            "/push/view/a1",
            json={"data": {"tampered": True}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
    assert resp.status_code >= 400


@pytest.mark.asyncio
async def test_projection_failure_does_not_break_client_write():
    def boom(e: WriteEvent):
        raise RuntimeError("boom")

    app, _ = _build_app(
        collections=[_col("source", "src/{id}")],
        projections=[Projection(source="source", project=boom)],
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/src/a1",
            json={"data": {"name": "x"}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
    assert resp.status_code == 200
    assert len(resp.json()["hash"]) == 64
