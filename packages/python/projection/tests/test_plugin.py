"""Integration tests — the projection plugin maintains an incremental list on push."""

import json

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
    ProjectionRemove,
    ProjectionSet,
    create_projection_server_plugin,
)
from starfish_protocol.plugins import WriteEvent

from tests.helpers import MemoryObjectStore, OneShotConflictStore


def _build_app(
    collections: list[CollectionConfig],
    projections: list[Projection],
    *,
    store=None,
    max_items: int | None = None,
    max_retries: int = 8,
):
    store = store or MemoryObjectStore()
    config = SyncConfig(version=1, collections=collections)

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["self"])

    plugin = create_projection_server_plugin(
        store=store, projections=projections, max_retries=max_retries, max_items=max_items
    )
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


def _source_and_list() -> list[CollectionConfig]:
    return [
        _col("products", "products/{id}"),
        _col("catalog", "catalog", pullOnly=True),
    ]


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


async def _read_list(store, key: str) -> list[dict]:
    raw = await store.get_string(key)
    if raw is None:
        return []
    return json.loads(raw)["data"]["items"]


def _ids(items: list[dict]) -> list[str]:
    return [i["id"] for i in items]


# Mirror each product as a {id, value:{name}} entry in `catalog`, treating
# {deleted: True} as a removal.
def _catalog_project(e: WriteEvent):
    if (e.body or {}).get("deleted") is True:
        return ProjectionRemove(id=e.params["id"])
    return ProjectionSet(id=e.params["id"], value={"name": (e.body or {}).get("name", "")})


def _catalog_projection() -> Projection:
    return Projection(source="products", target="catalog", project=_catalog_project)


@pytest.mark.asyncio
async def test_appends_entries_and_serves_whole_list():
    app, store = _build_app(_source_and_list(), [_catalog_projection()])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/products/a", {"name": "Alpha"})
        await _push(client, "/push/products/b", {"name": "Beta"})
        body = (await client.get("/pull/catalog")).json()

    expected = [
        {"id": "a", "value": {"name": "Alpha"}},
        {"id": "b", "value": {"name": "Beta"}},
    ]
    assert await _read_list(store, "catalog") == expected
    # The client reads the whole list in a single GET of the one list document.
    assert body["data"]["items"] == expected


@pytest.mark.asyncio
async def test_updates_entry_in_place_keeping_position():
    app, store = _build_app(_source_and_list(), [_catalog_projection()])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/products/a", {"name": "Alpha"})
        await _push(client, "/push/products/b", {"name": "Beta"})
        await _push(client, "/push/products/a", {"name": "Alpha v2"})

    items = await _read_list(store, "catalog")
    assert _ids(items) == ["a", "b"]  # position preserved
    assert items[0]["value"] == {"name": "Alpha v2"}  # value fully replaced


@pytest.mark.asyncio
async def test_removes_entry_on_tombstone_and_list_survives_when_emptied():
    app, store = _build_app(_source_and_list(), [_catalog_projection()])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/products/a", {"name": "Alpha"})
        await _push(client, "/push/products/b", {"name": "Beta"})
        await _push(client, "/push/products/a", {"deleted": True})
        assert _ids(await _read_list(store, "catalog")) == ["b"]

        # Removing an absent id is a no-op.
        await _push(client, "/push/products/zzz", {"deleted": True})
        assert _ids(await _read_list(store, "catalog")) == ["b"]

        # Emptying the list leaves an empty list document, not a 404.
        await _push(client, "/push/products/b", {"deleted": True})
        assert await _read_list(store, "catalog") == []
        assert (await client.get("/pull/catalog")).status_code == 200


@pytest.mark.asyncio
async def test_ignores_when_project_returns_none():
    app, store = _build_app(
        _source_and_list(),
        [Projection(source="products", target="catalog", project=lambda e: None)],
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/products/a", {"name": "Alpha"})
    assert await store.get_string("catalog") is None


@pytest.mark.asyncio
async def test_target_function_shards_across_multiple_sources():
    app, store = _build_app(
        collections=[
            _col("products", "products/{tenant}/{id}"),
            _col("services", "services/{tenant}/{id}"),
        ],
        projections=[
            Projection(
                source=["products", "services"],
                target=lambda e: (f"catalog/{e.params['tenant']}" if e.params.get("tenant") else None),
                project=lambda e: ProjectionSet(
                    id=e.params["id"],
                    value={"kind": e.collection, "name": (e.body or {}).get("name", "")},
                ),
            )
        ],
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/products/t1/p1", {"name": "P1"})
        await _push(client, "/push/services/t1/s1", {"name": "S1"})
        await _push(client, "/push/products/t2/p2", {"name": "P2"})

    assert await _read_list(store, "catalog/t1") == [
        {"id": "p1", "value": {"kind": "products", "name": "P1"}},
        {"id": "s1", "value": {"kind": "services", "name": "S1"}},
    ]
    assert _ids(await _read_list(store, "catalog/t2")) == ["p2"]


@pytest.mark.asyncio
async def test_client_fetches_all_shards_via_list_endpoint():
    # Shard a product catalog by category (the documented manual-sharding pattern).
    app, _ = _build_app(
        collections=[
            _col("products", "products/{id}"),
            _col("catalog", "catalog/{category}", pullOnly=True, listable=True),
        ],
        projections=[
            Projection(
                source="products",
                target=lambda e: (f"catalog/{e.body['category']}" if (e.body or {}).get("category") else None),
                project=lambda e: ProjectionSet(id=e.params["id"], value={"name": (e.body or {}).get("name", "")}),
            )
        ],
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/products/p1", {"name": "Novel", "category": "books"})
        await _push(client, "/push/products/p2", {"name": "Phone", "category": "electronics"})
        await _push(client, "/push/products/p3", {"name": "Comic", "category": "books"})

        # Discover shards via the list endpoint, then pull each and concatenate.
        shards = (await client.get("/list/catalog")).json()["items"]
        all_items: list[dict] = []
        for cat in shards:
            body = (await client.get(f"/pull/catalog/{cat}")).json()
            all_items.extend(body["data"]["items"])

    assert sorted(shards) == ["books", "electronics"]
    assert sorted(i["id"] for i in all_items) == ["p1", "p2", "p3"]


@pytest.mark.asyncio
async def test_concurrent_writes_do_not_lose_updates():
    store = OneShotConflictStore()
    app, _ = _build_app(_source_and_list(), [_catalog_projection()], store=store)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Seed the list with one entry.
        await _push(client, "/push/products/a", {"name": "Alpha"})

        # Arm a competing write that adds entry "c", then push "b". The plugin's
        # first push hash-mismatches, re-pulls (now seeing "a" + "c") and re-applies
        # "b" on top — losing neither.
        store.arm(
            "catalog",
            json.dumps(
                {
                    "v": 1,
                    "data": {
                        "items": [
                            {"id": "a", "value": {"name": "Alpha"}},
                            {"id": "c", "value": {"name": "Concurrent"}},
                        ]
                    },
                    "ts": 1,
                    "hash": "f" * 64,
                }
            ),
        )
        await _push(client, "/push/products/b", {"name": "Beta"})

    assert _ids(await _read_list(store, "catalog")) == ["a", "c", "b"]


@pytest.mark.asyncio
async def test_max_items_caps_the_list():
    app, store = _build_app(_source_and_list(), [_catalog_projection()], max_items=2)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/products/a", {"name": "A"})
        await _push(client, "/push/products/b", {"name": "B"})
        await _push(client, "/push/products/c", {"name": "C"})  # exceeds cap → dropped
    assert _ids(await _read_list(store, "catalog")) == ["a", "b"]


@pytest.mark.asyncio
async def test_pullonly_list_rejects_client_writes():
    app, _ = _build_app(_source_and_list(), [_catalog_projection()])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/products/a", {"name": "Alpha"})
        assert (await client.get("/pull/catalog")).status_code == 200
        # pullOnly → no push route registered for the list.
        resp = await client.post(
            "/push/catalog",
            json={"data": {"tampered": True}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
    assert resp.status_code >= 400


@pytest.mark.asyncio
async def test_projection_failure_does_not_break_client_write():
    def boom(e: WriteEvent):
        raise RuntimeError("boom")

    app, _ = _build_app(
        collections=[_col("products", "products/{id}")],
        projections=[Projection(source="products", target="catalog", project=boom)],
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/products/a",
            json={"data": {"name": "x"}, "baseHash": None},
            headers={"content-type": "application/json"},
        )
    assert resp.status_code == 200
    assert len(resp.json()["hash"]) == 64
