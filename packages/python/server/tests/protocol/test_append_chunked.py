"""Precise tests for the two opt-in append-only scaling knobs (mirrors the TS
``append-only.chunked.test.ts``):

- ``max_items`` — reject appends past a cap (409 ``append_limit_exceeded``).
- ``chunk_size`` — segmented storage (sealed chunks + head), bounded-cost append.

The load-bearing claim is wire-contract parity: a ``chunk_size`` collection must
return identical pull responses AND the identical ``hash`` to a single-doc
collection for the same append sequence. Most cases are one-liners over a shared
parity helper that runs the same sequence against both layouts.
"""

import json
import shutil
import tempfile

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import (
    AppendOnlyConfig,
    CollectionConfig,
    SyncConfig,
)
from starfish_server.protocol.push import append_item, append_seg_prefix
from starfish_server.protocol.types import PushSuccess
from starfish_server.router.helpers import handle_append_only_pull
from starfish_server.router.route_builder import create_sync_router, SyncRouterOptions, AuthResult
from starfish_server.storage.filesystem import FilesystemObjectStore, FilesystemStorageOptions
from tests.helpers import MemoryObjectStore

FIELD = "items"


def _seq(count: int) -> list[tuple[dict, int]]:
    """`count` elements with ts = 10, 20, … (strictly increasing)."""
    return [({"n": i + 1}, (i + 1) * 10) for i in range(count)]


async def _run_seq(store, key: str, seq: list[tuple[dict, int]], **opts) -> str:
    """Append a sequence; return the final element's hash (assert no conflict)."""
    last_hash = ""
    for item, ts in seq:
        out = await append_item(store, key, item, FIELD, ts, **opts)
        assert isinstance(out, PushSuccess), f"unexpected append outcome: {out}"
        last_hash = out.hash
    return last_hash


async def _pull(store, key: str, *, checkpoint: int | None = None, last: int | None = None) -> list:
    resp = await handle_append_only_pull(
        key,
        store,
        checkpoint_param=str(checkpoint) if checkpoint is not None else None,
        append_field=FIELD,
        last_param=str(last) if last is not None else None,
    )
    return json.loads(resp.body)["data"][FIELD]


# 25 elements, ts 10..250; chunk_size 10 → chunks [10..100],[110..200],[210..250].
_QUERIES = [
    {},  # full
    {"checkpoint": 0},
    {"checkpoint": 5},  # before all
    {"checkpoint": 100},  # == last ts of chunk 0 (boundary)
    {"checkpoint": 105},  # gap between chunk 0 and chunk 1
    {"checkpoint": 110},  # == firstTs of chunk 1
    {"checkpoint": 155},  # inside chunk 1
    {"checkpoint": 250},  # == last element
    {"checkpoint": 300},  # after all
    {"last": 0},
    {"last": 3},  # within one chunk
    {"last": 10},  # == chunk_size
    {"last": 15},  # spanning chunks
    {"last": 100},  # > n
    {"checkpoint": 100, "last": 2},
    {"checkpoint": 5, "last": 12},
    {"checkpoint": 110, "last": 5},
]


@pytest.mark.asyncio
async def test_chunked_pull_parity_with_single_doc():
    seg = MemoryObjectStore()
    single = MemoryObjectStore()
    seq = _seq(25)
    await _run_seq(seg, "k", seq, chunk_size=10)
    await _run_seq(single, "k", seq)
    for q in _QUERIES:
        assert await _pull(seg, "k", **q) == await _pull(single, "k", **q), f"query {q}"


@pytest.mark.asyncio
async def test_chunked_hash_identical_to_single_doc():
    seg = MemoryObjectStore()
    single = MemoryObjectStore()
    seq = _seq(25)
    seg_hash = await _run_seq(seg, "k", seq, chunk_size=10)
    single_hash = await _run_seq(single, "k", seq)
    assert seg_hash == single_hash


@pytest.mark.asyncio
async def test_chunk_rollover_at_boundary():
    store = MemoryObjectStore()
    await _run_seq(store, "k", _seq(10), chunk_size=10)
    assert len(await store.list_keys(append_seg_prefix("k"))) == 1
    await append_item(store, "k", {"n": 11}, FIELD, 110, chunk_size=10)
    keys = await store.list_keys(append_seg_prefix("k"))
    assert len(keys) == 2
    assert len(json.loads(await store.get_string(keys[0]))) == 10
    assert len(json.loads(await store.get_string(keys[1]))) == 1
    assert len(await _pull(store, "k")) == 11


@pytest.mark.asyncio
async def test_lazy_migration_from_legacy_single_doc():
    store = MemoryObjectStore()
    await _run_seq(store, "k", _seq(25))  # legacy single-doc
    assert len(await store.list_keys(append_seg_prefix("k"))) == 0
    await append_item(store, "k", {"n": 26}, FIELD, 260, chunk_size=10)
    assert len(await store.list_keys(append_seg_prefix("k"))) == 3  # ceil(26/10)
    items = await _pull(store, "k")
    assert [e["data"]["n"] for e in items] == list(range(1, 27))


@pytest.mark.asyncio
async def test_lazy_migration_exact_multiple_starts_fresh_tail():
    store = MemoryObjectStore()
    await _run_seq(store, "k", _seq(20))  # 20 = 2 × chunk_size
    await append_item(store, "k", {"n": 21}, FIELD, 210, chunk_size=10)
    keys = await store.list_keys(append_seg_prefix("k"))
    assert len(keys) == 3  # two sealed (10+10) + one new (1)
    assert len(json.loads(await store.get_string(keys[2]))) == 1
    assert len(await _pull(store, "k")) == 21


@pytest.mark.asyncio
async def test_migration_preserves_other_top_level_fields():
    store = MemoryObjectStore()
    await store.put(
        "k",
        json.dumps({"v": 1, "data": {"items": [{"ts": 10, "data": {"n": 1}}], "meta": "keep"}, "ts": 10, "hash": "x"}),
        content_type="application/json",
    )
    await append_item(store, "k", {"n": 2}, FIELD, 20, chunk_size=10)
    resp = await handle_append_only_pull("k", store, append_field=FIELD)
    data = json.loads(resp.body)["data"]
    assert data["meta"] == "keep"
    assert len(data[FIELD]) == 2


@pytest.mark.asyncio
async def test_stays_chunked_when_chunk_size_removed_from_config():
    store = MemoryObjectStore()
    await _run_seq(store, "k", _seq(15), chunk_size=10)  # 2 chunks
    # Config drift: this append carries no chunk_size. Must NOT overwrite the head
    # as a single-doc and orphan the chunks.
    out = await append_item(store, "k", {"n": 16}, FIELD, 160)
    assert isinstance(out, PushSuccess)
    head = json.loads(await store.get_string("k"))
    assert head["seg"] is True
    assert len(await _pull(store, "k")) == 16


@pytest.mark.asyncio
async def test_chunked_on_filesystem_backend():
    base = tempfile.mkdtemp(prefix="starfish-seg-")
    try:
        store = FilesystemObjectStore(FilesystemStorageOptions(base_dir=base))
        await _run_seq(store, "events", _seq(15), chunk_size=10)
        assert len(await _pull(store, "events")) == 15
        assert len(await _pull(store, "events", checkpoint=100)) == 5  # ts 110..150
        assert await store.get_string("events")  # head readable as a normal doc
        assert len(await store.list_keys(append_seg_prefix("events"))) == 2
    finally:
        shutil.rmtree(base, ignore_errors=True)


@pytest.mark.asyncio
async def test_cap_rejects_past_max_items_without_storing():
    store = MemoryObjectStore()
    await append_item(store, "k", {"n": 1}, FIELD, 10, max_items=2)
    await append_item(store, "k", {"n": 2}, FIELD, 20, max_items=2)  # exactly at cap → ok
    out = await append_item(store, "k", {"n": 3}, FIELD, 30, max_items=2)
    assert out.error == "append_limit_exceeded"
    assert out.limit == 2
    assert len(json.loads(await store.get_string("k"))["data"]["items"]) == 2


@pytest.mark.asyncio
async def test_cap_enforced_with_chunked_storage():
    store = MemoryObjectStore()
    await _run_seq(store, "k", _seq(25), chunk_size=10, max_items=25)
    out = await append_item(store, "k", {"n": 26}, FIELD, 260, chunk_size=10, max_items=25)
    assert out.error == "append_limit_exceeded"
    assert out.limit == 25
    assert len(await _pull(store, "k")) == 25


def _build_app(col: CollectionConfig):
    store = MemoryObjectStore()
    config = SyncConfig(version=1, collections=[col])

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["admin"])

    router = create_sync_router(SyncRouterOptions(store=store, config=config, role_resolver=role_resolver))
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.mark.asyncio
async def test_router_returns_409_past_cap():
    col = CollectionConfig(
        name="events",
        storagePath="events",
        readRoles=["admin"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
        appendOnly=AppendOnlyConfig(type="by_timestamp", max_items=1),
    )
    app = _build_app(col)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.post("/push/events", json={"data": {"n": 1}})).status_code == 200
        resp = await client.post("/push/events", json={"data": {"n": 2}})
    assert resp.status_code == 409
    assert resp.json() == {"error": "append_limit_exceeded", "limit": 1}
