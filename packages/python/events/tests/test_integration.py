"""Integration tests for create_events_server_plugin.

Uses a real ``create_sync_router`` + ``MemoryObjectStore`` to exercise the full
``intercept_push`` dispatch path — the same approach used in
``packages/python/projection/tests/test_plugin.py``.

Each test gets a fresh store + app (via the ``_build_app`` factory) so state
never bleeds between tests.
"""

from __future__ import annotations

import hashlib
import io
import json
import re

import pyarrow.parquet as pq
import pytest
from fastapi import FastAPI, Request
from httpx import ASGITransport, AsyncClient

from starfish_protocol.constants import PARQUET_MIME_TYPE
from starfish_server.config.schema import CollectionConfig, SyncConfig
from starfish_server.router.route_builder import AuthResult, SyncRouterOptions, create_sync_router

from starfish_events import create_events_server_plugin
from starfish_events.encode import COLUMNS

from tests.helpers import FailingBinaryStore, MemoryObjectStore, NoBinaryStore

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

COLLECTION = "events"
STORAGE_PATH = "events/{app}/{batchId}"

_EVENTS_COLLECTION = CollectionConfig(
    name=COLLECTION,
    storagePath=STORAGE_PATH,
    readRoles=["admin"],
    writeRoles=["public"],
    encryption="none",
    maxBodyBytes=8_000_000,
    allowedMimeTypes=["application/json"],
)

_SAMPLE_EVENT = {
    "event_type": "capture",
    "event": "button_clicked",
    "distinct_id": "user-abc",
    "anonymous_id": "anon-xyz",
    "ts": "2024-06-01T10:00:00.000Z",
    "message_id": "msg-001",
    "properties": '{"label":"Submit"}',
    "context": '{"platform":"web"}',
    "dt": "2024-06-01",
}


def _build_app(store=None, *, extra_collections: list[CollectionConfig] | None = None):
    store = store or MemoryObjectStore()
    collections = [_EVENTS_COLLECTION] + (extra_collections or [])
    config = SyncConfig(version=1, collections=collections)

    async def _resolver(request: Request) -> AuthResult:
        return AuthResult(identity=None, roles=[])

    plugin = create_events_server_plugin(
        store=store, collection=COLLECTION, storage_path=STORAGE_PATH
    )
    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=_resolver, plugins=[plugin])
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


def _push_body(events: list[dict]) -> str:
    return json.dumps({"data": {"events": events}, "baseHash": None})


async def _push(client: AsyncClient, path: str, events: list[dict]) -> dict:
    resp = await client.post(
        path,
        content=_push_body(events),
        headers={"Content-Type": "application/json"},
    )
    return resp


def _decode_parquet(raw: bytes) -> list[dict]:
    table = pq.read_table(io.BytesIO(raw))
    df = table.to_pydict()
    n = table.num_rows
    return [{col: df[col][i] for col in df} for i in range(n)]


# ---------------------------------------------------------------------------
# Happy path: 200 + Parquet written
# ---------------------------------------------------------------------------


async def test_valid_push_returns_200():
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, f"/push/events/myapp/batch-1", [_SAMPLE_EVENT])

    assert resp.status_code == 200


async def test_valid_push_response_body_contains_hash():
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, "/push/events/myapp/batch-1", [_SAMPLE_EVENT])

    body = resp.json()
    assert "hash" in body


async def test_hash_is_64_char_hex():
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, "/push/events/myapp/batch-1", [_SAMPLE_EVENT])

    hash_val = resp.json()["hash"]
    assert len(hash_val) == 64
    assert re.fullmatch(r"[0-9a-f]{64}", hash_val), "hash must be lowercase hex"


async def test_hash_equals_sha256_of_stored_bytes():
    """The response hash must be SHA-256 of the raw Parquet bytes."""
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, "/push/events/myapp/batch-1", [_SAMPLE_EVENT])

    stored = await store.get_bytes("events/myapp/batch-1.parquet")
    assert stored is not None
    raw_bytes, _ = stored
    expected_hash = hashlib.sha256(raw_bytes).hexdigest()
    assert resp.json()["hash"] == expected_hash


async def test_stored_parquet_has_par1_magic_at_start():
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/events/myapp/batch-1", [_SAMPLE_EVENT])

    stored = await store.get_bytes("events/myapp/batch-1.parquet")
    raw_bytes, _ = stored
    assert raw_bytes[:4] == b"PAR1"


async def test_stored_parquet_has_par1_magic_at_end():
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/events/myapp/batch-1", [_SAMPLE_EVENT])

    stored = await store.get_bytes("events/myapp/batch-1.parquet")
    raw_bytes, _ = stored
    assert raw_bytes[-4:] == b"PAR1"


async def test_stored_parquet_has_correct_content_type():
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/events/myapp/batch-1", [_SAMPLE_EVENT])

    stored = await store.get_bytes("events/myapp/batch-1.parquet")
    _, content_type = stored
    assert content_type == PARQUET_MIME_TYPE


async def test_parquet_key_has_dot_parquet_extension():
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/events/myapp/batch-1", [_SAMPLE_EVENT])

    stored = await store.get_bytes("events/myapp/batch-1.parquet")
    assert stored is not None, "Parquet file should be stored at the .parquet-suffixed key"


# ---------------------------------------------------------------------------
# Parquet content correctness
# ---------------------------------------------------------------------------


async def test_parquet_roundtrip_correct_event_values():
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/events/myapp/batch-1", [_SAMPLE_EVENT])

    raw_bytes, _ = await store.get_bytes("events/myapp/batch-1.parquet")
    rows = _decode_parquet(raw_bytes)
    assert len(rows) == 1
    row = rows[0]
    assert row["event"] == "button_clicked"
    assert row["event_type"] == "capture"
    assert row["distinct_id"] == "user-abc"
    assert row["anonymous_id"] == "anon-xyz"
    assert row["ts"] == "2024-06-01T10:00:00.000Z"
    assert row["message_id"] == "msg-001"
    assert row["properties"] == '{"label":"Submit"}'
    assert row["dt"] == "2024-06-01"


async def test_parquet_schema_has_all_ten_columns():
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/events/myapp/batch-1", [_SAMPLE_EVENT])

    raw_bytes, _ = await store.get_bytes("events/myapp/batch-1.parquet")
    schema = pq.read_schema(io.BytesIO(raw_bytes))
    assert schema.names == list(COLUMNS)


async def test_received_at_stamped_server_side():
    """received_at must not be taken from the client event — it is server-stamped."""
    app, store = _build_app()
    event_with_received_at = {**_SAMPLE_EVENT, "received_at": "CLIENT_VALUE_SHOULD_BE_OVERWRITTEN"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/events/myapp/batch-1", [event_with_received_at])

    raw_bytes, _ = await store.get_bytes("events/myapp/batch-1.parquet")
    rows = _decode_parquet(raw_bytes)
    assert rows[0]["received_at"] != "CLIENT_VALUE_SHOULD_BE_OVERWRITTEN"
    assert rows[0]["received_at"] != ""  # must be a real timestamp


async def test_received_at_is_valid_iso8601_utc():
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/events/myapp/batch-1", [_SAMPLE_EVENT])

    raw_bytes, _ = await store.get_bytes("events/myapp/batch-1.parquet")
    rows = _decode_parquet(raw_bytes)
    received_at = rows[0]["received_at"]
    # e.g. "2024-06-01T10:00:01.000Z"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", received_at), (
        f"received_at should be ISO-8601 UTC with ms: got {received_at!r}"
    )


async def test_missing_event_fields_default_to_empty_string_in_parquet():
    """Partial events (only some fields set) must produce empty strings for missing columns."""
    partial_event = {"event": "minimal_event", "ts": "2024-01-01T00:00:00.000Z"}
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/events/myapp/batch-1", [partial_event])

    raw_bytes, _ = await store.get_bytes("events/myapp/batch-1.parquet")
    rows = _decode_parquet(raw_bytes)
    assert rows[0]["event"] == "minimal_event"
    assert rows[0]["event_type"] == ""
    assert rows[0]["distinct_id"] == ""
    assert rows[0]["anonymous_id"] == ""


# ---------------------------------------------------------------------------
# Multi-event batches
# ---------------------------------------------------------------------------


async def test_multi_event_batch_all_rows_preserved():
    events = [
        {**_SAMPLE_EVENT, "message_id": f"msg-{i}", "event": f"event_{i}"}
        for i in range(5)
    ]
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/events/myapp/batch-1", events)

    raw_bytes, _ = await store.get_bytes("events/myapp/batch-1.parquet")
    rows = _decode_parquet(raw_bytes)
    assert len(rows) == 5
    assert [r["event"] for r in rows] == [f"event_{i}" for i in range(5)]


async def test_multi_event_batch_events_in_order():
    events = [
        {**_SAMPLE_EVENT, "message_id": "msg-a", "event": "first"},
        {**_SAMPLE_EVENT, "message_id": "msg-b", "event": "second"},
        {**_SAMPLE_EVENT, "message_id": "msg-c", "event": "third"},
    ]
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/events/myapp/batch-1", events)

    raw_bytes, _ = await store.get_bytes("events/myapp/batch-1.parquet")
    rows = _decode_parquet(raw_bytes)
    assert [r["event"] for r in rows] == ["first", "second", "third"]


# ---------------------------------------------------------------------------
# Empty events array
# ---------------------------------------------------------------------------


async def test_empty_events_batch_returns_200():
    app, _ = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, "/push/events/myapp/batch-empty", [])

    assert resp.status_code == 200


async def test_empty_events_batch_writes_valid_parquet_with_zero_rows():
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, "/push/events/myapp/batch-empty", [])

    stored = await store.get_bytes("events/myapp/batch-empty.parquet")
    assert stored is not None
    raw_bytes, _ = stored
    assert raw_bytes[:4] == b"PAR1"
    table = pq.read_table(io.BytesIO(raw_bytes))
    assert table.num_rows == 0


# ---------------------------------------------------------------------------
# Hash consistency
# ---------------------------------------------------------------------------


async def test_hash_is_deterministic_for_same_received_at():
    """Encode + hash is deterministic: same events + same received_at → same Parquet bytes → same hash."""
    from datetime import datetime, timezone
    from unittest.mock import patch

    fixed_time = datetime(2024, 6, 1, 10, 0, 1, 123_000, timezone.utc)

    with patch("starfish_events.plugin.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_time

        app1, store1 = _build_app()
        app2, store2 = _build_app()

        async with AsyncClient(transport=ASGITransport(app=app1), base_url="http://test") as c1:
            r1 = (await _push(c1, "/push/events/myapp/batch-1", [_SAMPLE_EVENT])).json()
        async with AsyncClient(transport=ASGITransport(app=app2), base_url="http://test") as c2:
            r2 = (await _push(c2, "/push/events/myapp/batch-1", [_SAMPLE_EVENT])).json()

    assert r1["hash"] == r2["hash"]


async def test_different_data_produces_different_hash():
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r1 = (await _push(client, "/push/events/myapp/batch-1",
                          [{**_SAMPLE_EVENT, "message_id": "msg-a"}])).json()
        r2 = (await _push(client, "/push/events/myapp/batch-2",
                          [{**_SAMPLE_EVENT, "message_id": "msg-b"}])).json()
    assert r1["hash"] != r2["hash"]


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


async def test_bad_json_body_returns_400():
    app, _ = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/events/myapp/batch-bad",
            content="this is not json at all }{",
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 400


async def test_put_bytes_failure_propagates_as_500():
    """S3 write failures should return 500 so the SDK requeues the batch."""
    app, _ = _build_app(store=FailingBinaryStore())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, "/push/events/myapp/batch-1", [_SAMPLE_EVENT])
    assert resp.status_code == 500


async def test_missing_events_key_treated_as_empty_not_error():
    """``{"data": {}, "baseHash": null}`` — missing events key → empty batch (200)."""
    app, store = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/events/myapp/batch-1",
            content=json.dumps({"data": {}, "baseHash": None}),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200
    stored = await store.get_bytes("events/myapp/batch-1.parquet")
    assert stored is not None
    raw_bytes, _ = stored
    assert pq.read_table(io.BytesIO(raw_bytes)).num_rows == 0


# ---------------------------------------------------------------------------
# Other collections pass through
# ---------------------------------------------------------------------------


async def test_other_collection_not_intercepted_default_json_write_occurs():
    """Pushes to a non-events collection bypass the plugin → default JSON write."""
    other_col = CollectionConfig(
        name="other",
        storagePath="other/{id}",
        readRoles=["public"],
        writeRoles=["public"],
        encryption="none",
        maxBodyBytes=1_000_000,
        allowedMimeTypes=["application/json"],
    )
    app, store = _build_app(extra_collections=[other_col])
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/push/other/123",
            content=json.dumps({"data": {"foo": "bar"}, "baseHash": None}),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 200
    # JSON document written by the default handler, no Parquet file created.
    assert (await store.get_bytes("other/123.parquet")) is None
    assert (await store.get_string("other/123")) is not None


# ---------------------------------------------------------------------------
# Construction-time guard
# ---------------------------------------------------------------------------


def test_construction_guard_raises_when_store_lacks_put_bytes():
    """Passing a store that does not override put_bytes must raise TypeError at construction."""
    with pytest.raises(TypeError, match="put_bytes"):
        create_events_server_plugin(
            store=NoBinaryStore(),
            collection="events",
            storage_path="events/{app}/{batchId}",
        )
