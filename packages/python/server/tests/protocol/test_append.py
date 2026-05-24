"""Tests for the append_item protocol helper (mirrors the TS append.test.ts)."""

import asyncio
import json
import time

import pytest

from starfish_protocol.hash import compute_hash
from starfish_server.protocol.push import append_item, AppendConflict
from starfish_server.protocol.types import PushSuccess
from tests.helpers import MemoryObjectStore


async def _read_doc(store: MemoryObjectStore, key: str) -> dict | None:
    raw = await store.get_string(key)
    return json.loads(raw) if raw else None


@pytest.mark.asyncio
async def test_empty_store_single_element_auto_ts():
    store = MemoryObjectStore()
    item = {"msg": "hello"}
    out = await append_item(store, "col/doc", item, "items", None)
    assert isinstance(out, PushSuccess)
    doc = await _read_doc(store, "col/doc")
    assert len(doc["data"]["items"]) == 1
    assert doc["data"]["items"][0]["data"] == item
    assert isinstance(doc["data"]["items"][0]["ts"], int)
    assert out.timestamp == doc["data"]["items"][0]["ts"]
    assert out.hash == compute_hash({"n": 1, "last": item})
    # doc-level ts equals the most recent element's ts
    assert doc["ts"] == doc["data"]["items"][0]["ts"]


@pytest.mark.asyncio
async def test_empty_store_single_element_provided_ts():
    store = MemoryObjectStore()
    out = await append_item(store, "col/doc", {"a": 1}, "items", 5000)
    assert isinstance(out, PushSuccess)
    assert out.timestamp == 5000
    doc = await _read_doc(store, "col/doc")
    assert doc["data"]["items"][0]["ts"] == 5000
    assert doc["ts"] == 5000


@pytest.mark.asyncio
async def test_provided_ts_stored_verbatim():
    store = MemoryObjectStore()
    await append_item(store, "col/doc", {"a": 1}, "items", 12345)
    doc = await _read_doc(store, "col/doc")
    assert doc["data"]["items"][0]["ts"] == 12345


@pytest.mark.asyncio
async def test_auto_ts_strictly_increasing():
    store = MemoryObjectStore()
    await append_item(store, "col/doc", {"n": 1}, "items", None)
    await append_item(store, "col/doc", {"n": 2}, "items", None)
    doc = await _read_doc(store, "col/doc")
    assert len(doc["data"]["items"]) == 2
    assert doc["data"]["items"][1]["ts"] > doc["data"]["items"][0]["ts"]


@pytest.mark.asyncio
async def test_provided_ts_greater_than_latest_accepted():
    store = MemoryObjectStore()
    await append_item(store, "col/doc", {"n": 1}, "items", 100)
    out = await append_item(store, "col/doc", {"n": 2}, "items", 200)
    assert isinstance(out, PushSuccess)
    assert out.timestamp == 200


@pytest.mark.asyncio
async def test_provided_ts_equal_latest_conflict():
    store = MemoryObjectStore()
    await append_item(store, "col/doc", {"n": 1}, "items", 100)
    out = await append_item(store, "col/doc", {"n": 2}, "items", 100)
    assert isinstance(out, AppendConflict)
    assert out.error == "non_monotonic_timestamp"
    assert out.latest == 100
    # rejected append must not be stored
    doc = await _read_doc(store, "col/doc")
    assert len(doc["data"]["items"]) == 1


@pytest.mark.asyncio
async def test_provided_ts_less_than_latest_conflict():
    store = MemoryObjectStore()
    await append_item(store, "col/doc", {"n": 1}, "items", 100)
    out = await append_item(store, "col/doc", {"n": 2}, "items", 50)
    assert isinstance(out, AppendConflict)
    assert out.error == "non_monotonic_timestamp"
    assert out.latest == 100


@pytest.mark.asyncio
async def test_auto_ts_after_future_provided_ts_stays_increasing():
    store = MemoryObjectStore()
    future = (time.time_ns() // 1_000_000) + 1_000_000
    await append_item(store, "col/doc", {"n": 1}, "items", future)
    out = await append_item(store, "col/doc", {"n": 2}, "items", None)
    assert isinstance(out, PushSuccess)
    # max(now, latest + 1) == latest + 1 since `future` is far ahead of now
    assert out.timestamp == future + 1


@pytest.mark.asyncio
async def test_hash_is_length_tagged_last_item_only():
    store = MemoryObjectStore()
    item = {"msg": "hello"}
    out = await append_item(store, "col/doc", item, "items", None)
    assert isinstance(out, PushSuccess)
    assert out.hash == compute_hash({"n": 1, "last": item})


@pytest.mark.asyncio
async def test_hash_reflects_length_and_last_after_multiple_appends():
    store = MemoryObjectStore()
    await append_item(store, "col/doc", {"n": 1}, "items", 1)
    item2 = {"n": 2}
    out = await append_item(store, "col/doc", item2, "items", 2)
    assert isinstance(out, PushSuccess)
    assert out.hash == compute_hash({"n": 2, "last": item2})


@pytest.mark.asyncio
async def test_custom_append_field():
    store = MemoryObjectStore()
    await append_item(store, "col/doc", {"x": 1}, "events", None)
    doc = await _read_doc(store, "col/doc")
    assert len(doc["data"]["events"]) == 1
    assert doc["data"]["events"][0]["data"] == {"x": 1}


@pytest.mark.asyncio
async def test_preserves_other_top_level_fields():
    store = MemoryObjectStore()
    # Seed an existing doc carrying an unrelated top-level field.
    await store.put(
        "col/doc",
        json.dumps({
            "v": 1,
            "data": {"items": [{"ts": 1, "data": {"a": 1}}], "meta": "info"},
            "ts": 1,
            "hash": "x",
        }),
        content_type="application/json",
    )
    await append_item(store, "col/doc", {"a": 2}, "items", 2)
    doc = await _read_doc(store, "col/doc")
    assert doc["data"]["meta"] == "info"
    assert [el["data"] for el in doc["data"]["items"]] == [{"a": 1}, {"a": 2}]


@pytest.mark.asyncio
async def test_opaque_payload_stored_as_is():
    store = MemoryObjectStore()
    # delegated-style payload: an encryptor wrapper object
    wrapper = {"_encrypted": "BASE64CIPHERTEXT", "epoch": 1}
    await append_item(store, "col/doc", wrapper, "items", None)
    doc = await _read_doc(store, "col/doc")
    assert doc["data"]["items"][0]["data"] == wrapper


@pytest.mark.asyncio
async def test_corrupt_json_recovers_as_empty():
    store = MemoryObjectStore()
    await store.put("col/doc", "NOT_JSON", content_type="application/json")
    out = await append_item(store, "col/doc", {"a": 1}, "items", None)
    assert isinstance(out, PushSuccess)
    doc = await _read_doc(store, "col/doc")
    assert len(doc["data"]["items"]) == 1
    assert doc["data"]["items"][0]["data"] == {"a": 1}


@pytest.mark.asyncio
async def test_concurrent_appends_both_land():
    store = MemoryObjectStore()
    await asyncio.gather(
        append_item(store, "col/doc", {"n": 1}, "items", None),
        append_item(store, "col/doc", {"n": 2}, "items", None),
    )
    doc = await _read_doc(store, "col/doc")
    assert len(doc["data"]["items"]) == 2
    # serialised by the per-key lock → strictly increasing ts preserved
    assert doc["data"]["items"][1]["ts"] > doc["data"]["items"][0]["ts"]
