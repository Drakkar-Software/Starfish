"""Tests for append protocol helpers."""

import pytest

from starfish_protocol.hash import compute_hash
from starfish_server.protocol.append import build_append_only_data, check_last_item_conflict
from starfish_server.protocol.push import push
from starfish_server.protocol.types import PushSuccess
from tests.helpers import MemoryObjectStore

NOW = 1714000000


@pytest.mark.asyncio
async def test_empty_store_single_item_empty_base_hash():
    store = MemoryObjectStore()
    data, base_hash, timestamps, _ = await build_append_only_data(store, "col/doc", {"msg": "hello"}, "items", NOW)
    assert data == {"items": [{"msg": "hello"}]}
    assert base_hash == ""


@pytest.mark.asyncio
async def test_existing_doc_appends_to_end():
    store = MemoryObjectStore()
    await push(store, "col/doc", {"items": [{"msg": "first"}]}, None)
    data, _, _, _ = await build_append_only_data(store, "col/doc", {"msg": "second"}, "items", NOW)
    assert data == {"items": [{"msg": "first"}, {"msg": "second"}]}


@pytest.mark.asyncio
async def test_returns_current_hash_as_base_hash():
    store = MemoryObjectStore()
    r1 = await push(store, "col/doc", {"items": []}, None)
    assert isinstance(r1, PushSuccess)
    _, base_hash, _, _ = await build_append_only_data(store, "col/doc", {"msg": "x"}, "items", NOW)
    assert base_hash == r1.hash


@pytest.mark.asyncio
async def test_non_array_items_recovers_with_single_item():
    store = MemoryObjectStore()
    await push(store, "col/doc", {"items": "not-an-array"}, None)
    data, _, _, _ = await build_append_only_data(store, "col/doc", {"msg": "x"}, "items", NOW)
    assert data == {"items": [{"msg": "x"}]}


@pytest.mark.asyncio
async def test_corrupt_json_recovers_as_empty():
    store = MemoryObjectStore()
    await store.put("col/doc", "NOT_JSON", content_type="application/json")
    data, base_hash, _, _ = await build_append_only_data(store, "col/doc", {"a": 1}, "items", NOW)
    assert data == {"items": [{"a": 1}]}
    assert base_hash == ""


@pytest.mark.asyncio
async def test_custom_append_field():
    store = MemoryObjectStore()
    data, _, _, _ = await build_append_only_data(store, "col/doc", {"x": 1}, "events", NOW)
    assert data == {"events": [{"x": 1}]}


@pytest.mark.asyncio
async def test_preserves_other_top_level_fields():
    store = MemoryObjectStore()
    await push(store, "col/doc", {"items": [{"a": 1}], "meta": "info"}, None)
    data, _, _, _ = await build_append_only_data(store, "col/doc", {"a": 2}, "items", NOW)
    assert data["meta"] == "info"
    assert data["items"] == [{"a": 1}, {"a": 2}]


@pytest.mark.asyncio
async def test_returns_parallel_timestamps_array():
    store = MemoryObjectStore()
    _, _, timestamps, _ = await build_append_only_data(store, "col/doc", {"msg": "first"}, "items", NOW)
    assert timestamps["items"] == [NOW]


@pytest.mark.asyncio
async def test_appends_now_to_existing_timestamps():
    store = MemoryObjectStore()
    data1, base1, ts1, hash1 = await build_append_only_data(store, "col/doc", {"n": 1}, "items", NOW)
    await push(store, "col/doc", data1, base1, None, False, False, precomputed_hash=hash1, precomputed_timestamps=ts1)
    _, _, ts2, _ = await build_append_only_data(store, "col/doc", {"n": 2}, "items", NOW + 1)
    assert ts2["items"] == [NOW, NOW + 1]


@pytest.mark.asyncio
async def test_last_item_hash_is_length_tagged():
    store = MemoryObjectStore()
    item = {"msg": "hello"}
    _, _, _, last_item_hash = await build_append_only_data(store, "col/doc", item, "items", NOW)
    expected = compute_hash({"n": 1, "last": item})
    assert last_item_hash == expected


@pytest.mark.asyncio
async def test_last_item_hash_correct_length_after_multiple_appends():
    store = MemoryObjectStore()
    item1, item2 = {"n": 1}, {"n": 2}
    data1, base1, ts1, h1 = await build_append_only_data(store, "col/doc", item1, "items", NOW)
    await push(store, "col/doc", data1, base1, None, False, False, precomputed_hash=h1, precomputed_timestamps=ts1)
    _, _, _, last_hash = await build_append_only_data(store, "col/doc", item2, "items", NOW + 1)
    expected = compute_hash({"n": 2, "last": item2})
    assert last_hash == expected


# --- Helper: write a doc in appendOnly format ---

async def _store_as_append_only(
    store: MemoryObjectStore,
    key: str,
    items: list[dict],
    field: str = "items",
) -> None:
    if not items:
        await push(store, key, {field: []}, None)
        return
    data, base, ts, h = await build_append_only_data(store, key, items[0], field, NOW)
    await push(store, key, data, base, None, False, False, precomputed_hash=h, precomputed_timestamps=ts)
    for i, item in enumerate(items[1:], start=1):
        data, base, ts, h = await build_append_only_data(store, key, item, field, NOW + i)
        await push(store, key, data, base, None, False, False, precomputed_hash=h, precomputed_timestamps=ts)


# --- checkLastItemConflict tests ---

@pytest.mark.asyncio
async def test_check_last_item_empty_store_empty_hash_no_conflict():
    store = MemoryObjectStore()
    result = await check_last_item_conflict(store, "col/doc", "", "items")
    assert result is None


@pytest.mark.asyncio
async def test_check_last_item_empty_store_non_empty_hash_mismatch():
    store = MemoryObjectStore()
    result = await check_last_item_conflict(store, "col/doc", "somehash", "items")
    assert result == "hash_mismatch"


@pytest.mark.asyncio
async def test_check_last_item_matching_stored_hash_no_conflict():
    store = MemoryObjectStore()
    item = {"msg": "hello"}
    await _store_as_append_only(store, "col/doc", [item])
    stored_hash = compute_hash({"n": 1, "last": item})
    result = await check_last_item_conflict(store, "col/doc", stored_hash, "items")
    assert result is None


@pytest.mark.asyncio
async def test_check_last_item_stale_hash_mismatch():
    store = MemoryObjectStore()
    await _store_as_append_only(store, "col/doc", [{"msg": "hello"}])
    result = await check_last_item_conflict(store, "col/doc", "stalehash", "items")
    assert result == "hash_mismatch"


@pytest.mark.asyncio
async def test_check_last_item_null_hash_when_doc_exists_mismatch():
    store = MemoryObjectStore()
    await _store_as_append_only(store, "col/doc", [{"msg": "hello"}])
    result = await check_last_item_conflict(store, "col/doc", None, "items")
    assert result == "hash_mismatch"


@pytest.mark.asyncio
async def test_check_last_item_corrupt_json_mismatch():
    store = MemoryObjectStore()
    await store.put("col/doc", "NOT_JSON", content_type="application/json")
    result = await check_last_item_conflict(store, "col/doc", "", "items")
    assert result == "hash_mismatch"
