"""Tests for pull operation — ported from pull.test.ts.

Regular pull always returns the full document — ``?checkpoint=`` incremental
filtering was removed for regular collections (it is now appendOnly-only).
"""

import pytest

from starfish_server.protocol.pull import pull
from starfish_server.protocol.push import push
from starfish_server.protocol.types import PushSuccess
from tests.helpers import MemoryObjectStore


@pytest.mark.asyncio
async def test_returns_empty_data_when_no_document_exists():
    store = MemoryObjectStore()
    result = await pull(store, "col/doc1")
    assert result.data == {}
    assert result.hash == ""
    assert isinstance(result.timestamp, int)


@pytest.mark.asyncio
async def test_returns_full_data_after_push():
    store = MemoryObjectStore()
    data = {"sig-1": {"payload": {"value": 42}}}
    await push(store, "col/doc1", data, None)

    result = await pull(store, "col/doc1")
    assert result.data == data
    assert len(result.hash) == 64
    assert isinstance(result.timestamp, int)


@pytest.mark.asyncio
async def test_always_returns_full_document_after_multiple_pushes():
    """Regular pull always returns the full document — no checkpoint filtering."""
    store = MemoryObjectStore()

    data1 = {"sig-1": {"payload": {"value": 1}}}
    r1 = await push(store, "col/doc1", data1, None)
    assert isinstance(r1, PushSuccess)

    data2 = {"sig-1": {"payload": {"value": 1}}, "sig-2": {"payload": {"value": 2}}}
    await push(store, "col/doc1", data2, r1.hash)

    result = await pull(store, "col/doc1")
    assert result.data == data2
    assert "sig-1" in result.data
    assert "sig-2" in result.data
    assert len(result.hash) == 64


@pytest.mark.asyncio
async def test_corrupt_stored_document_does_not_crash_pull():
    """A corrupt stored document must return empty data, not raise an unhandled exception."""
    store = MemoryObjectStore()
    # Inject a corrupt (non-JSON) value directly into the store
    await store.put("col/corrupt", "NOT_VALID_JSON", content_type="application/json")

    result = await pull(store, "col/corrupt")
    assert result.data == {}
    assert result.hash == ""
