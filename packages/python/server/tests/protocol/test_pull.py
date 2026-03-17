"""Tests for pull operation — ported from pull.test.ts."""

import asyncio

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
async def test_returns_filtered_data_with_checkpoint():
    store = MemoryObjectStore()

    data1 = {"sig-1": {"payload": {"value": 1}}}
    r1 = await push(store, "col/doc1", data1, None)
    assert isinstance(r1, PushSuccess)
    checkpoint = r1.timestamp

    await asyncio.sleep(0.001)
    data2 = {"sig-1": {"payload": {"value": 1}}, "sig-2": {"payload": {"value": 2}}}
    await push(store, "col/doc1", data2, r1.hash)

    result = await pull(store, "col/doc1", checkpoint)
    assert "sig-2" in result.data
    assert len(result.hash) == 64


@pytest.mark.asyncio
async def test_returns_full_data_when_timestamps_empty_client_encrypted():
    store = MemoryObjectStore()

    r1 = await push(store, "col/doc1", {"_encrypted": "v1"}, None, skip_timestamps=True)
    assert isinstance(r1, PushSuccess)
    checkpoint = r1.timestamp

    await push(store, "col/doc1", {"_encrypted": "v2"}, r1.hash, skip_timestamps=True)

    result = await pull(store, "col/doc1", checkpoint)
    assert result.data == {"_encrypted": "v2"}


@pytest.mark.asyncio
async def test_returns_full_data_when_checkpoint_is_zero():
    store = MemoryObjectStore()
    data = {"sig-1": {"payload": {"value": 42}}}
    await push(store, "col/doc1", data, None)

    result = await pull(store, "col/doc1", 0)
    assert result.data == data
