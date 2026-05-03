"""Tests for append-only pull/push via StarfishClient."""

import pytest
import respx
import httpx

from starfish_sdk.client import StarfishClient
from starfish_protocol.types import PushSuccess, PullResult


BASE = "https://api.example.com/v1"
PUSH_SUCCESS = PushSuccess(hash="abc123", timestamp=1714000000)


def _json_resp(data: object) -> httpx.Response:
    return httpx.Response(200, json={"data": data, "hash": "h1", "timestamp": 0})


@pytest.mark.asyncio
async def test_push_null_base_hash_for_append():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.post("/v1/push/events").mock(return_value=httpx.Response(
            200, json={"hash": "abc123", "timestamp": 1714000000}
        ))
        async with StarfishClient(BASE) as client:
            result = await client.push("/push/events", {"type": "click"}, None)
    assert result == PUSH_SUCCESS


@pytest.mark.asyncio
async def test_pull_append_field_returns_list():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": [{"msg": "a"}, {"msg": "b"}]}))
        async with StarfishClient(BASE) as client:
            result = await client.pull("/pull/events", append_field="items")
    assert result == [{"msg": "a"}, {"msg": "b"}]


@pytest.mark.asyncio
async def test_pull_since_defaults_field_to_items():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": [{"n": 1}]}))
        async with StarfishClient(BASE) as client:
            result = await client.pull("/pull/events", since=1000)
    assert result == [{"n": 1}]


@pytest.mark.asyncio
async def test_pull_append_returns_empty_when_data_none():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp(None))
        async with StarfishClient(BASE) as client:
            result = await client.pull("/pull/events", append_field="items")
    assert result == []


@pytest.mark.asyncio
async def test_pull_append_returns_empty_when_field_absent():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({}))
        async with StarfishClient(BASE) as client:
            result = await client.pull("/pull/events", append_field="items")
    assert result == []


@pytest.mark.asyncio
async def test_pull_append_returns_empty_when_not_list():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": "not-a-list"}))
        async with StarfishClient(BASE) as client:
            result = await client.pull("/pull/events", append_field="items")
    assert result == []


@pytest.mark.asyncio
async def test_pull_append_custom_field():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"logs": [{"x": 1}]}))
        async with StarfishClient(BASE) as client:
            result = await client.pull("/pull/events", append_field="logs")
    assert result == [{"x": 1}]


@pytest.mark.asyncio
async def test_pull_since_sends_checkpoint_param():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": []}))
        async with StarfishClient(BASE) as client:
            await client.pull("/pull/events", since=1714000000)
        assert "checkpoint=1714000000" in str(mock.calls[0].request.url)


@pytest.mark.asyncio
async def test_pull_last_sends_last_param():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": []}))
        async with StarfishClient(BASE) as client:
            await client.pull("/pull/events", last=10)
        assert "last=10" in str(mock.calls[0].request.url)


@pytest.mark.asyncio
async def test_pull_since_and_last_combined():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": []}))
        async with StarfishClient(BASE) as client:
            await client.pull("/pull/events", since=5000, last=20)
        url = str(mock.calls[0].request.url)
        assert "checkpoint=5000" in url
        assert "last=20" in url


@pytest.mark.asyncio
async def test_pull_no_append_options_returns_pull_result():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/settings").mock(return_value=httpx.Response(
            200, json={"data": {"key": "value"}, "hash": "h1", "timestamp": 123}
        ))
        async with StarfishClient(BASE) as client:
            result = await client.pull("/pull/settings")
    assert isinstance(result, PullResult)
    assert result.data == {"key": "value"}


@pytest.mark.asyncio
async def test_pull_negative_since_raises():
    async with StarfishClient(BASE) as client:
        with pytest.raises(ValueError, match="since must be non-negative"):
            await client.pull("/pull/events", since=-1)


@pytest.mark.asyncio
async def test_pull_negative_last_raises():
    async with StarfishClient(BASE) as client:
        with pytest.raises(ValueError, match="last must be non-negative"):
            await client.pull("/pull/events", last=-1)
