"""Tests for StarfishClient HTTP layer."""


from unittest.mock import AsyncMock, MagicMock

import pytest

from starfish_sdk.client import StarfishClient
from starfish_sdk.types import ConflictError, StarfishHttpError


def make_response(status_code: int, data: dict | None = None, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if data is not None:
        resp.json.return_value = data
    return resp


@pytest.mark.asyncio
async def test_pull_success():
    mock_http = AsyncMock()
    mock_http.get.return_value = make_response(
        200, {"data": {"k": "v"}, "hash": "abc", "timestamp": 1000}
    )
    client = StarfishClient("http://test", client=mock_http)

    result = await client.pull("/pull/test")

    assert result.data == {"k": "v"}
    assert result.hash == "abc"
    assert result.timestamp == 1000
    assert result.author_pubkey is None


@pytest.mark.asyncio
async def test_pull_with_checkpoint_sends_param():
    mock_http = AsyncMock()
    mock_http.get.return_value = make_response(
        200, {"data": {}, "hash": "h", "timestamp": 500}
    )
    client = StarfishClient("http://test", client=mock_http)

    await client.pull("/pull/test", checkpoint=500)

    call_kwargs = mock_http.get.call_args.kwargs
    assert call_kwargs["params"] == {"checkpoint": "500"}


@pytest.mark.asyncio
async def test_pull_zero_checkpoint_omits_param():
    mock_http = AsyncMock()
    mock_http.get.return_value = make_response(
        200, {"data": {}, "hash": "h", "timestamp": 0}
    )
    client = StarfishClient("http://test", client=mock_http)

    await client.pull("/pull/test", checkpoint=0)

    call_kwargs = mock_http.get.call_args.kwargs
    assert call_kwargs["params"] == {}


@pytest.mark.asyncio
async def test_pull_http_error_raises():
    mock_http = AsyncMock()
    mock_http.get.return_value = make_response(500, text="internal error")
    client = StarfishClient("http://test", client=mock_http)

    with pytest.raises(StarfishHttpError) as exc_info:
        await client.pull("/pull/test")
    assert exc_info.value.status == 500


@pytest.mark.asyncio
async def test_push_success():
    mock_http = AsyncMock()
    mock_http.post.return_value = make_response(200, {"hash": "def", "timestamp": 2000})
    client = StarfishClient("http://test", client=mock_http)

    result = await client.push("/push/test", {"x": 1}, "base-hash")

    assert result.hash == "def"
    assert result.timestamp == 2000


@pytest.mark.asyncio
async def test_push_conflict_raises():
    mock_http = AsyncMock()
    mock_http.post.return_value = make_response(409)
    client = StarfishClient("http://test", client=mock_http)

    with pytest.raises(ConflictError):
        await client.push("/push/test", {}, "bad-hash")


@pytest.mark.asyncio
async def test_push_http_error_raises():
    mock_http = AsyncMock()
    mock_http.post.return_value = make_response(500, text="server error")
    client = StarfishClient("http://test", client=mock_http)

    with pytest.raises(StarfishHttpError) as exc_info:
        await client.push("/push/test", {}, None)
    assert exc_info.value.status == 500


@pytest.mark.asyncio
async def test_auth_headers_included_in_pull():
    async def my_auth(method: str, path: str, body: str | None) -> dict[str, str]:
        return {"Authorization": "Bearer token"}

    mock_http = AsyncMock()
    mock_http.get.return_value = make_response(200, {"data": {}, "hash": "h", "timestamp": 0})
    client = StarfishClient("http://test", auth=my_auth, client=mock_http)

    await client.pull("/pull/test")

    headers = mock_http.get.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer token"


@pytest.mark.asyncio
async def test_context_manager_closes_client():
    mock_http = AsyncMock()
    client = StarfishClient("http://test", client=mock_http)

    async with client:
        pass

    mock_http.aclose.assert_called_once()


@pytest.mark.asyncio
async def test_base_url_trailing_slash_stripped():
    mock_http = AsyncMock()
    mock_http.get.return_value = make_response(200, {"data": {}, "hash": "h", "timestamp": 0})
    client = StarfishClient("http://test///", client=mock_http)

    await client.pull("/pull/test")

    url = mock_http.get.call_args.args[0]
    assert url == "http://test/pull/test"
