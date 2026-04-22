"""Tests for StarfishClient HTTP layer."""


from unittest.mock import AsyncMock, MagicMock

import pytest

from starfish_sdk.client import StarfishClient
from starfish_sdk.types import BlobPullResult, BlobPushResult, ConflictError, StarfishHttpError


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


# ---------------------------------------------------------------------------
# pull_blob / push_blob
# ---------------------------------------------------------------------------

def make_binary_response(
    status_code: int,
    content: bytes = b"",
    content_type: str = "application/octet-stream",
    etag: str | None = None,
) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = content
    resp.headers = {}
    resp.text = ""
    resp.headers["content-type"] = content_type
    if etag:
        resp.headers["etag"] = f'"{etag}"'
    return resp


@pytest.mark.asyncio
async def test_pull_blob_returns_bytes_with_hash_and_content_type():
    png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 8
    mock_http = AsyncMock()
    mock_http.get.return_value = make_binary_response(
        200, content=png_bytes, content_type="image/png", etag="abc123"
    )
    client = StarfishClient("http://test", client=mock_http)

    result = await client.pull_blob("/pull/avatars/user1")

    assert result.data == png_bytes
    assert result.hash == "abc123"
    assert result.content_type == "image/png"


@pytest.mark.asyncio
async def test_pull_blob_no_etag_returns_none_hash():
    mock_http = AsyncMock()
    mock_http.get.return_value = make_binary_response(200, content=b"\xff\xd8")
    client = StarfishClient("http://test", client=mock_http)

    result = await client.pull_blob("/pull/blobs/x")

    assert result.hash is None
    assert result.content_type == "application/octet-stream"


@pytest.mark.asyncio
async def test_pull_blob_error_raises():
    mock_http = AsyncMock()
    mock_http.get.return_value = make_binary_response(404, content=b"not found")
    mock_http.get.return_value.text = "not found"
    client = StarfishClient("http://test", client=mock_http)

    with pytest.raises(StarfishHttpError) as exc_info:
        await client.pull_blob("/pull/blobs/missing")
    assert exc_info.value.status == 404


@pytest.mark.asyncio
async def test_push_blob_sends_bytes_and_returns_hash():
    mock_http = AsyncMock()
    mock_http.post.return_value = MagicMock(
        status_code=200,
        json=MagicMock(return_value={"hash": "sha256hex"}),
    )
    client = StarfishClient("http://test", client=mock_http)

    result = await client.push_blob("/push/avatars/user1", b"\x89PNG", "image/png")

    assert result.hash == "sha256hex"
    call_kwargs = mock_http.post.call_args.kwargs
    assert call_kwargs["headers"]["Content-Type"] == "image/png"
    assert call_kwargs["content"] == b"\x89PNG"


@pytest.mark.asyncio
async def test_push_blob_error_raises():
    mock_http = AsyncMock()
    mock_http.post.return_value = MagicMock(
        status_code=415,
        text="unsupported media type",
    )
    client = StarfishClient("http://test", client=mock_http)

    with pytest.raises(StarfishHttpError) as exc_info:
        await client.push_blob("/push/blobs/x", b"data", "video/mp4")
    assert exc_info.value.status == 415


# ---------------------------------------------------------------------------
# namespace path transformation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_namespace_none_leaves_paths_unchanged():
    signed_paths: list[str] = []

    async def capture_auth(method: str, path: str, body: str | None) -> dict[str, str]:
        signed_paths.append(path)
        return {}

    mock_http = AsyncMock()
    mock_http.get.return_value = make_response(200, {"data": {}, "hash": "h", "timestamp": 0})
    client = StarfishClient("http://test", auth=capture_auth, namespace=None, client=mock_http)

    await client.pull("/v1/pull/users/abc/settings")

    url = mock_http.get.call_args.args[0]
    assert url == "http://test/v1/pull/users/abc/settings"
    assert signed_paths == ["/v1/pull/users/abc/settings"]


@pytest.mark.asyncio
async def test_namespace_send_path_prepends_sync_prefix():
    mock_http = AsyncMock()
    mock_http.post.return_value = make_response(200, {"hash": "h", "timestamp": 1})
    client = StarfishClient("http://sync.example.com", namespace="octobot", client=mock_http)

    await client.push("/v1/push/users/abc/errors/salt", {"x": 1}, None)

    url = mock_http.post.call_args.args[0]
    assert url == "http://sync.example.com/sync/octobot/v1/push/users/abc/errors/salt"


@pytest.mark.asyncio
async def test_namespace_sign_path_inserts_namespace_after_v1():
    signed_paths: list[str] = []

    async def capture_auth(method: str, path: str, body: str | None) -> dict[str, str]:
        signed_paths.append(path)
        return {}

    mock_http = AsyncMock()
    mock_http.post.return_value = make_response(200, {"hash": "h", "timestamp": 1})
    client = StarfishClient("http://test", auth=capture_auth, namespace="octobot", client=mock_http)

    await client.push("/v1/push/users/abc/errors/salt", {"x": 1}, None)

    assert signed_paths == ["/v1/octobot/push/users/abc/errors/salt"]


@pytest.mark.asyncio
async def test_get_config_without_namespace():
    mock_http = AsyncMock()
    mock_http.get.return_value = make_response(200, {"collections": [], "version": 1})
    client = StarfishClient("http://test", client=mock_http)

    result = await client.get_config()

    url = mock_http.get.call_args.args[0]
    assert url == "http://test/config"
    assert result == {"collections": [], "version": 1}


@pytest.mark.asyncio
async def test_get_config_with_namespace():
    mock_http = AsyncMock()
    mock_http.get.return_value = make_response(200, {"collections": [], "version": 1})
    client = StarfishClient("http://sync.example.com", namespace="octobot", client=mock_http)

    await client.get_config()

    url = mock_http.get.call_args.args[0]
    assert url == "http://sync.example.com/sync/config"
