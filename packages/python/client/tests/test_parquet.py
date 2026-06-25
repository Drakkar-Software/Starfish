"""Tests for pushParquet / pullParquet client methods and PARQUET_MIME_TYPE re-exports."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from starfish_sdk import PARQUET_MIME_TYPE, PARQUET_MIME_TYPES
from starfish_sdk.client import StarfishClient
from starfish_sdk.types import BlobPullResult, BlobPushResult, StarfishHttpError
from starfish_protocol.constants import PARQUET_MIME_TYPE as PROTO_PARQUET_MIME_TYPE

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PARQUET_BYTES = b"PAR1" + b"\x00" * 20 + b"PAR1"


def make_ok_response(**kwargs) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.text = ""
    for k, v in kwargs.items():
        setattr(resp, k, v)
    return resp


def make_error_response(status_code: int, text: str = "error") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


# ---------------------------------------------------------------------------
# MIME constant re-exports
# ---------------------------------------------------------------------------


class TestParquetMimeConstants:
    def test_canonical_mime_type(self):
        assert PARQUET_MIME_TYPE == "application/vnd.apache.parquet"

    def test_matches_protocol_package(self):
        assert PARQUET_MIME_TYPE == PROTO_PARQUET_MIME_TYPE

    def test_mime_types_contains_all_variants(self):
        assert "application/vnd.apache.parquet" in PARQUET_MIME_TYPES
        assert "application/x-parquet" in PARQUET_MIME_TYPES
        assert "application/octet-stream" in PARQUET_MIME_TYPES


# ---------------------------------------------------------------------------
# push_parquet
# ---------------------------------------------------------------------------


class TestPushParquet:
    @pytest.mark.asyncio
    async def test_sends_parquet_content_type(self):
        mock_http = AsyncMock()
        mock_http.post.return_value = make_ok_response()
        mock_http.post.return_value.json.return_value = {"hash": "abc123"}

        client = StarfishClient("http://test", client=mock_http)
        await client.push_parquet("/push/analytics/alice/q1.parquet", PARQUET_BYTES)

        call_kwargs = mock_http.post.call_args.kwargs
        headers = call_kwargs.get("headers", {})
        assert headers.get("Content-Type") == PARQUET_MIME_TYPE

    @pytest.mark.asyncio
    async def test_posts_to_correct_url(self):
        mock_http = AsyncMock()
        mock_http.post.return_value = make_ok_response()
        mock_http.post.return_value.json.return_value = {"hash": "abc"}

        client = StarfishClient("http://test", client=mock_http)
        await client.push_parquet("/push/analytics/alice/q1.parquet", PARQUET_BYTES)

        url = mock_http.post.call_args.args[0]
        assert url == "http://test/push/analytics/alice/q1.parquet"

    @pytest.mark.asyncio
    async def test_returns_blob_push_result(self):
        mock_http = AsyncMock()
        mock_http.post.return_value = make_ok_response()
        mock_http.post.return_value.json.return_value = {"hash": "deadbeef"}

        client = StarfishClient("http://test", client=mock_http)
        result = await client.push_parquet("/push/analytics/alice/q1.parquet", PARQUET_BYTES)

        assert isinstance(result, BlobPushResult)
        assert result.hash == "deadbeef"

    @pytest.mark.asyncio
    async def test_raises_on_error(self):
        mock_http = AsyncMock()
        mock_http.post.return_value = make_error_response(403, "forbidden")

        client = StarfishClient("http://test", client=mock_http)
        with pytest.raises(StarfishHttpError) as exc_info:
            await client.push_parquet("/push/analytics/alice/q1.parquet", PARQUET_BYTES)

        assert exc_info.value.status == 403


# ---------------------------------------------------------------------------
# pull_parquet
# ---------------------------------------------------------------------------


class TestPullParquet:
    def _make_pull_response(self) -> MagicMock:
        resp = MagicMock()
        resp.status_code = 200
        resp.text = ""
        resp.content = PARQUET_BYTES
        resp.headers = {
            "content-type": PARQUET_MIME_TYPE,
            "etag": '"abc123"',
        }
        return resp

    @pytest.mark.asyncio
    async def test_makes_get_request(self):
        mock_http = AsyncMock()
        mock_http.get.return_value = self._make_pull_response()

        client = StarfishClient("http://test", client=mock_http)
        await client.pull_parquet("/pull/analytics/alice/q1.parquet")

        url = mock_http.get.call_args.args[0]
        assert url == "http://test/pull/analytics/alice/q1.parquet"

    @pytest.mark.asyncio
    async def test_returns_blob_pull_result(self):
        mock_http = AsyncMock()
        mock_http.get.return_value = self._make_pull_response()

        client = StarfishClient("http://test", client=mock_http)
        result = await client.pull_parquet("/pull/analytics/alice/q1.parquet")

        assert isinstance(result, BlobPullResult)
        assert result.data == PARQUET_BYTES
        assert result.content_type == PARQUET_MIME_TYPE
        assert result.hash == "abc123"

    @pytest.mark.asyncio
    async def test_raises_on_error(self):
        mock_http = AsyncMock()
        err_resp = MagicMock()
        err_resp.status_code = 404
        err_resp.text = "not found"
        mock_http.get.return_value = err_resp

        client = StarfishClient("http://test", client=mock_http)
        with pytest.raises(StarfishHttpError) as exc_info:
            await client.pull_parquet("/pull/analytics/alice/missing.parquet")

        assert exc_info.value.status == 404
