"""Tests for fetch_server_config."""

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from starfish_sdk.config import fetch_server_config, ConfigResponse, CollectionClientInfo, NamespaceClientConfig

BASE_URL = "https://api.example.com/v1"

MOCK_BODY = {
    "collections": [
        {
            "name": "posts",
            "maxBodyBytes": 65536,
            "encryption": "none",
            "allowedMimeTypes": ["application/json"],
            "publicKey": "base64key==",
        },
        {
            "name": "events",
            "maxBodyBytes": 16384,
            "encryption": "none",
            "allowedMimeTypes": ["application/json"],
            "queueOnly": True,
        },
    ]
}


def _make_mock_client(status_code: int = 200, body: dict | None = None) -> AsyncMock:
    resp = MagicMock()
    resp.json.return_value = body or {}
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"{status_code}",
            request=MagicMock(),
            response=MagicMock(status_code=status_code),
        )
    else:
        resp.raise_for_status.return_value = None
    mock = AsyncMock()
    mock.get.return_value = resp
    return mock


@pytest.mark.asyncio
async def test_fetch_returns_typed_config_response():
    mock_client = _make_mock_client(200, MOCK_BODY)
    result = await fetch_server_config(BASE_URL, _client=mock_client)

    assert isinstance(result, ConfigResponse)
    assert len(result.collections) == 2
    assert result.collections[0].name == "posts"
    assert result.collections[0].public_key == "base64key=="
    assert result.collections[1].queue_only is True


@pytest.mark.asyncio
async def test_fetch_strips_trailing_slash():
    mock_client = _make_mock_client(200, {"collections": []})
    await fetch_server_config(f"{BASE_URL}/", _client=mock_client)
    call_url = mock_client.get.call_args.args[0]
    assert call_url == f"{BASE_URL}/config"


@pytest.mark.asyncio
async def test_fetch_passes_custom_headers():
    mock_client = _make_mock_client(200, {"collections": []})
    await fetch_server_config(BASE_URL, headers={"Authorization": "Bearer token"}, _client=mock_client)
    call_kwargs = mock_client.get.call_args.kwargs
    assert call_kwargs["headers"]["Authorization"] == "Bearer token"


@pytest.mark.asyncio
async def test_fetch_raises_on_non_2xx():
    mock_client = _make_mock_client(404)
    with pytest.raises(httpx.HTTPStatusError):
        await fetch_server_config(BASE_URL, _client=mock_client)


@pytest.mark.asyncio
async def test_fetch_parses_namespaces():
    payload = {
        "collections": [],
        "namespaces": {
            "tenantA": {
                "collections": [
                    {
                        "name": "settings",
                        "maxBodyBytes": 1024,
                        "encryption": "none",
                        "allowedMimeTypes": ["application/json"],
                    }
                ]
            }
        },
    }
    mock_client = _make_mock_client(200, payload)
    result = await fetch_server_config(BASE_URL, _client=mock_client)

    assert result.namespaces is not None
    assert "tenantA" in result.namespaces
    tenant = result.namespaces["tenantA"]
    assert isinstance(tenant, NamespaceClientConfig)
    assert tenant.collections[0].name == "settings"


@pytest.mark.asyncio
async def test_fetch_empty_collections():
    mock_client = _make_mock_client(200, {"collections": []})
    result = await fetch_server_config(BASE_URL, _client=mock_client)
    assert result.collections == []
    assert result.namespaces is None
