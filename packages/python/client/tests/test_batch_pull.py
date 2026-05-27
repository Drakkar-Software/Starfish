"""Tests for StarfishClient.batch_pull (the /batch/pull helper)."""

import json
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import urlparse, parse_qs

import pytest

from starfish_sdk.client import StarfishClient


def _resp(data: dict) -> MagicMock:
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = data
    return r


@pytest.mark.asyncio
async def test_batch_pull_builds_collections_and_params_query():
    mock_http = AsyncMock()
    mock_http.get.return_value = _resp(
        {
            "collections": {
                "profile": {"data": {"p": 1}, "hash": "h", "timestamp": 1},
                "notes": {"error": "Forbidden"},
            }
        }
    )
    client = StarfishClient("http://test", client=mock_http)

    res = await client.batch_pull(["profile", "notes"], params={"notes": {"teamId": "42"}})

    url = mock_http.get.call_args.args[0]
    parsed = urlparse(url)
    assert parsed.path == "/batch/pull"
    q = parse_qs(parsed.query)
    # collections is a CSV; params is URL-encoded JSON the server decodes back.
    assert q["collections"] == ["profile,notes"]
    assert json.loads(q["params"][0]) == {"notes": {"teamId": "42"}}
    # The per-collection results are parsed through verbatim.
    assert res["collections"]["profile"]["data"] == {"p": 1}
    assert res["collections"]["notes"]["error"] == "Forbidden"


@pytest.mark.asyncio
async def test_batch_pull_omits_params_and_honors_namespace():
    mock_http = AsyncMock()
    mock_http.get.return_value = _resp({"collections": {}})
    client = StarfishClient("http://sync.example.com", namespace="octochat", client=mock_http)

    await client.batch_pull(["settings", "notes"])

    url = mock_http.get.call_args.args[0]
    parsed = urlparse(url)
    assert parsed.path == "/v1/octochat/batch/pull"  # namespace inserted before the query
    q = parse_qs(parsed.query)
    assert q["collections"] == ["settings,notes"]
    assert "params" not in q
