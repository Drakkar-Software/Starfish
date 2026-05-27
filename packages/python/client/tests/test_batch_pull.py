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
async def test_batch_pull_builds_collections_and_array_params_query():
    mock_http = AsyncMock()
    mock_http.get.return_value = _resp(
        {
            "collections": {
                # `profile` fanned in two documents; `notes` one (denied).
                "profile": [
                    {"data": {"p": 1}, "hash": "h1", "timestamp": 1},
                    {"data": {"p": 2}, "hash": "h2", "timestamp": 2},
                ],
                "notes": [{"error": "Forbidden"}],
            }
        }
    )
    client = StarfishClient("http://test", client=mock_http)

    res = await client.batch_pull(
        ["profile", "notes"],
        params={"profile": [{"identity": "a"}, {"identity": "b"}], "notes": [{"teamId": "42"}]},
    )

    url = mock_http.get.call_args.args[0]
    parsed = urlparse(url)
    assert parsed.path == "/batch/pull"
    q = parse_qs(parsed.query)
    # collections is a CSV; params is URL-encoded JSON (arrays of param-sets) the
    # server decodes back.
    assert q["collections"] == ["profile,notes"]
    assert json.loads(q["params"][0]) == {
        "profile": [{"identity": "a"}, {"identity": "b"}],
        "notes": [{"teamId": "42"}],
    }
    # The per-document results are parsed through verbatim, in order.
    assert [e["data"] for e in res["collections"]["profile"]] == [{"p": 1}, {"p": 2}]
    assert res["collections"]["notes"][0]["error"] == "Forbidden"


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


@pytest.mark.asyncio
async def test_batch_pull_many_reads_one_collection_aligned_by_index():
    mock_http = AsyncMock()
    mock_http.get.return_value = _resp(
        {
            "collections": {
                "profile": [
                    {"data": {"pseudo": "a"}, "hash": "h1", "timestamp": 1},
                    {"error": "Forbidden"},
                    {"data": {"pseudo": "c"}, "hash": "h3", "timestamp": 3},
                ],
            }
        }
    )
    client = StarfishClient("http://test", client=mock_http)

    entries = await client.batch_pull_many(
        "profile", [{"identity": "a"}, {"identity": "b"}, {"identity": "c"}]
    )

    # One round-trip; the array aligns 1:1 with the requested param-sets.
    assert mock_http.get.call_count == 1
    q = parse_qs(urlparse(mock_http.get.call_args.args[0]).query)
    assert q["collections"] == ["profile"]
    assert json.loads(q["params"][0]) == {
        "profile": [{"identity": "a"}, {"identity": "b"}, {"identity": "c"}]
    }
    assert len(entries) == 3
    assert entries[0]["data"] == {"pseudo": "a"}
    assert entries[1]["error"] == "Forbidden"
    assert entries[2]["data"] == {"pseudo": "c"}


@pytest.mark.asyncio
async def test_batch_pull_many_empty_list_issues_no_request():
    mock_http = AsyncMock()
    client = StarfishClient("http://test", client=mock_http)

    entries = await client.batch_pull_many("profile", [])

    assert entries == []
    mock_http.get.assert_not_called()
