"""Append/checkpoint-aware batch pull tests (Python).

Mirrors the TS test at:
  packages/ts/server/tests/router/batch-pull-append.test.ts

Key invariants:
- last=N returns N newest elements
- since (maps to checkpoint) filters ts > since; requires last unless since > 0
- since=0 is an explicit checkpoint=0 (non-null) — not rejected, returns all
- since + last combined: checkpoint filter then tail
- full:true in appendParams → 400 whole-request (DoS guard)
- empty appendParams entry {} → pull_bound_required per-entry
- non-append collection + appendParams → append_params_not_supported per-entry
- mixed: append + non-append collections in one batch
- non-default appendField ("entries")
- maxPullLimit clamps requested last
- appendParams with fewer entries than params → trailing fall back to full-doc
- field-filter applied on the append branch
- invalid appendParams JSON → 400
- appendParams as JSON array → 400
- per-entry different bounds in same collection
- float value in since/last → 400
- aggregate budget exceeded → 400
- _keyring collection key → Forbidden per-entry
"""
import json
import urllib.parse

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_server.config.schema import CollectionConfig, SyncConfig, AppendOnlyConfig, FieldPermission
from starfish_server.router.route_builder import AuthResult, SyncRouterOptions, create_sync_router
from starfish_server.storage.memory import MemoryObjectStore


# ── helpers ───────────────────────────────────────────────────────────────────


ROOM1_ITEMS = [
    {"ts": 100, "data": {"text": "first"}},
    {"ts": 200, "data": {"text": "second"}},
    {"ts": 300, "data": {"text": "third"}},
    {"ts": 400, "data": {"text": "fourth"}},
    {"ts": 500, "data": {"text": "fifth"}},
]
ROOM2_ITEMS = [
    {"ts": 10, "data": {"text": "a"}},
    {"ts": 20, "data": {"text": "b"}},
]


def _make_app(
    collections: list[CollectionConfig],
    fixtures: dict[str, dict],
    identity: str = "alice",
    roles: list[str] | None = None,
    scope_paths: list[str] | None = None,
    max_batch_append_elements: int = 5000,
) -> FastAPI:
    """Build a FastAPI app with a seeded MemoryObjectStore and given collections."""
    # Append-only docs stored as { data: { <field>: [...] }, hash, ts }
    data: dict[str, str] = {}
    for key, val in fixtures.items():
        data[key] = json.dumps({"data": val, "hash": f"h-{key}", "ts": 9999})

    store = MemoryObjectStore(data=data)

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity=identity, roles=roles or [], scope_paths=scope_paths)

    router = create_sync_router(
        SyncRouterOptions(
            store=store,
            config=SyncConfig(version=1, collections=collections),
            role_resolver=role_resolver,
            max_batch_append_elements=max_batch_append_elements,
        )
    )
    app = FastAPI()
    app.include_router(router)
    return app


def _batch_url(
    collections: list[str],
    params: dict[str, list[dict]],
    append_params: dict[str, list[dict]] | None = None,
) -> str:
    url = f"/batch/pull?collections={','.join(collections)}"
    url += f"&params={urllib.parse.quote(json.dumps(params, separators=(',', ':')),'')}"
    if append_params is not None:
        url += f"&appendParams={urllib.parse.quote(json.dumps(append_params, separators=(',', ':')), '')}"
    return url


# ── collection configs ────────────────────────────────────────────────────────

EVENTS_COL = CollectionConfig(
    name="events",
    storagePath="rooms/{roomId}/events",
    readRoles=["public"],
    writeRoles=["self"],
    encryption="none",
    maxBodyBytes=1_000_000,
    appendOnly=AppendOnlyConfig(type="by_timestamp", field="items", persist=True, allowFull=True),
)

STRICT_EVENTS_COL = CollectionConfig(
    name="strictevents",
    storagePath="rooms/{roomId}/strictevents",
    readRoles=["public"],
    writeRoles=["self"],
    encryption="none",
    maxBodyBytes=1_000_000,
    appendOnly=AppendOnlyConfig(type="by_timestamp", field="items", persist=True, allowFull=False, maxPullLimit=2),
)

FEED_COL = CollectionConfig(
    name="feed",
    storagePath="users/{userId}/feed",
    readRoles=["public"],
    writeRoles=["self"],
    encryption="none",
    maxBodyBytes=1_000_000,
    appendOnly=AppendOnlyConfig(type="by_timestamp", field="entries", persist=True, allowFull=True),
)

NOTES_COL = CollectionConfig(
    name="notes",
    storagePath="users/{userId}/notes",
    readRoles=["public"],
    writeRoles=["self"],
    encryption="none",
    maxBodyBytes=1_000_000,
)

# Collection with a field that requires "admin" role to read.
# Callers without the admin role should not see "secretField" in element data.
RESTRICTED_EVENTS_COL = CollectionConfig(
    name="revents",
    storagePath="rooms/{roomId}/revents",
    readRoles=["public"],
    writeRoles=["self"],
    encryption="none",
    maxBodyBytes=1_000_000,
    appendOnly=AppendOnlyConfig(type="by_timestamp", field="items", persist=True, allowFull=True),
    fieldPermissions={"secretField": FieldPermission(readRoles=["admin"])},
)

# Collection for the _keyring deny-suffix test
KEYRING_COL = CollectionConfig(
    name="_keyring",
    storagePath="rooms/{roomId}/_keyring",
    readRoles=["public"],
    writeRoles=["self"],
    encryption="none",
    maxBodyBytes=1_000_000,
)


# ── tests ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_last_1_returns_newest_element():
    app = _make_app([EVENTS_COL], {"rooms/room-1/events": {"items": ROOM1_ITEMS}})
    url = _batch_url(["events"], {"events": [{"roomId": "room-1"}]}, {"events": [{"last": 1}]})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    assert resp.status_code == 200
    body = resp.json()
    items = body["collections"]["events"][0]["data"]["items"]
    assert len(items) == 1
    assert items[0]["ts"] == 500


@pytest.mark.asyncio
async def test_last_3_returns_three_newest():
    app = _make_app([EVENTS_COL], {"rooms/room-1/events": {"items": ROOM1_ITEMS}})
    url = _batch_url(["events"], {"events": [{"roomId": "room-1"}]}, {"events": [{"last": 3}]})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    body = resp.json()
    items = body["collections"]["events"][0]["data"]["items"]
    assert len(items) == 3
    assert items[0]["ts"] == 300
    assert items[2]["ts"] == 500


@pytest.mark.asyncio
async def test_since_with_last_filters_and_tails():
    """since=200 (checkpoint=200) + last=100: ts>200 → third,fourth,fifth (count=3)."""
    app = _make_app([EVENTS_COL], {"rooms/room-1/events": {"items": ROOM1_ITEMS}})
    url = _batch_url(["events"], {"events": [{"roomId": "room-1"}]}, {"events": [{"since": 200, "last": 100}]})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    body = resp.json()
    items = body["collections"]["events"][0]["data"]["items"]
    assert len(items) == 3
    assert items[0]["ts"] == 300
    assert items[2]["ts"] == 500


@pytest.mark.asyncio
async def test_since_zero_explicit_checkpoint_returns_all():
    """since=0 → checkpointParam='0' (non-null explicit) → not rejected → all 5 items."""
    app = _make_app([EVENTS_COL], {"rooms/room-1/events": {"items": ROOM1_ITEMS}})
    url = _batch_url(["events"], {"events": [{"roomId": "room-1"}]}, {"events": [{"since": 0}]})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    body = resp.json()
    items = body["collections"]["events"][0]["data"]["items"]
    assert len(items) == 5


@pytest.mark.asyncio
async def test_empty_append_opts_returns_pull_bound_required():
    """appendParams entry {} passes checkpointParam=None, no last → pull_bound_required."""
    app = _make_app([EVENTS_COL], {"rooms/room-1/events": {"items": ROOM1_ITEMS}})
    url = _batch_url(["events"], {"events": [{"roomId": "room-1"}]}, {"events": [{}]})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    assert resp.status_code == 200
    body = resp.json()
    assert body["collections"]["events"][0]["error"] == "pull_bound_required"


@pytest.mark.asyncio
async def test_since_and_last_combined():
    """since=100 (checkpoint=100) + last=2 → ts>100: 200,300,400,500 → last 2: 400,500."""
    app = _make_app([EVENTS_COL], {"rooms/room-1/events": {"items": ROOM1_ITEMS}})
    url = _batch_url(["events"], {"events": [{"roomId": "room-1"}]}, {"events": [{"since": 100, "last": 2}]})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    body = resp.json()
    items = body["collections"]["events"][0]["data"]["items"]
    assert len(items) == 2
    assert items[0]["ts"] == 400
    assert items[1]["ts"] == 500


@pytest.mark.asyncio
async def test_full_true_in_append_params_rejected_400():
    """full:true in appendParams is rejected 400 for the whole request (DoS guard)."""
    app = _make_app([EVENTS_COL], {"rooms/room-1/events": {"items": ROOM1_ITEMS}})
    url = _batch_url(["events"], {"events": [{"roomId": "room-1"}]}, {"events": [{"full": True}]})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_non_append_collection_returns_append_params_not_supported():
    """appendParams for a non-append-only collection → append_params_not_supported."""
    app = _make_app([NOTES_COL], {"users/alice/notes": {"body": "hi"}})
    url = _batch_url(["notes"], {"notes": [{"userId": "alice"}]}, {"notes": [{"last": 1}]})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    assert resp.status_code == 200
    body = resp.json()
    assert body["collections"]["notes"][0]["error"] == "append_params_not_supported"


@pytest.mark.asyncio
async def test_mixed_append_and_regular_collections():
    """Append collection (events) with appendParams + regular collection (notes) without → both ok."""
    app = _make_app(
        [EVENTS_COL, NOTES_COL],
        {
            "rooms/room-1/events": {"items": ROOM1_ITEMS},
            "users/alice/notes": {"body": "a note"},
        },
    )
    url = _batch_url(
        ["events", "notes"],
        {"events": [{"roomId": "room-1"}], "notes": [{"userId": "alice"}]},
        {"events": [{"last": 1}]},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    body = resp.json()
    # events → bounded tail
    items = body["collections"]["events"][0]["data"]["items"]
    assert len(items) == 1
    assert items[0]["ts"] == 500
    # notes → full doc (no appendParams)
    assert body["collections"]["notes"][0]["data"]["body"] == "a note"


@pytest.mark.asyncio
async def test_non_default_append_field():
    """feed uses 'entries' as appendField — result must use that field name."""
    app = _make_app(
        [FEED_COL],
        {"users/alice/feed": {"entries": [{"ts": 1000, "data": {"post": "hello"}}, {"ts": 2000, "data": {"post": "world"}}]}},
    )
    url = _batch_url(["feed"], {"feed": [{"userId": "alice"}]}, {"feed": [{"last": 1}]})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    body = resp.json()
    entries = body["collections"]["feed"][0]["data"]["entries"]
    assert len(entries) == 1
    assert entries[0]["ts"] == 2000
    assert "items" not in body["collections"]["feed"][0]["data"]


@pytest.mark.asyncio
async def test_max_pull_limit_clamps_last():
    """strictevents maxPullLimit=2: requesting last=999 is clamped to 2."""
    app = _make_app(
        [STRICT_EVENTS_COL],
        {"rooms/room-1/strictevents": {"items": [{"ts": 100, "data": {"msg": "x"}}, {"ts": 200, "data": {"msg": "y"}}, {"ts": 300, "data": {"msg": "z"}}]}},
    )
    url = _batch_url(["strictevents"], {"strictevents": [{"roomId": "room-1"}]}, {"strictevents": [{"last": 999}]})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    body = resp.json()
    items = body["collections"]["strictevents"][0]["data"]["items"]
    assert len(items) == 2  # clamped to maxPullLimit=2
    assert items[0]["ts"] == 200
    assert items[1]["ts"] == 300


@pytest.mark.asyncio
async def test_per_entry_different_last_bounds():
    """Different last bounds per room in same batch: room-1 last=2, room-2 last=1."""
    app = _make_app(
        [EVENTS_COL],
        {"rooms/room-1/events": {"items": ROOM1_ITEMS}, "rooms/room-2/events": {"items": ROOM2_ITEMS}},
    )
    url = _batch_url(
        ["events"],
        {"events": [{"roomId": "room-1"}, {"roomId": "room-2"}]},
        {"events": [{"last": 2}, {"last": 1}]},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    body = resp.json()
    entries = body["collections"]["events"]
    # room-1: last 2 → 400, 500
    assert len(entries[0]["data"]["items"]) == 2
    assert entries[0]["data"]["items"][0]["ts"] == 400
    assert entries[0]["data"]["items"][1]["ts"] == 500
    # room-2: last 1 → 20
    assert len(entries[1]["data"]["items"]) == 1
    assert entries[1]["data"]["items"][0]["ts"] == 20


@pytest.mark.asyncio
async def test_append_params_length_mismatch_returns_400():
    """appendParams array length must equal the params array length for that collection.
    Sending 1 appendParams entry with 2 params entries → 400 (whole request)."""
    app = _make_app(
        [EVENTS_COL],
        {"rooms/room-1/events": {"items": ROOM1_ITEMS}, "rooms/room-2/events": {"items": ROOM2_ITEMS}},
    )
    url = _batch_url(
        ["events"],
        {"events": [{"roomId": "room-1"}, {"roomId": "room-2"}]},
        {"events": [{"last": 1}]},  # only 1 entry for 2 param-sets → length mismatch
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_restricted_field_stripped_from_append_elements():
    """A field marked admin-only in fieldPermissions is absent from every element's
    data when the caller does not hold the admin role."""
    items_with_secret = [
        {"ts": 100, "data": {"text": "hello", "secretField": "classified"}},
        {"ts": 200, "data": {"text": "world", "secretField": "classified"}},
    ]
    app = _make_app(
        [RESTRICTED_EVENTS_COL],
        {"rooms/room-1/revents": {"items": items_with_secret}},
        roles=[],  # no admin role
    )
    url = _batch_url(["revents"], {"revents": [{"roomId": "room-1"}]}, {"revents": [{"last": 2}]})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    assert resp.status_code == 200
    body = resp.json()
    entry = body["collections"]["revents"][0]
    assert entry.get("error") is None
    items = entry["data"]["items"]
    assert len(items) == 2
    for item in items:
        # secretField must be absent — caller has no admin role
        assert "secretField" not in item["data"]
        # allowed field must be present
        assert "text" in item["data"]


@pytest.mark.asyncio
async def test_invalid_append_params_json_returns_400():
    """Malformed appendParams JSON → 400 (whole request)."""
    app = _make_app([EVENTS_COL], {})
    params_str = urllib.parse.quote(json.dumps({"events": [{"roomId": "room-1"}]}, separators=(",", ":")), "")
    url = f"/batch/pull?collections=events&params={params_str}&appendParams=NOT_JSON"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_append_params_as_array_returns_400():
    """appendParams as JSON array (not object) → 400."""
    app = _make_app([EVENTS_COL], {})
    params_str = urllib.parse.quote(json.dumps({"events": [{"roomId": "room-1"}]}, separators=(",", ":")), "")
    bad_ap = urllib.parse.quote("[1,2,3]", "")
    url = f"/batch/pull?collections=events&params={params_str}&appendParams={bad_ap}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_append_params_non_array_value_returns_400():
    """appendParams with non-array value for a collection → 400."""
    app = _make_app([EVENTS_COL], {})
    params_str = urllib.parse.quote(json.dumps({"events": [{"roomId": "room-1"}]}, separators=(",", ":")), "")
    bad_ap = urllib.parse.quote(json.dumps({"events": {"last": 1}}, separators=(",", ":")), "")
    url = f"/batch/pull?collections=events&params={params_str}&appendParams={bad_ap}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_limit_alias_same_as_last():
    """limit is an alias for last; limit=2 returns the 2 newest elements."""
    app = _make_app([EVENTS_COL], {"rooms/room-1/events": {"items": ROOM1_ITEMS}})
    url = _batch_url(["events"], {"events": [{"roomId": "room-1"}]}, {"events": [{"limit": 2}]})
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    body = resp.json()
    items = body["collections"]["events"][0]["data"]["items"]
    assert len(items) == 2
    assert items[0]["ts"] == 400
    assert items[1]["ts"] == 500


@pytest.mark.asyncio
async def test_two_collections_both_with_append_params():
    """Two collections (events + feed) each with appendParams in one request."""
    app = _make_app(
        [EVENTS_COL, FEED_COL],
        {
            "rooms/room-1/events": {"items": ROOM1_ITEMS},
            "users/alice/feed": {"entries": [{"ts": 1000, "data": {"post": "hello"}}, {"ts": 2000, "data": {"post": "world"}}]},
        },
    )
    url = _batch_url(
        ["events", "feed"],
        {"events": [{"roomId": "room-1"}], "feed": [{"userId": "alice"}]},
        {"events": [{"last": 1}], "feed": [{"last": 1}]},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    body = resp.json()
    assert body["collections"]["events"][0]["data"]["items"][0]["ts"] == 500
    assert body["collections"]["feed"][0]["data"]["entries"][0]["ts"] == 2000


# ── G14: additional tests ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_float_bound_rejected_400():
    """appendParams with since=1.5 (a float) → 400 for the whole request.
    The server requires integer values for since/last/limit."""
    app = _make_app([EVENTS_COL], {"rooms/room-1/events": {"items": ROOM1_ITEMS}})
    # Build the appendParams manually to include a float — json.dumps preserves it.
    params_str = urllib.parse.quote(json.dumps({"events": [{"roomId": "room-1"}]}, separators=(",", ":")), "")
    bad_ap = urllib.parse.quote(json.dumps({"events": [{"since": 1.5}]}, separators=(",", ":")), "")
    url = f"/batch/pull?collections=events&params={params_str}&appendParams={bad_ap}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_persist_false_falls_back_to_regular_pull():
    """An append collection with persist=False + appendParams returns
    append_params_not_supported (the server treats persist=False as non-append
    for pull purposes; the collection does not store a log to slice)."""
    queue_col = CollectionConfig(
        name="queueevents",
        storagePath="rooms/{roomId}/queueevents",
        readRoles=["public"],
        writeRoles=["self"],
        encryption="none",
        maxBodyBytes=1_000_000,
        appendOnly=AppendOnlyConfig(type="by_timestamp", field="items", persist=False, allowFull=True),
    )
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        app = _make_app([queue_col], {})
    url = _batch_url(
        ["queueevents"],
        {"queueevents": [{"roomId": "room-1"}]},
        {"queueevents": [{"last": 1}]},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    assert resp.status_code == 200
    body = resp.json()
    # persist=False is treated as non-append for pull → append_params_not_supported
    assert body["collections"]["queueevents"][0]["error"] == "append_params_not_supported"


@pytest.mark.asyncio
async def test_key_deny_suffix_keyring_forbidden():
    """A collection whose resolved key ends with '_keyring' is rejected Forbidden
    per entry even when the caller's roles would normally allow access.
    The batch handler's key denylist blocks _keyring reads regardless of enricher output."""
    app = _make_app(
        [KEYRING_COL],
        {"rooms/room-1/_keyring": {"key": "data"}},
    )
    url = _batch_url(
        ["_keyring"],
        {"_keyring": [{"roomId": "room-1"}]},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    assert resp.status_code == 200
    body = resp.json()
    entry = body["collections"]["_keyring"][0]
    assert entry["error"] == "Forbidden"


@pytest.mark.asyncio
async def test_aggregate_budget_exceeded():
    """Configure maxBatchAppendElements=10. Request more than 10 total across entries → 400."""
    # EVENTS_COL has no maxPullLimit so the server uses a default of 1000 per entry.
    # Requesting last=6 per entry × 2 entries = 12 > 10 → budget exceeded.
    app = _make_app(
        [EVENTS_COL],
        {
            "rooms/room-1/events": {"items": ROOM1_ITEMS},
            "rooms/room-2/events": {"items": ROOM2_ITEMS},
        },
        max_batch_append_elements=10,
    )
    url = _batch_url(
        ["events"],
        {"events": [{"roomId": "room-1"}, {"roomId": "room-2"}]},
        {"events": [{"last": 6}, {"last": 6}]},
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get(url)
    assert resp.status_code == 400


# ── G13: conformance vector tests ─────────────────────────────────────────────

import json as _json
from pathlib import Path as _Path

_VECTOR_PATH = _Path(__file__).parents[5] / "tests/test-vectors/batch-pull-append.json"


def _make_app_from_vector(vdata: dict) -> FastAPI:
    """Build a seeded FastAPI app directly from the vector's collections+fixtures."""
    raw_cols = vdata["collections"]
    collections = []
    for rc in raw_cols:
        # Reconstruct CollectionConfig from the vector dict (aliased field names).
        ao = rc.get("appendOnly")
        col = CollectionConfig(
            name=rc["name"],
            storagePath=rc["storagePath"],
            readRoles=rc["readRoles"],
            writeRoles=rc["writeRoles"],
            encryption=rc["encryption"],
            maxBodyBytes=rc.get("maxBodyBytes", 1_000_000),
            appendOnly=AppendOnlyConfig(**ao) if ao else None,
        )
        collections.append(col)

    data: dict[str, str] = {}
    for key, val in vdata["fixtures"].items():
        data[key] = _json.dumps({"data": val, "hash": f"h-{key}", "ts": 9999})

    store = MemoryObjectStore(data=data)

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="alice", roles=[], scope_paths=None)

    router = create_sync_router(
        SyncRouterOptions(
            store=store,
            config=SyncConfig(version=1, collections=collections),
            role_resolver=role_resolver,
        )
    )
    app = FastAPI()
    app.include_router(router)
    return app


def _build_case_url(case: dict, params_by_col: dict, append_params_by_col: dict | None, raw_ap: str | None) -> str:
    col_names = ",".join(case["collections"])
    params_str = urllib.parse.quote(_json.dumps(params_by_col, separators=(",", ":")), "")
    url = f"/batch/pull?collections={col_names}&params={params_str}"
    if raw_ap is not None:
        url += f"&appendParams={urllib.parse.quote(raw_ap, '')}"
    elif append_params_by_col is not None:
        url += f"&appendParams={urllib.parse.quote(_json.dumps(append_params_by_col, separators=(',', ':')), '')}"
    return url


class TestConformanceVectors:
    def _load_vectors(self) -> dict:
        return _json.loads(_VECTOR_PATH.read_text())

    # Cases skipped in the shared-app vector run:
    # - absent_collection_entry_in_append_params_is_null: the server now enforces
    #   appendParams length equality (returns 400) rather than falling back for
    #   trailing entries. Behavior diverged after the vector was written.
    # - aggregate_budget_exceeded: requires a server configured with a low
    #   maxBatchAppendElements (e.g. 5); the shared vector app uses the default
    #   5000. Covered separately by test_aggregate_budget_exceeded above.
    _SKIP_CASES = {
        "absent_collection_entry_in_append_params_is_null",
        "aggregate_budget_exceeded",
    }

    @pytest.mark.asyncio
    async def test_vectors(self):
        vdata = self._load_vectors()
        app = _make_app_from_vector(vdata)

        for case in vdata["cases"]:
            case_id: str = case["id"]
            if case_id in self._SKIP_CASES:
                continue

            # Build the request URL
            params_by_col: dict = case.get("params", {col: [{}] for col in case["collections"]})
            append_params_by_col: dict | None = case.get("appendParams")
            raw_ap: str | None = case.get("rawAppendParams")

            url = _build_case_url(case, params_by_col, append_params_by_col, raw_ap)

            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
                resp = await c.get(url)

            # Whole-request status check
            expected_status = case.get("expectedStatus", 200)
            assert resp.status_code == expected_status, (
                f"[{case_id}] expected HTTP {expected_status}, got {resp.status_code}: {resp.text}"
            )
            if expected_status != 200:
                continue

            body = resp.json()
            expected: dict = case.get("expected", {})

            for col_name, col_expected in expected.items():
                actual_entries = body["collections"].get(col_name, [])
                assert len(actual_entries) == len(col_expected), (
                    f"[{case_id}] collection '{col_name}': expected {len(col_expected)} entries, "
                    f"got {len(actual_entries)}"
                )
                for i, (exp_entry, act_entry) in enumerate(zip(col_expected, actual_entries)):
                    outcome = exp_entry.get("outcome")
                    if outcome == "error":
                        assert "error" in act_entry, (
                            f"[{case_id}][{col_name}][{i}] expected error={exp_entry['error']!r}, got ok"
                        )
                        assert act_entry["error"] == exp_entry["error"], (
                            f"[{case_id}][{col_name}][{i}] error mismatch: "
                            f"expected {exp_entry['error']!r}, got {act_entry['error']!r}"
                        )
                    elif outcome == "ok":
                        assert "error" not in act_entry, (
                            f"[{case_id}][{col_name}][{i}] expected ok, got error={act_entry.get('error')!r}"
                        )
                        # Full-doc fallback: just check no error and data is present
                        if exp_entry.get("fullDoc"):
                            assert "data" in act_entry, (
                                f"[{case_id}][{col_name}][{i}] expected full-doc data"
                            )
                            continue
                        # Append-aware assertions
                        append_field = exp_entry.get("appendField")
                        if append_field is not None:
                            items = act_entry["data"].get(append_field, [])
                            if "count" in exp_entry:
                                assert len(items) == exp_entry["count"], (
                                    f"[{case_id}][{col_name}][{i}] count: "
                                    f"expected {exp_entry['count']}, got {len(items)}"
                                )
                            if "firstTs" in exp_entry:
                                assert items[0]["ts"] == exp_entry["firstTs"], (
                                    f"[{case_id}][{col_name}][{i}] firstTs mismatch"
                                )
                            if "lastTs" in exp_entry:
                                assert items[-1]["ts"] == exp_entry["lastTs"], (
                                    f"[{case_id}][{col_name}][{i}] lastTs mismatch"
                                )
                        # Regular field assertions
                        if "dataFields" in exp_entry:
                            for field_name, field_val in exp_entry["dataFields"].items():
                                assert act_entry["data"].get(field_name) == field_val, (
                                    f"[{case_id}][{col_name}][{i}] dataField {field_name!r} mismatch"
                                )
