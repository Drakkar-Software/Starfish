"""Router integration tests for appendOnly+persist=true collections.

Mirrors the TS router/append-only.test.ts: each element is stored as a
``{ts, data}`` envelope, there is no hash/conflict check (a stale baseHash is
accepted), client-supplied timestamps must be strictly monotonic, checkpoint
filters by element ts, and delegated encryption is now supported.
"""

import asyncio
import json
import time

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_protocol.hash import compute_hash
from starfish_server.config.schema import SyncConfig, CollectionConfig, AppendOnlyConfig
from starfish_server.config.validate import validate_config
from starfish_server.router.route_builder import create_sync_router, SyncRouterOptions, AuthResult
from tests.helpers import MemoryObjectStore


def _append_only(**kwargs) -> AppendOnlyConfig:
    kwargs.setdefault("type", "by_timestamp")
    return AppendOnlyConfig(**kwargs)


def _make_col(**overrides) -> CollectionConfig:
    defaults = dict(
        name="events",
        storagePath="events",
        readRoles=["admin"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
        appendOnly=_append_only(),
    )
    defaults.update(overrides)
    return CollectionConfig(**defaults)


def _build_app(col: CollectionConfig):
    store = MemoryObjectStore()
    config = SyncConfig(version=1, collections=[col])

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["admin"])

    router = create_sync_router(
        SyncRouterOptions(
            store=store,
            config=config,
            role_resolver=role_resolver,
        ),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


async def _push(client: AsyncClient, item, *, base_hash=..., ts=None):
    """POST an append. `base_hash` defaults to omitted; pass explicitly to send one."""
    body: dict = {"data": item}
    if base_hash is not ...:
        body["baseHash"] = base_hash
    if ts is not None:
        body["ts"] = ts
    return await client.post("/push/events", json=body)


def _payloads(arr):
    """Extract element payloads, dropping the `{ts}` envelope."""
    return [el["data"] for el in arr]


# --- basic stored {ts, data} array semantics ---

@pytest.mark.asyncio
async def test_first_push_creates_array():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, {"msg": "hello"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_two_sequential_pushes_array_has_2_items():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, {"msg": "first"})
        await _push(client, {"msg": "second"})
        resp = await client.get("/pull/events")
    assert resp.status_code == 200
    items = resp.json()["data"]["items"]
    assert _payloads(items) == [{"msg": "first"}, {"msg": "second"}]
    for el in items:
        assert isinstance(el["ts"], int)
    assert items[1]["ts"] > items[0]["ts"]


@pytest.mark.asyncio
async def test_base_hash_ignored_no_409():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, {"msg": "first"})
        resp = await _push(client, {"msg": "second"}, base_hash="wrong-hash-doesnt-matter")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_pull_returns_stored_array():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for i in range(1, 4):
            await _push(client, {"n": i})
        resp = await client.get("/pull/events")
    assert resp.status_code == 200
    assert _payloads(resp.json()["data"]["items"]) == [{"n": 1}, {"n": 2}, {"n": 3}]


@pytest.mark.asyncio
async def test_custom_append_field():
    col = _make_col(appendOnly=_append_only(field="logs"))
    app, _ = _build_app(col)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, {"msg": "entry"})
        resp = await client.get("/pull/events")
    body = resp.json()
    assert _payloads(body["data"]["logs"]) == [{"msg": "entry"}]
    assert "items" not in body["data"]


# --- client-supplied timestamps ---

@pytest.mark.asyncio
async def test_provided_ts_stored_verbatim_and_returned():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, {"n": 1}, ts=1000)
        assert resp.json()["timestamp"] == 1000
        pulled = await client.get("/pull/events")
    assert pulled.json()["data"]["items"][0]["ts"] == 1000


@pytest.mark.asyncio
async def test_provided_ts_equal_latest_409():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, {"n": 1}, ts=1000)
        resp = await _push(client, {"n": 2}, ts=1000)
    assert resp.status_code == 409
    body = resp.json()
    assert body["error"] == "non_monotonic_timestamp"
    # 409 must not leak the latest element's ts to a write-only credential.
    assert "latest" not in body


@pytest.mark.asyncio
async def test_provided_ts_less_than_latest_409():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, {"n": 1}, ts=1000)
        resp = await _push(client, {"n": 2}, ts=500)
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_provided_ts_greater_than_latest_accepted():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, {"n": 1}, ts=1000)
        resp = await _push(client, {"n": 2}, ts=2000)
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_non_integer_ts_400():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, {"n": 1}, ts=1.5)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_ts_too_far_in_future_400():
    app, _ = _build_app(_make_col())
    now_ms = int(time.time_ns() // 1_000_000)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, {"n": 1}, ts=now_ms + 3_600_000)  # +1h ≫ 5m skew
    assert resp.status_code == 400
    assert "future" in resp.json()["error"]


@pytest.mark.asyncio
async def test_ts_within_future_skew_accepted():
    app, _ = _build_app(_make_col())
    now_ms = int(time.time_ns() // 1_000_000)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, {"n": 1}, ts=now_ms + 60_000)  # +1m < 5m skew
    assert resp.status_code == 200


# --- stored hash semantics (length-tagged) ---

@pytest.mark.asyncio
async def test_push_hash_is_length_tagged():
    app, _ = _build_app(_make_col())
    item = {"msg": "hello"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, item)
    assert resp.status_code == 200
    assert resp.json()["hash"] == compute_hash({"n": 1, "last": item})


@pytest.mark.asyncio
async def test_duplicate_item_produces_different_hash():
    app, _ = _build_app(_make_col())
    item = {"msg": "same"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r1 = await _push(client, item)
        r2 = await _push(client, item)
    assert r1.json()["hash"] != r2.json()["hash"]


# --- checkpoint pull ---

@pytest.mark.asyncio
async def test_checkpoint_zero_returns_full_array():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for n in (1, 2, 3):
            await _push(client, {"n": n})
        resp = await client.get("/pull/events?checkpoint=0")
    assert resp.status_code == 200
    assert _payloads(resp.json()["data"]["items"]) == [{"n": 1}, {"n": 2}, {"n": 3}]


@pytest.mark.asyncio
async def test_checkpoint_after_second_push_returns_only_third():
    # Explicit timestamps keep this deterministic — auto-ts uses max(now, latest+1),
    # so back-to-back appends in the same millisecond can bump past a wall-clock
    # checkpoint captured between them (mirrors the TS router/append-only test).
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, {"n": 1}, ts=100)
        await _push(client, {"n": 2}, ts=200)
        await _push(client, {"n": 3}, ts=300)
        resp = await client.get("/pull/events?checkpoint=200")
    assert resp.status_code == 200
    assert _payloads(resp.json()["data"]["items"]) == [{"n": 3}]


@pytest.mark.asyncio
async def test_checkpoint_after_all_pushes_returns_empty():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, {"n": 1})
        await _push(client, {"n": 2})
        after = int(time.time() * 1000) + 1000
        resp = await client.get(f"/pull/events?checkpoint={after}")
    assert resp.json()["data"]["items"] == []


@pytest.mark.asyncio
async def test_checkpoint_works_with_client_supplied_timestamps():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, {"n": 1}, ts=100)
        await _push(client, {"n": 2}, ts=200)
        await _push(client, {"n": 3}, ts=300)
        resp = await client.get("/pull/events?checkpoint=150")
    assert _payloads(resp.json()["data"]["items"]) == [{"n": 2}, {"n": 3}]


# --- ?last=K pull ---

@pytest.mark.asyncio
async def test_last_param_returns_last_k_items():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for i in range(1, 4):
            await _push(client, {"n": i})
        resp = await client.get("/pull/events?last=2")
    assert resp.status_code == 200
    assert _payloads(resp.json()["data"]["items"]) == [{"n": 2}, {"n": 3}]


@pytest.mark.asyncio
async def test_last_zero_returns_empty_array():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, {"n": 1})
        resp = await client.get("/pull/events?last=0")
    assert resp.json()["data"]["items"] == []


@pytest.mark.asyncio
async def test_last_larger_than_array_returns_full():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, {"n": 1})
        await _push(client, {"n": 2})
        resp = await client.get("/pull/events?last=100")
    assert _payloads(resp.json()["data"]["items"]) == [{"n": 1}, {"n": 2}]


@pytest.mark.asyncio
async def test_last_combined_with_checkpoint():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, {"n": 1}, ts=10)
        await _push(client, {"n": 2}, ts=20)
        await _push(client, {"n": 3}, ts=30)
        await _push(client, {"n": 4}, ts=40)
        await _push(client, {"n": 5}, ts=50)
        # checkpoint filters to [3,4,5]; last=2 → [4,5]
        resp = await client.get("/pull/events?checkpoint=20&last=2")
    assert _payloads(resp.json()["data"]["items"]) == [{"n": 4}, {"n": 5}]


@pytest.mark.asyncio
async def test_last_no_pushes_returns_empty():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/events?last=5")
    assert resp.json()["data"]["items"] == []


@pytest.mark.asyncio
async def test_last_invalid_returns_400():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/events?last=abc")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_last_negative_returns_400():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/pull/events?last=-1")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_last_respects_custom_field():
    app, _ = _build_app(_make_col(appendOnly=_append_only(field="logs")))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for msg in ["a", "b", "c"]:
            await _push(client, {"msg": msg})
        resp = await client.get("/pull/events?last=1")
    assert _payloads(resp.json()["data"]["logs"]) == [{"msg": "c"}]


# --- delegated encryption (real keyring round-trip) ---

def _make_encryptor():
    """Build a real per-collection keyring + encryptor (not a stub), so the tests
    prove encrypt -> push -> store-opaque -> pull -> decrypt works end-to-end and
    the server filters by the plaintext `ts` without reading the ciphertext."""
    import json
    import pathlib
    from starfish_keyring import create_keyring, create_keyring_encryptor

    fixtures = json.loads(
        (pathlib.Path(__file__).parents[5]
         / "tests" / "test-vectors" / "multi-recipient-wrap.json").read_text()
    )["fixtures"]
    adder = fixtures["alice_root"]
    dev = fixtures["alice_dev_1"]
    keyring, _ = create_keyring(adder["edPriv"], adder["edPub"], [dev["kemPub"]])
    return create_keyring_encryptor(
        keyring, dev["kemPub"], dev["kemPriv"], trusted_adders=[adder["edPub"]]
    )


@pytest.mark.asyncio
async def test_delegated_real_keyring_round_trip():
    app, _ = _build_app(_make_col(encryption="delegated"))
    enc = _make_encryptor()
    sealed = enc.encrypt({"secret": "alpha", "n": 1})
    assert isinstance(sealed["_encrypted"], str)  # real ciphertext, not plaintext
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await _push(client, sealed)
        assert resp.status_code == 200
        body = await client.get("/pull/events")
    stored_el = body.json()["data"]["items"][0]
    assert isinstance(stored_el["ts"], int)
    # The server stored ciphertext opaquely — the plaintext is NOT visible.
    assert "alpha" not in json.dumps(stored_el["data"])
    assert enc.decrypt(stored_el["data"]) == {"secret": "alpha", "n": 1}


@pytest.mark.asyncio
async def test_delegated_checkpoint_filters_encrypted_elements_by_ts():
    app, _ = _build_app(_make_col(encryption="delegated"))
    enc = _make_encryptor()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, enc.encrypt({"secret": "one"}), ts=100)
        await _push(client, enc.encrypt({"secret": "two"}), ts=200)
        resp = await client.get("/pull/events?checkpoint=150")
    items = resp.json()["data"]["items"]
    assert len(items) == 1 and items[0]["ts"] == 200
    assert enc.decrypt(items[0]["data"]) == {"secret": "two"}


# --- concurrency (no hash check) ---

@pytest.mark.asyncio
async def test_concurrent_pushes_both_land():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r1, r2 = await asyncio.gather(
            _push(client, {"n": 1}),
            _push(client, {"n": 2}),
        )
        resp = await client.get("/pull/events")
    assert [r1.status_code, r2.status_code] == [200, 200]
    items = resp.json()["data"]["items"]
    assert len(items) == 2
    assert items[1]["ts"] > items[0]["ts"]


# --- config validation ---

def test_valid_append_only_config_passes():
    errors = validate_config(SyncConfig(version=1, collections=[_make_col()]))
    assert errors == []


def test_append_only_with_delegated_encryption_now_accepted():
    col = _make_col(encryption="delegated")
    errors = validate_config(SyncConfig(version=1, collections=[col]))
    assert errors == []


def test_unknown_append_only_type_rejected():
    col = _make_col(appendOnly=AppendOnlyConfig(type="by_sequence"))
    errors = validate_config(SyncConfig(version=1, collections=[col]))
    assert any("by_sequence" in e or "not supported" in e for e in errors)


def test_append_only_with_bundle_rejected():
    col = _make_col(bundle="myBundle", storagePath="events/{identity}", encryption="none")
    errors = validate_config(SyncConfig(version=1, collections=[col]))
    assert any("bundle" in e for e in errors)
