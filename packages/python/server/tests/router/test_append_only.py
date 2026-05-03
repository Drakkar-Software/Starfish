"""Router integration tests for appendOnly+persist=true collections."""

import pytest
from fastapi import FastAPI, Request
from httpx import AsyncClient, ASGITransport

from starfish_protocol.hash import compute_hash
from starfish_server.config.schema import SyncConfig, CollectionConfig, AppendOnlyConfig
from starfish_server.config.validate import validate_config
from starfish_server.router.route_builder import create_sync_router, SyncRouterOptions, AuthResult
from tests.helpers import MemoryObjectStore


def _make_col(**overrides) -> CollectionConfig:
    defaults = dict(
        name="events",
        storagePath="events",
        readRoles=["admin"],
        writeRoles=["admin"],
        encryption="none",
        maxBodyBytes=65536,
        appendOnly=AppendOnlyConfig(),
    )
    defaults.update(overrides)
    return CollectionConfig(**defaults)


def _build_app(col: CollectionConfig, signature_verifier=None):
    store = MemoryObjectStore()
    config = SyncConfig(version=1, collections=[col])

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["admin"])

    router = create_sync_router(
        SyncRouterOptions(
            store=store,
            config=config,
            role_resolver=role_resolver,
            signature_verifier=signature_verifier,
        ),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


@pytest.mark.asyncio
async def test_first_push_creates_array():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/push/events", json={"data": {"msg": "hello"}, "baseHash": None})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_two_sequential_pushes_array_has_2_items():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/push/events", json={"data": {"msg": "first"}, "baseHash": None})
        await client.post("/push/events", json={"data": {"msg": "second"}, "baseHash": None})
        resp = await client.get("/pull/events")
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["items"] == [{"msg": "first"}, {"msg": "second"}]


@pytest.mark.asyncio
async def test_base_hash_ignored_no_409():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/push/events", json={"data": {"msg": "first"}, "baseHash": None})
        resp = await client.post("/push/events", json={"data": {"msg": "second"}, "baseHash": "wrong-hash"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_pull_returns_stored_array():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for i in range(1, 4):
            await client.post("/push/events", json={"data": {"n": i}, "baseHash": None})
        resp = await client.get("/pull/events")
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["items"] == [{"n": 1}, {"n": 2}, {"n": 3}]


@pytest.mark.asyncio
async def test_custom_append_field():
    col = _make_col(appendOnly=AppendOnlyConfig(field="logs"))
    app, _ = _build_app(col)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/push/events", json={"data": {"msg": "entry"}, "baseHash": None})
        resp = await client.get("/pull/events")
    body = resp.json()
    assert body["data"]["logs"] == [{"msg": "entry"}]
    assert "items" not in body["data"]


@pytest.mark.asyncio
async def test_signature_verifier_bypassed_for_append_only():
    async def always_reject(canonical, sig, identity):
        return False

    app, _ = _build_app(_make_col(), signature_verifier=always_reject)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/push/events", json={"data": {"msg": "unsigned"}, "baseHash": None})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_push_hash_is_length_tagged():
    app, _ = _build_app(_make_col())
    item = {"msg": "hello"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/push/events", json={"data": item, "baseHash": None})
    assert resp.status_code == 200
    expected = compute_hash({"n": 1, "last": item})
    assert resp.json()["hash"] == expected


@pytest.mark.asyncio
async def test_duplicate_item_produces_different_hash():
    app, _ = _build_app(_make_col())
    item = {"msg": "same"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r1 = await client.post("/push/events", json={"data": item, "baseHash": None})
        r2 = await client.post("/push/events", json={"data": item, "baseHash": None})
    assert r1.json()["hash"] != r2.json()["hash"]


@pytest.mark.asyncio
async def test_checkpoint_zero_returns_full_array():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for n in (1, 2, 3):
            await client.post("/push/events", json={"data": {"n": n}, "baseHash": None})
        resp = await client.get("/pull/events?checkpoint=0")
    assert resp.status_code == 200
    assert resp.json()["data"]["items"] == [{"n": 1}, {"n": 2}, {"n": 3}]


@pytest.mark.asyncio
async def test_checkpoint_after_second_push_returns_only_third():
    import asyncio
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/push/events", json={"data": {"n": 1}, "baseHash": None})
        await client.post("/push/events", json={"data": {"n": 2}, "baseHash": None})
        import time
        after_two = int(time.time() * 1000)
        await asyncio.sleep(0.002)
        await client.post("/push/events", json={"data": {"n": 3}, "baseHash": None})
        resp = await client.get(f"/pull/events?checkpoint={after_two}")
    assert resp.status_code == 200
    assert resp.json()["data"]["items"] == [{"n": 3}]


@pytest.mark.asyncio
async def test_check_last_item_matching_hash_accepted():
    col = _make_col(appendOnly=AppendOnlyConfig(check_last_item=True))
    app, _ = _build_app(col)
    item = {"msg": "first"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/push/events", json={"data": item, "baseHash": ""})
        # Pull to get stored hash (length-tagged), use as baseHash
        pull_body = (await client.get("/pull/events")).json()
        stored_hash = pull_body["hash"]
        resp = await client.post("/push/events", json={"data": {"msg": "second"}, "baseHash": stored_hash})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_check_last_item_stale_hash_409():
    col = _make_col(appendOnly=AppendOnlyConfig(check_last_item=True))
    app, _ = _build_app(col)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/push/events", json={"data": {"msg": "first"}, "baseHash": ""})
        resp = await client.post("/push/events", json={"data": {"msg": "second"}, "baseHash": "stale"})
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_check_last_item_empty_store_empty_hash_accepted():
    col = _make_col(appendOnly=AppendOnlyConfig(check_last_item=True))
    app, _ = _build_app(col)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/push/events", json={"data": {"msg": "first"}, "baseHash": ""})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_check_last_item_empty_store_non_empty_hash_409():
    col = _make_col(appendOnly=AppendOnlyConfig(check_last_item=True))
    app, _ = _build_app(col)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post("/push/events", json={"data": {"msg": "first"}, "baseHash": "wrong"})
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_check_last_item_concurrent_same_base_hash_one_wins():
    # Both pushes believe the store is empty (baseHash=""). Under the old pre-loop
    # check_last_item_conflict, the second push's retry would slip through because the
    # pre-loop check already passed. With the inlined check, every attempt re-reads
    # the stored hash, so the loser deterministically gets 409.
    import asyncio
    col = _make_col(appendOnly=AppendOnlyConfig(check_last_item=True))
    app, _ = _build_app(col)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        r1, r2 = await asyncio.gather(
            client.post("/push/events", json={"data": {"n": 1}, "baseHash": ""}),
            client.post("/push/events", json={"data": {"n": 2}, "baseHash": ""}),
        )
    statuses = sorted([r1.status_code, r2.status_code])
    assert statuses == [200, 409]


@pytest.mark.asyncio
async def test_last_param_returns_last_k_items():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for i in range(1, 4):
            await client.post("/push/events", json={"data": {"n": i}, "baseHash": None})
        resp = await client.get("/pull/events?last=2")
    assert resp.status_code == 200
    assert resp.json()["data"]["items"] == [{"n": 2}, {"n": 3}]


@pytest.mark.asyncio
async def test_last_zero_returns_empty_array():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/push/events", json={"data": {"n": 1}, "baseHash": None})
        resp = await client.get("/pull/events?last=0")
    assert resp.json()["data"]["items"] == []


@pytest.mark.asyncio
async def test_last_larger_than_array_returns_full():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/push/events", json={"data": {"n": 1}, "baseHash": None})
        await client.post("/push/events", json={"data": {"n": 2}, "baseHash": None})
        resp = await client.get("/pull/events?last=100")
    assert resp.json()["data"]["items"] == [{"n": 1}, {"n": 2}]


@pytest.mark.asyncio
async def test_last_combined_with_checkpoint():
    import asyncio
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await client.post("/push/events", json={"data": {"n": 1}, "baseHash": None})
        await client.post("/push/events", json={"data": {"n": 2}, "baseHash": None})
        import time
        after2 = int(time.time() * 1000)
        await asyncio.sleep(0.002)
        for i in range(3, 6):
            await client.post("/push/events", json={"data": {"n": i}, "baseHash": None})
        # checkpoint filters to [3,4,5]; last=2 → [4,5]
        resp = await client.get(f"/pull/events?checkpoint={after2}&last=2")
    assert resp.json()["data"]["items"] == [{"n": 4}, {"n": 5}]


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
    app, _ = _build_app(_make_col(appendOnly=AppendOnlyConfig(field="logs")))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        for msg in ["a", "b", "c"]:
            await client.post("/push/events", json={"data": {"msg": msg}, "baseHash": None})
        resp = await client.get("/pull/events?last=1")
    assert resp.json()["data"]["logs"] == [{"msg": "c"}]


def test_valid_append_only_config_passes():
    errors = validate_config(SyncConfig(version=1, collections=[_make_col()]))
    assert errors == []


def test_append_only_with_client_encrypted_rejected():
    col = _make_col(client_encrypted=True)
    errors = validate_config(SyncConfig(version=1, collections=[col]))
    assert any("clientEncrypted" in e for e in errors)


def test_append_only_with_delegated_encryption_rejected():
    col = _make_col(encryption="delegated")
    errors = validate_config(SyncConfig(version=1, collections=[col]))
    assert any("delegated" in e for e in errors)


def test_append_only_with_bundle_rejected():
    col = _make_col(bundle="myBundle", storagePath="events/{identity}", encryption="identity")
    errors = validate_config(SyncConfig(version=1, collections=[col]))
    assert any("bundle" in e for e in errors)
