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

from starfish_protocol.append_author import sign_append_author, verify_append_author
from starfish_protocol.hash import compute_hash
from starfish_server.config.schema import SyncConfig, CollectionConfig, AppendOnlyConfig
from starfish_server.config.validate import validate_config
from starfish_server.router.route_builder import (
    create_sync_router,
    SyncRouterOptions,
    AuthResult,
    Presenter,
)
from tests.helpers import MemoryObjectStore

# Fixed Ed25519 keypair used by the mechanics tests: `_build_app` advertises its
# pubkey as the request presenter and `_push` signs every element with it, so
# author proof (enforced by default) is satisfied transparently. The negative /
# enforcement cases live in their own section.
_SIGNER_PRIV = "1133557799bbddff1133557799bbddff1133557799bbddff1133557799bbddff"
_SIGNER_PUB = "062f2ba3c6a5590364b0864d539af151907d09ea0b741b0811e0d761a059bda4"


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
        return AuthResult(
            identity="user-1",
            roles=["admin"],
            presenter=Presenter(pub_hex=_SIGNER_PUB),
        )

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
    # Sign the element so the default `requireAuthorSignature` is satisfied. The
    # signature is over the element data only (independent of ts/baseHash). Skip
    # for a non-dict item — the server rejects that at the data check before
    # author verification, which is what those tests assert.
    if isinstance(item, dict):
        signed = sign_append_author("events", item, _SIGNER_PUB, _SIGNER_PRIV)
        body.update(signed)
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
        resp = await client.get("/pull/events?full=true")
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
        resp = await client.get("/pull/events?full=true")
    assert resp.status_code == 200
    assert _payloads(resp.json()["data"]["items"]) == [{"n": 1}, {"n": 2}, {"n": 3}]


@pytest.mark.asyncio
async def test_custom_append_field():
    col = _make_col(appendOnly=_append_only(field="logs"))
    app, _ = _build_app(col)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _push(client, {"msg": "entry"})
        resp = await client.get("/pull/events?full=true")
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
        pulled = await client.get("/pull/events?full=true")
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


# --- pull bounding (limit / full / required bound) ---

async def _seed5(client: AsyncClient):
    for n in range(1, 6):
        await _push(client, {"n": n}, ts=n * 10)


@pytest.mark.asyncio
async def test_unbounded_pull_rejected():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _seed5(client)
        resp = await client.get("/pull/events")
    assert resp.status_code == 400
    assert resp.json()["error"] == "pull_bound_required"


@pytest.mark.asyncio
async def test_each_bound_accepted_individually():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _seed5(client)
        for q in ("checkpoint=0", "limit=2", "last=2", "full=true"):
            assert (await client.get(f"/pull/events?{q}")).status_code == 200


@pytest.mark.asyncio
async def test_limit_is_alias_of_last():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _seed5(client)
        by_limit = (await client.get("/pull/events?limit=2")).json()
        by_last = (await client.get("/pull/events?last=2")).json()
    assert by_limit["data"]["items"] == by_last["data"]["items"]
    assert _payloads(by_limit["data"]["items"]) == [{"n": 4}, {"n": 5}]


@pytest.mark.asyncio
async def test_limit_wins_over_last_when_both_given():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _seed5(client)
        body = (await client.get("/pull/events?limit=1&last=4")).json()
    assert _payloads(body["data"]["items"]) == [{"n": 5}]


@pytest.mark.asyncio
async def test_limit_boundaries():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _seed5(client)
        assert (await client.get("/pull/events?limit=0")).json()["data"]["items"] == []
        assert len((await client.get("/pull/events?limit=100")).json()["data"]["items"]) == 5


@pytest.mark.asyncio
async def test_full_with_bounds_rejected():
    app, _ = _build_app(_make_col())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _seed5(client)
        for q in ("full=true&checkpoint=0", "full=true&limit=2", "full=true&last=2"):
            resp = await client.get(f"/pull/events?{q}")
            assert resp.status_code == 400
            assert resp.json()["error"] == "full_with_bounds"


@pytest.mark.asyncio
async def test_full_not_allowed_when_allow_full_false():
    app, _ = _build_app(_make_col(appendOnly=_append_only(allowFull=False)))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _seed5(client)
        resp = await client.get("/pull/events?full=true")
        assert resp.status_code == 400
        assert resp.json()["error"] == "full_not_allowed"
        assert (await client.get("/pull/events?limit=2")).status_code == 200


@pytest.mark.asyncio
async def test_limit_clamped_to_max_pull_limit():
    app, _ = _build_app(_make_col(appendOnly=_append_only(maxPullLimit=2)))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _seed5(client)
        body = (await client.get("/pull/events?limit=100")).json()
    assert _payloads(body["data"]["items"]) == [{"n": 4}, {"n": 5}]


@pytest.mark.asyncio
async def test_checkpoint_too_old_rejected():
    app, _ = _build_app(_make_col(appendOnly=_append_only(maxCheckpointAgeMs=60_000)))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        await _seed5(client)
        old = await client.get("/pull/events?checkpoint=10")
        assert old.status_code == 400
        assert old.json()["error"] == "checkpoint_too_old"
        recent = await client.get(f"/pull/events?checkpoint={int(time.time() * 1000) - 1000}")
        assert recent.status_code == 200


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
        body = await client.get("/pull/events?full=true")
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
        resp = await client.get("/pull/events?full=true")
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


@pytest.mark.parametrize("bad", [
    {"maxPullLimit": 0},
    {"maxPullLimit": -1},
    {"maxCheckpointAgeMs": 0},
])
def test_non_positive_pull_bounds_rejected(bad):
    col = _make_col(appendOnly=_append_only(**bad))
    errors = validate_config(SyncConfig(version=1, collections=[col]))
    assert any("positive integer" in e for e in errors)


def test_pull_bounds_require_persist_true():
    col = _make_col(appendOnly=_append_only(persist=False, maxPullLimit=10, maxCheckpointAgeMs=1000))
    errors = validate_config(SyncConfig(version=1, collections=[col]))
    assert any("maxPullLimit requires persist=true" in e for e in errors)
    assert any("maxCheckpointAgeMs requires persist=true" in e for e in errors)


def test_valid_pull_bounds_config_passes():
    col = _make_col(appendOnly=_append_only(allowFull=False, maxPullLimit=100, maxCheckpointAgeMs=86_400_000))
    errors = validate_config(SyncConfig(version=1, collections=[col]))
    assert errors == []


# ─── Author proof (requireAuthorSignature, default on) ──────────────────────────
# An unrelated keypair for the impersonation case (valid signature, but by a key
# that is NOT the request presenter).
_OTHER_PRIV = "99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa"
_OTHER_PUB = "01e3bf84a66206793b37113dfa7c682573d748d93f7328d76375cde6f11a622f"


def _build_author_app(presenter_pub: str | None = _SIGNER_PUB):
    """An app whose resolver advertises ``presenter_pub`` as the verified request
    presenter. Author proof is enforced by default (the col carries no opt-out)."""
    store = MemoryObjectStore()
    config = SyncConfig(version=1, collections=[_make_col()])

    async def role_resolver(request: Request) -> AuthResult:
        presenter = (
            Presenter(pub_hex=_SIGNER_PUB) if presenter_pub else None
        )
        return AuthResult(identity="user-1", roles=["admin"], presenter=presenter)

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver),
    )
    app = FastAPI()
    app.include_router(router)
    return app, store


@pytest.fixture
async def author_client():
    app, store = _build_author_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c, store


async def test_accepts_signed_append_and_stores_author(author_client):
    client, _ = author_client
    item = {"msg": "signed hello"}
    signed = sign_append_author("events", item, _SIGNER_PUB, _SIGNER_PRIV)
    res = await client.post("/push/events", json={"data": item, **signed})
    assert res.status_code == 200

    pulled = (await client.get("/pull/events?full=true")).json()
    el = pulled["data"]["items"][0]
    assert el["authorPubkey"] == _SIGNER_PUB
    # The stored proof re-verifies against the stored element data.
    assert verify_append_author("events", el["data"], el["authorPubkey"], el["authorSignature"]) is True


async def test_rejects_append_with_no_author_proof(author_client):
    client, _ = author_client
    res = await client.post("/push/events", json={"data": {"msg": "x"}})
    assert res.status_code == 400


async def test_rejects_author_not_request_presenter_impersonation():
    # Validly signed by OTHER, but the presenter is SIGNER → impersonation attempt.
    app, _ = _build_author_app(presenter_pub=_SIGNER_PUB)
    item = {"msg": "i am the presenter, honest"}
    signed = sign_append_author("events", item, _OTHER_PUB, _OTHER_PRIV)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        res = await client.post("/push/events", json={"data": item, **signed})
    assert res.status_code == 403


async def test_rejects_tampered_signature(author_client):
    client, _ = author_client
    item = {"msg": "tamper me"}
    signed = sign_append_author("events", item, _SIGNER_PUB, _SIGNER_PRIV)
    sig = signed["authorSignature"]
    bad = ("B" if sig[0] == "A" else "A") + sig[1:]
    res = await client.post(
        "/push/events",
        json={"data": item, "authorPubkey": _SIGNER_PUB, "authorSignature": bad},
    )
    assert res.status_code == 403


async def test_rejects_signature_over_different_data(author_client):
    client, _ = author_client
    # Sign one object, send another → the server verifies over the sent item.
    signed = sign_append_author("events", {"msg": "original"}, _SIGNER_PUB, _SIGNER_PRIV)
    res = await client.post("/push/events", json={"data": {"msg": "swapped"}, **signed})
    assert res.status_code == 403


async def test_opt_out_collection_accepts_unsigned_append():
    store = MemoryObjectStore()
    col = _make_col(appendOnly=_append_only(requireAuthorSignature=False))
    config = SyncConfig(version=1, collections=[col])

    async def role_resolver(request: Request) -> AuthResult:
        return AuthResult(identity="user-1", roles=["admin"])

    router = create_sync_router(
        SyncRouterOptions(store=store, config=config, role_resolver=role_resolver),
    )
    app = FastAPI()
    app.include_router(router)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        res = await client.post("/push/events", json={"data": {"msg": "no sig needed"}})
    assert res.status_code == 200
