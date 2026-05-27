"""Tests for the AppendLogCursor incremental append-only reader."""

import json
from typing import Any

import httpx
import pytest
import respx

from starfish_protocol.append_author import sign_append_author
from starfish_sdk.append_log import AppendAuthorError, AppendLogCursor, checkpoint_of
from starfish_sdk.client import StarfishClient

BASE = "https://api.example.com/v1"


def _json_resp(data: object) -> httpx.Response:
    return httpx.Response(200, json={"data": data, "hash": "h1", "timestamp": 0})


# --- cold start ---


@pytest.mark.asyncio
async def test_cold_start_no_checkpoint_returns_all():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(
            return_value=_json_resp({"items": [{"ts": 1, "data": {"a": 1}}, {"ts": 2, "data": {"b": 2}}]})
        )
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events")
            batch = await log.pull()
        assert "checkpoint" not in str(mock.calls[0].request.url)
    assert batch == [{"ts": 1, "data": {"a": 1}}, {"ts": 2, "data": {"b": 2}}]
    assert log.items == batch
    assert log.checkpoint == 2


@pytest.mark.asyncio
async def test_cold_start_empty_keeps_checkpoint_zero():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": []}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events")
            assert await log.pull() == []
    assert log.checkpoint == 0


@pytest.mark.asyncio
async def test_keeps_ts_zero_first_element_and_does_not_redeliver():
    # since=0 means "no server filter", so the defensive skip must NOT drop ts=0.
    items = [{"ts": 0, "data": {"a": 1}}, {"ts": 1, "data": {"b": 2}}]
    with respx.mock(base_url="https://api.example.com") as mock:
        # First pull (cold) returns both; second pull (?checkpoint=1) echoes them.
        mock.get("/v1/pull/events").mock(side_effect=[_json_resp({"items": items}), _json_resp({"items": items})])
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events")
            first = await log.pull()
            assert first == items
            assert log.checkpoint == 1
            # since=1 > 0 → defensive filter active → echoed items dropped.
            assert await log.pull() == []
    assert len(log.items) == 2


# --- warm start ---


@pytest.mark.asyncio
async def test_warm_start_from_initial_items():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": [{"ts": 300, "data": {"c": 3}}]}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(
                client,
                "/pull/events",
                initial_items=[{"ts": 100, "data": {"a": 1}}, {"ts": 200, "data": {"b": 2}}],
            )
            assert log.checkpoint == 200
            batch = await log.pull()
        assert "checkpoint=200" in str(mock.calls[0].request.url)
    assert batch == [{"ts": 300, "data": {"c": 3}}]
    assert log.items == [
        {"ts": 100, "data": {"a": 1}},
        {"ts": 200, "data": {"b": 2}},
        {"ts": 300, "data": {"c": 3}},
    ]
    assert log.checkpoint == 300


@pytest.mark.asyncio
async def test_warm_start_from_since_only():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": [{"ts": 250, "data": {"c": 3}}]}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events", since=200)
            batch = await log.pull()
        assert "checkpoint=200" in str(mock.calls[0].request.url)
    assert batch == [{"ts": 250, "data": {"c": 3}}]
    assert log.items == [{"ts": 250, "data": {"c": 3}}]


@pytest.mark.asyncio
async def test_no_new_items_keeps_checkpoint():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": []}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events", since=200)
            assert await log.pull() == []
    assert log.checkpoint == 200
    assert log.items == []


@pytest.mark.asyncio
async def test_defensively_skips_already_held_ts():
    # Server wrongly returns an already-held element (ts=150) plus a new one (ts=250).
    items = [{"ts": 150, "data": {"a": 1}}, {"ts": 250, "data": {"b": 2}}]
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": items}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events", since=200)
            batch = await log.pull()
    assert batch == [{"ts": 250, "data": {"b": 2}}]
    assert log.items == [{"ts": 250, "data": {"b": 2}}]
    assert log.checkpoint == 250


@pytest.mark.asyncio
async def test_custom_append_field():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"logs": [{"ts": 1, "data": {"x": 1}}]}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events", append_field="logs")
            assert await log.pull() == [{"ts": 1, "data": {"x": 1}}]
    assert log.checkpoint == 1


# --- checkpoint advances ---


@pytest.mark.asyncio
async def test_checkpoint_advances_across_pulls():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(
            side_effect=[
                _json_resp({"items": [{"ts": 1, "data": {"a": 1}}, {"ts": 2, "data": {"b": 2}}]}),
                _json_resp({"items": [{"ts": 3, "data": {"c": 3}}]}),
            ]
        )
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events")
            await log.pull()
            second = await log.pull()
        assert "checkpoint" not in str(mock.calls[0].request.url)
        assert "checkpoint=2" in str(mock.calls[1].request.url)
    assert second == [{"ts": 3, "data": {"c": 3}}]
    assert log.checkpoint == 3
    assert len(log.items) == 3


@pytest.mark.asyncio
async def test_set_checkpoint_restores_position():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": [{"ts": 99, "data": {"z": 1}}]}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events")
            log.set_checkpoint(50)
            await log.pull()
        assert "checkpoint=50" in str(mock.calls[0].request.url)


# --- encryption ---


class _Encryptor:
    def encrypt(self, data: dict[str, Any]) -> dict[str, Any]:
        return {"_encrypted": json.dumps(data)}

    def decrypt(self, wrapper: dict[str, Any]) -> dict[str, Any]:
        return json.loads(wrapper["_encrypted"])


@pytest.mark.asyncio
async def test_decrypts_each_element_preserving_ts_and_author():
    items = [
        {"ts": 1, "data": {"_encrypted": json.dumps({"msg": "a"})}},
        {"ts": 2, "data": {"_encrypted": json.dumps({"msg": "b"})}, "authorPubkey": "ab"},
    ]
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": items}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events", encryptor=_Encryptor())
            batch = await log.pull()
    assert batch == [
        {"ts": 1, "data": {"msg": "a"}},
        {"ts": 2, "data": {"msg": "b"}, "authorPubkey": "ab"},
    ]
    assert log.checkpoint == 2


class _FailingEncryptor:
    def encrypt(self, data: dict[str, Any]) -> dict[str, Any]:
        return data

    def decrypt(self, wrapper: dict[str, Any]) -> dict[str, Any]:
        if wrapper.get("bad"):
            raise ValueError("bad key")
        return wrapper


@pytest.mark.asyncio
async def test_decrypt_failure_is_atomic():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(
            return_value=_json_resp({"items": [{"ts": 1, "data": {"ok": True}}, {"ts": 2, "data": {"bad": True}}]})
        )
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events", encryptor=_FailingEncryptor())
            with pytest.raises(ValueError, match="bad key"):
                await log.pull()
    assert log.items == []
    assert log.checkpoint == 0


# --- author verification ---

# A real Ed25519 keypair so the emitted signature actually verifies.
_KP_PRIV = "1133557799bbddff1133557799bbddff1133557799bbddff1133557799bbddff"
_KP_PUB = "062f2ba3c6a5590364b0864d539af151907d09ea0b741b0811e0d761a059bda4"


def _signed_element(ts: int, data: dict[str, Any]) -> dict[str, Any]:
    author = sign_append_author("events", data, _KP_PUB, _KP_PRIV, "ed25519")
    return {"ts": ts, "data": data, **author}


@pytest.mark.asyncio
async def test_author_verify_passes_for_valid_signatures():
    items = [_signed_element(1, {"msg": "a"}), _signed_element(2, {"msg": "b"})]
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": items}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(
                client,
                "/pull/events",
                verify_author={"expected_author_pubkey": _KP_PUB, "alg": "ed25519"},
            )
            batch = await log.pull()
    assert len(batch) == 2
    assert log.checkpoint == 2


@pytest.mark.asyncio
async def test_author_verify_tampered_raises_atomic():
    good = _signed_element(1, {"msg": "a"})
    tampered = {**_signed_element(2, {"msg": "b"}), "data": {"msg": "TAMPERED"}}
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": [good, tampered]}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events", verify_author=True)
            with pytest.raises(AppendAuthorError):
                await log.pull()
    assert log.items == []
    assert log.checkpoint == 0


@pytest.mark.asyncio
async def test_author_verify_unsigned_raises():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": [{"ts": 1, "data": {"msg": "a"}}]}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events", verify_author=True)
            with pytest.raises(AppendAuthorError):
                await log.pull()


@pytest.mark.asyncio
async def test_author_verify_wrong_expected_pubkey_raises():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": [_signed_element(1, {"msg": "a"})]}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(
                client,
                "/pull/events",
                verify_author={"expected_author_pubkey": "00" * 32, "alg": "ed25519"},
            )
            with pytest.raises(AppendAuthorError):
                await log.pull()


@pytest.mark.asyncio
async def test_rejects_element_signed_for_different_document_key():
    # Valid signature, but bound to "other" — pulling from "/pull/events" makes the
    # cursor verify over document_key "events", so it must reject the replay.
    data = {"msg": "a"}
    author = sign_append_author("other", data, _KP_PUB, _KP_PRIV, "ed25519")
    el = {"ts": 1, "data": data, **author}
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": [el]}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events", verify_author=True)
            with pytest.raises(AppendAuthorError):
                await log.pull()
    assert log.items == []


@pytest.mark.asyncio
async def test_expected_author_pubkey_case_insensitive():
    data = {"msg": "a"}
    author = sign_append_author("events", data, _KP_PUB, _KP_PRIV, "ed25519")
    el = {"ts": 1, "data": data, **author}
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": [el]}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(
                client,
                "/pull/events",
                verify_author={"expected_author_pubkey": _KP_PUB.upper(), "alg": "ed25519"},
            )
            assert len(await log.pull()) == 1


@pytest.mark.asyncio
async def test_verify_over_ciphertext_then_decrypt():
    # The author proof is signed over the STORED bytes — the ciphertext, not the plaintext.
    ciphertext = {"_encrypted": json.dumps({"msg": "secret"})}
    author = sign_append_author("events", ciphertext, _KP_PUB, _KP_PRIV, "ed25519")
    el = {"ts": 1, "data": ciphertext, **author}
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": [el]}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(
                client,
                "/pull/events",
                encryptor=_Encryptor(),
                verify_author={"expected_author_pubkey": _KP_PUB, "alg": "ed25519"},
            )
            batch = await log.pull()
    # Verification passed (no raise) AND the returned data is decrypted, ts/author preserved.
    assert batch == [
        {"ts": 1, "data": {"msg": "secret"}, "authorPubkey": _KP_PUB, "authorSignature": author["authorSignature"]}
    ]


# --- constructor validation ---


@pytest.mark.asyncio
async def test_since_below_initial_items_max_raises():
    async with StarfishClient(BASE) as client:
        with pytest.raises(ValueError, match="since must be >= the max ts of initial_items"):
            AppendLogCursor(client, "/pull/events", initial_items=[{"ts": 200, "data": {}}], since=100)


@pytest.mark.asyncio
async def test_negative_since_raises():
    async with StarfishClient(BASE) as client:
        with pytest.raises(ValueError, match="since must be non-negative"):
            AppendLogCursor(client, "/pull/events", since=-1)


@pytest.mark.asyncio
async def test_set_checkpoint_rejects_rewind_below_held():
    async with StarfishClient(BASE) as client:
        log = AppendLogCursor(client, "/pull/events", initial_items=[{"ts": 200, "data": {}}])
        with pytest.raises(ValueError, match="checkpoint must be >= the max ts already held"):
            log.set_checkpoint(100)
        log.set_checkpoint(200)  # equal is allowed


def test_checkpoint_of():
    assert checkpoint_of([]) == 0
    assert checkpoint_of([{"ts": 5}, {"ts": 3}, {"ts": 9}]) == 9


# --- on_element_error: skip ---


@pytest.mark.asyncio
async def test_skip_drops_undecryptable_keeps_rest_and_advances_checkpoint():
    items = [{"ts": 1, "data": {"ok": True}}, {"ts": 2, "data": {"bad": True}}, {"ts": 3, "data": {"ok": True}}]
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": items}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events", encryptor=_FailingEncryptor(), on_element_error="skip")
            batch = await log.pull()
    assert batch == [{"ts": 1, "data": {"ok": True}}, {"ts": 3, "data": {"ok": True}}]
    # Checkpoint advanced PAST the skipped ts=2 so it is never re-fetched.
    assert log.checkpoint == 3


@pytest.mark.asyncio
async def test_skip_does_not_refetch_skipped_element():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(
            side_effect=[
                _json_resp({"items": [{"ts": 1, "data": {"ok": True}}, {"ts": 2, "data": {"bad": True}}]}),
                _json_resp({"items": [{"ts": 3, "data": {"ok": True}}]}),
            ]
        )
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events", encryptor=_FailingEncryptor(), on_element_error="skip")
            await log.pull()
            assert log.checkpoint == 2
            await log.pull()
        assert "checkpoint=2" in str(mock.calls[1].request.url)


@pytest.mark.asyncio
async def test_skip_drops_author_verification_failure():
    good = _signed_element(1, {"msg": "a"})
    tampered = {**_signed_element(2, {"msg": "b"}), "data": {"msg": "TAMPERED"}}
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": [good, tampered]}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events", verify_author=True, on_element_error="skip")
            batch = await log.pull()
    assert batch == [good]
    assert log.checkpoint == 2


# --- concurrent pull() is serialized ---


@pytest.mark.asyncio
async def test_concurrent_pulls_are_serialized():
    import asyncio

    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(
            side_effect=[
                _json_resp({"items": [{"ts": 1, "data": {"a": 1}}, {"ts": 2, "data": {"b": 2}}]}),
                _json_resp({"items": [{"ts": 3, "data": {"c": 3}}]}),
            ]
        )
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events")
            b1, b2 = await asyncio.gather(log.pull(), log.pull())
        # The 2nd pull ran AFTER the 1st advanced the checkpoint → carried ?checkpoint=2.
        assert "checkpoint=2" in str(mock.calls[1].request.url)
    assert b1 == [{"ts": 1, "data": {"a": 1}}, {"ts": 2, "data": {"b": 2}}]
    assert b2 == [{"ts": 3, "data": {"c": 3}}]
    assert log.checkpoint == 3
    assert len(log.items) == 3


@pytest.mark.asyncio
async def test_failed_pull_does_not_wedge_the_lock():
    import asyncio

    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(
            side_effect=[httpx.ConnectError("network"), _json_resp({"items": [{"ts": 1, "data": {"a": 1}}]})]
        )
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events")
            r1, r2 = await asyncio.gather(log.pull(), log.pull(), return_exceptions=True)
    assert isinstance(r1, Exception)
    assert r2 == [{"ts": 1, "data": {"a": 1}}]


# --- persist_encrypted (E2EE-safe persistence) ---


def _cipher(o: object) -> dict[str, Any]:
    return {"_encrypted": json.dumps(o)}


@pytest.mark.asyncio
async def test_persist_encrypted_keeps_ciphertext_pull_returns_plaintext():
    items = [{"ts": 1, "data": _cipher({"msg": "a"})}, {"ts": 2, "data": _cipher({"msg": "b"})}]
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/streamchat").mock(return_value=_json_resp({"items": items}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/streamchat", encryptor=_Encryptor(), persist_encrypted=True)
            batch = await log.pull()
    assert batch == [{"ts": 1, "data": {"msg": "a"}}, {"ts": 2, "data": {"msg": "b"}}]
    # items is the persistable CIPHERTEXT — no plaintext at rest.
    assert log.items == [{"ts": 1, "data": _cipher({"msg": "a"})}, {"ts": 2, "data": _cipher({"msg": "b"})}]
    assert log.get_decrypted_items() == [{"ts": 1, "data": {"msg": "a"}}, {"ts": 2, "data": {"msg": "b"}}]


@pytest.mark.asyncio
async def test_persist_encrypted_round_trip_renders_history_without_network():
    items = [{"ts": 1, "data": _cipher({"msg": "a"})}, {"ts": 2, "data": _cipher({"msg": "b"})}]
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/streamchat").mock(return_value=_json_resp({"items": items}))
        async with StarfishClient(BASE) as client:
            log1 = AppendLogCursor(client, "/pull/streamchat", encryptor=_Encryptor(), persist_encrypted=True)
            await log1.pull()
            persisted = log1.items  # ciphertext written to "disk"

    # New session: warm-start from persisted ciphertext; render history with NO network.
    async with StarfishClient(BASE) as client:
        log2 = AppendLogCursor(
            client, "/pull/streamchat", encryptor=_Encryptor(), persist_encrypted=True, initial_items=persisted
        )
        assert log2.checkpoint == 2
        assert log2.get_decrypted_items() == [{"ts": 1, "data": {"msg": "a"}}, {"ts": 2, "data": {"msg": "b"}}]


@pytest.mark.asyncio
async def test_persist_encrypted_get_decrypted_items_honors_skip():
    async with StarfishClient(BASE) as client:
        log = AppendLogCursor(
            client,
            "/pull/streamchat",
            encryptor=_FailingEncryptor(),
            persist_encrypted=True,
            on_element_error="skip",
            initial_items=[{"ts": 1, "data": {"_encrypted": json.dumps({"msg": "a"})}}, {"ts": 2, "data": {"bad": True}}],
        )
        # _FailingEncryptor.decrypt raises on the {"bad": True} element and returns the
        # other wrapper unchanged — so skip drops ts=2 and keeps ts=1.
        decrypted = log.get_decrypted_items()
    assert [d["ts"] for d in decrypted] == [1]


@pytest.mark.asyncio
async def test_persist_encrypted_is_noop_without_encryptor():
    with respx.mock(base_url="https://api.example.com") as mock:
        mock.get("/v1/pull/events").mock(return_value=_json_resp({"items": [{"ts": 1, "data": {"a": 1}}]}))
        async with StarfishClient(BASE) as client:
            log = AppendLogCursor(client, "/pull/events", persist_encrypted=True)
            await log.pull()
    assert log.items == [{"ts": 1, "data": {"a": 1}}]
    assert log.get_decrypted_items() == [{"ts": 1, "data": {"a": 1}}]
