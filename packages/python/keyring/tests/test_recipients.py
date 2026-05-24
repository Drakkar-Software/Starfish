"""Tests for collection-scoped recipient management helpers."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from starfish_protocol.types import PullResult, PushSuccess
from starfish_sdk.client import StarfishClient
from starfish_keyring.keyring import (
    Keyring,
    add_recipient,
    create_keyring,
    unwrap_from_entry,
    wrap_for_recipient,
)
from starfish_keyring.recipients import (
    add_recipient as add_collection_recipient,
    current_epoch,
    keyring_path_for,
    list_recipients,
    remove_recipient,
)
from starfish_sdk.types import StarfishHttpError


# ── Helpers ──────────────────────────────────────────────────────────────────


class _Party:
    def __init__(self) -> None:
        ed = Ed25519PrivateKey.generate()
        ed_priv_bytes = ed.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        ed_pub_bytes = ed.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        kem = X25519PrivateKey.generate()
        kem_priv_bytes = kem.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        kem_pub_bytes = kem.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.ed_priv = ed_priv_bytes.hex()
        self.ed_pub = ed_pub_bytes.hex()
        self.kem_priv = kem_priv_bytes.hex()
        self.kem_pub = kem_pub_bytes.hex()


def _make_mock_client(initial: dict | None = None) -> tuple[StarfishClient, dict]:
    """Make an in-memory mock StarfishClient keyed by path.

    ``initial`` is ``{"path": str, "data": Keyring, "hash": str}`` or ``None``.
    Returns ``(client, store)`` where ``store`` is a dict of path -> entry.
    """
    store: dict[str, dict] = {}
    counter = {"n": 0}
    if initial is not None:
        store[initial["path"]] = {"data": initial["data"], "hash": initial["hash"]}
        counter["n"] = 1

    client = StarfishClient.__new__(StarfishClient)

    async def _pull(path: str, checkpoint: int = 0) -> PullResult:
        entry = store.get(path)
        if entry is None:
            raise StarfishHttpError(404, "not found")
        kr: Keyring = entry["data"]
        return PullResult(data=kr.to_dict(), hash=entry["hash"], timestamp=1000)

    async def _push(path: str, data: dict, base_hash, sig=None) -> PushSuccess:
        counter["n"] += 1
        new_hash = f"h{counter['n']}"
        store[path] = {"data": Keyring.from_dict(data), "hash": new_hash}
        return PushSuccess(hash=new_hash, timestamp=2000)

    client.pull = AsyncMock(side_effect=_pull)  # type: ignore[attr-defined]
    client.push = AsyncMock(side_effect=_push)  # type: ignore[attr-defined]
    return client, store


# ── keyring_path_for ─────────────────────────────────────────────────────────


def test_keyring_path_for_returns_underscore_keyring_suffix():
    assert keyring_path_for("myColl") == "myColl/_keyring"


# ── current_epoch ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_current_epoch_returns_stored_value():
    admin = _Party()
    alice = _Party()
    keyring, _ = create_keyring(admin.ed_priv, admin.ed_pub, [alice.kem_pub])
    path = f"/pull/{keyring_path_for('vault')}"
    client, _ = _make_mock_client({"path": path, "data": keyring, "hash": "h0"})

    assert await current_epoch(client, "vault") == 1


@pytest.mark.asyncio
async def test_current_epoch_returns_zero_when_no_keyring():
    client, _ = _make_mock_client()
    assert await current_epoch(client, "vault") == 0


# ── list_recipients ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_recipients_returns_subkem_addedby_addedat():
    admin = _Party()
    alice = _Party()
    bob = _Party()
    added_at = 1234567
    keyring, _ = create_keyring(
        admin.ed_priv,
        admin.ed_pub,
        [alice.kem_pub, bob.kem_pub],
        added_at=added_at,
    )
    path = f"/pull/{keyring_path_for('vault')}"
    client, _ = _make_mock_client({"path": path, "data": keyring, "hash": "h0"})

    result = await list_recipients(client, "vault", trusted_adders=[admin.ed_pub])
    assert result["epoch"] == 1
    assert len(result["recipients"]) == 2

    by_sub = {r["subKem"]: r for r in result["recipients"]}
    assert by_sub[alice.kem_pub] == {
        "subKem": alice.kem_pub,
        "addedBy": admin.ed_pub,
        "addedAt": added_at,
    }
    assert by_sub[bob.kem_pub] == {
        "subKem": bob.kem_pub,
        "addedBy": admin.ed_pub,
        "addedAt": added_at,
    }


@pytest.mark.asyncio
async def test_list_recipients_returns_empty_when_no_keyring():
    client, _ = _make_mock_client()
    result = await list_recipients(client, "vault", trusted_adders=[_Party().ed_pub])
    assert result == {"epoch": 0, "recipients": []}


@pytest.mark.asyncio
async def test_list_recipients_is_required_to_pin_trusted_adders():
    """`list_recipients` is fail-closed: omitting `trusted_adders` raises."""
    admin = _Party()
    keyring, _ = create_keyring(admin.ed_priv, admin.ed_pub, [_Party().kem_pub])
    path = f"/pull/{keyring_path_for('vault')}"
    client, _ = _make_mock_client({"path": path, "data": keyring, "hash": "h0"})
    with pytest.raises(ValueError, match="trusted_adders"):
        await list_recipients(client, "vault")  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_list_recipients_filters_entries_from_untrusted_adders():
    """Entries authored by an adder outside `trusted_adders` are excluded.

    A hostile server can substitute the stored keyring with attacker-authored
    entries, but `list_recipients` pinned to the owner drops anything whose
    `addedBy` is not trusted — so the membership view cannot be spoofed.
    """
    admin = _Party()       # the real owner (genesis adder)
    attacker = _Party()    # a hostile adder
    alice = _Party()
    ghost = _Party()

    # The stored keyring lists alice (added by the owner) and a ghost (added by
    # the attacker) — as if a hostile server merged in a forged entry.
    keyring, cek = create_keyring(admin.ed_priv, admin.ed_pub, [alice.kem_pub])
    keyring = add_recipient(keyring, attacker.ed_priv, attacker.ed_pub, cek, ghost.kem_pub)
    path = f"/pull/{keyring_path_for('vault')}"
    client, _ = _make_mock_client({"path": path, "data": keyring, "hash": "h0"})

    listing = await list_recipients(client, "vault", trusted_adders=[admin.ed_pub])
    kems = {r["subKem"] for r in listing["recipients"]}
    assert alice.kem_pub in kems          # owner-added survives
    assert ghost.kem_pub not in kems      # attacker-added is filtered out


# ── add_recipient (collection-scoped) ────────────────────────────────────────


@pytest.mark.asyncio
async def test_add_recipient_adds_to_current_epoch_and_recoverable():
    admin = _Party()
    alice = _Party()
    charlie = _Party()
    keyring, cek = create_keyring(
        admin.ed_priv,
        admin.ed_pub,
        [admin.kem_pub, alice.kem_pub],
    )
    path = f"/pull/{keyring_path_for('vault')}"
    push_path = f"/push/{keyring_path_for('vault')}"
    client, store = _make_mock_client({"path": path, "data": keyring, "hash": "h0"})

    await add_collection_recipient(
        client,
        "vault",
        {"subKem": charlie.kem_pub, "userId": "charlie"},
        {"edPriv": admin.ed_priv, "edPub": admin.ed_pub, "kemPriv": admin.kem_priv},
        trusted_adders=[admin.ed_pub],
    )

    updated = store[push_path]["data"]
    assert updated.current_epoch == 1
    charlie_entry = next(
        (e for e in updated.epochs["1"].wrapped_keys if e.sub_kem == charlie.kem_pub),
        None,
    )
    assert charlie_entry is not None
    recovered_cek = unwrap_from_entry(charlie_entry, charlie.kem_priv)
    assert recovered_cek == cek


@pytest.mark.asyncio
async def test_add_recipient_preserves_existing_recipients():
    admin = _Party()
    alice = _Party()
    charlie = _Party()
    keyring, _ = create_keyring(
        admin.ed_priv,
        admin.ed_pub,
        [admin.kem_pub, alice.kem_pub],
    )
    path = f"/pull/{keyring_path_for('vault')}"
    push_path = f"/push/{keyring_path_for('vault')}"
    client, store = _make_mock_client({"path": path, "data": keyring, "hash": "h0"})

    await add_collection_recipient(
        client,
        "vault",
        {"subKem": charlie.kem_pub},
        {"edPriv": admin.ed_priv, "edPub": admin.ed_pub, "kemPriv": admin.kem_priv},
        trusted_adders=[admin.ed_pub],
    )

    updated = store[push_path]["data"]
    subs = sorted(e.sub_kem for e in updated.epochs["1"].wrapped_keys)
    assert subs == sorted([admin.kem_pub, alice.kem_pub, charlie.kem_pub])


@pytest.mark.asyncio
async def test_add_recipient_uses_prior_hash_as_basehash():
    admin = _Party()
    alice = _Party()
    charlie = _Party()
    keyring, _ = create_keyring(
        admin.ed_priv,
        admin.ed_pub,
        [admin.kem_pub, alice.kem_pub],
    )
    path = f"/pull/{keyring_path_for('vault')}"
    client, _ = _make_mock_client({"path": path, "data": keyring, "hash": "h-prev"})

    await add_collection_recipient(
        client,
        "vault",
        {"subKem": charlie.kem_pub},
        {"edPriv": admin.ed_priv, "edPub": admin.ed_pub, "kemPriv": admin.kem_priv},
        trusted_adders=[admin.ed_pub],
    )

    push_call = client.push.await_args  # type: ignore[attr-defined]
    assert push_call is not None
    # signature: push(path, data, base_hash)
    args = push_call.args
    assert args[2] == "h-prev"


@pytest.mark.asyncio
async def test_add_recipient_throws_when_no_keyring_exists():
    admin = _Party()
    charlie = _Party()
    client, _ = _make_mock_client()
    with pytest.raises(Exception):
        await add_collection_recipient(
            client,
            "vault",
            {"subKem": charlie.kem_pub},
            {"edPriv": admin.ed_priv, "edPub": admin.ed_pub, "kemPriv": admin.kem_priv},
        )


def _forge_replaced_admin_entry(admin: _Party, attacker: _Party) -> tuple[Keyring, bytes]:
    # A hostile server REPLACES the adder's own entry with one wrapping an
    # attacker-chosen CEK to the adder's (public) KEM key, self-signed by an
    # attacker ed key. The self-attesting addedSig verifies, so without a
    # trusted-adders pin the adder unwraps the forged CEK and re-wraps it.
    keyring, _cek = create_keyring(admin.ed_priv, admin.ed_pub, [admin.kem_pub])
    attacker_cek = b"\xab" * 32
    forged = wrap_for_recipient(
        attacker_cek,
        admin.kem_pub,
        adder_ed_priv_hex=attacker.ed_priv,
        adder_ed_pub_hex=attacker.ed_pub,
        added_at=1,
        epoch=1,
    )
    keyring.epochs["1"].wrapped_keys = [forged]
    return keyring, attacker_cek


@pytest.mark.asyncio
async def test_add_recipient_with_trusted_adders_rejects_replaced_entry():
    admin = _Party()
    attacker = _Party()
    charlie = _Party()
    keyring, _ = _forge_replaced_admin_entry(admin, attacker)
    path = f"/pull/{keyring_path_for('vault')}"
    client, _ = _make_mock_client({"path": path, "data": keyring, "hash": "h0"})

    with pytest.raises(ValueError):
        await add_collection_recipient(
            client,
            "vault",
            {"subKem": charlie.kem_pub},
            {"edPriv": admin.ed_priv, "edPub": admin.ed_pub, "kemPriv": admin.kem_priv},
            trusted_adders=[admin.ed_pub],
        )


@pytest.mark.asyncio
async def test_add_recipient_fails_closed_without_trusted_adders():
    # Previously this silently re-wrapped a server-substituted CEK for the
    # newcomer; the mutation helpers now refuse to run without a provenance pin.
    admin = _Party()
    charlie = _Party()
    keyring, _ = create_keyring(admin.ed_priv, admin.ed_pub, [admin.kem_pub])
    path = f"/pull/{keyring_path_for('vault')}"
    client, _ = _make_mock_client({"path": path, "data": keyring, "hash": "h0"})

    with pytest.raises(ValueError, match="trusted_adders"):
        await add_collection_recipient(
            client,
            "vault",
            {"subKem": charlie.kem_pub},
            {"edPriv": admin.ed_priv, "edPub": admin.ed_pub, "kemPriv": admin.kem_priv},
        )


@pytest.mark.asyncio
async def test_add_recipient_fails_closed_on_duplicate_subkem_in_epoch():
    # A valid epoch has unique subKems. Two entries for the same subKem mean the
    # keyring was tampered with (e.g. a hostile server injected a second entry
    # wrapping an attacker-chosen CEK to the adder's own key, self-signed by the
    # adder's key so it survives the trusted-adder + addedSig checks).
    # _recover_current_cek must fail closed on the duplicate rather than probe
    # past it and risk re-wrapping a forged CEK. Mirrors the TS twin in
    # recipients.test.ts.
    admin = _Party()
    charlie = _Party()
    keyring, cek = create_keyring(admin.ed_priv, admin.ed_pub, [admin.kem_pub])
    duplicate = wrap_for_recipient(
        cek,
        admin.kem_pub,
        adder_ed_priv_hex=admin.ed_priv,
        adder_ed_pub_hex=admin.ed_pub,
        added_at=2,
        epoch=1,
    )
    keyring.epochs["1"].wrapped_keys.append(duplicate)
    path = f"/pull/{keyring_path_for('vault')}"
    client, _ = _make_mock_client({"path": path, "data": keyring, "hash": "h0"})

    with pytest.raises(ValueError, match="duplicate"):
        await add_collection_recipient(
            client,
            "vault",
            {"subKem": charlie.kem_pub},
            {"edPriv": admin.ed_priv, "edPub": admin.ed_pub, "kemPriv": admin.kem_priv},
            trusted_adders=[admin.ed_pub],
        )


# ── remove_recipient (collection-scoped) ─────────────────────────────────────


@pytest.mark.asyncio
async def test_remove_recipient_increments_epoch_and_excludes_removed():
    admin = _Party()
    alice = _Party()
    bob = _Party()
    keyring, _ = create_keyring(
        admin.ed_priv,
        admin.ed_pub,
        [admin.kem_pub, alice.kem_pub, bob.kem_pub],
    )
    path = f"/pull/{keyring_path_for('vault')}"
    push_path = f"/push/{keyring_path_for('vault')}"
    client, store = _make_mock_client({"path": path, "data": keyring, "hash": "h0"})

    result = await remove_recipient(
        client,
        "vault",
        [bob.kem_pub],
        {"edPriv": admin.ed_priv, "edPub": admin.ed_pub, "kemPriv": admin.kem_priv},
        trusted_adders=[admin.ed_pub],
    )
    assert result == {"newEpoch": 2}

    updated = store[push_path]["data"]
    assert updated.current_epoch == 2
    subs_epoch2 = [e.sub_kem for e in updated.epochs["2"].wrapped_keys]
    assert admin.kem_pub in subs_epoch2
    assert alice.kem_pub in subs_epoch2
    assert bob.kem_pub not in subs_epoch2


@pytest.mark.asyncio
async def test_remove_recipient_retained_can_unwrap_new_cek():
    admin = _Party()
    alice = _Party()
    bob = _Party()
    keyring, _ = create_keyring(
        admin.ed_priv,
        admin.ed_pub,
        [admin.kem_pub, alice.kem_pub, bob.kem_pub],
    )
    path = f"/pull/{keyring_path_for('vault')}"
    push_path = f"/push/{keyring_path_for('vault')}"
    client, store = _make_mock_client({"path": path, "data": keyring, "hash": "h0"})

    await remove_recipient(
        client,
        "vault",
        [bob.kem_pub],
        {"edPriv": admin.ed_priv, "edPub": admin.ed_pub, "kemPriv": admin.kem_priv},
        trusted_adders=[admin.ed_pub],
    )

    updated = store[push_path]["data"]
    alice_entry = next(
        e for e in updated.epochs["2"].wrapped_keys if e.sub_kem == alice.kem_pub
    )
    new_cek = unwrap_from_entry(alice_entry, alice.kem_priv)
    assert len(new_cek) == 32

    # Bob is absent from the new epoch.
    assert not any(
        e.sub_kem == bob.kem_pub for e in updated.epochs["2"].wrapped_keys
    )


@pytest.mark.asyncio
async def test_remove_recipient_throws_when_no_keyring_exists():
    admin = _Party()
    bob = _Party()
    client, _ = _make_mock_client()
    with pytest.raises(Exception):
        await remove_recipient(
            client,
            "vault",
            [bob.kem_pub],
            {"edPriv": admin.ed_priv, "edPub": admin.ed_pub, "kemPriv": admin.kem_priv},
        )
