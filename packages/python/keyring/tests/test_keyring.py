"""Cross-language vector tests for v3.0 multi-recipient key wrapping.

Reproduces the deterministic ``wrappedKeys[0]`` byte-for-byte using the
generator's ``deterministic_eph_key(cek, recipient_kem_pub)`` and the
``iv = HKDF(cek || recipient_kem_pub, salt="starfish-wrap-iv-vector", info="iv", length=12)``
derivation rules from ``tests/test-vectors/_generators/multi_recipient_wrap.py``.
"""

from __future__ import annotations

import json
import pathlib

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from starfish_keyring.keyring import (
    KEYRING_BLOB_EPOCH_HEADER_BYTES,
    KEYRING_IV_BYTES,
    KEYRING_WRAP_INFO,
    KEYRING_WRAP_SALT,
    Keyring,
    KeyringEpoch,
    WrappedKeyEntry,
    add_recipient,
    create_keyring,
    create_keyring_encryptor,
    rotate_epoch,
    unwrap_from_entry,
    verify_entry_signature,
    wrap_for_recipient,
)

VECTORS_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent
    / "tests"
    / "test-vectors"
    / "multi-recipient-wrap.json"
)
V = json.loads(VECTORS_PATH.read_text())


# ── Helpers (mirror the test vector generator) ────────────────────────────────


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def _deterministic_eph_key(cek: bytes, recipient_kem_pub: bytes) -> bytes:
    return _hkdf(cek + recipient_kem_pub, b"starfish-eph-test-vector", b"x25519", 32)


def _deterministic_iv(cek: bytes, recipient_kem_pub: bytes) -> bytes:
    return _hkdf(cek + recipient_kem_pub, b"starfish-wrap-iv-vector", b"iv", 12)


# ── Constants ─────────────────────────────────────────────────────────────────


def test_constants_match_vector_locks():
    assert KEYRING_WRAP_SALT.decode("utf-8") == V["constants"]["wrapSaltUtf8"]
    assert KEYRING_WRAP_INFO.decode("utf-8") == V["constants"]["wrapInfoUtf8"]
    assert KEYRING_IV_BYTES == V["constants"]["ivBytes"]


# ── Deterministic wrap reproduction ───────────────────────────────────────────


def test_wrap_for_recipient_reproduces_first_vector_entry():
    cek = bytes.fromhex(V["cek"])
    recipient = V["fixtures"]["alice_dev_1"]
    adder = V["fixtures"]["alice_root"]
    expected = V["keyring"]["epochs"]["1"]["wrappedKeys"][0]

    eph_priv = _deterministic_eph_key(cek, bytes.fromhex(recipient["kemPub"]))
    iv = _deterministic_iv(cek, bytes.fromhex(recipient["kemPub"]))

    entry = wrap_for_recipient(
        cek,
        recipient["kemPub"],
        adder_ed_priv_hex=adder["edPriv"],
        adder_ed_pub_hex=adder["edPub"],
        added_at=expected["addedAt"],
        epoch=1,
        eph_priv=eph_priv,
        iv=iv,
    )

    assert entry.sub_kem == expected["subKem"]
    assert entry.eph_kem == expected["ephKem"]
    assert entry.ct == expected["ct"]
    assert entry.added_by == expected["addedBy"]
    assert entry.added_at == expected["addedAt"]
    assert entry.added_sig == expected["addedSig"]


def test_wrap_preserves_caller_supplied_eph_priv_and_roundtrips():
    # The wrap scrubs only a locally generated ephemeral key; a caller-supplied
    # key must be left intact (and the entry must still unwrap to the CEK).
    cek = bytes.fromhex(V["cek"])
    recipient = V["fixtures"]["alice_dev_1"]
    adder = V["fixtures"]["alice_root"]
    eph_priv = bytearray(_deterministic_eph_key(cek, bytes.fromhex(recipient["kemPub"])))
    snapshot = bytes(eph_priv)

    entry = wrap_for_recipient(
        cek,
        recipient["kemPub"],
        adder_ed_priv_hex=adder["edPriv"],
        adder_ed_pub_hex=adder["edPub"],
        added_at=99,
        epoch=1,
        eph_priv=eph_priv,
    )
    assert bytes(eph_priv) == snapshot
    assert any(eph_priv)
    assert unwrap_from_entry(entry, recipient["kemPriv"]) == cek


def test_wrap_for_recipient_reproduces_all_three_vector_entries():
    cek = bytes.fromhex(V["cek"])
    adder = V["fixtures"]["alice_root"]
    entries = V["keyring"]["epochs"]["1"]["wrappedKeys"]
    recipients = [
        V["fixtures"]["alice_dev_1"],
        V["fixtures"]["alice_dev_2"],
        V["fixtures"]["bob_root"],
    ]

    for recipient, expected in zip(recipients, entries):
        eph_priv = _deterministic_eph_key(cek, bytes.fromhex(recipient["kemPub"]))
        iv = _deterministic_iv(cek, bytes.fromhex(recipient["kemPub"]))
        got = wrap_for_recipient(
            cek,
            recipient["kemPub"],
            adder_ed_priv_hex=adder["edPriv"],
            adder_ed_pub_hex=adder["edPub"],
            added_at=expected["addedAt"],
            epoch=1,
            eph_priv=eph_priv,
            iv=iv,
        )
        assert got.to_dict() == expected


# ── Signature verification ────────────────────────────────────────────────────


def test_verify_entry_signature_succeeds_for_all_vector_entries():
    for entry_data in V["keyring"]["epochs"]["1"]["wrappedKeys"]:
        entry = WrappedKeyEntry.from_dict(entry_data)
        assert verify_entry_signature(entry, 1) is True


def test_verify_entry_signature_fails_on_wrong_epoch():
    entry = WrappedKeyEntry.from_dict(V["keyring"]["epochs"]["1"]["wrappedKeys"][0])
    assert verify_entry_signature(entry, 2) is False


def test_verify_entry_signature_fails_on_tampered_ct():
    entry_data = dict(V["keyring"]["epochs"]["1"]["wrappedKeys"][0])
    entry_data["ct"] = "Z" + entry_data["ct"][1:]
    entry = WrappedKeyEntry.from_dict(entry_data)
    assert verify_entry_signature(entry, 1) is False


# ── Unwrap from entry ─────────────────────────────────────────────────────────


def test_unwrap_from_entry_recovers_cek_for_each_recipient():
    entries = V["keyring"]["epochs"]["1"]["wrappedKeys"]
    recipients_by_pub = {
        V["fixtures"]["alice_dev_1"]["kemPub"]: V["fixtures"]["alice_dev_1"],
        V["fixtures"]["alice_dev_2"]["kemPub"]: V["fixtures"]["alice_dev_2"],
        V["fixtures"]["bob_root"]["kemPub"]: V["fixtures"]["bob_root"],
    }
    for entry_data in entries:
        entry = WrappedKeyEntry.from_dict(entry_data)
        recipient = recipients_by_pub[entry.sub_kem]
        recovered = unwrap_from_entry(entry, recipient["kemPriv"])
        assert recovered.hex() == V["cek"]


def test_unwrap_from_entry_throws_with_wrong_recipient_key():
    entry = WrappedKeyEntry.from_dict(V["keyring"]["epochs"]["1"]["wrappedKeys"][0])
    with pytest.raises(ValueError):
        unwrap_from_entry(entry, V["fixtures"]["bob_root"]["kemPriv"])


def test_unwrap_rejects_entry_whose_ciphertext_is_shorter_than_the_iv():
    """A structurally malformed entry (ct decodes to fewer than IV bytes) raises a clear
    error from the explicit length guard, not a silent empty slice or AES surprise.

    `ct` is `iv || aesgcm(...)`; an attacker (or a corrupt store) supplying a stub shorter
    than the 12-byte IV must be rejected before the IV/ct split, so the unwrap can't slice
    past the end and feed a degenerate input to AES-GCM.
    """
    import base64

    good = V["keyring"]["epochs"]["1"]["wrappedKeys"][0]
    too_short = base64.b64encode(b"\x00" * (KEYRING_IV_BYTES - 1)).decode("ascii")
    malformed = WrappedKeyEntry.from_dict({**good, "ct": too_short})
    with pytest.raises(ValueError, match="shorter than IV length"):
        unwrap_from_entry(malformed, V["fixtures"]["alice_dev_1"]["kemPriv"])


# ── Keyring lifecycle ─────────────────────────────────────────────────────────


@pytest.fixture
def actors():
    return {
        "alice": V["fixtures"]["alice_root"],
        "dev1": V["fixtures"]["alice_dev_1"],
        "dev2": V["fixtures"]["alice_dev_2"],
        "bob": V["fixtures"]["bob_root"],
    }


def test_create_keyring_wraps_for_every_recipient_with_valid_signatures(actors):
    alice, dev1, dev2 = actors["alice"], actors["dev1"], actors["dev2"]
    keyring, cek = create_keyring(
        alice["edPriv"], alice["edPub"], [dev1["kemPub"], dev2["kemPub"]]
    )
    assert keyring.v == 1
    assert keyring.current_epoch == 1
    wrapped = keyring.epochs["1"].wrapped_keys
    assert len(wrapped) == 2
    for entry in wrapped:
        assert verify_entry_signature(entry, 1) is True
    assert unwrap_from_entry(wrapped[0], dev1["kemPriv"]) == cek
    assert unwrap_from_entry(wrapped[1], dev2["kemPriv"]) == cek


def test_add_recipient_appends_entry_to_current_epoch(actors):
    alice, dev1, dev2 = actors["alice"], actors["dev1"], actors["dev2"]
    keyring, cek = create_keyring(alice["edPriv"], alice["edPub"], [dev1["kemPub"]])
    updated = add_recipient(
        keyring, alice["edPriv"], alice["edPub"], cek, dev2["kemPub"]
    )
    assert len(updated.epochs["1"].wrapped_keys) == 2
    assert updated.epochs["1"].wrapped_keys[1].sub_kem == dev2["kemPub"]
    assert unwrap_from_entry(updated.epochs["1"].wrapped_keys[1], dev2["kemPriv"]) == cek


def test_add_recipient_rejects_duplicate_sub_kem(actors):
    alice, dev1 = actors["alice"], actors["dev1"]
    keyring, cek = create_keyring(alice["edPriv"], alice["edPub"], [dev1["kemPub"]])
    with pytest.raises(ValueError):
        add_recipient(keyring, alice["edPriv"], alice["edPub"], cek, dev1["kemPub"])


def test_rotate_epoch_excludes_removed_recipient(actors):
    alice, dev1, dev2, bob = actors["alice"], actors["dev1"], actors["dev2"], actors["bob"]
    keyring, cek1 = create_keyring(
        alice["edPriv"],
        alice["edPub"],
        [dev1["kemPub"], dev2["kemPub"], bob["kemPub"]],
    )
    rotated, cek2 = rotate_epoch(
        keyring,
        alice["edPriv"],
        alice["edPub"],
        [dev1["kemPub"], dev2["kemPub"]],
    )
    assert rotated.current_epoch == 2
    assert cek1 != cek2
    assert "1" in rotated.epochs  # old epoch preserved
    assert len(rotated.epochs["2"].wrapped_keys) == 2
    for entry in rotated.epochs["2"].wrapped_keys:
        assert entry.sub_kem != bob["kemPub"]
        assert verify_entry_signature(entry, 2) is True


def test_re_adding_a_rotated_out_recipient_restores_access(actors):
    # Churn: a recipient removed by a rotation can be re-granted access by adding
    # them back to the (new) current epoch. Mirrors keyring.test.ts.
    alice, dev1, dev2 = actors["alice"], actors["dev1"], actors["dev2"]
    keyring, _cek1 = create_keyring(
        alice["edPriv"], alice["edPub"], [dev1["kemPub"], dev2["kemPub"]]
    )
    rotated, cek2 = rotate_epoch(
        keyring, alice["edPriv"], alice["edPub"], [dev1["kemPub"]]  # dev2 rotated out
    )
    assert all(e.sub_kem != dev2["kemPub"] for e in rotated.epochs["2"].wrapped_keys)

    readded = add_recipient(rotated, alice["edPriv"], alice["edPub"], cek2, dev2["kemPub"])
    entry = next(e for e in readded.epochs["2"].wrapped_keys if e.sub_kem == dev2["kemPub"])
    assert unwrap_from_entry(entry, dev2["kemPriv"]) == cek2


def test_rotating_out_every_recipient_yields_empty_epoch_and_encryptor_fails(actors):
    alice, dev1 = actors["alice"], actors["dev1"]
    keyring, _cek = create_keyring(alice["edPriv"], alice["edPub"], [dev1["kemPub"]])
    emptied, _cek2 = rotate_epoch(keyring, alice["edPriv"], alice["edPub"], [])  # retain nobody
    assert emptied.current_epoch == 2
    assert len(emptied.epochs["2"].wrapped_keys) == 0
    with pytest.raises(ValueError):
        create_keyring_encryptor(
            emptied, dev1["kemPub"], dev1["kemPriv"], trusted_adders=[alice["edPub"]]
        )


# ── Encryptor round-trip ──────────────────────────────────────────────────────


def test_keyring_encryptor_round_trip_between_two_recipients(actors):
    alice, dev1, dev2 = actors["alice"], actors["dev1"], actors["dev2"]
    keyring, _cek = create_keyring(
        alice["edPriv"], alice["edPub"], [dev1["kemPub"], dev2["kemPub"]]
    )
    enc1 = create_keyring_encryptor(keyring, dev1["kemPub"], dev1["kemPriv"], trusted_adders=[alice["edPub"]])
    enc2 = create_keyring_encryptor(keyring, dev2["kemPub"], dev2["kemPriv"], trusted_adders=[alice["edPub"]])

    payload = enc1.encrypt({"hello": "world", "n": 7})
    assert isinstance(payload["_encrypted"], str)
    assert payload["_epoch"] == 1
    assert enc2.decrypt(payload) == {"hello": "world", "n": 7}


def test_keyring_encryptor_seals_and_opens_binary_blobs_with_path_aad(actors):
    """Cross-language parity for binary-attachment sealing.

    ``KeyringEncryptor.seal_bytes`` produces ``[u32 BE epoch][12B iv]
    [AES-256-GCM ct‖tag]`` with the caller's storage path bound into the GCM tag
    as AAD, so a hostile server cannot relocate the blob to another path or replay
    it at a different epoch. ``open_bytes`` verifies that AAD. Binary collections
    must use ``encryption: "none"`` on the server, so this client-side primitive
    is the only way to E2E-protect attachments. Byte-compatible with the TS
    keyring's ``sealBytes``/``openBytes`` (same header, IV size, and ``aad`` rule).
    """
    alice, dev1, dev2 = actors["alice"], actors["dev1"], actors["dev2"]
    keyring, _cek = create_keyring(
        alice["edPriv"], alice["edPub"], [dev1["kemPub"], dev2["kemPub"]]
    )
    enc1 = create_keyring_encryptor(
        keyring, dev1["kemPub"], dev1["kemPriv"], trusted_adders=[alice["edPub"]]
    )
    enc2 = create_keyring_encryptor(
        keyring, dev2["kemPub"], dev2["kemPriv"], trusted_adders=[alice["edPub"]]
    )

    data = bytes([0, 1, 2, 250, 251, 255, 7, 7])
    blob = enc1.seal_bytes(data, aad="attachments/rooms/r1/blob1")
    # Big-endian epoch 1 in the 4-byte header (matches the TS layout: blob[3]==1).
    assert blob[3] == 1
    assert len(blob) > KEYRING_BLOB_EPOCH_HEADER_BYTES + KEYRING_IV_BYTES + len(data)  # + GCM tag
    # A co-recipient on the same epoch opens it with the matching path AAD.
    assert enc2.open_bytes(blob, aad="attachments/rooms/r1/blob1") == data
    # A path (AAD) mismatch must fail closed with a clear decryption error
    # (mirrors the TS openBytes message and the existing decrypt() guard).
    with pytest.raises(ValueError, match="(?i)decryption failed|tampered|aad"):
        enc2.open_bytes(blob, aad="attachments/rooms/r1/blobB")


def test_keyring_encryptor_rejects_epoch_rollback(actors):
    """`min_epoch` refuses a keyring whose `current_epoch` is below the last-seen floor.

    Models a hostile server serving a STALE keyring to undo a rotation. The caller
    persists the highest epoch it has seen and passes it as `min_epoch`.
    """
    alice, dev1 = actors["alice"], actors["dev1"]
    keyring, _cek = create_keyring(alice["edPriv"], alice["edPub"], [dev1["kemPub"]])
    rotated, _cek2 = rotate_epoch(keyring, alice["edPriv"], alice["edPub"], [dev1["kemPub"]])
    assert rotated.current_epoch == 2

    # At/above the floor → fine.
    create_keyring_encryptor(
        rotated, dev1["kemPub"], dev1["kemPriv"], trusted_adders=[alice["edPub"]], min_epoch=2
    )
    # A rolled-back keyring (epoch 1) presented when the caller has seen epoch 2 → rejected.
    with pytest.raises(ValueError, match="rollback"):
        create_keyring_encryptor(
            keyring, dev1["kemPub"], dev1["kemPriv"], trusted_adders=[alice["edPub"]], min_epoch=2
        )


def test_keyring_encryptor_falls_back_to_current_epoch_when_epoch_missing(actors):
    alice, dev1 = actors["alice"], actors["dev1"]
    keyring, _cek = create_keyring(alice["edPriv"], alice["edPub"], [dev1["kemPub"]])
    enc = create_keyring_encryptor(keyring, dev1["kemPub"], dev1["kemPriv"], trusted_adders=[alice["edPub"]])
    wrapped = enc.encrypt({"a": 1})
    wrapped.pop("_epoch")
    assert enc.decrypt(wrapped) == {"a": 1}


def test_removed_recipient_cannot_decrypt_new_epoch_documents(actors):
    alice, dev1, bob = actors["alice"], actors["dev1"], actors["bob"]
    keyring, _cek = create_keyring(
        alice["edPriv"], alice["edPub"], [dev1["kemPub"], bob["kemPub"]]
    )
    # Bob builds his encryptor while still in the keyring.
    bob_old_enc = create_keyring_encryptor(keyring, bob["kemPub"], bob["kemPriv"], trusted_adders=[alice["edPub"]])

    rotated, _cek2 = rotate_epoch(
        keyring, alice["edPriv"], alice["edPub"], [dev1["kemPub"]]
    )
    alice_enc = create_keyring_encryptor(rotated, dev1["kemPub"], dev1["kemPriv"], trusted_adders=[alice["edPub"]])
    payload = alice_enc.encrypt({"secret": "for-alice-only"})
    assert payload["_epoch"] == 2

    with pytest.raises(ValueError):
        bob_old_enc.decrypt(payload)

    # Bob also cannot construct a fresh encryptor from the rotated keyring.
    with pytest.raises(ValueError):
        create_keyring_encryptor(rotated, bob["kemPub"], bob["kemPriv"], trusted_adders=[alice["edPub"]])


def test_recipient_added_after_rotation_needs_reseal_to_read_old_content(actors):
    alice, dev1, dev2, bob = (
        actors["alice"],
        actors["dev1"],
        actors["dev2"],
        actors["bob"],
    )
    # dev1 + bob start in epoch 1; dev1 seals a document there.
    keyring, _cek = create_keyring(
        alice["edPriv"], alice["edPub"], [dev1["kemPub"], bob["kemPub"]]
    )
    enc1 = create_keyring_encryptor(keyring, dev1["kemPub"], dev1["kemPriv"], trusted_adders=[alice["edPub"]])
    old_doc = enc1.encrypt({"msg": "history"})
    assert old_doc["_epoch"] == 1

    # Revoking bob rotates to epoch 2 — the old doc stays sealed under epoch 1.
    rotated, cek2 = rotate_epoch(
        keyring, alice["edPriv"], alice["edPub"], [dev1["kemPub"]]
    )
    # A NEW device (dev2) is then added — to the current epoch (2) only.
    with_dev2 = add_recipient(
        rotated, alice["edPriv"], alice["edPub"], cek2, dev2["kemPub"]
    )

    # dev2 builds an encryptor fine (it IS in the current epoch)…
    dev2_enc = create_keyring_encryptor(with_dev2, dev2["kemPub"], dev2["kemPriv"], trusted_adders=[alice["edPub"]])
    # …but cannot read the epoch-1 history.
    with pytest.raises(ValueError, match="No key available for epoch 1"):
        dev2_enc.decrypt(old_doc)

    # An existing recipient present in BOTH epochs re-seals the doc at the
    # current epoch (what the app does after adding a recipient).
    re_sealer = create_keyring_encryptor(with_dev2, dev1["kemPub"], dev1["kemPriv"], trusted_adders=[alice["edPub"]])
    re_sealed = re_sealer.encrypt(re_sealer.decrypt(old_doc))
    assert re_sealed["_epoch"] == 2
    # Now the freshly-added device can read it.
    assert dev2_enc.decrypt(re_sealed) == {"msg": "history"}


def test_create_encryptor_skips_entry_with_tampered_added_by(actors):
    """A server that mutates ``addedBy`` post-wrap must not be trusted.

    The audit signature is verified before unwrap; a tampered entry is
    skipped, so the recipient is locked out of that epoch instead of
    silently accepting forged provenance.
    """
    alice, dev1, dev2, bob = (
        actors["alice"],
        actors["dev1"],
        actors["dev2"],
        actors["bob"],
    )
    keyring, _cek = create_keyring(
        alice["edPriv"], alice["edPub"], [dev1["kemPub"], dev2["kemPub"]]
    )
    # Mutate dev1's addedBy to bob's edPub (signature was computed with alice's
    # priv over alice's pub — verifying against bob's pub fails).
    epoch_one = keyring.epochs["1"]
    new_keys = []
    for entry in epoch_one.wrapped_keys:
        if entry.sub_kem == dev1["kemPub"]:
            new_keys.append(
                WrappedKeyEntry(
                    sub_kem=entry.sub_kem,
                    eph_kem=entry.eph_kem,
                    ct=entry.ct,
                    added_by=bob["edPub"],
                    added_sig=entry.added_sig,
                    added_at=entry.added_at,
                )
            )
        else:
            new_keys.append(entry)
    tampered = Keyring(
        v=keyring.v,
        current_epoch=keyring.current_epoch,
        epochs={
            **keyring.epochs,
            "1": KeyringEpoch(wrapped_keys=new_keys, created_at=epoch_one.created_at),
        },
    )
    with pytest.raises(ValueError, match="No wrapped key for recipient"):
        create_keyring_encryptor(tampered, dev1["kemPub"], dev1["kemPriv"], trusted_adders=[alice["edPub"]])


def test_create_encryptor_keeps_other_epochs_when_one_entry_is_tampered(actors):
    """Tampering one epoch's entry must not lock the recipient out of others."""
    alice, dev1 = actors["alice"], actors["dev1"]
    bob = actors["bob"]
    keyring, _cek = create_keyring(alice["edPriv"], alice["edPub"], [dev1["kemPub"]])
    rotated, _cek2 = rotate_epoch(
        keyring, alice["edPriv"], alice["edPub"], [dev1["kemPub"]]
    )
    # Tamper with epoch 1 only.
    ep1 = rotated.epochs["1"]
    new_keys = [
        WrappedKeyEntry(
            sub_kem=e.sub_kem,
            eph_kem=e.eph_kem,
            ct=e.ct,
            added_by=bob["edPub"],
            added_sig=e.added_sig,
            added_at=e.added_at,
        )
        if e.sub_kem == dev1["kemPub"]
        else e
        for e in ep1.wrapped_keys
    ]
    tampered = Keyring(
        v=rotated.v,
        current_epoch=rotated.current_epoch,
        epochs={
            **rotated.epochs,
            "1": KeyringEpoch(wrapped_keys=new_keys, created_at=ep1.created_at),
        },
    )
    enc = create_keyring_encryptor(tampered, dev1["kemPub"], dev1["kemPriv"], trusted_adders=[alice["edPub"]])
    payload = enc.encrypt({"value": 42})
    assert payload["_epoch"] == 2
    assert enc.decrypt(payload) == {"value": 42}


# ── to_dict / from_dict round-trip ────────────────────────────────────────────


def test_keyring_serialization_round_trip(actors):
    alice, dev1, dev2 = actors["alice"], actors["dev1"], actors["dev2"]
    keyring, _ = create_keyring(
        alice["edPriv"], alice["edPub"], [dev1["kemPub"], dev2["kemPub"]]
    )
    as_dict = keyring.to_dict()
    parsed = Keyring.from_dict(as_dict)
    assert parsed.current_epoch == keyring.current_epoch
    assert parsed.v == keyring.v
    assert parsed.epochs.keys() == keyring.epochs.keys()
    assert isinstance(parsed.epochs["1"], KeyringEpoch)


# ── createKeyringEncryptor rejects keyring tampering (hostile server) ─────────


def test_fails_closed_on_injected_duplicate_sub_kem(actors):
    """A SECOND entry for the recipient's subKem is tampering — fail closed.

    The audit signature is self-attesting, so an attacker can sign their own
    forged entry. First-match selection would let a prepended attacker entry
    override the recipient's real CEK; a valid epoch has at most one entry per
    subKem, so a duplicate is rejected.
    """
    alice, dev1, dev2, attacker = (
        actors["alice"],
        actors["dev1"],
        actors["dev2"],
        actors["bob"],
    )
    keyring, _cek = create_keyring(
        alice["edPriv"], alice["edPub"], [dev1["kemPub"], dev2["kemPub"]]
    )
    forged = wrap_for_recipient(
        bytes([0xAA]) * 32,
        dev1["kemPub"],
        adder_ed_priv_hex=attacker["edPriv"],
        adder_ed_pub_hex=attacker["edPub"],
        added_at=1_700_000_000,
        epoch=1,
    )
    epoch_one = keyring.epochs["1"]
    tampered = Keyring(
        v=keyring.v,
        current_epoch=keyring.current_epoch,
        epochs={
            **keyring.epochs,
            # Prepend so a naive first-match would pick the attacker's entry.
            "1": KeyringEpoch(
                wrapped_keys=[forged, *epoch_one.wrapped_keys],
                created_at=epoch_one.created_at,
            ),
        },
    )
    with pytest.raises(ValueError, match="No wrapped key for recipient"):
        create_keyring_encryptor(tampered, dev1["kemPub"], dev1["kemPriv"], trusted_adders=[alice["edPub"]])


def test_trusted_adders_rejects_replaced_entry(actors):
    """With trusted_adders, a REPLACED entry whose addedBy is not trusted is rejected."""
    alice, dev1, attacker = actors["alice"], actors["dev1"], actors["bob"]
    keyring, _cek = create_keyring(alice["edPriv"], alice["edPub"], [dev1["kemPub"]])
    forged = wrap_for_recipient(
        bytes([0xBB]) * 32,
        dev1["kemPub"],
        adder_ed_priv_hex=attacker["edPriv"],
        adder_ed_pub_hex=attacker["edPub"],
        added_at=1_700_000_000,
        epoch=1,
    )
    # Replace the legit entry entirely — no duplicate subKem, so only adder
    # provenance can catch it. The forged entry's self-signature verifies.
    epoch_one = keyring.epochs["1"]
    tampered = Keyring(
        v=keyring.v,
        current_epoch=keyring.current_epoch,
        epochs={
            **keyring.epochs,
            "1": KeyringEpoch(wrapped_keys=[forged], created_at=epoch_one.created_at),
        },
    )
    with pytest.raises(ValueError, match="No wrapped key for recipient"):
        create_keyring_encryptor(
            tampered,
            dev1["kemPub"],
            dev1["kemPriv"],
            trusted_adders=[alice["edPub"]],
        )


def test_trusted_adders_allows_owner_added_entry(actors):
    """An owner-added entry still resolves when trusted_adders pins the owner."""
    alice, dev1 = actors["alice"], actors["dev1"]
    keyring, _cek = create_keyring(alice["edPriv"], alice["edPub"], [dev1["kemPub"]])
    enc = create_keyring_encryptor(
        keyring, dev1["kemPub"], dev1["kemPriv"], trusted_adders=[alice["edPub"]]
    )
    payload = enc.encrypt({"ok": True})
    assert enc.decrypt(payload) == {"ok": True}


# ---------------------------------------------------------------------------
# Epoch AAD binding in JSON encrypt/decrypt
# ---------------------------------------------------------------------------


def test_json_encrypt_epoch_is_authenticated(actors):
    """Flipping _epoch in an encrypted JSON payload must fail at AEAD authentication.

    The epoch is bound into the AES-GCM AAD so a hostile server cannot substitute
    a different _epoch value to redirect decryption to a wrong CEK. We rotate the
    epoch so the decryptor has TWO valid CEKs (epochs 1 and 2), then flip the
    envelope from epoch 2 to epoch 1. Without AAD binding, decrypt() would silently
    use the epoch-1 CEK on epoch-2 ciphertext — returning garbled data with no error.
    With binding, AES-GCM authentication fails with a clear error.
    """
    alice, dev1 = actors["alice"], actors["dev1"]
    keyring, _cek = create_keyring(alice["edPriv"], alice["edPub"], [dev1["kemPub"]])

    # Rotate so the encryptor has both epoch 1 and epoch 2 CEKs
    rotated, _cek2 = rotate_epoch(keyring, alice["edPriv"], alice["edPub"], [dev1["kemPub"]])
    assert rotated.current_epoch == 2

    enc = create_keyring_encryptor(
        rotated, dev1["kemPub"], dev1["kemPriv"], trusted_adders=[alice["edPub"]]
    )
    # Encrypts at epoch 2 (current)
    payload = enc.encrypt({"secret": "data"})
    assert payload["_epoch"] == 2

    # Tamper: flip to epoch 1 (a CEK that EXISTS but is WRONG for this ciphertext)
    tampered = {**payload, "_epoch": 1}
    with pytest.raises(ValueError, match="(?i)decryption failed|tampered|wrong epoch"):
        enc.decrypt(tampered)


def test_json_encrypt_epoch_aad_round_trip(actors):
    """encrypt/decrypt with epoch AAD succeeds normally for the right epoch."""
    alice, dev1, dev2 = actors["alice"], actors["dev1"], actors["dev2"]
    keyring, _cek = create_keyring(
        alice["edPriv"], alice["edPub"], [dev1["kemPub"], dev2["kemPub"]]
    )
    enc1 = create_keyring_encryptor(
        keyring, dev1["kemPub"], dev1["kemPriv"], trusted_adders=[alice["edPub"]]
    )
    enc2 = create_keyring_encryptor(
        keyring, dev2["kemPub"], dev2["kemPriv"], trusted_adders=[alice["edPub"]]
    )

    payload = enc1.encrypt({"message": "hello", "value": 42})
    assert enc2.decrypt(payload) == {"message": "hello", "value": 42}

