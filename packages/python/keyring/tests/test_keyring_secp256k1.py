"""secp256k1 KEM keyring tests (Python mirror of TS
``tests/keyring-secp256k1.test.ts``): cross-language vector conformance, the
four tolerant-reader tag combinations, and downgrade + fail-closed canaries.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import secrets

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from starfish_protocol.suites import get_suite
from starfish_keyring.keyring import (
    WrappedKeyEntry,
    create_keyring,
    create_keyring_encryptor,
    rotate_epoch,
    unwrap_from_entry,
    verify_entry_signature,
    wrap_for_recipient,
)

_VEC = json.loads(
    (
        pathlib.Path(__file__).parent.parent.parent.parent.parent
        / "tests"
        / "test-vectors"
        / "keyring-wrap-secp256k1.json"
    ).read_text()
)

_CEK = bytes.fromhex(_VEC["cek"])
_SECP = get_suite("secp256k1-schnorr")
_ED_KEM = get_suite("ed25519")


def _secp_keypair() -> tuple[str, str]:
    return _SECP.generate_kem_keypair()


def _ed_sign_keypair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.from_private_bytes(secrets.token_bytes(32))
    priv_hex = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    ).hex()
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return priv_hex, pub_hex


@pytest.mark.parametrize("case", _VEC["cases"], ids=lambda c: c["label"])
def test_secp256k1_keyring_wrap_vector(case: dict) -> None:
    entry = wrap_for_recipient(
        _CEK,
        case["recipientKemPubHex"],
        adder_ed_priv_hex=case["adderPrivHex"],
        adder_ed_pub_hex=case["adderPubHex"],
        added_at=case["addedAt"],
        epoch=case["epoch"],
        kem_alg=case["kemAlg"],
        added_by_alg=case["addedByAlg"],
        eph_priv=bytes.fromhex(case["ephPrivHex"]),
        iv=bytes.fromhex(case["ivHex"]),
    )
    assert entry.to_dict() == case["entry"]  # byte-identical to @noble
    assert verify_entry_signature(entry, case["epoch"]) is True
    assert unwrap_from_entry(entry, case["recipientKemPrivHex"]).hex() == _VEC["cek"]


@pytest.mark.parametrize("neg", _VEC["negativeCases"], ids=lambda n: n["label"])
def test_secp256k1_keyring_wrap_negative_vector(neg: dict) -> None:
    # Shared downgrade canaries: each entry is case 1's signed entry with a tag
    # stripped/swapped. Verification MUST fail — proving the guard cross-language,
    # not just per-implementation (mirrors TS).
    assert neg["expectVerify"] is False
    entry = WrappedKeyEntry.from_dict(neg["entry"])
    assert verify_entry_signature(entry, neg["epoch"]) is False


# The four tolerant-reader combinations of (kemAlg present?) × (addedByAlg
# present?) — i.e. both sealing directions between ed25519 and secp256k1.
def _wrap(adder, recipient_pub, *, kem_alg="ed25519", added_by_alg="ed25519"):
    return wrap_for_recipient(
        _CEK,
        recipient_pub,
        adder_ed_priv_hex=adder[0],
        adder_ed_pub_hex=adder[1],
        added_at=1,
        epoch=1,
        kem_alg=kem_alg,
        added_by_alg=added_by_alg,
    )


def test_both_absent_ed25519_adder_x25519_recipient() -> None:
    r_priv, r_pub = _ED_KEM.generate_kem_keypair()
    entry = _wrap(_ed_sign_keypair(), r_pub)
    assert entry.kem_alg is None and entry.added_by_alg is None
    assert verify_entry_signature(entry, 1) is True
    assert unwrap_from_entry(entry, r_priv) == _CEK


def test_kem_alg_only_ed25519_adder_secp_member() -> None:
    r_priv, r_pub = _secp_keypair()
    entry = _wrap(_ed_sign_keypair(), r_pub, kem_alg="secp256k1-schnorr")
    assert entry.kem_alg == "secp256k1-schnorr" and entry.added_by_alg is None
    assert verify_entry_signature(entry, 1) is True
    assert unwrap_from_entry(entry, r_priv) == _CEK


def test_added_by_alg_only_secp_owner_x25519_member() -> None:
    r_priv, r_pub = _ED_KEM.generate_kem_keypair()
    entry = _wrap(_secp_keypair(), r_pub, added_by_alg="secp256k1-schnorr")
    assert entry.kem_alg is None and entry.added_by_alg == "secp256k1-schnorr"
    assert verify_entry_signature(entry, 1) is True
    assert unwrap_from_entry(entry, r_priv) == _CEK


def test_both_present_secp_owner_secp_member() -> None:
    r_priv, r_pub = _secp_keypair()
    entry = _wrap(
        _secp_keypair(), r_pub, kem_alg="secp256k1-schnorr", added_by_alg="secp256k1-schnorr"
    )
    assert entry.kem_alg == "secp256k1-schnorr" and entry.added_by_alg == "secp256k1-schnorr"
    assert verify_entry_signature(entry, 1) is True
    assert unwrap_from_entry(entry, r_priv) == _CEK


# ── Lifecycle: owner seals, member decrypts (end-to-end) ──────────────────────
def test_lifecycle_secp_owner_secp_member_roundtrip() -> None:
    o_priv, o_pub = _secp_keypair()
    m_priv, m_pub = _secp_keypair()
    keyring, _cek = create_keyring(
        o_priv, o_pub, [(m_pub, "secp256k1-schnorr")], added_by_alg="secp256k1-schnorr"
    )
    enc = create_keyring_encryptor(keyring, m_pub, m_priv, trusted_adders=[o_pub])
    sealed = enc.encrypt({"hello": "nostr"})
    assert enc.decrypt(sealed) == {"hello": "nostr"}


def test_lifecycle_ed25519_owner_seals_to_secp_member() -> None:
    o_priv, o_pub = _ed_sign_keypair()  # ed25519 owner (default added_by_alg)
    m_priv, m_pub = _secp_keypair()
    keyring, _cek = create_keyring(o_priv, o_pub, [(m_pub, "secp256k1-schnorr")])
    enc = create_keyring_encryptor(keyring, m_pub, m_priv, trusted_adders=[o_pub])
    sealed = enc.encrypt({"x": 1})
    assert enc.decrypt(sealed) == {"x": 1}


def test_lifecycle_rotate_epoch_retains_secp_member() -> None:
    o_priv, o_pub = _secp_keypair()
    m_priv, m_pub = _secp_keypair()
    keyring, _cek = create_keyring(
        o_priv, o_pub, [(m_pub, "secp256k1-schnorr")], added_by_alg="secp256k1-schnorr"
    )
    rotated, _new = rotate_epoch(
        keyring, o_priv, o_pub, [(m_pub, "secp256k1-schnorr")], added_by_alg="secp256k1-schnorr"
    )
    assert rotated.current_epoch == 2
    enc = create_keyring_encryptor(rotated, m_pub, m_priv, trusted_adders=[o_pub])
    sealed = enc.encrypt({"epoch": 2})
    assert enc.decrypt(sealed) == {"epoch": 2}


def test_lifecycle_rotate_epoch_drops_secp_member() -> None:
    # Cryptographic revocation proof (not just structural): the dropped member
    # keeps their stale epoch-1 entry, but current_epoch is 2 and they have no
    # epoch-2 entry, so they can never obtain the new CEK.
    o_priv, o_pub = _secp_keypair()
    k_priv, k_pub = _secp_keypair()  # kept
    d_priv, d_pub = _secp_keypair()  # dropped
    keyring, _cek = create_keyring(
        o_priv,
        o_pub,
        [(k_pub, "secp256k1-schnorr"), (d_pub, "secp256k1-schnorr")],
        added_by_alg="secp256k1-schnorr",
    )
    # Re-wrap retaining only the kept member; the dropped member is excluded.
    rotated, _new = rotate_epoch(
        keyring, o_priv, o_pub, [(k_pub, "secp256k1-schnorr")], added_by_alg="secp256k1-schnorr"
    )
    assert rotated.current_epoch == 2
    # Retained member still decrypts the new epoch.
    kept_enc = create_keyring_encryptor(rotated, k_pub, k_priv, trusted_adders=[o_pub])
    assert kept_enc.decrypt(kept_enc.encrypt({"ok": 1})) == {"ok": 1}
    # Dropped member: no entry in epoch 2 → encryptor construction fails closed.
    with pytest.raises(ValueError, match="current epoch"):
        create_keyring_encryptor(rotated, d_pub, d_priv, trusted_adders=[o_pub])


def _both_tags_entry() -> tuple[WrappedKeyEntry, str]:
    r_priv, r_pub = _secp_keypair()
    entry = _wrap(
        _secp_keypair(), r_pub, kem_alg="secp256k1-schnorr", added_by_alg="secp256k1-schnorr"
    )
    return entry, r_priv


def test_stripping_kem_alg_fails_verification() -> None:
    entry, _ = _both_tags_entry()
    assert verify_entry_signature(dataclasses.replace(entry, kem_alg=None), 1) is False


def test_stripping_added_by_alg_fails_verification() -> None:
    entry, _ = _both_tags_entry()
    assert verify_entry_signature(dataclasses.replace(entry, added_by_alg=None), 1) is False


def test_swapping_added_by_alg_to_ed25519_fails_verification() -> None:
    entry, _ = _both_tags_entry()
    assert verify_entry_signature(dataclasses.replace(entry, added_by_alg="ed25519"), 1) is False


def test_unwrap_fails_closed_on_malformed_eph_kem() -> None:
    entry, r_priv = _both_tags_entry()
    with pytest.raises(Exception):
        unwrap_from_entry(dataclasses.replace(entry, eph_kem="ff" * 32), r_priv)


def test_verify_returns_false_on_junk_signature() -> None:
    entry, _ = _both_tags_entry()
    assert verify_entry_signature(dataclasses.replace(entry, added_sig="!!notbase64!!"), 1) is False


def test_verify_returns_false_on_unknown_added_by_alg() -> None:
    # Regression: get_suite() for an unimplemented suite must fail closed to
    # False inside verify_entry_signature, not raise out of recover_current_cek/
    # list_recipients (a server-injected-entry DoS). Mirrors TS.
    entry, _ = _both_tags_entry()
    assert verify_entry_signature(dataclasses.replace(entry, added_by_alg="rsa"), 1) is False


def test_verify_returns_false_on_empty_added_by_alg() -> None:
    # Regression for the or-vs-?? split: a server-controlled "" tag must NOT be
    # coerced to ed25519 (which would fork verification vs TS) — only None
    # defaults, so "" → get_suite("") raises → caught → False, matching TS.
    entry, _ = _both_tags_entry()
    assert verify_entry_signature(dataclasses.replace(entry, added_by_alg=""), 1) is False
