"""Sealed-envelope round-trips: self-seal, peer-seal, sealer pinning, and the
wrong-recipient / tamper failure modes that make trial-unseal safe."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from starfish_protocol.suites import ed25519 as ed25519_suite
from starfish_keyring.seal import (
    seal,
    seal_to_self,
    unseal,
    unseal_from_self,
    unseal_to_str,
)

_RAW = serialization.Encoding.Raw


def _make_identity() -> dict[str, str]:
    """A fresh identity: Ed25519 signing keypair + X25519 KEM keypair (all hex)."""
    ed = Ed25519PrivateKey.generate()
    ed_priv = ed.private_bytes(
        _RAW, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    ).hex()
    ed_pub = ed.public_key().public_bytes(_RAW, serialization.PublicFormat.Raw).hex()
    kem_priv, kem_pub = ed25519_suite.generate_kem_keypair()
    return {
        "ed_priv": ed_priv,
        "ed_pub": ed_pub,
        "kem_priv": kem_priv,
        "kem_pub": kem_pub,
    }


def test_self_seal_round_trips_a_string() -> None:
    me = _make_identity()
    blob = seal_to_self(
        "bearer-secret-123", me["kem_pub"],
        sealer_ed_priv_hex=me["ed_priv"], sealer_ed_pub_hex=me["ed_pub"],
    )
    assert unseal_to_str(blob, me["kem_priv"]) == "bearer-secret-123"
    out = unseal_from_self(blob, kem_priv_hex=me["kem_priv"], ed_pub_hex=me["ed_pub"])
    assert out.decode("utf-8") == "bearer-secret-123"


def test_seals_raw_bytes_to_a_peer() -> None:
    sender = _make_identity()
    peer = _make_identity()
    payload = bytes([1, 2, 3, 4, 250, 251, 252])
    blob = seal(
        payload, peer["kem_pub"],
        sealer_ed_priv_hex=sender["ed_priv"], sealer_ed_pub_hex=sender["ed_pub"],
    )
    assert blob.entry.added_by == sender["ed_pub"]
    assert unseal(blob, peer["kem_priv"]) == payload


def test_rejects_wrong_recipient() -> None:
    sender = _make_identity()
    peer = _make_identity()
    stranger = _make_identity()
    blob = seal(
        "for-peer-only", peer["kem_pub"],
        sealer_ed_priv_hex=sender["ed_priv"], sealer_ed_pub_hex=sender["ed_pub"],
    )
    with pytest.raises(ValueError):
        unseal(blob, stranger["kem_priv"])


def test_enforces_require_sealer() -> None:
    sender = _make_identity()
    impostor = _make_identity()
    peer = _make_identity()
    blob = seal(
        "hi", peer["kem_pub"],
        sealer_ed_priv_hex=sender["ed_priv"], sealer_ed_pub_hex=sender["ed_pub"],
    )
    assert unseal_to_str(blob, peer["kem_priv"], require_sealer=sender["ed_pub"]) == "hi"
    with pytest.raises(ValueError):
        unseal(blob, peer["kem_priv"], require_sealer=impostor["ed_pub"])


def test_rejects_tampered_ciphertext() -> None:
    me = _make_identity()
    blob = seal_to_self(
        "integrity", me["kem_pub"],
        sealer_ed_priv_hex=me["ed_priv"], sealer_ed_pub_hex=me["ed_pub"],
    )
    blob.ct = blob.ct[:-4] + ("BBBB" if blob.ct.endswith("AAAA") else "AAAA")
    with pytest.raises(ValueError):
        unseal(blob, me["kem_priv"])


def test_to_dict_from_dict_round_trip() -> None:
    me = _make_identity()
    peer = _make_identity()
    blob = seal(
        "carry-me", peer["kem_pub"],
        sealer_ed_priv_hex=me["ed_priv"], sealer_ed_pub_hex=me["ed_pub"],
    )
    from starfish_keyring.seal import SealedBlob

    revived = SealedBlob.from_dict(blob.to_dict())
    assert unseal_to_str(revived, peer["kem_priv"]) == "carry-me"
