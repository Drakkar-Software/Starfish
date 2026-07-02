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


# ---------------------------------------------------------------------------
# AAD context-binding (v=1 blobs)
# ---------------------------------------------------------------------------


def test_aad_seal_round_trip() -> None:
    """A blob sealed with aad can only be opened with the same aad."""
    me = _make_identity()
    ctx = "keyring/spaces/sp-123/user/u1"
    blob = seal_to_self(
        "my-secret", me["kem_pub"],
        sealer_ed_priv_hex=me["ed_priv"], sealer_ed_pub_hex=me["ed_pub"],
        aad=ctx,
    )
    assert blob.v == 1, "v=1 must be set when aad is provided"
    # Must open with the same aad
    result = unseal(blob, me["kem_priv"], aad=ctx)
    assert result == b"my-secret"


def test_aad_v1_blob_requires_aad_on_open() -> None:
    """Opening a v=1 blob without aad must raise before any crypto (timing guard)."""
    me = _make_identity()
    blob = seal_to_self(
        "secret", me["kem_pub"],
        sealer_ed_priv_hex=me["ed_priv"], sealer_ed_pub_hex=me["ed_pub"],
        aad="some-context",
    )
    assert blob.v == 1
    with pytest.raises(ValueError, match="aad required"):
        unseal(blob, me["kem_priv"])  # no aad → must raise


def test_aad_wrong_context_fails_aead() -> None:
    """Opening a v=1 blob with the WRONG aad fails at AEAD authentication."""
    me = _make_identity()
    blob = seal_to_self(
        "secret", me["kem_pub"],
        sealer_ed_priv_hex=me["ed_priv"], sealer_ed_pub_hex=me["ed_pub"],
        aad="correct-context",
    )
    with pytest.raises(ValueError):
        unseal(blob, me["kem_priv"], aad="wrong-context")


def test_aad_blob_survives_dict_serialization() -> None:
    """v=1 round-trips through to_dict/from_dict correctly."""
    from starfish_keyring.seal import SealedBlob

    me = _make_identity()
    ctx = "spaces/sp-abc/keyring"
    blob = seal_to_self(
        "persist-me", me["kem_pub"],
        sealer_ed_priv_hex=me["ed_priv"], sealer_ed_pub_hex=me["ed_pub"],
        aad=ctx,
    )
    revived = SealedBlob.from_dict(blob.to_dict())
    assert revived.v == 1
    assert unseal_to_str(revived, me["kem_priv"], aad=ctx) == "persist-me"
    # Still rejects open without aad after round-trip
    with pytest.raises(ValueError, match="aad required"):
        unseal(revived, me["kem_priv"])


def test_no_aad_blob_v_is_none() -> None:
    """Blobs sealed without aad have v=None and open without aad."""
    me = _make_identity()
    blob = seal_to_self(
        "plain", me["kem_pub"],
        sealer_ed_priv_hex=me["ed_priv"], sealer_ed_pub_hex=me["ed_pub"],
    )
    assert blob.v is None
    d = blob.to_dict()
    assert "v" not in d, "v should be absent from dict when None (legacy compat)"
    assert unseal_to_str(blob, me["kem_priv"]) == "plain"


def test_empty_string_aad_behaves_like_no_aad() -> None:
    """aad="" is treated as no context (matches TS truthiness): the blob has no
    v=1 marker and round-trips via the no-aad open path — never a v=1 blob whose
    tag mixed in no AAD (which TS could never open)."""
    me = _make_identity()
    blob = seal_to_self(
        "empty-aad", me["kem_pub"],
        sealer_ed_priv_hex=me["ed_priv"], sealer_ed_pub_hex=me["ed_pub"],
        aad="",
    )
    assert blob.v is None
    assert "v" not in blob.to_dict()
    assert unseal_to_str(blob, me["kem_priv"]) == "empty-aad"


def test_aad_unseal_to_str() -> None:
    """unseal_to_str propagates aad correctly."""
    me = _make_identity()
    blob = seal_to_self(
        "string-secret", me["kem_pub"],
        sealer_ed_priv_hex=me["ed_priv"], sealer_ed_pub_hex=me["ed_pub"],
        aad="ctx",
    )
    assert unseal_to_str(blob, me["kem_priv"], aad="ctx") == "string-secret"


def test_aad_unseal_from_self() -> None:
    """unseal_from_self propagates aad correctly."""
    me = _make_identity()
    blob = seal_to_self(
        "self-ctx", me["kem_pub"],
        sealer_ed_priv_hex=me["ed_priv"], sealer_ed_pub_hex=me["ed_pub"],
        aad="my-context",
    )
    result = unseal_from_self(blob, kem_priv_hex=me["kem_priv"], ed_pub_hex=me["ed_pub"], aad="my-context")
    assert result == b"self-ctx"
