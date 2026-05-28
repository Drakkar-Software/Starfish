"""Cross-type signature domain separation (mirrors domain-separation.test.ts)."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from starfish_protocol.append_author import append_author_canonical_input
from starfish_protocol.cap import cap_cert_canonical_signing_input
from starfish_protocol.request_signing import request_signing_canonical_input
from starfish_protocol.revocation import revocation_list_canonical_signing_input
from starfish_protocol.suites import ed25519 as ed25519_suite

_CAP_CANON = cap_cert_canonical_signing_input(
    {
        "v": 1,
        "kind": "device",
        "iss": "aa" * 32,
        "issUserId": "x",
        "scope": {"ops": ["read"], "collections": ["c"]},
        "nbf": 0,
        "exp": 1,
        "nonce": "AAAAAAAAAAAAAAAAAAAAAA==",
    }
)
_REQ_CANON = request_signing_canonical_input(
    "GET", "/pull/notes/x/0", b"", 1, "AAAAAAAAAAAAAAAAAAAAAA==", host="api.example.com"
)
_REV_CANON = revocation_list_canonical_signing_input(
    {"v": 1, "iss": "aa" * 32, "issUserId": "x", "generation": 1}
)
_APD_CANON = append_author_canonical_input("events", {"msg": "hello"})


def _ed_keypair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    ).hex()
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return priv_hex, pub_hex


def test_each_canonical_input_starts_with_its_own_domain_tag() -> None:
    assert _CAP_CANON.startswith("starfish-capcert-v1\n")
    assert _REQ_CANON.startswith("starfish-req-v1\n")
    assert _REV_CANON.startswith("starfish-revlist-v1\n")
    assert _APD_CANON.startswith("starfish-append-author-v1\n")
    tags = {c.split("\n", 1)[0] for c in (_CAP_CANON, _REQ_CANON, _REV_CANON, _APD_CANON)}
    assert len(tags) == 4


def test_cap_cert_signature_does_not_verify_as_request_or_revocation() -> None:
    priv_hex, pub_hex = _ed_keypair()
    sig = ed25519_suite.sign(_CAP_CANON.encode("utf-8"), priv_hex)
    assert ed25519_suite.verify(sig, _CAP_CANON.encode("utf-8"), pub_hex) is True
    assert ed25519_suite.verify(sig, _REQ_CANON.encode("utf-8"), pub_hex) is False
    assert ed25519_suite.verify(sig, _REV_CANON.encode("utf-8"), pub_hex) is False
    assert ed25519_suite.verify(sig, _APD_CANON.encode("utf-8"), pub_hex) is False


def test_append_author_signature_does_not_verify_as_cap_cert_or_request() -> None:
    priv_hex, pub_hex = _ed_keypair()
    sig = ed25519_suite.sign(_APD_CANON.encode("utf-8"), priv_hex)
    assert ed25519_suite.verify(sig, _APD_CANON.encode("utf-8"), pub_hex) is True
    assert ed25519_suite.verify(sig, _CAP_CANON.encode("utf-8"), pub_hex) is False
    assert ed25519_suite.verify(sig, _REQ_CANON.encode("utf-8"), pub_hex) is False
