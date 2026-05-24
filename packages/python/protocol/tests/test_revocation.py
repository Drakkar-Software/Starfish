"""Cross-language conformance + round-trip tests for revocation-list building.

The canonical signing input is the byte-for-byte contract shared with the TS
implementation (Ed25519 is deterministic, so equal canonical input + key ⇒ equal
signature). We pin it against `tests/test-vectors/revocation-list.json` and check
the vector's own signatures verify (and the forged one does not), then round-trip
`build_revocation_list` with a fresh key.
"""

import base64
import json
import pathlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from starfish_protocol import (
    build_revocation_list,
    revocation_list_canonical_signing_input,
)

VECTORS_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent
    / "tests"
    / "test-vectors"
    / "revocation-list.json"
)
VECTORS = json.loads(VECTORS_PATH.read_text())


def _strip_sig(lst: dict) -> dict:
    return {k: v for k, v in lst.items() if k != "sig"}


def _ed_verify(pub_hex: str, sig_b64: str, message: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            base64.b64decode(sig_b64), message.encode("utf-8")
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def test_canonical_signing_input_matches_vector():
    """Our canonical serialization is byte-for-byte the vector's (gen1 + gen2)."""
    for gen in ("1", "2"):
        entry = VECTORS["generations"][gen]
        assert (
            revocation_list_canonical_signing_input(_strip_sig(entry["list"]))
            == entry["canonicalSigningInput"]
        )


def test_vector_signatures_verify_and_forged_fails():
    """The vector's signed lists verify against the issuer; the forged sig fails."""
    iss = VECTORS["issuer"]["edPub"]
    for gen in ("1", "2"):
        entry = VECTORS["generations"][gen]
        assert _ed_verify(iss, entry["list"]["sig"], entry["canonicalSigningInput"])
    forged = VECTORS["forged"]
    assert not _ed_verify(iss, forged["list"]["sig"], forged["canonicalSigningInput"])


def test_build_revocation_list_round_trip():
    """build_revocation_list derives issUserId = sha256(edPub)[:32] and self-verifies."""
    priv = Ed25519PrivateKey.generate()
    ed_priv_hex = priv.private_bytes_raw().hex()
    ed_pub_hex = priv.public_key().public_bytes_raw().hex()

    revoked = [{"sub": "aa" * 32, "nonce": base64.b64encode(b"\x00" * 16).decode(), "exp": 1999999999}]
    lst = build_revocation_list(ed_pub_hex, ed_priv_hex, generation=1, revoked=revoked)

    assert lst["v"] == 1
    assert lst["iss"] == ed_pub_hex
    assert len(lst["issUserId"]) == 32  # 128-bit truncated hash
    assert lst["generation"] == 1
    assert lst["revoked"] == revoked
    # The attached signature verifies against the canonical input we re-derive.
    assert _ed_verify(ed_pub_hex, lst["sig"], revocation_list_canonical_signing_input(lst))


def test_build_revocation_list_includes_optional_revoked_subjects():
    """revoked_subjects is included (and signed) only when supplied."""
    priv = Ed25519PrivateKey.generate()
    ed_priv_hex = priv.private_bytes_raw().hex()
    ed_pub_hex = priv.public_key().public_bytes_raw().hex()

    subjects = [{"sub": "bb" * 32, "exp": 1999999999}]
    lst = build_revocation_list(
        ed_pub_hex, ed_priv_hex, generation=3, revoked=[], revoked_subjects=subjects
    )
    assert lst["revokedSubjects"] == subjects
    assert _ed_verify(ed_pub_hex, lst["sig"], revocation_list_canonical_signing_input(lst))

    without = build_revocation_list(ed_pub_hex, ed_priv_hex, generation=4, revoked=[])
    assert "revokedSubjects" not in without
