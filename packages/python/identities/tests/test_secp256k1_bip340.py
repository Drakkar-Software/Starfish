"""Official BIP-340 Schnorr verification test vectors.

Drives ``_secp256k1.schnorr_verify`` against all 19 cases from
``tests/test-vectors/bip340-schnorr.json`` (sourced from the BIP-340 reference
CSV at https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv).

These vectors were specifically designed to catch buggy verifiers:
- Cases 5-14 cover adversarial inputs (pubkey not on curve, has_even_y(R)
  false, R=infinity, r≥p, s≥n, x-coord exceeds field size, etc.)
- Cases 15-18 cover variable-length messages (0, 1, 17, 100 bytes).
"""

from __future__ import annotations

import json
import pathlib

import pytest

from starfish_identities._secp256k1 import schnorr_verify

_VECTOR_PATH = (
    pathlib.Path(__file__).resolve().parents[4]
    / "tests"
    / "test-vectors"
    / "bip340-schnorr.json"
)
_VECTORS = json.loads(_VECTOR_PATH.read_text())
_CASES = _VECTORS["cases"]


@pytest.mark.parametrize("case", _CASES, ids=[f"bip340-{c['index']}" for c in _CASES])
def test_bip340_vector(case: dict) -> None:
    """Each official BIP-340 vector must produce the expected result."""
    pubkey = bytes.fromhex(case["pubkeyHex"])
    msg = bytes.fromhex(case["messageHex"])
    sig = bytes.fromhex(case["signatureHex"])
    expected = case["result"]
    comment = case.get("comment", "")

    got = schnorr_verify(pubkey, msg, sig)
    assert got == expected, (
        f"BIP-340 case {case['index']}: expected {expected}, got {got}"
        + (f" — {comment}" if comment else "")
    )


def test_bip340_negative_cases_all_return_false() -> None:
    """A quick sanity check: all cases with result=false return False."""
    negative = [c for c in _CASES if not c["result"]]
    assert len(negative) == 10, "vector file should have 10 negative cases"
    for case in negative:
        assert not schnorr_verify(
            bytes.fromhex(case["pubkeyHex"]),
            bytes.fromhex(case["messageHex"]),
            bytes.fromhex(case["signatureHex"]),
        ), f"Case {case['index']} should return False: {case.get('comment')}"


def test_bip340_positive_cases_all_return_true() -> None:
    """A quick sanity check: all cases with result=true return True."""
    positive = [c for c in _CASES if c["result"]]
    assert len(positive) == 9, "vector file should have 9 positive cases"
    for case in positive:
        assert schnorr_verify(
            bytes.fromhex(case["pubkeyHex"]),
            bytes.fromhex(case["messageHex"]),
            bytes.fromhex(case["signatureHex"]),
        ), f"Case {case['index']} should return True: {case.get('comment')}"


def test_schnorr_verify_never_raises() -> None:
    """schnorr_verify must return bool and never raise, even on garbage input."""
    junk_cases = [
        (b"", b"", b""),
        (b"\x00" * 32, b"\x00" * 32, b"\x00" * 64),
        (b"\xff" * 32, b"\xff" * 32, b"\xff" * 64),
        (b"\x00" * 31, b"\x00" * 32, b"\x00" * 64),   # wrong key length
        (b"\x00" * 32, b"\x00" * 32, b"\x00" * 63),   # wrong sig length
    ]
    for pub, msg, sig in junk_cases:
        result = schnorr_verify(pub, msg, sig)
        assert isinstance(result, bool), "schnorr_verify must return bool"
