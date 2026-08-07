"""Tests for sign_kem_sig / verify_kem_sig."""

from __future__ import annotations

import json
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from starfish_spaces.request_verify import sign_kem_sig, verify_kem_sig

_VECTOR_PATH = (
    pathlib.Path(__file__).parents[4] / "tests" / "test-vectors" / "spaces-kemsig.json"
)

# ── Fixed test fixtures (deterministic via key derivation) ────────────────────

# Minimal fixture: generate a fresh keypair each test run.
def _make_keypair():
    priv_key = Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    priv_hex = priv_key.private_bytes_raw().hex()
    pub_hex = pub_key.public_bytes_raw().hex()
    return priv_hex, pub_hex


def _make_kem_pub():
    """Generate a throwaway 32-byte KEM public key hex (X25519 pubkey placeholder)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    priv = X25519PrivateKey.generate()
    return priv.public_key().public_bytes_raw().hex()


# ── Core behaviour ────────────────────────────────────────────────────────────


def test_sign_kem_sig_returns_128_hex_chars():
    ed_priv, ed_pub = _make_keypair()
    kem_pub = _make_kem_pub()
    sig = sign_kem_sig(kem_pub, ed_priv)
    # Ed25519 signature is 64 bytes → 128 hex chars
    assert len(sig) == 128
    assert all(c in "0123456789abcdef" for c in sig)


def test_verify_kem_sig_valid():
    ed_priv, ed_pub = _make_keypair()
    kem_pub = _make_kem_pub()
    sig = sign_kem_sig(kem_pub, ed_priv)
    assert verify_kem_sig(ed_pub, kem_pub, sig) is True


def test_verify_kem_sig_wrong_ed_pub():
    ed_priv, ed_pub = _make_keypair()
    _, wrong_pub = _make_keypair()
    kem_pub = _make_kem_pub()
    sig = sign_kem_sig(kem_pub, ed_priv)
    assert verify_kem_sig(wrong_pub, kem_pub, sig) is False


def test_verify_kem_sig_tampered_sig():
    ed_priv, ed_pub = _make_keypair()
    kem_pub = _make_kem_pub()
    sig = sign_kem_sig(kem_pub, ed_priv)
    # Overwriting the last byte with a CONSTANT is a no-op whenever the real
    # signature already ends in that byte — 1 run in 256 tampered with nothing
    # and then failed, because verify correctly returned True. Flip the byte
    # relative to what is there so the input is always genuinely different.
    tampered = sig[:-2] + ("01" if sig[-2:] == "00" else "00")
    assert tampered != sig
    assert verify_kem_sig(ed_pub, kem_pub, tampered) is False


def test_verify_kem_sig_none():
    _, ed_pub = _make_keypair()
    kem_pub = _make_kem_pub()
    assert verify_kem_sig(ed_pub, kem_pub, None) is False


def test_verify_kem_sig_empty_string():
    _, ed_pub = _make_keypair()
    kem_pub = _make_kem_pub()
    assert verify_kem_sig(ed_pub, kem_pub, "") is False


def test_verify_kem_sig_malformed_hex():
    _, ed_pub = _make_keypair()
    kem_pub = _make_kem_pub()
    assert verify_kem_sig(ed_pub, kem_pub, "not-hex") is False


# ── Cross-language vector (optional) ─────────────────────────────────────────


@pytest.mark.skipif(not _VECTOR_PATH.exists(), reason="spaces-kemsig.json not yet generated")
def test_kemsig_vector():
    data = json.loads(_VECTOR_PATH.read_text())
    for case in data.get("sign", []):
        sig = sign_kem_sig(case["kemPub"], case["edPriv"])
        assert sig == case["sig"], f"sig mismatch in case {case.get('label', '?')}"

    for case in data.get("verify", []):
        result = verify_kem_sig(case["edPub"], case["kemPub"], case["sig"])
        assert result == case["expected"], f"verify mismatch in case {case.get('label', '?')}"
