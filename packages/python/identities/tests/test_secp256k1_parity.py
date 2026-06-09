"""Differential parity test: _secp256k1 vs. coincurve.

Runs a fixed seeded corpus — valid signatures plus a battery of adversarial
corruptions — through both coincurve and the pure-Python ``_secp256k1`` module,
and asserts identical results.  This is the "works exactly as before with
coincurve" guarantee.

Skipped automatically when coincurve is not installed (e.g. production
environments where it has been removed as a runtime dep).  To run:

    uv run --python 3.12 pytest -v tests/test_secp256k1_parity.py
    # or, with coincurve installed in the active env:
    pytest -v tests/test_secp256k1_parity.py
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
from typing import Iterator

import pytest

from starfish_identities import _secp256k1

_HAVE_COINCURVE = importlib.util.find_spec("coincurve") is not None
_SKIP = pytest.mark.skipif(not _HAVE_COINCURVE, reason="coincurve not installed")

# ── Corpus parameters ────────────────────────────────────────────────────────

# Fixed 32-byte seeds for reproducibility (no randomness).
_SEEDS: list[bytes] = [
    bytes([i]) * 32 for i in range(1, 9)          # 0x01*32 through 0x08*32
] + [
    bytes.fromhex("0b" * 32),                      # 0x0b*32
    (1).to_bytes(32, "big"),                       # scalar = 1
    (_secp256k1._N - 1).to_bytes(32, "big"),       # scalar = n−1 (max valid)
    bytes.fromhex("cacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacaca"),  # from project vector
]

# Fixed messages to sign (all 32 bytes for Schnorr; also used as ECDSA digests).
_MESSAGES: list[bytes] = [
    b"\x00" * 32,
    b"\xff" * 32,
    b"\x42" * 32,
    bytes(range(32)),
]

# Aux-rand for Schnorr (zero for determinism — matches project test vectors).
_AUX_RAND = b"\x00" * 32


# ── Helpers ──────────────────────────────────────────────────────────────────

def _coincurve_schnorr_verify(pub_bytes: bytes, msg: bytes, sig: bytes) -> bool:
    """Call coincurve PublicKeyXOnly.verify, treating any exception as False."""
    from coincurve.keys import PublicKeyXOnly  # noqa: PLC0415
    try:
        pub = PublicKeyXOnly(pub_bytes)
        return pub.verify(sig, msg)
    except Exception:
        return False


def _coincurve_schnorr_sign(seed: bytes, msg: bytes) -> tuple[bytes, bytes]:
    """Return (xonly_pubkey_bytes, sig_bytes) from coincurve."""
    from coincurve import PrivateKey  # noqa: PLC0415
    from coincurve.keys import PublicKeyXOnly  # noqa: PLC0415

    priv = PrivateKey(seed)
    sig = priv.sign_schnorr(msg, _AUX_RAND)
    pub_bytes = PublicKeyXOnly.from_secret(seed).format()
    return pub_bytes, sig


def _corruptions(sig: bytes, pub_bytes: bytes, msg: bytes) -> Iterator[tuple[str, bytes, bytes, bytes]]:
    """Yield (description, pub, msg, sig) for a battery of corruptions."""
    # Flip each byte of the signature
    for i in range(len(sig)):
        corrupted = bytearray(sig)
        corrupted[i] ^= 0xFF
        yield f"flip_sig_byte_{i}", pub_bytes, msg, bytes(corrupted)
    # Flip first byte of pubkey
    corrupted_pub = bytearray(pub_bytes)
    corrupted_pub[0] ^= 0xFF
    yield "flip_pub_byte_0", bytes(corrupted_pub), msg, sig
    # Flip last byte of pubkey
    corrupted_pub = bytearray(pub_bytes)
    corrupted_pub[-1] ^= 0xFF
    yield "flip_pub_byte_last", bytes(corrupted_pub), msg, sig
    # Flip one byte of message
    corrupted_msg = bytearray(msg)
    corrupted_msg[0] ^= 0xFF
    yield "flip_msg_byte_0", pub_bytes, bytes(corrupted_msg), sig
    # r = 0 (all zeros)
    yield "r_zero", pub_bytes, msg, b"\x00" * 32 + sig[32:]
    # r = p (field size)
    p_bytes = _secp256k1._P.to_bytes(32, "big")
    yield "r_equals_p", pub_bytes, msg, p_bytes + sig[32:]
    # s = n (curve order)
    n_bytes = _secp256k1._N.to_bytes(32, "big")
    yield "s_equals_n", pub_bytes, msg, sig[:32] + n_bytes
    # all-zero signature
    yield "all_zero_sig", pub_bytes, msg, b"\x00" * 64
    # all-zero pubkey (not on curve)
    yield "zero_pubkey", b"\x00" * 32, msg, sig
    # pubkey = p+1 (exceeds field size)
    p_plus1 = (_secp256k1._P + 1).to_bytes(32, "big")
    yield "pubkey_gt_p", p_plus1, msg, sig


# ── Schnorr parity tests ─────────────────────────────────────────────────────

@_SKIP
def test_schnorr_valid_signatures_agree() -> None:
    """Valid signatures: both coincurve and _secp256k1 return True."""
    for seed in _SEEDS:
        for msg in _MESSAGES:
            pub_bytes, sig = _coincurve_schnorr_sign(seed, msg)
            coincurve_result = _coincurve_schnorr_verify(pub_bytes, msg, sig)
            our_result = _secp256k1.schnorr_verify(pub_bytes, msg, sig)
            assert coincurve_result is True, f"coincurve rejected its own sig (seed={seed[:4].hex()}, msg={msg[:4].hex()})"
            assert our_result is True, f"_secp256k1 rejected a valid sig (seed={seed[:4].hex()}, msg={msg[:4].hex()})"


@_SKIP
def test_schnorr_corruptions_agree() -> None:
    """Corrupted signatures: coincurve and _secp256k1 agree on every rejection."""
    # Use a smaller subset for corruptions to keep the test fast
    for seed in _SEEDS[:4]:
        for msg in _MESSAGES[:2]:
            pub_bytes, sig = _coincurve_schnorr_sign(seed, msg)
            for desc, cp, cm, cs in _corruptions(sig, pub_bytes, msg):
                cc = _coincurve_schnorr_verify(cp, cm, cs)
                oc = _secp256k1.schnorr_verify(cp, cm, cs)
                assert cc == oc, (
                    f"Schnorr parity mismatch [{desc}]: "
                    f"coincurve={cc}, ours={oc} "
                    f"(seed={seed[:4].hex()}, msg={msg[:4].hex()})"
                )


@_SKIP
def test_schnorr_project_vectors_agree() -> None:
    """Project secp256k1 bootstrap test vectors: both implementations agree."""
    vector_path = (
        pathlib.Path(__file__).resolve().parents[4]
        / "tests" / "test-vectors" / "identity-derivation-secp256k1.json"
    )
    cases = json.loads(vector_path.read_text())["cases"]
    for case in cases:
        pub_bytes = bytes.fromhex(case["secpPubHex"])
        sig = bytes.fromhex(case["signatureHex"])
        from starfish_identities.identity import SECP256K1_BOOTSTRAP_CHALLENGE  # noqa: PLC0415
        cc = _coincurve_schnorr_verify(pub_bytes, SECP256K1_BOOTSTRAP_CHALLENGE, sig)
        oc = _secp256k1.schnorr_verify(pub_bytes, SECP256K1_BOOTSTRAP_CHALLENGE, sig)
        assert cc == oc, f"Schnorr parity mismatch on project vector {case['label']}"
        assert oc is True, f"_secp256k1 rejected valid project vector {case['label']}"


# ── ECDSA recovery parity tests ──────────────────────────────────────────────

def _coincurve_ecdsa_recover(digest: bytes, r: int, s: int, recid: int) -> bytes | None:
    """coincurve ECDSA recovery; returns uncompressed pubkey or None on failure."""
    from coincurve import PublicKey  # noqa: PLC0415
    compact = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    try:
        pub = PublicKey.from_signature_and_message(
            compact + bytes([recid]), digest, hasher=None
        )
        return pub.format(compressed=False)
    except Exception:
        return None


@_SKIP
def test_ecdsa_recovery_valid_agrees() -> None:
    """Valid ECDSA signatures: both implementations recover the same pubkey."""
    from coincurve import PrivateKey  # noqa: PLC0415

    for seed in _SEEDS:
        priv = PrivateKey(seed)
        for digest in _MESSAGES:
            # sign_recoverable returns r‖s (64 bytes) + recid (1 byte, last byte)
            raw = priv.sign_recoverable(digest, hasher=None)
            r = int.from_bytes(raw[:32], "big")
            s = int.from_bytes(raw[32:64], "big")
            recid = raw[64]

            expected = _coincurve_ecdsa_recover(digest, r, s, recid)
            assert expected is not None, "coincurve failed to recover its own sig"

            try:
                got = _secp256k1.ecdsa_recover_pubkey(digest, r, s, recid)
            except ValueError as exc:
                pytest.fail(f"_secp256k1 raised on valid sig (seed={seed[:4].hex()}): {exc}")

            assert got == expected, (
                f"ECDSA recovery mismatch (seed={seed[:4].hex()}, "
                f"digest={digest[:4].hex()}, recid={recid})"
            )


@_SKIP
def test_ecdsa_recovery_project_evm_vectors_agree() -> None:
    """EVM bootstrap test vectors: both implementations recover the same pubkey."""
    from starfish_identities.identity import _eip191_digest, EVM_BOOTSTRAP_CHALLENGE  # noqa: PLC0415

    vector_path = (
        pathlib.Path(__file__).resolve().parents[4]
        / "tests" / "test-vectors" / "identity-derivation-evm.json"
    )
    cases = json.loads(vector_path.read_text())["cases"]
    for case in cases:
        sig_bytes = bytes.fromhex(case["signatureHex"].removeprefix("0x"))
        challenge = case.get("challenge", EVM_BOOTSTRAP_CHALLENGE)
        digest = _eip191_digest(challenge.encode("utf-8"))
        v = sig_bytes[64]
        recid = v - 27 if v >= 27 else v
        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:64], "big")

        expected = _coincurve_ecdsa_recover(digest, r, s, recid)
        assert expected is not None, f"coincurve failed on EVM vector {case['label']}"

        got = _secp256k1.ecdsa_recover_pubkey(digest, r, s, recid)
        assert got == expected, f"ECDSA recovery mismatch on EVM vector {case['label']}"


def test_ecdsa_recovery_invalid_recid_raises() -> None:
    """recid not in {0,1} must raise ValueError (no coincurve dependency)."""
    digest = b"\x42" * 32
    r, s = 1, 1
    for bad_recid in (2, 3):
        with pytest.raises(ValueError, match="recid"):
            _secp256k1.ecdsa_recover_pubkey(digest, r, s, bad_recid)


def test_ecdsa_recovery_out_of_range_r_raises() -> None:
    """r = 0 and r = n must raise ValueError (no coincurve dependency)."""
    digest = b"\x42" * 32
    for bad_r in (0, _secp256k1._N, _secp256k1._N + 1):
        with pytest.raises(ValueError, match="r out of range"):
            _secp256k1.ecdsa_recover_pubkey(digest, bad_r, 1, 0)


def test_ecdsa_recovery_out_of_range_s_raises() -> None:
    """s = 0 and s = n must raise ValueError (no coincurve dependency)."""
    digest = b"\x42" * 32
    for bad_s in (0, _secp256k1._N, _secp256k1._N + 1):
        with pytest.raises(ValueError, match="s out of range"):
            _secp256k1.ecdsa_recover_pubkey(digest, 1, bad_s, 0)
