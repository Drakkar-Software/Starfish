"""Tests for v3.0 per-request Ed25519 signing.

Cross-language vector: tests/test-vectors/request-signature.json.
"""

import base64
import json
import pathlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from starfish_protocol.request_signing import (
    RequestSignature,
    is_within_clock_skew,
    request_signing_canonical_input,
    sign_request,
    verify_request_signature,
)

VECTORS_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent
    / "tests"
    / "test-vectors"
    / "request-signature.json"
)
VECTORS = json.loads(VECTORS_PATH.read_text())


def _derive_alice_dev_1_ed_priv_hex() -> str:
    """Replicate the test-vector generator's device-key chain inline."""
    ikm = b"alice-root-passphrase::alice-laptop"
    salt = b"starfish-device-sign-test-vector"
    info = b"ed25519"
    seed = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(ikm)
    return seed.hex()


def _derive_alice_dev_1_ed_pub_hex() -> str:
    priv = bytes.fromhex(_derive_alice_dev_1_ed_priv_hex())
    pub = Ed25519PrivateKey.from_private_bytes(priv).public_key().public_bytes_raw()
    return pub.hex()


# ─── Canonical input ─────────────────────────────────────────────────────────


def test_canonical_input_matches_vector_cases():
    for case in VECTORS["cases"]:
        body_bytes = case["bodyUtf8"].encode("utf-8")
        canon = request_signing_canonical_input(
            case["method"],
            case["pathAndQuery"],
            body_bytes,
            case["tsMs"],
            case["nonceBase64"],
            host=case.get("host"),
        )
        assert canon == case["canonicalSigningInput"], case["label"]


def test_canonical_input_empty_body_hash_is_sha256_of_empty_buffer():
    canon = request_signing_canonical_input("GET", "/x", b"", 0, "AA==")
    assert (
        '"b":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"'
        in canon
    )


def test_canonical_input_omits_host_emits_empty_string():
    canon = request_signing_canonical_input("GET", "/x", b"", 0, "AA==")
    assert '"h":""' in canon


def test_canonical_input_with_host_emits_host_value():
    canon = request_signing_canonical_input(
        "GET", "/x", b"", 0, "AA==", host="api.example.com"
    )
    assert '"h":"api.example.com"' in canon


# ─── Verify ──────────────────────────────────────────────────────────────────


def _find_case(label: str) -> dict:
    for c in VECTORS["cases"]:
        if c["label"] == label:
            return c
    raise KeyError(label)


def test_verify_pull_empty_body():
    c = _find_case("pull-empty-body")
    sig = RequestSignature(sig=c["signatureBase64"], ts=c["tsMs"], nonce=c["nonceBase64"])
    ok = verify_request_signature(
        c["method"],
        c["pathAndQuery"],
        c["bodyUtf8"].encode("utf-8"),
        sig,
        VECTORS["signer"]["edPub"],
        host=c.get("host"),
    )
    assert ok is True


def test_verify_push_json_body():
    c = _find_case("push-json-body")
    sig = RequestSignature(sig=c["signatureBase64"], ts=c["tsMs"], nonce=c["nonceBase64"])
    ok = verify_request_signature(
        c["method"],
        c["pathAndQuery"],
        c["bodyUtf8"].encode("utf-8"),
        sig,
        VECTORS["signer"]["edPub"],
        host=c.get("host"),
    )
    assert ok is True


def test_verify_rejects_wrong_signer():
    c = _find_case("wrong-signer")
    sig = RequestSignature(sig=c["signatureBase64"], ts=c["tsMs"], nonce=c["nonceBase64"])
    ok = verify_request_signature(
        c["method"],
        c["pathAndQuery"],
        c["bodyUtf8"].encode("utf-8"),
        sig,
        VECTORS["signer"]["edPub"],
        host=c.get("host"),
    )
    assert ok is False


def test_verify_rejects_host_mismatch():
    c = _find_case("host-mismatch")
    sig = RequestSignature(sig=c["signatureBase64"], ts=c["tsMs"], nonce=c["nonceBase64"])
    ok = verify_request_signature(
        c["method"],
        c["pathAndQuery"],
        c["bodyUtf8"].encode("utf-8"),
        sig,
        VECTORS["signer"]["edPub"],
        host=c["verifyHost"],
    )
    assert ok is False


def test_verify_host_mismatch_case_passes_when_rebuilt_with_signed_host():
    c = _find_case("host-mismatch")
    sig = RequestSignature(sig=c["signatureBase64"], ts=c["tsMs"], nonce=c["nonceBase64"])
    ok = verify_request_signature(
        c["method"],
        c["pathAndQuery"],
        c["bodyUtf8"].encode("utf-8"),
        sig,
        VECTORS["signer"]["edPub"],
        host=c["host"],
    )
    assert ok is True


# ─── Sign roundtrip ──────────────────────────────────────────────────────────


def test_sign_request_roundtrip_pull_empty_body():
    c = _find_case("pull-empty-body")
    dev_ed_priv_hex = _derive_alice_dev_1_ed_priv_hex()
    nonce_bytes = base64.b64decode(c["nonceBase64"])
    sig = sign_request(
        c["method"],
        c["pathAndQuery"],
        c["bodyUtf8"].encode("utf-8"),
        dev_ed_priv_hex,
        host=c.get("host"),
        ts=c["tsMs"],
        nonce=nonce_bytes,
    )
    assert sig.ts == c["tsMs"]
    assert sig.nonce == c["nonceBase64"]
    assert sig.sig == c["signatureBase64"]


def test_sign_request_roundtrip_push_json_body():
    c = _find_case("push-json-body")
    dev_ed_priv_hex = _derive_alice_dev_1_ed_priv_hex()
    nonce_bytes = base64.b64decode(c["nonceBase64"])
    sig = sign_request(
        c["method"],
        c["pathAndQuery"],
        c["bodyUtf8"].encode("utf-8"),
        dev_ed_priv_hex,
        host=c.get("host"),
        ts=c["tsMs"],
        nonce=nonce_bytes,
    )
    assert sig.ts == c["tsMs"]
    assert sig.nonce == c["nonceBase64"]
    assert sig.sig == c["signatureBase64"]


def test_sign_request_defaults_produce_verifiable_signature():
    dev_ed_priv_hex = _derive_alice_dev_1_ed_priv_hex()
    dev_ed_pub_hex = _derive_alice_dev_1_ed_pub_hex()
    sig = sign_request("POST", "/x", b"hello", dev_ed_priv_hex)
    assert sig.ts > 0
    assert isinstance(sig.nonce, str)
    assert isinstance(sig.sig, str)
    ok = verify_request_signature("POST", "/x", b"hello", sig, dev_ed_pub_hex)
    assert ok is True


# ─── Tampered-field negatives ────────────────────────────────────────────────


def test_verify_rejects_when_ts_is_bumped():
    dev_ed_priv_hex = _derive_alice_dev_1_ed_priv_hex()
    dev_ed_pub_hex = _derive_alice_dev_1_ed_pub_hex()
    ts = 1_700_000_000_000
    nonce = base64.b64decode("AAECAwQFBgcICQoLDA0ODw==")
    sig = sign_request("POST", "/x", b"hello", dev_ed_priv_hex, ts=ts, nonce=nonce)
    # Re-derive canonical with ts+1 → signature won't match.
    tampered = RequestSignature(sig=sig.sig, ts=ts + 1, nonce=sig.nonce)
    ok = verify_request_signature("POST", "/x", b"hello", tampered, dev_ed_pub_hex)
    assert ok is False


def test_verify_rejects_when_nonce_is_changed():
    dev_ed_priv_hex = _derive_alice_dev_1_ed_priv_hex()
    dev_ed_pub_hex = _derive_alice_dev_1_ed_pub_hex()
    ts = 1_700_000_000_000
    nonce = base64.b64decode("AAECAwQFBgcICQoLDA0ODw==")
    sig = sign_request("POST", "/x", b"hello", dev_ed_priv_hex, ts=ts, nonce=nonce)
    # A different nonce, same length.
    tampered = RequestSignature(sig=sig.sig, ts=sig.ts, nonce="EBESExQVFhcYGRobHB0eHw==")
    ok = verify_request_signature("POST", "/x", b"hello", tampered, dev_ed_pub_hex)
    assert ok is False


def test_verify_rejects_a_re_encoded_but_byte_equivalent_nonce():
    """The nonce is bound as the verbatim base64 STRING, not as decoded bytes.

    A padded and an unpadded base64 of the SAME 16 nonce bytes decode identically,
    but the canonical signing input embeds the string verbatim — so swapping one
    encoding for the other changes the signed material and fails verification. This
    is what keeps the string-keyed nonce cache safe: an attacker cannot re-encode a
    captured nonce onto a different cache key while keeping the signature valid (the
    sibling test above only changes the nonce to *different* bytes).
    """
    dev_ed_priv_hex = _derive_alice_dev_1_ed_priv_hex()
    dev_ed_pub_hex = _derive_alice_dev_1_ed_pub_hex()
    ts = 1_700_000_000_000
    nonce = base64.b64decode("AAECAwQFBgcICQoLDA0ODw==")
    sig = sign_request("POST", "/x", b"hello", dev_ed_priv_hex, ts=ts, nonce=nonce)
    assert sig.nonce.endswith("==")
    # Same 16 bytes, padding stripped → identical bytes, different STRING.
    unpadded = sig.nonce.rstrip("=")
    assert base64.b64decode(unpadded + "==") == nonce  # byte-equivalent
    tampered = RequestSignature(sig=sig.sig, ts=sig.ts, nonce=unpadded)
    ok = verify_request_signature("POST", "/x", b"hello", tampered, dev_ed_pub_hex)
    assert ok is False


def test_verify_rejects_when_body_is_tampered_same_length():
    dev_ed_priv_hex = _derive_alice_dev_1_ed_priv_hex()
    dev_ed_pub_hex = _derive_alice_dev_1_ed_pub_hex()
    ts = 1_700_000_000_000
    nonce = base64.b64decode("AAECAwQFBgcICQoLDA0ODw==")
    sig = sign_request("POST", "/x", b"hello", dev_ed_priv_hex, ts=ts, nonce=nonce)
    # Same length, last byte flipped.
    tampered_body = b"hellp"
    assert len(tampered_body) == len(b"hello")
    ok = verify_request_signature("POST", "/x", tampered_body, sig, dev_ed_pub_hex)
    assert ok is False


# ─── Clock skew ──────────────────────────────────────────────────────────────


def test_clock_skew_within_default():
    now = 1_700_000_000_000
    assert is_within_clock_skew(now + 200_000, now) is True
    assert is_within_clock_skew(now - 200_000, now) is True


def test_clock_skew_outside_default():
    now = 1_700_000_000_000
    assert is_within_clock_skew(now + 600_000, now) is False
    assert is_within_clock_skew(now - 600_000, now) is False


def test_clock_skew_custom_max():
    now = 1_700_000_000_000
    assert is_within_clock_skew(now + 1_000, now, max_skew_ms=500) is False
    assert is_within_clock_skew(now + 200, now, max_skew_ms=500) is True


def test_clock_skew_inclusive_at_exact_boundary():
    # The gate is `abs(req_ts - now_ms) <= max_skew_ms`, so a ts exactly max_skew
    # away is accepted and one ms further is rejected. Pinned both sides so an
    # off-by-one (`<` vs `<=`) can't slip in. Mirrors request-signing.test.ts.
    now = 1_700_000_000_000
    assert is_within_clock_skew(now + 300_000, now) is True
    assert is_within_clock_skew(now - 300_000, now) is True
    assert is_within_clock_skew(now + 300_001, now) is False
    assert is_within_clock_skew(now - 300_001, now) is False


# ─── Host binding ────────────────────────────────────────────────────────────


def test_host_binding_sign_verify_passes_when_host_matches():
    priv_hex = _derive_alice_dev_1_ed_priv_hex()
    pub_hex = _derive_alice_dev_1_ed_pub_hex()
    sig = sign_request("POST", "/x", b"hello", priv_hex, host="api.example.com")
    ok = verify_request_signature(
        "POST", "/x", b"hello", sig, pub_hex, host="api.example.com"
    )
    assert ok is True


def test_host_binding_verify_fails_when_host_differs():
    priv_hex = _derive_alice_dev_1_ed_priv_hex()
    pub_hex = _derive_alice_dev_1_ed_pub_hex()
    sig = sign_request("POST", "/x", b"hello", priv_hex, host="api.example.com")
    ok = verify_request_signature(
        "POST", "/x", b"hello", sig, pub_hex, host="evil.example.com"
    )
    assert ok is False


def test_host_binding_sign_verify_passes_when_host_omitted_on_both_sides():
    priv_hex = _derive_alice_dev_1_ed_priv_hex()
    pub_hex = _derive_alice_dev_1_ed_pub_hex()
    sig = sign_request("POST", "/x", b"hello", priv_hex)
    ok = verify_request_signature("POST", "/x", b"hello", sig, pub_hex)
    assert ok is True


def test_host_binding_verify_fails_when_sign_omits_but_verify_provides_host():
    priv_hex = _derive_alice_dev_1_ed_priv_hex()
    pub_hex = _derive_alice_dev_1_ed_pub_hex()
    sig = sign_request("POST", "/x", b"hello", priv_hex)
    ok = verify_request_signature(
        "POST", "/x", b"hello", sig, pub_hex, host="api.example.com"
    )
    assert ok is False


def test_host_binding_verify_fails_when_sign_provides_but_verify_omits_host():
    priv_hex = _derive_alice_dev_1_ed_priv_hex()
    pub_hex = _derive_alice_dev_1_ed_pub_hex()
    sig = sign_request("POST", "/x", b"hello", priv_hex, host="api.example.com")
    ok = verify_request_signature("POST", "/x", b"hello", sig, pub_hex)
    assert ok is False


def test_sign_and_verify_patch_request_roundtrip():
    """PATCH must be supported by SignableMethod (parity with TS)."""
    priv_hex = _derive_alice_dev_1_ed_priv_hex()
    sig = sign_request(
        "PATCH",
        "/x",
        b"",
        priv_hex,
    )
    assert isinstance(sig.sig, str)
    ok = verify_request_signature(
        "PATCH", "/x", b"", sig, VECTORS["signer"]["edPub"]
    )
    assert ok is True
