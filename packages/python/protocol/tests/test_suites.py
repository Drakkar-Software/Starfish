"""Crypto-suite registry + secp256k1-schnorr cross-language conformance.

Mirror of TS ``tests/suites.test.ts``. Loads ``suite-secp256k1.json`` (shared
with the TS test) to prove @noble (TS) and coincurve (Python) sign/verify
byte-identical, plus the downgrade guard and cross-suite delegation canary.
"""

import base64
import hashlib
import json
import pathlib

import pytest

from starfish_protocol.cap import (
    assert_cap_cert_well_formed,
    recipient_kem,
    sign_cap_cert,
    user_id_from_pub_hex,
    verify_cap_cert,
    verify_cap_cert_signature,
)
from starfish_protocol.request_signing import (
    sign_request,
    verify_request_signature,
)
from starfish_protocol.suites import (
    DEFAULT_ALG,
    get_suite,
    is_alg,
    suite_has_separate_kem,
)

_VEC = json.loads(
    (
        pathlib.Path(__file__).parent.parent.parent.parent.parent
        / "tests"
        / "test-vectors"
        / "suite-secp256k1.json"
    ).read_text()
)

_ECDH_VEC = json.loads(
    (
        pathlib.Path(__file__).parent.parent.parent.parent.parent
        / "tests"
        / "test-vectors"
        / "suite-secp256k1-ecdh.json"
    ).read_text()
)


def test_is_alg_recognizes_both_and_rejects_junk() -> None:
    assert is_alg("ed25519") is True
    assert is_alg("secp256k1-schnorr") is True
    assert is_alg("rsa") is False
    assert is_alg(None) is False


def test_get_suite_resolves_and_fails_closed() -> None:
    assert get_suite("ed25519").alg == "ed25519"
    assert get_suite("secp256k1-schnorr").alg == "secp256k1-schnorr"
    assert get_suite(None).alg == DEFAULT_ALG
    with pytest.raises(ValueError):
        get_suite("rsa")
    # Only None defaults; an empty string fails closed (matches TS getSuite("")),
    # so a tampered "" alg tag is rejected identically in both languages.
    with pytest.raises(ValueError):
        get_suite("")


def test_suite_has_separate_kem() -> None:
    assert suite_has_separate_kem("ed25519") is True
    assert suite_has_separate_kem("secp256k1-schnorr") is False


def test_recipient_kem_resolution() -> None:
    # ed25519 subject → separate X25519 subKem.
    assert recipient_kem(
        {"issAlg": "ed25519", "subAlg": "ed25519", "sub": "aa" * 32, "subKem": "bb" * 32}
    ) == ("bb" * 32, "ed25519")
    # same-suite secp256k1 → sub IS the KEM key (no subKem).
    assert recipient_kem(
        {"issAlg": "secp256k1-schnorr", "subAlg": "secp256k1-schnorr", "sub": "cc" * 32}
    ) == ("cc" * 32, "secp256k1-schnorr")
    # mixed: ed25519 sign + explicit secp256k1 subKemAlg → distinct subKem.
    assert recipient_kem(
        {"issAlg": "ed25519", "subAlg": "ed25519", "subKemAlg": "secp256k1-schnorr",
         "sub": "aa" * 32, "subKem": "dd" * 32}
    ) == ("dd" * 32, "secp256k1-schnorr")
    # kemAlg falls back through subAlg to issAlg.
    assert recipient_kem({"issAlg": "secp256k1-schnorr", "sub": "cc" * 32})[1] == "secp256k1-schnorr"
    # subject-less (audience) cap → raises.
    with pytest.raises(ValueError):
        recipient_kem({"issAlg": "ed25519"})


def test_secp256k1_kem_ecdh_conformance() -> None:
    # The secp256k1 KEM shared secret (x-coord of priv·lift_even(peer)) must match
    # the cross-language vector byte-for-byte and be symmetric in both directions.
    suite = get_suite("secp256k1-schnorr")
    for c in _ECDH_VEC["cases"]:
        assert suite.kem_public(c["aPrivHex"]) == c["aPubHex"]
        assert suite.kem_public(c["bPrivHex"]) == c["bPubHex"]
        assert suite.derive_shared_secret(c["aPrivHex"], c["bPubHex"]).hex() == c["sharedHex"]
        assert suite.derive_shared_secret(c["bPrivHex"], c["aPubHex"]).hex() == c["sharedHex"]


def test_secp256k1_kem_vector_has_odd_peer() -> None:
    # At least one odd-y peer locks the even-y lift convention against a regression.
    parities = [p for c in _ECDH_VEC["cases"] for p in (c["aParity"], c["bParity"])]
    assert "odd" in parities


def test_secp256k1_kem_fails_closed_on_bad_peer() -> None:
    # 0xFF…FF is >= p, so no curve point has it as an x — lift must raise, not
    # silently return a usable secret.
    suite = get_suite("secp256k1-schnorr")
    with pytest.raises(Exception):
        suite.derive_shared_secret(_ECDH_VEC["cases"][0]["aPrivHex"], "ff" * 32)


def test_x25519_kem_fails_closed_on_low_order_peer() -> None:
    # An all-zero peer is a low-order point; derive_shared_secret must reject it
    # (cryptography rejects at the lib layer — the contract is fail-closed,
    # whichever layer fires).
    suite = get_suite("ed25519")
    with pytest.raises(Exception):
        suite.derive_shared_secret(_ECDH_VEC["cases"][0]["aPrivHex"], "00" * 32)


def test_assert_usable_shared_secret_backstop() -> None:
    # Direct coverage of the degenerate-point guard so a refactor that drops it
    # fails a test. PRIMARY defense for secp256k1 (a valid point never has an
    # all-zero x); defense-in-depth for X25519 (RFC 7748 §6.1).
    from starfish_protocol.suites._kem import assert_usable_shared_secret

    with pytest.raises(Exception, match="zero KEM shared secret"):
        assert_usable_shared_secret(bytes(32))
    assert_usable_shared_secret(bytes(31) + b"\x01")  # one non-zero byte → ok


def test_verify_fails_closed_on_malformed_inputs() -> None:
    # CryptoSuite contract: ``verify`` NEVER raises — every decode/curve/length
    # error (and a missing optional C extension) must fail closed to False, not
    # crash the request with a 500 + logged traceback. secp256k1.py documents the
    # DoS rationale (unauthenticated log amplification). The cross-language vector
    # only exercises wrong-sig-with-valid-lengths (case 4), so the throw paths are
    # otherwise untested. If this test threw instead of returning False, it fails.
    msg = b"m"
    for alg in ("ed25519", "secp256k1-schnorr"):
        suite = get_suite(alg)
        assert suite.verify(bytes(64), msg, "zz" * 32) is False  # non-hex pubkey
        assert suite.verify(bytes(64), msg, "ab") is False  # wrong-length pubkey
        assert suite.verify(bytes(64), msg, "") is False  # empty pubkey
        assert suite.verify(bytes(3), msg, "aa" * 32) is False  # wrong-length sig


def test_subkem_presence_is_suite_driven() -> None:
    # The well-formedness of ``subKem`` is decided by the SUBJECT's suite, not a
    # constant: ed25519 has a separate X25519 KEM key (subKem REQUIRED), secp256k1
    # reuses its one key (subKem FORBIDDEN). The delegation canary covers only the
    # positive secp256k1-without-subKem path; these pin the two reject branches.
    iss, sub = "aa" * 32, "bb" * 32
    base = {
        "v": 1,
        "kind": "member",
        "iss": iss,
        "issUserId": user_id_from_pub_hex(iss),
        "sub": sub,
        "subUserId": user_id_from_pub_hex(sub),
        "scope": {"ops": ["read"], "collections": ["x"]},
        "nbf": 1000,
        "exp": 2000,
        "nonce": base64.b64encode(bytes([1]) * 16).decode("ascii"),
    }

    def code_of(cert: dict) -> str:
        try:
            assert_cap_cert_well_formed(cert)
            return "NO_THROW"
        except ValueError as e:
            return e.args[0] if e.args else "ValueError"

    ed = {**base, "issAlg": "ed25519", "subAlg": "ed25519"}
    assert code_of(ed) == "malformed-shape"  # separate-KEM suite, subKem missing
    assert code_of({**ed, "subKem": "cc" * 32}) == "NO_THROW"

    secp = {**base, "issAlg": "secp256k1-schnorr", "subAlg": "secp256k1-schnorr"}
    assert code_of(secp) == "NO_THROW"  # one-key suite, subKem correctly absent
    assert code_of({**secp, "subKem": "cc" * 32}) == "malformed-shape"  # forbidden


def test_secp256k1_vector_verify_and_resign() -> None:
    suite = get_suite("secp256k1-schnorr")
    for case in _VEC["cases"]:
        msg = case["messageUtf8"].encode("utf-8")
        sig = bytes.fromhex(case["signatureHex"])
        assert suite.verify(sig, msg, case["pubHex"]) is case["expectVerify"]
        if case["expectVerify"]:
            # Deterministic (aux_rand=0) → re-sign reproduces the bytes exactly.
            assert suite.sign(msg, case["privHex"]).hex() == case["signatureHex"]


def test_request_signature_downgrade_guard() -> None:
    case = _VEC["cases"][0]
    sig = sign_request("GET", "/x", b"", case["privHex"], alg="secp256k1-schnorr")
    assert verify_request_signature("GET", "/x", b"", sig, case["pubHex"]) is True
    # Swapping the declared alg changes the canonical input → verify fails.
    from dataclasses import replace

    swapped = replace(sig, alg="ed25519")
    assert verify_request_signature("GET", "/x", b"", swapped, case["pubHex"]) is False


def test_cross_suite_delegation_canary() -> None:
    # ed25519 issuer mints a member cap for a secp256k1 subject; the cap verifies
    # under issAlg=ed25519 and the subject signs requests under subAlg=secp256k1.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    iss_priv_hex = "ad5a91be445615ad20823ff607df3d69f9fabc7a2f3f6cfce79dd6b8827e1a89"
    iss_pub = (
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex(iss_priv_hex))
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    iss_pub_hex = iss_pub.hex()
    iss_user_id = hashlib.sha256(iss_pub).hexdigest()[:32]

    sub = _VEC["cases"][0]
    sub_user_id = hashlib.sha256(bytes.fromhex(sub["pubHex"])).hexdigest()[:32]

    unsigned = {
        "v": 1,
        "kind": "member",
        "issAlg": "ed25519",
        "subAlg": "secp256k1-schnorr",
        "iss": iss_pub_hex,
        "issUserId": iss_user_id,
        "sub": sub["pubHex"],
        # No subKem — secp256k1 reuses one key.
        "subUserId": sub_user_id,
        "scope": {
            "ops": ["read"],
            "collections": ["shared"],
            "paths": ["shared/*"],
        },
        "nbf": 1_747_000_000,
        "exp": 1_747_000_000 + 3600,
        "nonce": base64.b64encode(bytes([9]) * 16).decode("ascii"),
    }
    cert = sign_cap_cert(unsigned, iss_priv_hex)
    assert verify_cap_cert_signature(cert) is True
    assert verify_cap_cert(cert, now=cert["nbf"] + 5)["ok"] is True

    req_sig = sign_request("GET", "/pull/shared", b"", sub["privHex"], alg=cert["subAlg"])
    assert req_sig.alg == "secp256k1-schnorr"
    assert verify_request_signature("GET", "/pull/shared", b"", req_sig, cert["sub"]) is True


def test_subalg_absent_defaults_to_issalg() -> None:
    # A same-suite cap that omits subAlg on the wire. The subject signs under
    # issAlg (subAlg or issAlg) and that request signature must verify — guards
    # the client/server tolerant-reader fallback against a regression. Mirror of
    # TS "subAlg absent => subject suite defaults to issAlg".
    sub = _VEC["cases"][0]
    iss_pub_hex = sub["pubHex"]
    iss_priv_hex = sub["privHex"]
    iss_user_id = hashlib.sha256(bytes.fromhex(iss_pub_hex)).hexdigest()[:32]
    unsigned = {
        "v": 1,
        "kind": "device",
        "issAlg": "secp256k1-schnorr",
        # subAlg intentionally omitted → defaults to issAlg.
        "iss": iss_pub_hex,
        "issUserId": iss_user_id,
        "sub": iss_pub_hex,
        "scope": {"ops": ["read"], "collections": ["notes"], "paths": ["notes/**"]},
        "nbf": 1_747_000_000,
        "exp": 1_747_000_000 + 3600,
        "nonce": base64.b64encode(bytes([4]) * 16).decode("ascii"),
    }
    cert = sign_cap_cert(unsigned, iss_priv_hex)
    assert verify_cap_cert(cert, now=cert["nbf"] + 5)["ok"] is True
    req_alg = cert.get("subAlg") or cert["issAlg"]  # resolver-equivalent resolution
    assert req_alg == "secp256k1-schnorr"
    req_sig = sign_request("GET", "/pull/notes", b"", iss_priv_hex, alg=req_alg)
    assert verify_request_signature("GET", "/pull/notes", b"", req_sig, cert["sub"]) is True


_ISS = "aa" * 32


def _member(**overrides) -> dict:
    cert = {
        "v": 1,
        "kind": "member",
        "issAlg": "ed25519",
        "iss": _ISS,
        "issUserId": user_id_from_pub_hex(_ISS),
        "sub": "dd" * 32,
        "subUserId": user_id_from_pub_hex("dd" * 32),
        "scope": {"ops": ["read"], "collections": ["x"], "paths": ["x/*", "!x/_keyring", "!x/_members"]},
        "nbf": 1000,
        "exp": 2000,
        "nonce": base64.b64encode(bytes([1]) * 16).decode("ascii"),
    }
    cert.update(overrides)
    return cert


def _code(fn) -> str:
    try:
        fn()
        return "OK"
    except ValueError as e:
        return e.args[0] if e.args else "ValueError"


def test_subkemalg_secp_sign_ed25519_kem_requires_subkem() -> None:
    # secp256k1 signing + ed25519 (X25519) KEM → distinct subKem REQUIRED.
    assert _code(lambda: assert_cap_cert_well_formed(
        _member(subAlg="secp256k1-schnorr", subKemAlg="ed25519", subKem="ee" * 32)
    )) == "OK"
    assert _code(lambda: assert_cap_cert_well_formed(
        _member(subAlg="secp256k1-schnorr", subKemAlg="ed25519")  # subKem missing
    )) == "malformed-shape"


def test_subkemalg_ed25519_sign_secp_kem_requires_subkem() -> None:
    assert _code(lambda: assert_cap_cert_well_formed(
        _member(subAlg="ed25519", subKemAlg="secp256k1-schnorr", subKem="ff" * 32)
    )) == "OK"


def test_subkemalg_secp_same_suite_forbids_subkem() -> None:
    assert _code(lambda: assert_cap_cert_well_formed(_member(subAlg="secp256k1-schnorr"))) == "OK"
    assert _code(lambda: assert_cap_cert_well_formed(
        _member(subAlg="secp256k1-schnorr", subKem="ee" * 32)
    )) == "malformed-shape"


def test_audience_must_not_carry_subkemalg() -> None:
    aud = {
        "v": 1,
        "kind": "audience",
        "issAlg": "ed25519",
        "iss": _ISS,
        "issUserId": user_id_from_pub_hex(_ISS),
        "subKemAlg": "ed25519",
        "scope": {"ops": ["read"], "collections": ["b"], "paths": ["b/**"]},
        "nbf": 1000,
        "exp": 2000,
        "nonce": base64.b64encode(bytes([1]) * 16).decode("ascii"),
    }
    assert _code(lambda: assert_cap_cert_well_formed(aud)) == "audience-has-sub"


def test_rejects_unknown_subkemalg() -> None:
    assert _code(lambda: assert_cap_cert_well_formed(
        _member(subKemAlg="rsa", subKem="ee" * 32)
    )) == "malformed-shape"
