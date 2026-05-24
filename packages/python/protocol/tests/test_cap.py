"""Tests for capability certificate canonical signing input."""

import json
import pathlib

from starfish_protocol.cap import cap_cert_canonical_signing_input

VECTORS_PATH = (
    pathlib.Path(__file__).parent.parent.parent.parent.parent
    / "tests"
    / "test-vectors"
    / "cap-cert.json"
)
VECTORS = json.loads(VECTORS_PATH.read_text())


def _strip_sig(cert: dict) -> dict:
    return {k: v for k, v in cert.items() if k != "sig"}


def test_device_cap_canonical_signing_input():
    cert = VECTORS["deviceCap"]["cert"]
    expected = VECTORS["deviceCap"]["canonicalSigningInput"]
    assert cap_cert_canonical_signing_input(_strip_sig(cert)) == expected


def test_member_cap_canonical_signing_input():
    cert = VECTORS["memberCap"]["cert"]
    expected = VECTORS["memberCap"]["canonicalSigningInput"]
    assert cap_cert_canonical_signing_input(_strip_sig(cert)) == expected


def test_forged_device_cap_canonical_signing_input():
    # Canonical input is independent of signature validity.
    cert = VECTORS["forgedDeviceCap"]["cert"]
    expected = VECTORS["forgedDeviceCap"]["canonicalSigningInput"]
    assert cap_cert_canonical_signing_input(_strip_sig(cert)) == expected


def test_cross_suite_member_cap_canonical_signing_input():
    # ed25519 issuer → secp256k1 subject (no subKem). Locks the canonical byte
    # placement of a non-default subAlg cross-language (TS counterpart in cap.test.ts).
    cert = VECTORS["crossSuiteMemberCap"]["cert"]
    expected = VECTORS["crossSuiteMemberCap"]["canonicalSigningInput"]
    assert cap_cert_canonical_signing_input(_strip_sig(cert)) == expected


def test_mixed_kem_member_cap_canonical_signing_input():
    # secp256k1 signing + decoupled ed25519 subKemAlg (distinct X25519 subKem).
    # Locks the canonical byte placement of subKemAlg cross-language.
    cert = VECTORS["mixedKemMemberCap"]["cert"]
    expected = VECTORS["mixedKemMemberCap"]["canonicalSigningInput"]
    assert cap_cert_canonical_signing_input(_strip_sig(cert)) == expected


def test_cap_cert_canonical_signing_input_strips_sig_when_present():
    # The function must strip `sig` from the input dict before serializing,
    # so passing the full cert (with sig) yields the same canonical string.
    cert = VECTORS["deviceCap"]["cert"]
    expected = VECTORS["deviceCap"]["canonicalSigningInput"]
    assert cap_cert_canonical_signing_input(cert) == expected
