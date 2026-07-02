"""ed25519 suite primitive tests (Python mirror of TS ``tests/suites.test.ts``)."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

import pytest

from starfish_protocol.suites import ed25519 as ed25519_suite


_RAW = serialization.Encoding.Raw
_RAW_PUB = serialization.PublicFormat.Raw
_RAW_PRIV = serialization.PrivateFormat.Raw
_NO_ENC = serialization.NoEncryption()


def test_sign_verify_round_trip() -> None:
    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes(_RAW, _RAW_PRIV, _NO_ENC).hex()
    pub_hex = priv.public_key().public_bytes(_RAW, _RAW_PUB).hex()
    message = b"hello starfish"
    sig = ed25519_suite.sign(message, priv_hex)
    assert ed25519_suite.verify(sig, message, pub_hex) is True


def test_verify_fails_closed_on_malformed_inputs() -> None:
    m = b"m"
    assert ed25519_suite.verify(bytes(64), m, "abc") is False
    assert ed25519_suite.verify(bytes(64), m, "ab") is False
    assert ed25519_suite.verify(bytes(64), m, "") is False
    assert ed25519_suite.verify(bytes(3), m, "aa" * 32) is False


def test_verify_rejects_hex_with_embedded_whitespace() -> None:
    # bytes.fromhex silently strips ASCII whitespace, so a key hex with embedded
    # spaces would be accepted by Python but rejected by TS (regex ^[0-9a-fA-F]*$)
    # — a cross-language accept/reject split on the inputs feeding verification.
    # A real signing keypair whose pub hex is corrupted with a space must fail.
    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes(_RAW, _RAW_PRIV, _NO_ENC).hex()
    pub_hex = priv.public_key().public_bytes(_RAW, _RAW_PUB).hex()
    sig = ed25519_suite.sign(b"m", priv_hex)
    spaced_pub = pub_hex[:8] + " " + pub_hex[8:]
    assert ed25519_suite.verify(sig, b"m", spaced_pub) is False


def test_x25519_ecdh_symmetric_and_rejects_low_order_peer() -> None:
    a_priv = X25519PrivateKey.generate()
    a_priv_hex = a_priv.private_bytes(_RAW, _RAW_PRIV, _NO_ENC).hex()
    a_pub_hex = a_priv.public_key().public_bytes(_RAW, _RAW_PUB).hex()
    b_priv = X25519PrivateKey.generate()
    b_priv_hex = b_priv.private_bytes(_RAW, _RAW_PRIV, _NO_ENC).hex()
    b_pub_hex = b_priv.public_key().public_bytes(_RAW, _RAW_PUB).hex()
    ab = ed25519_suite.derive_shared_secret(a_priv_hex, b_pub_hex)
    ba = ed25519_suite.derive_shared_secret(b_priv_hex, a_pub_hex)
    assert ab == ba
    with pytest.raises(Exception):
        ed25519_suite.derive_shared_secret(a_priv_hex, "00" * 32)


def test_assert_usable_shared_secret_rejects_zero() -> None:
    with pytest.raises(ValueError, match="zero KEM shared secret"):
        ed25519_suite.assert_usable_shared_secret(bytes(32))


def test_assert_usable_shared_secret_accepts_non_zero() -> None:
    s = bytearray(32)
    s[31] = 1
    ed25519_suite.assert_usable_shared_secret(bytes(s))
