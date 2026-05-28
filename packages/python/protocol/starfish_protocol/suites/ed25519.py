"""ed25519 primitives — the single signature + KEM suite Starfish speaks on the
wire. Ed25519 for signing; X25519 for the KEM half (the two are separate keys).

Callers pass keys as lowercase hex; this module owns the hex↔bytes conversion.
``verify`` never raises — it returns ``False`` on any decode/curve error so
callers fail closed.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

_RAW = serialization.Encoding.Raw
_RAW_PUB = serialization.PublicFormat.Raw
_RAW_PRIV = serialization.PrivateFormat.Raw
_NO_ENC = serialization.NoEncryption()


def _assert_usable_shared_secret(secret: bytes) -> None:
    """Reject the all-zero X25519 shared secret produced against a low-order
    point (RFC 7748 §6.1). The wrap key derived from it would be predictable —
    fail closed."""
    if not any(secret):
        raise ValueError("Rejected zero KEM shared secret (degenerate point)")


def sign(message: bytes, priv_hex: str) -> bytes:
    """Sign ``message`` with the signer's Ed25519 private key (hex)."""
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    return priv.sign(message)


def verify(sig: bytes, message: bytes, pub_hex: str) -> bool:
    """Verify ``sig`` over ``message`` against ``pub_hex``. Returns ``False``,
    never raises."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
        pub.verify(sig, message)
        return True
    except Exception:
        return False


def derive_shared_secret(priv_hex: str, peer_pub_hex: str) -> bytes:
    """X25519 ECDH: derive a 32-byte shared secret. Raises on a degenerate result."""
    priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    peer = X25519PublicKey.from_public_bytes(bytes.fromhex(peer_pub_hex))
    shared = priv.exchange(peer)
    _assert_usable_shared_secret(shared)
    return shared


def generate_kem_keypair() -> tuple[str, str]:
    """Generate a fresh ephemeral X25519 keypair, returning ``(priv_hex, pub_hex)``."""
    priv = X25519PrivateKey.generate()
    priv_hex = priv.private_bytes(_RAW, _RAW_PRIV, _NO_ENC).hex()
    pub_hex = priv.public_key().public_bytes(_RAW, _RAW_PUB).hex()
    return (priv_hex, pub_hex)


def kem_public(priv_hex: str) -> str:
    """Derive the X25519 public key (hex) from a private key (hex)."""
    priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    return priv.public_key().public_bytes(_RAW, _RAW_PUB).hex()


def assert_usable_shared_secret(secret: bytes) -> None:
    """Public alias — kept exported for downstream packages that imported the
    helper from the suites layer."""
    _assert_usable_shared_secret(secret)
