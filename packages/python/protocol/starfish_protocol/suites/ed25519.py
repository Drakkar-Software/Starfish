"""``ed25519`` suite — the original Starfish identity model: Ed25519 signing +
X25519 KEM (separate keys).

The sign/verify halves are a behavior-preserving extraction of the inline
``Ed25519PrivateKey`` / ``Ed25519PublicKey`` calls that previously lived in
``cap.py``, ``request_signing.py``, and ``revocation.py``; the KEM half is the
X25519 ECDH that previously lived inline in the keyring/pairing layers — moved
here byte-for-byte so existing wrap vectors are unchanged. Mirrors the
TypeScript ``packages/ts/protocol/src/suites/ed25519.ts``.
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

from starfish_protocol.suites._kem import assert_usable_shared_secret

_RAW = serialization.Encoding.Raw
_RAW_PUB = serialization.PublicFormat.Raw
_RAW_PRIV = serialization.PrivateFormat.Raw
_NO_ENC = serialization.NoEncryption()


class Ed25519Suite:
    alg = "ed25519"

    def sign(self, message: bytes, priv_hex: str) -> bytes:
        priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
        return priv.sign(message)

    def verify(self, sig: bytes, message: bytes, pub_hex: str) -> bool:
        # Catch every exception — the CryptoSuite contract is "verify never
        # raises"; any decode/curve/length error fails closed to False.
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
            pub.verify(sig, message)
            return True
        except Exception:
            return False

    def derive_shared_secret(self, priv_hex: str, peer_pub_hex: str) -> bytes:
        priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
        peer = X25519PublicKey.from_public_bytes(bytes.fromhex(peer_pub_hex))
        shared = priv.exchange(peer)
        assert_usable_shared_secret(shared)
        return shared

    def generate_kem_keypair(self) -> tuple[str, str]:
        priv = X25519PrivateKey.generate()
        priv_hex = priv.private_bytes(_RAW, _RAW_PRIV, _NO_ENC).hex()
        pub_hex = priv.public_key().public_bytes(_RAW, _RAW_PUB).hex()
        return (priv_hex, pub_hex)

    def kem_public(self, priv_hex: str) -> str:
        priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
        return priv.public_key().public_bytes(_RAW, _RAW_PUB).hex()
