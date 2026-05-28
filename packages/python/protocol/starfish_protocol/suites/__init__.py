"""Single signature + KEM suite for Starfish: Ed25519 sign + X25519 KEM.

Re-exports the primitive functions from :mod:`starfish_protocol.suites.ed25519`
so callers can import them via either path.
"""

from starfish_protocol.suites import ed25519
from starfish_protocol.suites.ed25519 import (
    assert_usable_shared_secret,
    derive_shared_secret,
    generate_kem_keypair,
    kem_public,
    sign,
    verify,
)

__all__ = [
    "ed25519",
    "sign",
    "verify",
    "derive_shared_secret",
    "generate_kem_keypair",
    "kem_public",
    "assert_usable_shared_secret",
]
