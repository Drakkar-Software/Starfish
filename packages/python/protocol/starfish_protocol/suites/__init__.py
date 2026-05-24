"""Crypto-suite contract — the seam that lets one Starfish deployment carry
multiple identity models side by side, selectable per user.

A *suite* bundles the signature scheme (and, in later phases, the KEM and key
encoding) behind one ``alg`` tag. The tag travels inside every signed canonical
input (cap-certs, request signatures, revocation lists), so the algorithm an
attacker would have to forge against is itself authenticated — stripping or
downgrading ``alg`` changes the signed bytes and fails verification.

Two suites are shipped, each in its own module:

- :mod:`starfish_protocol.suites.ed25519`   — Ed25519 sign + X25519 KEM.
- :mod:`starfish_protocol.suites.secp256k1` — BIP-340 Schnorr + secp256k1 ECDH.

Only *implemented* suites are registered; :func:`get_suite` raises for an
unimplemented ``alg`` rather than silently falling back to a different curve.
Mirrors the TypeScript ``packages/ts/protocol/src/suites`` package.
"""

from __future__ import annotations

from typing import Literal, Optional, Protocol, runtime_checkable

try:
    from typing import TypeGuard
except ImportError:  # pragma: no cover - safety net for older runtimes
    from typing_extensions import TypeGuard  # type: ignore[assignment]

from starfish_protocol.suites.ed25519 import Ed25519Suite
from starfish_protocol.suites.secp256k1 import Secp256k1SchnorrSuite

# Algorithm identifier carried by every signed artifact.
Alg = Literal["ed25519", "secp256k1-schnorr"]

# Default suite for newly created identities when none is specified.
DEFAULT_ALG: Alg = "ed25519"


@runtime_checkable
class CryptoSuite(Protocol):
    """Signature + KEM operations for one suite. Keys are passed as lowercase
    hex; the suite owns the hex↔bytes conversion and any curve-specific
    encoding. ``verify`` must never raise — it returns ``False`` on any error.

    The KEM half operates on the suite's **KEM** keys, which may differ from its
    signing keys: ``ed25519`` pairs Ed25519 signing with a *separate* X25519 KEM
    key, while ``secp256k1-schnorr`` reuses its one secp256k1 key for both.
    """

    alg: Alg

    def sign(self, message: bytes, priv_hex: str) -> bytes: ...

    def verify(self, sig: bytes, message: bytes, pub_hex: str) -> bool: ...

    def derive_shared_secret(self, priv_hex: str, peer_pub_hex: str) -> bytes:
        """Derive a 32-byte shared secret from our KEM private key and a peer's
        KEM public key (both hex). Raises on an invalid peer point or a
        degenerate (all-zero) result so callers fail closed."""
        ...

    def generate_kem_keypair(self) -> tuple[str, str]:
        """Generate a fresh ephemeral KEM keypair, returning ``(priv_hex, pub_hex)``."""
        ...

    def kem_public(self, priv_hex: str) -> str:
        """Derive the KEM public key (hex) from a KEM private key (hex)."""
        ...


_REGISTRY: dict[str, CryptoSuite] = {
    "ed25519": Ed25519Suite(),
    "secp256k1-schnorr": Secp256k1SchnorrSuite(),
}


def is_alg(x: object) -> TypeGuard[Alg]:
    """True when ``x`` is a recognized ``alg`` string (implemented or not)."""
    return x in ("ed25519", "secp256k1-schnorr")


def suite_has_separate_kem(alg: Alg) -> bool:
    """Whether a suite uses a **separate** KEM key (distinct from its signing key).

    ``ed25519`` pairs Ed25519 signing with a separate X25519 KEM key, so a cap's
    ``subKem`` is required. ``secp256k1-schnorr`` reuses the one secp256k1 key
    for both signing and ECDH, so ``subKem`` is absent (the KEM key derives from
    ``sub``).
    """
    return alg == "ed25519"


def get_suite(alg: Optional[Alg] = None) -> CryptoSuite:
    """Resolve the suite for ``alg`` (defaulting to :data:`DEFAULT_ALG`).

    Raises ``ValueError`` if the algorithm is unknown or not yet implemented.
    Only ``None`` defaults (mirrors TS ``getSuite``'s ``?? DEFAULT_ALG``): an
    empty string or any other non-registered value fails closed, so a tampered
    (server-supplied) ``""`` alg tag is rejected identically in both languages
    rather than silently coerced to ed25519.
    """
    suite = _REGISTRY.get(DEFAULT_ALG if alg is None else alg)
    if suite is None:
        raise ValueError(f"crypto suite not available: {alg}")
    return suite


__all__ = [
    "Alg",
    "DEFAULT_ALG",
    "CryptoSuite",
    "is_alg",
    "suite_has_separate_kem",
    "get_suite",
]
