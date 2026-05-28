"""v3.0 root-identity derivation.

Two entry points:

1. :func:`derive_root_identity` — passphrase → Argon2id → HKDF-SHA256 →
   Ed25519 + X25519 seeds. The passphrase path.
2. :func:`derive_root_identity_from_secp256k1_signature` — bootstrap an
   identity from an external secp256k1 root (e.g. a Nostr nsec). The caller
   signs a fixed challenge with their secp256k1 signer; the signature is
   verified against the originating pubkey, then HKDF-expanded to produce
   the Ed25519 + X25519 seeds. The secp256k1 private key never reaches
   Starfish; the bootstrapped identity is a regular Ed25519 identity from
   the wire's perspective.

Both paths produce the same downstream artifacts (Ed25519 + X25519 keys +
``user_id``). The secp256k1 path attaches a non-load-bearing
``bootstrap_origin`` metadata field recording the originating pubkey.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Optional

from argon2.low_level import Type as Argon2Type, hash_secret_raw
from coincurve.keys import PublicKeyXOnly
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from starfish_keyring import hkdf_bytes

# ── Constants ─────────────────────────────────────────────────────────────────

ARGON2_MEMORY_KIB = 47_104
ARGON2_ITERATIONS = 3
ARGON2_PARALLELISM = 1
ARGON2_HASH_LENGTH = 32
ARGON2_SALT_UTF8 = b"starfish-v3-root"

_ROOT_ED_HKDF_SALT = b"starfish-root-sign"
_ROOT_ED_HKDF_INFO = b"ed25519"
_ROOT_KEM_HKDF_SALT = b"starfish-root-kem"
_ROOT_KEM_HKDF_INFO = b"x25519"
_USER_ID_HEX_LEN = 32

_BOOTSTRAP_SECP_HKDF_SALT = b"starfish-v3-bootstrap-secp256k1"
_BOOTSTRAP_SECP_SIGN_INFO = b"starfish-root-sign:ed25519"
_BOOTSTRAP_SECP_KEM_INFO = b"starfish-root-kem:x25519"

SECP256K1_BOOTSTRAP_CHALLENGE: bytes = hashlib.sha256(
    b"starfish-v3:bootstrap-secp256k1"
).digest()
"""Fixed 32-byte challenge the caller's secp256k1 signer must sign to bootstrap
an identity. Byte-identical across TS and Python."""


# ── Types ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RootKeyPair:
    """Root key material — all values are 64-char lowercase hex (32 raw bytes)."""

    ed_priv: str
    ed_pub: str
    kem_priv: str
    kem_pub: str


@dataclass(frozen=True)
class BootstrapOrigin:
    """Non-load-bearing origin metadata recording how a root identity was derived.

    Never appears on the wire — used only for external systems (e.g. Nostr-aware
    UIs, audit logs) to display the bootstrap source.
    """

    kind: str  # "secp256k1"
    pub_hex: str


@dataclass(frozen=True)
class RootIdentity:
    """A v3 root identity. Carries ``bootstrap_origin`` when bootstrapped from
    an external root (e.g. secp256k1); absent for passphrase-derived identities."""

    user_id: str
    keys: RootKeyPair
    bootstrap_origin: Optional[BootstrapOrigin] = None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _argon2id_stretch(passphrase: str) -> bytes:
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=ARGON2_SALT_UTF8,
        time_cost=ARGON2_ITERATIONS,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LENGTH,
        type=Argon2Type.ID,
    )


def _user_id_from_ed_pub(ed_pub_bytes: bytes) -> str:
    return hashlib.sha256(ed_pub_bytes).hexdigest()[:_USER_ID_HEX_LEN]


# ── Public API ────────────────────────────────────────────────────────────────


def derive_root_identity(passphrase: str) -> RootIdentity:
    """Derive a v3 root identity from a passphrase."""
    if not passphrase.strip():
        raise ValueError("Passphrase must not be empty")

    master = bytearray(_argon2id_stretch(passphrase))

    ed_seed = hkdf_bytes(bytes(master), _ROOT_ED_HKDF_SALT, _ROOT_ED_HKDF_INFO, 32)
    ed_private = Ed25519PrivateKey.from_private_bytes(ed_seed)
    ed_pub_bytes = ed_private.public_key().public_bytes_raw()

    kem_seed = hkdf_bytes(bytes(master), _ROOT_KEM_HKDF_SALT, _ROOT_KEM_HKDF_INFO, 32)
    kem_private = X25519PrivateKey.from_private_bytes(kem_seed)
    kem_pub_bytes = kem_private.public_key().public_bytes_raw()
    for i in range(len(master)):
        master[i] = 0

    user_id = _user_id_from_ed_pub(ed_pub_bytes)

    return RootIdentity(
        user_id=user_id,
        keys=RootKeyPair(
            ed_priv=ed_seed.hex(),
            ed_pub=ed_pub_bytes.hex(),
            kem_priv=kem_seed.hex(),
            kem_pub=kem_pub_bytes.hex(),
        ),
    )


# `fullmatch` (not `match` + `$`) so a trailing newline is rejected. Python's
# `$` matches BEFORE a final `\n`, so `"<64-hex>\n"` would pass `match()` while
# the TS `/^[0-9a-f]{64}$/.test(...)` rejects it. Use `fullmatch` to keep the
# two languages in lockstep on bad input — see MEMORY: cross-lang-gap-seams.
_SECP_PUBHEX_RE = re.compile(r"[0-9a-f]{64}")


def _is_lowercase_hex_64(s: object) -> bool:
    return isinstance(s, str) and _SECP_PUBHEX_RE.fullmatch(s) is not None


def derive_root_identity_from_secp256k1_signature(
    secp_pub_hex: str,
    signature: bytes,
) -> RootIdentity:
    """Derive a v3 root identity from a secp256k1 (Nostr / BIP-340) signature.

    The caller signs :data:`SECP256K1_BOOTSTRAP_CHALLENGE` with their external
    BIP-340 Schnorr signer and passes the signature in here. The signature is
    verified against ``secp_pub_hex``, then its 64 bytes are piped through
    HKDF-SHA256 to produce the Ed25519 + X25519 seeds. Starfish itself only
    ever holds the derived Ed25519 identity from this point on; the secp256k1
    root never appears on the wire.

    The returned identity carries ``bootstrap_origin=BootstrapOrigin(kind="secp256k1",
    pub_hex=secp_pub_hex)`` for external systems to display the origin.

    **The signature is private-key-equivalent.** The Ed25519 + X25519 seeds
    are derived deterministically from the 64-byte signature alone, so
    possession of the signature lets anyone reconstruct the full identity.
    Treat it with the same care as the secp256k1 private key itself: never
    log it, transmit it, or persist it in cleartext. Derive once, then keep
    only the resulting identity material.

    **Determinism contract.** The caller MUST sign with deterministic BIP-340
    Schnorr (``aux_rand = b"\\x00" * 32``). BIP-340 permits this. A
    non-deterministic signer yields a different signature → different seeds →
    different ``user_id`` on every call, and any caps minted by an earlier
    derivation will not verify against the new root. Recommended pattern:
    derive once at first install, persist the resulting identity (e.g. via
    :func:`seal_with_passphrase`), and never call this function again for the
    same secp256k1 root unless you intend to start over.
    """
    if not _is_lowercase_hex_64(secp_pub_hex):
        raise ValueError("secp_pub_hex must be 64 lowercase hex characters")
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        raise ValueError("signature must be 64 bytes (BIP-340 Schnorr)")
    signature_bytes = bytes(signature)

    try:
        pub = PublicKeyXOnly(bytes.fromhex(secp_pub_hex))
        sig_ok = pub.verify(signature_bytes, SECP256K1_BOOTSTRAP_CHALLENGE)
    except Exception:
        sig_ok = False
    if not sig_ok:
        raise ValueError(
            "BIP-340 Schnorr signature does not verify against secp_pub_hex over the Starfish bootstrap challenge"
        )

    ed_seed = hkdf_bytes(
        signature_bytes, _BOOTSTRAP_SECP_HKDF_SALT, _BOOTSTRAP_SECP_SIGN_INFO, 32
    )
    kem_seed = hkdf_bytes(
        signature_bytes, _BOOTSTRAP_SECP_HKDF_SALT, _BOOTSTRAP_SECP_KEM_INFO, 32
    )

    ed_private = Ed25519PrivateKey.from_private_bytes(ed_seed)
    ed_pub_bytes = ed_private.public_key().public_bytes_raw()
    kem_private = X25519PrivateKey.from_private_bytes(kem_seed)
    kem_pub_bytes = kem_private.public_key().public_bytes_raw()

    user_id = _user_id_from_ed_pub(ed_pub_bytes)

    return RootIdentity(
        user_id=user_id,
        keys=RootKeyPair(
            ed_priv=ed_seed.hex(),
            ed_pub=ed_pub_bytes.hex(),
            kem_priv=kem_seed.hex(),
            kem_pub=kem_pub_bytes.hex(),
        ),
        bootstrap_origin=BootstrapOrigin(kind="secp256k1", pub_hex=secp_pub_hex),
    )


__all__ = [
    "RootIdentity",
    "RootKeyPair",
    "BootstrapOrigin",
    "SECP256K1_BOOTSTRAP_CHALLENGE",
    "derive_root_identity",
    "derive_root_identity_from_secp256k1_signature",
]
