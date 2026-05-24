"""v3.0 root-identity derivation from a passphrase.

Two-stage pipeline:

1. Argon2id (memory-hard password stretch) ``passphrase`` → 32-byte master.
2. Two HKDF-SHA256 expansions over the master:
   - a 32-byte Ed25519 signing seed (cap-cert signing / request auth), and
   - a 32-byte X25519 KEM scalar (wraps secrets to a recipient).

The Ed25519 public key is hashed (SHA-256) and the first 32 hex characters
form a short ``user_id``.

Argon2id is the gate that raises offline brute-force cost for low-entropy
passphrases; HKDF is the cheap domain-separated expander. This module
covers root-identity derivation only — cap-certs and device keys are
emitted by higher-level operations (pairing, bootstrap).
"""

import hashlib
from dataclasses import dataclass

from argon2.low_level import Type as Argon2Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from starfish_keyring import hkdf_bytes

# ── Constants ─────────────────────────────────────────────────────────────────
# These MUST match the cross-language test vector
# (tests/test-vectors/identity-derivation.json) — changing any constant
# below requires regenerating every cross-language vector that uses a
# fixture root identity.

# Argon2id parameters. Above the OWASP interactive-login minimum (m=19456,
# t=2): a root identity — and a passphrase-sealed envelope carrying private
# device keys — is a higher-value, longer-lived secret than a session login.
# Must stay byte-identical to the TS ARGON2_PARAMS. Changing these requires
# regenerating every cross-language fixture-identity vector.
ARGON2_MEMORY_KIB = 47_104
ARGON2_ITERATIONS = 3
ARGON2_PARALLELISM = 1
ARGON2_HASH_LENGTH = 32
# Global UTF-8 salt — root derivation must be deterministic across the user's
# devices for the same passphrase, so no per-user salt is possible here.
ARGON2_SALT_UTF8 = b"starfish-v3-root"

_ROOT_ED_HKDF_SALT = b"starfish-root-sign"
_ROOT_ED_HKDF_INFO = b"ed25519"
_ROOT_KEM_HKDF_SALT = b"starfish-root-kem"
_ROOT_KEM_HKDF_INFO = b"x25519"
_USER_ID_HEX_LEN = 32


# ── Types ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RootKeyPair:
    """Root key material derived from a passphrase.

    All values are 64-character lowercase hex strings (32 raw bytes).
    """

    ed_priv: str
    """Hex-encoded Ed25519 32-byte seed / private key."""

    ed_pub: str
    """Hex-encoded Ed25519 32-byte public key."""

    kem_priv: str
    """Hex-encoded X25519 32-byte private scalar (raw HKDF output; clamping
    is applied implicitly by X25519 point multiplication)."""

    kem_pub: str
    """Hex-encoded X25519 32-byte public key."""


@dataclass(frozen=True)
class RootIdentity:
    """A v3 root identity bound to a passphrase."""

    user_id: str
    """First 32 hex characters (16 bytes) of ``sha256(rootEdPub)``."""

    keys: RootKeyPair
    """Ed25519 signing and X25519 KEM key pairs as hex."""


# ── Helpers ───────────────────────────────────────────────────────────────────


def _argon2id_stretch(passphrase: str) -> bytes:
    """Run Argon2id over the passphrase to produce a 32-byte master secret."""
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=ARGON2_SALT_UTF8,
        time_cost=ARGON2_ITERATIONS,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LENGTH,
        type=Argon2Type.ID,
    )


# ── Public API ────────────────────────────────────────────────────────────────


def derive_root_identity(passphrase: str) -> RootIdentity:
    """Derive a v3 root identity from a passphrase.

    Pipeline: Argon2id (memory-hard password stretch) → HKDF-SHA256
    (domain-separated expansion into Ed25519 + X25519 seeds) → public key
    derivation → ``user_id``. Deterministic: same passphrase always yields
    the same root identity.

    Raises:
        ValueError: if ``passphrase`` is empty or whitespace-only.
    """
    if not passphrase.strip():
        raise ValueError("Passphrase must not be empty")

    # Stage 1 — Argon2id stretches the passphrase into a 32-byte master secret.
    # Held in a bytearray so it can be overwritten after use (mirrors the TS
    # `master.fill(0)`). Best-effort only: Argon2/HKDF may keep internal copies
    # Python cannot reach, and `bytes` elsewhere are immutable — this wipes the
    # one buffer under our control, it is not a guarantee.
    master = bytearray(_argon2id_stretch(passphrase))

    # Stage 2 — HKDF-SHA256 expands the master into domain-separated subkeys.
    ed_seed = hkdf_bytes(bytes(master), _ROOT_ED_HKDF_SALT, _ROOT_ED_HKDF_INFO, 32)
    ed_private = Ed25519PrivateKey.from_private_bytes(ed_seed)
    ed_pub_bytes = ed_private.public_key().public_bytes_raw()

    kem_seed = hkdf_bytes(bytes(master), _ROOT_KEM_HKDF_SALT, _ROOT_KEM_HKDF_INFO, 32)
    kem_private = X25519PrivateKey.from_private_bytes(kem_seed)
    kem_pub_bytes = kem_private.public_key().public_bytes_raw()
    # Overwrite the master secret now that both seeds are derived.
    for i in range(len(master)):
        master[i] = 0

    # user_id = first 32 hex chars of SHA-256(rootEdPub bytes)
    user_id = hashlib.sha256(ed_pub_bytes).hexdigest()[:_USER_ID_HEX_LEN]

    return RootIdentity(
        user_id=user_id,
        keys=RootKeyPair(
            ed_priv=ed_seed.hex(),
            ed_pub=ed_pub_bytes.hex(),
            kem_priv=kem_seed.hex(),
            kem_pub=kem_pub_bytes.hex(),
        ),
    )


__all__ = ["RootIdentity", "RootKeyPair", "derive_root_identity"]
