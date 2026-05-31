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
from Crypto.Hash import keccak as _keccak
from coincurve import PublicKey
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

_BOOTSTRAP_EVM_HKDF_SALT = b"starfish-v3-bootstrap-evm"
_BOOTSTRAP_EVM_SIGN_INFO = b"starfish-root-sign:ed25519"
_BOOTSTRAP_EVM_KEM_INFO = b"starfish-root-kem:x25519"

SECP256K1_BOOTSTRAP_CHALLENGE: bytes = hashlib.sha256(
    b"starfish-v3:bootstrap-secp256k1"
).digest()
"""Fixed 32-byte challenge the caller's secp256k1 signer must sign to bootstrap
an identity. Byte-identical across TS and Python."""

EVM_BOOTSTRAP_CHALLENGE: str = "starfish:bootstrap-evm"
"""Default message the caller's EVM wallet signs (EIP-191 ``personal_sign``) to
bootstrap an identity. The signed digest is
``keccak256("\\x19Ethereum Signed Message:\\n" + len + msg)``. Byte-identical
across TS and Python; sign it with a deterministic (RFC 6979) ECDSA signer.

An app may pass its own ``challenge`` to
:func:`derive_root_identity_from_evm_signature` (e.g. ``"myapp:bootstrap"``) to
namespace its identities — distinct challenges yield distinct identities from
the same wallet. Whatever challenge an app picks, it must stay fixed forever:
changing it changes the signature, hence the derived ``user_id``."""

_EVM_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")


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
    UIs, audit logs) to display the bootstrap source. ``pub_hex`` is set for
    ``kind="secp256k1"`` (the originating x-only pubkey); ``address`` is set for
    ``kind="evm"`` (the originating EVM address).
    """

    kind: str  # "secp256k1" | "evm"
    pub_hex: Optional[str] = None
    address: Optional[str] = None


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


def _keccak256(data: bytes) -> bytes:
    h = _keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def _eip191_digest(message: bytes) -> bytes:
    """The 32-byte digest an EVM ``personal_sign`` actually signs over ``message``."""
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(message)).encode("ascii")
    return _keccak256(prefix + message)


def _recover_evm_address(digest: bytes, signature: bytes) -> str:
    """Recover the lowercase 0x EVM address that produced ``signature`` over ``digest``.

    ``signature`` is the 65-byte ``r‖s‖v`` form an EVM wallet returns (``v`` is
    27/28, or 0/1). Raises on a malformed/unrecoverable signature.
    """
    v = signature[64]
    recid = v - 27 if v >= 27 else v
    if recid not in (0, 1):
        raise ValueError("signature recovery id out of range")
    # coincurve wants compact r‖s followed by a recovery-id byte in [0,3].
    pub = PublicKey.from_signature_and_message(
        signature[:64] + bytes([recid]), digest, hasher=None
    )
    uncompressed = pub.format(compressed=False)  # 0x04 ‖ X(32) ‖ Y(32)
    return "0x" + _keccak256(uncompressed[1:])[-20:].hex()


def derive_root_identity_from_evm_signature(
    address: str,
    signature: bytes,
    *,
    challenge: str = EVM_BOOTSTRAP_CHALLENGE,
) -> RootIdentity:
    """Derive a v3 root identity from a deterministic EVM-wallet signature.

    The caller signs ``challenge`` (default :data:`EVM_BOOTSTRAP_CHALLENGE`) with
    their EVM wallet via EIP-191 ``personal_sign`` and passes the 65-byte
    signature in here. The signature is verified by recovering its signer over
    that same challenge and checking it equals ``address``, then its bytes are
    piped through HKDF-SHA256 to produce the Ed25519 + X25519 seeds. Starfish
    only ever holds the derived Ed25519 identity from this point on; the EVM
    private key never appears on the wire.

    Pass a custom ``challenge`` (e.g. ``"myapp:bootstrap"``) to namespace an
    app's identities: a different challenge produces a different signature, hence
    a different ``user_id``, from the same wallet. The signer MUST sign the
    *same* challenge string passed here, and the app MUST keep that string fixed.

    The returned identity carries
    ``bootstrap_origin=BootstrapOrigin(kind="evm", address=address)`` for
    external systems to display the origin.

    **The signature is private-key-equivalent.** The Ed25519 + X25519 seeds are
    derived deterministically from the signature alone, so possession of it lets
    anyone reconstruct the full identity. Treat it with the same care as the EVM
    private key itself: never log it, transmit it, or persist it in cleartext.
    Derive once, then keep only the resulting identity material.

    **Determinism contract.** The caller MUST sign with deterministic ECDSA
    (RFC 6979) — the default for ``eth-account`` / standard EVM signers, and
    EIP-191 personal-sign carries no per-call salt. A non-deterministic signer
    yields a different signature → different seeds → a different ``user_id`` on
    every call, and any caps minted by an earlier derivation will not verify
    against the new root. Recommended pattern: derive once at first install,
    persist the resulting identity (e.g. via :func:`seal_with_passphrase`), and
    never call this function again for the same EVM root unless you intend to
    start over.
    """
    if not isinstance(address, str) or _EVM_ADDRESS_RE.fullmatch(address) is None:
        raise ValueError("address must be a 0x-prefixed 40-hex-character EVM address")
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 65:
        raise ValueError("signature must be 65 bytes (r‖s‖v ECDSA)")
    signature_bytes = bytes(signature)

    try:
        recovered = _recover_evm_address(
            _eip191_digest(challenge.encode("utf-8")), signature_bytes
        )
    except Exception as exc:
        raise ValueError(
            "EVM signature does not recover a valid signer over the Starfish bootstrap challenge"
        ) from exc
    if recovered.lower() != address.lower():
        raise ValueError(
            "EVM signature does not recover to address over the Starfish bootstrap challenge"
        )

    ed_seed = hkdf_bytes(
        signature_bytes, _BOOTSTRAP_EVM_HKDF_SALT, _BOOTSTRAP_EVM_SIGN_INFO, 32
    )
    kem_seed = hkdf_bytes(
        signature_bytes, _BOOTSTRAP_EVM_HKDF_SALT, _BOOTSTRAP_EVM_KEM_INFO, 32
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
        bootstrap_origin=BootstrapOrigin(kind="evm", address=address),
    )


__all__ = [
    "RootIdentity",
    "RootKeyPair",
    "BootstrapOrigin",
    "SECP256K1_BOOTSTRAP_CHALLENGE",
    "EVM_BOOTSTRAP_CHALLENGE",
    "derive_root_identity",
    "derive_root_identity_from_secp256k1_signature",
    "derive_root_identity_from_evm_signature",
]
