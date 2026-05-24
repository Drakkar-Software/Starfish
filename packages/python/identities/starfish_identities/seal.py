"""Passphrase-sealed envelopes — Argon2id (memory-hard stretch) → AES-256-GCM.

Byte-for-byte mirror of the TypeScript ``seal.ts`` so cross-language test
vectors round-trip. A small, generic primitive for transporting a secret blob
(e.g. a one-way device setup code, which carries private keys) under a
user-chosen PIN/passphrase. The envelope is JSON-serialisable and useless on
its own: opening it needs the passphrase, which should travel a DIFFERENT
channel than the envelope (the out-of-band / two-channel pattern).

Construction::

    key = Argon2id(NFC(passphrase), random_salt, ARGON2_PARAMS)   # per-seal salt
    ct  = AES-256-GCM(key, random_iv, plaintext)                  # tag appended

Security notes:

* Strength is bounded by passphrase entropy. Argon2id raises the per-guess cost
  but cannot rescue a low-entropy PIN — a 4-digit numeric PIN is still
  brute-forceable offline once the envelope is captured. Prefer a real
  passphrase when the envelope may be intercepted.
* The KDF header (salt + params) is *implicitly* authenticated: tampering with
  it yields a different key (or a bad nonce), so the GCM tag check fails on
  open. ``v`` / ``enc`` are NOT in the KDF input, so they are guarded only by
  the explicit allow-list in :func:`open_with_passphrase`.
* :func:`open_with_passphrase` validates the envelope BEFORE running Argon2id,
  so a hostile envelope cannot trigger an expensive memory-hard computation
  (denial of service) on the recipient.
"""

import base64
import secrets
import unicodedata
from typing import Optional

from argon2.low_level import Type as Argon2Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from starfish_identities.identity import (
    ARGON2_HASH_LENGTH,
    ARGON2_ITERATIONS,
    ARGON2_MEMORY_KIB,
    ARGON2_PARALLELISM,
)

_SALT_BYTES = 16
_IV_BYTES = 12

# One generic failure for every open-side rejection (wrong passphrase, tamper,
# or bad params). Distinguishing them would leak whether the structure was
# valid; callers should surface a single "wrong PIN or corrupted code" message.
_OPEN_FAILED = (
    "Failed to open sealed envelope: wrong passphrase or corrupted/invalid envelope"
)


def _derive_seal_key(passphrase: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=unicodedata.normalize("NFC", passphrase).encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_ITERATIONS,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LENGTH,
        type=Argon2Type.ID,
    )


def seal_with_passphrase(
    passphrase: str,
    plaintext: bytes,
    *,
    salt: Optional[bytes] = None,
    iv: Optional[bytes] = None,
) -> dict:
    """Seal ``plaintext`` under ``passphrase``; return a JSON-serialisable dict.

    The passphrase is NFC-normalised before stretching so the same human input
    produces the same key across platforms. ``salt`` / ``iv`` overrides exist
    for deterministic test vectors only.

    Raises:
        ValueError: if ``passphrase`` is empty.
    """
    if not passphrase:
        raise ValueError("Passphrase must not be empty")
    salt_bytes = salt if salt is not None else secrets.token_bytes(_SALT_BYTES)
    iv_bytes = iv if iv is not None else secrets.token_bytes(_IV_BYTES)
    key = _derive_seal_key(passphrase, salt_bytes)
    ct = AESGCM(key).encrypt(iv_bytes, plaintext, None)
    return {
        "v": 1,
        "enc": "passphrase",
        "kdf": {
            "alg": "argon2id",
            "memKiB": ARGON2_MEMORY_KIB,
            "iter": ARGON2_ITERATIONS,
            "par": ARGON2_PARALLELISM,
            "salt": base64.b64encode(salt_bytes).decode("ascii"),
        },
        "iv": base64.b64encode(iv_bytes).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }


def is_sealed_envelope(value: object) -> bool:
    """Structural check: does ``value`` look like a sealed envelope dict?

    Lets callers branch between a sealed code and a plaintext blob without
    raising.
    """
    if not isinstance(value, dict):
        return False
    if (
        value.get("v") != 1
        or value.get("enc") != "passphrase"
        or not isinstance(value.get("iv"), str)
        or not isinstance(value.get("ct"), str)
    ):
        return False
    kdf = value.get("kdf")
    if not isinstance(kdf, dict):
        return False
    return kdf.get("alg") == "argon2id" and isinstance(kdf.get("salt"), str)


def open_with_passphrase(passphrase: str, envelope: dict) -> bytes:
    """Open an envelope produced by :func:`seal_with_passphrase`.

    Validates the envelope shape and Argon2id parameters BEFORE doing any KDF
    work, so a hostile envelope cannot trigger an expensive memory-hard
    computation. Every failure — malformed envelope, disallowed params, wrong
    passphrase, or tampered ciphertext — raises the same generic ``ValueError``.
    """
    try:
        if not is_sealed_envelope(envelope):
            raise ValueError("malformed envelope")
        kdf = envelope["kdf"]
        # Param allow-list — reject before KDF. Strictest sensible choice: the
        # canonical params. Loosen only if the format ever legitimately varies.
        if (
            kdf.get("alg") != "argon2id"
            or kdf.get("memKiB") != ARGON2_MEMORY_KIB
            or kdf.get("iter") != ARGON2_ITERATIONS
            or kdf.get("par") != ARGON2_PARALLELISM
        ):
            raise ValueError("disallowed KDF parameters")
        salt = base64.b64decode(kdf["salt"])
        iv = base64.b64decode(envelope["iv"])
        ct = base64.b64decode(envelope["ct"])
        if len(salt) != _SALT_BYTES:
            raise ValueError("bad salt length")
        if len(iv) != _IV_BYTES:
            raise ValueError("bad iv length")
        key = _derive_seal_key(passphrase, salt)
        return AESGCM(key).decrypt(iv, ct, None)
    except Exception as exc:  # noqa: BLE001 — collapse to one generic error
        raise ValueError(_OPEN_FAILED) from exc


__all__ = [
    "seal_with_passphrase",
    "open_with_passphrase",
    "is_sealed_envelope",
]
