"""Shared fixtures and helpers for v3.0 vector generators.

Importable as a sibling module: scripts at tests/test-vectors/_generators/*.py
add the parent dir to sys.path or use a relative import via __package__.
For simplicity, we use sys.path injection in each script entrypoint.

Locks:
- HKDF parameters for root + device + ephemeral derivation
- stable_stringify (matches packages/python/protocol/starfish_protocol/hash.py)
- A small cast of fixture identities used across all vector files so they
  cross-reference (e.g., cap-cert mentions a device whose keys appear in
  identity-derivation, multi-recipient-wrap, etc.).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from argon2.low_level import Type as Argon2Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Argon2id params (locked across all vectors) ──────────────────────────────

# Must stay byte-identical to ARGON2_PARAMS in the TS/Python identity modules.
ARGON2_MEMORY_KIB = 47_104
ARGON2_ITERATIONS = 3
ARGON2_PARALLELISM = 1
ARGON2_HASH_LENGTH = 32
ARGON2_SALT_UTF8 = b"starfish-v3-root"

# ── HKDF parameters (locked across all vectors) ──────────────────────────────

ROOT_ED_SALT = b"starfish-root-sign"
ROOT_ED_INFO = b"ed25519"
ROOT_KEM_SALT = b"starfish-root-kem"
ROOT_KEM_INFO = b"x25519"

# Device keys are FRESHLY GENERATED in real use. For vectors we need
# reproducibility, so we derive them from a (seed, deviceLabel) pair.
DEVICE_ED_SALT = b"starfish-device-sign-test-vector"
DEVICE_ED_INFO = b"ed25519"
DEVICE_KEM_SALT = b"starfish-device-kem-test-vector"
DEVICE_KEM_INFO = b"x25519"

# Ephemeral wrap keys are random in real use. For vectors we derive them
# from (cek, recipientSubKem) so wraps are reproducible.
EPH_SALT = b"starfish-eph-test-vector"
EPH_INFO = b"x25519"

# Per-recipient wrap key derivation (matches the implementation contract):
WRAP_SALT = b"starfish-wrap"
WRAP_INFO = b"starfish-wrap"

# AES-GCM IV is 12 bytes. For vectors we derive deterministically.
IV_BYTES = 12


def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def short_user_id(ed_pub: bytes) -> str:
    return sha256_hex(ed_pub)[:32]


def stable_stringify(value: Any) -> str:
    """Mirror of packages/python/protocol/starfish_protocol/hash.py."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(stable_stringify(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys())
        pairs = [json.dumps(k, ensure_ascii=False) + ":" + stable_stringify(value[k]) for k in keys]
        return "{" + ",".join(pairs) + "}"
    return "null"


# ── Key material types ───────────────────────────────────────────────────────


@dataclass
class Identity:
    label: str
    passphrase: str
    ed_priv: bytes
    ed_pub: bytes
    kem_priv: bytes
    kem_pub: bytes
    user_id: str

    def as_dict(self) -> dict[str, str]:
        return {
            "label": self.label,
            "passphrase": self.passphrase,
            "edPriv": self.ed_priv.hex(),
            "edPub": self.ed_pub.hex(),
            "kemPriv": self.kem_priv.hex(),
            "kemPub": self.kem_pub.hex(),
            "userId": self.user_id,
        }


def _key_from_seed(seed: bytes, kind: str) -> bytes:
    if kind == "ed25519":
        return seed  # used as Ed25519 private bytes directly
    if kind == "x25519":
        return seed
    raise ValueError(kind)


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


def derive_root(passphrase: str, label: str) -> Identity:
    """Root identity from passphrase (matches identity-derivation.json).

    Pipeline: Argon2id(passphrase) → master; then HKDF over master for the
    Ed25519 and X25519 subkeys.
    """
    master = _argon2id_stretch(passphrase)
    ed_priv_bytes = hkdf(master, ROOT_ED_SALT, ROOT_ED_INFO)
    kem_priv_bytes = hkdf(master, ROOT_KEM_SALT, ROOT_KEM_INFO)
    ed_pub = Ed25519PrivateKey.from_private_bytes(ed_priv_bytes).public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )
    kem_pub = X25519PrivateKey.from_private_bytes(kem_priv_bytes).public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )
    return Identity(
        label=label,
        passphrase=passphrase,
        ed_priv=ed_priv_bytes,
        ed_pub=ed_pub,
        kem_priv=kem_priv_bytes,
        kem_pub=kem_pub,
        user_id=short_user_id(ed_pub),
    )


def derive_device(seed_phrase: str, device_label: str) -> Identity:
    """Device identity for vector purposes only — in production these are random."""
    ikm = (seed_phrase + "::" + device_label).encode("utf-8")
    ed_priv_bytes = hkdf(ikm, DEVICE_ED_SALT, DEVICE_ED_INFO)
    kem_priv_bytes = hkdf(ikm, DEVICE_KEM_SALT, DEVICE_KEM_INFO)
    ed_pub = Ed25519PrivateKey.from_private_bytes(ed_priv_bytes).public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )
    kem_pub = X25519PrivateKey.from_private_bytes(kem_priv_bytes).public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )
    return Identity(
        label=device_label,
        passphrase=seed_phrase,
        ed_priv=ed_priv_bytes,
        ed_pub=ed_pub,
        kem_priv=kem_priv_bytes,
        kem_pub=kem_pub,
        user_id=short_user_id(ed_pub),
    )


# ── Wrap primitive (deterministic for vectors) ───────────────────────────────


def deterministic_eph_key(cek: bytes, recipient_kem_pub: bytes) -> bytes:
    """Per-recipient ephemeral X25519 priv, derived deterministically for vectors."""
    return hkdf(cek + recipient_kem_pub, EPH_SALT, EPH_INFO)


def wrap_for_recipient(
    cek: bytes,
    recipient_kem_pub: bytes,
    eph_priv_bytes: bytes,
    iv: bytes,
) -> tuple[str, bytes]:
    """Wrap a CEK for a recipient.

    Returns (ct_base64, eph_kem_pub_bytes). Uses ephemeral ECDH (HPKE-DHKEM-style):
        shared = ECDH(eph_priv, recipient_kem_pub)
        wrap_key = HKDF(shared, salt=WRAP_SALT, info=WRAP_INFO)
        ct = AES-GCM(wrap_key, iv, cek)
    """
    import base64

    eph_priv = X25519PrivateKey.from_private_bytes(eph_priv_bytes)
    eph_pub_bytes = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,
    )
    recipient_pub = X25519PublicKey.from_public_bytes(recipient_kem_pub)
    shared = eph_priv.exchange(recipient_pub)
    wrap_key = hkdf(shared, WRAP_SALT, WRAP_INFO)
    aead = AESGCM(wrap_key)
    ct = aead.encrypt(iv, cek, None)
    return base64.b64encode(iv + ct).decode("ascii"), eph_pub_bytes


def unwrap_for_recipient(
    ct_b64: str,
    recipient_kem_priv: bytes,
    eph_kem_pub: bytes,
) -> bytes:
    """Inverse of wrap_for_recipient."""
    import base64

    blob = base64.b64decode(ct_b64)
    iv = blob[:IV_BYTES]
    ct = blob[IV_BYTES:]
    recipient = X25519PrivateKey.from_private_bytes(recipient_kem_priv)
    eph_pub = X25519PublicKey.from_public_bytes(eph_kem_pub)
    shared = recipient.exchange(eph_pub)
    wrap_key = hkdf(shared, WRAP_SALT, WRAP_INFO)
    aead = AESGCM(wrap_key)
    return aead.decrypt(iv, ct, None)


# ── Ed25519 sign/verify helpers ──────────────────────────────────────────────


def ed_sign(ed_priv_bytes: bytes, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(ed_priv_bytes).sign(message)


def ed_verify(ed_pub_bytes: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(ed_pub_bytes).verify(signature, message)
        return True
    except Exception:
        return False


# ── Standard fixture cast (used across all vector files) ─────────────────────

FIXTURES = {
    "alice_root":  ("alice-root-passphrase",  "alice-root"),
    "alice_dev_1": ("alice-root-passphrase",  "alice-laptop"),
    "alice_dev_2": ("alice-root-passphrase",  "alice-phone"),
    "bob_root":    ("bob-root-passphrase",    "bob-root"),
    "bob_dev_1":   ("bob-root-passphrase",    "bob-laptop"),
}


def load_fixture(name: str) -> Identity:
    if name not in FIXTURES:
        raise KeyError(name)
    passphrase, label = FIXTURES[name]
    if label.endswith("-root"):
        return derive_root(passphrase, label)
    return derive_device(passphrase, label)
