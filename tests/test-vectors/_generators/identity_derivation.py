"""Generate identity-derivation.json — v3.0 root-identity vector.

Locks the Argon2id + HKDF pipeline used to derive root Ed25519 (sign) and
X25519 (KEM) keypairs from a user passphrase, and the SHA-256 truncation
that produces the stable userId. Both TS and Python implementations of
bootstrapRootIdentity must reproduce these outputs byte-for-byte.

Run:
    python3 tests/test-vectors/_generators/identity_derivation.py

Writes to:
    tests/test-vectors/identity-derivation.json
"""

from __future__ import annotations

import hashlib
import json
import pathlib

from argon2.low_level import Type as Argon2Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Must stay byte-identical to ARGON2_PARAMS in the TS/Python identity modules.
ARGON2_MEMORY_KIB = 47_104
ARGON2_ITERATIONS = 3
ARGON2_PARALLELISM = 1
ARGON2_HASH_LENGTH = 32
ARGON2_SALT = b"starfish-v3-root"

ED_SALT = b"starfish-root-sign"
ED_INFO = b"ed25519"
KEM_SALT = b"starfish-root-kem"
KEM_INFO = b"x25519"


def _argon2id(passphrase: str) -> bytes:
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=ARGON2_SALT,
        time_cost=ARGON2_ITERATIONS,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LENGTH,
        type=Argon2Type.ID,
    )


def _hkdf(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


def _derive(passphrase: str) -> dict[str, str]:
    master = _argon2id(passphrase)

    ed_priv_bytes = _hkdf(master, ED_SALT, ED_INFO)
    ed_priv = Ed25519PrivateKey.from_private_bytes(ed_priv_bytes)
    ed_pub_bytes = ed_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    kem_priv_bytes = _hkdf(master, KEM_SALT, KEM_INFO)
    kem_priv = X25519PrivateKey.from_private_bytes(kem_priv_bytes)
    kem_pub_bytes = kem_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    user_id = hashlib.sha256(ed_pub_bytes).hexdigest()[:32]

    return {
        "passphrase": passphrase,
        "argon2Master": master.hex(),
        "rootEdPriv": ed_priv_bytes.hex(),
        "rootEdPub": ed_pub_bytes.hex(),
        "rootKemPriv": kem_priv_bytes.hex(),
        "rootKemPub": kem_pub_bytes.hex(),
        "userId": user_id,
    }


PASSPHRASES = [
    "test-passphrase",
    "the quick brown fox jumps over the lazy dog",
    "café-passphrase-🔑",
    "able acid bald beam cake calm card cell ego envy face fact",
]


def main() -> None:
    out = {
        "description": (
            "Cross-language vector for v3.0 root-identity derivation. "
            "Pipeline: Argon2id(passphrase) → master; HKDF-SHA256(master) → "
            "Ed25519 + X25519 seeds; sha256(rootEdPub)[0:16] → userId. "
            "Both TS and Python implementations must reproduce these outputs."
        ),
        "constants": {
            "argon2": {
                "memoryKiB": ARGON2_MEMORY_KIB,
                "iterations": ARGON2_ITERATIONS,
                "parallelism": ARGON2_PARALLELISM,
                "hashLength": ARGON2_HASH_LENGTH,
                "saltUtf8": ARGON2_SALT.decode("utf-8"),
                "type": "argon2id",
            },
            "edHkdfSaltUtf8": ED_SALT.decode("utf-8"),
            "edHkdfInfoUtf8": ED_INFO.decode("utf-8"),
            "kemHkdfSaltUtf8": KEM_SALT.decode("utf-8"),
            "kemHkdfInfoUtf8": KEM_INFO.decode("utf-8"),
            "userIdHexLen": 16,
            "userIdSource": "sha256(rootEdPub) truncated to first 16 hex chars",
        },
        "vectors": [_derive(p) for p in PASSPHRASES],
    }

    out_path = pathlib.Path(__file__).resolve().parents[1] / "identity-derivation.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
