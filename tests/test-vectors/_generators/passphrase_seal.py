"""Generate passphrase-seal.json — passphrase-sealed envelope vector.

Locks the seal construction shared by TS ``seal.ts`` and Python ``seal.py``:

    key = Argon2id(NFC(passphrase), salt, ARGON2_PARAMS)   # 32-byte key
    ct  = AES-256-GCM(key, iv, plaintext)                  # 16-byte tag appended

Salt and IV are random in real use; here they are derived deterministically
from each vector's label so re-running reproduces the file byte-for-byte. Both
implementations must (a) open each vector's envelope to its plaintext and
(b) reproduce the exact envelope when given the same salt + iv.

Run:
    python3 tests/test-vectors/_generators/passphrase_seal.py

Writes to:
    tests/test-vectors/passphrase-seal.json
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import unicodedata

from argon2.low_level import Type as Argon2Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Must stay byte-identical to ARGON2_PARAMS in the TS/Python identity modules
# (the seal layer reuses the root-derivation params).
ARGON2_MEMORY_KIB = 47_104
ARGON2_ITERATIONS = 3
ARGON2_PARALLELISM = 1
ARGON2_HASH_LENGTH = 32

SALT_BYTES = 16
IV_BYTES = 12


def _salt_for(label: str) -> bytes:
    return hashlib.sha256(b"starfish-seal-vector-salt:" + label.encode("utf-8")).digest()[:SALT_BYTES]


def _iv_for(label: str) -> bytes:
    return hashlib.sha256(b"starfish-seal-vector-iv:" + label.encode("utf-8")).digest()[:IV_BYTES]


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


def _seal(label: str, passphrase: str, plaintext_utf8: str) -> dict:
    salt = _salt_for(label)
    iv = _iv_for(label)
    key = _derive_seal_key(passphrase, salt)
    ct = AESGCM(key).encrypt(iv, plaintext_utf8.encode("utf-8"), None)
    return {
        "label": label,
        "passphrase": passphrase,
        "plaintextUtf8": plaintext_utf8,
        "saltB64": base64.b64encode(salt).decode("ascii"),
        "ivB64": base64.b64encode(iv).decode("ascii"),
        "envelope": {
            "v": 1,
            "enc": "passphrase",
            "kdf": {
                "alg": "argon2id",
                "memKiB": ARGON2_MEMORY_KIB,
                "iter": ARGON2_ITERATIONS,
                "par": ARGON2_PARALLELISM,
                "salt": base64.b64encode(salt).decode("ascii"),
            },
            "iv": base64.b64encode(iv).decode("ascii"),
            "ct": base64.b64encode(ct).decode("ascii"),
        },
    }


# (label, passphrase, plaintext) — a short numeric PIN, a multi-word passphrase,
# and a unicode passphrase + payload to lock NFC handling.
CASES = [
    ("numeric-pin", "1234", '{"hello":"world","n":42}'),
    ("passphrase", "correct horse battery staple", "one-way device setup code payload"),
    ("unicode", "café-🔑-passphrase", "café ☕ secret — déjà vu"),
]


def main() -> None:
    out = {
        "description": (
            "Cross-language vector for passphrase-sealed envelopes. "
            "key = Argon2id(NFC(passphrase), salt) → AES-256-GCM(key, iv, plaintext) "
            "with the 16-byte tag appended to ct. Both TS and Python must open each "
            "envelope to plaintextUtf8 and reproduce the exact envelope from "
            "(passphrase, plaintext, salt, iv)."
        ),
        "constants": {
            "argon2": {
                "memoryKiB": ARGON2_MEMORY_KIB,
                "iterations": ARGON2_ITERATIONS,
                "parallelism": ARGON2_PARALLELISM,
                "hashLength": ARGON2_HASH_LENGTH,
                "type": "argon2id",
            },
            "saltBytes": SALT_BYTES,
            "ivBytes": IV_BYTES,
            "aead": "AES-256-GCM",
            "passphraseNormalization": "NFC",
            "base64": "standard (padded)",
        },
        "vectors": [_seal(label, p, pt) for (label, p, pt) in CASES],
    }

    out_path = pathlib.Path(__file__).resolve().parents[1] / "passphrase-seal.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
