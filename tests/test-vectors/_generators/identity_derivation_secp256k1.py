"""Generate identity-derivation-secp256k1.json — secp256k1 → Ed25519 bootstrap.

Locks the deterministic derivation:

    challenge = sha256(b"starfish-v3:bootstrap-secp256k1")     # 32 bytes
    signature = BIP-340 Schnorr sign(challenge, secp_priv, aux_rand=0)
    ed_seed   = HKDF-SHA256(signature, salt="starfish-v3-bootstrap-secp256k1",
                            info="starfish-root-sign:ed25519", L=32)
    kem_seed  = HKDF-SHA256(signature, salt="starfish-v3-bootstrap-secp256k1",
                            info="starfish-root-kem:x25519",  L=32)
    ed_pub    = Ed25519.publicKey(ed_seed)
    kem_pub   = X25519.publicKey(kem_seed)
    user_id   = sha256(ed_pub)[:16].hex()  # first 32 hex chars

Run:
    python3 tests/test-vectors/_generators/identity_derivation_secp256k1.py
"""

from __future__ import annotations

import hashlib
import json
import pathlib

from coincurve.keys import PrivateKey, PublicKeyXOnly
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


SECP256K1_BOOTSTRAP_CHALLENGE = hashlib.sha256(b"starfish-v3:bootstrap-secp256k1").digest()
BOOTSTRAP_SALT = b"starfish-v3-bootstrap-secp256k1"
SIGN_INFO = b"starfish-root-sign:ed25519"
KEM_INFO = b"starfish-root-kem:x25519"


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def derive(secp_priv_hex: str) -> dict:
    secp_priv_bytes = bytes.fromhex(secp_priv_hex)
    secp_priv = PrivateKey(secp_priv_bytes)
    secp_pub_hex = PublicKeyXOnly.from_secret(secp_priv_bytes).format().hex()
    # Deterministic Schnorr: aux_rand = 32 zero bytes.
    signature = secp_priv.sign_schnorr(SECP256K1_BOOTSTRAP_CHALLENGE, b"\x00" * 32)
    assert len(signature) == 64
    # Verify the signature round-trips.
    assert PublicKeyXOnly(bytes.fromhex(secp_pub_hex)).verify(
        signature, SECP256K1_BOOTSTRAP_CHALLENGE
    )

    ed_seed = hkdf_sha256(signature, BOOTSTRAP_SALT, SIGN_INFO)
    kem_seed = hkdf_sha256(signature, BOOTSTRAP_SALT, KEM_INFO)

    _RAW = serialization.Encoding.Raw
    _RAW_PUB = serialization.PublicFormat.Raw
    ed_pub_bytes = Ed25519PrivateKey.from_private_bytes(ed_seed).public_key().public_bytes(_RAW, _RAW_PUB)
    kem_pub_bytes = X25519PrivateKey.from_private_bytes(kem_seed).public_key().public_bytes(_RAW, _RAW_PUB)

    user_id = hashlib.sha256(ed_pub_bytes).hexdigest()[:32]
    return {
        "secpPubHex": secp_pub_hex,
        "signatureHex": signature.hex(),
        "edPrivHex": ed_seed.hex(),
        "edPubHex": ed_pub_bytes.hex(),
        "kemPrivHex": kem_seed.hex(),
        "kemPubHex": kem_pub_bytes.hex(),
        "userId": user_id,
        "bootstrapOrigin": {"kind": "secp256k1", "pubHex": secp_pub_hex},
    }


def main() -> None:
    out = {
        "description": (
            "Cross-language vector for the secp256k1 → Ed25519 bootstrap. The "
            "caller signs the fixed 32-byte SECP256K1_BOOTSTRAP_CHALLENGE with "
            "deterministic BIP-340 Schnorr (aux_rand=0), then HKDF-expands the "
            "64-byte signature into Ed25519 and X25519 seeds via "
            "salt='starfish-v3-bootstrap-secp256k1' and the two info strings. "
            "The Ed25519 pubkey hashes to the userId, identical to the "
            "passphrase-derived root identity downstream."
        ),
        "challenge": {
            "literal": "starfish-v3:bootstrap-secp256k1",
            "challengeHex": SECP256K1_BOOTSTRAP_CHALLENGE.hex(),
        },
        "hkdf": {
            "saltUtf8": BOOTSTRAP_SALT.decode("utf-8"),
            "signInfoUtf8": SIGN_INFO.decode("utf-8"),
            "kemInfoUtf8": KEM_INFO.decode("utf-8"),
        },
        "cases": [
            {
                "label": "fixture-secp-priv-01",
                "secpPrivHex": "01" * 32,
                **derive("01" * 32),
            },
            {
                "label": "fixture-secp-priv-cafe",
                "secpPrivHex": "ca" * 32,
                **derive("ca" * 32),
            },
        ],
    }
    out_path = pathlib.Path(__file__).resolve().parents[1] / "identity-derivation-secp256k1.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
