"""Shared cryptographic primitives for the Starfish sync protocol."""


from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

IV_BYTES = 12
ENCRYPTED_KEY = "_encrypted"


def _derive_key(secret: str, salt: str, info: bytes) -> bytes:
    """Derive a 256-bit AES key from a secret and salt using HKDF(SHA-256)."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode("utf-8"),
        info=info,
    )
    return hkdf.derive(secret.encode("utf-8"))
