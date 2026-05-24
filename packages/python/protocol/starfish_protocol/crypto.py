"""Shared cryptographic primitives for the Starfish sync protocol."""


from typing import Any, Protocol, runtime_checkable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

IV_BYTES = 12
ENCRYPTED_KEY = "_encrypted"


@runtime_checkable
class Encryptor(Protocol):
    """Encrypt/decrypt contract for client-side E2E encryption.

    Defined as a structural :class:`typing.Protocol` (not an ABC) because
    implementations such as the keyring's ``KeyringEncryptor`` conform by
    shape rather than by subclassing. Lives in the shared protocol layer so
    the client (``SyncManager``) and the implementations can both reference
    the contract without a package dependency cycle.
    """

    def encrypt(self, data: dict[str, Any]) -> dict[str, Any]: ...

    def decrypt(self, wrapper: dict[str, Any]) -> dict[str, Any]: ...


def derive_key(secret: str, salt: str, info: bytes) -> bytes:
    """Derive a 256-bit AES key from a secret and salt using HKDF(SHA-256).

    Mirrors the TypeScript :func:`deriveKey`.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode("utf-8"),
        info=info,
    )
    return hkdf.derive(secret.encode("utf-8"))
