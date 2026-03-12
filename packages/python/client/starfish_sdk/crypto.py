"""Client-side AES-256-GCM encryption for end-to-end encrypted sync."""

import base64
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from starfish_protocol.crypto import _derive_key, IV_BYTES, ENCRYPTED_KEY


class Encryptor:
    """AES-256-GCM encryptor with HKDF-derived keys for client-side E2E encryption."""

    def __init__(self, secret: str, salt: str, info: str = "starfish-e2e") -> None:
        key = _derive_key(secret, salt, info.encode("utf-8"))
        self._aesgcm = AESGCM(key)

    def encrypt(self, data: dict[str, Any]) -> dict[str, Any]:
        """Encrypt a plaintext data dict into ``{ _encrypted: "<base64>" }``."""
        plaintext = json.dumps(data).encode("utf-8")
        iv = os.urandom(IV_BYTES)
        ciphertext = self._aesgcm.encrypt(iv, plaintext, None)
        combined = iv + ciphertext
        encoded = base64.b64encode(combined).decode("ascii")
        return {ENCRYPTED_KEY: encoded}

    def decrypt(self, wrapper: dict[str, Any]) -> dict[str, Any]:
        """Decrypt an encrypted wrapper back to the original data dict.

        Raises ``ValueError`` if the wrapper does not contain encrypted data.
        """
        encoded = wrapper.get(ENCRYPTED_KEY)
        if not isinstance(encoded, str):
            raise ValueError("Expected encrypted data but received unencrypted document")

        combined = base64.b64decode(encoded)
        if len(combined) < IV_BYTES:
            raise ValueError("Encrypted data is too short")
        iv = combined[:IV_BYTES]
        ciphertext = combined[IV_BYTES:]
        try:
            plaintext = self._aesgcm.decrypt(iv, ciphertext, None)
        except InvalidTag as exc:
            raise ValueError("Decryption failed: data may be tampered or key is incorrect") from exc
        return json.loads(plaintext.decode("utf-8"))


def create_encryptor(secret: str, salt: str, info: str = "starfish-e2e") -> Encryptor:
    if not secret:
        raise ValueError("encryption secret must not be empty")
    if not salt:
        raise ValueError("encryption salt must not be empty")
    return Encryptor(secret, salt, info)
