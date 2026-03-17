"""AES-256-GCM encrypted object store wrapper."""


import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from starfish_protocol.crypto import _derive_key, IV_BYTES
from starfish_server.storage.base import AbstractObjectStore
from starfish_server.constants import HKDF_INFO_DEFAULT


class EncryptedObjectStore(AbstractObjectStore):
    """Wraps an AbstractObjectStore to transparently encrypt/decrypt all values.

    Keys (paths) are NOT encrypted — only the stored content.
    """

    def __init__(
        self,
        inner: AbstractObjectStore,
        secret: str,
        salt: str,
        info: str = HKDF_INFO_DEFAULT,
    ) -> None:
        self._inner = inner
        key = _derive_key(secret, salt, info.encode("utf-8"))
        self._aesgcm = AESGCM(key)

    def _encrypt(self, plaintext: str) -> str:
        iv = os.urandom(IV_BYTES)
        data = plaintext.encode("utf-8")
        ciphertext = self._aesgcm.encrypt(iv, data, None)
        combined = iv + ciphertext
        return base64.b64encode(combined).decode("ascii")

    def _decrypt(self, encoded: str) -> str:
        combined = base64.b64decode(encoded)
        if len(combined) < IV_BYTES:
            raise ValueError("Encrypted data is too short")
        iv = combined[:IV_BYTES]
        ciphertext = combined[IV_BYTES:]
        try:
            plaintext = self._aesgcm.decrypt(iv, ciphertext, None)
        except InvalidTag as exc:
            raise ValueError("Decryption failed: data may be tampered or key is incorrect") from exc
        return plaintext.decode("utf-8")

    async def get_string(self, key: str) -> str | None:
        raw = await self._inner.get_string(key)
        if raw is None:
            return None
        return self._decrypt(raw)

    async def put(
        self,
        key: str,
        body: str,
        *,
        content_type: str | None = None,
        cache_control: str | None = None,
    ) -> None:
        encrypted = self._encrypt(body)
        await self._inner.put(key, encrypted, content_type=content_type, cache_control=cache_control)

    async def list_keys(
        self,
        prefix: str,
        *,
        start_after: str | None = None,
        limit: int | None = None,
    ) -> list[str]:
        return await self._inner.list_keys(prefix, start_after=start_after, limit=limit)

    async def delete(self, key: str) -> None:
        await self._inner.delete(key)

    async def delete_many(self, keys: list[str]) -> None:
        await self._inner.delete_many(keys)
