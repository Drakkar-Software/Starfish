"""Internal crypto helpers shared by identity, keyring, and pairing.

The leading underscore on the module name marks this as module-private — it
is NOT re-exported from ``__init__.py``. External consumers should not
import it.

This helper was previously duplicated verbatim across three modules
(``identity.py``, ``keyring.py``, ``pairing.py``); consolidating it keeps
the byte-level behavior identical while removing copy-paste drift risk.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def hkdf_bytes(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 → ``length`` raw bytes.

    Mirrors the TypeScript ``hkdfBytes`` (Web Crypto ``deriveBits``) so
    cross-language test vectors remain byte-identical.
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)
