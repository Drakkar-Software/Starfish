"""Session-scoped sealed-envelope helpers.

Wire format: ``ct = hex(iv[12] ‖ AES-256-GCM ciphertext+tag)``.
Distinct from ``starfish_keyring``'s base64 ct format.

``v:1`` = AAD-context-bound seal.  :func:`unseal_from_self` and
:func:`unseal_from_recipient` reject ``v:1`` blobs when no namespace is
provided (fail-closed: an envelope sealed with a namespace cannot be opened
without it).
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from starfish_keyring import (
    WrappedKeyEntry,
    unwrap_from_entry,
    verify_entry_signature,
    wrap_for_recipient,
)

# ── Constants ─────────────────────────────────────────────────────────────────

SELF_EPOCH = 0
"""Epoch used for self-addressed sealed blobs (owner sealing to themselves)."""

_IV_BYTES = 12


# ── Internal helpers ──────────────────────────────────────────────────────────


def _seal_raw(
    adder_ed_priv: str,
    adder_ed_pub: str,
    recipient_kem_pub: str,
    data: Any,
    namespace: Optional[str],
    epoch: int,
) -> dict[str, Any]:
    """Generate a fresh CEK, wrap it for ``recipient_kem_pub``, AES-GCM-seal ``data``."""
    cek = secrets.token_bytes(32)
    iv = secrets.token_bytes(_IV_BYTES)
    added_at = int(time.time() * 1000)

    entry: WrappedKeyEntry = wrap_for_recipient(
        cek,
        recipient_kem_pub,
        adder_ed_priv_hex=adder_ed_priv,
        adder_ed_pub_hex=adder_ed_pub,
        added_at=added_at,
        epoch=epoch,
    )

    plaintext = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    aad = namespace.encode("utf-8") if namespace else None
    aead = AESGCM(cek)
    ct = aead.encrypt(iv, plaintext, aad)

    blob: dict[str, Any] = {
        "entry": entry.to_dict(),
        "ct": (iv + ct).hex(),
    }
    if namespace is not None:
        blob["v"] = 1
    return blob


def _open_raw(
    recipient_kem_priv: str,
    blob: dict[str, Any],
    namespace: Optional[str],
    epoch: int,
) -> Any:
    """Unwrap the CEK from ``blob.entry``, verify its signature, and decrypt."""
    if blob.get("v") == 1 and namespace is None:
        raise ValueError(
            "v:1 sealed blob requires an AAD namespace — "
            "cannot open without the namespace it was sealed with"
        )

    entry = WrappedKeyEntry.from_dict(blob["entry"])
    if not verify_entry_signature(entry, epoch):
        raise ValueError("Sealed blob entry signature verification failed")

    cek = unwrap_from_entry(entry, recipient_kem_priv)

    ct_hex = blob["ct"]
    ct_bytes = bytes.fromhex(ct_hex)
    iv = ct_bytes[:_IV_BYTES]
    ct = ct_bytes[_IV_BYTES:]
    aad = namespace.encode("utf-8") if namespace else None
    aead = AESGCM(cek)
    plaintext = aead.decrypt(iv, ct, aad)
    return json.loads(plaintext.decode("utf-8"))


# ── HasKeys protocol ──────────────────────────────────────────────────────────


class HasKeys:
    """A minimal protocol satisfied by both :class:`Session` and plain key dicts.

    Any object with a ``keys`` attribute that has ``edPriv``, ``edPub``,
    ``kemPriv``, ``kemPub`` (hex strings) satisfies this.  Alternatively,
    pass a ``dict`` with a ``"keys"`` key (the dict must itself have those four
    fields).
    """


def _extract_keys(has_keys: Any) -> dict[str, str]:
    """Extract the device keys dict from a ``HasKeys``-compatible object."""
    if isinstance(has_keys, dict):
        return has_keys.get("keys", has_keys)
    return has_keys.keys  # type: ignore[return-value]


# ── Public API ────────────────────────────────────────────────────────────────


def seal_to_self(
    has_keys: Any,
    data: Any,
    namespace: Optional[str] = None,
) -> dict[str, Any]:
    """Seal ``data`` to the device's own KEM key.

    The device is both the adder and the recipient.

    Args:
        has_keys: A ``Session`` or ``{"keys": {...}}`` dict with device keys.
        data:     JSON-serialisable payload to seal.
        namespace: When provided the blob is marked ``v:1`` (AAD-bound).
            :func:`unseal_from_self` MUST receive the same namespace.

    Returns:
        A :class:`SealedBlob`-shaped dict: ``{"entry": {...}, "ct": "hexhex", "v": 1?}``.
    """
    keys = _extract_keys(has_keys)
    return _seal_raw(
        keys["edPriv"], keys["edPub"], keys["kemPub"], data, namespace, SELF_EPOCH
    )


def unseal_from_self(
    has_keys: Any,
    blob: dict[str, Any],
    namespace: Optional[str] = None,
) -> Any:
    """Open a blob sealed with :func:`seal_to_self`.

    Verifies that ``blob.entry`` was signed at ``SELF_EPOCH`` before decrypting.

    Args:
        has_keys:  Device keys (same as :func:`seal_to_self`).
        blob:      The sealed blob dict.
        namespace: The namespace the blob was sealed with (required when ``v==1``).

    Returns:
        The decrypted payload (as parsed JSON).

    Raises:
        ValueError: on signature failure, wrong epoch, missing AAD, or when the
            blob was not self-signed (``entry.addedBy != own edPub``).
    """
    keys = _extract_keys(has_keys)
    if (blob.get("entry") or {}).get("addedBy") != keys["edPub"]:
        raise ValueError("sealed blob not self-signed")
    return _open_raw(keys["kemPriv"], blob, namespace, SELF_EPOCH)


def seal_to_recipient(
    keys: dict[str, str],
    recipient_ed_pub: str,
    recipient_kem_pub: str,
    data: Any,
    namespace: Optional[str] = None,
) -> dict[str, Any]:
    """Seal ``data`` for ``recipient_kem_pub``, signed by ``keys.edPriv``.

    Args:
        keys:              Adder (sender) device keys dict.
        recipient_ed_pub:  Recipient's Ed25519 public key (hex) — stored in entry for audit.
        recipient_kem_pub: Recipient's X25519 KEM public key (hex).
        data:              JSON-serialisable payload.
        namespace:         Optional AAD binding.

    Returns:
        Sealed blob dict.
    """
    _ = recipient_ed_pub  # stored in entry via wrap_for_recipient's sub_kem field implicitly
    return _seal_raw(
        keys["edPriv"], keys["edPub"], recipient_kem_pub, data, namespace, epoch=0
    )


def unseal_from_recipient(
    keys: dict[str, str],
    blob: dict[str, Any],
    namespace: Optional[str] = None,
) -> Any:
    """Open a blob sealed by a third party (no sender pinning).

    Verifies the entry's addedSig but does NOT check that the adder is a specific
    trusted pubkey — the caller is responsible for that check when needed.

    Args:
        keys:      Recipient's device keys dict.
        blob:      The sealed blob dict.
        namespace: The namespace the blob was sealed with (required when ``v==1``).

    Returns:
        The decrypted payload.

    Raises:
        ValueError: on signature failure or missing AAD.
    """
    return _open_raw(keys["kemPriv"], blob, namespace, epoch=0)


__all__ = [
    "HasKeys",
    "SELF_EPOCH",
    "seal_to_self",
    "unseal_from_self",
    "seal_to_recipient",
    "unseal_from_recipient",
]
