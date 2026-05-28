"""v3.0 multi-recipient keyring with delegated encryption.

Each ``WrappedKeyEntry`` uses per-entry ephemeral X25519 ECDH (HPKE-DHKEM-style)::

    shared   = X25519(eph_priv, recipient.sub_kem)
    wrap_key = HKDF-SHA256(shared, salt="starfish-wrap", info="starfish-wrap")
    ct       = base64( iv || AES-256-GCM(wrap_key, iv, cek) )
    added_sig = base64( Ed25519(adder.priv, stable_stringify(canonical)) )

Starfish speaks ed25519 only on the wire — the keyring entry carries no suite
discriminator. Recipients are identified by exact ``sub_kem`` match.

This module replaces the removed v2 ``starfish_sdk.group`` module: the
per-collection delegated keyring is the only encryption surface.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from starfish_protocol.hash import stable_stringify
from starfish_protocol.suites import ed25519 as ed25519_suite

from ._crypto_helpers import hkdf_bytes

# ── Locked protocol constants ─────────────────────────────────────────────────

KEYRING_WRAP_SALT: bytes = b"starfish-wrap"
"""HKDF salt for wrap-key derivation. Locked by the cross-language vector."""

KEYRING_WRAP_INFO: bytes = b"starfish-wrap"
"""HKDF info for wrap-key derivation. Locked by the cross-language vector."""

KEYRING_IV_BYTES: int = 12
"""AES-GCM IV length used by the wrap layer."""

KEYRING_BLOB_EPOCH_HEADER_BYTES: int = 4
"""Big-endian u32 epoch header prepended to a sealed blob."""


def _blob_aad(epoch: int, aad: str | None) -> bytes:
    """Additional authenticated data binding a sealed blob to its epoch + path."""
    return f"starfish-blob:{epoch}:{aad if aad is not None else ''}".encode("utf-8")


# ── Types ─────────────────────────────────────────────────────────────────────


@dataclass
class WrappedKeyEntry:
    """A single recipient's wrapped CEK, with audit signature from the adder."""

    sub_kem: str
    """Recipient X25519 KEM pubkey (hex)."""

    eph_kem: str
    """Ephemeral X25519 KEM pubkey for this entry (hex)."""

    ct: str
    """``base64(iv || AES-GCM(wrap_key, iv, cek))``."""

    added_by: str
    """Adder's Ed25519 signing pubkey (hex)."""

    added_sig: str
    """Ed25519 signature over the canonical signing input, base64."""

    added_at: int
    """Unix seconds when the entry was added."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "subKem": self.sub_kem,
            "ephKem": self.eph_kem,
            "ct": self.ct,
            "addedBy": self.added_by,
            "addedSig": self.added_sig,
            "addedAt": self.added_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WrappedKeyEntry":
        return cls(
            sub_kem=data["subKem"],
            eph_kem=data["ephKem"],
            ct=data["ct"],
            added_by=data["addedBy"],
            added_sig=data["addedSig"],
            added_at=int(data["addedAt"]),
        )


@dataclass
class KeyringEpoch:
    """All recipients with access to a given CEK epoch."""

    wrapped_keys: list[WrappedKeyEntry] = field(default_factory=list)
    created_at: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "wrappedKeys": [e.to_dict() for e in self.wrapped_keys],
            "createdAt": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KeyringEpoch":
        return cls(
            wrapped_keys=[WrappedKeyEntry.from_dict(e) for e in data.get("wrappedKeys", [])],
            created_at=int(data.get("createdAt", 0)),
        )


@dataclass
class Keyring:
    """Full keyring document, suitable for pushing to a Starfish collection."""

    v: int = 1
    current_epoch: int = 1
    epochs: dict[str, KeyringEpoch] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": self.v,
            "currentEpoch": self.current_epoch,
            "epochs": {k: e.to_dict() for k, e in self.epochs.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Keyring":
        return cls(
            v=int(data.get("v", 1)),
            current_epoch=int(data["currentEpoch"]),
            epochs={k: KeyringEpoch.from_dict(v) for k, v in data.get("epochs", {}).items()},
        )


# ── Internal helpers ──────────────────────────────────────────────────────────


def _wipe(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


def _canonical_added_sig_input(
    *,
    added_at: int,
    added_by: str,
    ct: str,
    eph_kem: str,
    epoch: int,
    sub_kem: str,
) -> str:
    """Canonical signing input. Stable-stringify of the six base keys."""
    return stable_stringify(
        {
            "addedAt": added_at,
            "addedBy": added_by,
            "ct": ct,
            "ephKem": eph_kem,
            "epoch": epoch,
            "subKem": sub_kem,
        }
    )


# ── Core wrap / unwrap ────────────────────────────────────────────────────────


def wrap_for_recipient(
    cek: bytes,
    recipient_kem_pub_hex: str,
    *,
    adder_ed_priv_hex: str,
    adder_ed_pub_hex: str,
    added_at: int,
    epoch: int,
    eph_priv: bytes | None = None,
    iv: bytes | None = None,
) -> WrappedKeyEntry:
    """Wrap a CEK for a single recipient using ephemeral X25519 ECDH.

    Generates a fresh ephemeral X25519 keypair (or uses ``eph_priv`` if provided,
    useful for reproducible vectors), runs X25519 ECDH with the recipient's KEM
    pubkey, derives the wrap key via HKDF-SHA256, and encrypts the CEK with
    AES-256-GCM. The adder signs the entry with Ed25519 for audit.
    """
    eph_priv_hex = eph_priv.hex() if eph_priv is not None else ed25519_suite.generate_kem_keypair()[0]
    eph_kem_hex = ed25519_suite.kem_public(eph_priv_hex)

    shared = bytearray(ed25519_suite.derive_shared_secret(eph_priv_hex, recipient_kem_pub_hex))
    wrap_key = bytearray(hkdf_bytes(bytes(shared), KEYRING_WRAP_SALT, KEYRING_WRAP_INFO, 32))
    try:
        iv_bytes = iv if iv is not None else secrets.token_bytes(KEYRING_IV_BYTES)
        aead = AESGCM(bytes(wrap_key))
        ct_bytes = aead.encrypt(iv_bytes, cek, None)
        ct_b64 = base64.b64encode(iv_bytes + ct_bytes).decode("ascii")

        canonical = _canonical_added_sig_input(
            added_at=added_at,
            added_by=adder_ed_pub_hex,
            ct=ct_b64,
            eph_kem=eph_kem_hex,
            epoch=epoch,
            sub_kem=recipient_kem_pub_hex,
        )
        added_sig = base64.b64encode(
            ed25519_suite.sign(canonical.encode("utf-8"), adder_ed_priv_hex)
        ).decode("ascii")

        return WrappedKeyEntry(
            sub_kem=recipient_kem_pub_hex,
            eph_kem=eph_kem_hex,
            ct=ct_b64,
            added_by=adder_ed_pub_hex,
            added_sig=added_sig,
            added_at=added_at,
        )
    finally:
        _wipe(shared)
        _wipe(wrap_key)


def unwrap_from_entry(entry: WrappedKeyEntry, recipient_kem_priv_hex: str) -> bytes:
    """Recover the CEK from a ``WrappedKeyEntry`` using the recipient's X25519 key."""
    shared = ed25519_suite.derive_shared_secret(recipient_kem_priv_hex, entry.eph_kem)
    wrap_key = hkdf_bytes(shared, KEYRING_WRAP_SALT, KEYRING_WRAP_INFO, 32)

    blob = base64.b64decode(entry.ct)
    if len(blob) < KEYRING_IV_BYTES:
        raise ValueError("Wrapped entry ciphertext shorter than IV length")
    iv = blob[:KEYRING_IV_BYTES]
    ct = blob[KEYRING_IV_BYTES:]
    aead = AESGCM(wrap_key)
    try:
        return aead.decrypt(iv, ct, None)
    except InvalidTag as exc:
        raise ValueError("Failed to unwrap CEK: AES-GCM authentication failed") from exc


def verify_entry_signature(entry: WrappedKeyEntry, epoch: int) -> bool:
    """Verify the audit signature on a wrapped key entry."""
    canonical = _canonical_added_sig_input(
        added_at=entry.added_at,
        added_by=entry.added_by,
        ct=entry.ct,
        eph_kem=entry.eph_kem,
        epoch=epoch,
        sub_kem=entry.sub_kem,
    )
    try:
        sig = base64.b64decode(entry.added_sig)
        return ed25519_suite.verify(sig, canonical.encode("utf-8"), entry.added_by)
    except Exception:
        return False


# ── Keyring lifecycle ─────────────────────────────────────────────────────────


def create_keyring(
    adder_ed_priv_hex: str,
    adder_ed_pub_hex: str,
    recipients: list[str],
    cek: bytes | None = None,
    added_at: int | None = None,
) -> tuple[Keyring, bytes]:
    """Create a brand-new keyring at epoch 1 wrapping a CEK for every recipient.

    Args:
        adder_ed_priv_hex: Adder's Ed25519 signing private key (hex).
        adder_ed_pub_hex: Adder's Ed25519 signing public key (hex).
        recipients: List of recipient X25519 KEM pubkeys (hex).
        cek: Optional 32-byte CEK; generated randomly if omitted.
        added_at: Optional unix-seconds timestamp; defaults to now.

    Returns:
        ``(keyring, cek)``.
    """
    import time

    resolved_cek = cek if cek is not None else secrets.token_bytes(32)
    timestamp = added_at if added_at is not None else int(time.time())

    wrapped: list[WrappedKeyEntry] = []
    for sub_kem_hex in recipients:
        wrapped.append(
            wrap_for_recipient(
                resolved_cek,
                sub_kem_hex,
                adder_ed_priv_hex=adder_ed_priv_hex,
                adder_ed_pub_hex=adder_ed_pub_hex,
                added_at=timestamp,
                epoch=1,
            )
        )
    keyring = Keyring(
        v=1,
        current_epoch=1,
        epochs={"1": KeyringEpoch(wrapped_keys=wrapped, created_at=timestamp)},
    )
    return keyring, resolved_cek


def add_recipient(
    keyring: Keyring,
    adder_ed_priv_hex: str,
    adder_ed_pub_hex: str,
    current_cek: bytes,
    recipient_kem_hex: str,
    added_at: int | None = None,
) -> Keyring:
    """Append a new recipient to the current epoch."""
    import time

    epoch_key = str(keyring.current_epoch)
    epoch = keyring.epochs.get(epoch_key)
    if epoch is None:
        raise ValueError(f"Epoch {keyring.current_epoch} not found in keyring")
    if any(e.sub_kem == recipient_kem_hex for e in epoch.wrapped_keys):
        raise ValueError(
            f"Recipient {recipient_kem_hex} already present in epoch {keyring.current_epoch}"
        )

    timestamp = added_at if added_at is not None else int(time.time())
    entry = wrap_for_recipient(
        current_cek,
        recipient_kem_hex,
        adder_ed_priv_hex=adder_ed_priv_hex,
        adder_ed_pub_hex=adder_ed_pub_hex,
        added_at=timestamp,
        epoch=keyring.current_epoch,
    )
    new_epoch = KeyringEpoch(
        wrapped_keys=[*epoch.wrapped_keys, entry],
        created_at=epoch.created_at,
    )
    return Keyring(
        v=keyring.v,
        current_epoch=keyring.current_epoch,
        epochs={**keyring.epochs, epoch_key: new_epoch},
    )


def rotate_epoch(
    keyring: Keyring,
    adder_ed_priv_hex: str,
    adder_ed_pub_hex: str,
    retained_recipients: list[str],
    added_at: int | None = None,
) -> tuple[Keyring, bytes]:
    """Mint a new CEK and append a new epoch wrapping for retained recipients."""
    import time

    timestamp = added_at if added_at is not None else int(time.time())
    new_epoch_num = keyring.current_epoch + 1
    new_cek = secrets.token_bytes(32)

    wrapped: list[WrappedKeyEntry] = []
    for sub_kem_hex in retained_recipients:
        wrapped.append(
            wrap_for_recipient(
                new_cek,
                sub_kem_hex,
                adder_ed_priv_hex=adder_ed_priv_hex,
                adder_ed_pub_hex=adder_ed_pub_hex,
                added_at=timestamp,
                epoch=new_epoch_num,
            )
        )
    new_epoch = KeyringEpoch(wrapped_keys=wrapped, created_at=timestamp)
    return (
        Keyring(
            v=keyring.v,
            current_epoch=new_epoch_num,
            epochs={**keyring.epochs, str(new_epoch_num): new_epoch},
        ),
        new_cek,
    )


# ── Encryptor factory ─────────────────────────────────────────────────────────


class KeyringEncryptor:
    """Encryptor whose payloads carry the epoch they were sealed under."""

    def __init__(self, current_epoch: int, epoch_ceks: dict[int, bytes]):
        self._current_epoch = current_epoch
        self._epoch_ceks = epoch_ceks

    def encrypt(self, data: dict[str, Any]) -> dict[str, Any]:
        cek = self._epoch_ceks[self._current_epoch]
        iv = secrets.token_bytes(KEYRING_IV_BYTES)
        aead = AESGCM(cek)
        ct = aead.encrypt(iv, json.dumps(data).encode("utf-8"), None)
        return {
            "_encrypted": base64.b64encode(iv + ct).decode("ascii"),
            "_epoch": self._current_epoch,
        }

    def decrypt(self, payload: dict[str, Any]) -> dict[str, Any]:
        raw_epoch = payload.get("_epoch")
        epoch = raw_epoch if isinstance(raw_epoch, int) else self._current_epoch
        cek = self._epoch_ceks.get(epoch)
        if cek is None:
            raise ValueError(
                f"No key available for epoch {epoch}: this recipient joined the "
                "keyring in a later epoch (e.g. after a rotation) and can't read "
                "content sealed earlier — re-seal it at the current epoch to grant access"
            )
        blob = base64.b64decode(payload["_encrypted"])
        if len(blob) < KEYRING_IV_BYTES:
            raise ValueError("Encrypted payload is too short")
        iv = blob[:KEYRING_IV_BYTES]
        ct = blob[KEYRING_IV_BYTES:]
        aead = AESGCM(cek)
        try:
            pt = aead.decrypt(iv, ct, None)
        except InvalidTag as exc:
            raise ValueError("Decryption failed: payload may be tampered or wrong epoch CEK") from exc
        return json.loads(pt.decode("utf-8"))

    def seal_bytes(self, data: bytes, aad: str | None = None) -> bytes:
        """Seal raw bytes under the current epoch as a self-describing blob."""
        cek = self._epoch_ceks[self._current_epoch]
        iv = secrets.token_bytes(KEYRING_IV_BYTES)
        aead = AESGCM(cek)
        ct = aead.encrypt(iv, data, _blob_aad(self._current_epoch, aad))
        header = self._current_epoch.to_bytes(KEYRING_BLOB_EPOCH_HEADER_BYTES, "big")
        return header + iv + ct

    def open_bytes(self, blob: bytes, aad: str | None = None) -> bytes:
        """Open a blob produced by :meth:`seal_bytes`, verifying the bound ``aad``."""
        header_len = KEYRING_BLOB_EPOCH_HEADER_BYTES + KEYRING_IV_BYTES
        if len(blob) < header_len:
            raise ValueError("open_bytes: blob shorter than its epoch+iv header")
        epoch = int.from_bytes(blob[:KEYRING_BLOB_EPOCH_HEADER_BYTES], "big")
        cek = self._epoch_ceks.get(epoch)
        if cek is None:
            raise ValueError(
                f"No key available for epoch {epoch}: this recipient joined the "
                "keyring in a later epoch (e.g. after a rotation) and can't read "
                "content sealed earlier — re-seal it at the current epoch to grant access"
            )
        iv = blob[KEYRING_BLOB_EPOCH_HEADER_BYTES:header_len]
        ct = blob[header_len:]
        aead = AESGCM(cek)
        try:
            return aead.decrypt(iv, ct, _blob_aad(epoch, aad))
        except InvalidTag as exc:
            raise ValueError(
                "open_bytes: decryption failed — tampered, wrong epoch CEK, or AAD mismatch"
            ) from exc


def create_keyring_encryptor(
    keyring: Keyring,
    recipient_kem_pub_hex: str,
    recipient_kem_priv_hex: str,
    trusted_adders: list[str] | None = None,
    *,
    min_epoch: int | None = None,
) -> KeyringEncryptor:
    """Build a ``KeyringEncryptor`` for the given recipient.

    Pre-unwraps the CEK for every epoch the recipient appears in. ``trusted_adders``
    is REQUIRED — without a provenance pin a hostile server could substitute a
    forged wrapped-key entry (the ``addedSig`` is self-attesting).
    """
    import logging

    _log = logging.getLogger(__name__)
    if not trusted_adders:
        raise ValueError(
            "create_keyring_encryptor: `trusted_adders` is required — pass the Ed25519 "
            "pubkey(s) you trust to grant keyring access (e.g. the collection owner's root "
            "key). Without it a hostile server could substitute a wrapped-key entry (the "
            "addedSig is self-attesting)."
        )
    if min_epoch is not None and keyring.current_epoch < min_epoch:
        raise ValueError(
            f"create_keyring_encryptor: keyring epoch {keyring.current_epoch} is below the "
            f"last-seen epoch {min_epoch} — possible rollback by a hostile server; refusing "
            "to adopt a stale keyring."
        )
    trusted = set(trusted_adders)
    epoch_ceks: dict[int, bytes] = {}
    for epoch_str, epoch in keyring.epochs.items():
        matches = [e for e in epoch.wrapped_keys if e.sub_kem == recipient_kem_pub_hex]
        if not matches:
            continue
        epoch_num = int(epoch_str)
        if len(matches) > 1:
            _log.warning(
                "skipping epoch %d for recipient %s: %d entries share this subKem (tampering)",
                epoch_num,
                recipient_kem_pub_hex,
                len(matches),
            )
            continue
        entry = matches[0]
        if entry.added_by not in trusted:
            _log.warning(
                "skipping epoch %d for recipient %s: addedBy %s is not a trusted adder",
                epoch_num,
                recipient_kem_pub_hex,
                entry.added_by,
            )
            continue
        if not verify_entry_signature(entry, epoch_num):
            _log.warning(
                "skipping epoch %d for recipient %s: addedSig verification failed",
                epoch_num,
                recipient_kem_pub_hex,
            )
            continue
        try:
            cek = unwrap_from_entry(entry, recipient_kem_priv_hex)
            epoch_ceks[epoch_num] = cek
        except Exception:
            continue

    if keyring.current_epoch not in epoch_ceks:
        raise ValueError(
            f"No wrapped key for recipient {recipient_kem_pub_hex} in current epoch {keyring.current_epoch}"
        )
    return KeyringEncryptor(current_epoch=keyring.current_epoch, epoch_ceks=epoch_ceks)
