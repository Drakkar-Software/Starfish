"""v3.0 multi-recipient keyring with delegated encryption.

Each ``WrappedKeyEntry`` uses per-entry ephemeral ECDH (HPKE-DHKEM-style),
dispatched by the recipient's KEM suite (``kemAlg``)::

    shared   = suite(kemAlg).derive_shared_secret(eph_priv, recipient.kem_pub)
    wrap_key = HKDF-SHA256(shared, salt="starfish-wrap", info=wrap_info(kemAlg))
    ct       = base64( iv || AES-256-GCM(wrap_key, iv, cek) )
    added_sig = base64( suite(addedByAlg).sign(adder.priv, stable_stringify(canonical)) )

``kemAlg`` / ``addedByAlg`` are optional and default to ``ed25519`` (tolerant
reader); both are folded into the ``added_sig`` canonical input ONLY when present
so an ``ed25519`` entry is byte-identical to the pre-suite format (the existing
cross-language wrap vector is the no-drift proof). Recipients are identified by
exact ``subKem`` match (for a same-suite secp256k1 recipient, ``subKem`` is their
one secp256k1 key — see ``recipient_kem`` in the protocol package).

This module replaces the removed v2 ``starfish_sdk.group`` module (deleted in
3.0): the per-collection delegated keyring is the only encryption surface.
"""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from starfish_protocol.hash import stable_stringify
from starfish_protocol.suites import DEFAULT_ALG, get_suite

from ._crypto_helpers import hkdf_bytes

# ── Locked protocol constants ─────────────────────────────────────────────────

KEYRING_WRAP_SALT: bytes = b"starfish-wrap"
"""HKDF salt for wrap-key derivation. Locked by the cross-language vector."""

KEYRING_WRAP_INFO: bytes = b"starfish-wrap"
"""HKDF info for wrap-key derivation. Locked by the cross-language vector."""

KEYRING_IV_BYTES: int = 12
"""AES-GCM IV length used by the wrap layer."""

KEYRING_BLOB_EPOCH_HEADER_BYTES: int = 4
"""Big-endian u32 epoch header prepended to a sealed blob (see ``seal_bytes``)."""


def _blob_aad(epoch: int, aad: str | None) -> bytes:
    """Additional authenticated data binding a sealed blob to its epoch + path.

    Byte-for-byte identical to the TS keyring's ``blobAad`` — the ``aad`` is
    rendered as ``""`` only when ``None`` (mirroring TS's ``aad ?? ""``; an empty
    string passed explicitly stays empty), so a blob sealed by one language opens
    in the other.
    """
    return f"starfish-blob:{epoch}:{aad if aad is not None else ''}".encode("utf-8")


# ── Types ─────────────────────────────────────────────────────────────────────


@dataclass
class WrappedKeyEntry:
    """A single recipient's wrapped CEK, with audit signature from the adder."""

    sub_kem: str
    """Recipient KEM pubkey (hex) of suite ``kem_alg`` (X25519 for ed25519)."""

    eph_kem: str
    """Ephemeral KEM pubkey for this entry (hex), of suite ``kem_alg``."""

    ct: str
    """``base64(iv || AES-GCM(wrap_key, iv, cek))``."""

    added_by: str
    """Adder's signing pubkey (hex), of suite ``added_by_alg``."""

    added_sig: str
    """Signature over the canonical signing input under ``added_by_alg``, base64."""

    added_at: int
    """Unix seconds when the entry was added."""

    kem_alg: Optional[str] = None
    """Recipient KEM suite. Absent ⇒ ``ed25519`` (X25519). Folded into ``added_sig`` when present."""

    added_by_alg: Optional[str] = None
    """Adder's signing suite. Absent ⇒ ``ed25519``. Folded into ``added_sig`` when present."""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "subKem": self.sub_kem,
            "ephKem": self.eph_kem,
            "ct": self.ct,
            "addedBy": self.added_by,
            "addedSig": self.added_sig,
            "addedAt": self.added_at,
        }
        if self.kem_alg is not None:
            out["kemAlg"] = self.kem_alg
        if self.added_by_alg is not None:
            out["addedByAlg"] = self.added_by_alg
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "WrappedKeyEntry":
        return cls(
            sub_kem=data["subKem"],
            eph_kem=data["ephKem"],
            ct=data["ct"],
            added_by=data["addedBy"],
            added_sig=data["addedSig"],
            added_at=int(data["addedAt"]),
            kem_alg=data.get("kemAlg"),
            added_by_alg=data.get("addedByAlg"),
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


def _wrap_info(kem_alg: str) -> bytes:
    """HKDF ``info`` for the wrap key, domain-separated per KEM suite. The
    ``ed25519``/X25519 value (``b"starfish-wrap"``) is **frozen by the existing
    cross-language vector and must not change**; other suites get a distinct
    info so a shared secret from one curve can never derive the same wrap key."""
    return KEYRING_WRAP_INFO if kem_alg == "ed25519" else f"starfish-wrap:{kem_alg}".encode("utf-8")


def _tag_if_present(alg: str) -> Optional[str]:
    """A present alg tag, or ``None`` when it is the ``ed25519`` default (omitted on the wire)."""
    return None if alg == DEFAULT_ALG else alg


def _wipe(buf: bytearray) -> None:
    """Best-effort overwrite of a mutable secret buffer.

    Python ``bytes`` are immutable, so the only secrets we can actually scrub
    are the ``bytearray`` copies we hold; the immutable buffers the crypto
    library returns cannot be wiped. This mirrors the TypeScript wrap's
    ``.fill(0)`` of the shared secret, wrap key, and ephemeral private key.
    """
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
    kem_alg: Optional[str] = None,
    added_by_alg: Optional[str] = None,
) -> str:
    """Canonical signing input. Stable-stringify of the six base keys, plus
    ``kemAlg`` / ``addedByAlg`` **only when present**. The tolerant-reader rule:
    an ``ed25519``/X25519 entry omits both, so its canonical input is
    byte-identical to the pre-suite format (the existing cross-language wrap
    vector is the regression proof). Stripping a present tag changes these bytes
    ⇒ ``added_sig`` fails ⇒ fail closed (downgrade caught)."""
    obj: dict[str, Any] = {
        "addedAt": added_at,
        "addedBy": added_by,
        "ct": ct,
        "ephKem": eph_kem,
        "epoch": epoch,
        "subKem": sub_kem,
    }
    if kem_alg is not None:
        obj["kemAlg"] = kem_alg
    if added_by_alg is not None:
        obj["addedByAlg"] = added_by_alg
    return stable_stringify(obj)


# ── Core wrap / unwrap ────────────────────────────────────────────────────────


def wrap_for_recipient(
    cek: bytes,
    recipient_kem_pub_hex: str,
    *,
    adder_ed_priv_hex: str,
    adder_ed_pub_hex: str,
    added_at: int,
    epoch: int,
    kem_alg: str = DEFAULT_ALG,
    added_by_alg: str = DEFAULT_ALG,
    eph_priv: bytes | None = None,
    iv: bytes | None = None,
) -> WrappedKeyEntry:
    """Wrap a CEK for a single recipient using ephemeral ECDH under the
    recipient's KEM suite (``kem_alg``, default ``ed25519``/X25519).

    Generates a fresh ephemeral keypair of that suite (or uses ``eph_priv`` if
    provided, useful for reproducible vectors), runs the suite ECDH with the
    recipient's KEM pubkey, derives the wrap key via HKDF-SHA256 (info
    domain-separated per suite), and encrypts the CEK with AES-256-GCM. The adder
    signs the entry under ``added_by_alg`` (default ``ed25519``) for audit.
    """
    kem_suite = get_suite(kem_alg)
    sign_suite = get_suite(added_by_alg)

    eph_priv_hex = eph_priv.hex() if eph_priv is not None else kem_suite.generate_kem_keypair()[0]
    eph_kem_hex = kem_suite.kem_public(eph_priv_hex)

    # derive_shared_secret asserts a usable (non-degenerate) secret, fail closed.
    shared = bytearray(kem_suite.derive_shared_secret(eph_priv_hex, recipient_kem_pub_hex))
    wrap_key = bytearray(hkdf_bytes(bytes(shared), KEYRING_WRAP_SALT, _wrap_info(kem_alg), 32))
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
            kem_alg=_tag_if_present(kem_alg),
            added_by_alg=_tag_if_present(added_by_alg),
        )
        added_sig = base64.b64encode(
            sign_suite.sign(canonical.encode("utf-8"), adder_ed_priv_hex)
        ).decode("ascii")

        return WrappedKeyEntry(
            sub_kem=recipient_kem_pub_hex,
            eph_kem=eph_kem_hex,
            ct=ct_b64,
            added_by=adder_ed_pub_hex,
            added_sig=added_sig,
            added_at=added_at,
            kem_alg=_tag_if_present(kem_alg),
            added_by_alg=_tag_if_present(added_by_alg),
        )
    finally:
        # Best-effort wipe of secret intermediates before returning. The eph
        # private is a hex string from the suite (immutable), so — like the TS
        # wrap — only the shared secret and wrap key are scrubbed.
        _wipe(shared)
        _wipe(wrap_key)


def unwrap_from_entry(entry: WrappedKeyEntry, recipient_kem_priv_hex: str) -> bytes:
    """Recover the CEK from a ``WrappedKeyEntry`` using the recipient's KEM key.

    Raises ``ValueError`` if AES-GCM authentication fails.
    """
    # Only None defaults (mirror TS `?? DEFAULT_ALG`); a tampered "" tag flows to
    # get_suite("") and fails closed identically to TS, not silently to ed25519.
    kem_alg = DEFAULT_ALG if entry.kem_alg is None else entry.kem_alg
    # derive_shared_secret asserts a usable secret + validates the peer point, fail closed.
    shared = get_suite(kem_alg).derive_shared_secret(recipient_kem_priv_hex, entry.eph_kem)
    wrap_key = hkdf_bytes(shared, KEYRING_WRAP_SALT, _wrap_info(kem_alg), 32)

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
    """Verify the audit signature on a wrapped key entry, dispatched on the
    entry's ``added_by_alg``. Re-derives the canonical input from the entry's own
    (possibly absent) tags: a stripped/swapped kemAlg or addedByAlg changes those
    bytes and fails here."""
    canonical = _canonical_added_sig_input(
        added_at=entry.added_at,
        added_by=entry.added_by,
        ct=entry.ct,
        eph_kem=entry.eph_kem,
        epoch=epoch,
        sub_kem=entry.sub_kem,
        kem_alg=entry.kem_alg,
        added_by_alg=entry.added_by_alg,
    )
    # get_suite() is INSIDE the try: an unknown/unimplemented addedByAlg on a
    # (server-supplied) entry must fail closed to False, not raise — otherwise a
    # tampered entry could DoS recoverCurrentCek/listRecipients. Mirrors TS.
    try:
        sig = base64.b64decode(entry.added_sig)
        # Only None defaults (mirror TS `?? DEFAULT_ALG`): a tampered "" addedByAlg
        # makes get_suite("") raise → caught → False, matching TS (not coerced to
        # ed25519, which would fork verification across languages).
        added_by_alg = DEFAULT_ALG if entry.added_by_alg is None else entry.added_by_alg
        return get_suite(added_by_alg).verify(
            sig, canonical.encode("utf-8"), entry.added_by
        )
    except Exception:
        return False


# ── Keyring lifecycle ─────────────────────────────────────────────────────────


# A recipient is either a bare KEM pubkey hex (ed25519/X25519) or a
# ``(kem_pub_hex, kem_alg)`` pair for another suite (e.g. secp256k1-schnorr).
RecipientSpec = "str | tuple[str, str]"


def _normalize_recipient(r: "str | tuple[str, str]") -> tuple[str, str]:
    return (r, DEFAULT_ALG) if isinstance(r, str) else (r[0], r[1])


def create_keyring(
    adder_ed_priv_hex: str,
    adder_ed_pub_hex: str,
    recipients: "list[str | tuple[str, str]]",
    cek: bytes | None = None,
    added_at: int | None = None,
    *,
    added_by_alg: str = DEFAULT_ALG,
) -> tuple[Keyring, bytes]:
    """Create a brand-new keyring at epoch 1 wrapping a CEK for every recipient.

    Args:
        adder_ed_priv_hex: Adder's signing private key (hex), suite ``added_by_alg``.
        adder_ed_pub_hex: Adder's signing public key (hex).
        recipients: Each entry is a KEM pubkey hex (ed25519/X25519) or a
            ``(kem_pub_hex, kem_alg)`` pair for another suite.
        cek: Optional 32-byte CEK; generated randomly if omitted.
        added_at: Optional unix-seconds timestamp; defaults to now.
        added_by_alg: Adder's signing suite (governs each entry's ``addedSig``).

    Returns:
        ``(keyring, cek)`` — admin keeps the raw CEK to add future members.
    """
    import time

    resolved_cek = cek if cek is not None else secrets.token_bytes(32)
    timestamp = added_at if added_at is not None else int(time.time())

    wrapped: list[WrappedKeyEntry] = []
    for r in recipients:
        sub_kem_hex, kem_alg = _normalize_recipient(r)
        wrapped.append(
            wrap_for_recipient(
                resolved_cek,
                sub_kem_hex,
                adder_ed_priv_hex=adder_ed_priv_hex,
                adder_ed_pub_hex=adder_ed_pub_hex,
                added_at=timestamp,
                epoch=1,
                kem_alg=kem_alg,
                added_by_alg=added_by_alg,
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
    *,
    kem_alg: str = DEFAULT_ALG,
    added_by_alg: str = DEFAULT_ALG,
) -> Keyring:
    """Append a new recipient to the current epoch.

    The newcomer is wrapped into the CURRENT epoch ONLY. Documents sealed under
    an EARLIER epoch (e.g. before a revoke rotated the epoch) stay unreadable to
    them, surfacing as "No key available for epoch N" on decrypt. To share
    existing content, re-seal it at the current epoch (decrypt with a recipient
    that holds the old CEK, then re-encrypt) after adding them.

    Raises ``ValueError`` if a recipient with the same ``subKem`` already
    exists in the current epoch.
    """
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
        kem_alg=kem_alg,
        added_by_alg=added_by_alg,
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
    retained_recipients: "list[str | tuple[str, str]]",
    added_at: int | None = None,
    *,
    added_by_alg: str = DEFAULT_ALG,
) -> tuple[Keyring, bytes]:
    """Mint a new CEK and append a new epoch wrapping for retained recipients.

    Each retained recipient is a KEM pubkey hex (ed25519/X25519) or a
    ``(kem_pub_hex, kem_alg)`` pair. Old epochs are preserved unchanged.
    """
    import time

    timestamp = added_at if added_at is not None else int(time.time())
    new_epoch_num = keyring.current_epoch + 1
    new_cek = secrets.token_bytes(32)

    wrapped: list[WrappedKeyEntry] = []
    for r in retained_recipients:
        sub_kem_hex, kem_alg = _normalize_recipient(r)
        wrapped.append(
            wrap_for_recipient(
                new_cek,
                sub_kem_hex,
                adder_ed_priv_hex=adder_ed_priv_hex,
                adder_ed_pub_hex=adder_ed_pub_hex,
                added_at=timestamp,
                epoch=new_epoch_num,
                kem_alg=kem_alg,
                added_by_alg=added_by_alg,
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
    """Encryptor whose payloads carry the epoch they were sealed under.

    ``encrypt(data)`` returns ``{"_encrypted": "<base64(iv || ct)>", "_epoch": N}``.
    ``decrypt(payload)`` locates the recipient's entry for the given epoch and
    unwraps the matching epoch's CEK (cached after first use). Falls back to
    ``current_epoch`` if ``_epoch`` is missing on the payload.
    """

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
        """Seal raw bytes under the current epoch as a self-describing blob.

        Layout — ``[u32 BE epoch][12-byte iv][AES-256-GCM ciphertext‖tag]`` —
        suitable for storing directly via the client's ``push_blob``. The epoch
        and the caller's ``aad`` (e.g. the blob's storage path) are bound into
        the GCM tag so a hostile server cannot relocate the blob to another path
        or replay it at a different epoch. Use for large binary payloads
        (attachments) the JSON ``encrypt`` path would otherwise base64-inflate.

        Byte-compatible with the TS keyring's ``sealBytes`` — a blob sealed here
        opens with TS ``openBytes`` and vice-versa.
        """
        cek = self._epoch_ceks[self._current_epoch]
        iv = secrets.token_bytes(KEYRING_IV_BYTES)
        aead = AESGCM(cek)
        ct = aead.encrypt(iv, data, _blob_aad(self._current_epoch, aad))
        header = self._current_epoch.to_bytes(KEYRING_BLOB_EPOCH_HEADER_BYTES, "big")
        return header + iv + ct

    def open_bytes(self, blob: bytes, aad: str | None = None) -> bytes:
        """Open a blob produced by :meth:`seal_bytes`, verifying the bound ``aad``.

        Reads the epoch from the big-endian header, unwraps that epoch's CEK, and
        decrypts under the matching ``aad``. Raises ``ValueError`` if the blob is
        shorter than its epoch+iv header, the recipient lacks the epoch's key, or
        the GCM tag fails (tampered ciphertext, wrong epoch CEK, or AAD mismatch).
        """
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

    Pre-unwraps the CEK for every epoch the recipient appears in.

    Security — the keyring document is fetched from an untrusted server, so the
    encryptor refuses to adopt CEK material it cannot vouch for:

    - **Epoch rollback (``min_epoch``).** The keyring is an opaque server doc with
      no built-in epoch floor, so a hostile server could serve a STALE keyring
      (lower ``currentEpoch``) to undo a rotation and re-admit a removed recipient.
      Pass ``min_epoch`` (the highest epoch the caller has previously seen,
      persisted client-side) to reject any keyring whose ``current_epoch`` is below
      it — closing the rollback by construction.

    - **Duplicate ``subKem`` ⇒ tampering.** A well-formed epoch has at most one
      entry per recipient (enforced on write by :func:`add_recipient`). If the
      recipient's ``subKem`` appears more than once in an epoch — e.g. a hostile
      server injected an extra entry wrapping an attacker-chosen CEK — the
      epoch is skipped (fail closed) rather than picking one by position.
    - **``trusted_adders`` (recommended).** The ``addedSig`` audit signature is
      *self-attesting*: it only proves "whoever owns ``addedBy`` signed this
      entry", which any attacker satisfies for their own forgery. Pass the set
      of Ed25519 pubkeys (hex) you trust to grant access (e.g. the collection
      owner's root key); entries added by anyone else are skipped. When omitted,
      provenance is NOT verified — only the duplicate-``subKem`` and signature
      self-consistency checks apply, so a server that *replaces* an entry can
      still substitute a CEK. Supply ``trusted_adders`` for end-to-end safety.

    Other verification failures (bad ``addedSig``, unwrap failure) are skipped
    with a logged warning. Raises ``ValueError`` if the recipient has no usable
    entry in ``current_epoch``.
    """
    import logging

    _log = logging.getLogger(__name__)
    # Fail closed: ``trusted_adders`` is mandatory. The per-entry ``addedSig`` is
    # self-attesting (any key signs its own entry), so without a provenance pin a
    # hostile server could REPLACE the caller's entry with one wrapping an
    # attacker-chosen CEK to the caller's KEM pubkey and self-sign it. Requiring
    # the trusted-adder set closes that substitution by construction.
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
            # Duplicate entries for one recipient: the keyring was tampered
            # with. Fail closed — never pick one and risk adopting an attacker
            # CEK.
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
            # Skip unrecoverable epochs (e.g. wrong key bound to same subKem).
            continue

    if keyring.current_epoch not in epoch_ceks:
        raise ValueError(
            f"No wrapped key for recipient {recipient_kem_pub_hex} in current epoch {keyring.current_epoch}"
        )
    return KeyringEncryptor(current_epoch=keyring.current_epoch, epoch_ceks=epoch_ceks)
