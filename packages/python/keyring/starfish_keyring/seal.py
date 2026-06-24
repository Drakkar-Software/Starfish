"""Sealed envelopes — wrap a small secret to a single X25519 KEM key so it can
ride inside a *plaintext* synced document without exposing it to the server (or
to anyone who can read the doc but lacks the recipient's KEM private key).

A thin, general-purpose layer over the keyring's single-recipient primitive
(:func:`wrap_for_recipient`), independent of any keyring document or epoch
rotation — each blob wraps a fresh content key to one static recipient key — so
it suits one-off sealed credentials (API tokens, OAuth secrets, bearer secrets
embedded in invite links, peer-to-peer hand-offs).

Two shapes, one mechanism:

- :func:`seal_to_self` / :func:`unseal_from_self` — sealed to the sealer's OWN KEM
  key, for account secrets that must sync across a user's devices.
- :func:`seal` / :func:`unseal` — sealed to ANOTHER identity's published KEM key,
  for delivering a secret to a peer through a doc they can read. The recipient
  trial-unseals (a wrong-recipient blob simply raises), which lets several
  recipients share one carrier doc.

Mechanism: a random AES-256 content key is wrapped to the recipient's X25519 KEM
key via :func:`wrap_for_recipient` (sealer-signed, so the recipient can
authenticate who sealed it via ``entry.added_by``), then the payload is sealed
with AES-256-GCM under that content key. Cross-language byte-compatible with the
TypeScript ``@drakkar.software/starfish-keyring`` ``seal`` module.

Context-binding (AAD)
---------------------
Pass an ``aad`` string to :func:`seal` / :func:`seal_to_self` to bind the
AES-GCM authentication tag to that context string. The resulting blob has
``v=1`` set and can only be opened by callers that supply the SAME ``aad``.
Opening a ``v=1`` blob without ``aad`` raises immediately — this is the
downgrade/relocation-attack guard: a blob sealed in one context (e.g. a specific
keyring path) cannot be silently replayed in another.

``aad`` is NOT stored in the blob and is never transmitted to the server; both
sealer and opener must agree on the value out-of-band.
"""

from __future__ import annotations

import base64
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keyring import (
    WrappedKeyEntry,
    unwrap_from_entry,
    verify_entry_signature,
    wrap_for_recipient,
)

# Every blob wraps to a single STATIC recipient key with no rotating keyring, so
# the wrap entry lives at a fixed pseudo-epoch. ``wrap_for_recipient`` and
# ``verify_entry_signature`` must agree on it (it is bound into ``added_sig``).
SEAL_EPOCH = 0
_IV_BYTES = 12


@dataclass
class SealedBlob:
    """A payload sealed to a KEM key: the wrapped content key + base64(iv || ct).

    ``v`` is set to ``1`` when the blob was sealed with an AAD context string.
    Opening a ``v=1`` blob without the matching ``aad`` raises immediately
    (prevents relocation/downgrade attacks where a blob sealed in one context is
    replayed in another).
    """

    entry: WrappedKeyEntry
    """The content key wrapped to the recipient's KEM key (single-recipient, sealer-signed)."""

    ct: str
    """``base64( iv(12) || AES-256-GCM(cek, iv, plaintext[, aad]) )``."""

    v: int | None = field(default=None)
    """Version marker. ``1`` means the blob was sealed with an AAD context binding.
    ``None`` means the blob was sealed without AAD (legacy / no relocation guard)."""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"entry": self.entry.to_dict(), "ct": self.ct}
        if self.v is not None:
            d["v"] = self.v
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SealedBlob":
        return cls(
            entry=WrappedKeyEntry.from_dict(data["entry"]),
            ct=data["ct"],
            v=data.get("v"),
        )


def _to_bytes(plaintext: bytes | str) -> bytes:
    return plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext


def seal(
    plaintext: bytes | str,
    recipient_kem_pub_hex: str,
    *,
    sealer_ed_priv_hex: str,
    sealer_ed_pub_hex: str,
    aad: str | None = None,
) -> SealedBlob:
    """Seal ``plaintext`` to ``recipient_kem_pub_hex``, signed by the sealer.

    Only the holder of the recipient KEM private key can open the result.
    ``plaintext`` may be raw bytes or a UTF-8 string.

    :param aad: Optional Additional Authenticated Data string. When provided,
        the AES-GCM encryption binds ``aad`` into the authentication tag and the
        returned blob has ``v=1`` set. An :func:`unseal` call that does NOT
        supply the matching ``aad`` raises immediately — preventing
        relocation/downgrade attacks where a blob sealed in one context is
        replayed in another. ``aad`` is NOT stored in the blob.
    """
    cek = secrets.token_bytes(32)
    entry = wrap_for_recipient(
        cek,
        recipient_kem_pub_hex,
        adder_ed_priv_hex=sealer_ed_priv_hex,
        adder_ed_pub_hex=sealer_ed_pub_hex,
        added_at=int(time.time()),
        epoch=SEAL_EPOCH,
    )
    iv = secrets.token_bytes(_IV_BYTES)
    aad_bytes = aad.encode("utf-8") if aad else None
    ct = AESGCM(cek).encrypt(iv, _to_bytes(plaintext), aad_bytes)
    v = 1 if aad is not None else None
    return SealedBlob(entry=entry, ct=base64.b64encode(iv + ct).decode("ascii"), v=v)


def seal_to_self(
    plaintext: bytes | str,
    self_kem_pub_hex: str,
    *,
    sealer_ed_priv_hex: str,
    sealer_ed_pub_hex: str,
    aad: str | None = None,
) -> SealedBlob:
    """Seal ``plaintext`` so only the holder of ``self_kem_pub_hex``'s private key
    (the sealer's own account, across its devices) can open it.

    Pass ``aad`` to enable context-binding — see :func:`seal` for full semantics.
    """
    return seal(
        plaintext,
        self_kem_pub_hex,
        sealer_ed_priv_hex=sealer_ed_priv_hex,
        sealer_ed_pub_hex=sealer_ed_pub_hex,
        aad=aad,
    )


def _open(blob: SealedBlob, recipient_kem_priv_hex: str, aad: str | None = None) -> bytes:
    cek = unwrap_from_entry(blob.entry, recipient_kem_priv_hex)
    packed = base64.b64decode(blob.ct)
    if len(packed) < _IV_BYTES:
        raise ValueError("sealed blob shorter than the IV length")
    iv = packed[:_IV_BYTES]
    ct = packed[_IV_BYTES:]
    aad_bytes = aad.encode("utf-8") if aad else None
    try:
        return AESGCM(cek).decrypt(iv, ct, aad_bytes)
    except InvalidTag as exc:
        raise ValueError("sealed blob decryption failed — wrong recipient or tampered") from exc


def unseal(
    blob: SealedBlob,
    recipient_kem_priv_hex: str,
    *,
    require_sealer: str | None = None,
    aad: str | None = None,
) -> bytes:
    """Open a :class:`SealedBlob` sealed to the holder of ``recipient_kem_priv_hex``.

    Always verifies the wrap entry's signature so ``entry.added_by`` is an authentic
    claim of who sealed it. Pass ``require_sealer`` (an Ed25519 pubkey hex) to also
    PIN the sealer — the open raises unless the blob was signed by that key. Without
    it, any peer may have sealed to us (trial-unseal mode for a shared carrier doc).

    Pass ``aad`` when the blob was sealed with a context string (i.e. ``blob.v == 1``).
    Opening a ``v=1`` blob without the matching ``aad`` raises immediately — this is
    the downgrade/relocation-attack guard.

    Raises on a wrong recipient, an invalid signature, a required-sealer mismatch,
    or AEAD failure.
    """
    # v=1 blobs were sealed with context AAD — reject any open that lacks it.
    # This must happen BEFORE any crypto to prevent timing-side-channel leaks.
    if blob.v == 1 and aad is None:
        raise ValueError(
            "aad required: this blob (v=1) was sealed with context-binding — "
            "pass the matching aad to open it"
        )
    if not verify_entry_signature(blob.entry, SEAL_EPOCH):
        raise ValueError("sealed blob signature invalid")
    if require_sealer is not None and blob.entry.added_by != require_sealer:
        raise ValueError("sealed blob not signed by the required sealer")
    return _open(blob, recipient_kem_priv_hex, aad)


def unseal_to_str(
    blob: SealedBlob,
    recipient_kem_priv_hex: str,
    *,
    require_sealer: str | None = None,
    aad: str | None = None,
) -> str:
    """:func:`unseal` decoding the plaintext as a UTF-8 string.

    Pass ``aad`` for ``v=1`` blobs — see :func:`unseal`.
    """
    return unseal(blob, recipient_kem_priv_hex, require_sealer=require_sealer, aad=aad).decode("utf-8")


def unseal_from_self(
    blob: SealedBlob,
    *,
    kem_priv_hex: str,
    ed_pub_hex: str,
    aad: str | None = None,
) -> bytes:
    """Open a blob produced by :func:`seal_to_self`: pins the sealer to the account's
    own Ed key (defense-in-depth — only our own self-seal is trusted).

    Pass ``aad`` when the blob was sealed with a context string (``v=1``).
    """
    return unseal(blob, kem_priv_hex, require_sealer=ed_pub_hex, aad=aad)
