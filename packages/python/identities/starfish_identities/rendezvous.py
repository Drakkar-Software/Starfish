"""Pairing-rendezvous helpers (Python mirror of TS ``identities/rendezvous.ts``).

The phone → computer return leg of QR-in / auto-return device pairing. The new
device (e.g. a computer with no camera) shows a QR; the root device (phone)
scans it, assembles a :class:`PairingBundle`, and drops it in a small anonymous,
TTL'd collection at ``_pairing/<rendezvousId>``. The new device — which has no
cap-cert yet and so cannot read the owner-only ``_devices`` directory — fetches
the bundle from that public slot and installs it.

Why a public slot is safe: the bundle's ``wrappedCEKs`` are already E2E-wrapped
to the new device's KEM pubkey, and :func:`install_pairing_bundle` verifies the
root signature + ``sub``/``subKem`` + ``qr_nonce`` (+ optional
``expected_root_ed_pub``). So the channel only needs delivery + DoS-resistance,
never confidentiality. See ``docs/ts/client/24-pairing.md``.

The rendezvous location derives from the QR's existing ``qr_nonce`` — both
devices hold it — so no extra field travels in the QR. ``qr_nonce`` was never a
secret (it is the anti-replay session binder, visible in the QR and as the path).
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any, Optional

from starfish_sdk.types import ConflictError, StarfishHttpError

from .pairing import PairingBundle

if TYPE_CHECKING:
    from starfish_sdk.client import StarfishClient

#: Collection storage-path prefix for rendezvous slots.
RENDEZVOUS_PREFIX = "_pairing"

_MAX_RETRIES = 3


def rendezvous_path_for(qr_nonce: str) -> str:
    """Path-safe rendezvous storage path derived from the (base64) ``qr_nonce``.

    ``qr_nonce`` is standard base64 (may contain ``+``/``/``/``=``), so it is
    decoded to bytes and re-encoded as hex to keep the storage path
    URL/path-safe. Both devices derive the identical path from the same nonce.
    """
    return f"{RENDEZVOUS_PREFIX}/{base64.b64decode(qr_nonce).hex()}"


async def _pull_hash(client: "StarfishClient", path: str) -> Optional[str]:
    try:
        result = await client.pull(f"/pull/{path}")
    except StarfishHttpError as exc:
        if exc.status == 404:
            return None
        raise
    return result.hash  # type: ignore[union-attr,return-value]


async def push_pairing_bundle(
    client: "StarfishClient", qr_nonce: str, bundle: PairingBundle
) -> None:
    """Root (phone) side: write the assembled bundle to the rendezvous slot.

    Last-write-wins: pulls the slot's current baseHash and pushes with it, so
    the write succeeds whether the slot is empty (fresh ``qr_nonce``) or already
    holds a stale/junk value. Retries on a concurrent-write conflict.
    """
    path = rendezvous_path_for(qr_nonce)
    last_err: Optional[Exception] = None
    for attempt in range(_MAX_RETRIES):
        base_hash = await _pull_hash(client, path)
        try:
            await client.push(f"/push/{path}", bundle.to_dict(), base_hash)
            return
        except ConflictError as exc:
            last_err = exc
            if attempt < _MAX_RETRIES - 1:
                continue
            raise
    if last_err is not None:
        raise last_err


async def fetch_pairing_bundle(
    client: "StarfishClient", qr_nonce: str
) -> Optional[PairingBundle]:
    """New-device (computer) side: a SINGLE fetch — no polling.

    Returns the bundle, or ``None`` when the slot is still empty (the root hasn't
    pushed yet, or the slot expired) so the UI can prompt the user to finish on
    the root device and trigger another fetch. The caller installs the returned
    bundle and SHOULD then call :func:`clear_pairing_bundle` to one-shot the slot.
    """
    path = rendezvous_path_for(qr_nonce)
    try:
        result = await client.pull(f"/pull/{path}")
    except StarfishHttpError as exc:
        if exc.status == 404:
            return None
        raise
    data: Any = result.data
    # Empty slot (never written, or TTL-expired → server returns ``{}``).
    if not isinstance(data, dict) or "capCert" not in data:
        return None
    return PairingBundle.from_dict(data)


async def clear_pairing_bundle(client: "StarfishClient", qr_nonce: str) -> None:
    """Best-effort one-shot cleanup: overwrite the slot with ``{}`` after a
    successful install so the bundle is not left readable. Cryptographically the
    bundle is useless to anyone but this device, so a failure here is harmless —
    the collection's TTL is the real backstop. Swallows conflicts/errors.
    """
    path = rendezvous_path_for(qr_nonce)
    try:
        base_hash = await _pull_hash(client, path)
        await client.push(f"/push/{path}", {}, base_hash)
    except Exception:  # noqa: BLE001 — best-effort; TTL expires the slot regardless
        pass


__all__ = [
    "RENDEZVOUS_PREFIX",
    "rendezvous_path_for",
    "push_pairing_bundle",
    "fetch_pairing_bundle",
    "clear_pairing_bundle",
]
