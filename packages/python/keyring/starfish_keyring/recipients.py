"""Collection-scoped recipient management helpers.

These wrap the low-level keyring functions in :mod:`starfish_sdk.keyring` with
HTTP-aware I/O via :class:`StarfishClient`. The keyring document for a
collection lives at the conventional path ``<collection>/_keyring`` and is
fetched/pushed using the ``/pull/`` and ``/push/`` route prefixes.

Hash-based conflict detection is preserved: each push uses the hash from the
prior pull as ``base_hash``. Callers may retry on :class:`ConflictError`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypedDict

from starfish_sdk.types import StarfishHttpError

from .keyring import (
    Keyring,
    add_recipient as keyring_add_recipient,
    rotate_epoch,
    unwrap_from_entry,
    verify_entry_signature,
)

if TYPE_CHECKING:
    from starfish_sdk.client import StarfishClient


def keyring_path_for(collection_name: str) -> str:
    """Document path used to store a collection's keyring.

    Returns ``<collection>/_keyring``. The helpers below prefix this with
    ``/pull/`` or ``/push/`` as required by the route layer.
    """
    return f"{collection_name}/_keyring"


class RecipientRef(TypedDict, total=False):
    """A recipient referenced by its KEM (X25519) public key, with metadata."""

    subKem: str
    userId: str
    label: str


class AdderKeys(TypedDict):
    """Adder's keypair material — device must already be in the current epoch."""

    edPriv: str
    edPub: str
    kemPriv: str


class ListedRecipient(TypedDict):
    """One recipient projected for listing."""

    subKem: str
    addedBy: str
    addedAt: int


def _pull_path_for(collection_name: str) -> str:
    return f"/pull/{keyring_path_for(collection_name)}"


def _push_path_for(collection_name: str) -> str:
    return f"/push/{keyring_path_for(collection_name)}"


async def _pull_keyring(
    client: StarfishClient, collection_name: str
) -> tuple[Keyring, str] | None:
    """Pull the keyring; ``None`` if the document doesn't exist yet (HTTP 404)."""
    try:
        result = await client.pull(_pull_path_for(collection_name))
    except StarfishHttpError as exc:
        if exc.status == 404:
            return None
        raise
    # result is a PullResult — data is a dict suitable for Keyring.from_dict.
    data: dict[str, Any] = result.data  # type: ignore[union-attr]
    return Keyring.from_dict(data), result.hash  # type: ignore[union-attr]


def _recover_current_cek(
    keyring: Keyring,
    adder_kem_priv_hex: str,
    trusted_adders: set[str] | None = None,
) -> bytes:
    """Locate the adder's entry in the current epoch and recover the CEK.

    Probes each entry until one decrypts successfully — this lets callers pass
    just the KEM private key without also having to identify which ``subKem``
    is theirs.

    Each candidate entry's ``addedSig`` is verified before the unwrap
    attempt: tampered audit signatures (e.g. server-mutated ``addedBy``)
    cause the entry to be skipped (with a logged warning), so the adder
    never trusts unattested wrap material and a single corrupted entry
    does not prevent recovery via a sibling entry in the same epoch.

    When ``trusted_adders`` is provided, entries whose ``added_by`` is not in
    the set are skipped — the ``addedSig`` is self-attesting, so a hostile
    server can REPLACE the adder's own entry with one wrapping an
    attacker-chosen CEK to the adder's KEM pubkey and self-sign it; pinning the
    trusted adders closes that substitution.
    """
    import logging

    _log = logging.getLogger(__name__)
    epoch_key = str(keyring.current_epoch)
    epoch = keyring.epochs.get(epoch_key)
    if epoch is None:
        raise ValueError(f"Epoch {keyring.current_epoch} not found in keyring")

    # A valid epoch has unique subKems (enforced on write by add_recipient).
    # Duplicates mean the keyring was tampered with — e.g. a hostile server
    # injected an entry wrapping an attacker-chosen CEK to this adder's key.
    # Fail closed rather than risk recovering and re-wrapping a forged CEK.
    seen_sub_kems: set[str] = set()
    for entry in epoch.wrapped_keys:
        if entry.sub_kem in seen_sub_kems:
            raise ValueError(
                f"Keyring epoch {keyring.current_epoch} has duplicate entries "
                f"for subKem={entry.sub_kem} (tampering)"
            )
        seen_sub_kems.add(entry.sub_kem)

    last_err: Exception | None = None
    for entry in epoch.wrapped_keys:
        if trusted_adders is not None and entry.added_by not in trusted_adders:
            _log.warning(
                "skipping entry subKem=%s in epoch %d: addedBy %s is not a trusted adder",
                entry.sub_kem,
                keyring.current_epoch,
                entry.added_by,
            )
            continue
        if not verify_entry_signature(entry, keyring.current_epoch):
            _log.warning(
                "skipping entry subKem=%s in epoch %d: addedSig verification failed",
                entry.sub_kem,
                keyring.current_epoch,
            )
            continue
        try:
            return unwrap_from_entry(entry, adder_kem_priv_hex)
        except Exception as err:  # noqa: BLE001 — try every entry
            last_err = err
    raise ValueError(
        f"Adder has no usable entry in current epoch {keyring.current_epoch}"
    ) from last_err


def _require_trusted_adders(trusted_adders: list[str] | None, fn: str) -> set[str]:
    """Resolve the mandatory ``trusted_adders`` pin into a set, or raise.

    The mutation helpers recover the current CEK from a server-supplied keyring;
    without a provenance pin a hostile server could substitute a forged entry
    (the ``addedSig`` is self-attesting). Fail closed rather than mutate off
    unverified key material.
    """
    if not trusted_adders:
        raise ValueError(
            f"{fn}: `trusted_adders` is required — pass the Ed25519 pubkey(s) you trust to "
            f"grant keyring access (e.g. the collection owner's root key). Without it a hostile "
            f"server could substitute a wrapped-key entry (the addedSig is self-attesting)."
        )
    return set(trusted_adders)


async def add_recipient(
    client: StarfishClient,
    collection_name: str,
    recipient: RecipientRef,
    adder: AdderKeys,
    *,
    trusted_adders: list[str] | None = None,
) -> None:
    """Add a new recipient to the current epoch (no rotation).

    Pulls the current keyring, unwraps the CEK using the adder's KEM private
    key, appends a new entry signed by the adder, and pushes the updated
    keyring back using the prior hash as ``base_hash``.

    ``trusted_adders`` is the same pin ``create_keyring_encryptor`` accepts.
    The ``addedSig`` is self-attesting, so a hostile server can REPLACE the
    adder's own entry with one wrapping an attacker-chosen CEK to the adder's
    (public) KEM key and self-sign it; ``_recover_current_cek`` would then
    unwrap that forged CEK and re-wrap it for the new recipient. Pinning the
    trusted adders ignores such entries. Strongly recommended whenever the
    server is not fully trusted.

    Raises ``ValueError`` if the keyring document does not exist yet.
    """
    pulled = await _pull_keyring(client, collection_name)
    if pulled is None:
        raise ValueError(
            f"Cannot add recipient: no keyring exists at {keyring_path_for(collection_name)}. "
            f"Create the keyring first."
        )
    keyring, prev_hash = pulled

    trusted = _require_trusted_adders(trusted_adders, "add_recipient")
    current_cek = _recover_current_cek(keyring, adder["kemPriv"], trusted)
    next_keyring = keyring_add_recipient(
        keyring,
        adder_ed_priv_hex=adder["edPriv"],
        adder_ed_pub_hex=adder["edPub"],
        current_cek=current_cek,
        recipient_kem_hex=recipient["subKem"],
    )

    await client.push(
        _push_path_for(collection_name),
        next_keyring.to_dict(),
        prev_hash,
    )


async def remove_recipient(
    client: StarfishClient,
    collection_name: str,
    remove_sub_kems: list[str],
    adder: AdderKeys,
    *,
    trusted_adders: list[str] | None = None,
) -> dict[str, int]:
    """Rotate the epoch, dropping the named recipients.

    When ``trusted_adders`` is set, entries written by an untrusted adder (e.g.
    a recipient a hostile server injected) are not carried into the new epoch —
    the rotation would otherwise re-wrap the fresh CEK for them.

    Returns ``{"newEpoch": <int>}``. Raises ``ValueError`` if the keyring
    document does not exist yet.
    """
    pulled = await _pull_keyring(client, collection_name)
    if pulled is None:
        raise ValueError(
            f"Cannot remove recipient: no keyring exists at {keyring_path_for(collection_name)}."
        )
    keyring, prev_hash = pulled

    epoch_key = str(keyring.current_epoch)
    epoch = keyring.epochs.get(epoch_key)
    if epoch is None:
        raise ValueError(f"Epoch {keyring.current_epoch} not found in keyring")

    trusted = _require_trusted_adders(trusted_adders, "remove_recipient")
    remove_set = set(remove_sub_kems)
    retained = [
        e.sub_kem
        for e in epoch.wrapped_keys
        if e.sub_kem not in remove_set and e.added_by in trusted
    ]

    rotated, _new_cek = rotate_epoch(
        keyring,
        adder_ed_priv_hex=adder["edPriv"],
        adder_ed_pub_hex=adder["edPub"],
        retained_recipients=retained,
    )

    await client.push(
        _push_path_for(collection_name),
        rotated.to_dict(),
        prev_hash,
    )

    return {"newEpoch": rotated.current_epoch}


async def list_recipients(
    client: StarfishClient,
    collection_name: str,
    *,
    trusted_adders: list[str] | None = None,
) -> dict[str, Any]:
    """List recipients in the current epoch, filtered by provenance.

    Returns ``{"epoch": int, "recipients": [{"subKem", "addedBy", "addedAt"}, ...]}``.
    Only entries whose ``addedBy`` is in ``trusted_adders`` AND whose ``addedSig``
    verifies are returned — mirroring :func:`create_keyring_encryptor`, so a forged
    or server-substituted entry never surfaces in a membership/admin view.

    ``trusted_adders`` is REQUIRED (fail-closed): the keyring is fetched from an
    untrusted server and the per-entry ``addedSig`` is self-attesting, so without a
    provenance pin a hostile server could spoof the listing. Pass the Ed25519
    pubkey(s) you trust to grant access (e.g. the collection owner's root key).
    If the keyring document doesn't exist yet, returns ``{"epoch": 0, "recipients": []}``.
    """
    trusted = _require_trusted_adders(trusted_adders, "list_recipients")
    pulled = await _pull_keyring(client, collection_name)
    if pulled is None:
        return {"epoch": 0, "recipients": []}
    keyring, _ = pulled

    epoch = keyring.epochs.get(str(keyring.current_epoch))
    if epoch is None:
        return {"epoch": keyring.current_epoch, "recipients": []}

    recipients: list[ListedRecipient] = [
        {"subKem": e.sub_kem, "addedBy": e.added_by, "addedAt": e.added_at}
        for e in epoch.wrapped_keys
        if e.added_by in trusted and verify_entry_signature(e, keyring.current_epoch)
    ]
    return {"epoch": keyring.current_epoch, "recipients": recipients}


async def current_epoch(client: StarfishClient, collection_name: str) -> int:
    """Return the current epoch number; ``0`` if no keyring exists yet."""
    pulled = await _pull_keyring(client, collection_name)
    if pulled is None:
        return 0
    keyring, _ = pulled
    return keyring.current_epoch
