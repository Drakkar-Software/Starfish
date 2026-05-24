"""Device directory helpers (Python mirror of TS
``identities/directory.ts``).

One entry per ``kind: "device"`` cap the root has issued. The doc lives at
``users/{rootUserId}/_devices`` and is reachable by any of the root's
devices.

Member directory helpers (``add_member_entry``, ``list_members``,
``remove_member_entry``, ``members_path_for``) live in
``starfish_sharing.directory``.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Optional, TypedDict

from starfish_protocol.cap import CapCert, recipient_kem
from starfish_sdk.types import ConflictError, StarfishHttpError

if TYPE_CHECKING:
    from starfish_sdk.client import StarfishClient


class DirectoryEntry(TypedDict, total=False):
    """A single entry in a device or member directory document."""

    nonce: str
    sub: str
    subKem: str
    subKemAlg: str
    subUserId: str
    scope: dict[str, Any]
    nbf: int
    exp: int
    label: str
    addedBy: str
    addedAt: int


class Directory(TypedDict):
    """Directory document stored at the conventional path."""

    v: int
    entries: list[DirectoryEntry]


def devices_path_for(root_user_id: str) -> str:
    """Returns the storage path for a root's devices directory."""
    return f"users/{root_user_id}/_devices"


_MAX_RETRIES = 3


async def _pull_directory(
    client: StarfishClient, path: str
) -> tuple[Directory, Optional[str]]:
    try:
        result = await client.pull(f"/pull/{path}")
    except StarfishHttpError as exc:
        if exc.status == 404:
            return ({"v": 1, "entries": []}, None)
        raise
    return (result.data, result.hash)  # type: ignore[union-attr,return-value]


def _entry_from_cert(
    cert: CapCert | dict[str, Any],
    *,
    label: Optional[str] = None,
    added_by: Optional[str] = None,
) -> DirectoryEntry:
    cert_d: dict[str, Any] = dict(cert)  # type: ignore[arg-type]
    # This directory records single-subject device caps. ``recipient_kem``
    # resolves the recipient's KEM pubkey + suite (the dedicated ``subKem`` for
    # ed25519/mixed pairs, or the signing ``sub`` for same-suite secp256k1); it
    # raises for a subject-less (audience) cap, which has no place here.
    if cert_d.get("sub") is None:
        raise ValueError(
            "cannot record a subject-less cap (e.g. audience) in the device directory"
        )
    kem_pub_hex, kem_alg = recipient_kem(cert_d)
    entry: DirectoryEntry = {
        "nonce": cert_d["nonce"],
        "sub": cert_d["sub"],
        "subKem": kem_pub_hex,
        "scope": cert_d["scope"],
        "nbf": cert_d["nbf"],
        "exp": cert_d["exp"],
        "addedAt": int(time.time()),
    }
    if kem_alg != "ed25519":
        entry["subKemAlg"] = kem_alg
    if "subUserId" in cert_d:
        entry["subUserId"] = cert_d["subUserId"]
    if label is not None:
        entry["label"] = label
    if added_by is not None:
        entry["addedBy"] = added_by
    return entry


async def _upsert_entry(
    client: StarfishClient,
    path: str,
    cert: CapCert | dict[str, Any],
    *,
    label: Optional[str] = None,
    added_by: Optional[str] = None,
) -> None:
    cert_nonce = dict(cert)["nonce"]  # type: ignore[arg-type]
    last_err: Optional[Exception] = None
    for attempt in range(_MAX_RETRIES):
        directory, base_hash = await _pull_directory(client, path)
        filtered = [e for e in directory["entries"] if e["nonce"] != cert_nonce]
        new_entry = _entry_from_cert(cert, label=label, added_by=added_by)
        next_doc: Directory = {"v": 1, "entries": [*filtered, new_entry]}
        try:
            await client.push(f"/push/{path}", dict(next_doc), base_hash)
            return
        except ConflictError as exc:
            last_err = exc
            if attempt < _MAX_RETRIES - 1:
                continue
            raise
    if last_err is not None:
        raise last_err


async def _remove_entry_by_nonce(
    client: StarfishClient, path: str, nonce: str
) -> bool:
    last_err: Optional[Exception] = None
    for attempt in range(_MAX_RETRIES):
        directory, base_hash = await _pull_directory(client, path)
        if not any(e["nonce"] == nonce for e in directory["entries"]):
            return False
        next_doc: Directory = {
            "v": 1,
            "entries": [e for e in directory["entries"] if e["nonce"] != nonce],
        }
        try:
            await client.push(f"/push/{path}", dict(next_doc), base_hash)
            return True
        except ConflictError as exc:
            last_err = exc
            if attempt < _MAX_RETRIES - 1:
                continue
            raise
    if last_err is not None:
        raise last_err
    return False


class ListDirectoryOpts(TypedDict, total=False):
    """Optional filters applied at list time."""

    include_expired: bool
    revoked_nonces: frozenset[str] | set[str]


async def _list_entries(
    client: StarfishClient,
    path: str,
    opts: Optional[ListDirectoryOpts] = None,
) -> list[DirectoryEntry]:
    opts = opts or {}
    include_expired = opts.get("include_expired", False)
    revoked = opts.get("revoked_nonces") or set()
    directory, _ = await _pull_directory(client, path)
    now = int(time.time())
    out: list[DirectoryEntry] = []
    for e in directory["entries"]:
        if not include_expired and e.get("exp", 0) < now:
            continue
        if e["nonce"] in revoked:
            continue
        out.append(e)
    return out


async def add_device_entry(
    client: StarfishClient,
    root_user_id: str,
    cert: CapCert | dict[str, Any],
    *,
    label: Optional[str] = None,
    added_by: Optional[str] = None,
) -> None:
    """Append (or overwrite by nonce) a device cap-cert entry in the directory
    at ``users/{rootUserId}/_devices``. Pull-merge-push with baseHash retry.

    Raises ``ValueError`` when ``cert["kind"] != "device"``.
    """
    cert_d = dict(cert)  # type: ignore[arg-type]
    if cert_d.get("kind") != "device":
        raise ValueError(
            f"add_device_entry: expected kind='device', got kind={cert_d.get('kind')!r}"
        )
    await _upsert_entry(
        client,
        devices_path_for(root_user_id),
        cert,
        label=label,
        added_by=added_by,
    )


async def list_devices(
    client: StarfishClient,
    root_user_id: str,
    opts: Optional[ListDirectoryOpts] = None,
) -> list[DirectoryEntry]:
    """List devices recorded in the directory for ``root_user_id``."""
    return await _list_entries(client, devices_path_for(root_user_id), opts)


async def remove_device_entry(
    client: StarfishClient, root_user_id: str, nonce: str
) -> bool:
    """Remove a device entry by nonce.

    Note: this does NOT revoke the cap-cert on the server — build a signed
    ``RevocationList`` with ``build_revocation_list`` (``starfish-protocol``) and
    submit it for that. (For members, ``evict_member`` in ``starfish-sharing``
    composes revoke + keyring rotation + directory removal in one call.)
    """
    return await _remove_entry_by_nonce(
        client, devices_path_for(root_user_id), nonce
    )


__all__ = [
    "Directory",
    "DirectoryEntry",
    "ListDirectoryOpts",
    "add_device_entry",
    "devices_path_for",
    "list_devices",
    "remove_device_entry",
]
