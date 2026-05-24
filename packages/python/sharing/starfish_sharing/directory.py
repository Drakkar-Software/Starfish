"""Member directory helpers (Python mirror of TS ``sharing/directory.ts``).

One entry per ``kind: "member"`` cap the owner has issued for a given
collection. The doc lives at ``<collectionPath>/_members`` and is
**owner-only**: non-admin member caps are rejected at well-formedness time
when they would reach ``<col>/_members``.

Device directory helpers live in ``starfish_identities.directory``.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Optional, TypedDict

from starfish_protocol.cap import CapCert, recipient_kem
from starfish_sdk.types import ConflictError, StarfishHttpError

if TYPE_CHECKING:
    from starfish_sdk.client import StarfishClient


class DirectoryEntry(TypedDict, total=False):
    """A single entry in a device or member directory document.

    ``cert`` carries the full signed cap-cert so a ``_members`` roster can double
    as a cap-distribution list for plaintext (cap-only) collections: the owner
    publishes each member's signed cap here and members fetch their own with
    ``fetch_my_member_cap``. The
    other fields are a redundant projection kept for back-compat and cheap
    ``exp``/``subUserId`` filtering. Safe to publish — a cap is usable only by the
    holder of its subject (``sub``) private key (the server verifies each request
    against ``cert.sub``), so a readable roster never lets one member act as another.
    """

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
    cert: dict[str, Any]


class Directory(TypedDict):
    """Directory document stored at the conventional path."""

    v: int
    entries: list[DirectoryEntry]


def members_path_for(collection_path: str) -> str:
    """Returns the storage path for a collection's members directory."""
    return f"{collection_path}/_members"


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
    # The ``_members`` directory records single-subject grants. ``recipient_kem``
    # resolves the recipient's KEM pubkey + suite (the dedicated ``subKem`` for
    # ed25519/mixed pairs, or the signing ``sub`` for same-suite secp256k1); it
    # raises for an audience cap, distributed as a public link, not a roster entry.
    if cert_d.get("sub") is None:
        raise ValueError(
            "cannot publish a subject-less cap (e.g. audience) to the member directory"
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
        "cert": cert_d,
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


async def add_member_entry(
    client: StarfishClient,
    collection_path: str,
    cert: CapCert | dict[str, Any],
    *,
    label: Optional[str] = None,
    added_by: Optional[str] = None,
) -> None:
    """Append (or overwrite by nonce) a member cap-cert entry in the directory
    at ``<collectionPath>/_members``. Pull-merge-push with baseHash retry.

    Raises ``ValueError`` when ``cert["kind"] != "member"``.
    """
    cert_d = dict(cert)  # type: ignore[arg-type]
    if cert_d.get("kind") != "member":
        raise ValueError(
            f"add_member_entry: expected kind='member', got kind={cert_d.get('kind')!r}"
        )
    await _upsert_entry(
        client,
        members_path_for(collection_path),
        cert,
        label=label,
        added_by=added_by,
    )


async def list_members(
    client: StarfishClient,
    collection_path: str,
    opts: Optional[ListDirectoryOpts] = None,
) -> list[DirectoryEntry]:
    """List members recorded for ``collection_path``."""
    return await _list_entries(client, members_path_for(collection_path), opts)


async def remove_member_entry(
    client: StarfishClient, collection_path: str, nonce: str
) -> bool:
    """Remove a member entry by nonce."""
    return await _remove_entry_by_nonce(
        client, members_path_for(collection_path), nonce
    )


# ── Published caps ───────────────────────────────────────────────────────────
#
# In the plaintext, cap-only sharing mode there is no keyring. Instead the owner
# PUBLISHES each member's full signed cap into the single ``<col>/_members`` list
# (configure that collection read-open + owner-only write). A member fetches its
# own cap from there — no out-of-band forwarding — and presents it for content.
# Safe even when world-readable: a cap is bound to its subject key (the server
# verifies each request against ``cert.sub``), so reading another member's cap is
# useless without their private key.


async def publish_member_cap(
    client: StarfishClient,
    collection_path: str,
    cert: CapCert | dict[str, Any],
    *,
    label: Optional[str] = None,
    added_by: Optional[str] = None,
) -> None:
    """Publish a member's full signed cap into ``<collection_path>/_members``.

    Intention-revealing alias for ``add_member_entry`` (which stores the full
    ``cert``). Owner-only by collection write-roles. Raises on a non-member cap.
    """
    await add_member_entry(
        client, collection_path, cert, label=label, added_by=added_by
    )


async def fetch_member_caps(
    client: StarfishClient,
    collection_path: str,
    opts: Optional[ListDirectoryOpts] = None,
) -> list[dict[str, Any]]:
    """Fetch every published member cap from ``<collection_path>/_members``.

    Returns the usable signed caps (skipping legacy entries written before caps
    were stored). Honors ``ListDirectoryOpts`` (``include_expired``/``revoked_nonces``).
    """
    entries = await _list_entries(
        client, members_path_for(collection_path), opts
    )
    return [e["cert"] for e in entries if e.get("cert") is not None]


async def fetch_my_member_cap(
    client: StarfishClient,
    collection_path: str,
    my_ed_pub_hex: str,
    opts: Optional[ListDirectoryOpts] = None,
) -> Optional[dict[str, Any]]:
    """Fetch the caller's own published cap — the one whose ``sub`` equals their
    Ed25519 pubkey (hex). Returns ``None`` when none is published for them.
    """
    caps = await fetch_member_caps(client, collection_path, opts)
    for cap in caps:
        if cap.get("sub") == my_ed_pub_hex:
            return cap
    return None


async def unpublish_member_cap(
    client: StarfishClient, collection_path: str, nonce: str
) -> bool:
    """Remove a published cap by nonce (e.g. on eviction). Alias for
    ``remove_member_entry``. Returns ``False`` when the nonce was not present.
    """
    return await remove_member_entry(client, collection_path, nonce)


__all__ = [
    "Directory",
    "DirectoryEntry",
    "ListDirectoryOpts",
    "add_member_entry",
    "list_members",
    "members_path_for",
    "remove_member_entry",
    "publish_member_cap",
    "fetch_member_caps",
    "fetch_my_member_cap",
    "unpublish_member_cap",
]
