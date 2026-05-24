"""Protocol types for the Starfish sync protocol."""


from dataclasses import dataclass, field
from typing import Any, TypedDict

from starfish_protocol.types import PullResult, PushSuccess

DOCUMENT_VERSION = 1


class AppendElement(TypedDict):
    """One element of an appendOnly (``by_timestamp``) collection's stored array.

    ``ts`` (the server-visible plaintext timestamp) drives ``?checkpoint=``
    filtering; ``data`` is opaque — plaintext under ``"none"``, an encryptor
    wrapper under ``"delegated"``.
    """

    ts: int
    data: Any


@dataclass
class StoredDocument:
    """On-disk format for a synced document."""

    v: int
    data: dict[str, Any]
    hash: str
    ts: int | None = None
    """Document write-time (ms). Used for TTL and as the high-water mark on pull.
    For a regular doc it is the time of the last write; for an appendOnly doc it
    equals the ``ts`` of the most recent element. This is the only timestamp a
    document carries — the old per-field ``timestamps`` tree was removed."""
    author_pubkey: str | None = None
    author_signature: str | None = None


@dataclass
class PushConflict:
    """Failed push result due to hash mismatch."""

    error: str = field(default="hash_mismatch")


PushResult = PushSuccess | PushConflict
