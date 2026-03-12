"""Protocol types for the Starfish sync protocol."""


from dataclasses import dataclass, field
from typing import Any

from starfish_protocol.types import Timestamps, PullResult, PushSuccess

DOCUMENT_VERSION = 1


@dataclass
class StoredDocument:
    """On-disk format for a synced document."""

    v: int
    data: dict[str, Any]
    timestamps: Timestamps
    hash: str
    author_pubkey: str | None = None
    author_signature: str | None = None


@dataclass
class PushConflict:
    """Failed push result due to hash mismatch."""

    error: str = field(default="hash_mismatch")


PushResult = PushSuccess | PushConflict
