"""Shared wire-format types for the Starfish sync protocol."""


from dataclasses import dataclass
from typing import Any, Optional, Union

Timestamps = dict[str, Union[int, list[int], "Timestamps"]]


@dataclass
class PullKeyringProjection:
    """Sibling-keyring projection returned by ``GET /pull/...?withKeyring=1``.

    Author fields are dropped — the keyring document is unsigned in this model.
    """

    data: dict[str, Any]
    hash: str
    timestamp: int


@dataclass
class PullResult:
    data: dict[str, Any]
    hash: str
    timestamp: int
    author_pubkey: str | None = None
    author_signature: str | None = None
    # Sentinel: undefined means "not requested"; ``None`` means "requested
    # but the keyring document does not exist at ``<collection>/_keyring``";
    # a populated ``PullKeyringProjection`` means it was returned alongside
    # the data doc in the same round-trip.
    keyring: Optional["PullKeyringProjection"] = None


@dataclass
class PushSuccess:
    hash: str
    timestamp: int
