"""Shared wire-format types for the Starfish sync protocol."""


from dataclasses import dataclass
from typing import Any, Union

Timestamps = dict[str, Union[int, "Timestamps"]]


@dataclass
class PullResult:
    data: dict[str, Any]
    hash: str
    timestamp: int
    author_pubkey: str | None = None
    author_signature: str | None = None


@dataclass
class PushSuccess:
    hash: str
    timestamp: int
