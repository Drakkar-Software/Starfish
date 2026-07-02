"""Test helpers — in-memory KV adapter + shared key fixture."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import Any, Optional

from starfish_identities import generate_device_keys
from starfish_spaces.config import KvAdapter
from starfish_spaces.layout import default_space_layout, default_user_id_from_ed_pub


def user_id_for(ed_pub_hex: str) -> str:
    """Default userId derivation (``sha256(edPub)[:16]``) used by the fake session."""
    return hashlib.sha256(bytes.fromhex(ed_pub_hex)).digest()[:16].hex()


def make_fake_session(
    *,
    keys: Optional[dict[str, str]] = None,
    account_client: Any = None,
    content_client: Any = None,
) -> SimpleNamespace:
    """Build a duck-typed stand-in for :class:`Session` for unit/integration tests."""
    keys = keys or generate_device_keys()
    return SimpleNamespace(
        keys=keys,
        user_id=user_id_for(keys["edPub"]),
        owner_ed_pub=keys["edPub"],
        user_id_from_ed_pub=default_user_id_from_ed_pub,
        layout=default_space_layout,
        inbox_aad_namespace="starfish:inbox:v1",
        base_url="",
        namespace="",
        account_client=account_client,
        content_client=content_client,
    )


class MemoryKvAdapter:
    """An in-memory :class:`KvAdapter` for tests."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    async def get_item(self, key: str) -> str | None:
        return self._store.get(key)

    async def set_item(self, key: str, value: str) -> None:
        self._store[key] = value

    async def remove_item(self, key: str) -> None:
        self._store.pop(key, None)

    def get_all(self) -> dict[str, str]:
        return dict(self._store)
