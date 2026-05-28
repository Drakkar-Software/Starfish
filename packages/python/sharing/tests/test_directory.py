"""Tests for the member directory module."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, cast

import pytest

from starfish_identities.cap_mint import mint_device_cap, scopes as identity_scopes
from starfish_identities.identity import derive_root_identity
from starfish_protocol.cap import user_id_from_pub_hex
from starfish_sdk.types import ConflictError, StarfishHttpError
from starfish_sharing.cap_mint import MintOpts, mint_member_cap, scopes
from starfish_sharing.directory import (
    add_member_entry,
    fetch_member_caps,
    fetch_my_member_cap,
    list_members,
    members_path_for,
    publish_member_cap,
    remove_member_entry,
    unpublish_member_cap,
)


@dataclass
class _StoredDoc:
    data: dict[str, Any]
    hash: str


@dataclass
class _PullResult:
    data: dict[str, Any]
    hash: str
    timestamp: int = 1000


@dataclass
class _PushSuccess:
    hash: str
    timestamp: int = 2000


class MockStarfishClient:
    def __init__(self) -> None:
        self._store: dict[str, _StoredDoc] = {}
        self._counter = 0

    @property
    def store(self) -> dict[str, _StoredDoc]:
        return self._store

    async def pull(self, route_path: str) -> _PullResult:
        if not route_path.startswith("/pull/"):
            raise ValueError(f"expected /pull/ prefix in {route_path}")
        path = route_path[len("/pull/"):]
        doc = self._store.get(path)
        if doc is None:
            raise StarfishHttpError(404, "not found")
        return _PullResult(data=doc.data, hash=doc.hash)

    async def push(
        self,
        route_path: str,
        data: dict[str, Any],
        base_hash: Optional[str],
    ) -> _PushSuccess:
        if not route_path.startswith("/push/"):
            raise ValueError(f"expected /push/ prefix in {route_path}")
        path = route_path[len("/push/"):]
        current = self._store.get(path)
        if current is not None and base_hash != current.hash:
            raise ConflictError(f"baseHash mismatch for {path}")
        if current is None and base_hash is not None:
            raise ConflictError(f"baseHash mismatch (no existing doc) for {path}")
        self._counter += 1
        new_hash = f"h{self._counter}"
        self._store[path] = _StoredDoc(data=data, hash=new_hash)
        return _PushSuccess(hash=new_hash)


def _client() -> MockStarfishClient:
    return MockStarfishClient()


def test_members_path_for_flat_collection() -> None:
    assert members_path_for("shared-notes") == "shared-notes/_members"


def test_members_path_for_nested_collection_preserved() -> None:
    assert (
        members_path_for("users/owner-id/notes") == "users/owner-id/notes/_members"
    )


@pytest.mark.asyncio
async def test_add_member_entry_writes_to_col_members() -> None:
    alice = derive_root_identity("alice-mem-pass")
    bob = derive_root_identity("bob-mem-pass")
    cert = mint_member_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {
            "edPubHex": bob.keys.ed_pub,
            "kemPubHex": bob.keys.kem_pub,
            "userIdHex": bob.user_id,
        },
        "shared-notes",
        scopes.writer("shared-notes"),
    )
    client = _client()
    await add_member_entry(cast(Any, client), "shared-notes", cert, label="Bob")

    stored = client.store[members_path_for("shared-notes")]
    entries = stored.data["entries"]
    assert len(entries) == 1
    assert entries[0]["subUserId"] == bob.user_id
    assert entries[0]["label"] == "Bob"

    listed = await list_members(cast(Any, client), "shared-notes")
    assert len(listed) == 1
    assert listed[0]["subUserId"] == bob.user_id


@pytest.mark.asyncio
async def test_add_member_entry_supports_nested_collection_paths() -> None:
    alice = derive_root_identity("alice-nested-pass")
    bob = derive_root_identity("bob-nested-pass")
    cert = mint_member_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {
            "edPubHex": bob.keys.ed_pub,
            "kemPubHex": bob.keys.kem_pub,
            "userIdHex": bob.user_id,
        },
        "shared-notes",
        scopes.writer("shared-notes"),
    )
    client = _client()
    nested = f"users/{alice.user_id}/shared-notes"
    await add_member_entry(cast(Any, client), nested, cert)

    assert f"{nested}/_members" in client.store


@pytest.mark.asyncio
async def test_add_member_entry_rejects_device_cap() -> None:
    alice = derive_root_identity("alice-bad-mem-pass")
    device_cert = mint_device_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": alice.keys.ed_pub, "kemPubHex": alice.keys.kem_pub},
        identity_scopes.root_all(),
    )
    client = _client()
    with pytest.raises(ValueError, match="kind='device'"):
        await add_member_entry(cast(Any, client), "shared-notes", device_cert)


@pytest.mark.asyncio
async def test_remove_member_entry_roundtrip() -> None:
    alice = derive_root_identity("alice-remmem-pass")
    bob = derive_root_identity("bob-remmem-pass")
    cert = mint_member_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {
            "edPubHex": bob.keys.ed_pub,
            "kemPubHex": bob.keys.kem_pub,
            "userIdHex": bob.user_id,
        },
        "shared",
        scopes.writer("shared"),
    )
    client = _client()
    await add_member_entry(cast(Any, client), "shared", cert)
    assert (
        await remove_member_entry(cast(Any, client), "shared", cert["nonce"]) is True
    )
    assert await list_members(cast(Any, client), "shared") == []


@pytest.mark.asyncio
async def test_remove_nonexistent_member_is_idempotent_noop() -> None:
    """Removing a nonce that isn't in the roster returns False and writes nothing.

    Idempotence matters for retried/duplicate revoke calls: a second remove (or a remove
    of an already-evicted member) must not error or churn the directory document.
    """
    alice = derive_root_identity("alice-rem-noop-pass")
    bob = derive_root_identity("bob-rem-noop-pass")
    cert = mint_member_cap(
        alice.keys.ed_priv, alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
        "shared", scopes.writer("shared"),
    )
    client = _client()
    await add_member_entry(cast(Any, client), "shared", cert)
    hash_before = client.store[members_path_for("shared")].hash
    # A nonce that was never added → no-op, no error, roster + doc untouched.
    assert await remove_member_entry(cast(Any, client), "shared", "no-such-nonce") is False
    assert len(await list_members(cast(Any, client), "shared")) == 1
    assert client.store[members_path_for("shared")].hash == hash_before  # no write


@pytest.mark.asyncio
async def test_upsert_by_nonce_does_not_duplicate_on_readd() -> None:
    alice = derive_root_identity("alice-churn-dup-pass")
    bob = derive_root_identity("bob-churn-dup-pass")
    cert = mint_member_cap(
        alice.keys.ed_priv, alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
        "shared", scopes.writer("shared"),
    )
    client = _client()
    await add_member_entry(cast(Any, client), "shared", cert, label="Bob")
    await add_member_entry(cast(Any, client), "shared", cert, label="Bob (again)")

    listed = await list_members(cast(Any, client), "shared")
    assert len(listed) == 1
    assert listed[0]["label"] == "Bob (again)"  # last write wins on the same nonce


@pytest.mark.asyncio
async def test_publish_member_cap_stores_full_cert_and_fetch_my_returns_it() -> None:
    alice = derive_root_identity("alice-pub-pass")
    bob = derive_root_identity("bob-pub-pass")
    cert = mint_member_cap(
        alice.keys.ed_priv, alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
        "shared-board", scopes.writer("shared-board"),
    )
    client = _client()
    await publish_member_cap(cast(Any, client), "shared-board", cert, label="Bob")

    # The stored entry carries the usable, signed cap (not just a projection).
    entry = client.store[members_path_for("shared-board")].data["entries"][0]
    assert entry["cert"] == cert
    assert entry["cert"]["sig"] == cert["sig"]

    mine = await fetch_my_member_cap(cast(Any, client), "shared-board", bob.keys.ed_pub)
    assert mine == cert


@pytest.mark.asyncio
async def test_fetch_member_caps_returns_all_and_fetch_my_filters_by_sub() -> None:
    alice = derive_root_identity("alice-pub2-pass")
    bob = derive_root_identity("bob-pub2-pass")
    carol = derive_root_identity("carol-pub2-pass")
    bob_cert = mint_member_cap(
        alice.keys.ed_priv, alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
        "shared-board", scopes.writer("shared-board"),
    )
    carol_cert = mint_member_cap(
        alice.keys.ed_priv, alice.keys.ed_pub,
        {"edPubHex": carol.keys.ed_pub, "kemPubHex": carol.keys.kem_pub, "userIdHex": carol.user_id},
        "shared-board", scopes.read_only("shared-board"),
    )
    client = _client()
    await publish_member_cap(cast(Any, client), "shared-board", bob_cert)
    await publish_member_cap(cast(Any, client), "shared-board", carol_cert)

    all_caps = await fetch_member_caps(cast(Any, client), "shared-board")
    assert len(all_caps) == 2
    carol_fetched = await fetch_my_member_cap(cast(Any, client), "shared-board", carol.keys.ed_pub)
    assert carol_fetched is not None
    assert carol_fetched["sub"] == carol.keys.ed_pub


@pytest.mark.asyncio
async def test_fetch_my_member_cap_returns_none_when_absent() -> None:
    alice = derive_root_identity("alice-pub3-pass")
    bob = derive_root_identity("bob-pub3-pass")
    stranger = derive_root_identity("stranger-pub3-pass")
    cert = mint_member_cap(
        alice.keys.ed_priv, alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
        "shared-board", scopes.writer("shared-board"),
    )
    client = _client()
    await publish_member_cap(cast(Any, client), "shared-board", cert)
    assert await fetch_my_member_cap(cast(Any, client), "shared-board", stranger.keys.ed_pub) is None
    # also None when the list does not exist yet
    assert await fetch_my_member_cap(cast(Any, client), "absent-col", stranger.keys.ed_pub) is None


@pytest.mark.asyncio
async def test_unpublish_member_cap_removes_by_nonce() -> None:
    alice = derive_root_identity("alice-pub4-pass")
    bob = derive_root_identity("bob-pub4-pass")
    cert = mint_member_cap(
        alice.keys.ed_priv, alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
        "shared-board", scopes.writer("shared-board"),
    )
    client = _client()
    await publish_member_cap(cast(Any, client), "shared-board", cert)
    assert await unpublish_member_cap(cast(Any, client), "shared-board", cert["nonce"]) is True
    assert await fetch_my_member_cap(cast(Any, client), "shared-board", bob.keys.ed_pub) is None


@pytest.mark.asyncio
async def test_converges_on_present_after_add_remove_readd() -> None:
    alice = derive_root_identity("alice-churn-readd-pass")
    bob = derive_root_identity("bob-churn-readd-pass")
    cert = mint_member_cap(
        alice.keys.ed_priv, alice.keys.ed_pub,
        {"edPubHex": bob.keys.ed_pub, "kemPubHex": bob.keys.kem_pub, "userIdHex": bob.user_id},
        "shared", scopes.writer("shared"),
    )
    client = _client()
    await add_member_entry(cast(Any, client), "shared", cert)
    assert await remove_member_entry(cast(Any, client), "shared", cert["nonce"]) is True
    assert await list_members(cast(Any, client), "shared") == []

    await add_member_entry(cast(Any, client), "shared", cert)
    listed = await list_members(cast(Any, client), "shared")
    assert len(listed) == 1
    assert listed[0]["subUserId"] == bob.user_id
