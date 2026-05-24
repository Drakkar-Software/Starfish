"""Tests for the device directory module."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Optional, cast

import pytest

from starfish_identities.cap_mint import mint_device_cap, scopes
from starfish_identities.directory import (
    add_device_entry,
    devices_path_for,
    list_devices,
    remove_device_entry,
)
from starfish_identities.identity import derive_root_identity
from starfish_sdk.types import ConflictError, StarfishHttpError


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
    """Minimal StarfishClient stand-in for directory tests."""

    def __init__(self) -> None:
        self._store: dict[str, _StoredDoc] = {}
        self._counter = 0
        self.push_failure_mode: Optional[str] = None
        self.push_call_count = 0

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
        self.push_call_count += 1
        if self.push_failure_mode == "conflict_once":
            self.push_failure_mode = None
            raise ConflictError("synthetic")
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


def test_devices_path_for_returns_user_namespaced() -> None:
    assert devices_path_for("abc1234567890def") == "users/abc1234567890def/_devices"


@pytest.mark.asyncio
async def test_add_device_entry_appends_to_empty_directory() -> None:
    alice = derive_root_identity("alice-dir-pass")
    cert = mint_device_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": alice.keys.ed_pub, "kemPubHex": alice.keys.kem_pub},
        scopes.root_all(),
    )
    client = _client()
    await add_device_entry(
        cast(Any, client), alice.user_id, cert, label="Alice's iPhone"
    )

    stored = client.store[devices_path_for(alice.user_id)]
    entries = stored.data["entries"]
    assert len(entries) == 1
    assert entries[0]["nonce"] == cert["nonce"]
    assert entries[0]["label"] == "Alice's iPhone"

    listed = await list_devices(cast(Any, client), alice.user_id)
    assert len(listed) == 1
    assert listed[0]["nonce"] == cert["nonce"]


@pytest.mark.asyncio
async def test_add_device_entry_upserts_by_nonce() -> None:
    alice = derive_root_identity("alice-upsert-pass")
    cert = mint_device_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": alice.keys.ed_pub, "kemPubHex": alice.keys.kem_pub},
        scopes.root_all(),
    )
    client = _client()
    await add_device_entry(cast(Any, client), alice.user_id, cert, label="first")
    await add_device_entry(cast(Any, client), alice.user_id, cert, label="second")

    stored = client.store[devices_path_for(alice.user_id)]
    entries = stored.data["entries"]
    assert len(entries) == 1
    assert entries[0]["label"] == "second"


@pytest.mark.asyncio
async def test_add_device_entry_rejects_member_cap() -> None:
    alice = derive_root_identity("alice-bad-kind-pass")
    # add_device_entry dispatches purely on cert["kind"]; a minimal
    # member-kind dict exercises the guard without depending on the
    # sharing extension's mint_member_cap.
    member_cert = {
        "v": 1,
        "kind": "member",
        "iss": alice.keys.ed_pub,
        "issUserId": alice.user_id,
        "sub": alice.keys.ed_pub,
        "subKem": alice.keys.kem_pub,
        "subUserId": alice.user_id,
        "scope": {"ops": ["read"], "collections": ["shared"], "paths": ["shared/**"]},
        "nbf": 0,
        "exp": 0,
        "nonce": "AAAAAAAAAAAAAAAAAAAAAA==",
        "sig": "",
    }
    client = _client()
    with pytest.raises(ValueError, match="kind='member'"):
        await add_device_entry(cast(Any, client), alice.user_id, member_cert)


@pytest.mark.asyncio
async def test_list_devices_filters_expired_by_default() -> None:
    alice = derive_root_identity("alice-expired-pass")
    cert = mint_device_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": alice.keys.ed_pub, "kemPubHex": alice.keys.kem_pub},
        scopes.root_all(),
    )
    client = _client()
    await add_device_entry(cast(Any, client), alice.user_id, cert)

    path = devices_path_for(alice.user_id)
    client.store[path].data["entries"][0]["exp"] = int(time.time()) - 1000

    visible = await list_devices(cast(Any, client), alice.user_id)
    assert visible == []

    with_expired = await list_devices(
        cast(Any, client), alice.user_id, {"include_expired": True}
    )
    assert len(with_expired) == 1


@pytest.mark.asyncio
async def test_list_devices_filters_revoked_nonces() -> None:
    alice = derive_root_identity("alice-revoked-pass")
    cert = mint_device_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": alice.keys.ed_pub, "kemPubHex": alice.keys.kem_pub},
        scopes.root_all(),
    )
    client = _client()
    await add_device_entry(cast(Any, client), alice.user_id, cert)

    visible = await list_devices(
        cast(Any, client),
        alice.user_id,
        {"revoked_nonces": frozenset([cert["nonce"]])},
    )
    assert visible == []


@pytest.mark.asyncio
async def test_list_devices_empty_when_no_directory() -> None:
    client = _client()
    out = await list_devices(cast(Any, client), "noone")
    assert out == []


@pytest.mark.asyncio
async def test_remove_device_entry_roundtrip() -> None:
    alice = derive_root_identity("alice-rem-pass")
    cert = mint_device_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": alice.keys.ed_pub, "kemPubHex": alice.keys.kem_pub},
        scopes.root_all(),
    )
    client = _client()
    await add_device_entry(cast(Any, client), alice.user_id, cert)

    assert (
        await remove_device_entry(cast(Any, client), alice.user_id, cert["nonce"])
        is True
    )
    assert (
        await remove_device_entry(cast(Any, client), alice.user_id, cert["nonce"])
        is False
    )


@pytest.mark.asyncio
async def test_remove_device_entry_no_directory_returns_false() -> None:
    client = _client()
    assert (
        await remove_device_entry(cast(Any, client), "ghost", "nonce-xyz") is False
    )


@pytest.mark.asyncio
async def test_add_device_entry_retries_on_conflict() -> None:
    alice = derive_root_identity("alice-conflict-pass")
    cert = mint_device_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": alice.keys.ed_pub, "kemPubHex": alice.keys.kem_pub},
        scopes.root_all(),
    )
    client = _client()
    client.push_failure_mode = "conflict_once"
    await add_device_entry(cast(Any, client), alice.user_id, cert)

    assert client.push_call_count >= 2
    stored = client.store[devices_path_for(alice.user_id)]
    assert any(e["nonce"] == cert["nonce"] for e in stored.data["entries"])


@pytest.mark.asyncio
async def test_entry_shape_copies_scope_and_stamps_added_at() -> None:
    alice = derive_root_identity("alice-shape-pass")
    before = int(time.time())
    cert = mint_device_cap(
        alice.keys.ed_priv,
        alice.keys.ed_pub,
        {"edPubHex": alice.keys.ed_pub, "kemPubHex": alice.keys.kem_pub},
        scopes.root_all(),
    )
    client = _client()
    await add_device_entry(
        cast(Any, client),
        alice.user_id,
        cert,
        label="test-host",
        added_by=alice.keys.ed_pub,
    )
    entries = await list_devices(
        cast(Any, client), alice.user_id, {"include_expired": True}
    )
    assert len(entries) == 1
    e = entries[0]
    assert e["scope"] == cert["scope"]
    assert e["nbf"] == cert["nbf"]
    assert e["exp"] == cert["exp"]
    assert e["label"] == "test-host"
    assert e["addedBy"] == alice.keys.ed_pub
    assert e["addedAt"] >= before
