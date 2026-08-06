"""Verifies (rather than assumes) that canonical starfish_spaces resolves an
owner's node access with no pre-cached member cap.

## Why this test exists

`SpaceMirrorChannel` calls `get_node_access` unconditionally, including on the
very first cycle — a space and node the caller has only just created, with no
stored access entry of any kind. If node-access resolution required a cached
member cap, the whole write path would fail exactly when it is first used, and
callers would have to bypass it with raw content/keyring clients.

That it does NOT require one is therefore load-bearing for this subpackage, so
it is asserted here rather than assumed.

The relevant code is `starfish_spaces/space_access.py`'s **Tier 5 — owner
self-mint** branch (`if session.keys["edPub"] == session.owner_ed_pub`), which
returns a handle built from `session.content_client` with
`is_owner_open=True`, falling back to the space-level keyring when the node has
no keyring of its own. Tiers 1-4 all require a stored access entry; an owner
who just created the space and node has none.
"""

from __future__ import annotations

import pytest

from starfish_spaces.space_access import get_node_access
from starfish_spaces.space_access_error import SpaceAccessError
from starfish_spaces.space_access_store import clear_space_access_store


@pytest.fixture(autouse=True)
def _clean_access_store():
    # get_node_access memoizes; keep every case independent.
    import starfish_spaces.space_access as sa

    clear_space_access_store()
    sa._cache.clear()
    sa._space_encryptor_cache.clear()
    yield
    clear_space_access_store()
    sa._cache.clear()
    sa._space_encryptor_cache.clear()


class _NullClient:
    """Content client that has no keyring document — forces Tier 5's fallback
    path (build_node_encryptor -> None -> space keyring -> None)."""

    async def pull(self, path):
        raise RuntimeError("no keyring document")

    async def push(self, path, payload, base_hash=None):
        raise RuntimeError("read-only in this test")


def _owner_session():
    import hashlib
    from types import SimpleNamespace

    from starfish_identities import generate_device_keys
    from starfish_spaces.layout import default_space_layout, default_user_id_from_ed_pub

    keys = generate_device_keys()
    client = _NullClient()
    # default_user_id_from_ed_pub is async; derive the id the same synchronous
    # way packages/python/spaces/tests/helpers.py::user_id_for does, and keep
    # the async callable on the session for code that awaits it.
    user_id = hashlib.sha256(bytes.fromhex(keys["edPub"])).digest()[:16].hex()
    return SimpleNamespace(
        keys=keys,
        user_id=user_id,
        owner_ed_pub=keys["edPub"],          # <- the owner
        user_id_from_ed_pub=default_user_id_from_ed_pub,
        layout=default_space_layout,
        inbox_aad_namespace="starfish:inbox:v1",
        base_url="",
        namespace="",
        account_client=client,
        content_client=client,
        node_id_prefix="nd_",
        space_id_prefix="sp_",
    )


def _stranger_session():
    session = _owner_session()
    from starfish_identities import generate_device_keys

    # Same shape, but NOT the space owner.
    session.owner_ed_pub = generate_device_keys()["edPub"]
    return session


async def test_owner_resolves_node_access_with_no_cached_member_cap():
    """The load-bearing assertion: no store entry, no invite, no prior cap —
    the owner still gets a usable handle. This is exactly the case the
    vendored dk_spaces_sdk could not serve."""
    session = _owner_session()

    handle = await get_node_access(session, "sp-1", "nd-1")

    assert handle is not None
    assert handle.client is session.content_client


async def test_the_owner_handle_is_flagged_is_owner_open():
    session = _owner_session()
    handle = await get_node_access(session, "sp-1", "nd-1")
    assert handle.is_owner_open is True


async def test_a_non_owner_with_no_credential_is_rejected():
    # The control: Tier 5 must be gated on actually being the owner, or the
    # test above would pass for the wrong reason (a branch that fires for
    # everyone).
    session = _stranger_session()
    with pytest.raises(SpaceAccessError):
        await get_node_access(session, "sp-1", "nd-1")


async def test_owner_access_is_memoized_per_space_and_node():
    session = _owner_session()
    first = await get_node_access(session, "sp-1", "nd-1")
    second = await get_node_access(session, "sp-1", "nd-1")
    assert first is second


async def test_different_nodes_get_distinct_handles():
    session = _owner_session()
    a = await get_node_access(session, "sp-1", "nd-1")
    b = await get_node_access(session, "sp-1", "nd-2")
    assert a is not b


async def test_the_mirror_channel_can_write_through_a_real_owner_handle():
    """End-to-end-ish: the channel's own get_node_access call path resolves
    against the REAL starfish_spaces implementation (not a fake port), proving
    the workaround the vendored writer needed is unnecessary here."""
    from starfish_replica.channel import REPLICATOR_CTX
    from starfish_replica.space.mirror_channel import (
        SpaceMirrorCollection,
        create_space_mirror_channel,
    )
    from starfish_replica.space.port import default_space_port

    session = _owner_session()
    pushed: list[tuple[str, object]] = []

    class OwnerAccessPort:
        """Fakes only the space/node registry; get_node_access is the REAL one."""

        async def read_spaces(self, s):
            return [{"id": "sp-1", "name": "mirror"}]

        async def create_space(self, s, name):
            raise AssertionError("space already exists")

        async def read_object_tree(self, s, space_id):
            return [{"id": "nd-1", "type": "user-accounts"}]

        async def create_node(self, s, space_id, inp):
            raise AssertionError("node already exists")

        get_node_access = default_space_port.get_node_access  # the real thing

        async def push_node_doc(self, handle, pull_path, push_path, mutator, node=None):
            assert handle.is_owner_open is True
            # The channel forwards the node's access axes on every write; the
            # real get_node_access above needs them to pick a tier.
            assert node == {"access": "space", "enc": True}
            pushed.append((push_path, mutator(None)))

    async def read_source(cid, ctx):
        return {"collection": cid}

    channel = create_space_mirror_channel(
        name="mirror",
        session=session,
        collections=[SpaceMirrorCollection(id="user-accounts", space_name="mirror")],
        enabled_ids=lambda: ["user-accounts"],
        read_source=read_source,
        doc_path=lambda sp, nd: f"spaces/{sp}/objects/mirror/{nd}",
        port=OwnerAccessPort(),
    )

    await channel.sync(REPLICATOR_CTX)

    assert channel.result.written == ["user-accounts"]
    assert pushed == [
        ("/push/spaces/sp-1/objects/mirror/nd-1", {"collection": "user-accounts"})
    ]
