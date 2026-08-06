"""Regression tests for create_node's owner-identity self-mint bug.

create_node() used to unconditionally mint an ``objinvlog`` "member" cap for
the CREATOR'S OWN identity (subUserId == issUserId). starfish-sharing's
assert_member_cap_shape rejects that shape outright -- a ``kind:"member"`` cap
exists to grant access to someone ELSE, not to the issuer's own identity -- so
every create_node() call threw against a real server. See ../starfish_spaces/nodes.py.

Mirrors packages/ts/spaces/tests/nodes-create.test.ts (N1-N4) for parity.

N1: create_node (enc=False) resolves without throwing and returns the node.
N2: create_node never mints a cap for its own identity (mint_cap not called).
N3: create_node never records a node-stream access entry for the creator.
N4: create_node (enc=True) still ensures the SPACE keyring (unrelated,
    pre-existing path) but still does not self-mint a member cap.
N5: create_node rejects the access='public' + enc=True combination.
"""

from __future__ import annotations

import starfish_spaces.nodes as nodes_module
from starfish_spaces.space_access_store import get_node_stream_access_entry

from .helpers import make_fake_session


class FakeContentClient:
    """In-memory object-index doc supporting the pull/push shape update_object_index needs."""

    def __init__(self) -> None:
        self.data: dict = {"objects": []}
        self.hash = "H0"
        self.push_calls = 0

    class _Res:
        def __init__(self, data, hash_):
            self.data = data
            self.hash = hash_

    async def pull(self, path):
        return self._Res(self.data, self.hash)

    async def push(self, path, payload, base_hash):
        self.push_calls += 1
        self.data = payload
        self.hash = f"H{self.push_calls}"


def _session(content_client=None):
    session = make_fake_session(content_client=content_client or FakeContentClient())
    session.node_id_prefix = "nd_"
    return session


async def test_n1_create_node_resolves_and_returns_the_node():
    session = _session()

    node = await nodes_module.create_node(
        session, "sp-1", {"type": "doc", "title": "Mirror", "access": "space", "enc": False}
    )

    assert node.id
    assert node.type == "doc"
    assert node.title == "Mirror"


async def test_n2_create_node_never_mints_a_cap_for_its_own_identity(monkeypatch):
    calls = []
    monkeypatch.setattr(nodes_module, "mint_cap", lambda *a, **kw: calls.append((a, kw)) or {})

    session = _session()
    await nodes_module.create_node(session, "sp-1", {"type": "doc", "title": "Mirror", "access": "space", "enc": False})

    assert calls == []


async def test_n3_create_node_never_records_a_node_stream_access_entry():
    session = _session()
    node = await nodes_module.create_node(
        session, "sp-1", {"type": "doc", "title": "Mirror", "access": "space", "enc": False}
    )

    assert get_node_stream_access_entry("sp-1", node.id) is None


async def test_n4_enc_true_still_ensures_space_keyring_but_does_not_self_mint(monkeypatch):
    ensure_calls = []

    async def fake_ensure_space_keyring(*a, **kw):
        ensure_calls.append((a, kw))

    mint_calls = []
    monkeypatch.setattr(nodes_module, "owner_ensure_space_keyring", fake_ensure_space_keyring)
    monkeypatch.setattr(nodes_module, "mint_cap", lambda *a, **kw: mint_calls.append((a, kw)) or {})

    session = _session()
    node = await nodes_module.create_node(
        session, "sp-1", {"type": "doc", "title": "Mirror", "access": "space", "enc": True}
    )

    assert node.enc is True
    assert len(ensure_calls) == 1
    assert mint_calls == []


async def test_n5_create_node_rejects_public_plus_enc():
    session = _session()

    try:
        await nodes_module.create_node(session, "sp-1", {"type": "doc", "access": "public", "enc": True})
    except ValueError as exc:
        assert "public+enc" in str(exc)
    else:
        raise AssertionError("expected ValueError for public+enc")


async def test_create_node_survives_a_cas_conflict_on_the_object_index():
    """Not part of the TS parity set -- extra coverage for the CAS retry path
    create_node relies on via update_object_index / run_cas."""
    from starfish_sdk.types import ConflictError

    class ConflictingClient(FakeContentClient):
        async def push(self, path, payload, base_hash):
            self.push_calls += 1
            if self.push_calls == 1:
                # Someone else wrote a node concurrently; server has moved on.
                self.data = {"objects": [{"id": "nd_other", "type": "doc", "title": "Other"}]}
                self.hash = "H-conflict"
                raise ConflictError()
            self.data = payload
            self.hash = f"H{self.push_calls}"

    client = ConflictingClient()
    session = _session(content_client=client)

    node = await nodes_module.create_node(session, "sp-1", {"type": "doc", "title": "Mirror", "access": "space", "enc": False})

    assert client.push_calls == 2
    ids = {o["id"] for o in client.data["objects"]}
    assert "nd_other" in ids
    assert node.id in ids


async def test_create_node_ids_are_unique_across_calls():
    session = _session()

    n1 = await nodes_module.create_node(session, "sp-1", {"type": "doc", "title": "A", "access": "space", "enc": False})
    n2 = await nodes_module.create_node(session, "sp-1", {"type": "doc", "title": "B", "access": "space", "enc": False})

    assert n1.id != n2.id


# ── set_node_access ───────────────────────────────────────────────────────────
#
# set_node_access shared the exact same latent bug as create_node: its inner
# `mutator` closure was declared `async def` while `update_object_index` calls
# it synchronously (`mutator(current)`, no `await`) -- every other mutator in
# this codebase (registry.py x6, nodes.py's own create_node) is plain `def`.
# That means set_node_access has never actually worked either, independent of
# the self-mint cap bug above. No prior test in this repo exercised it.


async def test_set_node_access_patches_the_access_field():
    client = FakeContentClient()
    session = _session(content_client=client)
    node = await nodes_module.create_node(session, "sp-1", {"type": "doc", "title": "Mirror", "access": "space", "enc": False})

    await nodes_module.set_node_access(session, "sp-1", node.id, {"access": "invite"})

    patched = next(o for o in client.data["objects"] if o["id"] == node.id)
    assert patched["access"] == "invite"


async def test_set_node_access_is_a_noop_when_unchanged():
    client = FakeContentClient()
    session = _session(content_client=client)
    node = await nodes_module.create_node(session, "sp-1", {"type": "doc", "title": "Mirror", "access": "space", "enc": False})
    calls_before = client.push_calls

    await nodes_module.set_node_access(session, "sp-1", node.id, {"access": "space"})

    assert client.push_calls == calls_before


async def test_set_node_access_is_a_noop_for_an_unknown_node():
    client = FakeContentClient()
    session = _session(content_client=client)
    await nodes_module.create_node(session, "sp-1", {"type": "doc", "title": "Mirror", "access": "space", "enc": False})
    calls_before = client.push_calls

    await nodes_module.set_node_access(session, "sp-1", "nd_does_not_exist", {"access": "invite"})

    assert client.push_calls == calls_before


async def test_set_node_access_rejects_public_plus_enc():
    session = _session()

    try:
        await nodes_module.set_node_access(session, "sp-1", "nd_1", {"access": "public", "enc": True})
    except ValueError as exc:
        assert "public+enc" in str(exc)
    else:
        raise AssertionError("expected ValueError for public+enc")
