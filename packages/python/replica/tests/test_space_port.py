"""SpacePort — the only module that touches starfish_spaces.

Covers the three things the port exists to absorb (see port.py's docstring):
its CAS push helper (which TS gets free from NodeAccessHandle.push and Python
has to supply), the nested-vs-flat readObjectTree divergence, and in-flight
coalescing on find_or_create_space.

House style: hand-rolled fakes, no unittest.mock — matching
packages/python/spaces/tests/test_registry_cas.py.
"""

from __future__ import annotations

import asyncio

import pytest
from starfish_sdk.types import ConflictError, StarfishHttpError

from starfish_replica.space.port import (
    default_space_port,
    find_or_create_space,
    flatten_object_tree,
)


class _Res:
    def __init__(self, data, hash_):
        self.data = data
        self.hash = hash_


class FakeNodeClient:
    """In-memory node document; optionally conflicts on the first N pushes."""

    def __init__(self, data=None, hash_="h0", conflict_on=(), missing=False):
        self.data = data
        self.hash = hash_
        self.missing = missing
        self.conflict_on = set(conflict_on)
        self.push_calls = 0
        self.pull_calls = 0
        self.pushed: list[tuple[str, object, object]] = []

    async def pull(self, path):
        self.pull_calls += 1
        if self.missing:
            raise StarfishHttpError(404, "not found")
        return _Res(self.data, self.hash)

    async def push(self, path, payload, base_hash):
        self.push_calls += 1
        self.pushed.append((path, payload, base_hash))
        if self.push_calls in self.conflict_on:
            self.data = {"someone": "else"}
            self.hash = "h-conflict"
            self.missing = False
            raise ConflictError()
        self.data = payload
        self.hash = f"h{self.push_calls}"


class FakeEncryptor:
    """Synchronous encrypt/decrypt, like the real KeyringEncryptor."""

    def __init__(self):
        self.encrypt_calls = 0
        self.decrypt_calls = 0

    def encrypt(self, data):
        self.encrypt_calls += 1
        return {"_enc": data}

    def decrypt(self, blob):
        self.decrypt_calls += 1
        if isinstance(blob, dict) and "_enc" in blob:
            return blob["_enc"]
        raise ValueError("not an encrypted blob")


class Handle:
    def __init__(self, client, encryptor=None):
        self.client = client
        self.encryptor = encryptor
        self.is_owner_open = False


# ── push_node_doc: CAS ────────────────────────────────────────────────────────


async def test_push_node_doc_writes_the_mutator_result():
    client = FakeNodeClient(data={"old": True})
    await default_space_port.push_node_doc(
        Handle(client), "/pull/p", "/push/p", lambda cur: {"new": True}
    )
    assert client.data == {"new": True}
    assert client.push_calls == 1


async def test_push_node_doc_passes_the_current_doc_to_the_mutator():
    client = FakeNodeClient(data={"count": 1})
    seen = {}

    def mutator(cur):
        seen["cur"] = cur
        return {"count": cur["count"] + 1}

    await default_space_port.push_node_doc(Handle(client), "/pull/p", "/push/p", mutator)
    assert seen["cur"] == {"count": 1}
    assert client.data == {"count": 2}


async def test_push_node_doc_sends_the_pulled_hash_as_base_hash():
    client = FakeNodeClient(data={}, hash_="h-current")
    await default_space_port.push_node_doc(Handle(client), "/pull/p", "/push/p", lambda c: {"x": 1})
    _path, _payload, base_hash = client.pushed[0]
    assert base_hash == "h-current"


async def test_push_node_doc_retries_on_conflict():
    # A single-attempt push (no retry on conflict) would drop this write; the
    # port's run_cas wrapper is what makes it converge.
    client = FakeNodeClient(data={"v": 0}, conflict_on={1})
    await default_space_port.push_node_doc(
        Handle(client), "/pull/p", "/push/p", lambda cur: {"v": 1}
    )
    assert client.push_calls == 2
    assert client.data == {"v": 1}


async def test_push_node_doc_rereads_state_between_conflict_retries():
    # run_cas re-invokes the whole attempt, so the mutator must see the
    # post-conflict server state, not the stale first read.
    client = FakeNodeClient(data={"v": 0}, conflict_on={1})
    seen = []
    await default_space_port.push_node_doc(
        Handle(client), "/pull/p", "/push/p", lambda cur: seen.append(cur) or {"v": 1}
    )
    assert seen == [{"v": 0}, {"someone": "else"}]


async def test_push_node_doc_gives_up_after_max_attempts():
    client = FakeNodeClient(data={}, conflict_on=set(range(1, 20)))
    with pytest.raises(ConflictError):
        await default_space_port.push_node_doc(
            Handle(client), "/pull/p", "/push/p", lambda c: {"x": 1}
        )
    assert client.push_calls == 5  # cas_retry.MAX_ATTEMPTS


async def test_push_node_doc_treats_a_missing_document_as_absent():
    client = FakeNodeClient(missing=True)
    seen = []
    await default_space_port.push_node_doc(
        Handle(client), "/pull/p", "/push/p", lambda cur: seen.append(cur) or {"first": True}
    )
    assert seen == [None]
    _path, _payload, base_hash = client.pushed[0]
    assert base_hash is None
    assert client.data == {"first": True}


async def test_push_node_doc_skips_the_write_when_the_mutator_returns_none():
    client = FakeNodeClient(data={"keep": True})
    await default_space_port.push_node_doc(Handle(client), "/pull/p", "/push/p", lambda cur: None)
    assert client.push_calls == 0
    assert client.data == {"keep": True}


async def test_push_node_doc_uses_the_configured_paths():
    client = FakeNodeClient(data={})
    await default_space_port.push_node_doc(
        Handle(client), "/pull/spaces/sp1/objects/mirror/n1", "/push/spaces/sp1/objects/mirror/n1",
        lambda c: {"x": 1},
    )
    assert client.pushed[0][0] == "/push/spaces/sp1/objects/mirror/n1"


# ── push_node_doc: encryption ────────────────────────────────────────────────


async def test_push_node_doc_encrypts_on_the_way_out():
    client = FakeNodeClient(missing=True)
    enc = FakeEncryptor()
    await default_space_port.push_node_doc(
        Handle(client, enc), "/pull/p", "/push/p", lambda c: {"secret": 1}
    )
    assert client.data == {"_enc": {"secret": 1}}
    assert enc.encrypt_calls == 1


async def test_push_node_doc_decrypts_on_the_way_in():
    client = FakeNodeClient(data={"_enc": {"secret": 1}})
    enc = FakeEncryptor()
    seen = []
    await default_space_port.push_node_doc(
        Handle(client, enc), "/pull/p", "/push/p", lambda cur: seen.append(cur) or {"secret": 2}
    )
    assert seen == [{"secret": 1}]
    assert enc.decrypt_calls == 1


async def test_push_node_doc_round_trips_through_the_encryptor():
    client = FakeNodeClient(missing=True)
    enc = FakeEncryptor()
    handle = Handle(client, enc)
    await default_space_port.push_node_doc(handle, "/pull/p", "/push/p", lambda c: {"n": 1})
    client.missing = False
    seen = []
    await default_space_port.push_node_doc(
        handle, "/pull/p", "/push/p", lambda cur: seen.append(cur) or {"n": cur["n"] + 1}
    )
    assert seen == [{"n": 1}]
    assert client.data == {"_enc": {"n": 2}}


async def test_push_node_doc_does_not_decrypt_a_missing_document():
    # decrypt(None) would throw in the real KeyringEncryptor.
    client = FakeNodeClient(missing=True)
    enc = FakeEncryptor()
    await default_space_port.push_node_doc(
        Handle(client, enc), "/pull/p", "/push/p", lambda c: {"x": 1}
    )
    assert enc.decrypt_calls == 0


async def test_push_node_doc_leaves_payload_plain_without_an_encryptor():
    client = FakeNodeClient(data={"plain": True})
    await default_space_port.push_node_doc(
        Handle(client, None), "/pull/p", "/push/p", lambda c: {"still": "plain"}
    )
    assert client.data == {"still": "plain"}


# ── flatten_object_tree ──────────────────────────────────────────────────────


def test_flatten_object_tree_flattens_nested_children():
    # The divergence this exists for: Python's read_object_tree returns a NESTED
    # tree while TS's identically-named readObjectTree returns a FLAT list.
    # Without flattening, a non-root node is invisible to the planner and the
    # channel creates a duplicate alongside it.
    tree = [
        {"id": "a", "type": "t-a", "children": [
            {"id": "b", "type": "t-b", "children": [{"id": "c", "type": "t-c", "children": []}]},
        ]},
        {"id": "d", "type": "t-d", "children": []},
    ]
    flat = flatten_object_tree(tree)
    assert [n["id"] for n in flat] == ["a", "b", "c", "d"]


def test_flatten_object_tree_handles_an_empty_tree():
    assert flatten_object_tree([]) == []
    assert flatten_object_tree(None) == []


def test_flatten_object_tree_handles_missing_children_keys():
    assert [n["id"] for n in flatten_object_tree([{"id": "a", "type": "t"}])] == ["a"]


def test_flatten_object_tree_accepts_dataclass_like_nodes():
    class Node:
        def __init__(self, id, type, children=()):
            self.id = id
            self.type = type
            self.children = list(children)

    flat = flatten_object_tree([Node("a", "t-a", [Node("b", "t-b")])])
    assert [n["id"] for n in flat] == ["a", "b"]


# ── find_or_create_space ─────────────────────────────────────────────────────


class FakeSpacesPort:
    def __init__(self, spaces=None, delay=0.0):
        self.spaces = list(spaces or [])
        self.delay = delay
        self.read_calls = 0
        self.create_calls = 0

    async def read_spaces(self, session):
        self.read_calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        return list(self.spaces)

    async def create_space(self, session, name):
        self.create_calls += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        space = {"id": f"sp-{len(self.spaces) + 1}", "name": name}
        self.spaces.append(space)
        return space


class _Session:
    user_id = "user-1"


async def test_find_or_create_returns_an_existing_space():
    port = FakeSpacesPort([{"id": "sp-existing", "name": "mirror"}])
    space = await find_or_create_space(_Session(), "mirror", port)
    assert space["id"] == "sp-existing"
    assert port.create_calls == 0


async def test_find_or_create_creates_when_absent():
    port = FakeSpacesPort([])
    space = await find_or_create_space(_Session(), "mirror", port)
    assert space["name"] == "mirror"
    assert port.create_calls == 1


async def test_find_or_create_matches_by_exact_name():
    port = FakeSpacesPort([{"id": "sp-1", "name": "mirror-private"}])
    space = await find_or_create_space(_Session(), "mirror", port)
    assert space["id"] != "sp-1"
    assert port.create_calls == 1


async def test_concurrent_find_or_create_coalesces_into_one_create():
    # The in-flight coalescing fix, baked in from the start here rather than
    # found later by review as it was in TS. Without it both callers miss the
    # not-yet-created space and each calls create_space, leaving a duplicate.
    port = FakeSpacesPort([], delay=0.01)
    a, b = await asyncio.gather(
        find_or_create_space(_Session(), "mirror", port),
        find_or_create_space(_Session(), "mirror", port),
    )
    assert port.create_calls == 1
    assert port.read_calls == 1
    assert a["id"] == b["id"]


async def test_concurrent_find_or_create_for_different_names_does_not_coalesce():
    port = FakeSpacesPort([], delay=0.01)
    a, b = await asyncio.gather(
        find_or_create_space(_Session(), "mirror-shared", port),
        find_or_create_space(_Session(), "mirror-private", port),
    )
    assert port.create_calls == 2
    assert a["id"] != b["id"]


async def test_the_in_flight_entry_is_released_after_completion():
    # A leaked entry would make every later call return the first (stale)
    # result forever.
    port = FakeSpacesPort([])
    first = await find_or_create_space(_Session(), "mirror", port)
    second = await find_or_create_space(_Session(), "mirror", port)
    assert port.read_calls == 2  # not served from a stale in-flight entry
    assert first["id"] == second["id"]


async def test_the_in_flight_entry_is_released_after_a_failure():
    class Boom(FakeSpacesPort):
        async def read_spaces(self, session):
            raise RuntimeError("network down")

    port = Boom([])
    with pytest.raises(RuntimeError):
        await find_or_create_space(_Session(), "mirror", port)
    # A leaked failed task would make the retry re-raise the same stale error.
    ok = FakeSpacesPort([])
    space = await find_or_create_space(_Session(), "mirror", ok)
    assert space["name"] == "mirror"


async def test_concurrent_callers_both_see_a_failure():
    class Boom(FakeSpacesPort):
        async def read_spaces(self, session):
            await asyncio.sleep(0.01)
            raise RuntimeError("network down")

    port = Boom([])
    results = await asyncio.gather(
        find_or_create_space(_Session(), "mirror", port),
        find_or_create_space(_Session(), "mirror", port),
        return_exceptions=True,
    )
    assert all(isinstance(r, RuntimeError) for r in results)


async def test_different_sessions_do_not_share_an_in_flight_entry():
    class OtherSession:
        user_id = "user-2"

    port = FakeSpacesPort([], delay=0.01)
    await asyncio.gather(
        find_or_create_space(_Session(), "mirror", port),
        find_or_create_space(OtherSession(), "mirror", port),
    )
    # Keyed by f"{user_id}:{name}" — two identities must not coalesce.
    assert port.read_calls == 2
