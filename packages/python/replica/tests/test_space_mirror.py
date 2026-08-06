"""SpaceMirrorChannel — the space-mirror sync cycle.

Ports all 10 cases from the TS suite (packages/ts/replica/tests/space-mirror.test.ts)
for parity, then adds Python-specific and extra-coverage cases.

Uses a fake in-memory SpacePort — no unittest.mock, matching this monorepo's
hand-rolled fake idiom.
"""

from __future__ import annotations

import asyncio

import pytest

from starfish_replica.channel import REPLICATOR_CTX, ReplicaCallContext
from starfish_replica.space.mirror_channel import (
    SpaceMirrorCollection,
    create_space_mirror_channel,
)

SHARED = "app-mirror"
PRIVATE = "app-mirror-private"


class FakeSpacePort:
    """In-memory spaces/nodes/content with call counters."""

    def __init__(self, spaces=None):
        self.spaces: list[dict] = list(spaces or [])
        self.nodes: dict[str, list[dict]] = {}       # space_id -> [{id, type, children}]
        self.content: dict[str, object] = {}         # f"{space_id}:{node_id}" -> data
        self.create_space_calls: list[str] = []
        self.create_node_calls: list[tuple[str, str]] = []
        self.pushes: list[tuple[str, str, object]] = []  # (space_id, node_id, payload)
        self.node_access_calls: list[tuple[str, str]] = []
        self._seq = 0

    async def read_spaces(self, session):
        return list(self.spaces)

    async def create_space(self, session, name):
        self.create_space_calls.append(name)
        self._seq += 1
        space = {"id": f"sp-{self._seq}", "name": name}
        self.spaces.append(space)
        self.nodes[space["id"]] = []
        return space

    async def read_object_tree(self, session, space_id):
        return list(self.nodes.get(space_id, []))

    async def create_node(self, session, space_id, inp):
        self.create_node_calls.append((space_id, inp["type"]))
        self._seq += 1
        node = {"id": f"nd-{self._seq}", "type": inp["type"], "access": inp.get("access"),
                "enc": inp.get("enc"), "children": []}
        self.nodes.setdefault(space_id, []).append(node)
        return node

    async def get_node_access(self, session, space_id, node_id):
        self.node_access_calls.append((space_id, node_id))
        return _FakeHandle(space_id, node_id)

    async def push_node_doc(self, handle, pull_path, push_path, mutator):
        key = f"{handle.space_id}:{handle.node_id}"
        nxt = mutator(self.content.get(key))
        if nxt is None:
            return
        self.content[key] = nxt
        self.pushes.append((handle.space_id, handle.node_id, nxt))

    # helpers
    def space_id_for(self, name):
        return next((s["id"] for s in self.spaces if s["name"] == name), None)

    def node_for(self, space_name, type_):
        sid = self.space_id_for(space_name)
        return next((n for n in self.nodes.get(sid, []) if n["type"] == type_), None)

    def content_for(self, space_name, type_):
        sid = self.space_id_for(space_name)
        node = self.node_for(space_name, type_)
        return self.content.get(f"{sid}:{node['id']}") if node else None


class _FakeHandle:
    def __init__(self, space_id, node_id):
        self.space_id = space_id
        self.node_id = node_id
        self.client = None
        self.encryptor = None
        self.is_owner_open = False


class _Session:
    user_id = "user-1"


COLLECTIONS = [
    SpaceMirrorCollection(id="user-accounts", space_name=SHARED),
    SpaceMirrorCollection(id="user-data", space_name=SHARED),
    SpaceMirrorCollection(id="user-settings", space_name=PRIVATE),
]


def _make_channel(port, enabled, *, collections=None, change_detection="none",
                  read_source=None, node_enc=None, name="mirror"):
    enabled_box = {"ids": list(enabled)}

    async def default_read_source(cid, ctx):
        return {"collection": cid}

    channel = create_space_mirror_channel(
        name=name,
        session=_Session(),
        collections=collections if collections is not None else COLLECTIONS,
        enabled_ids=lambda: list(enabled_box["ids"]),
        read_source=read_source or default_read_source,
        doc_path=lambda space_id, node_id: f"spaces/{space_id}/objects/mirror/{node_id}",
        node_enc=node_enc,
        change_detection=change_detection,
        port=port,
    )
    return channel, enabled_box


# ── TS parity ────────────────────────────────────────────────────────────────


async def test_create_on_first_sync():
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"])

    await channel.sync(REPLICATOR_CTX)

    assert port.create_node_calls == [(port.space_id_for(SHARED), "user-accounts")]
    assert channel.result.created == ["user-accounts"]
    assert channel.result.written == ["user-accounts"]
    assert port.content_for(SHARED, "user-accounts") == {"collection": "user-accounts"}


async def test_reuse_existing_node_never_recreated():
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"])

    await channel.sync(REPLICATOR_CTX)
    await channel.sync(REPLICATOR_CTX)

    assert len(port.create_node_calls) == 1  # only the first cycle created
    assert channel.result.created == []
    assert channel.result.written == ["user-accounts"]


async def test_clear_on_disable_keeps_the_node():
    port = FakeSpacePort()
    channel, enabled = _make_channel(port, ["user-accounts"])
    await channel.sync(REPLICATOR_CTX)
    node_id = port.node_for(SHARED, "user-accounts")["id"]

    enabled["ids"] = []
    await channel.sync(REPLICATOR_CTX)

    assert channel.result.cleared == ["user-accounts"]
    assert port.content_for(SHARED, "user-accounts") == {}
    # the node itself survives so a later re-enable reuses it
    assert port.node_for(SHARED, "user-accounts")["id"] == node_id


async def test_a_reused_channel_does_not_reclear_an_already_cleared_node():
    # The _cleared_nodes fix, baked in from the start here (TS only got it
    # after an adversarial review pass).
    port = FakeSpacePort()
    channel, enabled = _make_channel(port, ["user-accounts"])
    await channel.sync(REPLICATOR_CTX)

    enabled["ids"] = []
    await channel.sync(REPLICATOR_CTX)
    pushes_after_first_clear = len(port.pushes)

    await channel.sync(REPLICATOR_CTX)  # third cycle, still disabled

    assert len(port.pushes) == pushes_after_first_clear  # no wasted no-op CAS write


async def test_reenabling_then_disabling_again_clears_for_real():
    port = FakeSpacePort()
    channel, enabled = _make_channel(port, ["user-accounts"])
    await channel.sync(REPLICATOR_CTX)

    enabled["ids"] = []
    await channel.sync(REPLICATOR_CTX)          # clear #1

    enabled["ids"] = ["user-accounts"]
    await channel.sync(REPLICATOR_CTX)          # re-enable, writes real data
    assert port.content_for(SHARED, "user-accounts") == {"collection": "user-accounts"}

    enabled["ids"] = []
    await channel.sync(REPLICATOR_CTX)          # clear #2 must actually happen

    assert channel.result.cleared == ["user-accounts"]
    assert port.content_for(SHARED, "user-accounts") == {}


async def test_two_space_routing():
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts", "user-settings"])

    await channel.sync(REPLICATOR_CTX)

    shared_id = port.space_id_for(SHARED)
    private_id = port.space_id_for(PRIVATE)
    assert shared_id and private_id and shared_id != private_id
    assert channel.result.spaces == {SHARED: shared_id, PRIVATE: private_id}
    assert port.content_for(SHARED, "user-accounts") == {"collection": "user-accounts"}
    assert port.content_for(PRIVATE, "user-settings") == {"collection": "user-settings"}
    # each collection landed in its OWN space only
    assert port.node_for(SHARED, "user-settings") is None
    assert port.node_for(PRIVATE, "user-accounts") is None


async def test_change_detection_source_hash_skips_an_unchanged_write():
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"], change_detection="source-hash")

    await channel.sync(REPLICATOR_CTX)          # creates + writes
    pushes_after_first = len(port.pushes)
    await channel.sync(REPLICATOR_CTX)          # same data → skip

    assert channel.result.skipped == ["user-accounts"]
    assert channel.result.written == []
    assert len(port.pushes) == pushes_after_first


async def test_change_detection_none_always_writes():
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"])  # default "none"

    await channel.sync(REPLICATOR_CTX)
    await channel.sync(REPLICATOR_CTX)

    assert channel.result.skipped == []
    assert channel.result.written == ["user-accounts"]
    assert len(port.pushes) == 2


async def test_passes_the_call_context_through_to_read_source():
    port = FakeSpacePort()
    seen: list[ReplicaCallContext] = []

    async def read_source(cid, ctx):
        seen.append(ctx)
        return {"x": 1}

    channel, _ = _make_channel(port, ["user-accounts"], read_source=read_source)
    ctx = ReplicaCallContext(call_kind="classic")
    await channel.sync(ctx)

    assert seen == [ctx]
    assert seen[0].call_kind == "classic"


async def test_skips_creating_an_empty_space_that_never_existed():
    port = FakeSpacePort()
    channel, _ = _make_channel(port, [])  # nothing enabled anywhere

    await channel.sync(REPLICATOR_CTX)

    assert port.create_space_calls == []
    assert channel.result.spaces == {SHARED: None, PRIVATE: None}


# ── Additional coverage ──────────────────────────────────────────────────────


async def test_an_existing_space_is_still_resolved_so_orphans_get_cleared():
    # The other half of the "skip empty space" rule: a space that DOES exist
    # must still be visited when nothing is enabled, so its nodes get cleared.
    port = FakeSpacePort()
    channel, enabled = _make_channel(port, ["user-accounts"])
    await channel.sync(REPLICATOR_CTX)

    enabled["ids"] = []
    await channel.sync(REPLICATOR_CTX)

    assert channel.result.cleared == ["user-accounts"]
    assert channel.result.spaces[SHARED] == port.space_id_for(SHARED)


async def test_enabled_ids_is_reread_every_cycle():
    # Captured once at construction would mean a settings toggle never applies
    # without rebuilding the channel.
    port = FakeSpacePort()
    channel, enabled = _make_channel(port, ["user-accounts"])
    await channel.sync(REPLICATOR_CTX)

    enabled["ids"] = ["user-accounts", "user-data"]
    await channel.sync(REPLICATOR_CTX)

    assert sorted(channel.result.written) == ["user-accounts", "user-data"]


async def test_an_async_enabled_ids_callable_is_supported():
    port = FakeSpacePort()

    async def enabled_ids():
        await asyncio.sleep(0)
        return ["user-accounts"]

    async def read_source(cid, ctx):
        return {"c": cid}

    channel = create_space_mirror_channel(
        name="mirror",
        session=_Session(),
        collections=COLLECTIONS,
        enabled_ids=enabled_ids,
        read_source=read_source,
        doc_path=lambda s, n: f"spaces/{s}/objects/mirror/{n}",
        port=port,
    )
    await channel.sync(REPLICATOR_CTX)

    assert channel.result.written == ["user-accounts"]


async def test_unknown_enabled_ids_are_ignored():
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts", "not-a-collection"])

    await channel.sync(REPLICATOR_CTX)

    assert channel.result.written == ["user-accounts"]
    assert port.create_node_calls == [(port.space_id_for(SHARED), "user-accounts")]


async def test_node_enc_defaults_to_space_access_and_encrypted():
    # access:"space" is the deliberate default — "invite" resolves through a
    # per-node keyring that nothing in a mirror-style writer ever seeds.
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"])
    await channel.sync(REPLICATOR_CTX)

    node = port.node_for(SHARED, "user-accounts")
    assert node["access"] == "space"
    assert node["enc"] is True


async def test_node_enc_can_be_overridden():
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"], node_enc={"enc": False})
    await channel.sync(REPLICATOR_CTX)

    node = port.node_for(SHARED, "user-accounts")
    assert node["access"] == "space"   # untouched default
    assert node["enc"] is False        # overridden


async def test_doc_path_is_used_for_pull_and_push_paths():
    port = FakeSpacePort()
    captured = {}

    class PathCapturingPort(FakeSpacePort):
        async def push_node_doc(self, handle, pull_path, push_path, mutator):
            captured["pull"] = pull_path
            captured["push"] = push_path
            await FakeSpacePort.push_node_doc(self, handle, pull_path, push_path, mutator)

    port = PathCapturingPort()
    channel, _ = _make_channel(port, ["user-accounts"])
    await channel.sync(REPLICATOR_CTX)

    sid = port.space_id_for(SHARED)
    nid = port.node_for(SHARED, "user-accounts")["id"]
    assert captured["pull"] == f"/pull/spaces/{sid}/objects/mirror/{nid}"
    assert captured["push"] == f"/push/spaces/{sid}/objects/mirror/{nid}"


async def test_read_source_is_not_called_for_a_cleared_collection():
    port = FakeSpacePort()
    calls: list[str] = []

    async def read_source(cid, ctx):
        calls.append(cid)
        return {"c": cid}

    channel, enabled = _make_channel(port, ["user-accounts"], read_source=read_source)
    await channel.sync(REPLICATOR_CTX)
    calls.clear()

    enabled["ids"] = []
    await channel.sync(REPLICATOR_CTX)

    assert calls == []


async def test_none_from_read_source_is_written_as_an_empty_document():
    port = FakeSpacePort()

    async def read_source(cid, ctx):
        return None

    channel, _ = _make_channel(port, ["user-accounts"], read_source=read_source)
    await channel.sync(REPLICATOR_CTX)

    assert port.content_for(SHARED, "user-accounts") == {}


async def test_result_is_replaced_not_accumulated_across_cycles():
    port = FakeSpacePort()
    channel, enabled = _make_channel(port, ["user-accounts"])
    await channel.sync(REPLICATOR_CTX)
    assert channel.result.created == ["user-accounts"]

    await channel.sync(REPLICATOR_CTX)
    assert channel.result.created == []          # not ["user-accounts", ...]
    assert channel.result.written == ["user-accounts"]


async def test_result_before_any_sync_is_empty():
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"])
    assert channel.result.spaces == {}
    assert channel.result.written == []


async def test_source_hash_rewrites_when_the_data_actually_changes():
    port = FakeSpacePort()
    payload = {"v": 1}

    async def read_source(cid, ctx):
        return dict(payload)

    channel, _ = _make_channel(
        port, ["user-accounts"], change_detection="source-hash", read_source=read_source
    )
    await channel.sync(REPLICATOR_CTX)
    payload["v"] = 2
    await channel.sync(REPLICATOR_CTX)

    assert channel.result.written == ["user-accounts"]
    assert channel.result.skipped == []
    assert port.content_for(SHARED, "user-accounts") == {"v": 2}


async def test_source_hash_never_skips_a_freshly_created_node():
    # The skip is gated on `existing is not None` — a brand-new node must
    # always get its first write, or it would sit empty.
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"], change_detection="source-hash")
    await channel.sync(REPLICATOR_CTX)
    assert channel.result.written == ["user-accounts"]
    assert channel.result.skipped == []


async def test_clearing_forgets_the_source_hash_so_a_reenable_rewrites():
    port = FakeSpacePort()
    channel, enabled = _make_channel(port, ["user-accounts"], change_detection="source-hash")
    await channel.sync(REPLICATOR_CTX)

    enabled["ids"] = []
    await channel.sync(REPLICATOR_CTX)          # clear drops the fingerprint

    enabled["ids"] = ["user-accounts"]
    await channel.sync(REPLICATOR_CTX)

    # Same source data as cycle 1, but the node was cleared in between — a
    # stale fingerprint would skip the write and leave the node empty.
    assert channel.result.written == ["user-accounts"]
    assert port.content_for(SHARED, "user-accounts") == {"collection": "user-accounts"}


async def test_an_invalid_change_detection_value_is_rejected_at_construction():
    port = FakeSpacePort()
    with pytest.raises(ValueError, match="change_detection"):
        _make_channel(port, [], change_detection="sometimes")


async def test_spaces_are_synced_concurrently():
    order: list[str] = []

    class SlowPort(FakeSpacePort):
        async def create_space(self, session, name):
            order.append(f"start:{name}")
            await asyncio.sleep(0.01)
            order.append(f"end:{name}")
            return await FakeSpacePort.create_space(self, session, name)

    port = SlowPort()
    channel, _ = _make_channel(port, ["user-accounts", "user-settings"])
    await channel.sync(REPLICATOR_CTX)

    # Interleaved (both start before either ends) rather than serialized.
    assert order[0].startswith("start:")
    assert order[1].startswith("start:")


async def test_channel_name_is_exposed_for_the_scheduler():
    port = FakeSpacePort()
    channel, _ = _make_channel(port, [], name="cloud-mirror")
    assert channel.name == "cloud-mirror"


async def test_channel_satisfies_the_replica_channel_protocol():
    from starfish_replica.channel import ReplicaChannel

    port = FakeSpacePort()
    channel, _ = _make_channel(port, [])
    assert isinstance(channel, ReplicaChannel)


async def test_channel_runs_under_the_real_scheduler():
    # End-to-end through the actual seam: the scheduler drives the space
    # channel exactly like it drives an HTTP one.
    from starfish_replica.channel import ChannelSchedule, ScheduledChannel, SyncTrigger
    from starfish_replica.scheduler import ChannelScheduler

    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"], name="cloud-mirror")
    scheduler = ChannelScheduler(
        [ScheduledChannel(channel=channel, schedule=ChannelSchedule(triggers=[SyncTrigger.ON_PULL]))]
    )

    await scheduler.sync_now("cloud-mirror")

    assert channel.result.written == ["user-accounts"]
    assert port.content_for(SHARED, "user-accounts") == {"collection": "user-accounts"}


async def test_a_node_nested_in_the_tree_is_found_not_duplicated():
    # Guards the flatten in port.read_object_tree: Python's real
    # read_object_tree nests children, so an un-flattened tree would hide this
    # node from the planner and the channel would create a second one.
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"])
    await channel.sync(REPLICATOR_CTX)

    sid = port.space_id_for(SHARED)
    existing = port.nodes[sid].pop()
    port.nodes[sid].append({"id": "parent", "type": "unrelated", "children": [existing]})

    class FlatteningPort(FakeSpacePort):
        async def read_object_tree(self, session, space_id):
            from starfish_replica.space.port import flatten_object_tree

            return flatten_object_tree(self.nodes.get(space_id, []))

    port.__class__ = FlatteningPort
    await channel.sync(REPLICATOR_CTX)

    assert len(port.create_node_calls) == 1  # reused the nested node, no duplicate
