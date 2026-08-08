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
        self.create_node_inputs: list[dict] = []     # the full create_node input
        self.set_access_calls: list[tuple[str, str, dict]] = []
        self.pushes: list[tuple[str, str, object]] = []  # (space_id, node_id, payload)
        self.node_access_calls: list[tuple[str, str]] = []
        self.node_access_nodes: list[object] = []    # the `node` axes each call got
        self.isolated_access_calls: list[tuple[str, str]] = []
        self.push_nodes: list[object] = []           # ditto, for push_node_doc
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
        self.create_node_inputs.append(dict(inp))
        self._seq += 1
        # Stored the way starfish_spaces' node creation really stores it: the
        # object index OMITS `access` when it is the default "space" and omits
        # `enc` when false. The channel reads these back to detect a tier flip,
        # so a fake that kept them verbatim would hide the "absent means
        # default" normalization the real index forces.
        node = {"id": f"nd-{self._seq}", "type": inp["type"], "children": []}
        if inp.get("access") and inp["access"] != "space":
            node["access"] = inp["access"]
        if inp.get("enc"):
            node["enc"] = True
        self.nodes.setdefault(space_id, []).append(node)
        return node

    async def set_node_access(self, session, space_id, node_id, patch):
        # Patched the way the real index patches — and, crucially, with the
        # SAME normalization create_node applies above: `access` dropped when
        # it is "space", `enc` dropped when false. A fake that stored the patch
        # verbatim would make a patched node distinguishable from one created
        # at that tier, and the next cycle's stored-vs-configured comparison
        # would read the difference as a fresh flip.
        self.set_access_calls.append((space_id, node_id, dict(patch)))
        node = next(
            (n for n in self.nodes.get(space_id, []) if n["id"] == node_id), None
        )
        if node is None:
            return
        if "access" in patch:
            if patch["access"] == "space":
                node.pop("access", None)
            else:
                node["access"] = patch["access"]
        if "enc" in patch:
            if patch["enc"]:
                node["enc"] = True
            else:
                node.pop("enc", None)

    async def get_node_access(self, session, space_id, node_id, node=None):
        self.node_access_calls.append((space_id, node_id))
        self.node_access_nodes.append(node)
        return _FakeHandle(space_id, node_id)

    async def get_isolated_node_access(self, session, space_id, node_id):
        self.isolated_access_calls.append((space_id, node_id))
        # The real port ensures the per-node keyring exists then opens it — a
        # DIFFERENT encryptor from the space one, which is the whole point.
        return _FakeHandle(space_id, node_id, encryptor=f"node-keyring:{node_id}")

    async def push_node_doc(self, handle, pull_path, push_path, mutator, node=None):
        self.push_nodes.append(node)
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

    def create_input_for(self, type_):
        """The axes/title create_node was CALLED with — as opposed to what the
        index then stored, which drops the defaults."""
        return next((i for i in self.create_node_inputs if i["type"] == type_), None)

    def content_for(self, space_name, type_):
        sid = self.space_id_for(space_name)
        node = self.node_for(space_name, type_)
        return self.content.get(f"{sid}:{node['id']}") if node else None


class _FakeHandle:
    def __init__(self, space_id, node_id, encryptor=None):
        self.space_id = space_id
        self.node_id = node_id
        self.client = None
        self.encryptor = encryptor
        self.is_owner_open = False


class _Session:
    user_id = "user-1"


COLLECTIONS = [
    SpaceMirrorCollection(id="user-accounts", space_name=SHARED),
    SpaceMirrorCollection(id="user-data", space_name=SHARED),
    SpaceMirrorCollection(id="user-settings", space_name=PRIVATE),
]


def _make_channel(port, enabled, *, collections=None, change_detection="none",
                  read_source=None, node_enc=None, name="mirror", title=None,
                  doc_path=None):
    enabled_box = {"ids": list(enabled)}

    async def default_read_source(cid, ctx):
        return {"collection": cid}

    channel = create_space_mirror_channel(
        name=name,
        session=_Session(),
        collections=collections if collections is not None else COLLECTIONS,
        enabled_ids=lambda: list(enabled_box["ids"]),
        read_source=read_source or default_read_source,
        doc_path=doc_path
        or (lambda cid, space_id, node_id: f"spaces/{space_id}/objects/mirror/{node_id}"),
        title=title,
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
        doc_path=lambda c, s, n: f"spaces/{s}/objects/mirror/{n}",
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

    created = port.create_input_for("user-accounts")
    assert created["access"] == "space"
    assert created["enc"] is True
    # ...and the index stores neither, because both ARE its defaults.
    node = port.node_for(SHARED, "user-accounts")
    assert "access" not in node
    assert node["enc"] is True


async def test_node_enc_can_be_overridden():
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"], node_enc={"enc": False})
    await channel.sync(REPLICATOR_CTX)

    created = port.create_input_for("user-accounts")
    assert created["access"] == "space"   # untouched default
    assert created["enc"] is False        # overridden


async def test_the_node_axes_are_forwarded_to_the_access_resolver():
    # THE regression. get_node_access cannot tell a plaintext node from an
    # encrypted one without these axes, and resolves an encryptor for both
    # (Tier 5 falls back to the space keyring, which exists in any space holding
    # one encrypted node). push_node_doc then seals on `encryptor is not None`,
    # so an unforwarded `node` writes ciphertext into a collection the server
    # declares encryption="none". TS has always passed this; Python did not.
    port = FakeSpacePort()
    channel, _ = _make_channel(
        port, ["user-accounts"], node_enc={"access": "public", "enc": False}
    )
    await channel.sync(REPLICATOR_CTX)

    assert port.node_access_nodes == [{"access": "public", "enc": False}]
    assert port.push_nodes == [{"access": "public", "enc": False}]


async def test_the_node_axes_are_forwarded_on_the_clear_path_too():
    # Clearing writes a document just like a normal write does, so it needs the
    # same axes — otherwise disabling a public collection is what seals it.
    port = FakeSpacePort()
    channel, enabled = _make_channel(
        port, ["user-accounts"], node_enc={"access": "public", "enc": False}
    )
    await channel.sync(REPLICATOR_CTX)
    port.node_access_nodes.clear()
    port.push_nodes.clear()

    enabled["ids"] = []
    await channel.sync(REPLICATOR_CTX)

    assert port.node_access_nodes == [{"access": "public", "enc": False}]
    assert port.push_nodes == [{"access": "public", "enc": False}]


async def test_the_default_encrypted_axes_are_forwarded_unchanged():
    # The control: forwarding must carry the real default through, not a
    # hardcoded plaintext stand-in that would disable encryption everywhere.
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"])
    await channel.sync(REPLICATOR_CTX)

    assert port.node_access_nodes == [{"access": "space", "enc": True}]
    assert port.push_nodes == [{"access": "space", "enc": True}]


async def test_doc_path_is_used_for_pull_and_push_paths():
    port = FakeSpacePort()
    captured = {}

    class PathCapturingPort(FakeSpacePort):
        async def push_node_doc(self, handle, pull_path, push_path, mutator, node=None):
            captured["pull"] = pull_path
            captured["push"] = push_path
            await FakeSpacePort.push_node_doc(
                self, handle, pull_path, push_path, mutator, node
            )

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


# ── Per-collection / per-space failure isolation ─────────────────────────────


class _Boom(RuntimeError):
    """Stands in for a 413 on an oversized document, a CAS conflict that
    outlived run_cas's retries, or a transient network error."""


async def _sync_expecting_failure(channel):
    """Run a cycle expected to have failures; hand back the raised group.

    Isolation does NOT mean silence. The cycle runs to completion and `result`
    is fully populated, but sync() still raises so ChannelScheduler's on_error
    funnel sees it — exactly like TS rejecting with an AggregateError. Every
    test below goes through here, so if sync() ever stopped raising they would
    all error out rather than quietly passing.
    """
    with pytest.raises(ExceptionGroup) as excinfo:
        await channel.sync(REPLICATOR_CTX)
    return excinfo.value


async def test_one_collections_write_failure_does_not_stop_the_others():
    # THE bug: a sequential write loop with no error handling meant one bad
    # collection took every other collection in the space down with it.
    class FailOnePort(FakeSpacePort):
        async def push_node_doc(self, handle, pull_path, push_path, mutator, node=None):
            node_obj = next(
                (n for ns in self.nodes.values() for n in ns if n["id"] == handle.node_id),
                None,
            )
            if node_obj and node_obj["type"] == "user-accounts":
                raise _Boom("413 payload too large")
            await FakeSpacePort.push_node_doc(
                self, handle, pull_path, push_path, mutator, node
            )

    port = FailOnePort()
    channel, _ = _make_channel(port, ["user-accounts", "user-data"])

    await _sync_expecting_failure(channel)

    assert channel.result.failed == ["user-accounts"]
    assert channel.result.written == ["user-data"]          # the survivor still wrote
    assert port.content_for(SHARED, "user-data") == {"collection": "user-data"}
    assert port.content_for(SHARED, "user-accounts") is None


async def test_a_read_source_failure_is_isolated_the_same_way():
    # The failure can come from the caller's own callback, not just the port.
    port = FakeSpacePort()

    async def read_source(cid, ctx):
        if cid == "user-accounts":
            raise _Boom("source unavailable")
        return {"collection": cid}

    channel, _ = _make_channel(
        port, ["user-accounts", "user-data"], read_source=read_source
    )

    await _sync_expecting_failure(channel)

    assert channel.result.failed == ["user-accounts"]
    assert channel.result.written == ["user-data"]


async def test_one_space_failing_leaves_the_other_spaces_results_intact():
    # asyncio.gather without return_exceptions aborted the whole cycle, so the
    # healthy space's writes were thrown away too.
    class FailOneSpacePort(FakeSpacePort):
        async def read_object_tree(self, session, space_id):
            if space_id == self.space_id_for(SHARED):
                raise _Boom("tree read failed")
            return await FakeSpacePort.read_object_tree(self, session, space_id)

    port = FailOneSpacePort()
    channel, _ = _make_channel(port, ["user-accounts", "user-settings"])

    await _sync_expecting_failure(channel)

    # The healthy space ran to completion.
    assert channel.result.written == ["user-settings"]
    assert channel.result.spaces[PRIVATE] == port.space_id_for(PRIVATE)
    assert port.content_for(PRIVATE, "user-settings") == {"collection": "user-settings"}
    # The broken one reports every id routed to it — none of them could run.
    assert channel.result.spaces[SHARED] is None
    assert sorted(channel.result.failed) == ["user-accounts", "user-data"]


async def test_a_collection_whose_node_create_fails_is_not_reported_as_created():
    # `created` used to come straight from plan.to_create — what SHOULD be
    # created, not what was. A create that raised therefore put the same id in
    # both `created` and `failed`, and a caller reconciling the two could not
    # tell whether the node exists.
    class FailOneCreatePort(FakeSpacePort):
        async def create_node(self, session, space_id, inp):
            if inp["type"] == "user-data":
                raise _Boom("node create rejected")
            return await FakeSpacePort.create_node(self, session, space_id, inp)

    port = FailOneCreatePort()
    channel, _ = _make_channel(port, ["user-accounts", "user-data"])

    await _sync_expecting_failure(channel)

    assert channel.result.failed == ["user-data"]
    assert channel.result.created == ["user-accounts"]      # NOT both
    assert channel.result.written == ["user-accounts"]


async def test_a_failing_clear_is_isolated_from_the_other_clears():
    port = FakeSpacePort()
    channel, enabled = _make_channel(port, ["user-accounts", "user-data"])
    await channel.sync(REPLICATOR_CTX)

    failing_node_id = port.node_for(SHARED, "user-accounts")["id"]

    class FailOneClearPort(FakeSpacePort):
        async def push_node_doc(self, handle, pull_path, push_path, mutator, node=None):
            if handle.node_id == failing_node_id:
                raise _Boom("clear rejected")
            await FakeSpacePort.push_node_doc(
                self, handle, pull_path, push_path, mutator, node
            )

    port.__class__ = FailOneClearPort
    enabled["ids"] = []
    await _sync_expecting_failure(channel)

    assert channel.result.failed == ["user-accounts"]
    assert channel.result.cleared == ["user-data"]
    assert port.content_for(SHARED, "user-data") == {}
    # Not marked cleared, so a later cycle retries it instead of skipping.
    assert port.content_for(SHARED, "user-accounts") == {"collection": "user-accounts"}


async def test_a_failed_clear_is_retried_on_the_next_cycle():
    # The _cleared_nodes short-circuit must not remember a clear that never
    # actually landed.
    port = FakeSpacePort()
    channel, enabled = _make_channel(port, ["user-accounts"])
    await channel.sync(REPLICATOR_CTX)

    fail = {"on": True}

    class FlakyClearPort(FakeSpacePort):
        async def push_node_doc(self, handle, pull_path, push_path, mutator, node=None):
            if fail["on"]:
                raise _Boom("clear rejected")
            await FakeSpacePort.push_node_doc(
                self, handle, pull_path, push_path, mutator, node
            )

    port.__class__ = FlakyClearPort
    enabled["ids"] = []
    await _sync_expecting_failure(channel)
    assert channel.result.failed == ["user-accounts"]

    fail["on"] = False
    await channel.sync(REPLICATOR_CTX)          # recovers, so no raise this time

    assert channel.result.failed == []
    assert channel.result.cleared == ["user-accounts"]
    assert port.content_for(SHARED, "user-accounts") == {}


async def test_the_happy_path_reports_no_failures():
    # The control: `failed` must not fill up on a clean cycle.
    port = FakeSpacePort()
    channel, enabled = _make_channel(port, ["user-accounts", "user-settings"])
    await channel.sync(REPLICATOR_CTX)
    assert channel.result.failed == []

    enabled["ids"] = []
    await channel.sync(REPLICATOR_CTX)          # clears, also clean
    assert channel.result.failed == []


async def test_result_is_replaced_not_stale_after_a_failing_cycle():
    # `self._result` used to be assigned only at the very end of sync(), so a
    # raised cycle left the PREVIOUS cycle's result in place and a caller read
    # last cycle's successes as if they were this cycle's.
    fail = {"on": False}

    class FlakyPort(FakeSpacePort):
        async def read_object_tree(self, session, space_id):
            if fail["on"]:
                raise _Boom("tree read failed")
            return await FakeSpacePort.read_object_tree(self, session, space_id)

    port = FlakyPort()
    channel, _ = _make_channel(port, ["user-accounts"])
    await channel.sync(REPLICATOR_CTX)
    assert channel.result.written == ["user-accounts"]

    fail["on"] = True
    await _sync_expecting_failure(channel)

    # `result` is assigned BEFORE the raise, so a caller catching the group can
    # still see exactly what did and did not get through this cycle.
    assert channel.result.written == []                     # not the stale success
    assert channel.result.failed == ["user-accounts", "user-data"]
    assert channel.result.spaces[SHARED] is None


async def test_the_original_exceptions_are_carried_out_in_the_group():
    # Counting an id in `failed` is not enough to debug it — the real exception,
    # with its traceback, has to reach the caller. Isolation must not degrade
    # into swallowing.
    port = FakeSpacePort()

    async def read_source(cid, ctx):
        raise _Boom(f"source unavailable: {cid}")

    channel, _ = _make_channel(port, ["user-accounts", "user-data"], read_source=read_source)

    group = await _sync_expecting_failure(channel)

    assert channel.result.failed == ["user-accounts", "user-data"]
    # One entry per failed collection, and they are the ACTUAL raised objects,
    # not stringified copies.
    assert len(group.exceptions) == 2
    assert all(isinstance(e, _Boom) for e in group.exceptions)
    assert {str(e) for e in group.exceptions} == {
        "source unavailable: user-accounts",
        "source unavailable: user-data",
    }
    # The summary message names what failed, so an on_error handler that only
    # logs `str(exc)` is still useful.
    assert "user-accounts" in str(group) and "user-data" in str(group)


async def test_a_failing_channel_reaches_the_schedulers_on_error_funnel():
    # THE reason sync() raises rather than logging: ChannelScheduler._sync_safe
    # routes a raised sync to on_error, which a caller can replace. A channel
    # that logged instead would be invisible to a custom handler, and would be
    # the only channel in the package reporting failure differently from
    # HttpReplicaChannel.
    from starfish_replica.channel import ChannelSchedule, ScheduledChannel, SyncTrigger
    from starfish_replica.scheduler import ChannelScheduler

    port = FakeSpacePort()

    async def read_source(cid, ctx):
        raise _Boom("source unavailable")

    channel, _ = _make_channel(port, ["user-accounts"], read_source=read_source)

    seen: list[tuple[str, Exception]] = []
    sched = ChannelScheduler(
        [ScheduledChannel(channel=channel, schedule=ChannelSchedule(triggers=[SyncTrigger.ON_PULL]))],
        on_error=lambda name, exc: seen.append((name, exc)),
    )

    await sched.on_pull("mirror")

    assert len(seen) == 1
    assert seen[0][0] == "mirror"
    assert isinstance(seen[0][1], ExceptionGroup)
    # And the result is still readable despite the raise.
    assert channel.result.failed == ["user-accounts"]


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


# ── Per-collection storage tiers ─────────────────────────────────────────────

PRIVATE_AXES = {"access": "space", "enc": True}
PUBLIC_AXES = {"access": "public", "enc": False}
ISOLATED_AXES = {"access": "invite", "enc": True}

# A node_enc override for the private tier that is NOT any tier's reserved
# pair — so a test can prove "the override is honoured" without also tripping
# the isolated tier's invite+enc routing.
CUSTOM_PRIVATE_AXES = {"access": "owner", "enc": True}

# One public and one private collection in the SAME space — the tier is a
# per-collection property, not a per-space or per-channel one.
MIXED_TIERS = [
    SpaceMirrorCollection(id="user-accounts", space_name=SHARED, tier="public"),
    SpaceMirrorCollection(id="user-data", space_name=SHARED),      # default: private
]

ONE_PUBLIC = [SpaceMirrorCollection(id="user-accounts", space_name=SHARED, tier="public")]
ONE_PRIVATE = [SpaceMirrorCollection(id="user-accounts", space_name=SHARED)]
ONE_ISOLATED = [
    SpaceMirrorCollection(id="user-accounts", space_name=SHARED, tier="isolated")
]


def _flip_tier(channel, cid, tier):
    """Retier a collection on a LIVE channel instance.

    ``SpaceMirrorCollection`` is a frozen dataclass captured at construction, so
    a caller genuinely retiers by rebuilding the channel — and the restart case
    below does exactly that, no internals touched. This helper exists for the
    one thing rebuilding CANNOT test: that the ``source-hash`` fingerprint is
    keyed by tier. A fresh instance has no fingerprints at all, so it could
    never skip anything, which would make that assertion vacuous. Poking the two
    maps ``__init__`` precomputes is exactly what constructing the channel with
    the new tier would have produced, minus the lost fingerprints.
    """
    channel._tier_for[cid] = tier
    channel._axes_for[cid] = channel._axes_for_tier(tier)


async def test_a_public_collection_gets_public_plaintext_axes_at_create():
    port = FakeSpacePort()
    channel, _ = _make_channel(
        port, ["user-accounts", "user-data"], collections=MIXED_TIERS
    )

    await channel.sync(REPLICATOR_CTX)

    public_created = port.create_input_for("user-accounts")
    private_created = port.create_input_for("user-data")
    assert (public_created["access"], public_created["enc"]) == ("public", False)
    # The neighbour in the same space is untouched by the other's tier.
    assert (private_created["access"], private_created["enc"]) == ("space", True)


async def test_a_public_collection_ignores_node_enc_but_a_private_one_does_not():
    # node_enc is the default for collections that did not pick a different
    # tier; "public" is a fixed pair because access="public" with enc=True is
    # a combination the server rejects.
    #
    # NB the custom value is deliberately not {"access": "invite", "enc": True}
    # — that pair is the isolated tier's, and is routed through the per-node
    # keyring wherever it appears. See CUSTOM_PRIVATE_AXES.
    port = FakeSpacePort()
    channel, _ = _make_channel(
        port,
        ["user-accounts", "user-data"],
        collections=MIXED_TIERS,
        node_enc=dict(CUSTOM_PRIVATE_AXES),
    )

    await channel.sync(REPLICATOR_CTX)

    public_created = port.create_input_for("user-accounts")
    private_created = port.create_input_for("user-data")
    assert (public_created["access"], public_created["enc"]) == ("public", False)
    assert (private_created["access"], private_created["enc"]) == ("owner", True)


async def test_the_public_tier_axes_reach_both_resolver_and_push_on_write():
    # Not the channel-wide default: the axes have to be the COLLECTION's, or
    # get_node_access hands back a space-keyring encryptor and push_node_doc
    # seals plaintext-declared content.
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"], collections=ONE_PUBLIC)

    await channel.sync(REPLICATOR_CTX)

    assert port.node_access_nodes == [PUBLIC_AXES]
    assert port.push_nodes == [PUBLIC_AXES]


async def test_the_public_tier_axes_reach_both_resolver_and_push_on_clear():
    port = FakeSpacePort()
    channel, enabled = _make_channel(port, ["user-accounts"], collections=ONE_PUBLIC)
    await channel.sync(REPLICATOR_CTX)
    port.node_access_nodes.clear()
    port.push_nodes.clear()

    enabled["ids"] = []
    await channel.sync(REPLICATOR_CTX)

    assert port.node_access_nodes == [PUBLIC_AXES]
    assert port.push_nodes == [PUBLIC_AXES]


async def test_each_collections_own_axes_are_used_within_one_space():
    # Two collections, one space, one cycle: the per-collection lookup must not
    # collapse to whichever tier was resolved first.
    port = FakeSpacePort()
    channel, _ = _make_channel(
        port, ["user-accounts", "user-data"], collections=MIXED_TIERS
    )

    await channel.sync(REPLICATOR_CTX)

    assert port.push_nodes == [PUBLIC_AXES, PRIVATE_AXES]
    assert port.node_access_nodes == [PUBLIC_AXES, PRIVATE_AXES]


async def test_doc_path_receives_the_collection_id_on_write_and_clear():
    port = FakeSpacePort()
    seen: list[tuple] = []

    def doc_path(cid, space_id, node_id):
        seen.append((cid, space_id, node_id))
        return f"{cid}/spaces/{space_id}/objects/{node_id}"

    channel, enabled = _make_channel(
        port, ["user-accounts"], collections=ONE_PRIVATE, doc_path=doc_path
    )
    await channel.sync(REPLICATOR_CTX)

    sid = port.space_id_for(SHARED)
    nid = port.node_for(SHARED, "user-accounts")["id"]
    assert seen == [("user-accounts", sid, nid), ("user-accounts", sid, nid)]  # pull+push
    seen.clear()

    enabled["ids"] = []
    await channel.sync(REPLICATOR_CTX)

    # On the clear path the id comes from the EXISTING node's type — there is no
    # enabled-collection id to read it from.
    assert seen == [("user-accounts", sid, nid), ("user-accounts", sid, nid)]


async def test_the_doc_path_collection_id_can_route_tiers_to_different_prefixes():
    port = FakeSpacePort()
    channel, _ = _make_channel(
        port,
        ["user-accounts", "user-data"],
        collections=MIXED_TIERS,
        doc_path=lambda cid, s, n: f"{cid}/{s}/{n}",
    )

    await channel.sync(REPLICATOR_CTX)

    sid = port.space_id_for(SHARED)
    pub = port.node_for(SHARED, "user-accounts")["id"]
    priv = port.node_for(SHARED, "user-data")["id"]
    assert channel._doc_push_path("user-accounts", sid, pub) == f"/push/user-accounts/{sid}/{pub}"
    assert channel._doc_pull_path("user-data", sid, priv) == f"/pull/user-data/{sid}/{priv}"


async def test_a_caller_supplied_title_reaches_create_node():
    port = FakeSpacePort()
    channel, _ = _make_channel(
        port,
        ["user-accounts"],
        collections=ONE_PRIVATE,
        title=lambda cid: f"My {cid}",
    )

    await channel.sync(REPLICATOR_CTX)

    assert port.create_node_inputs[0]["title"] == "My user-accounts"
    assert port.create_node_inputs[0]["type"] == "user-accounts"   # type is NOT the title


async def test_the_default_title_is_the_collection_id():
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"], collections=ONE_PRIVATE)

    await channel.sync(REPLICATOR_CTX)

    assert port.create_node_inputs[0]["title"] == "user-accounts"


async def test_a_tier_flip_clears_the_old_path_before_writing_the_new_one():
    # private -> public. The node keeps its id and its document path, so the
    # ONLY thing separating the old content from the new is this clear — and
    # going the other way (public -> private) without it leaves the previous
    # plaintext sitting at a world-readable URL.
    port = FakeSpacePort()
    channel, _ = _make_channel(
        port, ["user-accounts"], collections=ONE_PRIVATE, change_detection="source-hash"
    )
    await channel.sync(REPLICATOR_CTX)
    port.pushes.clear()
    port.push_nodes.clear()
    port.node_access_nodes.clear()

    _flip_tier(channel, "user-accounts", "public")
    await channel.sync(REPLICATOR_CTX)

    # Clear first, content second — in that order, in one cycle.
    assert [payload for _, _, payload in port.pushes] == [
        {},
        {"collection": "user-accounts"},
    ]
    # The clear goes through the OLD axes (the new ones resolve a different
    # handle and would not decrypt what is actually stored); the write through
    # the new ones.
    assert port.push_nodes == [PRIVATE_AXES, PUBLIC_AXES]
    assert port.node_access_nodes == [PRIVATE_AXES, PUBLIC_AXES]


async def test_a_tier_flip_is_not_skipped_by_the_source_hash_check():
    # The source data is byte-identical across the flip, so a fingerprint keyed
    # by node id alone matches and skips the one write that migrates the node.
    port = FakeSpacePort()
    channel, _ = _make_channel(
        port, ["user-accounts"], collections=ONE_PRIVATE, change_detection="source-hash"
    )
    await channel.sync(REPLICATOR_CTX)

    _flip_tier(channel, "user-accounts", "public")
    await channel.sync(REPLICATOR_CTX)

    assert channel.result.skipped == []
    assert channel.result.written == ["user-accounts"]
    assert port.content_for(SHARED, "user-accounts") == {"collection": "user-accounts"}


async def test_a_steady_tier_still_skips_an_unchanged_write():
    # The control for the two above: keying the fingerprint by tier must not
    # turn every source-hash cycle into a write.
    port = FakeSpacePort()
    channel, _ = _make_channel(
        port, ["user-accounts"], collections=ONE_PUBLIC, change_detection="source-hash"
    )
    await channel.sync(REPLICATOR_CTX)
    pushes_after_first = len(port.pushes)

    await channel.sync(REPLICATOR_CTX)

    assert channel.result.skipped == ["user-accounts"]
    assert len(port.pushes) == pushes_after_first


async def test_a_public_clear_is_never_skipped_on_a_reused_channel():
    # The private short-circuit trades a wasted no-op push against the risk of
    # not re-asserting a clear. For public data that trade is not available:
    # a missed clear leaves the content world-readable.
    port = FakeSpacePort()
    channel, enabled = _make_channel(port, ["user-accounts"], collections=ONE_PUBLIC)
    await channel.sync(REPLICATOR_CTX)

    enabled["ids"] = []
    await channel.sync(REPLICATOR_CTX)          # clear #1
    after_first_clear = len(port.pushes)

    await channel.sync(REPLICATOR_CTX)          # still disabled — clear again anyway
    await channel.sync(REPLICATOR_CTX)

    assert len(port.pushes) == after_first_clear + 2
    assert channel.result.cleared == ["user-accounts"]


async def test_a_private_clear_is_still_skipped_on_a_reused_channel():
    # The other half: dropping the short-circuit for public must not drop it
    # for private too.
    port = FakeSpacePort()
    channel, enabled = _make_channel(port, ["user-accounts"], collections=ONE_PRIVATE)
    await channel.sync(REPLICATOR_CTX)

    enabled["ids"] = []
    await channel.sync(REPLICATOR_CTX)
    after_first_clear = len(port.pushes)

    await channel.sync(REPLICATOR_CTX)

    assert len(port.pushes) == after_first_clear


# ── The isolated tier ────────────────────────────────────────────────────────


async def test_an_isolated_collection_is_created_as_an_invite_enc_node():
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"], collections=ONE_ISOLATED)

    await channel.sync(REPLICATOR_CTX)

    created = port.create_input_for("user-accounts")
    assert (created["access"], created["enc"]) == ("invite", True)


async def test_an_isolated_collection_ignores_node_enc():
    # Same rule as "public": the tier IS the access model, so a channel-wide
    # node_enc must not be able to quietly downgrade it to the space keyring.
    port = FakeSpacePort()
    channel, _ = _make_channel(
        port,
        ["user-accounts"],
        collections=ONE_ISOLATED,
        node_enc=dict(CUSTOM_PRIVATE_AXES),
    )

    await channel.sync(REPLICATOR_CTX)

    created = port.create_input_for("user-accounts")
    assert (created["access"], created["enc"]) == ("invite", True)


async def test_an_isolated_write_resolves_through_the_node_keyring_not_the_space_one():
    # The load-bearing assertion for this tier. get_node_access's owner tier
    # falls back to the SPACE keyring when a node keyring is missing, which
    # would seal isolated content under the key every space member holds.
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"], collections=ONE_ISOLATED)

    await channel.sync(REPLICATOR_CTX)

    node_id = port.node_for(SHARED, "user-accounts")["id"]
    assert port.isolated_access_calls == [(port.space_id_for(SHARED), node_id)]
    assert port.node_access_calls == []  # never the space-keyring resolver


async def test_an_isolated_clear_also_uses_the_node_keyring():
    # The clear path resolves from the node's STORED axes, so it must reach the
    # same per-node keyring the content was written under.
    port = FakeSpacePort()
    channel, enabled = _make_channel(port, ["user-accounts"], collections=ONE_ISOLATED)
    await channel.sync(REPLICATOR_CTX)
    node_id = port.node_for(SHARED, "user-accounts")["id"]

    enabled["ids"] = []
    await channel.sync(REPLICATOR_CTX)

    assert channel.result.cleared == ["user-accounts"]
    assert port.content_for(SHARED, "user-accounts") == {}
    assert port.isolated_access_calls == [
        (port.space_id_for(SHARED), node_id),
        (port.space_id_for(SHARED), node_id),
    ]
    assert port.node_access_calls == []


async def test_an_isolated_clear_is_never_short_circuited():
    # Same reasoning as public: `_cleared_nodes` is only a BELIEF about the
    # server's state, and an isolated node is readable by every holder of a
    # still-valid per-node grant — cheap to re-assert, unacceptable to skip
    # wrongly.
    port = FakeSpacePort()
    channel, enabled = _make_channel(port, ["user-accounts"], collections=ONE_ISOLATED)
    await channel.sync(REPLICATOR_CTX)

    enabled["ids"] = []
    await channel.sync(REPLICATOR_CTX)
    after_first_clear = len(port.pushes)

    await channel.sync(REPLICATOR_CTX)  # third cycle, still disabled

    assert len(port.pushes) == after_first_clear + 1


async def test_isolated_and_private_collections_coexist_in_one_space():
    # The point of the tier: one space per user, mixed sensitivities, and only
    # the isolated ones are reachable by a per-node grant.
    port = FakeSpacePort()
    collections = [
        SpaceMirrorCollection(id="user-accounts", space_name=SHARED, tier="isolated"),
        SpaceMirrorCollection(id="user-settings", space_name=SHARED),  # private
    ]
    channel, _ = _make_channel(
        port, ["user-accounts", "user-settings"], collections=collections
    )

    await channel.sync(REPLICATOR_CTX)

    assert port.create_input_for("user-accounts")["access"] == "invite"
    assert port.create_input_for("user-settings")["access"] == "space"
    # One space, two access models.
    assert len(port.create_space_calls) == 1
    isolated_node = port.node_for(SHARED, "user-accounts")["id"]
    assert port.isolated_access_calls == [(port.space_id_for(SHARED), isolated_node)]
    assert port.node_access_nodes == [PRIVATE_AXES]


async def test_a_flip_from_isolated_to_private_clears_under_the_node_keyring_first():
    # The stored axes say invite+enc, so the clear has to go through the node
    # keyring — resolving the new (space) axes would not decrypt what is
    # actually sitting there.
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"], collections=ONE_ISOLATED)
    await channel.sync(REPLICATOR_CTX)
    node_id = port.node_for(SHARED, "user-accounts")["id"]
    isolated_calls_after_write = len(port.isolated_access_calls)

    _flip_tier(channel, "user-accounts", "private")
    await channel.sync(REPLICATOR_CTX)

    # The migrating clear used the node keyring...
    assert len(port.isolated_access_calls) == isolated_calls_after_write + 1
    # ...and the new content went through the space resolver.
    assert port.node_access_nodes == [PRIVATE_AXES]
    # Stored axes patched to the new tier so the flip is self-limiting.
    assert port.set_access_calls == [
        (port.space_id_for(SHARED), node_id, PRIVATE_AXES)
    ]
    assert "access" not in port.node_for(SHARED, "user-accounts")


async def test_a_flip_from_private_to_isolated_migrates_onto_the_node_keyring():
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"], collections=ONE_PRIVATE)
    await channel.sync(REPLICATOR_CTX)
    node_id = port.node_for(SHARED, "user-accounts")["id"]

    _flip_tier(channel, "user-accounts", "isolated")
    await channel.sync(REPLICATOR_CTX)

    # Cleared under the STORED (space) axes, then written under the node keyring.
    assert port.node_access_nodes == [PRIVATE_AXES, PRIVATE_AXES]
    assert port.isolated_access_calls == [(port.space_id_for(SHARED), node_id)]
    assert port.set_access_calls == [
        (port.space_id_for(SHARED), node_id, ISOLATED_AXES)
    ]
    assert port.node_for(SHARED, "user-accounts")["access"] == "invite"


async def test_an_invalid_tier_is_rejected_at_construction():
    with pytest.raises(ValueError, match="tier"):
        SpaceMirrorCollection(id="user-accounts", space_name=SHARED, tier="secret")


async def test_the_tier_defaults_to_private():
    assert SpaceMirrorCollection(id="user-accounts", space_name=SHARED).tier == "private"


async def test_an_explicit_private_tier_resolves_to_node_enc_exactly_like_an_omitted_one():
    # `tier` DEFAULTS to "private", so spelling it out and leaving it off have
    # to be the same thing. Resolving an explicit "private" to a hardcoded
    # {"access": "space", "enc": True} would silently throw away a caller's
    # node_enc override — and only for the collections that documented their
    # tier, which is the opposite of what writing it down should do.
    port = FakeSpacePort()
    collections = [
        SpaceMirrorCollection(id="user-accounts", space_name=SHARED, tier="private"),
        SpaceMirrorCollection(id="user-data", space_name=SHARED),  # tier omitted
        SpaceMirrorCollection(id="user-settings", space_name=SHARED, tier="public"),
    ]
    custom = dict(CUSTOM_PRIVATE_AXES)
    channel, _ = _make_channel(
        port,
        ["user-accounts", "user-data", "user-settings"],
        collections=collections,
        node_enc=dict(custom),
    )

    await channel.sync(REPLICATOR_CTX)

    explicit = port.create_input_for("user-accounts")
    omitted = port.create_input_for("user-data")
    assert (explicit["access"], explicit["enc"]) == ("owner", True)
    assert (explicit["access"], explicit["enc"]) == (omitted["access"], omitted["enc"])
    # "public" is the ONE tier that overrides node_enc — it has to, since
    # access="public" with enc=True is what the server refuses.
    published = port.create_input_for("user-settings")
    assert (published["access"], published["enc"]) == ("public", False)

    # Same on the write path, not just at create.
    assert port.push_nodes == [custom, custom, PUBLIC_AXES]
    assert port.node_access_nodes == [custom, custom, PUBLIC_AXES]


async def test_a_tier_flip_is_detected_after_a_restart_by_a_fresh_channel():
    # The flip that actually matters. A user toggles a collection off "public"
    # in settings and the app restarts (or the caller builds a channel per
    # call): the new instance has no memory of ever writing this node, so a
    # flip detected from in-memory state finds nothing, skips the clear, and
    # leaves the published plaintext readable at its world-readable URL
    # indefinitely. The node's STORED axes still say "public", and they are
    # what drives the clear here.
    port = FakeSpacePort()
    before_restart, _ = _make_channel(port, ["user-accounts"], collections=ONE_PUBLIC)
    await before_restart.sync(REPLICATOR_CTX)
    node_id = port.node_for(SHARED, "user-accounts")["id"]
    port.pushes.clear()
    port.push_nodes.clear()
    port.node_access_nodes.clear()

    after_restart, _ = _make_channel(port, ["user-accounts"], collections=ONE_PRIVATE)
    await after_restart.sync(REPLICATOR_CTX)

    assert after_restart.result.created == []  # the same node, reused
    assert after_restart.result.written == ["user-accounts"]
    # Old public copy emptied FIRST, then the private content written.
    assert [(nid, payload) for _, nid, payload in port.pushes] == [
        (node_id, {}),
        (node_id, {"collection": "user-accounts"}),
    ]
    # The clear goes out under the PUBLIC axes that actually reach the stored
    # copy; only the write uses the collection's new private axes.
    assert port.push_nodes == [PUBLIC_AXES, PRIVATE_AXES]
    assert port.node_access_nodes == [PUBLIC_AXES, PRIVATE_AXES]


async def test_a_node_stored_without_access_or_enc_reads_as_a_plaintext_space_node():
    # The object index omits `access` when it is "space" and `enc` when false,
    # so a plaintext space node is stored with both fields simply absent.
    # Reading that back as "unknown" rather than "the defaults" would make
    # every such node look permanently flipped and re-clear it every cycle.
    plaintext = {"access": "space", "enc": False}
    port = FakeSpacePort()
    channel, _ = _make_channel(
        port, ["user-accounts"], collections=ONE_PRIVATE, node_enc={"enc": False}
    )
    await channel.sync(REPLICATOR_CTX)
    node = port.node_for(SHARED, "user-accounts")
    assert "access" not in node and "enc" not in node

    await channel.sync(REPLICATOR_CTX)  # the second cycle SEES the stored node

    # One plain write per cycle. A misread would have prepended a clear to the
    # second.
    assert len(port.pushes) == 2
    assert port.push_nodes == [plaintext, plaintext]


# ── The stored axes are patched after a flip ─────────────────────────────────


async def test_a_public_to_private_flip_patches_the_stored_axes_to_private():
    # The reason this matters is not bookkeeping. Infra's public-objects
    # projection extracts every node whose STORED `access` is "public" out of an
    # objindex write and upserts {id, title, type, updatedAt} into a
    # world-readable index keyed by spaceId. Clearing the CONTENT on the flip
    # (which the channel already did) leaves that entry standing: the node keeps
    # advertising its id, title and type to anonymous callers forever, directly
    # contradicting the setting the user just changed.
    port = FakeSpacePort()
    as_public, _ = _make_channel(port, ["user-accounts"], collections=ONE_PUBLIC)
    await as_public.sync(REPLICATOR_CTX)
    assert port.node_for(SHARED, "user-accounts")["access"] == "public"

    as_private, _ = _make_channel(port, ["user-accounts"], collections=ONE_PRIVATE)
    await as_private.sync(REPLICATOR_CTX)

    # Indistinguishable from a node BORN private: the index omits `access` when
    # it is "space", so the projection's access == "public" filter cannot match
    # it any more.
    node = port.node_for(SHARED, "user-accounts")
    assert "access" not in node
    assert node["enc"] is True


async def test_a_private_to_public_flip_patches_the_stored_axes_to_public():
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"], collections=ONE_PRIVATE)
    await channel.sync(REPLICATOR_CTX)
    assert "access" not in port.node_for(SHARED, "user-accounts")

    _flip_tier(channel, "user-accounts", "public")
    await channel.sync(REPLICATOR_CTX)

    node = port.node_for(SHARED, "user-accounts")
    assert node["access"] == "public"
    # `enc` DROPPED, not stored as False — the same normalization create_node
    # applies, so this node is indistinguishable from one born public.
    assert "enc" not in node


async def test_a_tier_flip_is_self_limiting():
    # Without the stored-axes patch the object index records the OLD tier
    # forever, so every subsequent cycle re-detects the same flip and re-fires
    # the clear — unbounded, for the life of the collection. The push count is
    # the observable: a flipping cycle pushes twice (clear + write), a settled
    # one pushes once.
    port = FakeSpacePort()
    channel, _ = _make_channel(port, ["user-accounts"], collections=ONE_PRIVATE)
    await channel.sync(REPLICATOR_CTX)

    _flip_tier(channel, "user-accounts", "public")
    port.pushes.clear()
    await channel.sync(REPLICATOR_CTX)          # the flip: clear + write + patch

    assert len(port.pushes) == 2
    sid = port.space_id_for(SHARED)
    nid = port.node_for(SHARED, "user-accounts")["id"]
    assert port.set_access_calls == [(sid, nid, PUBLIC_AXES)]
    port.pushes.clear()

    await channel.sync(REPLICATOR_CTX)          # settled: write only

    assert len(port.pushes) == 1
    assert port.push_nodes[-1] == PUBLIC_AXES
    assert len(port.set_access_calls) == 1      # no re-patch


async def test_a_collection_that_flipped_once_can_skip_a_later_unchanged_cycle():
    # Impossible before the stored-axes patch: the flip re-fired every cycle,
    # and its clear dropped the node's fingerprints each time, so a flipped
    # collection could never skip again no matter how unchanged its source was.
    port = FakeSpacePort()
    channel, _ = _make_channel(
        port, ["user-accounts"], collections=ONE_PRIVATE, change_detection="source-hash"
    )
    await channel.sync(REPLICATOR_CTX)

    _flip_tier(channel, "user-accounts", "public")
    await channel.sync(REPLICATOR_CTX)          # the migrating write, never skipped
    assert channel.result.written == ["user-accounts"]
    port.pushes.clear()

    await channel.sync(REPLICATOR_CTX)

    assert channel.result.skipped == ["user-accounts"]
    assert channel.result.written == []
    assert port.pushes == []


async def test_a_failing_set_node_access_is_isolated_to_its_collection():
    boom = RuntimeError("index CAS 409")

    class FailOnePatchPort(FakeSpacePort):
        async def set_node_access(self, session, space_id, node_id, patch):
            node = next(
                (n for n in self.nodes.get(space_id, []) if n["id"] == node_id), None
            )
            if node is not None and node["type"] == "user-accounts":
                raise boom
            await FakeSpacePort.set_node_access(self, session, space_id, node_id, patch)

    port = FailOnePatchPort()
    collections = [
        SpaceMirrorCollection(id="user-accounts", space_name=SHARED),
        SpaceMirrorCollection(id="user-data", space_name=SHARED),
    ]
    channel, _ = _make_channel(
        port, ["user-accounts", "user-data"], collections=collections
    )
    await channel.sync(REPLICATOR_CTX)

    # Only "user-accounts" flips; "user-data" stays private, so its patch is
    # never attempted.
    _flip_tier(channel, "user-accounts", "public")

    with pytest.raises(ExceptionGroup) as excinfo:
        await channel.sync(REPLICATOR_CTX)

    assert channel.result.failed == ["user-accounts"]
    assert channel.result.written == ["user-data"]
    # The raised group carries the real exception, not a stringified id.
    assert boom in excinfo.value.exceptions
