"""A :class:`~starfish_replica.channel.ReplicaChannel` that mirrors an app-local
data source into per-collection nodes of one or more Starfish spaces, encrypted
under each space's own keyring.

The channel owns the space/node mechanics — space find-or-create, node
find-or-create, CAS-write, clear-on-disable, and routing across several
spaces. What stays with the caller is the collection registry (which ids
exist, which space each routes to) and the ``read_source`` callback.

Mirrors the TS package's ``space/mirror-channel.ts``, including two fixes TS
only gained after an adversarial code-review pass — built in here from the
start rather than repeated as bugs:

- ``_cleared_nodes``: a reused channel instance does not re-push a no-op CAS
  clear every cycle for a node that has stayed disabled.
- in-flight coalescing on ``find_or_create_space`` (in ``port.py``).

Content pushes go through ``SpacePort.push_node_doc``, which retries on CAS
conflict via ``starfish_spaces.cas_retry.run_cas`` (5 attempts, jittered
backoff).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, Sequence, Union

from starfish_replica.channel import ReplicaCallContext
from starfish_replica.space.plan import ExistingSpaceNode, plan_space_mirror
from starfish_replica.space.port import SpacePort, default_space_port, find_or_create_space

__all__ = [
    "SpaceMirrorCollection",
    "SpaceMirrorResult",
    "SpaceMirrorChannel",
    "create_space_mirror_channel",
]

DEFAULT_NODE_ENC: dict[str, Any] = {"access": "space", "enc": True}


@dataclass(frozen=True)
class SpaceMirrorCollection:
    """One collection this channel mirrors, and which space its node lives in."""

    id: str
    space_name: str


@dataclass
class SpaceMirrorResult:
    spaces: dict[str, Optional[str]] = field(default_factory=dict)
    """Space id per space name, or ``None`` for a space never created (nothing
    has ever been enabled for it) — not an error, just "nothing to report"."""

    created: list[str] = field(default_factory=list)
    written: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    """Ids skipped this cycle because ``change_detection="source-hash"`` found
    no change since the last write. Always empty when change detection is
    ``"none"``."""

    cleared: list[str] = field(default_factory=list)


def _fingerprint(data: Any) -> str:
    """Cheap content fingerprint for the optional source-hash skip — change
    detection, not a cryptographic digest."""
    return json.dumps(data if data is not None else None, sort_keys=True, default=str)


async def _maybe_await(value: Union[Any, Awaitable[Any]]) -> Any:
    """Accept either a sync or async callable's result, so ``enabled_ids`` can
    be a plain function or a coroutine function (TS's ``enabledIds`` is
    likewise ``() => ids | Promise<ids>``)."""
    if asyncio.iscoroutine(value) or isinstance(value, asyncio.Future):
        return await value
    return value


class SpaceMirrorChannel:
    """See :func:`create_space_mirror_channel`."""

    def __init__(
        self,
        *,
        name: str,
        session: Any,
        collections: Sequence[SpaceMirrorCollection],
        enabled_ids: Callable[[], Union[Sequence[str], Awaitable[Sequence[str]]]],
        read_source: Callable[[str, ReplicaCallContext], Awaitable[Any]],
        doc_path: Callable[[str, str], str],
        node_enc: Optional[dict[str, Any]] = None,
        change_detection: str = "none",
        port: Optional[SpacePort] = None,
    ) -> None:
        if change_detection not in ("none", "source-hash"):
            raise ValueError(
                f"change_detection must be 'none' or 'source-hash', got {change_detection!r}"
            )

        self.name = name
        self._session = session
        self._collections = list(collections)
        self._enabled_ids = enabled_ids
        self._read_source = read_source
        self._doc_path = doc_path
        self._node_enc = {**DEFAULT_NODE_ENC, **(node_enc or {})}
        self._change_detection = change_detection
        self._port: SpacePort = port or default_space_port

        self._known_ids = frozenset(c.id for c in self._collections)
        self._space_name_for = {c.id: c.space_name for c in self._collections}
        # dict.fromkeys: de-duplicate while preserving declaration order.
        self._space_names = list(dict.fromkeys(c.space_name for c in self._collections))

        # node_id -> fingerprint of the data last written to it. Only consulted
        # under change_detection="source-hash".
        self._last_written: dict[str, str] = {}
        # node_ids already cleared by a prior cycle of THIS channel instance —
        # skips a repeat no-op CAS write for a node that has stayed disabled
        # since. Per-instance, not per-space-content: a fresh channel (e.g. a
        # caller that rebuilds the channel every call instead of reusing one
        # across a scheduled loop) starts with this empty and re-clears once,
        # same as if it did not exist — the skip only helps a REUSED instance.
        self._cleared_nodes: set[str] = set()

        self._result = SpaceMirrorResult()

    @property
    def result(self) -> SpaceMirrorResult:
        """The result of the most recently completed :meth:`sync` call."""
        return self._result

    # ── path helpers ─────────────────────────────────────────────────────────

    def _doc_pull_path(self, space_id: str, node_id: str) -> str:
        return f"/pull/{self._doc_path(space_id, node_id)}"

    def _doc_push_path(self, space_id: str, node_id: str) -> str:
        return f"/push/{self._doc_path(space_id, node_id)}"

    # ── node operations ──────────────────────────────────────────────────────

    async def _find_or_create_node(
        self,
        space_id: str,
        existing: Optional[ExistingSpaceNode],
        cid: str,
    ) -> dict[str, Any]:
        if existing is not None:
            return {"id": existing.id, "type": existing.type}
        return await self._port.create_node(
            self._session,
            space_id,
            {"type": cid, "title": cid, **self._node_enc},
        )

    async def _write_node(self, space_id: str, node_id: str, data: Any) -> None:
        """CAS-write a raw (uncurated) projection into one node — no field
        allowlist, no merge: whatever ``data`` is IS the node's content after
        this call."""
        handle = await self._port.get_node_access(self._session, space_id, node_id)
        await self._port.push_node_doc(
            handle,
            self._doc_pull_path(space_id, node_id),
            self._doc_push_path(space_id, node_id),
            lambda _current: data if data is not None else {},
        )

    async def _clear_node(self, space_id: str, node_id: str) -> None:
        """Clear a disabled collection's node content — stale data must not sit
        there encrypted under the space key indefinitely once the user opts
        out."""
        handle = await self._port.get_node_access(self._session, space_id, node_id)
        await self._port.push_node_doc(
            handle,
            self._doc_pull_path(space_id, node_id),
            self._doc_push_path(space_id, node_id),
            lambda _current: {},
        )

    # ── per-space cycle ──────────────────────────────────────────────────────

    async def _sync_one_space(
        self,
        space_name: str,
        enabled_ids: Sequence[str],
        ctx: ReplicaCallContext,
    ) -> dict[str, Any]:
        # Only the collections that actually belong in THIS space.
        for_this_space = [
            cid
            for cid in enabled_ids
            if cid in self._known_ids and self._space_name_for.get(cid) == space_name
        ]

        # Don't create an empty space just to immediately clear nothing in it —
        # if nothing is currently enabled for this space AND the space was never
        # created before (nothing to clear either), skip it entirely. A space
        # that DOES already exist (e.g. every collection routed here just got
        # disabled) is still resolved below so its now-orphaned nodes get
        # cleared.
        if not for_this_space:
            spaces = await self._port.read_spaces(self._session)
            if not any(s.get("name") == space_name for s in spaces):
                return {
                    "space_id": None,
                    "created": [],
                    "written": [],
                    "skipped": [],
                    "cleared": [],
                }

        space = await find_or_create_space(self._session, space_name, self._port)
        space_id = space["id"]
        tree = await self._port.read_object_tree(self._session, space_id)
        existing_nodes = [
            ExistingSpaceNode(id=node["id"], type=node["type"])
            for node in tree
            if node.get("type") in self._known_ids
        ]

        plan = plan_space_mirror(existing_nodes, for_this_space, self._known_ids)
        existing_by_type = {n.type: n for n in existing_nodes}

        written: list[str] = []
        skipped: list[str] = []
        for cid in plan.to_write:
            existing = existing_by_type.get(cid)
            node = await self._find_or_create_node(space_id, existing, cid)
            node_id = node["id"]
            data = await self._read_source(cid, ctx)

            if self._change_detection == "source-hash" and existing is not None:
                digest = _fingerprint(data)
                if self._last_written.get(node_id) == digest:
                    skipped.append(cid)
                    continue
                await self._write_node(space_id, node_id, data)
                self._last_written[node_id] = digest
            else:
                await self._write_node(space_id, node_id, data)
                if self._change_detection == "source-hash":
                    self._last_written[node_id] = _fingerprint(data)

            # A node just written to is no longer "already cleared" — if it gets
            # disabled again later it needs a real clear, not a skip.
            self._cleared_nodes.discard(node_id)
            written.append(cid)

        for node in plan.to_clear:
            # Already cleared in a prior cycle and never re-enabled since — a
            # repeat push would be a no-op CAS write wasted every cycle this
            # channel instance is reused for (e.g. via a persistent
            # ChannelScheduler-driven loop).
            if node.id in self._cleared_nodes:
                continue
            await self._clear_node(space_id, node.id)
            self._cleared_nodes.add(node.id)
            self._last_written.pop(node.id, None)

        return {
            "space_id": space_id,
            "created": plan.to_create,
            "written": written,
            "skipped": skipped,
            "cleared": [n.type for n in plan.to_clear],
        }

    # ── ReplicaChannel ───────────────────────────────────────────────────────

    async def sync(self, ctx: ReplicaCallContext) -> None:
        enabled_ids = await _maybe_await(self._enabled_ids())

        # The spaces are independent (different id, different keyring, no
        # shared state) — run them concurrently rather than paying sequential
        # network round trips per space every cycle.
        per_space = await asyncio.gather(
            *(self._sync_one_space(name, enabled_ids, ctx) for name in self._space_names)
        )

        result = SpaceMirrorResult()
        for space_name, r in zip(self._space_names, per_space):
            result.spaces[space_name] = r["space_id"]
            result.created.extend(r["created"])
            result.written.extend(r["written"])
            result.skipped.extend(r["skipped"])
            result.cleared.extend(r["cleared"])
        self._result = result


def create_space_mirror_channel(
    *,
    name: str,
    session: Any,
    collections: Sequence[SpaceMirrorCollection],
    enabled_ids: Callable[[], Union[Sequence[str], Awaitable[Sequence[str]]]],
    read_source: Callable[[str, ReplicaCallContext], Awaitable[Any]],
    doc_path: Callable[[str, str], str],
    node_enc: Optional[dict[str, Any]] = None,
    change_detection: str = "none",
    port: Optional[SpacePort] = None,
) -> SpaceMirrorChannel:
    """Build a :class:`SpaceMirrorChannel`.

    Args:
        name: Channel name, as seen by :class:`~starfish_replica.scheduler.ChannelScheduler`.
        session: A ``starfish_spaces`` session.
        collections: The full registry this channel manages — every
            id/space-name pairing it will ever create, write, or clear a node
            for.
        enabled_ids: Read fresh on every sync (not captured once at
            construction) so a settings toggle applies on the next cycle
            without rebuilding the channel. May be sync or async.
        read_source: Pull the CURRENT raw projection for one enabled
            collection from its real source. Called once per collection being
            written, never for one being cleared. ``ctx`` is threaded through
            unchanged from :meth:`SpaceMirrorChannel.sync`.
        doc_path: Bare storage path for one collection's node content (no
            ``/pull``/``/push`` prefix — the channel adds that).
        node_enc: Node access/encryption mode. Default
            ``{"access": "space", "enc": True}`` — content gated by space
            membership, encrypted under the space's own keyring.
            ``access="invite"`` is deliberately NOT the default: it resolves
            through a per-node keyring that nothing in a mirror-style writer
            ever seeds.
        change_detection: ``"none"`` (default) writes every enabled
            collection's projection every cycle, unconditionally — matching
            the original hand-rolled writer. ``"source-hash"`` skips the write
            (for an already-existing node) when ``read_source``'s result is
            identical to what this channel last wrote.

            ONLY safe when this channel is the SOLE writer of a node — a
            source-hash skip means the channel never re-checks what is
            actually stored, so any second writer (another device, another
            process) could silently diverge from what a skip assumes is still
            there. Default ``"none"`` for that reason.
        port: Override the ``starfish_spaces`` calls (tests). Default: the
            real SDK.
    """
    return SpaceMirrorChannel(
        name=name,
        session=session,
        collections=collections,
        enabled_ids=enabled_ids,
        read_source=read_source,
        doc_path=doc_path,
        node_enc=node_enc,
        change_detection=change_detection,
        port=port,
    )
