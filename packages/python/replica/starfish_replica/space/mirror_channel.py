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

PUBLIC_NODE_ENC: dict[str, Any] = {"access": "public", "enc": False}
"""The ``tier="public"`` resolution. Deliberately NOT influenced by ``node_enc``:
``access="public"`` with ``enc=True`` is a combination the server rejects, and
the whole point of a single ``tier`` enum is that it cannot be expressed."""

TIERS = ("private", "public")


@dataclass(frozen=True)
class SpaceMirrorCollection:
    """One collection this channel mirrors, and which space its node lives in."""

    id: str
    space_name: str

    tier: str = "private"
    """Storage tier for this collection's node: ``"private"`` (the default —
    the channel's ``node_enc``, itself ``{"access": "space", "enc": True}``
    unless the caller overrode it) or ``"public"``
    (``{"access": "public", "enc": False}``, always, ignoring ``node_enc``).

    Spelling ``"private"`` out is EXACTLY equivalent to leaving the field at
    its default — an explicit ``"private"`` that ignored a caller's custom
    ``node_enc`` would make the documented default a lie.

    One enum rather than a raw ``{access, enc}`` pair per collection: the
    server rejects ``access="public"`` with ``enc=True``, and an enum makes
    that combination unrepresentable here instead of catching it late, at
    ``create_node``, once a cycle is already half-run."""

    def __post_init__(self) -> None:
        if self.tier not in TIERS:
            raise ValueError(
                f"tier must be 'private' or 'public', got {self.tier!r}"
            )


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

    failed: list[str] = field(default_factory=list)
    """Ids whose write or clear raised this cycle. The failure is isolated — the
    other collections in the same space, and every other space, still ran — so
    this is the ONLY place a caller learns a collection did not make it. A
    space-level failure (space resolve or tree read) lists every id routed to
    that space, since none of them could run."""


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
        doc_path: Callable[[str, str, str], str],
        title: Optional[Callable[[str], str]] = None,
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
        self._title = title
        self._node_enc = {**DEFAULT_NODE_ENC, **(node_enc or {})}
        self._change_detection = change_detection
        self._port: SpacePort = port or default_space_port

        self._known_ids = frozenset(c.id for c in self._collections)
        self._space_name_for = {c.id: c.space_name for c in self._collections}
        # dict.fromkeys: de-duplicate while preserving declaration order.
        self._space_names = list(dict.fromkeys(c.space_name for c in self._collections))

        # Tier resolved ONCE, here, rather than per node per cycle: every hot
        # path below is a dict lookup.
        self._tier_for = {c.id: c.tier for c in self._collections}
        self._axes_for: dict[str, dict[str, Any]] = {
            c.id: self._axes_for_tier(c.tier) for c in self._collections
        }

        # f"{node_id}:{tier}" -> fingerprint of the data last written to it.
        # Only consulted under change_detection="source-hash".
        #
        # Keyed by tier, not by node id alone: flipping a collection's tier does
        # not change what read_source returns, so a node-id-keyed fingerprint
        # would match and skip the ONE write that migrates the node onto its new
        # access axes.
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

    # ── tier helpers ─────────────────────────────────────────────────────────

    def _axes_for_tier(self, tier: str) -> dict[str, Any]:
        """The ``{"access", "enc"}`` axes one tier resolves to.

        ``"private"`` — explicit or defaulted — resolves to the channel-wide
        ``node_enc`` (default ``{"access": "space", "enc": True}``) rather than
        to a hardcoded pair, so a caller that overrode ``node_enc`` keeps that
        override. ``tier`` defaults to ``"private"``, so an explicit
        ``"private"`` MUST behave identically to an omitted one.
        """
        if tier == "public":
            return dict(PUBLIC_NODE_ENC)
        return dict(self._node_enc)

    @staticmethod
    def _stored_axes(node: ExistingSpaceNode) -> dict[str, Any]:
        """The axes a node is ACTUALLY stored under, normalized.

        ``starfish_spaces``' node creation omits ``access`` when it is
        ``"space"`` and ``enc`` when false, so an absent field is the default,
        not a gap — normalizing here is what makes a stored-vs-configured
        comparison meaningful instead of "everything looks flipped".
        """
        return {"access": node.access or "space", "enc": node.enc is True}

    @staticmethod
    def _same_axes(a: dict[str, Any], b: dict[str, Any]) -> bool:
        """Compare the two axes only — a caller's ``node_enc`` may legitimately
        carry extra keys, and those are not what a tier flip is about."""
        return a.get("access") == b.get("access") and bool(a.get("enc")) == bool(b.get("enc"))

    def _forget_fingerprints(self, node_id: str) -> None:
        """Drop every tier's fingerprint for one node.

        Used wherever the node's stored content stops matching what any
        fingerprint claims — a clear, or a tier flip's clear. Popping only the
        tier just written would leave the OTHER tier's stale fingerprint to skip
        a later write back to it.
        """
        for tier in TIERS:
            self._last_written.pop(f"{node_id}:{tier}", None)

    # ── path helpers ─────────────────────────────────────────────────────────

    def _doc_pull_path(self, cid: str, space_id: str, node_id: str) -> str:
        return f"/pull/{self._doc_path(cid, space_id, node_id)}"

    def _doc_push_path(self, cid: str, space_id: str, node_id: str) -> str:
        return f"/push/{self._doc_path(cid, space_id, node_id)}"

    # ── node operations ──────────────────────────────────────────────────────

    async def _find_or_create_node(
        self,
        space_id: str,
        existing: Optional[ExistingSpaceNode],
        cid: str,
        axes: dict[str, Any],
    ) -> dict[str, Any]:
        if existing is not None:
            return {"id": existing.id, "type": existing.type}
        return await self._port.create_node(
            self._session,
            space_id,
            {
                "type": cid,
                "title": self._title(cid) if self._title is not None else cid,
                **axes,
            },
        )

    async def _write_node(
        self, cid: str, space_id: str, node_id: str, data: Any, axes: dict[str, Any]
    ) -> None:
        """CAS-write a raw (uncurated) projection into one node — no field
        allowlist, no merge: whatever ``data`` is IS the node's content after
        this call.

        ``axes`` is this COLLECTION's resolved tier, not the channel-wide
        default: get_node_access needs it to decide whether to resolve an
        encryptor at all, and push_node_doc needs it to refuse writing
        ciphertext into a collection the server declares ``encryption="none"``.
        """
        handle = await self._port.get_node_access(
            self._session, space_id, node_id, axes
        )
        await self._port.push_node_doc(
            handle,
            self._doc_pull_path(cid, space_id, node_id),
            self._doc_push_path(cid, space_id, node_id),
            lambda _current: data if data is not None else {},
            axes,
        )

    async def _clear_node(
        self, cid: str, space_id: str, node_id: str, axes: dict[str, Any]
    ) -> None:
        """Clear a disabled collection's node content — stale data must not sit
        there encrypted under the space key indefinitely once the user opts
        out, and must REALLY not sit there in plaintext at a public URL."""
        handle = await self._port.get_node_access(
            self._session, space_id, node_id, axes
        )
        await self._port.push_node_doc(
            handle,
            self._doc_pull_path(cid, space_id, node_id),
            self._doc_push_path(cid, space_id, node_id),
            lambda _current: {},
            axes,
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
                    "failed": [],
                    "errors": [],
                }

        space = await find_or_create_space(self._session, space_name, self._port)
        space_id = space["id"]
        tree = await self._port.read_object_tree(self._session, space_id)
        # access/enc are carried through, not narrowed away: they are the node's
        # STORED tier evidence, and the only kind that survives this channel
        # being rebuilt (an app restart, a caller that constructs a fresh
        # channel per call). Without them a flip made while this instance did
        # not exist is invisible.
        existing_nodes = [
            ExistingSpaceNode(
                id=node["id"],
                type=node["type"],
                access=node.get("access"),
                enc=node.get("enc"),
            )
            for node in tree
            if node.get("type") in self._known_ids
        ]

        plan = plan_space_mirror(existing_nodes, for_this_space, self._known_ids)
        existing_by_type = {n.type: n for n in existing_nodes}

        written: list[str] = []
        skipped: list[str] = []
        cleared: list[str] = []
        failed: list[str] = []
        # Accumulated from what _find_or_create_node ACTUALLY created, not from
        # plan.to_create — the plan says what should be created, and a create
        # that raises must not be reported as though it had happened. Otherwise
        # the same id lands in both `created` and `failed`, which is worse than
        # either alone: a caller reconciling the two cannot tell whether the
        # node exists.
        created: list[str] = []
        # The real exceptions behind `failed`, carried out so sync() can re-raise
        # them as one group. Mirrors TS's `errors: unknown[]`.
        errors: list[Exception] = []
        for cid in plan.to_write:
            # One collection is one independent unit of work: an oversized
            # document (413), a CAS conflict that outlived run_cas's retries, or
            # a blip on this one node must not cost the OTHER collections in
            # this space their write. Record and move on.
            try:
                tier = self._tier_for[cid]
                axes = self._axes_for[cid]
                existing = existing_by_type.get(cid)
                node = await self._find_or_create_node(space_id, existing, cid, axes)
                node_id = node["id"]
                if existing is None:
                    created.append(cid)
                # Set when this cycle migrated the node between tiers, so the
                # STORED axes can be patched to match once the new content is
                # safely written.
                flipped = False

                # Tier flip, detected from what is STORED rather than from what
                # this instance remembers writing. The realistic flip is a user
                # toggling a collection in settings and the app restarting or
                # rebuilding the channel — at which point an in-memory "last
                # tier I wrote" map is empty and reports no flip at all,
                # leaving a public -> private collection's old plaintext at its
                # world-readable URL indefinitely. That is the exact hazard
                # this clear exists to prevent.
                #
                # Cleared FIRST, under the STORED axes: the new ones resolve a
                # different handle, which does not reach (or decrypt) what is
                # actually sitting there.
                if existing is not None:
                    stored = self._stored_axes(existing)
                    if not self._same_axes(stored, axes):
                        await self._clear_node(cid, space_id, node_id, stored)
                        self._forget_fingerprints(node_id)
                        flipped = True

                data = await self._read_source(cid, ctx)
                key = f"{node_id}:{tier}"

                if self._change_detection == "source-hash" and existing is not None:
                    digest = _fingerprint(data)
                    if self._last_written.get(key) == digest:
                        skipped.append(cid)
                        continue
                    await self._write_node(cid, space_id, node_id, data, axes)
                    self._last_written[key] = digest
                else:
                    await self._write_node(cid, space_id, node_id, data, axes)
                    if self._change_detection == "source-hash":
                        self._last_written[key] = _fingerprint(data)

                # The flip is only finished once the INDEX agrees with the
                # content. Strictly AFTER the write, never before: patching
                # first would leave the index claiming a tier the stored
                # content does not match if the write then failed. Two things
                # go wrong without this:
                #
                # 1. Privacy. Infra's public-objects projection extracts every
                #    node whose stored `access` is "public" out of an objindex
                #    write and upserts {id, title, type, updatedAt} into a
                #    world-readable index. A collection flipped public ->
                #    private has its CONTENT cleared, but its node keeps being
                #    advertised — id, title and type — to anonymous callers
                #    indefinitely, contradicting the setting the user just
                #    changed.
                # 2. The flip would never be self-limiting: the stored axes
                #    still read as the old tier next cycle, so the clear
                #    re-fires forever and a source-hash collection can never
                #    skip again.
                #
                # The patch normalizes exactly like create_node (no `access`
                # for "space", no `enc` when false), so the node ends up
                # indistinguishable from one born at this tier.
                if flipped:
                    await self._port.set_node_access(self._session, space_id, node_id, axes)
            except Exception as exc:  # noqa: BLE001
                # Counting it in `failed` is not enough to debug it — the real
                # exception is carried out in `errors` and re-raised as a group
                # by sync(), so it reaches the scheduler's on_error funnel with
                # its traceback intact.
                failed.append(cid)
                errors.append(exc)
                continue

            # A node just written to is no longer "already cleared" — if it gets
            # disabled again later it needs a real clear, not a skip.
            self._cleared_nodes.discard(node_id)
            written.append(cid)

        for node in plan.to_clear:
            # The axes the content being cleared was actually written under,
            # read off the object index rather than remembered: a channel
            # rebuilt since the write has nothing to remember, and the
            # configured tier may since have been flipped to something that
            # does not reach the stored copy.
            clear_axes = self._stored_axes(node)
            configured = self._axes_for[node.type]
            # Public on EITHER side — what is stored, or what it is configured
            # as now.
            touches_public = (
                clear_axes["access"] == "public" or configured.get("access") == "public"
            )
            # Already cleared in a prior cycle and never re-enabled since — a
            # repeat push would be a no-op CAS write wasted every cycle this
            # channel instance is reused for (e.g. via a persistent
            # ChannelScheduler-driven loop).
            #
            # PRIVATE ONLY. A public node never takes this short-circuit: the
            # cost of a wasted no-op push is one request, the cost of a wrongly
            # skipped clear is world-readable data left up. Those are not
            # symmetric, and `_cleared_nodes` is only ever a BELIEF about the
            # server's state (a clear that landed but was rolled back, another
            # writer, a node recreated under the same id) — cheap to re-assert,
            # unacceptable to get wrong in public.
            if not touches_public and node.id in self._cleared_nodes:
                cleared.append(node.type)
                continue
            # Same isolation as the write loop: a clear that fails must not
            # abort the clears queued behind it.
            try:
                await self._clear_node(node.type, space_id, node.id, clear_axes)
            except Exception as exc:  # noqa: BLE001
                failed.append(node.type)
                errors.append(exc)
                continue
            self._cleared_nodes.add(node.id)
            self._forget_fingerprints(node.id)
            cleared.append(node.type)

        return {
            "space_id": space_id,
            "created": created,
            "written": written,
            "skipped": skipped,
            "cleared": cleared,
            "failed": failed,
            "errors": errors,
        }

    # ── ReplicaChannel ───────────────────────────────────────────────────────

    async def sync(self, ctx: ReplicaCallContext) -> None:
        enabled_ids = await _maybe_await(self._enabled_ids())

        # The spaces are independent (different id, different keyring, no
        # shared state) — run them concurrently rather than paying sequential
        # network round trips per space every cycle. Independent also means one
        # space blowing up says nothing about the others, so return_exceptions
        # keeps a bad space from cancelling their results out from under them.
        per_space = await asyncio.gather(
            *(self._sync_one_space(name, enabled_ids, ctx) for name in self._space_names),
            return_exceptions=True,
        )

        result = SpaceMirrorResult()
        errors: list[Exception] = []
        for space_name, r in zip(self._space_names, per_space):
            if isinstance(r, BaseException):
                # Raised BEFORE the per-collection loops (space resolve, tree
                # read) — nothing routed to this space could have run, so every
                # id declared for it is a failure, not just the enabled ones.
                result.spaces[space_name] = None
                result.failed.extend(
                    c.id for c in self._collections if c.space_name == space_name
                )
                if isinstance(r, Exception):
                    errors.append(r)
                else:
                    # asyncio.CancelledError and friends are not ours to fold
                    # into a group and report as a collection failure — let a
                    # cancelled cycle stay cancelled.
                    raise r
                continue
            result.spaces[space_name] = r["space_id"]
            result.created.extend(r["created"])
            result.written.extend(r["written"])
            result.skipped.extend(r["skipped"])
            result.cleared.extend(r["cleared"])
            result.failed.extend(r["failed"])
            errors.extend(r["errors"])
        # Assigned unconditionally and BEFORE the raise below, INCLUDING a cycle
        # where every space failed — a stale previous result read as if it were
        # this cycle's is worse than an honest empty one, and a caller handling
        # the raise still needs to see what DID get through.
        self._result = result

        # Parity with TS, which rejects with an AggregateError here. Raising is
        # what feeds ChannelScheduler's on_error funnel — the package's single
        # error surface, which a caller can replace. Logging instead would make
        # a mirror failure invisible to a custom on_error, and would make this
        # channel the only one that reports failure differently from
        # HttpReplicaChannel. The cycle has already fully run at this point, so
        # this is "the cycle finished and some of it failed", not an abort.
        if errors:
            raise ExceptionGroup(  # noqa: F821 - builtin on py311+, and we require >=3.11
                f"[SpaceMirrorChannel] {self.name}: "
                f"{len(result.failed)} collection(s) failed to mirror: "
                f"{', '.join(result.failed)}",
                errors,
            )


def create_space_mirror_channel(
    *,
    name: str,
    session: Any,
    collections: Sequence[SpaceMirrorCollection],
    enabled_ids: Callable[[], Union[Sequence[str], Awaitable[Sequence[str]]]],
    read_source: Callable[[str, ReplicaCallContext], Awaitable[Any]],
    doc_path: Callable[[str, str, str], str],
    title: Optional[Callable[[str], str]] = None,
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
            for. Each may carry a ``tier`` (``"private"``, the default, or
            ``"public"``) selecting the access axes its node is created with
            and written through.
        enabled_ids: Read fresh on every sync (not captured once at
            construction) so a settings toggle applies on the next cycle
            without rebuilding the channel. May be sync or async.
        read_source: Pull the CURRENT raw projection for one enabled
            collection from its real source. Called once per collection being
            written, never for one being cleared. ``ctx`` is threaded through
            unchanged from :meth:`SpaceMirrorChannel.sync`.
        doc_path: Bare storage path for one collection's node content, as
            ``(collection_id, space_id, node_id)`` (no ``/pull``/``/push``
            prefix — the channel adds that). The collection id is passed so a
            caller can route tiers to different path prefixes; on the CLEAR
            path it is the existing node's ``type``.
        title: Human-readable node title, derived from the collection id, used
            when a node is first created. Defaults to the collection id
            itself.
        node_enc: Node access/encryption mode for ``tier="private"``
            collections. Default ``{"access": "space", "enc": True}`` —
            content gated by space membership, encrypted under the space's own
            keyring. ``access="invite"`` is deliberately NOT the default: it
            resolves through a per-node keyring that nothing in a mirror-style
            writer ever seeds. A ``tier="public"`` collection ignores this and
            always resolves to ``{"access": "public", "enc": False}``.
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
        title=title,
        node_enc=node_enc,
        change_detection=change_detection,
        port=port,
    )
