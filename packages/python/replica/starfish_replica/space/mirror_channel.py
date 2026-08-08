"""A :class:`~starfish_replica.channel.ReplicaChannel` that mirrors an app-local
data source into per-collection nodes of one or more Starfish spaces.

The channel owns the space/node mechanics — space find-or-create, node
find-or-create, CAS-write, clear-on-disable, and routing across several
spaces. What stays with the caller is the collection registry (which ids
exist, which space each routes to) and the ``read_source`` callback.

Each collection picks a storage ``tier``: ``private`` (space keyring),
``isolated`` (its own per-node keyring, so it can be granted and revoked one
node at a time) or ``public`` (plaintext). See
``website/docs/extensions/replica.md``.

Mirrors the TS package's ``space/mirror-channel.ts``.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Optional, Sequence, Union

from starfish_replica.channel import ReplicaCallContext
from starfish_replica.space.plan import ExistingSpaceNode, plan_space_mirror
from starfish_replica.space.port import (
    NodeAccessHandle,
    SpacePort,
    default_space_port,
    find_or_create_space,
)

__all__ = [
    "SpaceMirrorCollection",
    "SpaceMirrorResult",
    "SpaceMirrorChannel",
    "create_space_mirror_channel",
]

DEFAULT_NODE_ENC: dict[str, Any] = {"access": "space", "enc": True}

# The "public" and "isolated" resolutions are fixed pairs, deliberately NOT
# influenced by ``node_enc``: for those two tiers the tier IS the access model.
PUBLIC_NODE_ENC: dict[str, Any] = {"access": "public", "enc": False}
ISOLATED_NODE_ENC: dict[str, Any] = {"access": "invite", "enc": True}

TIERS = ("private", "public", "isolated")


def _is_isolated(axes: dict[str, Any]) -> bool:
    return axes.get("access") == "invite" and bool(axes.get("enc"))


def _is_external(axes: dict[str, Any]) -> bool:
    """Reachable beyond this space's members: ``public`` is world-readable,
    ``invite`` is readable by every holder of a still-valid per-node grant."""
    return axes.get("access") in ("public", "invite")


@dataclass(frozen=True)
class SpaceMirrorCollection:
    """One collection this channel mirrors, and which space its node lives in."""

    id: str
    space_name: str

    tier: str = "private"
    """Storage tier for this collection's node:

    - ``"private"`` (default) — the channel's ``node_enc``, itself
      ``{"access": "space", "enc": True}`` unless the caller overrode it.
    - ``"isolated"`` — ``{"access": "invite", "enc": True}``, the node's OWN
      keyring, grantable and revocable one node at a time.
    - ``"public"`` — ``{"access": "public", "enc": False}``, world-readable.

    An explicit ``"private"`` is EXACTLY equivalent to omitting it. One enum
    rather than a raw ``{access, enc}`` pair: the server rejects
    ``access="public"`` with ``enc=True``, and an enum makes that combination
    unrepresentable. See ``website/docs/extensions/replica.md``."""

    def __post_init__(self) -> None:
        if self.tier not in TIERS:
            raise ValueError(
                f"tier must be one of {', '.join(map(repr, TIERS))}, got {self.tier!r}"
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
    no change since the last write."""

    cleared: list[str] = field(default_factory=list)

    failed: list[str] = field(default_factory=list)
    """Ids whose write or clear raised this cycle; failures are isolated. A
    space-level failure (space resolve or tree read) lists every id routed to
    that space, since none of them could run."""


@dataclass
class _SpaceOutcome:
    """One space's contribution to a cycle."""

    space_id: Optional[str] = None
    created: list[str] = field(default_factory=list)
    written: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    cleared: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    #: The real exceptions behind `failed`, re-raised as one group by `sync`.
    errors: list[Exception] = field(default_factory=list)


def _fingerprint(data: Any) -> str:
    """Cheap content fingerprint for the optional source-hash skip — change
    detection, not a cryptographic digest."""
    return json.dumps(data if data is not None else None, sort_keys=True, default=str)


async def _maybe_await(value: Union[Any, Awaitable[Any]]) -> Any:
    """Await ``value`` if awaitable, so ``enabled_ids`` may be sync or async."""
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

        self._tier_for = {c.id: c.tier for c in self._collections}
        self._axes_for: dict[str, dict[str, Any]] = {
            c.id: self._axes_for_tier(c.tier) for c in self._collections
        }

        # f"{node_id}:{tier}" -> fingerprint last written. Keyed by tier: a tier
        # flip does not change what read_source returns, so a node-id-only key
        # would match and skip the ONE write that migrates the node.
        self._last_written: dict[str, str] = {}
        # node_ids cleared by a prior cycle of THIS instance — skips a repeat
        # no-op CAS write. Per-instance: a rebuilt channel just re-clears once.
        self._cleared_nodes: set[str] = set()

        self._result = SpaceMirrorResult()

    @property
    def result(self) -> SpaceMirrorResult:
        """The result of the most recently completed :meth:`sync` call."""
        return self._result

    # ── tier helpers ─────────────────────────────────────────────────────────

    def _axes_for_tier(self, tier: str) -> dict[str, Any]:
        """The ``{"access", "enc"}`` axes one tier resolves to. ``"private"`` —
        explicit or defaulted — resolves to the channel-wide ``node_enc``, so a
        caller that overrode it keeps that override either way."""
        if tier == "public":
            return dict(PUBLIC_NODE_ENC)
        if tier == "isolated":
            return dict(ISOLATED_NODE_ENC)
        return dict(self._node_enc)

    @staticmethod
    def _stored_axes(node: ExistingSpaceNode) -> dict[str, Any]:
        """The axes a node is ACTUALLY stored under, normalized: node creation
        omits ``access`` when it is ``"space"`` and ``enc`` when false, so an
        absent field is the default, not a gap."""
        return {"access": node.access or "space", "enc": node.enc is True}

    @staticmethod
    def _same_axes(a: dict[str, Any], b: dict[str, Any]) -> bool:
        """Compare the two axes only — a caller's ``node_enc`` may legitimately
        carry extra keys, and those are not what a tier flip is about."""
        return a.get("access") == b.get("access") and bool(a.get("enc")) == bool(b.get("enc"))

    def _forget_fingerprints(self, node_id: str) -> None:
        """Drop EVERY tier's fingerprint for one node: popping only the tier just
        written would leave the other tier's stale one to skip a later write
        back to it."""
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

    async def _access_for(
        self, space_id: str, node_id: str, axes: dict[str, Any]
    ) -> NodeAccessHandle:
        """Handle for reading/writing one node under ``axes``. An isolated node
        goes through its OWN keyring, never the space one: ``get_node_access``'s
        owner tier would silently fall back to the space keyring if the node
        keyring were missing."""
        if _is_isolated(axes):
            return await self._port.get_isolated_node_access(self._session, space_id, node_id)
        return await self._port.get_node_access(self._session, space_id, node_id, axes)

    async def _write_node(
        self, cid: str, space_id: str, node_id: str, data: Any, axes: dict[str, Any]
    ) -> None:
        """CAS-write a raw (uncurated) projection into one node — no field
        allowlist, no merge: whatever ``data`` is IS the node's content after
        this call.

        ``axes`` is this COLLECTION's resolved tier, not the channel-wide
        default: it selects the encryptor (space keyring, node keyring, or none)
        and lets push_node_doc refuse ciphertext in a collection the server
        declares ``encryption="none"``.
        """
        handle = await self._access_for(space_id, node_id, axes)
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
        handle = await self._access_for(space_id, node_id, axes)
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
    ) -> _SpaceOutcome:
        # Only the collections that actually belong in THIS space.
        for_this_space = [
            cid
            for cid in enabled_ids
            if cid in self._known_ids and self._space_name_for.get(cid) == space_name
        ]

        # Don't create an empty space just to immediately clear nothing in it. A
        # space that DOES already exist is still resolved below, so its
        # now-orphaned nodes still get cleared.
        if not for_this_space:
            spaces = await self._port.read_spaces(self._session)
            if not any(s.get("name") == space_name for s in spaces):
                return _SpaceOutcome()

        space = await find_or_create_space(self._session, space_name, self._port)
        space_id = space["id"]
        tree = await self._port.read_object_tree(self._session, space_id)
        # access/enc are carried through, not narrowed away: they are the node's
        # STORED tier evidence, the only kind that survives this channel being
        # rebuilt. Without them a flip made while it was gone is invisible.
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

        # `created` is what _find_or_create_node ACTUALLY created, not
        # plan.to_create: a create that raises must not land in both `created`
        # and `failed`, leaving a caller unable to tell whether the node exists.
        out = _SpaceOutcome(space_id=space_id)
        for cid in plan.to_write:
            # One collection is one independent unit of work: a 413, a CAS
            # conflict that outlived run_cas's retries, or a blip on this one
            # node must not cost the OTHERS their write.
            try:
                tier = self._tier_for[cid]
                axes = self._axes_for[cid]
                existing = existing_by_type.get(cid)
                node = await self._find_or_create_node(space_id, existing, cid, axes)
                node_id = node["id"]
                if existing is None:
                    out.created.append(cid)
                flipped = False

                # Tier flip detected from what is STORED, not from what this
                # instance remembers: after a restart there is nothing to
                # remember, and a public -> private flip would leave the old
                # plaintext at its world-readable URL. Cleared FIRST, under the
                # STORED axes: the new ones resolve a different handle, which
                # does not reach (or decrypt) what is actually sitting there.
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
                        out.skipped.append(cid)
                        continue
                    await self._write_node(cid, space_id, node_id, data, axes)
                    self._last_written[key] = digest
                else:
                    await self._write_node(cid, space_id, node_id, data, axes)
                    if self._change_detection == "source-hash":
                        self._last_written[key] = _fingerprint(data)

                # Strictly AFTER the write: patching first would leave the index
                # claiming a tier the stored content does not match. Without the
                # patch a node flipped away from "public" stays advertised (id,
                # title, type) in Infra's world-readable public-objects
                # projection, and the flip never self-limits — the clear re-fires
                # every cycle. See website/docs/extensions/replica.md.
                if flipped:
                    await self._port.set_node_access(self._session, space_id, node_id, axes)
            except Exception as exc:  # noqa: BLE001
                # The real exception rides out in `errors` for sync() to re-raise
                # into the scheduler's on_error funnel, traceback intact.
                out.failed.append(cid)
                out.errors.append(exc)
                continue

            # A node just written to is no longer "already cleared" — if it gets
            # disabled again later it needs a real clear, not a skip.
            self._cleared_nodes.discard(node_id)
            out.written.append(cid)

        for node in plan.to_clear:
            # The axes the content being cleared was actually written under,
            # read off the object index rather than remembered: a channel
            # rebuilt since the write has nothing to remember, and the
            # configured tier may since have been flipped to something that
            # does not reach the stored copy.
            clear_axes = self._stored_axes(node)
            configured = self._axes_for[node.type]
            touches_external = _is_external(clear_axes) or _is_external(configured)
            # Already cleared in a prior cycle and never re-enabled since — skip
            # the no-op CAS write. SPACE-PRIVATE ONLY: `_cleared_nodes` is only
            # ever a BELIEF about the server's state (a clear rolled back,
            # another writer, a node recreated under the same id), cheap to
            # re-assert and unacceptable to get wrong for content the world or a
            # grant holder can read.
            if not touches_external and node.id in self._cleared_nodes:
                out.cleared.append(node.type)
                continue
            # Same isolation as the write loop: a clear that fails must not
            # abort the clears queued behind it.
            try:
                await self._clear_node(node.type, space_id, node.id, clear_axes)
            except Exception as exc:  # noqa: BLE001
                out.failed.append(node.type)
                out.errors.append(exc)
                continue
            self._cleared_nodes.add(node.id)
            self._forget_fingerprints(node.id)
            out.cleared.append(node.type)

        return out

    # ── ReplicaChannel ───────────────────────────────────────────────────────

    async def sync(self, ctx: ReplicaCallContext) -> None:
        enabled_ids = await _maybe_await(self._enabled_ids())

        # The spaces are independent (different id, different keyring, no shared
        # state), so run them concurrently; return_exceptions keeps one bad
        # space from cancelling the others' results out from under them.
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
                    # CancelledError and friends are not ours to fold into a
                    # group — let a cancelled cycle stay cancelled.
                    raise r
                continue
            result.spaces[space_name] = r.space_id
            result.created.extend(r.created)
            result.written.extend(r.written)
            result.skipped.extend(r.skipped)
            result.cleared.extend(r.cleared)
            result.failed.extend(r.failed)
            errors.extend(r.errors)
        # Assigned BEFORE the raise below, even when every space failed: a stale
        # previous result read as this cycle's is worse than an honest empty one.
        self._result = result

        # Parity with TS's AggregateError, and what feeds ChannelScheduler's
        # on_error funnel. The cycle has already fully run here, so this is
        # "finished with failures", not an abort.
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
            for. Each may carry a ``tier`` (``"private"`` (default),
            ``"isolated"`` or ``"public"``) selecting the access axes its node
            is created with and written through.
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
            collections. Default ``{"access": "space", "enc": True}``;
            ``"public"`` and ``"isolated"`` ignore it and use their own axes.
        change_detection: ``"none"`` (default) writes every enabled
            collection's projection every cycle. ``"source-hash"`` skips the
            write (for an already-existing node) when ``read_source``'s result
            is identical to what this channel last wrote. ONLY safe when this
            channel is the SOLE writer, since a skip never re-checks what is
            actually stored and a second writer could silently diverge.
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
