"""Pure planning step for a space-mirror sync cycle: given a space's current
object tree and the set of collection ids currently enabled, decide what the
channel needs to do this cycle. No network I/O and no ``starfish_spaces``
dependency, so it is directly unit-testable.

Mirrors the TS package's ``space/plan.ts``.
"""

from __future__ import annotations

from typing import Iterable, NamedTuple

__all__ = ["ExistingSpaceNode", "SpaceMirrorPlan", "plan_space_mirror"]


class ExistingSpaceNode(NamedTuple):
    """The subset of a space's object-tree node this planning logic reads."""

    id: str
    type: str


class SpaceMirrorPlan(NamedTuple):
    to_create: list[str]
    """Collections that need a fresh node created before they can be written."""

    to_write: list[str]
    """Collections to CAS-push a projection into this cycle — every currently
    enabled collection, whether its node is new or already existed."""

    to_clear: list[ExistingSpaceNode]
    """Existing nodes whose collection was enabled before but is not anymore —
    their content gets cleared, not deleted (the node id itself stays valid so a
    later re-enable reuses it instead of accumulating orphaned nodes)."""


def plan_space_mirror(
    existing_nodes: Iterable[ExistingSpaceNode],
    enabled_ids: Iterable[str],
    known_ids: frozenset[str] | set[str],
) -> SpaceMirrorPlan:
    """Partition this cycle's work into create/write/clear.

    ``existing_nodes`` should already be filtered to nodes this channel owns
    (``type`` present in ``known_ids``) — a caller passing a space's FULL tree
    (including content this channel doesn't manage, if the space is ever
    shared with other writers) must filter first regardless; ``known_ids`` is
    exactly that filter, applied consistently to both ``enabled_ids`` and
    ``existing_nodes``.
    """
    existing_nodes = list(existing_nodes)

    # dict.fromkeys preserves first-seen order (Python sets do not), so the
    # returned lists are deterministic — the TS version relies on JS Set
    # insertion order for the same guarantee.
    enabled = dict.fromkeys(cid for cid in enabled_ids if cid in known_ids)
    existing_by_type = {node.type: node for node in existing_nodes}

    to_create: list[str] = []
    to_write: list[str] = []
    for cid in enabled:
        to_write.append(cid)
        if cid not in existing_by_type:
            to_create.append(cid)

    to_clear = [
        node
        for node in existing_nodes
        if node.type in known_ids and node.type not in enabled
    ]

    return SpaceMirrorPlan(to_create=to_create, to_write=to_write, to_clear=to_clear)
