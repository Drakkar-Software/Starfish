"""Pure object-tree model — no network / session / crypto.

This module contains the deterministic tree algorithms for the space object index.
All functions are pure (no side-effects) and take / return plain Python objects.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from starfish_protocol.random import random_id

from starfish_spaces.config import NodeAccess, ObjectNode, ObjectType


# ── Tree node type ─────────────────────────────────────────────────────────────


@dataclass
class ObjectTreeNode:
    """An :class:`ObjectNode` with its resolved tree position (depth + children)."""

    id: str
    type: str
    parent_id: Optional[str]
    order: float
    title: str
    updated_at: int
    depth: int
    children: list["ObjectTreeNode"] = field(default_factory=list)
    emoji: Optional[str] = None
    archived: Optional[bool] = None
    content_kind: Optional[str] = None
    access: Optional[str] = None
    enc: Optional[bool] = None
    meta: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "parentId": self.parent_id,
            "order": self.order,
            "title": self.title,
            "updatedAt": self.updated_at,
            "depth": self.depth,
            "children": [c.to_dict() for c in self.children],
        }
        if self.emoji is not None:
            out["emoji"] = self.emoji
        if self.archived is not None:
            out["archived"] = self.archived
        if self.content_kind is not None:
            out["contentKind"] = self.content_kind
        if self.access is not None:
            out["access"] = self.access
        if self.enc is not None:
            out["enc"] = self.enc
        if self.meta is not None:
            out["meta"] = self.meta
        return out


# ── Input type ────────────────────────────────────────────────────────────────


@dataclass
class NewObjectInput:
    """Input for creating a new node in the tree."""

    type: ObjectType
    title: str
    parent_id: Optional[str] = None
    emoji: Optional[str] = None
    meta: Optional[dict[str, Any]] = None
    id: Optional[str] = None
    """Use a caller-supplied id (overrides ``id_prefix``)."""
    id_prefix: Optional[str] = None
    """Prefix for the auto-generated id (default ``"obj-"``)."""
    access: Optional[NodeAccess] = None
    """``None`` → omit from storage (server default is ``"space"``)."""
    enc: Optional[bool] = None
    """``None`` → omit from storage (server default is ``False``)."""


# ── Internal helpers ──────────────────────────────────────────────────────────


def _compare_siblings(a: ObjectNode, b: ObjectNode) -> int:
    """Deterministic total order for sibling nodes: by order, then by id."""
    if a.order != b.order:
        return -1 if a.order < b.order else 1
    if a.id < b.id:
        return -1
    if a.id > b.id:
        return 1
    return 0


def _cmp_key(node: ObjectNode):
    return (node.order, node.id)


def _update_nodes(
    nodes: list[ObjectNode], updates: list[dict[str, Any]]
) -> list[ObjectNode]:
    """Apply a list of ``{id: ..., ...fields}`` patches to a node list."""
    patch_map = {u["id"]: u for u in updates}
    result = []
    for node in nodes:
        patch = patch_map.get(node.id)
        if patch is None:
            result.append(node)
        else:
            d = node.to_dict()
            d.update({k: v for k, v in patch.items() if k != "id"})
            result.append(ObjectNode.from_dict(d))
    return result


# ── next_order ────────────────────────────────────────────────────────────────


def next_order(siblings: list[ObjectNode]) -> float:
    """Return the order value that places a new node at the end of ``siblings``."""
    if not siblings:
        return 1.0
    return max(n.order for n in siblings) + 1.0


# ── build_tree ────────────────────────────────────────────────────────────────


def build_tree(nodes: list[ObjectNode]) -> list[ObjectTreeNode]:
    """Build a tree from a flat node list.

    Repairs common corruption scenarios:
    - **Orphans** (parentId points to a non-existent node) → promoted to roots.
    - **Archived** nodes are included; callers filter them if needed.
    - **Cycles** (a node is its own ancestor) → detected and the deeper member is
      promoted to a root.

    Siblings are sorted deterministically: first by ``order`` (ascending),
    then by ``id`` (lexicographic) as a tiebreaker.

    Returns the root-level :class:`ObjectTreeNode` list (children are nested).
    """
    id_set = {n.id for n in nodes}
    by_parent: dict[Optional[str], list[ObjectNode]] = {}
    for node in nodes:
        parent = node.parent_id if node.parent_id in id_set else None
        by_parent.setdefault(parent, []).append(node)

    def build_subtree(
        node: ObjectNode,
        depth: int,
        visiting: set[str],
    ) -> ObjectTreeNode:
        children_raw = sorted(by_parent.get(node.id, []), key=_cmp_key)
        tree_node = ObjectTreeNode(
            id=node.id,
            type=node.type,
            parent_id=node.parent_id,
            order=node.order,
            title=node.title,
            updated_at=node.updated_at,
            depth=depth,
            emoji=node.emoji,
            archived=node.archived,
            content_kind=node.content_kind,
            access=node.access,
            enc=node.enc,
            meta=node.meta,
        )
        for child in children_raw:
            if child.id in visiting:
                # Cycle detected — treat as orphan root (skip in this subtree).
                continue
            visiting.add(child.id)
            tree_node.children.append(build_subtree(child, depth + 1, visiting))
            visiting.remove(child.id)
        return tree_node

    roots_raw = sorted(by_parent.get(None, []), key=_cmp_key)
    result = []
    for root in roots_raw:
        visiting: set[str] = {root.id}
        result.append(build_subtree(root, 0, visiting))
    return result


# ── breadcrumbs / ancestors / subtree_ids ─────────────────────────────────────


def breadcrumbs(nodes: list[ObjectNode], node_id: str) -> list[ObjectNode]:
    """Return the path from the root to ``node_id`` (inclusive).

    Cycle-safe: returns an empty list when ``node_id`` is not found or a cycle
    is detected.
    """
    by_id = {n.id: n for n in nodes}
    node = by_id.get(node_id)
    if node is None:
        return []
    path = []
    seen: set[str] = set()
    current: Optional[ObjectNode] = node
    while current is not None:
        if current.id in seen:
            return []  # cycle — bail
        seen.add(current.id)
        path.append(current)
        current = by_id.get(current.parent_id or "")
    path.reverse()
    return path


def ancestors(nodes: list[ObjectNode], node_id: str) -> list[ObjectNode]:
    """Return the breadcrumb trail for ``node_id``, excluding the node itself."""
    trail = breadcrumbs(nodes, node_id)
    return trail[:-1] if trail else []


def subtree_ids(nodes: list[ObjectNode], node_id: str) -> list[str]:
    """Return all node ids in the subtree rooted at ``node_id`` (inclusive)."""
    by_parent: dict[Optional[str], list[str]] = {}
    id_set = {n.id for n in nodes}
    for n in nodes:
        p = n.parent_id if n.parent_id in id_set else None
        by_parent.setdefault(p, []).append(n.id)

    result: list[str] = []
    queue = [node_id]
    while queue:
        current = queue.pop()
        result.append(current)
        queue.extend(by_parent.get(current, []))
    return result


# ── add_object ────────────────────────────────────────────────────────────────


def add_object(
    nodes: list[ObjectNode],
    inp: NewObjectInput,
) -> tuple[list[ObjectNode], ObjectNode]:
    """Add a new node to the tree and return the updated list + the new node.

    Args:
        nodes: The current flat node list.
        inp:   The new-node specification.

    Returns:
        ``(updated_nodes, new_node)`` where ``updated_nodes`` is ``nodes + [new_node]``.
    """
    id_set = {n.id for n in nodes}
    parent_id: Optional[str] = inp.parent_id if inp.parent_id in id_set else None

    siblings = [n for n in nodes if n.parent_id == parent_id]
    order = next_order(siblings)

    node_id = inp.id if inp.id else (inp.id_prefix or "obj-") + random_id()

    d: dict[str, Any] = {
        "id": node_id,
        "type": inp.type,
        "parentId": parent_id,
        "order": order,
        "title": inp.title,
        "updatedAt": int(time.time() * 1000),
    }
    if inp.emoji is not None:
        d["emoji"] = inp.emoji
    if inp.meta is not None:
        d["meta"] = inp.meta
    # Only store access/enc when they differ from the server default (space / False).
    if inp.access is not None and inp.access != "space":
        d["access"] = inp.access
    if inp.enc is not None and inp.enc:
        d["enc"] = inp.enc

    new_node = ObjectNode.from_dict(d)
    return nodes + [new_node], new_node


# ── patch_object ──────────────────────────────────────────────────────────────


def patch_object(
    nodes: list[ObjectNode],
    node_id: str,
    patch: dict[str, Any],
) -> list[ObjectNode]:
    """Apply ``patch`` to the node with ``node_id``; preserves all other nodes."""
    return _update_nodes(nodes, [{**patch, "id": node_id}])


# ── reparent_object ───────────────────────────────────────────────────────────


def reparent_object(
    nodes: list[ObjectNode],
    node_id: str,
    new_parent_id: Optional[str],
) -> list[ObjectNode]:
    """Move ``node_id`` to a new parent.

    Raises:
        ValueError: if ``new_parent_id`` is ``node_id`` itself or a descendant of it.
    """
    if new_parent_id == node_id:
        raise ValueError(f"Cannot reparent node {node_id!r} to itself")
    # Check that new_parent_id is not a descendant of node_id.
    if new_parent_id is not None:
        desc = subtree_ids(nodes, node_id)
        if new_parent_id in desc:
            raise ValueError(
                f"Cannot reparent node {node_id!r} to its own descendant {new_parent_id!r}"
            )
    id_set = {n.id for n in nodes}
    resolved_parent = new_parent_id if new_parent_id in id_set else None
    siblings = [n for n in nodes if n.parent_id == resolved_parent and n.id != node_id]
    order = next_order(siblings)
    return _update_nodes(nodes, [{"id": node_id, "parentId": resolved_parent, "order": order}])


# ── reorder_objects ───────────────────────────────────────────────────────────


def reorder_objects(
    nodes: list[ObjectNode],
    ordered_ids: list[str],
) -> list[ObjectNode]:
    """Assign new sequential order values (1, 2, 3, …) to the nodes in ``ordered_ids``.

    Nodes not in ``ordered_ids`` are unchanged.
    """
    updates = [{"id": nid, "order": float(i + 1)} for i, nid in enumerate(ordered_ids)]
    return _update_nodes(nodes, updates)


# ── archive_object ────────────────────────────────────────────────────────────


def archive_object(nodes: list[ObjectNode], node_id: str) -> list[ObjectNode]:
    """Archive ``node_id`` and all of its descendants (cascade).

    Sets ``archived = True`` on the node and every node in its subtree.
    """
    ids_to_archive = set(subtree_ids(nodes, node_id))
    updates = [{"id": nid, "archived": True} for nid in ids_to_archive]
    return _update_nodes(nodes, updates)


__all__ = [
    "ObjectTreeNode",
    "NewObjectInput",
    "next_order",
    "build_tree",
    "breadcrumbs",
    "ancestors",
    "subtree_ids",
    "add_object",
    "patch_object",
    "reparent_object",
    "reorder_objects",
    "archive_object",
]
