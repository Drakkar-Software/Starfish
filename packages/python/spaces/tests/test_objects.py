"""Tests for the pure object-tree algorithms.

Subset loads from the shared cross-language vector once that JSON file is
generated. The core tree-building behaviour is also covered inline.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

import pytest

from starfish_spaces.config import ObjectNode
from starfish_spaces.objects import (
    add_object,
    archive_object,
    breadcrumbs,
    build_tree,
    next_order,
    patch_object,
    reparent_object,
    reorder_objects,
    subtree_ids,
    NewObjectInput,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

_VECTOR_PATH = (
    pathlib.Path(__file__).parents[4] / "tests" / "test-vectors" / "spaces-objects.json"
)


def _node(id: str, parent_id: str | None = None, order: float = 1.0, **kw: Any) -> ObjectNode:
    return ObjectNode.from_dict({
        "id": id,
        "type": "page",
        "parentId": parent_id,
        "order": order,
        "title": id,
        "updatedAt": 0,
        **kw,
    })


# ── build_tree ────────────────────────────────────────────────────────────────


def test_build_tree_empty():
    assert build_tree([]) == []


def test_build_tree_single_root():
    nodes = [_node("a")]
    tree = build_tree(nodes)
    assert len(tree) == 1
    assert tree[0].id == "a"
    assert tree[0].depth == 0
    assert tree[0].children == []


def test_build_tree_parent_child():
    nodes = [_node("root"), _node("child", parent_id="root")]
    tree = build_tree(nodes)
    assert len(tree) == 1
    assert tree[0].id == "root"
    assert len(tree[0].children) == 1
    assert tree[0].children[0].id == "child"
    assert tree[0].children[0].depth == 1


def test_build_tree_orphan_reparented_to_root():
    nodes = [_node("a", parent_id="missing")]
    tree = build_tree(nodes)
    assert len(tree) == 1
    assert tree[0].id == "a"
    assert tree[0].depth == 0


def test_build_tree_sibling_order():
    nodes = [_node("b", order=2.0), _node("a", order=1.0)]
    tree = build_tree(nodes)
    assert [n.id for n in tree] == ["a", "b"]


def test_build_tree_sibling_tiebreak_by_id():
    nodes = [_node("z", order=1.0), _node("a", order=1.0)]
    tree = build_tree(nodes)
    assert tree[0].id == "a"
    assert tree[1].id == "z"


# ── next_order ────────────────────────────────────────────────────────────────


def test_next_order_empty():
    assert next_order([]) == 1.0


def test_next_order_after_siblings():
    siblings = [_node("a", order=3.0), _node("b", order=7.0)]
    assert next_order(siblings) == 8.0


# ── add_object ────────────────────────────────────────────────────────────────


def test_add_object_appends():
    nodes: list[ObjectNode] = []
    updated, node = add_object(nodes, NewObjectInput(id="obj-1", type="page", title="Hello"))
    assert len(updated) == 1
    assert node.id == "obj-1"
    assert node.title == "Hello"
    assert node.order == 1.0


def test_add_object_uses_next_order():
    nodes, _ = add_object([], NewObjectInput(id="first", type="page", title="A"))
    nodes2, second = add_object(nodes, NewObjectInput(id="second", type="page", title="B"))
    assert second.order > nodes[0].order


def test_add_object_with_access_stores_access():
    _, node = add_object([], NewObjectInput(id="x", type="page", title="X", access="invite"))
    d = node.to_dict()
    assert d.get("access") == "invite"


def test_add_object_space_access_omitted():
    _, node = add_object([], NewObjectInput(id="x", type="page", title="X", access="space"))
    d = node.to_dict()
    assert "access" not in d  # 'space' is the server default — omitted


# ── breadcrumbs / ancestors / subtree_ids ─────────────────────────────────────


def test_breadcrumbs_root():
    nodes = [_node("a")]
    assert [n.id for n in breadcrumbs(nodes, "a")] == ["a"]


def test_breadcrumbs_deep():
    nodes = [_node("root"), _node("child", parent_id="root"), _node("grand", parent_id="child")]
    trail = breadcrumbs(nodes, "grand")
    assert [n.id for n in trail] == ["root", "child", "grand"]


def test_ancestors_excludes_self():
    nodes = [_node("root"), _node("child", parent_id="root")]
    assert [n.id for n in breadcrumbs(nodes, "child")[:-1]] == ["root"]


def test_subtree_ids_leaf():
    nodes = [_node("a"), _node("b", parent_id="a")]
    ids = set(subtree_ids(nodes, "b"))
    assert ids == {"b"}


def test_subtree_ids_parent():
    nodes = [_node("a"), _node("b", parent_id="a"), _node("c", parent_id="a")]
    ids = set(subtree_ids(nodes, "a"))
    assert ids == {"a", "b", "c"}


# ── patch_object ──────────────────────────────────────────────────────────────


def test_patch_object():
    nodes = [_node("a", title="old")]
    updated = patch_object(nodes, "a", {"title": "new"})
    assert updated[0].title == "new"


# ── reparent_object ───────────────────────────────────────────────────────────


def test_reparent_raises_self():
    nodes = [_node("a")]
    with pytest.raises(ValueError):
        reparent_object(nodes, "a", "a")


def test_reparent_raises_descendant():
    nodes = [_node("parent"), _node("child", parent_id="parent")]
    with pytest.raises(ValueError):
        reparent_object(nodes, "parent", "child")


# ── archive_object ────────────────────────────────────────────────────────────


def test_archive_cascades():
    nodes = [_node("root"), _node("child", parent_id="root")]
    updated = archive_object(nodes, "root")
    assert all(n.archived for n in updated)


# ── Cross-language vector (optional — skipped if not yet generated) ───────────


@pytest.mark.skipif(not _VECTOR_PATH.exists(), reason="spaces-objects.json not yet generated")
def test_objects_vector():
    data = json.loads(_VECTOR_PATH.read_text())
    for case in data.get("buildTree", []):
        input_nodes = [ObjectNode.from_dict(n) for n in case["input"]]
        tree = build_tree(input_nodes)

        def flatten(tree_nodes, acc=None):
            if acc is None:
                acc = []
            for n in tree_nodes:
                acc.append({"id": n.id, "parentId": n.parent_id, "depth": n.depth, "order": n.order})
                flatten(n.children, acc)
            return acc

        flat = flatten(tree)
        expected = case["expected"]
        assert len(flat) == len(expected), f"len mismatch in case {case.get('label', '?')}"
        for got, exp in zip(flat, expected):
            assert got["id"] == exp["id"], f"id mismatch: {got} vs {exp}"
            assert got["depth"] == exp["depth"], f"depth mismatch: {got} vs {exp}"
