"""Generate tests/test-vectors/spaces-objects.json.

Builds ``build_tree`` test-vector cases with deterministic node lists and
expected flattened tree outputs (id, parentId, depth, order).

Usage::

    uv run --python 3.12 python tests/test-vectors/_generators/spaces_objects.py

from the repo root.
"""

from __future__ import annotations

import json
import pathlib
import sys

_REPO_ROOT = pathlib.Path(__file__).parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_SPACES_PKG = _REPO_ROOT / "packages" / "python" / "spaces"
if str(_SPACES_PKG) not in sys.path:
    sys.path.insert(0, str(_SPACES_PKG))

from starfish_spaces.config import ObjectNode  # noqa: E402
from starfish_spaces.objects import build_tree  # noqa: E402


def _node(id_, parent_id=None, order=1.0, title=None):
    d = {
        "id": id_,
        "type": "page",
        "order": order,
        "title": title or id_,
        "updatedAt": 0,
    }
    if parent_id is not None:
        d["parentId"] = parent_id
    return d


def _flatten(tree_nodes):
    out = []
    for n in tree_nodes:
        out.append({"id": n.id, "parentId": n.parent_id, "depth": n.depth, "order": n.order})
        out.extend(_flatten(n.children))
    return out


def _case(label, input_nodes, expected=None):
    nodes = [ObjectNode.from_dict(n) for n in input_nodes]
    tree = build_tree(nodes)
    flat = _flatten(tree)
    return {
        "label": label,
        "input": input_nodes,
        "expected": expected if expected is not None else flat,
    }


build_tree_cases = [
    _case("empty", []),
    _case("single-root", [_node("a")]),
    _case("two-roots-ordered", [_node("b", order=2.0), _node("a", order=1.0)]),
    _case(
        "parent-child",
        [_node("root"), _node("child", parent_id="root", order=1.5)],
    ),
    _case(
        "deep-tree",
        [
            _node("root", order=1.0),
            _node("child", parent_id="root", order=1.0),
            _node("grand", parent_id="child", order=1.0),
        ],
    ),
    _case(
        "orphan-becomes-root",
        [_node("orphan", parent_id="nonexistent", order=1.0)],
    ),
    _case(
        "siblings-tiebreak",
        [_node("z", order=1.0), _node("a", order=1.0)],
    ),
    _case(
        "mixed-depth",
        [
            _node("r1", order=1.0),
            _node("r2", order=2.0),
            _node("c1", parent_id="r1", order=1.0),
            _node("c2", parent_id="r1", order=2.0),
            _node("g1", parent_id="c2", order=1.0),
        ],
    ),
]

out = {"buildTree": build_tree_cases}
OUTPUT = _REPO_ROOT / "tests" / "test-vectors" / "spaces-objects.json"
OUTPUT.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
print(f"wrote {OUTPUT}")
