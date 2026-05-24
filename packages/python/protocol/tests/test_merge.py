"""Tests for ``starfish_protocol.merge.deep_merge``.

Python dicts don't carry the same prototype-pollution surface as JS objects,
but for consistency with the TypeScript implementation we still skip the
class/instance keys ``__class__`` / ``__dict__``.
"""

from __future__ import annotations

from starfish_protocol.merge import deep_merge


def test_remote_wins_for_primitives() -> None:
    assert deep_merge({"a": 1, "b": 2}, {"b": 3, "c": 4}) == {"a": 1, "b": 3, "c": 4}


def test_recurses_into_nested_dicts() -> None:
    out = deep_merge(
        {"meta": {"count": 1, "label": "old"}},
        {"meta": {"label": "new"}},
    )
    assert out == {"meta": {"count": 1, "label": "new"}}


# --- unsafe keys are dropped (parity with TypeScript) ---


def test_drops_class_and_dict_keys() -> None:
    out = deep_merge({"keep": 1}, {"__class__": "x", "__dict__": "y", "ok": 2})
    assert "__class__" not in out
    assert "__dict__" not in out
    assert out["keep"] == 1
    assert out["ok"] == 2


def test_drops_unsafe_keys_at_nested_level() -> None:
    out = deep_merge({"meta": {}}, {"meta": {"__class__": "x", "__dict__": "y", "ok": 1}})
    meta = out["meta"]
    assert "__class__" not in meta
    assert "__dict__" not in meta
    assert meta["ok"] == 1


def test_drops_unsafe_key_already_present_in_local() -> None:
    out = deep_merge({"keep": 1, "constructor": "bad", "__class__": "bad"}, {"ok": 2})
    assert "constructor" not in out
    assert "__class__" not in out
    assert out == {"keep": 1, "ok": 2}


# --- type transitions (remote always wins for non-dict/dict pairs) ---


def test_remote_scalar_replaces_local_dict() -> None:
    # Only two dicts merge recursively; a remote scalar over a local dict is a
    # plain remote-wins replacement (the nested structure is discarded).
    assert deep_merge({"a": {"x": 1}}, {"a": 5}) == {"a": 5}


def test_remote_dict_replaces_local_scalar() -> None:
    # Symmetric: a remote dict over a local scalar replaces wholesale — there is
    # no local dict to recurse into, so the remote object wins as-is.
    assert deep_merge({"a": 5}, {"a": {"x": 1}}) == {"a": {"x": 1}}


def test_remote_list_replaces_local_list_wholesale() -> None:
    # Lists are not element-merged; the remote list wins in full.
    assert deep_merge({"a": [1, 2, 3]}, {"a": [9]}) == {"a": [9]}


def test_remote_none_overwrites_local_dict() -> None:
    # None is not a dict, so the recursion guard fails and the remote-wins branch
    # assigns None verbatim. Matches the TS deepMerge (remoteVal === null).
    assert deep_merge({"a": {"x": 1}, "b": 2}, {"a": None}) == {"a": None, "b": 2}


def test_remote_dict_replaces_local_none() -> None:
    # A local None is not a dict, so the remote dict wins wholesale rather than
    # merging into the None. Matches the TS deepMerge.
    assert deep_merge({"a": None}, {"a": {"x": 1}}) == {"a": {"x": 1}}


# --- the unsafe-key scrub reaches dict values at every depth, but not the
#     dicts nested *inside an array* (which the remote-wins branch copies
#     wholesale). Both languages behave identically here; pinned so the
#     boundary cannot silently shift in one implementation only. ---


def test_unsafe_keys_inside_array_elements_are_copied_verbatim() -> None:
    out = deep_merge({}, {"items": [{"__proto__": 1, "ok": 2}]})
    # The array is taken whole by the remote-wins branch — its element dict is
    # never walked, so the dunder key rides along (matches the TS deepMerge).
    assert out == {"items": [{"__proto__": 1, "ok": 2}]}


def test_top_level_unsafe_key_dropped_while_array_nested_one_survives() -> None:
    out = deep_merge({}, {"__proto__": 9, "items": [{"__proto__": 1}]})
    assert "__proto__" not in out  # scrubbed at the merged document root
    assert out["items"] == [{"__proto__": 1}]  # but not inside an array element
