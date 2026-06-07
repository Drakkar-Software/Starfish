from starfish_wal import WalCrdt, compare_clocks
from functools import cmp_to_key


def _fold(ops):
    c = WalCrdt()
    c.fold(ops)
    return c


def _perms(ops):
    return [
        ops,
        list(reversed(ops)),
        sorted(ops, key=cmp_to_key(lambda a, b: compare_clocks(a["clock"], b["clock"]))),
        sorted(ops, key=cmp_to_key(lambda a, b: compare_clocks(b["clock"], a["clock"]))),
    ]


def test_lww_highest_clock_wins():
    ops = [
        {"t": "set", "reg": "title", "clock": {"c": 1, "r": "a"}, "value": "draft"},
        {"t": "set", "reg": "title", "clock": {"c": 2, "r": "a"}, "value": "final"},
        {"t": "set", "reg": "title", "clock": {"c": 2, "r": "b"}, "value": "other"},
    ]
    for p in _perms(ops):
        assert _fold(p).materialize() == {"title": "other"}


def test_delete_tombstone_and_resurrect():
    ops = [
        {"t": "set", "reg": "x", "clock": {"c": 1, "r": "a"}, "value": "v1"},
        {"t": "del", "reg": "x", "clock": {"c": 2, "r": "a"}},
        {"t": "set", "reg": "x", "clock": {"c": 3, "r": "a"}, "value": "v2"},
    ]
    for p in _perms(ops):
        assert _fold(p).materialize() == {"x": "v2"}


def test_stale_delete_cannot_erase_newer_set():
    c = _fold([
        {"t": "set", "reg": "k", "clock": {"c": 5, "r": "a"}, "value": "keep"},
        {"t": "del", "reg": "k", "clock": {"c": 2, "r": "b"}},
    ])
    assert c.get_register("k") == "keep"


def test_rga_concurrent_head_insert_tiebreak():
    ops = [
        {"t": "ins", "list": "l", "id": "1@a", "after": "", "clock": {"c": 1, "r": "a"}, "value": "A"},
        {"t": "ins", "list": "l", "id": "1@b", "after": "", "clock": {"c": 1, "r": "b"}, "value": "B"},
        {"t": "ins", "list": "l", "id": "2@a", "after": "1@a", "clock": {"c": 2, "r": "a"}, "value": "C"},
    ]
    for p in _perms(ops):
        assert _fold(p).list_values("l") == ["B", "A", "C"]


def test_rga_delete_keeps_anchor():
    ops = [
        {"t": "ins", "list": "l", "id": "1@a", "after": "", "clock": {"c": 1, "r": "a"}, "value": "x"},
        {"t": "ins", "list": "l", "id": "2@a", "after": "1@a", "clock": {"c": 2, "r": "a"}, "value": "y"},
        {"t": "rmv", "list": "l", "id": "1@a", "clock": {"c": 3, "r": "a"}},
    ]
    for p in _perms(ops):
        assert _fold(p).list_values("l") == ["y"]


def test_rga_insert_idempotent():
    ins = {"t": "ins", "list": "l", "id": "1@a", "after": "", "clock": {"c": 1, "r": "a"}, "value": "x"}
    assert _fold([ins, ins, ins]).list_values("l") == ["x"]


def test_remove_before_insert():
    c = _fold([
        {"t": "rmv", "list": "l", "id": "1@a", "clock": {"c": 2, "r": "a"}},
        {"t": "ins", "list": "l", "id": "1@a", "after": "", "clock": {"c": 1, "r": "a"}, "value": "x"},
    ])
    assert c.list_values("l") == []


def test_remove_before_insert_with_live_descendant():
    # Regression: the rmv-before-ins tombstone must not be mis-anchored at the
    # head and drag its live subtree (3@a) to the wrong position.
    ops = [
        {"t": "ins", "list": "l", "id": "1@a", "after": "", "clock": {"c": 1, "r": "a"}, "value": "A"},
        {"t": "ins", "list": "l", "id": "2@a", "after": "1@a", "clock": {"c": 2, "r": "a"}, "value": "B"},
        {"t": "rmv", "list": "l", "id": "2@a", "clock": {"c": 3, "r": "a"}},
        {"t": "ins", "list": "l", "id": "3@a", "after": "2@a", "clock": {"c": 4, "r": "a"}, "value": "C"},
    ]
    for p in _perms(ops):
        assert _fold(p).list_values("l") == ["A", "C"]


def test_sibling_identical_clock_orders_by_id():
    # Malformed ops (id decoupled from clock) sharing an exact clock must still
    # converge via the id tie-break, independent of fold order.
    ops = [
        {"t": "ins", "list": "l", "id": "A", "after": "", "clock": {"c": 1, "r": "x"}, "value": "first"},
        {"t": "ins", "list": "l", "id": "B", "after": "", "clock": {"c": 1, "r": "x"}, "value": "second"},
    ]
    assert _fold(ops).list_values("l") == ["second", "first"]
    assert _fold(list(reversed(ops))).list_values("l") == ["second", "first"]


def test_text_materializes_as_string():
    c = _fold([
        {"t": "ins", "list": "t", "id": "1@a", "after": "", "clock": {"c": 1, "r": "a"}, "value": "h"},
        {"t": "ins", "list": "t", "id": "2@a", "after": "1@a", "clock": {"c": 2, "r": "a"}, "value": "i"},
    ])
    assert c.text("t") == "hi"


def test_state_round_trip_with_tombstones():
    src = _fold([
        {"t": "set", "reg": "a", "clock": {"c": 1, "r": "a"}, "value": 1},
        {"t": "ins", "list": "l", "id": "1@a", "after": "", "clock": {"c": 2, "r": "a"}, "value": "x"},
        {"t": "rmv", "list": "l", "id": "1@a", "clock": {"c": 3, "r": "a"}},
    ])
    restored = WalCrdt()
    restored.import_state(src.export_state())
    assert restored.materialize() == src.materialize()
    restored.apply({"t": "ins", "list": "l", "id": "2@a", "after": "1@a", "clock": {"c": 4, "r": "a"}, "value": "y"})
    assert restored.list_values("l") == ["y"]


def test_clone_is_independent():
    src = _fold([{"t": "set", "reg": "a", "clock": {"c": 1, "r": "a"}, "value": 1}])
    copy = src.clone()
    copy.apply({"t": "set", "reg": "a", "clock": {"c": 2, "r": "a"}, "value": 2})
    assert src.get_register("a") == 1
    assert copy.get_register("a") == 2


def test_export_deep_copies_clocks():
    src = _fold([
        {"t": "set", "reg": "a", "clock": {"c": 5, "r": "a"}, "value": 1},
        {"t": "ins", "list": "l", "id": "1@a", "after": "", "clock": {"c": 6, "r": "a"}, "value": "x"},
    ])
    exported = src.export_state()
    # Mutate the exported clocks in place — the live document must be unaffected.
    exported["regs"]["a"]["clock"]["c"] = 999
    exported["lists"]["l"][0]["clock"]["c"] = 999
    after = src.export_state()
    assert after["regs"]["a"]["clock"]["c"] == 5
    assert after["lists"]["l"][0]["clock"]["c"] == 6


def test_export_state_idempotent_under_refold():
    ops = [
        {"t": "set", "reg": "a", "clock": {"c": 1, "r": "a"}, "value": 1},
        {"t": "ins", "list": "l", "id": "1@a", "after": "", "clock": {"c": 2, "r": "a"}, "value": "x"},
        {"t": "rmv", "list": "l", "id": "1@a", "clock": {"c": 3, "r": "a"}},
    ]
    c = WalCrdt()
    c.fold(ops)
    before = c.export_state()
    c.fold(ops)
    assert c.export_state() == before


def test_materializes_long_linear_chain_without_recursion_error():
    # A long text run is a deep RGA chain; _list_order must not recurse per node
    # (Python's default recursion limit is ~1000).
    n = 50_000
    ops = [
        {
            "t": "ins",
            "list": "body",
            "id": f"{i}@a",
            "after": "" if i == 0 else f"{i - 1}@a",
            "clock": {"c": i + 1, "r": "a"},
            "value": "x",
        }
        for i in range(n)
    ]
    c = WalCrdt()
    c.fold(ops)
    assert len(c.list_values("body")) == n
    assert len(c.text("body")) == n
