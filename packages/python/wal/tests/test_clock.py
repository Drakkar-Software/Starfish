from starfish_wal import (
    LamportClock,
    clock_greater,
    compare_clocks,
    derive_replica_id,
)


def _sign(n: int) -> int:
    return (n > 0) - (n < 0)


def test_orders_by_counter_first():
    assert _sign(compare_clocks({"c": 1, "r": "z"}, {"c": 2, "r": "a"})) == -1
    assert clock_greater({"c": 3, "r": "a"}, {"c": 2, "r": "z"})


def test_ties_break_on_replica_id():
    assert _sign(compare_clocks({"c": 2, "r": "a"}, {"c": 2, "r": "b"})) == -1
    assert _sign(compare_clocks({"c": 2, "r": "b"}, {"c": 2, "r": "a"})) == 1


def test_identical_clocks_compare_equal():
    assert compare_clocks({"c": 7, "r": "abc"}, {"c": 7, "r": "abc"}) == 0


def test_lamport_tick_and_observe():
    clk = LamportClock("r1")
    assert clk.tick() == {"c": 1, "r": "r1"}
    assert clk.tick() == {"c": 2, "r": "r1"}
    clk.observe({"c": 10, "r": "other"})
    assert clk.tick() == {"c": 11, "r": "r1"}


def test_replica_id_is_session_unique():
    assert derive_replica_id("pub", "s1") != derive_replica_id("pub", "s2")
