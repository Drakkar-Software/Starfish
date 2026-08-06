"""plan_space_mirror — pure create/write/clear partitioning.

Ports all 9 cases from the TS suite (packages/ts/replica/tests/space-plan.test.ts)
1:1 for parity, then adds Python-specific cases (ordering determinism, duplicate
inputs, generator inputs) that the TS version does not need.
"""

from __future__ import annotations

from starfish_replica.space.plan import ExistingSpaceNode, plan_space_mirror

# A five-collection registry, matching the fixture the TS suite uses.
KNOWN = frozenset(
    [
        "user-accounts",
        "user-data",
        "user-strategies",
        "user-accounts-trading",
        "user-settings",
    ]
)


def _node(node_id: str, type_: str) -> ExistingSpaceNode:
    return ExistingSpaceNode(id=node_id, type=type_)


# ── TS parity: the 9 cases from space-plan.test.ts ───────────────────────────


def test_plans_to_create_and_write_every_enabled_collection_when_space_is_empty():
    plan = plan_space_mirror([], ["user-accounts", "user-data"], KNOWN)
    assert sorted(plan.to_create) == ["user-accounts", "user-data"]
    assert sorted(plan.to_write) == ["user-accounts", "user-data"]
    assert plan.to_clear == []


def test_reuses_an_existing_node_no_recreate_still_writes():
    existing = [_node("obj-1", "user-accounts")]
    plan = plan_space_mirror(existing, ["user-accounts"], KNOWN)
    assert plan.to_create == []
    assert plan.to_write == ["user-accounts"]
    assert plan.to_clear == []


def test_clears_a_node_whose_collection_is_no_longer_enabled():
    existing = [_node("obj-1", "user-accounts"), _node("obj-2", "user-settings")]
    plan = plan_space_mirror(existing, ["user-accounts"], KNOWN)
    assert plan.to_write == ["user-accounts"]
    assert plan.to_create == []
    assert plan.to_clear == [_node("obj-2", "user-settings")]


def test_empty_enabled_set_clears_every_existing_node_and_creates_nothing():
    existing = [_node("obj-1", "user-accounts"), _node("obj-2", "user-data")]
    plan = plan_space_mirror(existing, [], KNOWN)
    assert plan.to_create == []
    assert plan.to_write == []
    assert plan.to_clear == existing


def test_ignores_an_unknown_enabled_id():
    plan = plan_space_mirror([], ["user-accounts", "totally-not-a-collection"], KNOWN)
    assert plan.to_create == ["user-accounts"]
    assert plan.to_write == ["user-accounts"]


def test_ignores_an_existing_node_whose_type_is_not_known():
    existing = [_node("obj-1", "some-unrelated-node-type")]
    plan = plan_space_mirror(existing, [], KNOWN)
    assert plan.to_clear == []


def test_a_reenabled_collection_reuses_its_still_present_node():
    existing = [_node("obj-1", "user-settings")]
    plan = plan_space_mirror(existing, ["user-settings"], KNOWN)
    assert plan.to_create == []
    assert plan.to_write == ["user-settings"]
    assert plan.to_clear == []


def test_handles_the_full_default_set_plus_an_opt_in_collection():
    plan = plan_space_mirror(
        [],
        ["user-accounts", "user-data", "user-strategies", "user-accounts-trading"],
        KNOWN,
    )
    assert sorted(plan.to_write) == [
        "user-accounts",
        "user-accounts-trading",
        "user-data",
        "user-strategies",
    ]
    assert plan.to_clear == []


def test_a_fully_independent_known_ids_set_plans_correctly():
    plan = plan_space_mirror([], ["notes", "contacts"], frozenset({"notes", "contacts", "photos"}))
    assert sorted(plan.to_create) == ["contacts", "notes"]
    assert sorted(plan.to_write) == ["contacts", "notes"]


# ── Python-specific additions ────────────────────────────────────────────────


def test_output_order_follows_enabled_ids_order_deterministically():
    # Python sets do not preserve insertion order, so plan.py uses
    # dict.fromkeys. Without that, to_write/to_create order would vary between
    # runs (PYTHONHASHSEED) and make any order-sensitive assertion flaky.
    ids = ["user-settings", "user-accounts", "user-data"]
    plan = plan_space_mirror([], ids, KNOWN)
    assert plan.to_write == ids
    assert plan.to_create == ids


def test_duplicate_enabled_ids_are_collapsed():
    plan = plan_space_mirror([], ["user-accounts", "user-accounts"], KNOWN)
    assert plan.to_write == ["user-accounts"]
    assert plan.to_create == ["user-accounts"]


def test_accepts_generators_not_just_lists():
    # The signature takes Iterable; a caller passing a generator must not have
    # it silently consumed before the second pass over existing_nodes.
    existing = (n for n in [_node("obj-1", "user-settings")])
    enabled = (i for i in ["user-accounts"])
    plan = plan_space_mirror(existing, enabled, KNOWN)
    assert plan.to_create == ["user-accounts"]
    assert plan.to_clear == [_node("obj-1", "user-settings")]


def test_accepts_a_plain_set_for_known_ids():
    plan = plan_space_mirror([], ["notes"], {"notes"})
    assert plan.to_write == ["notes"]


def test_to_clear_preserves_existing_node_order():
    existing = [
        _node("obj-3", "user-strategies"),
        _node("obj-1", "user-accounts"),
        _node("obj-2", "user-data"),
    ]
    plan = plan_space_mirror(existing, [], KNOWN)
    assert [n.id for n in plan.to_clear] == ["obj-3", "obj-1", "obj-2"]


def test_two_nodes_sharing_a_type_both_get_cleared():
    # Degenerate/corrupt space state (a duplicate node for one collection).
    # Only one can be the write target, but BOTH must be cleared when disabled
    # or the duplicate keeps stale plaintext-equivalent content forever.
    existing = [_node("obj-1", "user-accounts"), _node("obj-2", "user-accounts")]
    plan = plan_space_mirror(existing, [], KNOWN)
    assert len(plan.to_clear) == 2


def test_empty_known_ids_makes_everything_a_noop():
    existing = [_node("obj-1", "user-accounts")]
    plan = plan_space_mirror(existing, ["user-accounts"], frozenset())
    assert plan == ([], [], [])


def test_returns_a_named_tuple_that_unpacks():
    to_create, to_write, to_clear = plan_space_mirror([], ["user-data"], KNOWN)
    assert to_create == ["user-data"]
    assert to_write == ["user-data"]
    assert to_clear == []
