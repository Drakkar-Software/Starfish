"""The deterministic, op-based CRDT at the heart of ``starfish-wal``.

This is the Python mirror of ``packages/ts/wal/src/crdt.ts``; both fold the same
ops to byte-identical materialized state, locked by
``tests/test-vectors/wal-crdt.json``. The fold is commutative (order-independent)
and idempotent (re-applying an op is a structural no-op), so a server-reordered
or retried op-log converges without a dedup set.

Two CRDT shapes, addressed by name within one document:

* **LWW typed register** (``set`` / ``del``) — objects / scalar fields; the value
  is opaque JSON written whole, highest ``(clock)`` wins, ties broken on replica
  id.
* **RGA sequence** (``ins`` / ``rmv``) — ordered lists, and **text** as a
  sequence of single-character values.
"""

from __future__ import annotations

from typing import Any, Iterable

from .clock import Clock, _cmp_str, clock_greater, compare_clocks

# An op is a JSON dict discriminated by ``t``: "set" | "del" | "ins" | "rmv".
Op = dict[str, Any]


class _Reg:
    __slots__ = ("clock", "value", "deleted")

    def __init__(self, clock: Clock, value: Any, deleted: bool) -> None:
        self.clock = clock
        self.value = value
        self.deleted = deleted


class _Node:
    __slots__ = ("id", "after", "clock", "value", "deleted", "pending")

    def __init__(
        self, id: str, after: str, clock: Clock, value: Any, deleted: bool, pending: bool
    ) -> None:
        self.id = id
        self.after = after
        self.clock = clock
        self.value = value
        self.deleted = deleted
        # True for a tombstone created by a ``rmv`` whose ``ins`` has not yet
        # arrived: its after/clock/value are placeholders the insert fills in.
        self.pending = pending


class WalCrdt:
    """A bag of named LWW registers and named RGA sequences."""

    def __init__(self) -> None:
        self._regs: dict[str, _Reg] = {}
        self._lists: dict[str, dict[str, _Node]] = {}

    # ── ingest ──────────────────────────────────────────────────────────────────

    def apply(self, op: Op) -> None:
        """Apply one op (commutative and idempotent)."""
        kind = op["t"]
        if kind == "set":
            self._apply_reg(op["reg"], op["clock"], op["value"], False)
        elif kind == "del":
            self._apply_reg(op["reg"], op["clock"], None, True)
        elif kind == "ins":
            self._apply_ins(op)
        elif kind == "rmv":
            self._apply_rmv(op)

    def fold(self, ops: Iterable[Op]) -> None:
        for op in ops:
            self.apply(op)

    def _apply_reg(self, reg: str, clock: Clock, value: Any, deleted: bool) -> None:
        cur = self._regs.get(reg)
        # LWW: keep the highest clock; equal clock => identical op => no-op.
        if cur is not None and not clock_greater(clock, cur.clock):
            return
        self._regs[reg] = _Reg(clock, value, deleted)

    def _apply_ins(self, op: Op) -> None:
        nodes = self._lists.setdefault(op["list"], {})
        existing = nodes.get(op["id"])
        if existing is not None:
            # If a ``rmv`` arrived first it left a *pending* tombstone with no
            # real position; the insert now supplies the true after/clock/value
            # (the element stays deleted). This keeps the fold commutative under
            # out-of-order delivery — the placeholder must not own the anchor.
            # A non-pending hit is a verbatim replay => no-op.
            if existing.pending:
                existing.after = op["after"]
                existing.clock = op["clock"]
                existing.value = op["value"]
                existing.pending = False
            return
        nodes[op["id"]] = _Node(op["id"], op["after"], op["clock"], op["value"], False, False)

    def _apply_rmv(self, op: Op) -> None:
        # The remove may be delivered before any insert; create the list so the
        # *pending* tombstone placeholder survives until the insert fills in its
        # real position (see _apply_ins). Its ``after: ""`` never owns the anchor.
        nodes = self._lists.setdefault(op["list"], {})
        node = nodes.get(op["id"])
        if node is None:
            nodes[op["id"]] = _Node(op["id"], "", op["clock"], None, True, True)
            return
        node.deleted = True

    # ── projection ──────────────────────────────────────────────────────────────

    def _list_order(self, nodes: dict[str, _Node]) -> list[_Node]:
        # RGA: siblings sharing an ``after`` anchor are ordered by DESCENDING
        # clock (newest-first); pre-order DFS from the head ("").
        from functools import cmp_to_key

        children: dict[str, list[_Node]] = {}
        for node in nodes.values():
            children.setdefault(node.after, []).append(node)
        for bucket in children.values():
            # Descending clock; break exact-clock ties on the unique element id so
            # the order is total even for malformed ops with decoupled id/clock.
            bucket.sort(
                key=cmp_to_key(
                    lambda a, b: compare_clocks(b.clock, a.clock) or _cmp_str(b.id, a.id)
                )
            )

        # Iterative pre-order DFS (an explicit stack, NOT recursion): a long
        # linear chain — e.g. a multi-thousand-character text run — would
        # otherwise blow Python's recursion limit. Push each bucket reversed so
        # siblings pop in bucket order.
        out: list[_Node] = []
        stack: list[_Node] = list(reversed(children.get("", [])))
        while stack:
            node = stack.pop()
            out.append(node)
            stack.extend(reversed(children.get(node.id, [])))
        return out

    def list_values(self, list_name: str) -> list[Any]:
        """Live element values of a named list, in RGA order."""
        nodes = self._lists.get(list_name)
        if not nodes:
            return []
        return [n.value for n in self._list_order(nodes) if not n.deleted]

    def list_ids(self, list_name: str) -> list[str]:
        """Live element ids of a named list, in RGA order."""
        nodes = self._lists.get(list_name)
        if not nodes:
            return []
        return [n.id for n in self._list_order(nodes) if not n.deleted]

    def text(self, list_name: str) -> str:
        """A named list materialized as a string (1-char element values)."""
        return "".join(v for v in self.list_values(list_name) if isinstance(v, str))

    def get_register(self, reg: str) -> Any:
        cur = self._regs.get(reg)
        if cur is None or cur.deleted:
            return None
        return cur.value

    def materialize(self) -> dict[str, Any]:
        """Project the current document (live registers + lists as arrays)."""
        keys: set[str] = set()
        for reg, st in self._regs.items():
            if not st.deleted:
                keys.add(reg)
        keys.update(self._lists.keys())
        out: dict[str, Any] = {}
        for key in sorted(keys):
            reg = self._regs.get(key)
            if reg is not None and not reg.deleted:
                out[key] = reg.value
            else:
                out[key] = self.list_values(key)
        return out

    # ── snapshot state ──────────────────────────────────────────────────────────

    def list_names(self) -> list[str]:
        """Names of all RGA lists currently present (live or tombstoned)."""
        return sorted(self._lists.keys())

    def export_state(self) -> dict[str, Any]:
        """Export full CRDT state (tombstones included) for a snapshot. Clocks
        are deep-copied so an exported state (and ``clone``) never aliases the
        live document's nested clock dicts."""
        regs = {
            reg: {"clock": dict(st.clock), "value": st.value, "deleted": st.deleted}
            for reg, st in self._regs.items()
        }
        lists = {
            name: [
                {
                    "id": n.id,
                    "after": n.after,
                    "clock": dict(n.clock),
                    "value": n.value,
                    "deleted": n.deleted,
                    "pending": n.pending,
                }
                for n in nodes.values()
            ]
            for name, nodes in self._lists.items()
        }
        return {"v": 1, "regs": regs, "lists": lists}

    def import_state(self, state: dict[str, Any]) -> None:
        """Replace state from a snapshot's ``state`` (bootstrap readers)."""
        self._regs = {
            reg: _Reg(dict(st["clock"]), st["value"], st["deleted"])
            for reg, st in state["regs"].items()
        }
        self._lists = {}
        for name, nodes in state["lists"].items():
            self._lists[name] = {
                n["id"]: _Node(
                    n["id"],
                    n["after"],
                    dict(n["clock"]),
                    n["value"],
                    n["deleted"],
                    n.get("pending", False),
                )
                for n in nodes
            }

    def clone(self) -> "WalCrdt":
        c = WalCrdt()
        c.import_state(self.export_state())
        return c
