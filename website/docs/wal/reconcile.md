---
sidebar_position: 4
---

# WAL — Reconcile API (auto-generated ops)

Hand-driving `insert` / `removeAt` / `insertText` is the low-level path. The
**reconcile API** is the ergonomic one: you declare the **value you want**, and
`WalDocument` computes the **minimal** CRDT ops to get there by diffing it against
the current state. This is the natural way to connect a UI or a state store to a
WAL document — render from `materialize()`, feed edits back through `update()`.

## The three methods

```ts
doc.update(next)            // reconcile the whole document
doc.setText(list, next)     // reconcile a text list to a string
doc.setList(list, next)     // reconcile a list to an array of values
```

All three **queue** ops (fold locally); call `commit()` to publish. All three are
**no-ops when the value is unchanged** — nothing is queued, and `commit()` returns
`null`.

### `update(next)`

Reconciles a whole plain object:

- **array** values are diffed as RGA lists (`setList`);
- every **other** value is an LWW register, written **only when it changed**
  (structural comparison);
- keys present now but **absent from `next`** are deleted (a register is
  tombstoned; a list is cleared).

```ts
await doc.open()
doc.update({ title: "Hello", tags: ["draft", "wal"] })
await doc.commit()

doc.update({ title: "Hello, world", tags: ["wal"] }) // edit title, drop "draft"
await doc.commit()                                   // only those diffs are appended

doc.materialize() // { tags: ["wal"], title: "Hello, world" }
```

### `setText(list, next)`

A character-level diff of a text list — the ergonomic replacement for
`insertText`. Pass the whole new string; the minimal per-character `ins`/`rmv` ops
are computed for you.

```ts
doc.setText("body", "the quick brown fox")
await doc.commit()
doc.setText("body", "the quick red fox")   // replaces just "brown" → "red"
await doc.commit()
doc.text("body") // "the quick red fox"
```

### `setList(list, next)`

An LCS diff of an array into minimal `ins`/`rmv` ops. Unchanged elements are kept
in place; only genuinely added/removed values produce ops.

```ts
doc.setList("items", ["a", "b", "c"])
await doc.commit()
doc.setList("items", ["a", "x", "c"]) // exactly: remove "b", insert "x"
await doc.commit()
doc.materialize() // { items: ["a", "x", "c"] }
```

## How the diff works

`setList`/`setText` compute a **longest-common-subsequence** match between the
current values and the desired values (structural equality). Then:

- every current element **not** in the LCS is removed (`rmv` by its stable id);
- every desired value **not** in the LCS is inserted (`ins`), anchored after the
  element that precedes it in the final order (a kept element's id, or the
  previously inserted id).

Kept elements **retain their identity** (same RGA id), which is what makes
reconcile convergent: a concurrent edit to a part you didn't touch merges cleanly,
and re-applying the same desired value yields zero ops.

`update` adds a register layer on top: a scalar/object value becomes one
whole-value LWW `set` only when its stable serialization differs from the current
value.

## Convergence & identity

Because kept elements keep their ids, reconcile composes with concurrent editing:

```ts
// Two writers from the same base "ac":
a.setText("body", "abc") // inserts "b" between a and c
b.setText("body", "aXc") // inserts "X" between a and c
// after both commit + pull, both converge to the same order (RGA tie-break),
// keeping the shared "a" and "c" — neither edit is lost.
```

A **reorder** is expressed as remove + insert, so a moved value is re-created with
a new id rather than carrying its identity across the move (inherent to a
value-based diff; an explicit move op is out of scope — see
[CRDT model](/wal/crdt-model)).

## Schema rule: a key is a register **or** a list

The CRDT type of a key is a schema decision. `update` treats an **array** value as
a list and **everything else** as a register. Keep a given key consistently one or
the other across updates — don't send `tags: ["a"]` one time and `tags: "a"` the
next, or you'll switch its container type. For text, use `setText` (a text list is
an array of single characters; it materializes as a char array, so passing a plain
string through `update` would make it a whole-value register, not editable text).

## Wiring to a UI / state store

The pattern is a one-way render + a reconcile on edit:

```ts
// Render
render(doc.materialize())

// On any local edit, hand the whole next value back:
function onEdit(nextDoc: Record<string, Json>) {
  doc.update(nextDoc)
  schedulePush()        // debounced doc.commit()
}

// On remote changes (polling / push / cross-tab), fold and re-render:
async function onRemote() {
  if (await doc.pull()) render(doc.materialize())
}
```

You never compute deltas yourself — the store gives you the desired state, and
reconcile turns it into minimal, convergent CRDT ops.

## Performance

The diff trims the **common prefix and suffix** first and runs the quadratic LCS
only on the differing middle window, so a **localized edit is ~linear** in the
document length — only a wholesale change degrades to `O(m·n)` on the changed
region. Measured (single-character edit):

| Text length | `setText` (localized edit) |
|---|---|
| 1,000 | ~0.9 ms |
| 2,000 | ~2 ms |
| 4,000 | ~3 ms |

(For comparison, a naive full-matrix LCS took ~2,500 ms at 4,000 chars.) For very
large documents, still prefer many small lists (e.g. per-paragraph text) over one
giant string, and watch `maxBodyBytes` — a single reconcile that produces a huge
op-batch may need to be split across commits.
