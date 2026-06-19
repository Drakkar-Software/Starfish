> ⚠️ **Deprecated.** The Python implementation of Starfish is no longer maintained in
> parity with the TypeScript packages and will be **removed in a future release**.
> Use the TypeScript `@drakkar.software/starfish-*` packages instead.

# starfish-wal (Python)

Cross-language CRDT core for the [Starfish](https://github.com/Drakkar-Software/starfish)
write-ahead-log document model.

This package ships the deterministic clock + fold that mirrors the TypeScript
`@drakkar.software/starfish-wal` package and conforms to the shared vectors in
`tests/test-vectors/wal-crdt.json`. The fold is commutative, idempotent, and
byte-identical across languages:

- **LWW typed register** (`set` / `del`) — objects / scalar fields,
- **RGA sequence** (`ins` / `rmv`) — ordered lists,
- **text** — an RGA of single characters.

```python
from starfish_wal import WalCrdt

crdt = WalCrdt()
crdt.fold([
    {"t": "set", "reg": "title", "clock": {"c": 1, "r": "a"}, "value": "Hello"},
    {"t": "ins", "list": "body", "id": "1@a", "after": "", "clock": {"c": 2, "r": "a"}, "value": "h"},
    {"t": "ins", "list": "body", "id": "2@a", "after": "1@a", "clock": {"c": 3, "r": "a"}, "value": "i"},
])
crdt.materialize()  # {"body": ["h", "i"], "title": "Hello"}
crdt.text("body")   # "hi"
```

The client document-log layer (`WalDocument`: commit / materialize / snapshot)
currently ships in the TypeScript package; Python parity is planned.

Full reference: [`docs/ts/wal/01-overview.md`](../../../docs/ts/wal/01-overview.md)
