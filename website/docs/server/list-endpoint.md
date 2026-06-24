---
sidebar_position: 3
---

# List Endpoint

The list endpoint lets clients discover which documents exist under a collection's prefix — for example, which days have chat messages for a given group, or which user IDs have stored notes.

## How it works

1. A collection opts in by setting `listable: true` in its `CollectionConfig`.
2. The server registers a `GET /list/...` route with the collection's prefix path (everything except the last path parameter).
3. On every request, the server checks the collection's `readRoles`, then queries storage for all document keys under the resolved prefix.
4. The response returns the values of the last path parameter — the part that varies.

## CollectionConfig

```ts
{
  name: "chat",
  storagePath: "chats/{groupId}/{day}",
  readRoles: ["cap:read:chat"],
  writeRoles: ["cap:write:chat"],
  encryption: "none",
  maxBodyBytes: 65536,
  listable: true,   // ← opt in
}
```

## Route pattern

The list route derives from `storagePath` by dropping the last segment:

| `storagePath`              | List route                   | Returns        |
|----------------------------|------------------------------|----------------|
| `chats/{groupId}/{day}`    | `GET /list/chats/:groupId`   | day values     |
| `notes/{userId}`           | `GET /list/notes`            | userId values  |
| `data/{identity}/{bucket}` | `GET /list/data/:identity`   | bucket values  |

## Response

```json
{
  "items": ["2026-04-13", "2026-04-12", "2026-04-11"],
  "hasMore": false
}
```

`items` contains the values of the last path parameter for every document that exists under the prefix. `hasMore` indicates whether more results are available (see [Pagination](#pagination)).

## Pagination

| Query param | Description | Default | Max |
|---|---|---|---|
| `?limit=N` | Number of items to return | 100 | 1000 |
| `?after=<item>` | Return items lexicographically after this value | — | — |

Items are returned in lexicographic order. To paginate:

```ts
// Page 1
const page1 = await client.fetch("/list/chats/group-1?limit=50")
// { items: ["2026-04-01", ..., "2026-04-50"], hasMore: true }

// Page 2 — pick up after the last item from page 1
const lastItem = page1.items.at(-1)          // "2026-04-50"
const page2 = await client.fetch(`/list/chats/group-1?limit=50&after=${lastItem}`)
// { items: ["2026-04-51", ...], hasMore: false }
```

The list endpoint returns only the last-parameter values (keys); a client that
wants each document's content follows up with a per-key pull (or a `/batch/pull`).
When a derived list is small enough to live in one document, prefer the
[projection extension](/extensions/projection) instead — it maintains a single
list document the client pulls in one request, with no per-key fan-out.

## Auth

The list endpoint uses the collection's `readRoles`. The same `roleResolver` and `roleEnricher` callbacks apply.

**Important:** Path parameters that appear in the list route URL are still passed to `roleEnricher`. The last parameter (the one being enumerated) is absent — only the prefix params are available.

```
storagePath: "chats/{groupId}/{day}"
List route:  GET /list/chats/:groupId

roleEnricher receives params: { groupId: "abc" }   ← groupId present
                                                    ← day is NOT present
```

**`self` role behaviour:** If `{identity}` appears in the prefix path (e.g. `data/{identity}/{bucket}`), the `self` role is correctly granted when the URL identity matches the caller. If `{identity}` is the last segment (e.g. `notes/{identity}`), the `self` role is never granted on the list route — since `{identity}` is absent from the URL. This prevents listing all user IDs through a `readRoles: ["self"]` collection.

## Validation constraints

| Rule | Error |
|---|---|
| `listable` with no path params in `storagePath` | `listable requires at least one path parameter` |
| `listable` when the last segment is not a `{param}` | `listable requires the last storagePath segment to be a path parameter` |
| `listable: true` + `appendOnly: { type: "by_timestamp", persist: false }` | `listable cannot be used with appendOnly+persist=false` |
| `listable: true` + `bundle: "..."` | `listable cannot be used with bundle` |

## Python

```python
CollectionConfig(
    name="chat",
    storage_path="chats/{groupId}/{day}",
    read_roles=["cap:read:chat"],
    write_roles=["cap:write:chat"],
    encryption="none",
    max_body_bytes=65536,
    listable=True,
)
```

The list route and response shape are identical to the TypeScript server.

## Next Steps

- [Group Access](/server/group-access) — grant access based on a member list stored in another collection
- [Queuing](/extensions/queuing) — publish change events when documents are pushed
- [Multi-Document Architecture](/data-modeling/multi-document-architecture) — partitioning data across documents
