# Group-Based Access Control

Starfish's `roleEnricher` hook lets you grant roles based on application data — including group membership stored in another Starfish collection. The built-in `createGroupRoleEnricher` makes this pattern easy to wire up.

## Overview

A `GroupRoleEnricher` reads a membership document from the ObjectStore, checks whether the authenticated user's identity appears in the member list, and grants a configurable role if so.

```
Request arrives → roleResolver → roleEnricher reads members doc → grants "group-member" → auth check
```

## Members document format

Store a standard Starfish document whose `data` field contains a list of identity strings:

```json
{ "members": ["alice", "bob", "charlie"] }
```

Push this document using any Starfish client. The enricher reads the `data.members` array and checks for membership. The field name (`"members"`) is configurable.

## Setup (TypeScript)

```ts
import {
  createSyncRouter,
  createGroupRoleEnricher,
  type SyncConfig,
  type CollectionConfig,
} from "@drakkar.software/starfish-server"

// 1. Define collections
const config: SyncConfig = {
  version: 1,
  collections: [
    // Chat messages — one document per group per day
    {
      name: "chat",
      storagePath: "chats/{groupId}/{day}",
      readRoles: ["group-member"],
      writeRoles: ["group-member"],
      encryption: "none",
      maxBodyBytes: 524_288,
      allowedMimeTypes: ["application/json"],
      listable: true,
    },
    // Group membership — managed by admins
    {
      name: "group-members",
      storagePath: "groups/{groupId}/members",
      readRoles: ["group-admin"],
      writeRoles: ["group-admin"],
      encryption: "none",
      maxBodyBytes: 65_536,
      allowedMimeTypes: ["application/json"],
    },
  ],
}

// 2. Create the enricher
const enricher = createGroupRoleEnricher({
  store,                                   // the same ObjectStore used by the router
  membersPath: "groups/{groupId}/members", // where membership docs live
  groupParam: "groupId",                   // which URL param identifies the group
})

// 3. Wire into the router
const router = createSyncRouter({
  store,
  config,
  roleResolver: async (c) => {
    // Your auth logic: validate JWT, API key, session, etc.
    const token = c.req.header("Authorization")?.replace("Bearer ", "")
    const { userId, roles } = await verifyToken(token)
    return { identity: userId, roles }
  },
  roleEnricher: enricher,
})
```

## Setup (Python)

```python
from starfish_server import (
    create_sync_router,
    SyncRouterOptions,
    SyncConfig,
    CollectionConfig,
    GroupRoleEnricherOptions,
    create_group_role_enricher,
)

config = SyncConfig(version=1, collections=[
    CollectionConfig(
        name="chat",
        storage_path="chats/{groupId}/{day}",
        read_roles=["group-member"],
        write_roles=["group-member"],
        encryption="none",
        max_body_bytes=524_288,
        listable=True,
    ),
    CollectionConfig(
        name="group-members",
        storage_path="groups/{groupId}/members",
        read_roles=["group-admin"],
        write_roles=["group-admin"],
        encryption="none",
        max_body_bytes=65_536,
    ),
])

enricher = create_group_role_enricher(GroupRoleEnricherOptions(
    store=store,
    members_path="groups/{groupId}/members",
    group_param="groupId",
))

router = create_sync_router(SyncRouterOptions(
    store=store,
    config=config,
    role_resolver=role_resolver,
    role_enricher=enricher,
))
```

## Options

| Option (TS) | Option (Python) | Default | Description |
|---|---|---|---|
| `store` | `store` | — | The ObjectStore to read membership docs from |
| `membersPath` | `members_path` | — | `storagePath` template for the members doc (e.g. `"groups/{groupId}/members"`) |
| `groupParam` | `group_param` | — | URL path param that identifies the group (e.g. `"groupId"`) |
| `membersField` | `members_field` | `"members"` | Field name inside `data` holding the member list |
| `role` | `role` | `"group-member"` | Role granted to members |
| `cacheTtlMs` | `cache_ttl_ms` | `60000` | Membership cache TTL (ms). Set to `0` to disable |

## Caching

Membership lookups hit the ObjectStore on every request without caching, which adds latency. The enricher uses an in-memory cache keyed by group ID to avoid repeated reads:

- Default TTL: **1 minute** (`cacheTtlMs: 60_000`)
- After the TTL expires the next request re-reads from storage
- Cache is per-enricher-instance (not shared across server restarts)
- Set `cacheTtlMs: 0` if you need membership changes to take effect immediately

## Managing membership

Membership documents are ordinary Starfish documents — push them with any client:

```ts
// Admin adds a member (TypeScript client)
await membersSync.update((current) => {
  const existing = (current["members"] as string[] | undefined) ?? []
  return {
    ...current,
    members: [...new Set([...existing, newMemberId])],
  }
})

// Admin removes a member
await membersSync.update((current) => {
  const existing = (current["members"] as string[] | undefined) ?? []
  return {
    ...current,
    members: existing.filter((id) => id !== removedMemberId),
  }
})
```

Members see changes after the cache TTL elapses. To propagate membership changes faster, reduce `cacheTtlMs` — or set it to `0` at the cost of a storage read on every request.

## The full chat collection pattern

Combining the list endpoint and group role enricher gives a complete chat backend:

| Collection | storagePath | readRoles | writeRoles | Use |
|---|---|---|---|---|
| `chat` | `chats/{groupId}/{day}` | `["group-member"]` | `["group-member"]` | Messages per day |
| `group-members` | `groups/{groupId}/members` | `["group-admin"]` | `["group-admin"]` | Membership roster |

Client flow:
1. **List available days** — `GET /list/chats/:groupId` → `{ items: ["2026-04-13", ...] }`
2. **Pull messages** — `GET /pull/chats/:groupId/:day`
3. **Post a message** — `POST /push/chats/:groupId/:day` (pull → append → push with retry)
4. **Stay updated** — poll via `startAdaptivePolling`, or bridge queue events to WebSocket

See [List Endpoint](list-endpoint.md) for details on discovery and pagination.

## Limitations

- **No real-time push** — Starfish is poll-based. For chat-like UX, connect the queue system to a WebSocket server that notifies clients when a `chats/*` document changes.
- **High-concurrency appending** — many users posting to the same day-document causes 409 conflicts and `update()` retries. For very active groups, consider a `queueOnly` intake collection + a custom backend aggregator.
- **Cache invalidation** — membership changes are not immediately visible to the enricher. The default 1-minute TTL is a trade-off between latency and consistency.

## Next Steps

- [List Endpoint](list-endpoint.md) — discover which documents exist
- [Queue](queue.md) — react to pushes server-side
- [Collection Patterns](../client/19-collection-patterns.md) — more access control patterns
