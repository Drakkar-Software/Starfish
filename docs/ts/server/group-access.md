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
| `candidacyPath` | `candidacy_path` | `undefined` / `None` | `storagePath` template for candidacy docs. When absent, candidacy is disabled globally. Example: `"groups/{groupId}/candidacies/{identity}"` |
| `candidacyRole` | `candidacy_role` | `"group-candidate"` | Role granted to pending candidates |
| `candidacyStatusField` | `candidacy_status_field` | `"status"` | Field in the candidacy doc holding the status (`"pending"` / `"accepted"` / `"denied"`) |
| `candidacyEnabledField` | `candidacy_enabled_field` | `"candidacyEnabled"` | Field in the members doc that enables candidacy for that group |
| `candidacyCacheTtlMs` | `candidacy_cache_ttl_ms` | same as `cacheTtlMs` | Candidacy doc cache TTL (ms). Set to `0` to disable |

## Caching

Membership lookups hit the ObjectStore on every request without caching, which adds latency. The enricher uses an in-memory cache keyed by group ID to avoid repeated reads:

- Default TTL: **1 minute** (`cacheTtlMs: 60_000`)
- After the TTL expires the next request re-reads from storage
- Cache is per-enricher-instance (not shared across server restarts)
- Set `cacheTtlMs: 0` if you need membership changes to take effect immediately

## Owner-managed whitelist

The enricher is not limited to group chat. Any user can maintain a list of identities who are allowed to access their own collection — a whitelist they alone control.

**Encryption is optional.** Group access control and group encryption are independent features. You can gate a collection behind a membership list without any client-side encryption.

### How owner control works

The `"self"` role is automatically granted when the `{identity}` path parameter in a `storagePath` matches the authenticated user's identity. Use this on the whitelist collection so only the owner can read and write it. The protected collection uses a custom role (e.g. `"whitelisted"`) that the enricher grants to anyone in the list.

Your `roleResolver` does not need to return any special role — `"self"` is injected by the router automatically:

```ts
async function roleResolver(c: Context): Promise<AuthResult> {
  const token = c.req.header("Authorization")?.replace("Bearer ", "")
  const { userId } = await verifyToken(token)
  return { identity: userId, roles: [] }  // "self" is added automatically by the router
}
```

### Collection config

```ts
// W — whitelist: only the owner (ownerId == identity) can read/write
{
  name: "whitelist",
  storagePath: "owners/{ownerId}/whitelist",  // {ownerId} triggers "self" check
  readRoles: ["self"],
  writeRoles: ["self"],
  encryption: "none",
  maxBodyBytes: 65_536,
  allowedMimeTypes: ["application/json"],
},
// A — protected data: only users listed in W can access
{
  name: "restricted",
  storagePath: "owners/{ownerId}/restricted",
  readRoles: ["whitelisted"],
  writeRoles: ["whitelisted"],
  encryption: "none",
  maxBodyBytes: 1_048_576,
  allowedMimeTypes: ["application/json"],
},
```

### Enricher config

```ts
const whitelistEnricher = createGroupRoleEnricher({
  store,
  membersPath: "owners/{ownerId}/whitelist",  // reads from collection W
  groupParam: "ownerId",                       // URL param to resolve the path
  role: "whitelisted",                         // role granted if identity is in the list
})
```

If you already have a group enricher, compose both in a single `roleEnricher`:

```ts
roleEnricher: async (auth, params) => [
  ...(await groupEnricher(auth, params)),
  ...(await whitelistEnricher(auth, params)),
],
```

### Access flow

1. Owner pushes whitelist: `{ "members": ["alice", "bob"] }`
2. Alice requests collection A → enricher reads W, finds "alice" → grants `"whitelisted"` → **200**
3. Charlie requests collection A → not in W → no `"whitelisted"` role → **403**
4. Owner removes Alice from W → after cache TTL, Alice gets **403**

To make revocations take effect immediately, set `cacheTtlMs: 0`.

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

## Group candidacy

When `candidacyPath` is set, users can _apply_ to join a group. An admin then accepts or denies the application. Accepted candidates must still be added to the members document manually — there is no automatic promotion.

### How it works

```
User pushes { status: "pending", message: "..." } to candidacy collection
  → enricher checks members doc: user not a member
  → enricher checks candidacyEnabled in members doc: true
  → enricher reads candidacy doc: status == "pending"
  → grants "group-candidate" role
Admin reviews candidacy list, accepts user:
  → admin pushes { status: "accepted" } to candidacy doc
  → admin adds user identity to members doc
  → on next request, user is in members → granted "group-member"
```

### Setup

Add a candidacy collection and enable `candidacyPath` on the enricher:

```ts
// TypeScript
const config: SyncConfig = {
  version: 1,
  collections: [
    // existing chat and members collections...
    {
      name: "candidacy",
      storagePath: "groups/{groupId}/candidacies/{identity}",
      readRoles: ["group-admin", "self"],   // admin sees all; applicant sees own
      writeRoles: ["group-admin", "self"],  // admin updates status; user submits application
      encryption: "none",
      maxBodyBytes: 4_096,
      allowedMimeTypes: ["application/json"],
      listable: true,                       // admin can list all applications
    },
  ],
}

const enricher = createGroupRoleEnricher({
  store,
  membersPath: "groups/{groupId}/members",
  groupParam: "groupId",
  candidacyPath: "groups/{groupId}/candidacies/{identity}",
})
```

```python
# Python
config = SyncConfig(version=1, collections=[
    # existing chat and members collections...
    CollectionConfig(
        name="candidacy",
        storagePath="groups/{groupId}/candidacies/{identity}",
        readRoles=["group-admin", "self"],
        writeRoles=["group-admin", "self"],
        encryption="none",
        maxBodyBytes=4_096,
        listable=True,
    ),
])

enricher = create_group_role_enricher(GroupRoleEnricherOptions(
    store=store,
    members_path="groups/{groupId}/members",
    group_param="groupId",
    candidacy_path="groups/{groupId}/candidacies/{identity}",
))
```

### Members document with candidacy toggle

Enable candidacy for a specific group by adding `candidacyEnabled: true` to the members document. Without this field (or when it is `false`), the enricher skips candidacy lookups entirely — even if `candidacyPath` is set globally.

```json
{
  "members": ["alice", "bob"],
  "candidacyEnabled": true
}
```

The group admin controls this field by pushing an updated members document.

### Applying to join a group

A user submits an application by pushing to their own candidacy document. The `{identity}` placeholder in the `storagePath` matches the authenticated user's identity, which triggers the built-in `"self"` role:

```ts
// User "charlie" applies to group-1
await candidacySync.update(() => ({
  status: "pending",
  message: "I'd like to join the team!",
}))
// Pushes to: groups/group-1/candidacies/charlie
```

While the application is `"pending"`, the enricher grants `"group-candidate"` to that user. This role can be used to allow candidates to read a welcome or instructions document, but they cannot access member-only collections.

### Accepting and denying applications

Admins push an updated status to the candidacy document:

```ts
// Admin accepts charlie
await candidacySync.update((current) => ({ ...current, status: "accepted" }))

// Admin must also add charlie to the members document for member access to take effect
await membersSync.update((current) => ({
  ...current,
  members: [...(current.members ?? []), "charlie"],
}))

// Admin denies dave
await candidacySync.update((current) => ({ ...current, status: "denied" }))
```

Only `"pending"` status grants the `"group-candidate"` role. `"accepted"` and `"denied"` grant nothing — the user stays without roles until actually added to the members list.

### Listing pending applications (admin)

Because the candidacy collection is `listable: true` and the admin has `"group-admin"` in their roles, they can list all candidacy documents for a group:

```ts
// GET /list/groups/group-1/candidacies
// Returns all applicant identities as items
```

### Re-applying after denial

A denied user can re-push `{ status: "pending" }` since `"self"` role grants write access to their own candidacy document. This re-grants `"group-candidate"` but does not grant `"group-member"`. If you want to prevent re-application after denial, add a `fieldPermissions` rule on the `status` field restricting writes to `"group-admin"` only. Note that `fieldPermissions` is static configuration — it applies from the very first push, which means the applicant cannot set their own initial `status`. You would need to handle the initial status server-side (e.g. via an admin action) or by treating an absent `status` field as pending in your application logic.

### Disabling candidacy

- **Globally**: remove `candidacyPath` from the enricher options. No candidacy lookups run.
- **Per group**: set `candidacyEnabled: false` (or remove the field) in that group's members document. Other groups are unaffected.

## Limitations

- **No real-time push** — Starfish is poll-based. For chat-like UX, connect the queue system to a WebSocket server that notifies clients when a `chats/*` document changes.
- **High-concurrency appending** — many users posting to the same day-document causes 409 conflicts and `update()` retries. For very active groups, consider a `queueOnly` intake collection + a custom backend aggregator.
- **Cache invalidation** — membership changes are not immediately visible to the enricher. The default 1-minute TTL is a trade-off between latency and consistency.

## Encrypted group chat

For end-to-end encrypted groups where the server operator cannot read messages, use `encryption: "group"` on the chat collection. This works identically to the patterns above on the server side — the enricher still grants `"group-member"` based on the membership document; the difference is that the `SyncManager` uses a `GroupEncryptor` on the client side instead of a shared passphrase.

Key differences from unencrypted group chat:

| | Unencrypted (Pattern 6) | Encrypted (Pattern 7) |
|---|---|---|
| Server sees messages | Yes | No — opaque ciphertext only |
| Members share a secret | No | No — each member has own key pair |
| Revocation | Remove from member list | Remove from member list **and** rotate GEK epoch |
| Key derivation | n/a | Deterministic from passphrase via SHA-256 + X25519 |

Add a `keyring` collection (plaintext, admin-write, member-read) alongside the encrypted chat collection:

```ts
{
  name: "keyring",
  storagePath: "groups/{groupId}/keyring",
  readRoles: ["group-member"],
  writeRoles: ["group-admin"],
  encryption: "none",
  maxBodyBytes: 65_536,
  allowedMimeTypes: ["application/json"],
},
{
  name: "chat",
  storagePath: "chats/{groupId}/{day}",
  readRoles: ["group-member"],
  writeRoles: ["group-member"],
  encryption: "group",   // <-- E2E encrypted
  maxBodyBytes: 524_288,
  allowedMimeTypes: ["application/json"],
  listable: true,
},
```

See [Group Encryption](../client/21-group-encryption.md) for the full client-side API (key pair derivation, keyring creation, member addition, epoch rotation).

## Next Steps

- [List Endpoint](list-endpoint.md) — discover which documents exist
- [Queue](queue.md) — react to pushes server-side
- [Collection Patterns](../client/19-collection-patterns.md) — more access control patterns
- [Group Encryption](../client/21-group-encryption.md) — E2E encrypted group collections
