---
sidebar_position: 4
sidebar_label: "Spaces"
---

# starfish-spaces — Overview

`@drakkar.software/starfish-spaces` is a Starfish extension that implements **multi-user spaces**: a roster of members, a shared object tree with per-node access control and optional E2EE, invite / link join flows, revocation, and a sealed request/grant inbox round-trip. It is the generic extraction of the "spaces" feature from `octospaces-sdk`.

---

## Table of contents

1. [Concepts](#concepts)
2. [Quick start](#2-quick-start)
3. [SpaceLayout — parameterizing paths and scopes](#3-spacelayout--parameterizing-paths-and-scopes)
4. [Session](#4-session)
5. [Registry — creating and listing spaces](#5-registry)
6. [Members — invites and join flows](#6-members)
7. [Nodes — the two-axis access model](#7-nodes)
8. [Object tree — pure algorithms](#8-object-tree)
9. [Inbox and resource requests](#9-inbox-and-resource-requests)
10. [Identity links](#10-identity-links)
11. [Server companion](#11-server-companion)
12. [Migration from octospaces-sdk](#12-migration-from-octospaces-sdk)

---

## Concepts

| Concept | Description |
|---|---|
| **Space** | A named container with an owner + member roster, stored at `spaces/{spaceId}/_access`. |
| **Node** | An entry in a space's object tree. Each node has `access` (`'public'` \| `'space'` \| `'invite'`) and `enc` (boolean). |
| **SpaceLayout** | An interface that produces all storage paths and cap scopes. Inject a custom layout for non-standard server configurations; the `defaultSpaceLayout` implements the canonical octospaces structure. |
| **Session** | The central runtime object: identity keys + Starfish clients + resolved layout + namespace constants. |
| **CAS write** | All mutations use compare-and-swap: pull → modify → push with a hash guard. The `runCas` helper retries on `ConflictError` (HTTP 409) up to 3 times. |
| **Space-wide keyring** | One AES-256-GCM keyring per space encrypts all `enc` nodes. Lives at `spaces/{spaceId}/_keyring` (collection `spacekeyring`). |
| **Per-node keyring** | An isolated keyring for `invite+enc` nodes, wrapping the CEK only to the node's own members (not the space-wide key). |
| **Inbox** | Monthly-sharded public-write ring buffer at `inbox/{userId}/{YYYY-MM}`. Anyone may append (signed, no auth cap); only the recipient can pull (member cap). |

---

## 2. Quick start

```typescript
import {
  configureSpaces,
  deriveSession,
  createSpace,
  listSpaces,
} from '@drakkar.software/starfish-spaces'

// (Optional) configure module-level defaults
configureSpaces({ kvAdapter: myAsyncStorage })

// Derive a session from a 12-word seed phrase
const session = await deriveSession(seedWords, {
  baseUrl: 'https://sync.example.com',
  namespace: 'myapp',
})

// Create a space
const { space } = await createSpace(session, { name: 'Engineering' })

// List all joined spaces
const spaces = await listSpaces(session)
```

---

## 3. SpaceLayout — parameterizing paths and scopes

`SpaceLayout` is the seam between the generic domain logic and your application's concrete storage paths. The `defaultSpaceLayout` works for any server configured with the standard octospaces path structure.

```typescript
import { defaultSpaceLayout, type SpaceLayout } from '@drakkar.software/starfish-spaces'

// Custom layout example
const myLayout: SpaceLayout = {
  ...defaultSpaceLayout,
  // Override only what differs
  spacesPull: (userId) => `/pull/v2/user/${userId}/_spaces`,
  spacesPush: (userId) => `/push/v2/user/${userId}/_spaces`,
}

// Inject at session build time
const session = await buildSession({
  userId, keys, clientOpts,
  config: { layout: myLayout },
})
```

All path-returning functions include the `/pull/` or `/push/` verb prefix so they can be passed directly to `StarfishClient.pull()` / `.push()`.

---

## 4. Session

A `Session` carries everything needed to make authenticated requests. Build one from:

- A **derived root identity** — `buildSession({ userId, keys, clientOpts })`
- A **paired device** — `buildLinkedSession({ identity: { userId, keys, capCert }, clientOpts })`
- A **seed phrase** (runs Argon2id) — `deriveSession(seedWords, clientOpts)`

```typescript
import { buildSession } from '@drakkar.software/starfish-spaces'
import type { ClientOpts } from '@drakkar.software/starfish-spaces'

const clientOpts: ClientOpts = {
  baseUrl: 'https://sync.example.com',
  namespace: 'myapp',
  fetch: myTimeoutFetch,   // optional; uses globalThis.fetch if omitted
}

const session = await buildSession({ userId, keys, clientOpts })
// session.layout  — resolved SpaceLayout
// session.contentClient  — authenticated client for space content
// session.accountClient  — authenticated client for personal docs
// session.spacesRegistryClient  — client for the spaces registry
// session.spacesKeyringClient   — client for space-wide keyrings
```

---

## 5. Registry

```typescript
import { createSpace, listSpaces, readSpaceAccess } from '@drakkar.software/starfish-spaces'

// Create a space (owner registers it locally + writes the _access doc)
const { space, spaceEntry } = await createSpace(session, {
  name: 'My Space',
  extra: { short: 'MS', emoji: '🚀' },   // app-specific fields passed through
})

// List all joined spaces from the server
const spaces = await listSpaces(session)

// Read a specific space's access record
const access = await readSpaceAccess(session, spaceId)
// access.owner  — owner userId
// access.members  — array of member userIds
```

---

## 6. Members

```typescript
import {
  inviteMember,
  createSpaceInviteLink,
  acceptSpaceInvite,
  joinSpaceViaLink,
  revokeMember,
} from '@drakkar.software/starfish-spaces'

// Owner: send a direct invite to a member (requires their profile keys)
await inviteMember(session, spaceId, { userId: memberUserId })

// Owner: create a shareable invite link (bearer token)
const { url, token } = await createSpaceInviteLink(session, spaceId, { canWrite: true })

// Member: accept a direct invite (they received a join request in their inbox)
await acceptSpaceInvite(session, spaceId)

// Anyone with the link: join the space
await joinSpaceViaLink(session, token)

// Owner: revoke a member (rotates keyring + submits revocation)
await revokeMember(session, spaceId, { memberUserId })
```

---

## 7. Nodes

Nodes are the entries of a space's object tree. Each node has:
- `access`: `'public'` (world-readable) | `'space'` (all members, default) | `'invite'` (per-node cap)
- `enc`: `true` if the content is E2EE (space keyring for `space` nodes, per-node keyring for `invite` nodes)

```typescript
import { createNode, inviteToNode, acceptNodeInvite } from '@drakkar.software/starfish-spaces'

// Create a space-visible plaintext node
const { node } = await createNode(session, spaceId, {
  type: 'page', title: 'Meeting Notes',
  access: 'space', enc: false,
})

// Create an invite-only E2EE node
const { node: ticket } = await createNode(session, spaceId, {
  type: 'ticket', title: 'Private Issue',
  access: 'invite', enc: true,
})

// Invite a specific user to the node
await inviteToNode(session, spaceId, ticket.id, { userId: requesterUserId })
```

---

## 8. Object tree

Pure algorithms for working with a flat `ObjectNode[]` list:

```typescript
import {
  buildTree, addObject, patchObject, reparentObject,
  reorderObjects, archiveObject, breadcrumbs, subtreeIds,
} from '@drakkar.software/starfish-spaces'

// Build a render tree from the flat index
const tree = buildTree(objects)   // repairs orphans, cycles, drops archived

// Add a new node (returns updated array + the new node)
const { nodes, node } = addObject(objects, { type: 'page', title: 'Hello' }, Date.now())

// Move a node to a new parent
const updated = reparentObject(objects, node.id, parentId, Date.now())
```

---

## 9. Inbox and resource requests

The inbox is a monthly-sharded public-write append log. Anyone can write; only the recipient can read.

```typescript
import {
  pullInbox,
  submitResourceRequest,
  scanResourceRequests,
  acceptResourceRequest,
} from '@drakkar.software/starfish-spaces'

// Owner: scan inbox for incoming requests
const items = await pullInbox(session.spacesRegistryClient, session.userId)

// Requester: submit a request to access a resource
await submitResourceRequest(session, ownerUserId, {
  kind: 'space-join', spaceId,
})

// Owner: scan and accept the request
const reqs = await scanResourceRequests(session, { kind: 'space-join' })
await acceptResourceRequest(session, reqs[0])
```

---

## 10. Identity links

Identity links are credential-less public tokens that advertise a user's Ed25519 + KEM keys with a binding proof. They can be embedded in QR codes or shared links.

```typescript
import {
  myIdentityLink, encodeIdentityLink, decodeIdentityLink,
  verifyIdentityLinkKeys,
} from '@drakkar.software/starfish-spaces'

// Generate your own identity link
const link = await myIdentityLink(session)
const encoded = encodeIdentityLink(link)
const shareUrl = `https://app.example.com/join#${encoded}`

// Verify a received link
const decoded = decodeIdentityLink(encoded)
if (decoded && verifyIdentityLinkKeys(decoded)) {
  // Safe to use decoded.edPub / decoded.kemPub
}
```

---

## 11. Server companion

```typescript
import {
  createSpacesRoleEnricher,
  createSpacesDirectoryServerPlugin,
} from '@drakkar.software/starfish-spaces'
import { createSyncRouter } from '@drakkar.software/starfish-server'

const router = createSyncRouter({
  store,
  roleEnricher: createSpacesRoleEnricher(store),
  plugins: [
    sharingServerPlugin,
    createSpacesDirectoryServerPlugin(),
  ],
})
```

> To combine multiple enrichers, use `composeEnrichers` from `@drakkar.software/starfish-server`.

```typescript
```

`createSpacesRoleEnricher(store, layout?, options?)` reads `spaces/{spaceId}/_access`
and grants the `space:owner` or `space:member` role to authenticated identities. It
wraps the generic `makeRegistryRoleEnricher` from `starfish-sharing`.

**`options.allowTofu`** (default `false`) controls what the enricher does when the
`_access` doc is absent:

| `allowTofu` | Absent `_access` doc | When to use |
|---|---|---|
| `false` (default) | No roles → **Forbidden** | Any read path (normal, batch, cross-space). Safe default: a stale or missing space never looks like an open grant. |
| `true` | Grants `space:owner + space:member` | First-create provisioning flows only (e.g. the `createSpace` path where the owner writes the `_access` doc and immediately reads it back). The caller must already hold the storage-layer write cap; TOFU is only a convenience, not an access bypass. |

**Risk of `allowTofu: true`:** any unauthenticated or misconfigured request that hits an absent `_access` path silently receives full membership of that space. Do **not** use it on any route reachable by untrusted callers — in particular, never on the cross-space batch endpoint.

**Risk of `allowTofu: false`:** a creation flow that reads the `_access` doc before the write completes (race window) will get Forbidden instead of the expected roles. Coordinate the creation write and the first read, or use the account-scoped cap (which covers all space paths) for the write step.

`createSpacesDirectoryServerPlugin(layout?)` is a `ServerPlugin` with an `afterWrite` hook: when a write lands in the `objindex` collection, it extracts `access: 'public'` nodes from the updated index and writes them to `_index/objects/public` — the world-readable object directory.

### Cross-space batch reads

Two additional exports support reading the `_access` document for many spaces in a single
`/batch/pull` request:

**`createSpacesRoleEnricher(store, layout?)`** — use the default (`allowTofu: false`). A missing
`_access` doc yields no roles → the batch entry returns `{ error: "Forbidden" }`, preventing a
caller from "claiming" an unclaimed spaceId by being the first to read it. Never pass
`{ allowTofu: true }` on the batch route: a misconfigured or absent space would silently grant
full membership to whoever reads it first.

**`spacesCollections(layout?)`** — returns the canonical `CollectionConfig[]` for the `spaceaccess`
collection (the `spaces/{spaceId}/_access` registry, gated by `space:member`/`space:owner`). `_keyring`
and `_members` are intentionally excluded. Register these collections alongside
`createSpacesRoleEnricher` on the cross-space batch endpoint:

```ts
import {
  createSpacesRoleEnricher,
  spacesCollections,
} from '@drakkar.software/starfish-spaces'

const router = createSyncRouter({
  store,
  config: {
    version: 1,
    collections: [...appCollections, ...spacesCollections()],
  },
  roleEnricher: createSpacesRoleEnricher(store),  // allowTofu: false by default
})
```

**`readSpaceAccessBatch(session, spaceIds)`** — convenience helper that calls
`session.spacesRegistryClient.batchPullMany("spaceaccess", spaceIds.map(id => ({ spaceId: id })))` and
returns `Map<spaceId, SpaceEntry>`. Entries where the server returns an error (not a member, absent
`_access`) are silently omitted from the map.

```ts
import { readSpaceAccessBatch } from '@drakkar.software/starfish-spaces'

const spaces = await readSpaceAccessBatch(session, ['sp-1', 'sp-2', 'sp-3'])
// { 'sp-1': SpaceEntry, 'sp-3': SpaceEntry }  // sp-2 absent: not a member
```

Python equivalents: `create_spaces_role_enricher` (pass `allow_tofu=False`, which is the default),
`spaces_collections`, `read_space_access_batch`.

---

## 12. Migration from octospaces-sdk

`octospaces-sdk` can be migrated to consume `starfish-spaces` with the following steps:

1. **Add dependency**: `"@drakkar.software/starfish-spaces": "workspace:*"` (or the npm version).

2. **Inject your `SpaceLayout`**: the concrete path strings (which mirror your server's collection registration) stay in octospaces and are passed as `config: { layout: octospacesConceteLayout }` to `buildSession`.

3. **Remove migrated constants**: the id prefixes (`sp-`, `obj-`), `userId` derivation, inbox AAD namespace, and KV key prefix are now in the `starfish-spaces` defaults — delete your copies.

4. **Replace path imports**: `import { spacesPull, objIndexPull, … } from './sync/paths.js'` → `session.layout.spacesPull(…)`, etc.

5. **Remove re-implemented helpers**: delete `sync/account-seal.ts`, `sync/keyed-store.ts`, `spaces/request-verify.ts`, `spaces/identity-link.ts`, `spaces/registry.ts`, `spaces/members.ts`, `spaces/nodes.ts`, `spaces/object-index.ts`, `spaces/resource-requests.ts`, `spaces/object-directory.ts`, `sync/space-access-store.ts`, `sync/space-access.ts`, `sync/node-keyring.ts`, `sync/client.ts`, `sync/identity.ts`, `sync/inbox.ts`.

6. **Move `trusted-adders.ts` + `pairing.ts`**: these have moved to `starfish-identities`. Import `computeOwnerTrustedAdders` from `@drakkar.software/starfish-identities`.

7. **Update the server**: swap the bespoke role enricher + directory projection for `createSpacesRoleEnricher(store)` + `createSpacesDirectoryServerPlugin()` from this package.

The `starfish-spaces` defaults are data-compatible with the existing octospaces wire format — no server migration, no client data migration.
