# Collection Patterns

Common server-side collection configurations and their client-side counterparts. Each pattern defines a specific combination of read/write access, encryption, and TTL that maps to a real use case.

> **Prerequisites:** [SyncManager](03-sync-manager.md), [Integration Patterns](09-integration-patterns.md), [Multi-Document Architecture](18-multi-document-architecture.md)

---

## Pattern 1: Private Vault

**Use case:** One user (or a group sharing a passphrase) syncing encrypted private data across their own devices. This is the default Starfish use case.

**Access:** self-read, self-write, E2E encrypted.

```ts
// server/config.ts
const config: SyncConfig = {
  version: 1,
  collections: [
    {
      name: "data",
      storagePath: "data/{identity}",
      readRoles: ["self"],
      writeRoles: ["self"],
      encryption: "none",       // client handles encryption via SyncManager
      clientEncrypted: true,    // signal to tooling that content is already encrypted
      maxBodyBytes: 1_048_576,  // 1 MB
      allowedMimeTypes: ["application/json"],
    },
  ],
}
```

```ts
// client — derive credentials from a shared passphrase
import { deriveCredentials } from "@drakkar.software/starfish-client/identity"

const creds = await deriveCredentials(passphrase)

const client = new StarfishClient({
  baseUrl: serverUrl,
  auth: () => ({ Authorization: `Bearer ${creds.authToken}` }),
})

const syncManager = new SyncManager({
  client,
  pullPath: `/pull/${creds.userId}/data`,
  pushPath: `/push/${creds.userId}/data`,
  encryptionSecret: creds.encryptionSecret,
  encryptionSalt: creds.encryptionSalt,
})
```

**Properties:**
- Sharing the passphrase = granting full read/write access
- The server stores only encrypted ciphertext — it cannot inspect content
- Any number of devices can sync by deriving the same credentials from the same passphrase
- See [Identity & Key Derivation](./identity) for passphrase generation and credential derivation

---

## Pattern 2: Public Page

**Use case:** An owner publishes curated data that unauthenticated visitors can read (e.g., a public wedding timeline, a product catalog, a public profile).

**Access:** public-read, self-write. No encryption (visitors cannot decrypt).

```ts
// server/config.ts
{
  name: "public-page",
  storagePath: "public/{identity}",
  readRoles: ["public"],   // anyone can read
  writeRoles: ["self"],    // only the owner can write
  encryption: "none",
  maxBodyBytes: 524_288,   // 512 KB
  allowedMimeTypes: ["application/json"],
}
```

```ts
// client — owner push (authenticated)
const ownerSyncManager = new SyncManager({
  client: authenticatedClient,
  pullPath: `/pull/${userId}/public-page`,
  pushPath: `/push/${userId}/public-page`,
  // No encryption — content is intentionally public
})

await ownerSyncManager.push(buildPublicDocument())

// client — visitor read (unauthenticated)
const publicClient = new StarfishClient({ baseUrl: serverUrl })
const publicSyncManager = new SyncManager({
  client: publicClient,
  pullPath: `/pull/${userId}/public-page`,
  pushPath: `/push/${userId}/public-page`,  // push will 403 for unauthenticated callers
})

const result = await publicSyncManager.pull()
renderPage(result.data)
```

**Tips:**
- Use `createDedupFetch` to dedup concurrent visitors pulling the same page
- Set `cacheDurationMs` in the collection config to control server-side HTTP caching
- If the page is large, consider a separate pull-only collection for the public snapshot and a private collection for the source data

---

## Pattern 3: Public Roster (self-write, public-read)

**Use case:** The owner publishes a roster with per-record tokens. Visitors look up their own record by token. Example: RSVP guest list.

**Access:** public-read, self-write. No encryption.

Same server config as Pattern 2 (public-read + self-write). The difference is in the document shape — each record has a unique token so visitors can identify themselves:

```ts
// Owner builds and pushes the roster
interface RosterEntry {
  id: string
  name: string
  token: string  // UUID per entry — shared via private invite link
}

function buildRoster(guests: Guest[]): Record<string, unknown> {
  return {
    timestamp: Date.now(),
    entries: guests.map((g) => ({
      id: g.id,
      name: g.name,
      token: g.rsvpToken ?? crypto.randomUUID(),
    })),
  }
}

await rosterSyncManager.push(buildRoster(guests))
```

```ts
// Visitor reads the roster and finds their entry by token
const { data } = await publicClient.pull("/pull/{userId}/roster")
const roster = data as { entries: RosterEntry[] }
const myEntry = roster.entries.find((e) => e.token === myToken)
```

**Tips:**
- Token links can be QR codes or URL params: `https://app.com/rsvp?token={token}`
- Roster push is cheap — push after every guest list change to keep tokens in sync
- Never put private data (email, diet, notes) in the public roster — use the submission inbox (Pattern 4) for private fields

---

## Pattern 4: Submission Inbox (public-write, self-read)

**Use case:** Visitors submit data that only the owner can read. Example: RSVP responses, contact forms, ratings.

**Access:** self-read, public-write. Short TTL to control storage growth.

```ts
// server/config.ts
{
  name: "inbox",
  storagePath: "inbox/{identity}",
  readRoles: ["self"],    // only the owner reads submissions
  writeRoles: ["public"], // anyone can submit
  encryption: "none",
  maxBodyBytes: 65_536,   // 64 KB — small, structured submissions only
  ttlMs: 30 * 24 * 60 * 60 * 1000,  // auto-expire after 30 days
  allowedMimeTypes: ["application/json"],
}
```

### Submitting (visitor, unauthenticated)

Use `SyncManager.update()` for atomic read-modify-write. This is critical: multiple visitors may submit simultaneously, so each submission must be appended without overwriting others.

```ts
// Visitor submits their RSVP
const unauthClient = new StarfishClient({ baseUrl: serverUrl })
const inboxManager = new SyncManager({
  client: unauthClient,
  pullPath: `/pull/${ownerId}/inbox`,
  pushPath: `/push/${ownerId}/inbox`,
})

await inboxManager.update((current) => {
  const submissions = (current["submissions"] as Submission[] | undefined) ?? []

  // Upsert: replace existing submission by token if present
  const existing = submissions.findIndex((s) => s.token === myToken)
  const newEntry: Submission = {
    token: myToken,
    attending: true,
    diet: "vegetarian",
    submittedAt: Date.now(),
  }

  return {
    ...current,
    submissions:
      existing >= 0
        ? submissions.map((s, i) => (i === existing ? newEntry : s))
        : [...submissions, newEntry],
  }
})
```

`update()` automatically retries on 409 conflicts (default 3 attempts) with exponential backoff, so concurrent submissions are handled safely.

### Reading (owner, authenticated)

```ts
// Owner fetches and applies submissions
const ownerInbox = new SyncManager({
  client: authenticatedClient,
  pullPath: `/pull/${ownerId}/inbox`,
  pushPath: `/push/${ownerId}/inbox`,
})

const { data } = await ownerInbox.pull()
const submissions = (data["submissions"] as Submission[]) ?? []

for (const sub of submissions) {
  const guest = guests.find((g) => g.rsvpToken === sub.token)
  if (guest) applyRsvp(guest, sub)
}
```

**Tips:**
- Token-match submissions to roster entries to prevent spam (submissions without a valid token are ignored at the app level — the server cannot validate tokens)
- The 30-day TTL clears old submissions automatically; adjust based on your use case
- For high-volume inboxes, consider a separate inbox per category to stay under `maxBodyBytes`

---

## Pattern 5: Claim Tracker (public-write, self-read, short TTL)

**Use case:** Visitors claim items from a finite list. Only the owner sees who claimed what. Example: wedding gift registry.

**Access:** self-read, public-write. Shorter TTL than the inbox (claims are processed faster).

```ts
// server/config.ts
{
  name: "claims",
  storagePath: "claims/{identity}",
  readRoles: ["self"],
  writeRoles: ["public"],
  encryption: "none",
  maxBodyBytes: 16_384,   // 16 KB — small claim documents
  ttlMs: 90 * 24 * 60 * 60 * 1000,  // 90 days
  allowedMimeTypes: ["application/json"],
}
```

Same `update()` pattern as the inbox, but the document tracks claimed item IDs:

```ts
// Visitor claims a gift
await claimsManager.update((current) => {
  const claims = (current["claims"] as Claim[] | undefined) ?? []
  return {
    ...current,
    claims: [...claims, { giftId, claimedBy: visitorName, claimedAt: Date.now() }],
  }
})
```

---

## Pattern 6: Group Chat (member-list access, per-day partitioning)

**Use case:** A group messaging channel where access is granted to a specific set of users (not public, not owner-only), messages are stored per day to keep document size bounded, and clients can discover which days have messages.

**Access:** group-member read/write. Membership stored in a separate collection. No encryption (all members can read).

```ts
// server/config.ts
const config: SyncConfig = {
  version: 1,
  collections: [
    {
      name: "chat",
      storagePath: "chats/{groupId}/{day}",
      readRoles: ["group-member"],
      writeRoles: ["group-member"],
      encryption: "none",
      maxBodyBytes: 524_288,   // 512 KB per day
      allowedMimeTypes: ["application/json"],
      listable: true,           // enables GET /list/chats/:groupId
      queue: { topic: "chats.updated", includeParams: true }, // notify on push
    },
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

// Wire the group enricher: reads membership from the ObjectStore
import { createGroupRoleEnricher } from "@drakkar.software/starfish-server"

const router = createSyncRouter({
  store,
  config,
  roleResolver: async (c) => ({ identity: await getUserId(c), roles: [] }),
  roleEnricher: createGroupRoleEnricher({
    store,
    membersPath: "groups/{groupId}/members",
    groupParam: "groupId",
  }),
})
```

```ts
// client — discover available days
const days = await fetchJson(`/list/chats/${groupId}`)
// → { items: ["2026-04-13", "2026-04-12"], hasMore: false }

// client — load today's messages
const today = new Date().toISOString().slice(0, 10) // "2026-04-13"
const daySync = new SyncManager({
  client,
  pullPath: `/pull/chats/${groupId}/${today}`,
  pushPath: `/push/chats/${groupId}/${today}`,
})

// Post a message (append-only via update())
await daySync.update((current) => {
  const messages = (current["messages"] as Message[] | undefined) ?? []
  return {
    ...current,
    messages: [...messages, { id: crypto.randomUUID(), text, author: userId, ts: Date.now() }],
  }
})
```

**Properties:**
- One document per group per day — bounded growth, easy archiving
- `listable: true` lets clients discover which days have messages without guessing
- Access controlled by a member list stored in `groups/{groupId}/members`; admins manage membership with ordinary pushes
- Queue events fire on every push — bridge these to WebSocket/SSE for near-real-time delivery
- Membership changes propagate within the `roleEnricher` cache TTL (default 1 min)

**Tip:** Under high concurrency (many users posting simultaneously), `update()` retries on 409 conflicts handle burst writes. For very active groups (hundreds of concurrent posters), consider a `queueOnly` intake collection + a backend message aggregator to eliminate contention.

See [Group Access](../server/group-access.md) and [List Endpoint](../server/list-endpoint.md) for full API reference.

---

## Pattern 7: Encrypted Group Chat (E2E, per-member keys)

**Use case:** Same as Pattern 6 but with end-to-end encryption. Each member holds their own credentials; non-members (including the server operator) cannot read messages. Members can be added/removed without sharing a master passphrase.

**Access:** group-member read/write. `encryption: "group"` — server stores opaque ciphertext.

```ts
// server/config.ts
const config: SyncConfig = {
  version: 1,
  collections: [
    // Keyring — plaintext, admin-writable, member-readable
    {
      name: "keyring",
      storagePath: "groups/{groupId}/keyring",
      readRoles: ["group-member"],
      writeRoles: ["group-admin"],
      encryption: "none",
      maxBodyBytes: 65_536,
      allowedMimeTypes: ["application/json"],
    },
    // Encrypted chat messages — one document per day
    {
      name: "chat",
      storagePath: "chats/{groupId}/{day}",
      readRoles: ["group-member"],
      writeRoles: ["group-member"],
      encryption: "group",         // client handles E2E encryption
      maxBodyBytes: 524_288,
      allowedMimeTypes: ["application/json"],
      listable: true,
      queue: { topic: "chats.updated", includeParams: true },
    },
    // Group membership
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
```

```ts
// client — member reads and posts a message
import {
  deriveGroupKeyPair,
  createGroupEncryptor,
  type GroupKeyring,
} from "@drakkar.software/starfish-client/group"
import { SyncManager } from "@drakkar.software/starfish-client"

const myKp = await deriveGroupKeyPair(myPassphrase, myUserId)

// Pull keyring (plaintext)
const keyringSync = new SyncManager({ client, pullPath: `/pull/groups/${groupId}/keyring`, ... })
await keyringSync.pull()
const keyringData = keyringSync.getData() as unknown as GroupKeyring

// Create encryptor from keyring
const encryptor = await createGroupEncryptor(keyringData, myUserId, myKp.privateKey)

// Use encryptor for the chat collection
const today = new Date().toISOString().slice(0, 10)
const daySync = new SyncManager({
  client,
  pullPath:  `/pull/chats/${groupId}/${today}`,
  pushPath:  `/push/chats/${groupId}/${today}`,
  encryptor,   // replaces encryptionSecret/encryptionSalt
})

// Post a message (append-only, with conflict retry)
await daySync.update((current) => {
  const messages = (current["messages"] as Message[] | undefined) ?? []
  return {
    ...current,
    messages: [...messages, { id: crypto.randomUUID(), text, author: myUserId, ts: Date.now() }],
  }
})
```

**Properties vs Pattern 6:**
- Server operator cannot read message content — only members with their private keys can decrypt
- Each member uses their own credentials (own `userId`, own auth token)
- Adding a member = admin wraps current GEK for new member's public key (no passphrase sharing)
- Removing a member = admin rotates to a new GEK epoch; removed member retains old-epoch keys but cannot read new messages
- `_epoch` field in each encrypted document allows decrypting documents from any epoch the member had access to

See [Group Encryption](21-group-encryption.md) for the full API and key lifecycle.

---

## Combining Patterns

Real applications often combine several patterns. A typical setup:

| Collection | Access | Encryption | Purpose |
|---|---|---|---|
| `data/{id}` | self r/w | Client E2E | Private app data (Pattern 1) |
| `page/{id}` | public r, self w | None | Public-facing view (Pattern 2) |
| `roster/{id}` | public r, self w | None | Per-guest tokens (Pattern 3) |
| `inbox/{id}` | self r, public w | None | Guest submissions (Pattern 4) |

Push flow:
```
User edits private data
  └─► push to `data/{id}` (encrypted)
  └─► build and push public snapshot to `page/{id}`
  └─► rebuild and push roster to `roster/{id}` (if guests changed)
```

Pull flow:
```
App launches
  └─► pull `data/{id}` → decrypt → restore domain stores
  └─► pull `inbox/{id}` → apply submissions → push updated private data
```

---

## Anonymous Submissions with `update()`

> This section covers atomic anonymous writes in detail. Skip to [Anonymous Submissions](#anonymous-submissions) if you only want the pattern.

### Why `update()` instead of `push()`

`SyncManager.push(data)` sends the full document and requires you to already hold the current `baseHash`. When multiple visitors push simultaneously, the second one always gets a 409 conflict error.

`SyncManager.update(modifier)` handles this automatically:

1. Pulls the current document (gets latest hash)
2. Applies your modifier (append your submission)
3. Pushes with the correct `baseHash`
4. If it gets a 409 (another visitor submitted in the meantime), repeats from step 1

The default of 3 retries handles short bursts of concurrent submissions reliably. For a global event where hundreds of submissions arrive in seconds, increase `maxRetries` on the `SyncManager`.

### Idempotent modifiers

Your modifier **must** be idempotent — it may be called multiple times (once per retry). Use an upsert pattern with a stable identifier (token, UUID, email) instead of always appending:

```ts
// ❌ Wrong — may create duplicates on retry
await manager.update((current) => ({
  ...current,
  submissions: [...(current["submissions"] as unknown[] ?? []), newEntry],
}))

// ✅ Correct — upsert by token
await manager.update((current) => {
  const existing = (current["submissions"] as Submission[] ?? [])
  const idx = existing.findIndex((s) => s.token === newEntry.token)
  return {
    ...current,
    submissions:
      idx >= 0
        ? existing.map((s, i) => (i === idx ? newEntry : s))
        : [...existing, newEntry],
  }
})
```

### Error handling

`update()` throws after exhausting retries. Wrap in try/catch for visitor-facing flows:

```ts
try {
  await inboxManager.update((current) => appendSubmission(current, form))
  showSuccessToast()
} catch (err) {
  if (err instanceof ConflictError) {
    showErrorToast("Too many people submitting at once — please try again.")
  } else {
    showErrorToast("Submission failed. Check your connection and try again.")
  }
}
```

## Next Steps

- [Identity & Key Derivation](11-identity-key-derivation.md) — HKDF-based key derivation for private vaults
- [Multi-Document Architecture](18-multi-document-architecture.md) — URL design and document partitioning
- [Integration Patterns](09-integration-patterns.md) — Push/pull flows and restore-loop prevention
- [Conflict Resolution](07-conflict-resolution.md) — `createUnionMerge` for array merging
