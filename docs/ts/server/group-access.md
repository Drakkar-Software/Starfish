# Group & Shared-Collection Access

Starfish 3.0's default authenticator (`createCapCertRoleResolver`) does cap-cert validation, request-signature verification, replay protection, and revocation lookup — and synthesizes the per-request role set from the cap-cert's scope. **Sharing a collection with other people is done with member capability certificates** (`@drakkar.software/starfish-sharing`): the owner mints a signed `member` cap per recipient. `roleEnricher` remains available to layer *application-level* roles (entitlements, tenant/team RBAC, …) on top of the cap-cert baseline.

> **Removed in 3.0:** the built-in `createGroupRoleEnricher` (server-evaluated `groups/{groupId}/members` lists + candidacy). Authorization now flows from signed caps, not server-held membership lists. See the [migration guide](../../migration/v2-to-v3.md#removed-group-role-enricher) for the mapping. `composeEnrichers` and the entitlement enricher are unchanged.

> **Prerequisites:** [Capability Certificates](../client/25-capability-certs.md), [Config Endpoint](config-endpoint.md)

## How the pieces fit

```
Request arrives
  └─ roleResolver:  createCapCertRoleResolver({ plugins: [...] })
        verifies the cap-cert + request signature + nonce + revocation, then
        returns:
          { identity = <issUserId | subUserId>,
            roles    = ["cap:read:notes", "cap:write:notes",
                        "delegated:<issUserId>:notes"?,    // member caps only
                        "self"] }
  └─ roleEnricher:  your custom enricher(s), entitlement enricher, …   (optional)
        reads application data from the store and returns extra role strings
  └─ effective roles = resolver-roles ∪ enricher-roles
  └─ readRoles / writeRoles check
```

The cap-cert-derived roles use the namespace `cap:<op>:<collection>` (and, for `kind: "member"` caps only, also `delegated:<issuerUserId>:<collection>`). Enricher roles use whatever namespace you choose — `team-member`, `entitlement:premium-package-1`, etc. Both kinds live in the same role set; `readRoles` / `writeRoles` are plain string arrays that match either.

## Wiring the default resolver

```ts
import {
  createSyncRouter,
  createCapCertRoleResolver,
  createInMemoryNonceCache,
  createInMemoryRevocationStore,
} from "@drakkar.software/starfish-server"
import { identitiesServerPlugin } from "@drakkar.software/starfish-identities"
import { sharingServerPlugin } from "@drakkar.software/starfish-sharing"

const router = createSyncRouter({
  store,
  config,
  roleResolver: createCapCertRoleResolver({
    nonceCache: createInMemoryNonceCache(),
    revocationStore: createInMemoryRevocationStore(),
    // Per-kind cap validators live in the extensions. Under strict-kind
    // dispatch (the default) a `device` / `member` cap is rejected 401
    // unless its plugin is installed here.
    plugins: [identitiesServerPlugin, sharingServerPlugin],
    allowAnonymous: true,           // anonymous callers get { identity: "", roles: ["public"] }
  }),
})
```

`createCapCertRoleResolver` is the v3 default. For non-cap-cert auth (e.g. tying Starfish identities to an existing OAuth provider) you can still pass any function with the `(c: Context) => Promise<AuthResult>` shape — the enricher pipeline does not care which resolver feeds it.

## Pattern 1 — share a collection with a member (member caps)

The owner mints a **`kind: "member"` cap** for the would-be member. The recipient's `auth.identity` stays their own userId (member caps preserve identity); the cap synthesizes a `delegated:<issuerUserId>:<collection>` role that the collection config opts into. This is the canonical way to grant another user access to a collection.

```ts
// 1. Issuer (`alice-userid`) mints a member cap on her device
import { mintMemberCap, scopes, addMemberEntry } from "@drakkar.software/starfish-sharing"
import { addRecipient } from "@drakkar.software/starfish-keyring"

const bobCap = await mintMemberCap(
  alice.keys.edPriv,
  alice.keys.edPub,
  { edPubHex: bob.device.edPub, kemPubHex: bob.device.kemPub, userIdHex: bob.userId },
  "shared-team",                    // the single collection this cap grants
  scopes.writer("shared-team"),     // {ops:[read,list,write], paths:["shared-team/**","!shared-team/_keyring","!shared-team/_members"]}
)

// 2. (optional) record Bob in the owner-only members directory for your UI
await addMemberEntry(client, "shared-team", bobCap, { label: "Bob" })

// 3. for an E2E (`encryption: "delegated"`) collection, wrap the CEK for Bob
await addRecipient(client, "shared-team", { subKem: bob.device.kemPub }, aliceAdderKeys)

// Bob installs `bobCap` alongside his own root identity and sends it as the
// `Authorization: Cap` header on every request.
```

```ts
// Server-side: the collection allows access to anyone Alice has delegated to
{
  name: "shared-team",
  storagePath: "shared-team/{itemId}",
  readRoles:  ["delegated:alice-userid:shared-team", "cap:read:shared-team"],
  writeRoles: ["delegated:alice-userid:shared-team"],
  encryption: "delegated",
  maxBodyBytes: 262_144,
  allowedMimeTypes: ["application/json"],
}
```

Walk-through of a request:

1. Bob's client sends `Authorization: Cap <base64(bobCap)>` + signed request headers.
2. `createCapCertRoleResolver` validates Bob's cap (`sharingServerPlugin` enforces member-cap shape). It is `kind: "member"` issued by `alice-userid`, so:
   - `auth.identity = bob.userId` (member caps keep the subject's identity).
   - `auth.roles    = ["cap:read:shared-team", "cap:list:shared-team", "cap:write:shared-team", "delegated:alice-userid:shared-team", "self"]`.
3. The `shared-team` collection's `writeRoles` contains `"delegated:alice-userid:shared-team"` — match → 200.

No enricher is needed; the cap-cert resolver does all the work. The owner revokes by revoking the cap's `nonce` (and, for E2E, rotating the keyring epoch). See [Multi-Recipient Delegated Encryption](../client/23-multi-recipient-delegated.md).

## Pattern 2 — group chat with member caps

A "team chat" is Pattern 1 repeated for each participant. There is **no server-side membership roster** in 3.0 — every participant holds a member cap minted by the room owner, and the owner-only `<col>/_members` directory is just an audit/UI index (`listMembers`), never consulted for authorization.

```ts
const config: SyncConfig = {
  version: 1,
  collections: [
    {
      name: "chat",
      storagePath: "chats/{groupId}/{day}",
      readRoles:  ["delegated:owner-userid:chat", "cap:read:chat"],
      writeRoles: ["delegated:owner-userid:chat", "cap:write:chat"],
      encryption: "delegated",      // each member's KEM pubkey is a keyring recipient
      maxBodyBytes: 524_288,
      allowedMimeTypes: ["application/json"],
      listable: true,
    },
  ],
}

// For each participant: mint a writer cap + add them as a keyring recipient.
for (const member of participants) {
  const cap = await mintMemberCap(
    owner.keys.edPriv, owner.keys.edPub,
    { edPubHex: member.edPub, kemPubHex: member.kemPub, userIdHex: member.userId },
    "chat", scopes.writer("chat"),
  )
  await addMemberEntry(client, "chat", cap, { label: member.label })
  await addRecipient(client, "chat", { subKem: member.kemPub }, owner.adderKeys)
  // deliver `cap` to the member out-of-band (paste / QR / file)
}
```

> **Bulk membership is linear.** Each participant costs one cap mint + one keyring wrap; there is no single "members list" that admits N people at once. For small/medium groups this is fine. If you need list-based bulk membership, write your own `RoleEnricher` (see [Layering custom roles](#layering-custom-application-roles)) — Starfish no longer ships one.

Client flow is unchanged: list days (`GET /list/chats/:groupId`), pull a day, append-and-push a message, poll for updates. For E2E confidentiality the keyring at `chats/{groupId}/_keyring` gates plaintext; the cap gates HTTP access. See [24. Pairing](../client/24-pairing.md) for how each member's device gets its key pair.

## Pattern 3 — request-to-join (application-level recipe)

3.0 ships **no built-in invitation/request flow**. The capability model lets you build one with ordinary collections and no server code:

```
1. Invitee pushes  <col>/_requests/{subUserId} = { edPub, kemPub, subUserId, message }
   to a plain `encryption:"none"` collection gated by the built-in "self" role
   (so a requester can only write their own slot).
2. Owner lists <col>/_requests, vets each request out-of-band, then for approved ones:
       mintMemberCap(ownerEd, ownerEdPub, invitee, col, scopes.writer(col))
       addMemberEntry(client, col, cap, { label })
       addRecipient(client, col, { subKem: invitee.kemPub }, ownerAdderKeys)
3. Owner delivers the signed cap to the invitee out-of-band (or writes it to a
   <col>/_grants/{subUserId} doc the requester can read). The invitee imports it
   and starts syncing.
```

```ts
// Request collection — invitees write only their own slot via the "self" role
{
  name: "join-requests",
  storagePath: "shared-team/_requests/{identity}",
  readRoles:  ["delegated:alice-userid:shared-team"],   // owner reviews
  writeRoles: ["self"],                                  // invitee writes own slot
  encryption: "none",
  maxBodyBytes: 4_096,
  allowedMimeTypes: ["application/json"],
  listable: true,
}
```

Authorization still flows entirely through the cap the owner mints — the request document is just a vetting inbox, never a grant.

## Layering custom application roles

`roleEnricher` composes app-level roles on top of the cap baseline. Starfish no longer ships a group-membership enricher, but `composeEnrichers` merges any enrichers you write:

```ts
import { composeEnrichers, type RoleEnricher } from "@drakkar.software/starfish-server"
import { createEntitlementRoleEnricher } from "@drakkar.software/starfish-entitlements"

// Your own RBAC — e.g. read a tenant roster you already maintain
const teamEnricher: RoleEnricher = async (auth, params) =>
  (await isTeamMember(auth.identity, params.teamId)) ? ["team-member"] : []

const router = createSyncRouter({
  store,
  config,
  roleResolver: createCapCertRoleResolver({ nonceCache, revocationStore, plugins: [sharingServerPlugin] }),
  roleEnricher: composeEnrichers(teamEnricher, createEntitlementRoleEnricher({ store })),
})
```

A custom enricher is the place to re-implement list-based membership if your application genuinely needs the server to be the authority (the trade-off the old group enricher made): read your membership document, check `auth.identity`, return a role. Authorization for E2E data still requires the recipient to hold the keyring CEK.

## Removing a member

1. **Revoke the cap** — append its `nonce` to `_revocations/{ownerUserId}` (root-signed); the resolver rejects it after the next revocation-store refresh.
2. **Rotate the keyring epoch** for E2E collections — otherwise the removed member can still decrypt historical documents they previously had access to.
3. (optional) `removeMemberEntry(client, col, nonce)` to drop them from the audit directory.

`revokeAndRotate` in `@drakkar.software/starfish-keyring` performs steps 1–2 in the safe order.

## Limitations

- **No real-time push** — Starfish is poll-based. For chat-like UX, connect the queue system to a WebSocket server that notifies clients when a `chats/*` document changes.
- **High-concurrency appending** — many users posting to the same day-document via a regular collection causes 409 conflicts and `update()` retries. For very active groups, use an append-only intake collection (`appendOnly: { type: "by_timestamp" }`) — appends never conflict — or an `appendOnly: { type: "by_timestamp", persist: false }` queue-only intake plus a custom backend aggregator.
- **No server-side membership list** — access is per-cap. Bulk/list membership and self-service request-to-join are application patterns (above), not built-ins.

## Next Steps

- [Capability Certificates](../client/25-capability-certs.md) — cap-cert schema + the `delegated:<issUserId>:<collection>` role
- [Multi-Recipient Delegated Encryption](../client/23-multi-recipient-delegated.md) — pair `delegated:` roles with E2E encryption
- [Pairing](../client/24-pairing.md) — bootstrap, QR, and relay flows
- [Sharing](../sharing/01-overview.md) — `mintMemberCap`, scope presets, the `_members` directory
- [Entitlements](../entitlements/01-overview.md) — feature-slug roles composed alongside custom RBAC
- [List Endpoint](list-endpoint.md) — discover documents under a collection prefix
- [Queuing](../queuing/01-overview.md) — react to pushes server-side
