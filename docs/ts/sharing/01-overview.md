# starfish-sharing

`@drakkar.software/starfish-sharing` (TS) / `starfish-sharing` (Py) — member-cap extension for granting a third party scoped access to a shared collection.

## What it provides

- Member cap-cert minting: `mintMemberCap` (collection-scoped; the subject keeps their own identity).
- Scope presets: `scopes.readOnly` / `scopes.writer` / `scopes.admin`. The member presets (`readOnly`, `writer`) deny `<col>/_keyring` and `<col>/_members`. `scopes.admin` has no such deny and is therefore **device-only** — `mintMemberCap` rejects it (a member cap may never reach `_keyring`/`_members`); use it with `mintDeviceCap` for an owner device that manages the keyring.
- The authoritative member-cap shape validator: `assertMemberCapShape` (raises `MemberCapShapeCode`). This is the **owner** of the member structural rules — `starfish-protocol` only checks the generic iss/sub-userId relations.
- The per-collection member directory: `addMemberEntry`, `listMembers`, `removeMemberEntry`, `membersPathFor` (the owner-only doc at `<col>/_members`).
- The server plugin: `sharingServerPlugin` (registers the `member` cap kind; its validator is `assertMemberCapShape`).

## Member-cap structural rules

Enforced by `assertMemberCapShape` (at mint time and, server-side, via `sharingServerPlugin`):

| Code | Rule |
|---|---|
| `member-missing-sub-userid` | `kind: "member"` requires `subUserId`. |
| `member-self` | `subUserId !== issUserId`. |
| `member-wildcard-collections` | no `"*"` in `scope.collections`. |
| `member-multi-collection` | exactly one collection. |
| `member-private-path` | no path resolves into the issuer's `users/<issUserId>/` namespace. |
| `member-members-not-denied` | any allow reaching `<col>/_members` needs a sibling deny (read OR write). |
| `member-keyring-not-denied` | a write allow reaching `<col>/_keyring` needs a sibling deny. |

The "reaches" / "deny" tests use the protocol's `pathGlobMatch` — the **same** matcher (with `**` crossing `/`) the resolver uses at request time. This is required for safety: if the barrier used a weaker glob rule than the resolver, an allow like `**` or `notes**` could clear the barrier with no deny yet be granted `_keyring`/`_members` access at request time.

> Security note: because these rules live in the extension, a consumer calling the protocol's `verifyCapCert` standalone does **not** reject malformed member caps. The server stays safe because the cap-resolver's strict-kind dispatch is **always on** — even with no `plugins` it falls back to a device-only default, so a `member` cap is rejected outright unless `sharingServerPlugin` is installed to validate it.

## Install

```sh
pnpm add @drakkar.software/starfish-client @drakkar.software/starfish-sharing
```

## Server wiring

```ts
import { createCapCertRoleResolver } from "@drakkar.software/starfish-server"
import { identitiesServerPlugin } from "@drakkar.software/starfish-identities"
import { sharingServerPlugin } from "@drakkar.software/starfish-sharing"

const resolver = createCapCertRoleResolver({
  nonceCache, revocationStore,
  plugins: [identitiesServerPlugin, sharingServerPlugin],
})
```

## Membership patterns

Member caps are per-recipient — there is **no server-side membership list** in 3.0. Common patterns:

- **Share with a few people / group chat.** Mint one cap per participant (`scopes.writer(col)`), record them with `addMemberEntry`, and — for `encryption: "delegated"` collections — `addRecipient` so they can decrypt. Adding a member is a single cap mint; there is no roster that admits N users at once.
- **Large or fast-changing rosters.** When per-user caps are too many to manage, write your own `RoleEnricher` that reads an allow-list document and grants a role (the server becomes the membership authority — the trade-off the removed built-in group enricher made). See [Group & Shared-Collection Access](../server/group-access.md#layering-custom-application-roles).
- **Request-to-join.** 3.0 ships no built-in invitation/request flow. Build one with ordinary collections: the invitee pushes a request document to `<col>/_requests/{subUserId}` (gated by the `"self"` role), the owner vets it and then `mintMemberCap` + `addRecipient`, delivering the signed cap out-of-band. See the [request-to-join recipe](../server/group-access.md#pattern-3--request-to-join-application-level-recipe).

> Removed in 3.0: the built-in `createGroupRoleEnricher` (server-evaluated `groups/{groupId}/members` lists + candidacy). See the [migration guide](../../migration/v2-to-v3.md#removed-group-role-enricher).

## Plaintext, cap-only sharing

There are **two** sharing options, selected per collection by its `encryption` field:

| | Encrypted option (`"delegated"`) | Plaintext, cap-only (`"none"`) |
|---|---|---|
| Content | E2E-encrypted (server stores ciphertext) | plaintext (server stores JSON) |
| Key delivery | per-collection `_keyring` of wrapped CEKs | **none** — no keyring, no wrapped keys |
| Access | member cap **+** keyring entry | member cap only |
| Revocation | revoke cap **+** rotate epoch (forward secrecy) | revoke cap (CRL) — nothing to rotate |

The plaintext option authorizes access purely with **signed member caps + expiry**, the
same mechanism as devices. It is the right choice when the data does not need E2E
encryption and you'd rather drop the keyring (and its rotation/roster machinery) entirely.

**Why publishing caps is safe.** A cap is **subject-bound, not a bearer token**: the server
verifies every request's signature against the cap's `sub` (cap-resolver). So a cap is
usable only by the holder of that subject's private key — a readable list of everyone's
caps never lets one member act as another. The only trade-off of a readable roster is
visibility of *who* the members are.

**Stateless (out-of-band).** `mintMemberCap` → deliver out-of-band; nothing stored
server-side. The owner keeps its own `{sub, nonce, exp}` records to revoke later.

**Owner-published caps.** Publish each signed cap into the single `<col>/_members` list
with `publishMemberCap`; members fetch their own with `fetchMyMemberCap` (no forwarding).
The `_members` list *is* the revocation bookkeeping. Configure the list collection
read-open + owner-only write — e.g. in the server config:

```ts
{ name: "shared-board",         storagePath: "shared-board/{docId}",   readRoles: ["cap:read:shared-board"],  writeRoles: ["cap:write:shared-board"], encryption: "none", /* … */ },
// All members' full signed caps in one read-open doc; owner-only write. Member caps
// cannot write here — their scope denies `<col>/_members` (member-members-not-denied).
{ name: "shared-board-members", storagePath: "shared-board/_members",  readRoles: ["public"],                  writeRoles: ["cap:write:shared-board"], encryption: "none", /* … */ },
```

**Eviction is revoke-only:** `evictMember(client, { membersCollection, member, issEdPubHex,
issEdPrivHex, generation, submitRevocation }, { rotate: false, revoke: true })` — omit the
keyring params. It revokes the cap and drops the published `_members` entry. See
`examples/ts/server.ts` for the full collection config.

## Role enrichers

For apps that key a collection by a free id (`products/{id}/…`,
`pubspaces/{ownerId}/…`), a plain cap role would let any authenticated identity
read/overwrite any id. Two generic `RoleEnricher` factories synthesize
domain-specific roles instead. Both take the `store`/`auth` as **arguments**, so
they depend on the server package for **types only** (TS `import type`; Py
`TYPE_CHECKING`) — there is no runtime coupling to `starfish-server`. Compose them
with `composeEnrichers` / `compose_enrichers` and wire via
`createSyncRouter`'s `roleEnricher`.

### `makeRegistryRoleEnricher` / `make_registry_role_enricher`

Reads an authoritative owner-written `_registry` document (`{ owner, members:
[...userIds] }`) at a configurable path template and grants `ownerRole` /
`memberRole`:

- `ownerRole` — the creator. With `allowTofu: true` (default) the FIRST writer to
  an id is granted ownership (trust-on-first-use), bootstrapping resource
  creation. Pass `allowTofu: false` for the strict SSE/events variant, where a
  caller must already have a recorded role in an existing registry doc (so it
  can't subscribe to a not-yet-existing id and harvest the owner's future events).
- `memberRole` — owner OR any userId in `members`.

Security properties (preserved from the per-app product/space enrichers it
generalizes):

- **Fails CLOSED on store errors.** If `getString`/`get_string` raises, the error
  propagates (the resolver returns 500). A transient outage must not fall through
  to "no registry yet ⇒ open TOFU", or an attacker who can induce store errors
  could take over established resources.
- **Full id match.** The id must fully match `idPattern` (default
  `^[a-zA-Z0-9_-]+$`), guarding against trailing-newline / partial-match bypasses
  (Python uses `fullmatch`).
- **Owner-less / unparseable docs fail CLOSED** (`[]`) rather than re-opening
  TOFU.

```ts
const enricher = makeRegistryRoleEnricher(store, {
  idParam: "productId",
  registryPath: "products/{id}/_registry",
  ownerRole: "product:owner",
  memberRole: "product:member",
})
```

### `makeIssuerBoundRoleEnricher` / `make_issuer_bound_role_enricher`

Decides roles purely from the requester's cap (no store read) for a public share
keyed by a free `{ownerId}`:

- `ownerRole` + `readerRole` — the owner's own DEVICE cap. The reader role is
  granted too because device caps never carry a `delegated:` role, so without it
  the owner could write but not read their own data.
- `readerRole` — a member/audience cap the owner minted; the resolver emits
  `delegated:<owner>:<col>`, so read is granted only when the issuer is the path's
  owner (for any of `collections`).
- `writerRole` — additionally granted when such a delegated cap carries
  `cap:write:<col>` AND the request does not target the guard doc
  (`guardParam`/`guardValue`, e.g. the `_rooms` registry) — guests post in rooms
  but only the owner manages the room list.

```ts
const enricher = makeIssuerBoundRoleEnricher({
  ownerParam: "ownerId",
  ownerRole: "pubspace:owner",
  readerRole: "pubspace:reader",
  writerRole: "pubspace:writer",
  collections: ["pubspace", "pubstream"],
  guardParam: "docId",
  guardValue: "_rooms",
})
```

## Deep-dive docs

- [Public links (audience caps)](./02-public-links.md) — `createPublicLink` with optional expiry + server-enforced identity allow-list.
- [Multi-recipient delegated encryption](../client/23-multi-recipient-delegated.md) — `listMembers` next to keyring management.
- [Capability certificates](../client/25-capability-certs.md) — member vs device caps, scope semantics.
