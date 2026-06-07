# @drakkar.software/starfish-sharing

Starfish member-cap extension — issue scoped member capability certificates, the `readOnly` / `writer` / `admin` scope presets, and the per-collection member directory.

## Install

```sh
pnpm add @drakkar.software/starfish-client @drakkar.software/starfish-keyring @drakkar.software/starfish-sharing
```

## Usage

```ts
import { StarfishClient } from "@drakkar.software/starfish-client"
import {
  mintMemberCap,
  scopes,
  addMemberEntry,
  listMembers,
} from "@drakkar.software/starfish-sharing"

const cert = await mintMemberCap(
  owner.edPriv,
  owner.edPub,
  { edPubHex: bob.edPub, kemPubHex: bob.kemPub, userIdHex: bob.userId },
  "shared-notes",
  scopes.writer("shared-notes"),
)
await addMemberEntry(client, "shared-notes", cert, { label: "Bob" })
const members = await listMembers(client, "shared-notes")
```

## How membership works: cryptographic & collection view

Membership has two orthogonal layers — **authorization** (a CA-signed capability cert, verified by
the server) and **key delivery** (the collection key wrapped to the member, only for
`encryption: "delegated"`). Onboarding sets both up; revoking tears both down. The server never reads
a member roster — access is decided purely from the presented cap-cert.

### Onboarding a member

**Cryptographic**

- `mintMemberCap` produces a **CA-signed bearer token**: the owner's root **Ed25519** key signs the
  canonical cert (`kind: "member"`, `iss` = owner, `sub` = member Ed25519 pubkey,
  `subKem` = member X25519 pubkey, `subUserId`, a single-collection `scope`, plus `nbf` / `exp` /
  `nonce`). The cert carries the member's **public** keys only — it holds **no secret or wrapped key
  material**.
- For `encryption: "delegated"` collections, key access is granted separately: the owner **wraps the
  collection content-encryption key (CEK) to the member's X25519 `subKem`** via the keyring's
  `addRecipient`. Mechanically: ephemeral X25519 ECDH → HKDF-SHA256 wrap key → `AES-256-GCM(cek)`,
  appended as a `WrappedKeyEntry` (itself signed by the adder) to the keyring's current epoch.
- Authorization and key delivery are **independent**: a cap with no keyring entry lets the member
  reach the collection but not decrypt it; a keyring entry with no cap lets them decrypt bytes they
  can never fetch. Onboarding a reader of a delegated collection needs **both**.
- The signed cap is delivered to the member out-of-band (or via an ordinary collection). On each
  request the member sends it in the `Authorization: Cap …` header plus a per-request Ed25519
  signature; the **server verifies the signature, time window, revocation, and scope** — it does not
  consult any roster.

**Collection (what gets written)**

| Path | Written by | Holds | Server reads it? |
|---|---|---|---|
| `<col>/_members` | `addMemberEntry` (owner only) | Audit/UX roster: `{nonce, sub, subKem, subUserId, scope, nbf, exp, label?, addedBy?, addedAt}` | **No** — not an authority source |
| `<col>/_keyring` | `addRecipient` (delegated mode only) | The member's `WrappedKeyEntry` in the current epoch | **No** — stored opaquely; clients decrypt |

The cap-cert itself is **not** stored server-side as a membership record — it lives with the member.
`_members` is purely the owner's bookkeeping so they can list and later evict.

### Revoking a member

**Cryptographic**

- **Authorization kill-switch (revocation list).** The owner signs a generation-counted
  `RevocationList` (Ed25519) naming the cap by `{sub, nonce, exp}` (or `revokedSubjects` for
  incident response). The server's revocation store then rejects that cap **O(1) on every request**,
  cutting off both reads and writes immediately. This is the only thing that stops an already-issued
  cap — `exp` aside.
- **Forward secrecy (keyring rotation).** `removeRecipient` rotates the epoch: mints a **fresh CEK**,
  re-wraps it for the **retained** recipients only, and bumps `currentEpoch`. The evicted member's
  X25519 key is absent from the new epoch, so they cannot decrypt content sealed afterward.
  *Caveat:* earlier epochs are preserved, so content sealed **before** rotation stays decryptable to
  anyone who already held that CEK — rotation is forward-secret, not retroactive.
- The two are independent: **revoke** stops the member acting (writes/auth); **rotate** stops them
  reading future content. Doing only one is the footgun `evictMember` exists to prevent.

**Collection (what changes)**

- `<col>/_keyring` — rotation appends a new epoch whose `wrappedKeys` omit the evicted member.
- `<col>/_members` — `removeMemberEntry` drops the member's entry by `nonce`.

**Ordering matters:** revoke **first** (so a still-valid cap can't squeeze a write in between the
rotate and the revoke), then rotate the keyring, then drop the directory entry. `evictMember`
composes all three behind explicit `rotate` / `revoke` flags — see below.

## Eviction

Removing a member from the keyring (`removeRecipient`) rotates the epoch for forward
secrecy but does **not** stop them writing — write authority is cap-based. Full eviction
is therefore revoke-the-cap **and** rotate-the-keyring **and** drop the directory entry.
`evictMember` does all three in one call behind explicit flags, so the footgun (doing only
one) is hard to hit. It stays transport- and ledger-agnostic: you supply how to submit the
signed `RevocationList` and the strictly-increasing per-issuer `generation`.

```ts
import { evictMember } from "@drakkar.software/starfish-sharing"

await evictMember(
  client,
  {
    keyringCollection: "shared-notes",       // <coll> → <coll>/_keyring
    membersCollection: "shared-notes",       // <coll> → <coll>/_members
    member: { sub: bob.edPub, nonce: capNonce, exp: capExp, subKem: bob.kemPub },
    adder: { edPriv: owner.edPriv, edPub: owner.edPub, kemPriv: owner.kemPriv },
    trustedAdders: [owner.edPub],
    issEdPubHex: owner.edPub,
    issEdPrivHex: owner.edPriv,
    generation: nextGeneration,              // you track this (the store needs it to increase)
    priorRevoked,                            // previously-revoked entries to carry forward
    submitRevocation: (list) => post("/revocations", list),
  },
  { rotate: true, revoke: true },
)
```

The signed list is built with `buildRevocationList` from
[`@drakkar.software/starfish-protocol`](../protocol/README.md).

## Plaintext, cap-only sharing (no keyring)

The membership flow above is the **E2E-encrypted** option (`encryption: "delegated"`):
content is sealed under a per-collection keyring and members get a wrapped CEK. For
data that does **not** need E2E encryption there is a second option: a
**plaintext** (`encryption: "none"`) shared collection where access is authorized purely
by **signed member caps + expiry**, exactly like the device mechanism. There is **no
keyring and no wrapped keys**; the server enforces read/write from the presented cap.
The two options coexist and are selected by the collection's `encryption` field.

Why it's safe to hand caps around: a cap is **subject-bound**, not a bearer token — the
server verifies every request's signature against the cap's `sub`, so a cap is usable
only by the holder of that subject's private key.

Two delivery variants:

- **Stateless (out-of-band).** Mint the cap and deliver it out-of-band; nothing is
  stored server-side (no `_keyring`, no `_members`). The owner keeps its own record of
  `{sub, nonce, exp}` to revoke later.

  ```ts
  const cert = await mintMemberCap(
    owner.edPriv, owner.edPub,
    { edPubHex: bob.edPub, kemPubHex: bob.kemPub, userIdHex: bob.userId },
    "shared-board",
    scopes.writer("shared-board"),
  )
  // → hand `cert` to Bob; he presents it as `Authorization: Cap …`.
  ```

- **Owner-published caps.** Instead of forwarding, publish each signed cap into the
  single `<col>/_members` list; members fetch their own. Configure that collection
  read-open + owner-only write (see `examples/ts/server.ts`).

  ```ts
  import { publishMemberCap, fetchMyMemberCap, unpublishMemberCap } from "@drakkar.software/starfish-sharing"

  // Owner publishes Bob's cap into the shared list:
  await publishMemberCap(client, "shared-board", cert, { label: "Bob" })

  // Bob fetches his own cap (no forwarding) and uses it for content:
  const myCap = await fetchMyMemberCap(client, "shared-board", bob.edPub)
  ```

- **Public link (`audience` cap).** The two variants above target a *known* recipient — you
  already have Bob's pubkey. For a **public** share — a read-only broadcast feed, a status
  page, an "anyone in this list can post" board — use `createPublicLink`. It mints an
  **`audience` cap-cert** (a kind that binds *no* single subject) and packs it into a URL
  `#fragment`. Every redeemer signs requests with **their own** identity key (named via the
  `X-Starfish-Pub` header), so the link carries **no private key** and writes are
  attributable per user. An optional `allowedIdentities` list restricts who may redeem
  (server-enforced); omit it and **any** identity may. Optional `expiresAt` / `ttlSec` set
  the cap's expiry.

  ```ts
  import { createPublicLink, parsePublicLink, redeemPublicLink, scopes } from "@drakkar.software/starfish-sharing"

  // Owner mints the link. Restrict to a known set, or omit allowedIdentities for "anyone".
  const link = await createPublicLink({
    issEdPrivHex: owner.edPriv,
    issEdPubHex: owner.edPub,
    collection: "broadcast",
    scope: scopes.readOnly("broadcast"),     // or scopes.writer("broadcast")
    allowedIdentities: [bob.edPub, carol.edPub], // optional; omit ⇒ any identity
    ttlSec: 7 * 24 * 3600,                       // optional; or expiresAt: <unix seconds>
  })
  // Share `https://app.example/#${link.fragment}`. The fragment is never sent to the
  // server, logged, or put in Referer.

  // A redeemer (who already holds a Starfish identity) parses + signs as themselves:
  const parsed = parsePublicLink(fragment)
  const headers = await redeemPublicLink(parsed, {
    redeemerEdPrivHex: bob.edPriv,
    redeemerEdPubHex: bob.edPub,
    method: "GET",
    pathAndQuery: "/pull/broadcast/post-1",
    host: "api.example.com",
  })
  // Send `headers` (Authorization: Cap …, X-Starfish-{Sig,Ts,Nonce,Pub}) with the request.
  ```

  The server (with `sharingServerPlugin` wired) verifies the request signature against the
  `X-Starfish-Pub` key, checks it against the cap's `aud` when present (403 otherwise), and
  binds `auth.identity` to that redeemer's own userId. Because there is no single subject,
  **revocation is whole-link**: revoke the cap's nonce with `sub: ""` (see the CRL note
  below), or re-mint with a trimmed `allowedIdentities`. The `_members` directory and
  `evictMember` are for single-subject member caps only and do not apply to audience caps.

  > Caution: when many owners share one plaintext collection keyed by a free path param
  > (e.g. `broadcast/{ownerId}/…`), gating reads on a bare `cap:read:broadcast` role lets a
  > cap from *any* issuer read *any* owner's data — role synthesis is issuer-agnostic. Bind
  > access to the issuer with a `RoleEnricher` that checks the synthesized
  > `delegated:<issUserId>:<col>` role against the path's owner. A single-owner collection
  > (as in the example above) doesn't need this.

**Revocation is CRL-only** — there is nothing encrypted to rotate. Call `evictMember`
with `rotate: false` and omit the keyring params; it revokes the cap and drops the
published entry:

```ts
await evictMember(
  client,
  {
    membersCollection: "shared-board",
    member: { sub: bob.edPub, nonce: capNonce, exp: capExp, subKem: bob.kemPub },
    issEdPubHex: owner.edPub,
    issEdPrivHex: owner.edPriv,
    generation: nextGeneration,
    submitRevocation: (list) => post("/revocations", list),
  },
  { rotate: false, revoke: true },
)
```

## Server plugin

```ts
import { createCapCertRoleResolver } from "@drakkar.software/starfish-server"
import { sharingServerPlugin } from "@drakkar.software/starfish-sharing"

const resolver = createCapCertRoleResolver({
  nonceCache,
  revocationStore,
  plugins: [sharingServerPlugin],
})
```

## Role enrichers

Two generic `RoleEnricher` factories for apps that key a collection by a free id
(`products/{id}/…`, `pubspaces/{ownerId}/…`). Both take the `store`/`auth` as
arguments and depend on `@drakkar.software/starfish-server` for **types only** (no
runtime coupling).

### `makeRegistryRoleEnricher` — registry / TOFU owner-member

Reads an owner-written `_registry` doc (`{ owner, members }`) and grants
`ownerRole` / `memberRole`. With `allowTofu: true` (default) the first writer to a
new id is granted ownership; pass `allowTofu: false` for the strict SSE/events
variant. Fails CLOSED on store errors and on owner-less/unparseable docs.

```ts
import { makeRegistryRoleEnricher } from "@drakkar.software/starfish-sharing"

const enricher = makeRegistryRoleEnricher(store, {
  idParam: "productId",
  registryPath: "products/{id}/_registry", // {id} is substituted
  ownerRole: "product:owner",
  memberRole: "product:member",
  // allowTofu: false,                       // strict, for /events
  // idPattern: DEFAULT_SAFE_ID,             // ^[a-zA-Z0-9_-]+$, full match
})
```

### `makeIssuerBoundRoleEnricher` — issuer-bound public share

Decides roles purely from the requester's cap (no store read). Grants the owner's
own device cap `ownerRole` + `readerRole`; grants `readerRole` to caps the owner
delegated for one of `collections`; additionally grants `writerRole` when such a
cap carries `cap:write:<col>` and the request does not target the guard doc.

```ts
import { makeIssuerBoundRoleEnricher } from "@drakkar.software/starfish-sharing"

const enricher = makeIssuerBoundRoleEnricher({
  ownerParam: "ownerId",
  ownerRole: "pubspace:owner",
  readerRole: "pubspace:reader",
  writerRole: "pubspace:writer",
  collections: ["pubspace", "pubstream"],
  guardParam: "docId",
  guardValue: "_rooms", // withholds writerRole on the registry doc
})
```

See `docs/ts/sharing/` for the full guide.
