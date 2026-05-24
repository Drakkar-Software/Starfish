# Public links (audience caps)

`@drakkar.software/starfish-sharing` (TS) / `starfish-sharing` (Py) — a first-class API for **public links** to a plaintext (`encryption: "none"`) collection, with optional expiry and an optional, **server-enforced** identity allow-list.

A public link is an **`audience` cap-cert** packed into a URL `#fragment`. It differs from a member cap in one key way: it binds **no single subject**. Instead, every redeemer signs requests with **their own** identity key and names that key in the `X-Starfish-Pub` header. Consequences:

- **No private key is embedded in the link** — the fragment carries only the signed cap.
- **Writes are attributable per user** — `auth.identity` is the redeemer's own userId (`sha256(pub)[0:32]`), not a shared anonymous identity. For an *open* link this is only as strong as the identity itself — see [Security considerations](#security-considerations).
- **Redeemers must already hold a Starfish identity** (an Ed25519/X25519 keypair).

## API

| TypeScript | Python |
| --- | --- |
| `createPublicLink(opts)` → `{ fragment, cap }` | `create_public_link(...)` → `PublicLink(fragment, cap)` |
| `parsePublicLink(fragment)` → `{ cap }` | `parse_public_link(fragment)` → `ParsedPublicLink(cap)` |
| `redeemPublicLink(parsed, opts)` → header set | `redeem_public_link(parsed, ...)` → dict |
| `mintAudienceCap(...)` / `assertAudienceCapShape(cert)` | `mint_audience_cap(...)` / `assert_audience_cap_shape(cert)` |

`parsePublicLink` decodes + shape-checks the embedded cap; it does **not** verify the signature or expiry — that is the server's job at request time.

## Open vs restricted

The allow-list is **optional**:

- **Omit `allowedIdentities`** → an *open* link: any identity may redeem (each still signs as itself).
- **Provide `allowedIdentities`** (a list of redeemer Ed25519 pubkeys, 64-char lowercase hex) → only those identities may redeem. The server checks the presenter's key against the cap's `aud` and returns **403** otherwise.

## Expiry

Pass `expiresAt` (absolute unix seconds) or `ttlSec` (duration). `expiresAt` wins when both are given; both map to the cap's `exp` and are enforced by `verifyCapCert` (±300s clock skew). With neither set, the default 30-day TTL applies. (`mintMemberCap` accepts `expiresAt` too.)

## Owner: mint and share

```ts
import { createPublicLink, scopes } from "@drakkar.software/starfish-sharing"

const link = await createPublicLink({
  issEdPrivHex: owner.edPriv,
  issEdPubHex: owner.edPub,
  collection: "broadcast",
  scope: scopes.readOnly("broadcast"),       // or scopes.writer("broadcast")
  allowedIdentities: [bob.edPub, carol.edPub], // optional; omit for "anyone"
  ttlSec: 7 * 24 * 3600,                       // optional; or expiresAt
})
// Share: `https://app.example/#${link.fragment}`
```

The `#fragment` is never sent to the server, logged, or placed in `Referer`.

## Redeemer: parse and sign as self

```ts
import { parsePublicLink, redeemPublicLink } from "@drakkar.software/starfish-sharing"

const parsed = parsePublicLink(fragment)
const headers = await redeemPublicLink(parsed, {
  redeemerEdPrivHex: bob.edPriv,
  redeemerEdPubHex: bob.edPub,
  method: "GET",
  pathAndQuery: "/pull/broadcast/post-1",
  host: "api.example.com",
})
// headers: { Authorization: "Cap …", "X-Starfish-Sig", "X-Starfish-Ts",
//            "X-Starfish-Nonce", "X-Starfish-Pub" }
```

Using `StarfishClient` directly? Have your `capProvider.getCap()` return `pubHex` (the redeemer's own pubkey) alongside `cap` + `devEdPrivHex`; the client then emits `X-Starfish-Pub` automatically.

## Server wiring

The resolver accepts audience caps only when `sharingServerPlugin` is installed (strict-kind dispatch rejects an unregistered kind):

```ts
createCapCertRoleResolver({ nonceCache, revocationStore, plugins: [sharingServerPlugin] })
```

At request time the resolver: verifies the per-request signature against `X-Starfish-Pub`; if the cap carries `aud`, requires the presenter to be a member (403 otherwise); keys replay protection by the presenter pubkey; binds `auth.identity` to the presenter's userId; and synthesizes `cap:<op>:<col>` plus `delegated:<issUserId>:<col>` roles.

**Browser/CORS:** `X-Starfish-Pub` is a new request header. If a browser redeems public links cross-origin, add it to your server's CORS `Access-Control-Allow-Headers` alongside the existing `X-Starfish-Sig` / `X-Starfish-Ts` / `X-Starfish-Nonce` (or use a wildcard, as the example app does). The built-in CORS middleware's default header list does not include any `X-Starfish-*` header, so apps with browser clients already configure this.

## Revocation

An audience cap has no single subject, so revocation is **whole-link**: post a signed `RevocationList` entry keyed on the cap's nonce with `sub: ""` (`buildRevocationList` / `build_revocation_list`), or re-mint the link with a trimmed `allowedIdentities`. The `_members` directory, `publishMemberCap`, and `evictMember` apply to single-subject **member** caps only — not audience caps.

> Use `sub: ""` only in the per-nonce `revoked` list. Putting `sub: ""` in `revokedSubjects` (subject-wide revoke) would revoke **every** audience cap from that issuer at once — almost never what you want.

## Security considerations

A public link removes the embedded-key risk of a shared credential, but it is still a **grant anyone holding the link can present**. Keep these in mind:

- **An *open* writer link grants collection-wide writes.** Authorization is confined only by the cap's `scope.paths`, and `scopes.writer(col)` allows all of `<col>/**` (minus `_keyring` / `_members`). With no `allowedIdentities`, *any* identity can therefore write *anywhere* in the collection. To confine writers, either set `allowedIdentities`, or pass an `{identity}`-templated scope (paths like `<col>/{identity}/**`) so each redeemer is limited to their own subtree — the resolver substitutes `{identity}` with the redeemer's own userId. Prefer read-only (`scopes.readOnly`) for open links.

- **Attribution is only as strong as the identity.** `auth.identity` is the redeemer's own key, but anyone can generate a fresh keypair, so an *open* link's writes are attributable only to a self-asserted, possibly throwaway identity. Attribution — and any per-identity rate limiting — is meaningful only for **restricted** links, where `allowedIdentities` lists keys you already trust.

- **A cap grants authority, not decryption.** Public links target `encryption: "none"` collections. Pointing one at an `encryption: "delegated"` collection authorizes pulling **ciphertext** (and its metadata — timestamps, hashes, document structure) but hands over no content key, so redeemers still can't read the plaintext. A public link is not a substitute for adding a keyring recipient (`addRecipient`).

- **Use short TTLs.** The 30-day default suits a member cap, not an "anyone" link. Set a tight `ttlSec` / `expiresAt` and revoke when done. Revocation is whole-link and depends on the signed `RevocationList` reaching the server; until then a cap is honored to `exp` (+300s skew).

## Cross-language guarantees

Audience cap canonicalization, signatures, link fragments, and the redeemed request signature are byte-for-byte identical across TypeScript and Python. The `audienceCapOpen` / `audienceCapRestricted` cases in `tests/test-vectors/cap-cert.json` lock the canonical signing input and signature.
