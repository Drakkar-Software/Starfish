# 25. Capability Certificates

Starfish 3.0 uses **signed capability certificates** (cap-certs) for authorization. A cap-cert is a small JSON object signed by the user's root key. It says: "subject `S` is allowed to perform ops `O` on collections/paths `P` until time `E`". Every authenticated request carries one.

## Schema

```json
{
  "v": 1,
  "kind": "device",
  "issAlg":     "ed25519",
  "subAlg":     "ed25519",
  "subKemAlg":  "<KEM suite; omitted when == subAlg (the common case)>",
  "iss":        "<hex pub of issuer (root or collection owner)>",
  "issUserId":  "<hex 32 = sha256(iss)[0:32]>",
  "sub":        "<hex pub of subject (device or member)>",
  "subKem":     "<hex KEM pub of subject; present unless the KEM key is the signing key — see below>",
  "subUserId":  "<hex 32 = sha256(sub)[0:32]; required when kind=member>",
  "scope": {
    "ops":         ["read", "write", "list"],
    "collections": ["notes", "tasks"],
    "paths":       ["notes/<userId>/*", "tasks/<userId>/*"]
  },
  "nbf":   1747000000,
  "exp":   1749592000,
  "nonce": "<base64 16 bytes>",
  "sig":   "<base64 64 bytes = sign(iss, canonical signing input) under issAlg>"
}
```

### Crypto suites (`issAlg` / `subAlg`)

Each identity picks a **crypto suite** (see [Identity models](./26-identity-models.md)):

- **`issAlg`** — the issuer's suite; governs the `iss` key type and how `sig` is verified.
- **`subAlg`** — the subject's **signing** suite; governs the `sub` key type and the scheme the subject uses for its per-request signatures. Optional — absent means "same suite as the issuer". `audience` caps carry no subject and no `subAlg`.
- **`subKemAlg`** — the subject's **KEM** (encryption) suite, decoupled from `subAlg` so a subject can sign with one curve and receive encrypted keys under another (e.g. `secp256k1-schnorr` signing + X25519 KEM, or a future post-quantum KEM). Optional — absent means "same as `subAlg`". Honored by the suite-aware keyring (since 3.0.0-alpha.4); `recipientKem(cert)` resolves the `{ kemPubHex, kemAlg }` the keyring seals to.

`subKem` (the KEM pubkey) is **present unless the KEM key *is* the signing key** — i.e. it is omitted only when `subKemAlg == subAlg` and that suite reuses one key for both (`secp256k1-schnorr`). So `ed25519` subjects carry `subKem` (a distinct X25519 key); same-suite `secp256k1-schnorr` subjects omit it; any mixed sign/KEM pair carries a distinct `subKem` of suite `subKemAlg`. `issAlg` may differ from `subAlg` — an `ed25519` root can grant a `member` cap to a `secp256k1-schnorr` subject (cross-suite delegation).

### Canonical signing input

The signing input is `stableStringify(certWithoutSig)` — the full cert object minus its `sig` field, recursively sorted-key JSON. Because `issAlg`/`subAlg` are part of that object, the chosen suite is covered by the signature and cannot be stripped or downgraded. The signing helper in the protocol package handles this:

```ts
import { capCertCanonicalSigningInput, signCapCert, verifyCapCertSignature } from "@drakkar.software/starfish-protocol"
```

## Three kinds

### `kind: "device"`

The subject acts as a **proxy for the issuer**. The server resolves `auth.identity = issUserId`; URL `{identity}` placeholders bind to the issuer's userId. Use this for the issuer's own devices.

A device cap can grant any subset of the issuer's natural authority — wildcards like `scope.collections: ["*"]` are allowed.

### `kind: "audience"`

Binds **no single subject** — used by [public links](../sharing/02-public-links.md). `sub`/`subKem`/`subUserId` (and `subAlg`) are **absent**; an optional `aud` list (64-char lowercase-hex pubkeys — the curve is per the presenter's suite) is the allow-list. Each redeemer signs requests with **their own** key, naming it in the `X-Starfish-Pub` header and its suite in `X-Starfish-Alg`; the server verifies the signature against it, checks membership in `aud` when present (403 otherwise), and resolves `auth.identity` to the presenter's own userId (`sha256(pub)[0:32]`). When `aud` is absent, any identity may redeem. Same single-collection and owner-namespace barriers as member caps (codes `audience-multi-collection`, `audience-private-path`, `audience-members-not-denied`, `audience-keyring-not-denied`); minted with `mintAudienceCap`, validated by `assertAudienceCapShape` (via `sharingServerPlugin`).

### `kind: "member"`

The subject keeps **their own identity** (`auth.identity = subUserId`); the cap-cert adds collection-scoped roles only. Use this when the collection owner wants to grant a third party (another user) access to a specific shared collection.

Member caps are **structurally constrained**:

- `subUserId` is required and must differ from `issUserId`.
- `scope.collections` may not contain `"*"`.
- `scope.collections` must contain **exactly one** entry (a member cap targets a single collection by design). Code: `member-multi-collection`.
- `scope.paths`, after substituting `{identity}` with the issuer's userId, may not match the issuer's `users/<issUserId>/*` namespace.
- If `scope.paths` includes an allow rule that would match `<col>/_members`, a matching `!<col>/_members` deny rule is required. Code: `member-members-not-denied`. The members directory is owner-only — members don't need it for crypto (the keyring covers everything decryption-related), so denying access reduces metadata leakage between members.
- If `scope.ops.includes("write")` and an allow rule would match `<col>/_keyring`, a matching `!<col>/_keyring` deny is required. Code: `member-keyring-not-denied`. Keyring writes are an admin primitive.

These rules are enforced both at mint time (client-side `assertCapCertWellFormed`) and at every request (server-side `verifyCapCert` step 4).

### Built-in scope presets

`scopes` exports four convenience constructors:

| Preset | `ops` | `paths` | Notes |
|---|---|---|---|
| `scopes.readOnly(col)` | `read, list` | `<col>/**`, `!<col>/_members` | Members directory denied. |
| `scopes.writer(col)` | `read, list, write` | `<col>/**`, `!<col>/_keyring`, `!<col>/_members` | Keyring + members both denied. |
| `scopes.admin(col)` | `read, list, write` | `<col>/**` | Full access incl. keyring + members. **Device caps only** — `mintMemberCap` rejects it (a member cap may never reach `_keyring`/`_members`); use it with `mintDeviceCap`. |
| `scopes.rootAll()` | `read, list, write` | `**` | For device caps acting as proxy for root. |

The `mintMemberCap` helper takes the target `collection` as a separate argument and rewrites `scope.collections = [collection]` internally — there is no path where a member cap can span more than one collection:

```ts
const bobCap = await mintMemberCap(
  alice.device.edPriv,
  alice.device.edPub,
  { edPubHex: bob.device.edPub, kemPubHex: bob.device.kemPub, userIdHex: bob.userId },
  "shared-notes",
  scopes.writer("shared-notes"),
)
```

## Directory helpers

The client SDKs ship `directory.{ts,py}` for owner-side audit/UI metadata:

- **Devices** — `addDeviceEntry(client, rootUserId, cert, {label?})` writes (or upserts by nonce) into a single document at `users/{rootUserId}/_devices`. `listDevices(client, rootUserId, {includeExpired?, revokedNonces?})` reads it and filters expired/revoked entries by default. `removeDeviceEntry(client, rootUserId, nonce)` drops a row.
- **Members** — `addMemberEntry(client, collectionPath, cert, {label?})`, `listMembers(client, collectionPath, opts?)`, `removeMemberEntry(client, collectionPath, nonce)` operate on `<collectionPath>/_members`. The path is **owner-only** by virtue of cap scope: non-admin member caps are denied `<col>/_members` and get 403 on read.

The directory is **not** an authority source. Authorization still flows through the cap-cert presented in `Authorization` headers and the `_revocations/{rootUserId}` document. The directory exists so the owner can render "your linked devices" / "members with access to this collection" without remembering nonces out-of-band.

All directory writes use `pull-merge-push` with `baseHash` and retry once on `ConflictError`, so concurrent issuers on the same root don't lose writes.

## Validation algorithm (server)

`verifyCapCert(cert, {now, clockSkewSec})` runs:

1. Well-formedness, **first**, so a malformed `nbf`/`exp` can't slip past the window check: runtime shape validation, then `sha256(iss)[0:32] === issUserId` (and the same for `sub`/`subUserId` when present). The shape check (raises `malformed-shape`):
   - `kind ∈ {device, member, audience}`; `issAlg` is a known suite (`ed25519` | `secp256k1-schnorr`), as are `subAlg` / `subKemAlg` when present;
   - `iss` / `issUserId` / `nonce` are strings (`nonce` decodes to 16 bytes); `nbf` / `exp` are integers (`Infinity`/`NaN` rejected, or expiry could be disabled);
   - subject binding is **kind-specific**: an `audience` cap carries **no** `subAlg`/`subKemAlg`/`sub`/`subKem`/`subUserId`; a device/member cap requires `sub`, and carries `subKem` **unless the KEM key is the signing key** (present for `ed25519` and any mixed sign/KEM pair; absent only for a same-suite `secp256k1-schnorr` subject). A self-signed device cap (`iss === sub`) must have `issAlg === subAlg`;
   - `scope.ops` ⊆ {read, write, list}; `scope.collections` / `scope.paths` are string arrays.
   Without the shape check, a validly-signed cert with a string `scope.ops` would be iterated character-by-character into fabricated roles.
2. `now ∈ [nbf − skew, exp + skew]` (default skew 5 min).
3. Signature check against `iss`, dispatched through the suite named by `issAlg`.

Kind-specific member barriers (`subUserId` required, `subUserId !== issUserId`, exactly one non-wildcard collection, no path into the issuer namespace, mandatory `_keyring`/`_members` denies) live in `assertMemberCapShape` (`starfish-sharing`) and are enforced server-side by `sharingServerPlugin` — not by `verifyCapCert` alone.

The server pipeline (`createCapCertRoleResolver`) additionally:

5. Binds `auth.identity` per `kind` (device → `issUserId`, member → `subUserId`).
6. Verifies the per-request signature (`X-Starfish-Sig`/`-Ts`/`-Nonce`).
7. Checks the nonce-replay LRU.
8. Consults the `RevocationStore`.
9. Synthesizes roles for the existing `roleEnricher` pipeline: `cap:<op>:<collection>` for each (op, collection); `delegated:<issUserId>:<collection>` for member caps; `self` where `params.identity === auth.identity`.

## Minting

```ts
import { deriveRootIdentity, mintDeviceCap, mintMemberCap, scopes } from "@drakkar.software/starfish-client"

const alice = await deriveRootIdentity("alice-root-passphrase")

// A new laptop for Alice — full rights:
const laptopCap = await mintDeviceCap(
  alice.keys.edPriv, alice.keys.edPub,
  { edPubHex: laptop.edPub, kemPubHex: laptop.kemPub },
  scopes.rootAll(),
)

// Bob is granted writer access to alice's shared-notes. `mintMemberCap` takes
// the target collection as a separate positional arg before the scope:
const bobCap = await mintMemberCap(
  alice.keys.edPriv, alice.keys.edPub,
  { edPubHex: bob.keys.edPub, kemPubHex: bob.keys.kemPub, userIdHex: bob.userId },
  "shared-notes",
  scopes.writer("shared-notes"),
)
```

### Scope presets

```ts
scopes.readOnly("notes")   // {ops:["read","list"], collections:["notes"], paths:["notes/**","!notes/_members"]}
scopes.writer("notes")     // adds "write"; paths:["notes/**","!notes/_keyring","!notes/_members"]
scopes.admin("notes")      // no keyring/members deny — DEVICE caps only (mintMemberCap rejects it)
scopes.rootAll()           // wildcard everything (device caps only)
```

The `!` prefix in `paths` is a denylist. Explicit deny beats wildcard allow. This is how `writer` blocks the keyring + members documents while allowing data writes. The deny is enforced twice with **identical glob semantics**: at mint/validation time (`assertMemberCapShape`, run server-side by `sharingServerPlugin`) and at request time (the resolver's `matchScopePath`) — both use the protocol's `pathGlobMatch`, where `**` crosses `/`. At request time the path is canonicalized (`.`/empty segments collapsed) and a deny `!path` covers both `path` **and any descendant** `path/...`, so an owner-only deny can't be side-stepped with a trailing slash, an extra segment, or a `.` segment (e.g. `notes/_keyring/`, `notes/_keyring/x`, `notes/./_keyring`). `admin` carries no such deny, so it is only valid for a `device` cap, whose subject proxies for the owner and may legitimately rewrite the keyring and promote new recipients; passing `admin` to `mintMemberCap` is rejected.

## Root-device caps

A `bootstrapRootIdentity` cap is self-signed: its `iss` equals its `sub` (the
root device is its own subject). Every paired or provisioned device cap is minted
*by* the root (`iss !== sub`), and a member cap binds a distinct subject — so a
self-signed `kind: "device"` cap is the unique signature of the **root device**.
The protocol package exports a predicate for it (re-exported from
`@drakkar.software/starfish-identities`):

```ts
import { isRootDeviceCap } from "@drakkar.software/starfish-protocol"

isRootDeviceCap(cert) // true iff cert.kind === "device" && cert.iss === cert.sub
```

(Python: `is_root_device_cap(cert)`.) The server uses it to synthesize a
`device:root` role (`ROLE_ROOT_DEVICE`) for the root device, which lets a
collection be marked `rootOnly` (`root_only` in Python) so that paired/member
caps get a `403` even though they share the root's scope. See
[Root-Only Collections](../server/root-only-collections.md) for the server-side
configuration and behavior.

## Lifetime and rotation

- Default TTL: 30 days (`MintOpts.ttlSec`).
- A scope change is **a new cap-cert** with a fresh `nonce`. The old cert keeps working until `exp`.
- To force immediate downgrade, revoke the old `nonce` and ship the new cert.
- Revocation is via a signed `RevocationList` document at `_revocations/<userId>` (signature verified server-side via `RevocationStore.acceptList`).

## Bootstrap (first device of a user)

```ts
import { bootstrapRootIdentity } from "@drakkar.software/starfish-client"

const creds = await bootstrapRootIdentity("alice-root-passphrase")
// creds = {
//   rootEdPub, userId,
//   device: {edPriv, edPub, kemPriv, kemPub},   // same as root keypair on first device
//   capCert,                                     // self-signed kind:"device" full-scope cap
// }
```

There is no special "passphrase auth" path on the wire — even the first device presents a cap-cert.

## Pairing additional devices

In-person QR pairing and server-relay invite flows let you add more devices without re-deriving from the passphrase. See [24. Pairing](24-pairing.md).

## Why not JWT?

A recurring question is whether a cap-cert is just a reinvented JWT. It is not — they solve different problems. A cap-cert spans **three layers**, and a JWT only addresses one of them:

| Layer | What a cap-cert does | Could JWT/JWS do it? |
|---|---|---|
| **Authority envelope** | Signature (under `issAlg`) over `stableStringify(cert \ sig)` (see [Canonical signing input](#canonical-signing-input)). | This is the only layer JWS even competes on — see below. |
| **Proof-of-possession** | Every request carries `X-Starfish-Sig` over `alg + m + p + body-hash + host + ts + nonce`, verified against the subject key (see [Validation algorithm](#validation-algorithm-server) steps 6–7). | **No.** A plain JWT is a *bearer* token — possession is authorization, so a leaked token is a compromise. A cap-cert is **subject-bound, not a bearer token**: a leaked cap is useless without the subject's private key. Matching this with JWT needs DPoP (RFC 9449) or `cnf`-bound tokens (RFC 7800) **plus** the same per-request signing we already do — JWT removes none of it. |
| **Capability semantics** | Structured `scope` (`ops` × `collections` × `paths` globs, `kind`, allow/deny barriers). | **No.** Custom claims and custom validators either way. The standards that *would* help here are macaroons / Biscuit (caveats, attenuation) — not JWT. |

### Why not at least use a JWS *envelope*?

The tempting narrow version is "keep the design, but sign the cert as a JWS to drop our custom canonical JSON." That trade does not pay off, because `stableStringify` is the protocol's **universal** signing/hashing primitive, not a cap-cert detail. It is the canonical form for content hashing (`computeHash` — the basis of the library's hash-based conflict detection, entirely unrelated to auth), request signatures, revocation lists, keyring `addedSig`, pairing bundles, public-link fragments, and document signing. A JWS cap-cert would:

- **not** remove `stableStringify` — content hashing alone keeps it permanent — so it adds a *second* signing idiom alongside the uniform "canonical-JSON + raw-Ed25519" used everywhere else;
- add **no** functional gain (still Ed25519; still need the per-request signature; still need the custom `scope` claims and validators);
- add costs: a JOSE dependency, `alg`/`kid` header handling and its spec surface, churn to the `cap-cert` cross-language vector in `tests/test-vectors/cap-cert.json`, and turning a self-contained, inspectable cert (stored as-is in [directory](#directory-helpers) documents) into an opaque token.

### Prior art

The closest formal match to this design is **UCAN** (a JWT-enveloped capability token using DID/Ed25519, with offline verification and delegation). Adjacent designs: **Biscuit** (Ed25519 capability tokens with Datalog caveats), **macaroons**, **zcap-ld**, **SPKI/SDSI**. The one deliberate divergence from UCAN is that cap-certs are **flat** — every cert is signed directly by the root (`iss`), with no cert-issued-by-cert delegation chains — which keeps verification a single signature check.
