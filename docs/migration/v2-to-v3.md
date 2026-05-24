# Migrating from Starfish 2.x to 3.0

Starfish 3.0 is a major redesign of the encryption and authorization model. This document is the step-by-step runbook for upgrading a 2.x deployment.

## What changed in one paragraph

The server no longer holds encryption keys (the `"identity"` and `"server"` modes are gone). Group encryption is folded into `"delegated"` — a single multi-recipient KEM-DEM keyring covers both "another device of mine" and "another user in this group". Identity is now an Ed25519 (sign) + X25519 (KEM) keypair derived from the passphrase via Argon2id → HKDF-SHA256; the v2 `authToken = SHA-256(passphrase)` bearer model is removed. Every authenticated request is signed by a per-device Ed25519 key whose authority comes from a signed capability certificate (cap-cert) issued by the user's root.

## Lockstep upgrade — clean break

All twenty packages must move to v3.0 together — no mixed-version deployments. v3.0 is a **clean break**: the v2 `group-crypto`, `deriveCredentials`, `generatePassphrase`, `authProvider` Bearer path, `signData` hook, `signatureVerifier`, `createEncryptor`, and the `SyncManager` `encryptionSecret` / `encryptionSalt` / `encryptionInfo` single-secret shorthand are all *removed*, not deprecated alongside. (The `Encryptor` *contract type* now lives in `@drakkar.software/starfish-protocol` / `starfish-protocol`; supply a keyring-built `encryptor` — via `createKeyringEncryptor` — instead.) Cap-aware code (identity, keyring, member caps) also moved out of `starfish-client` / `starfish-sdk` into three extension packages with **no transitional re-exports**, so v2 imports of those helpers from the client package will fail to build against v3.0.

1. **Pin every dependency** in your service repo to v3.0.0:
   - TS core: `@drakkar.software/starfish-protocol`, `@drakkar.software/starfish-client`, `@drakkar.software/starfish-server`
   - TS extensions: `@drakkar.software/starfish-keyring`, `@drakkar.software/starfish-identities`, `@drakkar.software/starfish-sharing`, `@drakkar.software/starfish-entitlements`, `@drakkar.software/starfish-queuing`, `@drakkar.software/starfish-audit`, `@drakkar.software/starfish-replica`
   - Python core: `starfish-protocol`, `starfish-sdk`, `starfish-server`
   - Python extensions: `starfish-keyring`, `starfish-identities`, `starfish-sharing`, `starfish-entitlements`, `starfish-queuing`, `starfish-audit`, `starfish-replica`
2. **Roll the server first**, then clients. The server's cap-resolver still accepts custom `roleResolver` shapes, so a server pre-roll is safe (it can still serve v2 Bearer requests via a custom resolver if you keep that resolver around in your own code — but the built-in v2 path is gone). Clients must upgrade before they can talk to the new auth.
3. **Code search before deploy**: grep for `deriveCredentials`, `generatePassphrase`, `group-crypto`, `wrapGroupKey`, `createGroupKeyring`, `addGroupMember`, `rotateGroupKey`, `createGroupEncryptor`, `createEncryptor`, `signData`, `signatureVerifier`, `authProvider`, `encryptionSecret`, `serverIdentity`, `clientEncrypted`, `publicKey` in your service codebase. Every hit needs migration.

## Code changes

### Client side

**Before (v2.x):**

```ts
import { deriveCredentials, createEncryptor } from "@drakkar.software/starfish-client"

const creds = deriveCredentials(passphrase)
const encryptor = createEncryptor(creds.encryptionSecret, creds.encryptionSalt)
const client = new StarfishClient({ baseUrl, authProvider: () => ({ Authorization: `Bearer ${creds.authToken}` }) })
const sync = new SyncManager(client, "/pull/notes", "/push/notes", { encryptor })
```

**After (v3.0):**

```ts
import { StarfishClient, SyncManager } from "@drakkar.software/starfish-client"
import { bootstrapRootIdentity, mintDeviceCap, scopes } from "@drakkar.software/starfish-identities"
import { createKeyringEncryptor, type Keyring } from "@drakkar.software/starfish-keyring"
import { signRequest } from "@drakkar.software/starfish-protocol"
// Member-cap helpers (mintMemberCap, scopes.readOnly/writer/admin, listMembers)
// live in @drakkar.software/starfish-sharing — import from there when sharing a collection.

// First device — bootstrap from passphrase, self-signs a full-scope device cap-cert.
const creds = await bootstrapRootIdentity(passphrase)

// Build a CapProvider for the StarfishClient.
const capProvider = {
  getCap: async () => ({ cap: creds.capCert, devEdPrivHex: creds.device.edPriv }),
}

const client = new StarfishClient({ baseUrl, capProvider })

// Encryption: fetch the collection's keyring document, build an encryptor.
const keyring = (await client.pull(`notes/_keyring`)).data as Keyring
const encryptor = await createKeyringEncryptor(
  keyring,
  { kemPubHex: creds.device.kemPub, kemPrivHex: creds.device.kemPriv },
  // `trustedAdders` is required — the Ed25519 pubkey(s) you trust to grant
  // keyring access (here the collection owner's root key; on the first device
  // that is `creds.device.edPub`). Entries added by anyone else are skipped.
  { trustedAdders: [creds.device.edPub] },
)

// Wire SyncManager — single options object. Author signatures attach
// automatically when `signer` is set.
const signer = {
  getSigner: async () => ({
    devEdPubHex: creds.device.edPub,
    sign: (bytes: Uint8Array) => ed25519Sign(creds.device.edPriv, bytes),
  }),
}
const sync = new SyncManager({
  client,
  pullPath: "/pull/notes",
  pushPath: "/push/notes",
  encryptor,
  signer,
})
```

Python: the same surface with snake_case (`bootstrap_root_identity`, `create_keyring_encryptor`, `cap_provider=...`, `signer=...`).

### Server side

**Before (v2.x):**

```ts
const router = createSyncRouter({
  encryptionSecret: process.env.STARFISH_SECRET,
  serverIdentity: "my-server",
  signatureVerifier: async (canonical, sig, identity) => myVerify(canonical, sig, identity),
  roleResolver: async (c) => ({ identity: extractIdentity(c), roles: ["app-user"] }),
  collections: { notes: { storagePath: "users/{identity}/notes", encryption: "identity", ... } },
})
```

**After (v3.0):**

```ts
import { createCapCertRoleResolver, createInMemoryNonceCache, createInMemoryRevocationStore } from "@drakkar.software/starfish-server"
import { identitiesServerPlugin } from "@drakkar.software/starfish-identities"
import { sharingServerPlugin } from "@drakkar.software/starfish-sharing"

const router = createSyncRouter({
  roleResolver: createCapCertRoleResolver({
    nonceCache: createInMemoryNonceCache(),
    revocationStore: createInMemoryRevocationStore(),
    // Per-kind cap validators live in the extensions. Under strict-kind
    // dispatch (the default) a `device` / `member` cap is rejected 401
    // unless its plugin is installed here.
    plugins: [identitiesServerPlugin, sharingServerPlugin],
    allowAnonymous: true,
  }),
  collections: { notes: { storagePath: "users/{identity}/notes", encryption: "delegated", ... } },
})
```

Drop these `SyncRouterOptions`: `encryptionSecret`, `serverEncryptionSecret`, `serverIdentity`, `identityEncryptionInfo`, `serverEncryptionInfo`, `signatureVerifier`. Drop these `CollectionConfig` fields: `clientEncrypted`, `publicKey`. Add the optional `keyringPath` if your keyring lives at a non-default path. Install only the plugins for the cap kinds you accept — omit `sharingServerPlugin` if your deployment never issues member caps. Strict-kind dispatch is always on (secure by default): if you pass **no** `plugins` the resolver accepts `device` caps only and rejects `member` caps, so wire `sharingServerPlugin` the moment you start issuing them.

The custom-`roleResolver` extension point is preserved for non-cap-cert auth (e.g. tying Starfish identities to an existing OAuth provider). The default v3.0 path is `createCapCertRoleResolver`.

### Replica collections

Replication moved out of `starfish-server` into `@drakkar.software/starfish-replica` / `starfish-replica` (Py). The `remote` field on `CollectionConfig` and the `replicaManager` option on `createSyncRouter` are **both removed**; `ReplicaManager` / `RemoteConfig` / `WriteMode` / `SyncTrigger` no longer import from `starfish-server`.

**Before (v2.x / pre-extraction):**

```ts
import { ReplicaManager, createSyncRouter } from "@drakkar.software/starfish-server"

const replicaManager = new ReplicaManager(store, config.collections) // read remote off each collection
const router = createSyncRouter({ store, config, roleResolver, replicaManager })
// config had: collections: [{ ..., remote: { url, pullPath, writeMode, ... } }]
```

**After (v3.0):**

```ts
import { createSyncRouter, createGracefulShutdown } from "@drakkar.software/starfish-server"
import { createReplicaServerPlugin } from "@drakkar.software/starfish-replica"

// remote configs are passed to the plugin, keyed by collection name — not nested in CollectionConfig
const replica = createReplicaServerPlugin({
  store,
  syncConfig: config,
  collections: { posts: { url, pullPath, intervalMs, headers, writeMode: "pull_only", syncTriggers: ["scheduled"] } },
})
const router = createSyncRouter({ store, config, roleResolver, plugins: [replica] })
replica.manager.start()
createGracefulShutdown({ plugins: [replica] }) // shutdown hook stops the sync timers
```

Move every `collection.remote` block into the plugin's `collections` map (keyed by the collection's `name`), drop the `remote` field from your `CollectionConfig`s, and replace `replicaManager` / `replica_manager` with `plugins: [replica]` (`plugins=[replica.plugin]` in Python). The cross-cutting validation rules (a remote collection can't be `appendOnly`, binary, `pushOnly`, bundled, `delegated`-encrypted, or have a templated `storagePath`; `push_through`/`bidirectional` need `pushPath`) are unchanged — they now run inside `createReplicaServerPlugin` and throw at construction.

### Removed: group role enricher

`createGroupRoleEnricher` / `create_group_role_enricher` and `GroupRoleEnricherOptions` are **removed** in 3.0. They were a server-evaluated, list-based RBAC enricher (read `groups/{groupId}/members`, grant `group-member`) plus a candidacy/request-to-join flow — a paradigm at odds with v3's "authority is a signed capability, the server holds no membership lists" model. `composeEnrichers` / `compose_enrichers` and the entitlement enricher are unchanged.

Migrate each use-case to member capability certificates (`@drakkar.software/starfish-sharing` / `starfish-sharing`):

| Old (group enricher) | New |
|---|---|
| `group-member` role from a `members` list | A `member` cap per recipient: `mintMemberCap(ownerEd, ownerEdPub, sub, col, scopes.writer(col))`. The collection opts into `delegated:<ownerId>:<col>`. |
| `group-admin` writing the roster | The owner-only `<col>/_members` audit directory (`addMemberEntry` / `listMembers`); it is metadata, not an authorization source. |
| Bulk membership in one document | One cap per recipient (linear). If you genuinely need a server-authoritative allow-list, write your own `RoleEnricher` (≈10 lines) reading your list — that is the trade-off the built-in made. |
| Candidacy / request-to-join | App-level recipe — invitee pushes `<col>/_requests/{subUserId}` (gated by `"self"`); owner vets, then `mintMemberCap` + `addRecipient`, delivering the cap out-of-band. No built-in flow. |

```ts
// Before (v2.x)
import { createGroupRoleEnricher } from "@drakkar.software/starfish-server"
roleEnricher: createGroupRoleEnricher({ store, membersPath: "groups/{groupId}/members", groupParam: "groupId" })

// After (v3.0) — owner mints a writer cap for each member
import { mintMemberCap, scopes } from "@drakkar.software/starfish-sharing"
const cap = await mintMemberCap(owner.edPriv, owner.edPub, recipient, "chat", scopes.writer("chat"))
// collection: { name: "chat", readRoles: ["delegated:<ownerId>:chat"], writeRoles: ["delegated:<ownerId>:chat"], ... }
```

See [Group & Shared-Collection Access](../ts/server/group-access.md) for the full patterns (group chat, request-to-join, large-roster custom enricher).

## Data migration

### 1. `userId` rewriting

`userId` is now `sha256(rootEdPub)[0:32]` instead of `sha256(passphrase)[0:16]`. Every stored key whose path contains `{identity}` (e.g. `users/abc123.../notes`) needs to be moved to the new userId.

**No automated migration tool ships with 3.0.** Operators run their own offline migrator; the algorithm below is the one you implement. Tooling is a deferred follow-up (a future minor may ship a reference CLI).

Per-user algorithm (idempotent):

1. Look up the user's passphrase via your auth provider (the same mechanism that fed v2 `deriveCredentials`).
2. Compute the v2 `userId` as `sha256(passphrase)[0:16]` (the v2 derivation) and the v3 `userId` as `sha256(rootEdPub)[0:32]` (where `rootEdPub` is `bootstrapRootIdentity(passphrase).rootEdPub`).
3. For every stored key whose `{identity}` placeholder resolves to the v2 userId, copy the value to the corresponding key under the v3 userId. Verify the copy succeeded before deleting the original.
4. After verification, delete the v2-userId keys.

Run the algorithm in a two-phase fashion: first a dry-run pass that prints the proposed key moves; then the real run that performs the copy-then-delete sequence.

### 2. Encryption-mode conversion

For each collection whose v2 `encryption` was:

- `"identity"` or `"server"` — the server holds the key. Your migrator must (a) decrypt the value server-side with the old key, (b) re-wrap the resulting plaintext under `"delegated"` by encrypting with a fresh CEK, (c) build a v3 keyring document at `<collection>/_keyring` wrapping that CEK for the user's new X25519 pub. Done in the same pass as userId rewriting.
- `"group"` — rename to `"delegated"`. The existing group keyring documents (map-shape `wrappedKeys`) must be rewritten into the v3 shape (list of `{subKem, ephKem, ct, addedBy, addedSig, addedAt}`). For each member, generate an ephemeral X25519 priv per entry, wrap the existing GEK, and sign with the original admin's Ed25519 (recovered from the v2 admin passphrase via `bootstrapRootIdentity`). If the admin Ed25519 is unavailable (e.g. you only kept the X25519 keys), fall back to signing with a freshly-derived root from the admin's passphrase — re-signing the audit trail. Document this in your migration audit log.
- `"none"` / `"delegated"` — no data change required.

### 3. Operational sequencing

1. Pause writes (or accept that in-flight writes during the migration may need retry).
2. Run your migrator in dry-run mode; review the report.
3. Run the migrator for real. Keep the old keys in place until the migrator confirms the new keys are in the store (implement copy-then-delete two-phase commit).
4. Deploy v3.0 servers. v3.0 servers will only read from the new key shape.
5. Deploy v3.0 clients. They will call `bootstrapRootIdentity` on first launch and produce a v3 cap-cert.
6. After a soak period, run the cleanup phase of your migrator to remove the old keys.

## Test vectors

- `tests/test-vectors/group-crypto.json` is removed at v3.0. Any consumer reading it must switch to `tests/test-vectors/multi-recipient-wrap.json`, which uses the new schema.
- The other v2 vectors (`hash.json`, `crypto.json`, `protocol-push.json`, `protocol-timestamps.json`, `http-errors.json`) are unchanged.

## Verification checklist

After the upgrade is rolled out:

- [ ] Existing users can sign in with their v2 passphrase and see their v2 data through the new userId path.
- [ ] A new device can pair with an existing user via QR or the relay flow and read every collection the root has access to.
- [ ] A removed device cannot decrypt documents written after its removal (`removeRecipient` rotates the epoch).
- [ ] The server logs no `signatureVerifier`-related warnings; `Authorization: Cap` is the only auth scheme appearing in requests.
- [ ] `pnpm test` and `uv run pytest -v` in each Python package are fully green against the upgraded codebase.

## Known limitations

- **Forward secrecy for documents is not provided** — by design. Persistent documents must remain decryptable by current recipients, which is incompatible with full FS. Post-compromise security is provided via epoch rotation. See [`docs/ts/client/23-multi-recipient-delegated.md`](../ts/client/23-multi-recipient-delegated.md) for the full discussion.
- **Recipient set is server-visible metadata** — the `subKem` of each recipient appears in the (plaintext) keyring document. Encrypted-collection ciphertext is opaque, but membership is not.
- **No sub-delegation in 3.0** — a device cannot mint a cap-cert for a further sub-device. Only the root identity can mint caps. Sub-delegation (macaroon-style attenuation) may land in a future minor.
