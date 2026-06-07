# Changelog

## 3.0.0-alpha.20 — Identity action restrictions + client-side outbox + keyring seal + client mutateDoc + generic sync-server auth/enricher primitives

Two new extensions plus client/keyring helpers. **Identity action restrictions** add a
way to **deny** access by identity, scoped to the whole server, a namespace, a
collection, or a single action (`pull` / `push` / `list`). Where roles and cap scopes
*grant* access, restrictions *remove* it. Ships as a new extension package
(`@drakkar.software/starfish-restrictions` / `starfish-restrictions`) on top of a small,
generic `authorize` plugin hook added to the server core. The **outbox** extension is a
new generic client-side offline-first write queue, alongside a sealed-envelope helper in
`keyring` and a hash-CAS document mutator in `client`. Lands in TypeScript and Python.

This release also lands a set of **generic sync-server primitives** extracted from
downstream apps (full TS + Python parity): registry/TOFU and issuer-bound role
enrichers (`starfish-sharing`); an identity-match role enricher, a bodyless cap-cert
meta-request authenticator, and an authenticated SSE-proxy router (`starfish-server`);
a request-signing client for authenticated replicas (`starfish-replica`); and a
`CORS_ALLOW_HEADERS` protocol constant. They move auth/enricher mechanism that apps
were hand-rolling into the library.

### Added

- **`starfish-restrictions` extension package** (TS + Python) exposing
  `createRestrictionsPlugin({ rules, config })` / `create_restrictions_plugin(...)`
  and `restrictionsFromConfig` / `restrictions_from_config`. Each rule has a
  `mode` (`"deny"` blocks listed identities; `"allow"` permits only listed
  identities), an `identities` source (static array **or** callback, sync/async),
  and an optional `scope` (`namespace` / `collection` / `action`). **Deny beats
  allow**; the caller must satisfy every applicable `allow` rule; anonymous
  callers never satisfy an `allow` rule.
- **`authorize` plugin hook** on `ServerPlugin` (protocol) with `AuthorizeContext`
  / `AuthorizeResult` types, plus `dispatchAuthorize` / `hasAuthorizeHook`
  (`dispatch_authorize` / `has_authorize_hook`) on the server. Fires at the
  central authorization gate for every action — pull, push, list, and each
  batch-pull / bundle-pull member — after roles resolve and the role check passes.
- **Static `restrictions` config** on `SyncConfig`, `NamespaceConfig`, and
  `CollectionConfig` (the new `IdentityRestriction` type: `mode`, `identities`,
  optional `actions`). Compiled into rules by the restrictions plugin. Not exposed
  via `GET /config`.
- **`@drakkar.software/starfish-outbox` / `starfish-outbox`** — durable, per-identity
  offline write-queue (the client-side complement to server `queuing`). Generic over
  an opaque item; dedup-by-id, single-shot claim (no double-send), auto-retry-then-fail,
  crash-safe `sending` recovery, write-through persistence. `drainOutbox` is
  connectivity-agnostic.
- **`keyring`**: `seal` / `unseal` / `sealToSelf` / `unsealFromSelf` — wrap a secret to a
  single static X25519 KEM key for carrying inside a plaintext synced doc (sealed
  credentials, bearer secrets, peer hand-offs).
- **`client`**: `mutateDoc(client, path, mutator, { maxAttempts })` — generic
  pull→mutate→push-with-hash→retry-on-`ConflictError` loop; a 404 is surfaced as an
  absent doc the mutator may create, a `null` return is a no-op.
- **`makeIdentityRoleEnricher` (TS) / `make_identity_role_enricher` (Python)** in
  `starfish-server` — a generic `RoleEnricher` granting a fixed `role` when
  `auth.identity` exactly equals a configured `identity` (empty otherwise; an
  anonymous/empty identity is never elevated). Generalizes the per-app
  "platform admin" enricher. Exported next to `composeEnrichers` /
  `compose_enrichers`.
- **`authenticateMetaRequest` (TS) / `authenticate_meta_request` (Python)** in
  `starfish-server` (`router/cap-resolver`) — a reusable primitive that
  authenticates a BODYLESS meta-request (e.g. an SSE subscribe) over the SAME
  verify pipeline as the sync cap-cert resolver (clock-skew → `verifyCapCert` →
  per-kind plugin validators → per-request Ed25519 signature → nonce replay →
  revocation), but with an empty body hash and NO `scope.paths` enforcement
  (per-resource authorization is the caller's job). Rejects audience caps
  up-front (configurable `acceptKinds`, default `device`/`member`); returns the
  bound identity (device → `issUserId`, member → `subUserId`) or `null` on any
  failure. Lets apps stop hand-reimplementing the cap-cert auth pipeline.
- **`createEventsProxyRouter` (TS) / `create_events_proxy_router` (Python)** and a
  shared **`DEFAULT_SAFE_ID`** (`^[a-zA-Z0-9_-]+$`, matched in full) in
  `starfish-server` — a framework router factory for an authenticated SSE proxy
  exposing a single `GET /events`. Generic over an `authenticate` callback (uses
  the meta-request authenticator), a bounded `?<candidatesParam>=a,b,c` list
  (400 over `maxCandidates`), an `authorize(identity, candidate)` policy, an
  optional `publicPredicate` open-gate, an `idPattern` charset gate applied on
  both branches, a `topicMapper` upstream-topic transform, a `maxTopics` cap
  (silent truncation beyond), and a firehose-prevention invariant that always
  sends at least one `topic=` (substituting the sentinel `__none__` when nothing
  is authorized). Proxies the upstream SSE stream, propagating client disconnect,
  and returns `502` when the upstream is not OK.
- **`makeRegistryRoleEnricher` (TS) / `make_registry_role_enricher` (Python)** in
  `starfish-sharing` — a generic registry / trust-on-first-use (TOFU) owner-member
  role enricher. Reads an owner-written `_registry` document (`{ owner, members }`)
  at a configurable path template and grants a configurable `ownerRole` /
  `memberRole`. Generalizes the per-app product/space enrichers: configurable
  `idParam`, `registryPath` (with `{id}` placeholder), roles, an `allowTofu` flag
  (default `true`; pass `false` for the strict SSE/events variant), and an
  `idPattern` (default `DEFAULT_SAFE_ID` = `^[a-zA-Z0-9_-]+$`, matched in full to
  guard trailing-newline bypasses). Fails CLOSED on store errors (the error
  propagates → 500) and on owner-less/unparseable docs (never re-opens TOFU).
  Receives the store as an argument and depends on `starfish-server` for TYPES only
  (no runtime coupling).
- **`makeIssuerBoundRoleEnricher` (TS) / `make_issuer_bound_role_enricher` (Python)**
  in `starfish-sharing` — a generic issuer-bound public-share role enricher that
  decides roles purely from the requester's cap (no store access). Grants
  `ownerRole` + `readerRole` to the owner's own device cap, `readerRole` to caps
  the owner delegated for one of `collections` (resolver-synthesized
  `delegated:<owner>:<col>`), and additionally `writerRole` when such a cap carries
  `cap:write:<col>` AND the request does not target the guard doc
  (`guardParam`/`guardValue`, e.g. the `_rooms` registry). Generalizes the
  per-app public-space enricher.
- **`ReplicaAuth` (Python) / `createReplicaAuth` (TS)** in `starfish-replica` — a
  request-signing client for authenticated replicas. Bootstraps (or accepts a
  pre-bootstrapped) device cap-cert from a passphrase, signs every outgoing
  pull/push with `sign_request`/`signRequest`, and attaches the `Authorization:
  Cap …` + `X-Starfish-Sig`/`-Ts`/`-Nonce` headers. Re-mints the cap
  transparently as it nears expiry (configurable margin) so long-uptime replicas
  never 401-storm. Python ships an `httpx.Auth` (inject via
  `AsyncClient(auth=…)`); TS ships a signing `fetch` wrapper (inject via
  `ReplicaManager`'s `fetchFn`). Generalizes plumbing previously hand-rolled by
  apps. `starfish-replica` now depends on `starfish-identities`.
- **`CORS_ALLOW_HEADERS`** protocol constant — a canonical list of the non-simple
  request headers (`Authorization`, `Content-Type`, the `X-Starfish-*` auth
  headers, plus `X-Requested-With`) a server should advertise in
  `Access-Control-Allow-Headers`. Built from the existing `HEADER_*` constants so
  downstream apps import it instead of re-hardcoding the header names (TS +
  Python).

### Changed

- All packages bumped to `3.0.0-alpha.20` (lockstep). The lockstep set grows from 22 to
  26 packages with the new `restrictions` and `outbox` extensions (TS + Python). CI
  publish workflows gain the matching test steps and per-package publish jobs.
- A collection whose role check would normally short-circuit anonymously (a
  `public` collection) now resolves the caller's identity when an `authorize` hook
  is installed, so identity restrictions apply to public collections too. Behavior
  is unchanged when no `authorize` hook is wired.
- `createSyncRouter` / `create_sync_router` now logs a warning when a config
  declares `restrictions` but no plugin provides an `authorize` hook (the
  restrictions would otherwise be silently unenforced).

### Fixed

- `keyring` (Python): `unseal` length guard now references the same IV constant it slices
  with.
- `client` (Python): `mutateDoc` keeps an empty-string server hash verbatim instead of
  coercing it away (matches the TS `?? null`).

## 3.0.0-alpha.19 — Bounded append-only pulls (`limit` / `full`)

Append-only pulls must now declare how much they fetch. Previously a plain
`GET <path>` on an append-only collection returned the **entire** log — a footgun
that grows with the log. A pull must now carry one of `?checkpoint=`
(incremental), `?limit=`/`?last=` (tail of K), or `?full=true` (explicit "the
whole collection"); an unbounded pull is rejected `400 pull_bound_required`.
Server operators get three new knobs to cap what readers may request. Lands in
TypeScript and Python (server + client).

### Added

- **`?limit=N` append-only pull param** — an alias of the existing `?last=N`
  (tail of the newest N, applied after the checkpoint filter). When both are
  given, `limit` wins. Exposed on the client as `pull(path, { limit })` (TS) /
  `pull(path, limit=...)` (Python).
- **`?full=true` append-only pull param** — explicitly fetch the whole
  collection. Mutually exclusive with `checkpoint`/`limit`/`last`: combining them
  is rejected `400 full_with_bounds` (the client raises before sending). Exposed
  as `pull(path, { full: true })` (TS) / `pull(path, full=True)` (Python).
- **`appendOnly.allowFull`** collection config (default `true`) — set `false` to
  reject `?full=true` (`400 full_not_allowed`), forcing every reader to bound its
  fetch.
- **`appendOnly.maxPullLimit`** collection config — caps the `limit`/`last` tail a
  pull may request; a larger request is silently clamped down.
- **`appendOnly.maxCheckpointAgeMs`** collection config — rejects a `?checkpoint=`
  older than `now - maxCheckpointAgeMs` (`400 checkpoint_too_old`), stopping
  readers from rewinding to ancient history.
- New error codes `pull_bound_required`, `full_with_bounds`, `full_not_allowed`,
  `checkpoint_too_old`, and query-param constants `QUERY_LIMIT` / `QUERY_FULL` /
  `QUERY_LAST` (TS + Python).

### Changed

- **BREAKING:** an append-only pull with none of `checkpoint`/`limit`/`last`/`full`
  now returns `400 pull_bound_required` instead of the full collection. Callers
  doing a bare full pull must add `?full=true` (or a bound). `AppendLogCursor`
  (both languages) now sends `?full=true` automatically on cold start, so cursor
  users need no change.

## 3.0.0-alpha.18 — EVM-signature root-identity bootstrap

Lets a user with an existing EVM wallet (MetaMask, a hardware signer, any
secp256k1 EOA) bootstrap a Starfish identity without exposing the EVM private
key — the secp256k1-signature path of a12, applied to ECDSA/EIP-191 instead of
BIP-340 Schnorr. The EVM key never appears on the wire; Starfish holds only the
derived Ed25519 identity. Lands in TypeScript and Python.

### Added

- **`deriveRootIdentityFromEvmSignature` (TS) / `derive_root_identity_from_evm_signature` (Python)**
  in `starfish-identities`. The caller signs a challenge (default
  `EVM_BOOTSTRAP_CHALLENGE`, or an app-supplied one) with their EVM wallet via
  EIP-191 `personal_sign`; the 65-byte `r‖s‖v` signature is verified by recovering
  the signer over that challenge (keccak256 EIP-191 digest → secp256k1 ECDSA
  recover) and checking it equals the supplied address, then HKDF-SHA256-expanded
  (salt `starfish-v3-bootstrap-evm`) into the Ed25519 sign + X25519 KEM seeds.
  Determinism contract: the caller MUST sign with deterministic ECDSA (RFC 6979 —
  the default for eth-account / ethers / viem); EIP-191 personal-sign carries no
  per-call salt, so a standard signer is reproducible. The signature is
  **private-key-equivalent** — derive once, never log/persist/transmit it.
- **App-customizable challenge** — the optional `challenge` argument (TS
  `EvmBootstrapInput.challenge`; Python keyword) lets an app namespace its
  identities (e.g. `"myapp:bootstrap"`): a distinct challenge yields a distinct
  `user_id` from the same wallet. The challenge passed must equal what the wallet
  signed, and an app must keep it fixed forever.
- **`EVM_BOOTSTRAP_CHALLENGE` (TS + Python)** — the default personal-sign message
  (`"starfish:bootstrap-evm"`). Byte-identical across languages.
- **`evm` variant of `BootstrapOrigin`** (`{ kind: "evm", address }`) recording the
  originating EVM address on a bootstrapped `RootIdentity`. Non-load-bearing — never
  on the wire; for external systems (wallet-aware UIs, audit logs) to display the source.
- **`EvmBootstrapInput` type** (TS) exported from `starfish-identities`.
- **`tests/test-vectors/identity-derivation-evm.json`** — cross-language lock vector
  for the EVM bootstrap derivation.

### Changed

- `starfish-identities` (Python) gains a `pycryptodome` dependency (keccak-256 for the
  EIP-191 digest + address recovery); `coincurve`, already present for the secp256k1
  verify, performs the ECDSA recovery.
- Lockstep version bump of the whole suite a17 → a18.

## 3.0.0-alpha.17 — publish the projection package

### Fixed

- **`starfish-projection` is now actually published** to npm and PyPI. The package
  shipped in source in a16 but the release workflows had no job for it, so the
  `v3.0.0-alpha.16` tag published every package *except* projection — leaving
  downstreams that pin `starfish-projection==3.0.0a16` unable to install it. Both
  `publish-typescript.yml` and `publish-python.yml` now build, test and publish
  `projection` alongside the other packages (`needs: protocol, server`).

### Changed

- Version bump of the whole suite a16 → a17 (no API changes; release-plumbing only).

## 3.0.0-alpha.16 — new projection (incremental-list) extension

A new building block for directory/index-style features: maintaining a single
denormalized **list document** from a source of truth without a bespoke indexer, so
a client fetches the whole list in one pull. Lands in TypeScript and Python.

### Added

- **`@drakkar.software/starfish-projection` / `starfish-projection`** — a new
  incremental-list extension. After a successful push, its `afterWrite` hook runs an
  app-supplied pure `project(event)` for each watched `source` collection and folds
  the outcome into a single target list document: `{ id, value }` appends a new entry
  or replaces an existing one in place (keeping its position), `{ id, remove: true }`
  removes it (a tombstone push — there is no delete route), `null` ignores the event.
  The list is stored as `{ items: [{ id, value }, …] }` in insertion order; the client
  pulls that one document to read the whole list. The plugin owns all store IO and the
  read-modify-write; the app supplies only the mapping. Writes go in-process (never
  over HTTP), so the target collection can be declared `pullOnly: true` — clients read
  it, only the projection writes it. Concurrent writes to one list are safe via a
  compare-and-set retry loop (no update is lost); `target` may be a function for
  per-tenant/bucket **sharding** and `maxItems` caps a list's size, since every write
  rewrites the whole document. Projection failures are logged and never break the
  originating client write (same contract as `starfish-queuing`).
- **Per-action collection rate limiting** — a collection's `rateLimit` now accepts
  independent `push` / `pull` / `list` rules, each with its own `windowMs`, `maxRequests`,
  and `bucket` mode, and each with its own counter (exhausting one action never throttles
  another). `pull` and `list` are now rate-limitable (previously only `push` was). A rule's
  `bucket` may be `"identity"` (default; per authenticated caller, falling back to
  X-Forwarded-For / IP / anonymous), `"ip"` (strictly per IP — e.g. "10 push / hour / ip"),
  or `"identity+ip"` (one budget per distinct `(identity, ip)` pair). Alternatively a rule
  can declare **two independent limits** via `identity` and/or `ip` sub-limits — each its own
  counter, with the request rejected if *either* is over budget ("≤N per identity AND ≤M per
  ip"); a rule uses `bucket` or the sub-limits, not both. `windowMs` / `maxRequests` inherit
  from the flat collection fields then the global `rateLimit`. The legacy flat
  `{ windowMs, maxRequests }` form is unchanged — it still limits `push` only and still
  requires a global `rateLimit`, so existing configs are unaffected. Enforcement defaults to
  in-memory per process. Lands in TypeScript and Python; see `docs/ts/server/rate-limiting.md`.
  (TS/Hono caveat: IP-based bucketing relies on `X-Forwarded-For`; the config loader warns
  when it is used.)
- **Pluggable `KVAdapter` for ephemeral server state** — a small async key-value abstraction
  (`increment` for windowed counters, `recordIfAbsent` for nonces) backing both the
  rate-limit counters and the replay-protection nonce cache. Defaults to an in-memory
  (process-local) implementation that preserves the previous behavior; pass a shared adapter
  as `rateLimitStore` (router option) and/or build a nonce cache with `createKvNonceCache(kv)`
  to enforce limits and replay protection **across server instances**. Ships a Garage K2V
  backend (`createK2VAdapter` + `createFetchK2VTransport`): because K2V has no CAS, no atomic
  increment, and no native TTL, the backend embeds expiry in each value, **sums** concurrent
  counter siblings (overcount = fail-closed, never undercount), and does best-effort
  read-then-write for nonces (a narrow concurrent-duplicate replay window remains — use a
  CAS-capable store to close it). The `RateLimiter.check` / `NonceCache.checkAndRemember`
  APIs are now **async** to accommodate networked backends. Lands in TypeScript and Python.

## 3.0.0-alpha.15 — offline-first read cache (ciphertext-at-rest)

Adds a generic, opt-in offline-first read path to the client. A `StarfishClient`
given a `cache` writes every successful structured `pull()` through to it (keyed by
document path) and, when a later pull fails because the **transport** is unreachable
(`fetch` rejects — offline/DNS/timeout), returns the last cached snapshot instead of
throwing. A real HTTP error (404/403/5xx) is a genuine server answer and still
propagates — the cache is not consulted — so "no document yet" and "access denied"
keep their meaning. The cache stores the raw server payload, which for E2E
(`delegated`) collections is the sealed ciphertext the server holds, never the
decrypted form, so it is **ciphertext-at-rest by construction**; decryption happens
in memory on read. On the zustand binding this powers cache-first paint: the store
seeds from the cache before its initial pull and exposes a `stale` flag so a UI can
show an "offline / showing last-synced data" indicator that clears on the next live
pull. **TS-only release** — client-side only; the TS packages bump to
3.0.0-alpha.15 while the Python packages stay at 3.0.0a13 (no Python change).

### Added

- **`StarfishClientOptions.cache` (TS `starfish-client`)** — an optional `PullCache`
  (`{ get(k): Promise<string|null>; set(k, v): Promise<void> }`, host-backed). When
  set, `pull()` writes through on success and falls back to the cached snapshot on a
  transport failure (tagged via the exported `pullWasFromCache(result)`). Append
  collections are excluded (they persist via `AppendLogCursor`).
- **`StarfishClientOptions.cacheMaxAgeMs`** — optional TTL; an entry older than this
  is treated as a miss on every read. Omit for entries that never expire
  (recommended for offline-first).
- **`StarfishClient.peekCache(path)`** — read the cached snapshot without a network
  round-trip (basis for cache-first paint).
- **`SyncManager.seedFromCache()` / `getLastPullFromCache()`** — seed `localData`
  from the client cache, decrypting in memory for E2E collections; report whether the
  latest pull/seed came from cache.
- **zustand store: `seed()` action + `state.stale` flag**, and new
  `SyncInitConfig.cache` / `cacheMaxAgeMs`; `useSyncInit` seeds before the initial
  pull. Backwards-compatible — without a `cache`, behavior is unchanged.

## 3.0.0-alpha.14 — zustand `pull()` no longer discards un-pushed local writes

Fixes a data-loss bug where an optimistic local write could vanish. A `set()` on a
zustand-bound store mutates only the store's `data` and marks it `dirty`; the write
reaches the server (and the `SyncManager`'s local mirror) only once a push succeeds.
A plain `pull()` overwrote the store's `data` with the freshly fetched server
snapshot — so if a pull ran while a write was still un-pushed (e.g. a concurrent
write arrived over a live event stream, a poll fired, or a screen re-pulled on
focus), the local write was silently dropped. End-to-end-encrypted documents were
the most exposed because their pull always decrypts a full snapshot. The in-*push*
conflict path was never affected — it already unions the caller's pending data with
the remote. **TS-only release** — the affected store binding has no Python
counterpart, so the TS packages bump to 3.0.0-alpha.14 while the Python packages stay
at 3.0.0a13 (no Python change).

### Fixed

- **`createStarfishStore.pull` (TS `starfish-client`, `./zustand`)** now preserves
  un-pushed optimistic writes. When the store is `dirty`, the pulled snapshot is
  merged with the current store data through the store's configured `onConflict`
  resolver (the same one the push-conflict path uses) instead of overwriting it, and
  a flush is kicked (gated on `dirty` + `online`, like `setOnline`) so the preserved
  write still reaches the server. A clean (non-dirty) pull is unchanged — it takes
  the server snapshot verbatim. Consumers that use a union/CRDT-style resolver (e.g.
  `createUnionMerge`) keep both the local and remote writes; consumers on the default
  `deepMerge` keep prior behavior for arrays.

### Added

- **`SyncManager.resolve(local, remote)`** — applies the manager's conflict resolver
  to a pair of snapshots. Lets the store binding reuse the configured resolver to
  reconcile un-pushed local data with a pulled snapshot. The `onConflict` field stays
  private.

## 3.0.0-alpha.13 — writer identity on `WriteEvent`; opt-in identity forwarding in the queuing plugin

Plugins can now learn *who* performed a write. The server already authenticates the
writer (the cap-bound identity used for authorization and the audit log) but never
surfaced it to `afterWrite` hooks; it does now. The queuing plugin gains an opt-in
flag to forward that identity into published messages, enabling downstream consumers
(e.g. a push bridge) to address or exclude a specific user — without the server ever
exposing message *content*. Lockstep bump of all packages to 3.0.0-alpha.13 / 3.0.0a13.

### Added

- **`WriteEvent.identity`** (TS `starfish-protocol`; Python `starfish_protocol.plugins`):
  the authenticated writer's cap-bound userId handed to every `afterWrite` hook —
  `issUserId` for a device cap, `subUserId` for a member cap, the presenter's derived
  userId for an audience cap; absent for an unauthenticated (public) write. The server
  threads the already-resolved request identity (the same value the audit logger
  records) into the event at every push site (JSON, binary, bundle).
- **`QueueConfig.includeIdentity` (TS) / `QueueConfig.include_identity` (Python)** on the
  queuing plugin, default **false**. When enabled for a collection, the published
  `QueueMessage` carries the writer's userId as `identity`. Off by default because it
  exposes *who* wrote each document to the broker — metadata the server otherwise never
  emits — so it is strictly per-collection opt-in.
- **`QueueMessage.identity`** field (TS + Python), present only when `includeIdentity`
  is set for the collection.

### Changed

- `WriteEvent` / `QueueMessage` gain one optional field each; both are additive and
  backward-compatible — existing hooks and consumers that ignore the new fields are
  unaffected, and identity is never published unless a collection opts in.

## 3.0.0-alpha.12 — ed25519-only wire; secp256k1 root bootstrap via signature derivation

Starfish now speaks a single signature suite on the wire: Ed25519 signing + X25519 KEM.
The `secp256k1-schnorr` peer suite is removed from the protocol, keyring, and downstream
packages. Users with an existing secp256k1 root (Nostr / BIP-340) can still bootstrap a
Starfish identity via a new signature-based derivation in `starfish-identities`: the
caller signs a fixed bootstrap challenge with their external Schnorr signer, and the 64-byte
signature is HKDF-expanded into the Ed25519 + X25519 seeds. The secp256k1 root never
appears on the wire. Lockstep bump of all twenty packages to 3.0.0-alpha.12 / 3.0.0a12.

### Added

- **`deriveRootIdentityFromSecp256k1Signature` (TS) / `derive_root_identity_from_secp256k1_signature` (Python)**
  in `starfish-identities`. Takes a BIP-340 Schnorr signature over the fixed 32-byte
  `SECP256K1_BOOTSTRAP_CHALLENGE` (sha256 of `"starfish-v3:bootstrap-secp256k1"`) plus the
  originating secp256k1 x-only pubkey; verifies the signature, then HKDF-SHA256-expands the
  signature into Ed25519 sign + X25519 KEM seeds. Determinism contract: caller must sign with
  deterministic Schnorr (`aux_rand = 0`).
- **`bootstrapOrigin` (TS) / `bootstrap_origin` (Python)** optional metadata on `RootIdentity`
  recording the secp256k1 pubkey when an identity was bootstrapped from one. Non-load-bearing
  — never appears on the wire; for external systems (Nostr-aware UIs, audit logs) to display
  the bootstrap source.
- **`BootstrapOrigin` and `Secp256k1BootstrapInput` types** exported from
  `starfish-identities` (TS) / `starfish_identities` (Python): `BootstrapOrigin` is the
  discriminated-union type of the optional `bootstrapOrigin` field on `RootIdentity`
  (currently `{ kind: "secp256k1", pubHex }`); `Secp256k1BootstrapInput` is the input shape
  for `deriveRootIdentityFromSecp256k1Signature` (`{ secpPubHex, signature }`).
- **`tests/test-vectors/identity-derivation-secp256k1.json`** — cross-language lock vector
  for the bootstrap derivation.

### Changed

- **Wire format**: cap-certs, request signatures, revocation lists, append-author signatures,
  and keyring entries no longer carry a `alg`/`issAlg`/`subAlg`/`subKemAlg`/`kemAlg`/`addedByAlg`
  suite discriminator. Cap-certs always carry `subKem` (the X25519 KEM key, separate from the
  Ed25519 signing key). The `X-Starfish-Alg` HTTP header is removed.
- `recipientKem` (TS) / `recipient_kem` (Python) now returns the KEM pubkey only.

### Removed

- The `secp256k1-schnorr` crypto suite, the `Alg` type, the suite registry (`getSuite` /
  `get_suite`, `DEFAULT_ALG`, `is_alg`, `suite_has_separate_kem`).
- The deferred secp256k1 pairing gate (`assertEd25519PairingSuite`) — pairing was always
  ed25519, now naturally so.
- `coincurve` dependency from `starfish-protocol` (moved to `starfish-identities` where it's
  used only to verify the bootstrap signature).
- Test vectors `suite-secp256k1.json`, `suite-secp256k1-ecdh.json`,
  `keyring-wrap-secp256k1.json`, and their generators.

### Breaking

- Cap-certs / request signatures / revocation lists / keyring entries from 3.0.0-alpha.4
  through 3.0.0-alpha.11 that carried a non-default `alg` field DO NOT verify under
  alpha.12 — their canonical signed input differs. Pre-stable break, acceptable per the
  3.0.0-alpha series. Persisted documents in production should be re-signed; no migration
  path is provided.

## 3.0.0-alpha.11 — `batchPull` fan-in: many documents per collection in one round-trip

`batchPull` (TypeScript + Python, client + server) reshapes its params + response
so the SAME collection can fan in many documents in a single round-trip — e.g.
ten users' `profile` documents fetched together, instead of one collection name
per request. Adds a thin `batchPullMany` / `batch_pull_many` helper for the
common single-collection case. Lockstep bump of all twenty packages to
3.0.0-alpha.11 / 3.0.0a11.

### Changed

- **`batchPull` params shape** — `params[collectionName]` is now an **array of
  param-sets**, one per document to read from that collection (e.g.
  `{profile: [{identity: "a"}, {identity: "b"}]}` reads two profiles in one
  round-trip). A collection passed with `[{}]` (or omitted from `params`
  entirely) reads one self-doc with `{identity}` auto-filled from the
  authenticated caller. Mirrored across TS + Python clients and the server's
  router + OpenAPI.
- **`batchPull` response shape** — `collections[name]` comes back an **array of
  `BatchPullEntry`** in request order (one per requested param-set), instead of
  a single object. A collection read with no params yields a one-element array.
- **`maxCollectionsPerBatch`** now bounds the **total number of reads** (sum of
  param-set arrays across collections), not the count of distinct collection
  names — a single batch with one collection × 50 param-sets is bounded the
  same way as 50 collections × one param-set.
- OpenAPI `params` query parameter documentation and the namespaces guide
  (`docs/ts/client/20-namespaces.md`) updated to the new array shape.

### Added

- **`batchPullMany` (TS) / `batch_pull_many` (Python)** — convenience helper
  for fanning in many documents from a single collection without building the
  outer `params` object manually. Wraps the array shape under the hood.

### Breaking

- The old object-per-collection `params` shape (`{notes: {teamId: "x"}}`) is
  no longer accepted — the server returns **400** when a value is a plain
  object instead of an array. Callers must rewrite to the array form
  (`{notes: [{teamId: "x"}]}`). Pre-stable break.

## 3.0.0-alpha.10 — append-log cursor: skip policy, safe concurrency, E2EE-safe persistence

`AppendLogCursor` (TypeScript + Python) gains three opt-in, additive capabilities that let it
back a multi-writer, end-to-end-encrypted append-only log directly — behaviors a consumer
previously had to hand-roll around the cursor. All defaults preserve the prior behavior.
Lockstep bump of all twenty packages to 3.0.0-alpha.10 / 3.0.0a10.

### Added

- **Per-element error policy `onElementError: "throw" | "skip"`** (TS) / `on_element_error`
  (Python), default `"throw"`. Under `"skip"`, an element that fails author verification or
  decryption is dropped from the returned batch **and the checkpoint still advances past it**,
  so one poison element (keyring skew, a foreign / corrupt / wrong-key element) cannot blank —
  or permanently wedge — the log. `"throw"` keeps the prior atomic-pull behavior (first bad
  element throws, no state mutated). SECURITY: `"skip"` also silently drops author-verification
  failures, so combine it with `verifyAuthor.expectedAuthorPubkey` (single author) or a
  post-pull `authorPubkey` check against your authorized set if you need strict authorship.
- **`persistEncrypted` mode** (TS) / `persist_encrypted` (Python). With an `encryptor`, the
  cursor retains each element's **ciphertext** in its accumulated log, so `getItems()` returns
  the persistable ciphertext — safe to write to disk for an E2EE log without leaking plaintext
  at rest — while `pull()` still returns the freshly-decrypted batch. A no-op without an
  encryptor (plaintext is already its own stored form).
- **`getDecryptedItems()`** (TS, async) / **`get_decrypted_items()`** (Python). Returns the full
  accumulated log decrypted — for rendering warm-started history seeded from persisted
  ciphertext (`initialItems`). Honors the `onElementError` policy.
- **`SyncMetrics.skippedCount`** (TS): the number of elements a `"skip"` pull dropped, reported
  via `logger.pullSuccess` (omitted when none were skipped).
- **`ElementErrorPolicy`** type exported from `@drakkar.software/starfish-client`.

### Changed

- **`AppendLogCursor.pull()` is now safe to call concurrently** (TS + Python). Overlapping calls
  are serialized internally — a promise chain in TypeScript, an `asyncio.Lock` in Python — so
  each runs against the checkpoint the previous one advanced; no two overlapping pulls fetch and
  double-append the same window. A failed pull does not wedge the queue for the next call. The
  prior "not safe to call concurrently" caveat is retired.
- Docs: `docs/ts/server/append-only-collections.md` documents the skip policy, the
  `persistEncrypted` warm-start persistence flow, and concurrency safety; both client
  `README.md` files gain the new options.

## 3.0.0-alpha.9 — incremental append-only cursor

A new client helper, `AppendLogCursor`, makes incremental pulling of append-only collections
automatic: it owns the accumulated log locally and derives its checkpoint from the last element it
holds, so each pull fetches only newer elements. Because the checkpoint comes from the data (not a
separately-tracked number), it resumes correctly on a fresh page from persisted local data — or
fetches the whole collection on a cold start — through one code path. Opt-in and additive (the
stateless `client.pull(path, { since })` is unchanged); shipped in **both** TypeScript and Python
with matching test suites. Lockstep bump of all twenty packages to 3.0.0-alpha.9 / 3.0.0a9.

### Added

- **`AppendLogCursor`** (TS `@drakkar.software/starfish-client`, Python `starfish-sdk`): a stateful,
  incremental cursor over an append-only collection — the log counterpart to `SyncManager`. Each
  `pull()` derives `since` from the max `ts` it holds, fetches only newer elements via
  `client.pull(path, { appendField, since })`, appends them, and returns just the new batch.
  `getItems()` / `items` exposes the full accumulated log; `getCheckpoint()` / `checkpoint` and
  `setCheckpoint()` / `set_checkpoint()` support persistence across restarts.
- **Warm vs. cold start through one path.** Construct empty for a cold start (first pull fetches
  everything), or seed `initialItems` (raw `{ ts, data }` envelopes) and/or `since` to resume from
  persisted data. Persistence is a round-trip of the cursor's items (under an `encryptor` the
  round-tripped `data` is decrypted, so its `authorSignature` — over the stored ciphertext — must
  not be re-verified post-decryption).
- **Optional per-element decryption** (`encryptor`): freshly-pulled elements carry decrypted `data`
  with `ts`/author fields preserved. **Optional author verification on read** (`verifyAuthor`):
  verifies each element's signature over its stored (pre-decryption) `data` and throws
  `AppendAuthorError` atomically on failure (nothing appended, checkpoint unchanged).
- **`checkpointOf` / `checkpoint_of`**: pure helper returning the max `ts` of a list of elements
  (`0` when empty).
- **Reactive bindings for the cursor** (TS only — these integrations are React-oriented):
  `createStarfishLog` (Zustand, via `@drakkar.software/starfish-client/zustand`) with hooks
  `useStarfishLog` / `useStarfishLogItems` / `useLogStatus` / `subscribeLogStatus` /
  `useLogConnectivity`; `createStarfishLogObservable` (Legend-State, via `…/legend`); and
  `createAppendLogMobileLifecycle` (pull on app foreground). All are read-only `{ items, loading,
  online, error, checkpoint }` stores with a single `pull()` action — no `set`/`flush`/conflict
  surface, since a log only grows. `startPolling` / `createSuspenseResource` already work with
  `cursor.pull()` unchanged.
- **Path-param resolution for `/batch/pull`** (TS + Python server): the batch endpoint now resolves
  `{param}` collections instead of rejecting them. `{identity}` is auto-filled from the
  authenticated caller; other params (e.g. `{teamId}`) are supplied via a new optional `params`
  query parameter holding URL-encoded JSON mapping collection name → params, e.g.
  `?collections=profile,notes&params={"notes":{"teamId":"42"}}`. Backward compatible — existing
  `?collections=` calls are unchanged. The `params` query is documented in the OpenAPI spec.
- **Cap-scope enforcement for batch pull.** A `/batch/pull` URL carries no storage path, so the
  cap-cert resolver can no longer path-bind it: it now skips the URL path-scope check for `/batch/*`
  (keeping full signature / nonce / revocation verification) and the batch handler enforces
  `scope.paths` against each RESOLVED key — a cap reads only the keys its scope covers (its own
  room, not a sibling). A supplied identity that isn't the caller's earns no `self` role and falls
  outside scope → `Forbidden`; an anonymous caller has no identity to bind → `Missing required path
  parameter`. Never a side-channel around the `{identity}` self-binding.
- **Batch-pull hardening** (TS + Python server): a configurable `maxCollectionsPerBatch` (default
  100) bounds the per-request fan-out (a `Too many collections` 400 above it); the batch path now
  writes per-collection **audit records** on denials and successful reads, plus a request-level
  record when an invalid/revoked cap degrades to anonymous (closing an audit blind spot); `list`
  joins the reserved namespace names so the batch-route detector stays unambiguous; and a malformed
  `params` blob is rejected `400` even when pathologically deep. The `RoleEnricher` contract now
  documents that it may be invoked once per collection and must be idempotent.

### Changed

- Docs: `docs/ts/server/append-only-collections.md` and `docs/ts/client/03-sync-manager.md` now lead
  with `AppendLogCursor` for incremental pulls; manual `since` tracking remains documented as the
  escape hatch. Both client `README.md` files gained an `AppendLogCursor` section.
- **`resolveEffectiveRoles` split** (TS + Python server) into `resolveBaseAuth` (runs the
  nonce-consuming resolver once) + `foldCollectionRoles` (per-collection `self`/enricher folding),
  so batch pull can authorize many collections from a single resolve. The standalone and bundle
  pull paths are unchanged — a thin wrapper preserves the prior signature.
- **Batch-pull error strings**: the retired `"Collection requires path parameters; not
  batch-pullable"` is replaced by per-collection `"Missing required path parameter"`; a malformed
  `params` blob returns a whole-request 400 `"Invalid params parameter"`; an unsafe / `..` param
  value returns a per-collection `"Invalid path parameter"` (the resolved key is guarded before any
  store read).
- The Python `/batch/pull` handler now uses the shared field-read filter, fixing a latent case
  where a `read_roles: ["public"]` field was stripped for a non-`public`-role caller.

## 3.0.0-alpha.8 — author proof (append elements + merge documents)

Stored writes now carry a cryptographic **author proof** — bound to both the payload and the
document path — so a reader can verify *who* wrote each element/document instead of trusting a
self-declared id. Covers BOTH append-only elements and merge documents, in **both** TypeScript and
Python, with cross-language regression tests and a new conformance vector; full TS + Python suites
pass. Lockstep bump of all twenty packages to 3.0.0-alpha.8 / 3.0.0a8.

### Added

- **Author-proof primitives** in `starfish-protocol`: `signAppendAuthor` / `verifyAppendAuthor` (and
  `signDocAuthor` / `verifyDocAuthor`); Python `sign_append_author` / `verify_append_author` (and
  `sign_doc_author` / `verify_doc_author`). The signature is Ed25519 over
  `<domain> + stableStringify({ k: documentKey, d: data })`, producing `{ authorPubkey,
  authorSignature }`. Binding `documentKey` (the storage path) stops an authorized writer from
  replaying another author's signed write under a different key. Two distinct domain tags
  (`starfish-append-author-v1\n`, `starfish-doc-author-v1\n`) keep element and document signatures
  from ever cross-verifying. The canonical input is byte-identical across TS and Python — locked by
  `tests/test-vectors/append-author.json`. The client's `append()` and `SyncManager` push now sign
  with the same key that signs the request, so the proof rides along automatically.
- **`requireAuthorSignature` append-only collection option (DEFAULT: on).** When enforced, the server
  rejects an append that lacks an author proof (`400`), whose signature does not verify (`403`), or
  whose `authorPubkey` is not the authenticated request presenter (`403`) — binding the stored author
  to the cap-cert / audience key that authenticated the write. The proof is stored on the element so
  any reader re-verifies it. Set `requireAuthorSignature: false` only for an unauthenticated /
  public-write log where author identity is meaningless.
- **Wire-field-name constants** (`AUTHOR_PUBKEY_FIELD`, `AUTHOR_SIGNATURE_FIELD`, `DATA_FIELD`,
  `TS_FIELD`, `BASE_HASH_FIELD`, `PUSH_PATH_PREFIX`) defined once in `starfish-protocol`
  (`constants.ts` / `constants.py`) and used at every untyped body/document access in both languages,
  so the two implementations cannot drift on the wire contract.

### Changed

- **BREAKING: append-only writes require an author signature by default.** Every append-only
  collection now enforces `requireAuthorSignature` unless explicitly set to `false`. A client on
  3.0.0-alpha.7 (whose `append()` does not sign) is rejected by a 3.0.0-alpha.8 server — bump client
  and server in lockstep, or set `requireAuthorSignature: false` on collections that must keep
  accepting unsigned appends. The stored append *element* gains optional `authorPubkey` /
  `authorSignature` fields (additive; pulls of pre-existing elements are unaffected).
- **BREAKING: merge-document author proof now works and is verified.** Previously the author fields a
  signing client attached rode *inside* `data` while the server read them from the top-level body —
  so they were never verified and the server stored the caller's *userId hash* in `authorPubkey`
  (effectively a no-op). The author proof now travels as **top-level body siblings of `data`**; the
  server verifies it (`verifyDocAuthor`, bound to `documentKey`), requires `authorPubkey` to be the
  request presenter, and stores the **raw** author pubkey. Verification is **opt-in by presence** — an
  unsigned merge-doc push (no `SyncManager` signer) is accepted unchanged — but a *signed* push from
  an old client (author fields inside `data`) is no longer recognized. Pulls now return the author
  proof at the top level of the document.

### Notes

- **Path binding is data + documentKey, not the full request.** The signature binds the author to the
  payload and the storage `documentKey`; it does not separately bind query parameters or the
  namespace (which the per-request signature already covers).

## 3.0.0-alpha.7 — security & correctness fixes (auth review round)

Fixes from a security/coding/testing/encryption review of the capability-auth branch. All land in
**both** TypeScript and Python with cross-language regression tests; full TS + Python suites pass.
Lockstep bump of all twenty packages to 3.0.0-alpha.7 / 3.0.0a7.

### Security

- **Keyring rotation no longer re-wraps the fresh CEK to an unverified retained entry.**
  `removeRecipient` (TS `keyring/src/recipients.ts`, Python `keyring/.../recipients.py`) filtered the
  entries it carried into the new epoch on `addedBy ∈ trustedAdders` only — it never verified each
  entry's `addedSig`. Because `addedBy`/`subKem` are bound to each other *only* by that signature, a
  hostile server could swap a retained entry's `subKem` to an attacker key (leaving `addedBy` a
  trusted adder) and the rotation would mint a fresh CEK and wrap it for the attacker under a
  genuine, owner-signed entry — laundering a forged recipient and surviving the very rotation meant
  to evict them. Rotation now verifies `addedSig` (mirroring `recoverCurrentCek`) and drops tampered
  entries with a logged warning.
- **Percent-encoded request paths can no longer evade a cap-scope deny (TS server).**
  `canonicalizeRequestPath` matched scope against the raw URL pathname (`new URL().pathname`, which
  is *not* percent-decoded) while the storage key was built from Hono's *decoded* params — so a
  `writer` cap denying `!col/_keyring` was bypassed by requesting `col/_%6beyring`, which still wrote
  to `col/_keyring`. Scope matching now percent-decodes each segment so it equals the storage key.
  (Python/Starlette was unaffected — ASGI delivers an already-decoded path — and is now documented to
  stay that way; double-decoding there would re-open the gap.)
- **Member/audience caps with no `scope.paths` are rejected.** A subject-scoped cap that carried no
  path scope was path-*unrestricted* (`matchScopePath(_, undefined)` is true), clearing the gate for
  the owner-only `<col>/_keyring` and `<col>/_members`. The mint/server-side shape barrier now treats
  absent `paths` as an implicit allow-all (firing the existing `*-members-not-denied` /
  `*-keyring-not-denied` rules), and the resolver rejects a non-device cap with no `scope.paths` as
  defense-in-depth. TS + Python.

### Fixed

- **Segmented append-only pull no longer truncates at the storage list page size.** The S3 backend's
  `listKeys` issued a single `ListObjectsV2` and ignored `IsTruncated`/`NextContinuationToken`, so a
  log with >1000 chunks silently dropped every chunk past the first page (the checkpoint bisect then
  read incomplete data). It now follows the continuation token (stopping early when a `limit` is
  given). The `ObjectStore.listKeys` contract is documented to require all keys in lexicographic
  order. TS + Python.
- **`hexToBytes` rejects malformed hex instead of silently zeroing it.** The `parseInt`-based
  decoders (six TS modules) turned a non-hex character into `0x00` via `NaN`, diverging from Python's
  `bytes.fromhex` (which raises). They now validate the charset and throw, matching Python.
- **TS and Python clients accept the same `namespace` input convention.** The Python client's
  `_sign_path` required a `/v1/`-prefixed path under a namespace, while the TS client takes a bare
  `/pull/…`; the Python client now accepts a bare path (and still tolerates a legacy `/v1/`-prefixed
  one), so the two SDKs are drop-in compatible as the docs claim.
- **`appendChunkKey` rejects a negative timestamp.** A negative `firstTs` (only reachable by
  migrating an unsupported ts-less legacy element) would have produced different keys in JS
  `padStart` vs Python `zfill` and broken chunk ordering; both now fail closed.
- **Segmented append-only `head.n` no longer drifts after a crash.** The head's element count was
  read back and incremented (`n + 1`); a crash between the chunk write and the head write left it one
  behind, biasing the `maxItems` cap and the stored `hash({n,last})` (no data loss). The head now
  persists `sealedN` (elements in sealed chunks) and the total is re-derived as `sealedN +
  len(tail)`, so a non-roll append self-corrects the count on the next write. TS + Python. (The
  `maxItems` cap still reads `head.n` directly, so it remains best-effort across such a crash — it
  may admit one extra element in that window before self-correcting; bounded, never compounding.)

### Documented

- `unwrapFromEntry` / `unwrap_from_entry` now warn that they are low-level primitives that do **not**
  verify `addedSig`/`addedBy` — callers must pin `trustedAdders` and verify provenance first (the
  high-level helpers already do).

## 3.0.0-alpha.6 — `namespace` reaches the store bindings

Seventh alpha of 3.0.0. Completes the alpha.5 `namespace` work: the option now flows through the
React **store bindings**, not just a directly-constructed `StarfishClient`. Purely additive — with
no `namespace` set, behavior is byte-for-byte unchanged.

### Fixed

- **`useSyncInit` (zustand binding) ignored `namespace`.** alpha.5 added `namespace` to
  `StarfishClient`, but `useSyncInit` builds its *own* internal client from the config and never
  forwarded it — so an app syncing through the store binding (the common path: live document
  pull/push) always hit the un-namespaced `/{action}/…`, even while direct `client.pull/push`
  calls were correctly namespaced. On a namespace-mounted deployment that surfaced as document/room
  syncs 404-ing at the proxy while standalone client calls worked. (The `legend`/`suspense`
  bindings operate on an already-built store and were unaffected.)
- **Append-only checkpoint pull no longer makes an extra O(n) pass in the Python server.**
  `handle_append_only_pull` previously built a full per-element `ts` list before `bisect`; it now
  uses `bisect_right(…, key=…)` directly (parity with the TS binary search). Also de-flaked
  `test_checkpoint_after_second_push_returns_only_third`, which captured a wall-clock checkpoint
  between auto-`ts` appends (a real timing race); it now uses explicit timestamps, mirroring the TS
  router test.

### Added

- **`namespace` on `SyncInitConfig`** (`useSyncInit({ namespace })`), forwarded into the binding's
  internal `StarfishClient` so its `pullPath`/`pushPath` are rewritten to `/v1/{namespace}/…`
  (signed AND sent), exactly like a directly-constructed client. Pass the bare name; the `/v1/` is
  added by the client. Default unset = paths pass through unchanged.
- **Opt-in append-only scaling knobs** (`appendOnly.maxItems`, `appendOnly.chunkSize`). `maxItems`
  rejects an append once the stored element count reaches the cap with `409 { error:
  "append_limit_exceeded", limit }` (nothing written). `chunkSize` switches the collection to
  **segmented storage** — the log is kept as fixed-size sealed chunks plus a small head document, so
  an append touches only the head and the open tail chunk (O(chunkSize), not O(n) → no O(n²) build)
  and a `?checkpoint=`/`?last=` pull reads only the chunks it needs (each chunk key encodes its first
  element's `ts`, so the sorted key list — one `listKeys`, no chunk reads — tells the server which
  chunks a checkpoint can skip). Both knobs are additive and preserve the wire contract (identical
  pull response and `hash({ n, last })`); a single-document log lazily migrates to chunks on its next
  append and stays segmented thereafter. Server, TS + Python. See
  `docs/ts/server/append-only-collections.md` §Bounding & scaling.

### Tests

- `packages/ts/client/tests/react.test.ts`: `useSyncInit` with `namespace` set drives the store's
  mount pull to `/v1/<ns>/pull/…`; with it unset the path stays bare (no `/v1/`).
- Append-only scaling coverage: `packages/ts/server/tests/router/append-only.chunked.test.ts` and
  `packages/python/server/tests/protocol/test_append_chunked.py` assert byte-identical pull responses
  and `hash` between the chunked and single-document layouts across checkpoint/last edge cases, plus
  chunk rollover, lazy migration (including an exact `chunkSize` multiple), config-drift stickiness,
  the filesystem backend, the `maxItems` cap (protocol + router 409), and the combined knobs. The
  opt-in stress suites gain a chunked sequential-build variant showing flat per-item append time
  versus the single-document O(n²).

## 3.0.0-alpha.5 — TypeScript client `namespace` parity

Sixth alpha of 3.0.0. Brings the client-side **`namespace` option to the TypeScript
`StarfishClient`**, which the Python client (`StarfishClient(namespace=…)`) already had.
Purely additive: with no `namespace` set the TS client is byte-for-byte unchanged.

### Added

- **`namespace` on the TS `StarfishClient`** (`StarfishClientOptions.namespace`). When set,
  every request path `/{action}/…` is rewritten to `/v1/{namespace}/{action}/…` for **both**
  the URL the client hits **and** the canonical path it signs — so the signature the server
  reconstructs from the namespaced URL verifies with no reverse-proxy rewrite layer. Crucially
  it also rewrites the paths that namespace-unaware SDK helpers build internally (e.g.
  `starfish-keyring`'s `addCollectionRecipient`, blob uploads), so a consumer targeting a
  namespaced deployment no longer hand-prefixes paths or wraps the client. This mirrors the
  Python client's existing `namespace` parameter (identical `/v1/{ns}/…` wire output, adapted
  to TS's path convention where `/v1` lives in the path rather than `baseUrl`). Default unset =
  root-mounted server, paths pass through unchanged. See `docs/ts/client/20-namespaces.md`.

### Tests

- Precise client coverage in both languages asserts the namespace lands on **both** the URL
  **and** the signed canonical path — a URL-only rewrite would silently fail auth against a
  namespace-mounted server. New `packages/ts/client/tests/namespace.test.ts` (covers
  pull/push/append/pull-blob/push-blob, query strings, and the unset/empty backward-compatible
  cases); a signed-path assertion added to `packages/python/client/tests/test_client.py`
  alongside the existing URL-level namespace tests.
- **Append-only scaling stress tests** (opt-in) characterizing parse/serialize cost as a log
  grows: `packages/ts/server/tests/router/append-only.stress.test.ts` and
  `packages/python/server/tests/protocol/test_append_stress.py`. Run directly against an
  in-memory store at 1k–100k elements, they confirm append is O(N) per call (so building a log
  is O(N²)) and that a `?checkpoint=` pull still parses the whole document O(N) — the checkpoint
  bounds the *response*, not the server-side *parse* (the Python handler does an extra O(N)
  `ts`-list pass before `bisect`, so it never goes sub-linear). Gated behind `STARFISH_STRESS=1`
  (vitest `describe.skipIf`) and a `stress` pytest marker excluded by default via `addopts`, so
  the default suites stay fast. See `docs/ts/server/append-only-collections.md` §Size considerations.

## 3.0.0-alpha.4 — secp256k1 KEM (Nostr identities as encrypted-collection recipients)

Fifth alpha of 3.0.0. Completes the encryption half of the pluggable-suite work: the per-collection **keyring is now suite-aware**, so a `secp256k1-schnorr` ("Nostr") identity can be a first-class recipient of a `delegated`-encrypted collection — collection keys seal to its secp256k1 key, and a secp256k1 owner can grant/manage access. Additive over alpha.3: the `ed25519`/X25519 wire format is unchanged (existing keyring vectors verify byte-for-byte), and the new `WrappedKeyEntry` tags are optional (tolerant reader).

### Added

- **secp256k1 KEM (ECDH).** The `secp256k1-schnorr` suite now implements the KEM half: `deriveSharedSecret` / `generateKemKeypair` / `kemPublic` on `CryptoSuite`. ECDH is the **x-coordinate** of `priv·lift_even(peerXOnly)` — parity-free (so x-only BIP-340 keys work without parity bookkeeping) and ECDH-symmetric, byte-identical across `@noble/curves` (TS) and `coincurve` (Python). Locked by `tests/test-vectors/suite-secp256k1-ecdh.json` (includes an odd-y peer) and `keyring-wrap-secp256k1.json`. `ed25519` keeps X25519, moved behind the suite byte-for-byte.
- **Suite-aware keyring.** `WrappedKeyEntry` gains optional `kemAlg` (recipient KEM suite) and `addedByAlg` (adder signing suite); both default to `ed25519` (absent on the wire) and are folded into the `addedSig` canonical input **only when present**, so an `ed25519` entry is byte-identical to alpha.3 and a stripped/swapped tag fails verification (downgrade caught). Wrap/unwrap dispatch on `kemAlg`; `addedSig` dispatches on `addedByAlg`. HKDF `info` is domain-separated per KEM suite (`starfish-wrap` for ed25519 — frozen by the vector; `starfish-wrap:<alg>` otherwise).
- **`recipientKem(cert)`** (protocol) — single source of truth for the keyring recipient identity: `kemAlg = subKemAlg ?? subAlg ?? issAlg`, `kemPubHex = subKem ?? sub` (the signing key doubles as the KEM key for same-suite secp256k1). Both `_devices`/`_members` directories now record secp256k1 recipients and carry `subKemAlg`.

### Changed

- **Mint gate relaxed.** `mintDeviceCap` / `mintMemberCap` (both languages) no longer reject a non-`ed25519` `subKemAlg` — every registered suite's KEM is now wrappable. A same-suite `secp256k1-schnorr` subject still emits no `subKem` (its `sub` is the KEM key); a mixed sign/KEM pair emits a distinct `subKem`.

### Fixed

- **Cross-language suite-tag defaulting parity.** Every suite-tag default in the Python implementation now uses `is None` (mirroring TypeScript `??`), never `or`/truthiness. A server-controlled empty-string tag (`""`) no longer coerces to `ed25519` on Python while TypeScript fails closed — both now treat `""` identically (rejected via `get_suite("")`), closing a class of cross-language fork on hostile/malformed input. Sites: keyring `remove_recipient` retained-recipient `kemAlg`, request-signing `presenter_alg`/`subAlg`, revocation `alg`. An explicit `subUserId: null` on a subject cap is now rejected as `malformed-shape` in both languages (presence test, matching TS `!== undefined`).
- **Hardening coverage.** Added direct tests for the degenerate-shared-secret guard (`assertUsableSharedSecret` / `assert_usable_shared_secret`) and a cryptographic revocation canary — a `rotateEpoch`-dropped `secp256k1-schnorr` member can no longer recover the new epoch's CEK (proven via failed encryptor construction, not just structural absence).
- **Cross-suite cap-cert canonical-byte vectors.** Added `crossSuiteMemberCap` (ed25519 issuer → `secp256k1-schnorr` subject, no `subKem`) and `mixedKemMemberCap` (`secp256k1-schnorr` signing + decoupled `ed25519` `subKemAlg` + X25519 `subKem`) to `tests/test-vectors/cap-cert.json`, asserted in both languages (canonical input + signature + well-formedness). Previously every `canonicalSigningInput` vector was `ed25519`-only, so a TS↔Python canonicalization divergence on the `subAlg`/`subKemAlg` fields would not have been caught by a shared byte lock.
- **Revocation-list `verify` fail-closed parity.** `_verify_list_signature` (Python server) now catches `Exception` (was `(ValueError, KeyError, TypeError)`), matching the TS bare-catch — a future suite that violates the no-raise `verify` contract is rejected rather than surfacing a 500 + traceback.
- **`secp256k1-schnorr` interop wording.** Suite comments (TS + Python) and `docs/ts/client/26-identity-models.md` no longer imply Nostr/NIP-44 *wire* compatibility. The suite shares Nostr's secp256k1 key type and the ECDH primitive only: signatures are over `sha256(canonical Starfish bytes)` (not NIP-01 event ids) and the keyring wrap uses Starfish's own HKDF (`salt="starfish-wrap"`, suite-tagged info), not NIP-44's `conversation_key` — so a stock Nostr client can neither verify these signatures nor unwrap these keys.
- **Doc/comment drift.** The keyring modules (`keyring.ts` / `keyring.py`) no longer describe themselves as "side-by-side with the v2 group-crypto" module (removed in 3.0); `examples/app/TESTING.md` drops a stale paragraph describing the `compute_timestamps`/`filter_by_checkpoint` machinery removed in alpha.2.

### Security hardening (review-driven)

Hardening from a security review of this milestone. All changes are within the unreleased alpha.4 — no released artifact is affected — but they regenerate the cap-cert / request-signature / revocation-list / pairing-bundle test vectors.

- **Signature domain separation (by construction).** The cap-cert, per-request, and revocation-list signing inputs now each prepend a distinct domain tag (`starfish-capcert-v1\n` / `starfish-req-v1\n` / `starfish-revlist-v1\n`) to their canonical bytes. A signature minted for one message type can no longer verify as another even if a future field change made two stable-stringified bodies overlap — previously the separation was *emergent* from disjoint field sets. The server revocation-store and the vector generators route through the protocol canonical functions (single source of truth), closing a latent drift where a reimplemented canonical could diverge silently. Locked by `domain-separation.test.ts` / `test_domain_separation.py`. The keyring `addedSig` is out of scope (different signer role + field shape, no overlap with the identity-sig family).
- **Audience allow-list pinned to `ed25519`.** When an `audience` cap carries an `aud` allow-list, the server now rejects (401) a presenter declaring any non-`ed25519` suite. `aud` entries are bare 32-byte hex with no suite tag, so admitting another suite by raw-hex match was alg-blind type confusion (a secp256k1 x-only key whose bytes equal a listed Ed25519 pubkey). Open audiences (no `aud`) still accept any registered suite — only allow-listing is pinned.
- **secp256k1 root pairing explicitly gated.** `assemblePairingBundle` / `installPairingBundle` (both languages) now reject a non-`ed25519` pairing device or bundle cap-cert with a clear "secp256k1 root pairing not yet supported" error, instead of silently feeding a secp256k1 x-only key into the X25519 CEK wrap (which surfaced as an opaque GCM-tag failure at unwrap). `PairingQrPayload` gains an optional `alg` (absent ⇒ `ed25519`); the deferred-feature boundary is now enforced, not just documented.
- **Cross-language downgrade negative vectors.** `keyring-wrap-secp256k1.json` gains `negativeCases` (stripped/swapped `kemAlg`/`addedByAlg`, empty-string tag) and `cap-cert.json` gains `strippedSubAlgMemberCap` / `swappedSubAlgMemberCap` — all `expectVerify:false` and run in both languages — so the alg-downgrade guard is proven cross-language, not just by in-language tests.
- **Comment/doc accuracy.** Cap-cert `sig` comments (TS + Python) now read "signature under `issAlg`" rather than "Ed25519 signature" (the issuer suite governs it); `docs/ts/client/26-identity-models.md` no longer implies a future post-quantum KEM is a drop-in on the current seam (it would require splitting a separate `KemAlg` enum — see the KEM-phase forward-contract).

### KEM-phase contracts — now honored

The forward contracts recorded in alpha.3's Deferred section are satisfied: (1) `WrappedKeyEntry.kemAlg`/`addedByAlg` are folded into the signed `addedSig` (no algorithm confusion); (2) the wrapper treats `cert.subKemAlg` as the authoritative recipient KEM via `recipientKem`, never inferring from key bytes; (3) `Alg` remains the KEM tag (no separate `KemAlg` enum — a 1:1 sign↔KEM mapping still holds; a pure-KEM/PQ suite would revisit this); (4) `DirectoryEntry` carries `subKemAlg`.

### Deferred

- **Pairing is still X25519-only.** `pairing.ts` / `pairing.py` (QR + relay multi-device) wrap CEKs to a new device under X25519. A secp256k1 root cannot pair its own devices yet — this has a hard prerequisite that is **not** built: secp256k1 *root creation* (passphrase derivation is `ed25519`-only today). It lands with the npub/nsec bring-your-own-nsec / NIP-06 phase, which adds secp256k1 root identities. The boundary is now **enforced**: `assemblePairingBundle` / `installPairingBundle` reject a non-`ed25519` device/cap with an explicit error (see Security hardening above), so the gap fails loudly rather than producing a garbage X25519 secret.
- npub/nsec bech32 encoding, NIP-06 mnemonic derivation, NIP-07/46 external signers — unchanged from alpha.3.

### Migration

- **No on-disk break for `ed25519`.** alpha.3 keyrings, cap-certs, and request signatures verify unchanged under alpha.4 (the `ed25519`/X25519 paths are byte-identical; the new entry tags are additive and absent on existing data). A `secp256k1-schnorr` recipient is a new capability, not a migration.

## 3.0.0-alpha.3 — Pluggable identity suites (Ed25519 + Nostr/secp256k1)

Fourth alpha of 3.0.0. Introduces a **per-user crypto-suite abstraction** so one deployment can carry multiple identity models side by side: the original `ed25519` (Ed25519 signing + X25519 KEM) and a new `secp256k1-schnorr` ("Nostr") suite (BIP-340 Schnorr signing over secp256k1). Selection is per identity, carried by `alg` tags on cap-certs / request signatures / revocation lists. **Breaking** relative to alpha.2 — the cap-cert schema changed; pre-alpha.3 caps and signatures do not verify. The alpha.2 schema (single implicit curve) was a transient point; do not pin to it.

### Added

- **Crypto-suite registry** (`@drakkar.software/starfish-protocol` / `starfish-protocol`). `suites/` module exposing `getSuite(alg)`, `isAlg`, `suiteHasSeparateKem`, `DEFAULT_ALG`. Each suite lives in its own file (`ed25519`, `secp256k1`). `getSuite` is fail-closed: an unknown/unimplemented `alg` throws rather than silently falling back to a different curve.
- **`secp256k1-schnorr` suite.** BIP-340 Schnorr sign/verify, byte-identical across TypeScript (`@noble/curves`) and Python (`coincurve>=19.0`) via hash-then-sign `sha256(message)` + deterministic `aux_rand = 0`. The X25519/secp256k1-ECDH KEM half, npub/nsec encoding, and key derivation are **not** in this release (sign/verify only). Locked by `tests/test-vectors/suite-secp256k1.json`.
- **Cross-suite delegation.** An `ed25519` issuer can mint a `member` cap for a `secp256k1-schnorr` subject: the cap signature verifies under `issAlg`, the subject's per-request signature under `subAlg`.
- **`X-Starfish-Alg` request header** (TS + Python client/server). Conveys the request signature's suite. For device/member caps the server uses the authoritative `cert.subAlg`; for audience (public-link) caps it reads the header (validated, fail-closed).
- **`presenterAlg` on `capProvider.getCap()`** (TS) / `presenter_alg` on `get_cap()` (Python) — optional, defaults `ed25519`. The suite of the key that *signs* the request. It matters only for `audience` caps, where the redeemer signs with their own key (unrelated to the cap's `issAlg`); the client emits it as `X-Starfish-Alg`. For device/member caps the subject's suite is taken from the verified cert, so it is ignored.

### Changed (BREAKING)

- **Cap-cert carries `issAlg` + optional `subAlg` + optional `subKemAlg`** (was a single implicit Ed25519 curve). `issAlg` governs the issuer key + `sig`; `subAlg` governs the subject signing key + the subject's per-request signature (absent ⇒ same as `issAlg`); `subKemAlg` governs the subject's KEM (encryption) key, **decoupled** from the signing suite so a subject can sign with one curve and be encrypted to under another (absent ⇒ same as `subAlg`; reserved for the KEM phase, omitted today). All are folded into the canonical signing input, so a suite cannot be stripped or downgraded without invalidating the signature.
- **`subKem` is now suite-determined.** Present unless the KEM key *is* the signing key — i.e. omitted only when `subKemAlg == subAlg` and that suite reuses one key (`secp256k1-schnorr`). `ed25519` subjects carry a distinct X25519 `subKem`; any mixed sign/KEM pair carries a distinct `subKem` of suite `subKemAlg`. Audience caps still carry no subject keys.
- **Request signatures and revocation lists carry `alg`** (folded into their signed canonical inputs). Verification dispatches on it.
- **SDK `capProvider.getCap()`** caps now include `subAlg`; the client signs device/member requests with the cap's `subAlg` (falling back to `issAlg`), and audience requests with the presenter's own `presenterAlg`.

### Security

- **Downgrade guard.** `alg`/`issAlg`/`subAlg` are part of the signed bytes and validated in well-formedness *before* signature verification, so an attacker cannot strip or swap the suite to a weaker scheme.
- **`verify` is fail-closed in both languages.** The Python suite `verify` catches every exception (including a missing optional `coincurve` C extension), so a `secp256k1-schnorr` signature on an ed25519-only deployment fails closed to `False` instead of raising — closing an unauthenticated log-amplification path.
- **TS/Python parity.** The Python cap-resolver now resolves the request-signature suite the same way as TS (`cert.subAlg` for device/member, `X-Starfish-Alg` for audience), removing a cross-language verification split.

### Notes

- **Deferred to a later release:** the keyring/pairing KEM is still X25519-only (the `WrappedKeyEntry` wire format is unchanged and carries no suite tag); npub/nsec encoding and NIP-06 derivation are not implemented; the `SyncSigner` author-signature extension API is still Ed25519-shaped. These are tracked for the secp256k1 KEM phase. The cap-cert `subKemAlg` field is in place now so that decoupled signing/KEM suites (e.g. Nostr-sign + X25519-KEM, or a post-quantum KEM) land as an additive change rather than another breaking cap-cert revision. Because the keyring wraps via X25519 only today, the **mint helpers reject a `subKemAlg` that would require a non-X25519 recipient key** (a present `subKem` must be X25519); the one usable decoupled combo today is `secp256k1-schnorr` signing + `ed25519`/X25519 KEM. **KEM-phase contracts** (must hold when the KEM ships): (1) a future per-entry `WrappedKeyEntry.kemAlg` MUST be folded into the keyring's `addedSig` canonical input to avoid algorithm confusion; (2) the wrapper MUST treat `cert.subKemAlg` as the authoritative recipient KEM suite, not infer it from `subKem` bytes; (3) `Alg` is a *signing*-suite tag (every suite has sign/verify) — a pure-KEM or hybrid-PQ KEM will require splitting a `KemAlg` enum or making suite lookup role-aware; (4) the `_devices` `DirectoryEntry` records extracted fields (`sub`/`subKem`/…), not the full cert, so a recipient's KEM suite is not reconstructible from the directory today — the KEM phase must add `subKemAlg` to `DirectoryEntry` (or store the cert, as the `_members` directory already does) to keep recipient-suite resolution additive. The `_devices`/`_members` directory helpers reject a same-suite `secp256k1-schnorr` subject (which carries no separate `subKem`) with an explicit "KEM not yet implemented" error, since such a subject cannot be an encrypted-collection recipient until the KEM ships.

### Migration

- **No on-disk back-compat.** Cap-certs, request signatures, and revocation lists from alpha.2 do not verify under alpha.3 (the `alg`/`issAlg` fields changed the signed bytes). Re-mint caps, re-sign any persisted revocation lists, and re-pair devices. Existing `ed25519` identities remain valid as keys — only the cert/signature envelopes changed.

## 3.0.0-alpha.2 — Append-only logs, by-timestamp

Third alpha of 3.0.0. Reworks append-only collections into typed, timestamp-indexed event logs that work under both encryption modes, and makes `?checkpoint=` incremental sync an append-only-only feature. **Breaking** relative to alpha.1 — see Migration.

### Added

- **Append-only `delegated` encryption** (TS + Python). Append-only collections now support `encryption: "delegated"`: the client encrypts each element's `data` (via the existing per-collection keyring encryptor — already epoch-versioned and AEAD-bound) and the server stores it opaquely inside the `{ ts, data }` envelope. The server only ever appends and reads the plaintext `ts`, so `?checkpoint=` filtering works unchanged. The old "append-only + delegated is rejected at config load" ban is removed.
- **Client-supplied element timestamps.** An append may include a `ts` (non-negative integer, ms) in the request body. It must be strictly greater than the latest stored element's `ts` (else `409 { error: "non_monotonic_timestamp", latest }`) and is stored verbatim; omit it to let the server assign `max(now, latest + 1)`. New `StarfishClient.append(path, data, { ts? })` / `client.append(path, data, ts=None)` (Python).

### Changed (BREAKING)

- **`appendOnly` is now a tagged config**: `{ type: "by_timestamp", field?, persist? }` (Python `AppendOnlyConfig(type="by_timestamp", …)`). `appendOnly: true` and bare-object shorthands still normalize (defaulting `type`). An unknown `type` is rejected at config load. The `checkLastItem` option is **removed**.
- **Each appended element is stored as `{ ts, data }`** (was a raw item plus a parallel per-item `timestamps` array). `data` is opaque (plaintext under `none`, ciphertext under `delegated`). The append `pull` now returns `{ ts, data }` envelopes.
- **Appends are always accepted content-wise — no hash/conflict check.** The `baseHash`/`checkLastItem`/409-`hash_mismatch` path and the 3-try retry loop are gone; concurrent appends serialize on a per-key write lock and never lose an element. The stored `hash` is still `hash({ n, last })` (where `last` is the element's `data`), used for ETag/304.
- **`?checkpoint=` is now an append-only-only feature.** Regular (non-append) collections always return the full document; a stale `?checkpoint=` on a regular collection is ignored (no `400`). The per-field `timestamps` tree, `computeTimestamps`/`compute_timestamps`, and `filterByCheckpoint`/`filter_by_checkpoint` were removed; a document now carries a single doc-level `ts` write-time (used for TTL and as the pull high-water mark).

### Security

- **`?withKeyring=1` now authorizes the sibling keyring read against the caller's cap scope** (TS + Python). The pull optimization that piggybacks `<key>/_keyring` onto a response previously performed the storage read without re-checking the keyring path against the cap's `scope.paths`. A cap that allows a document but denies its `_keyring` sibling (e.g. a custom `["<col>", "!<col>/_keyring"]` scope) could read the owner-only keyring via the shortcut. The route layer now drops the optimization (returns no keyring) when the cap scope does not cover `<key>/_keyring`; resolvers with no path scope (pure role-based auth) are unaffected. `AuthResult` gains an optional `scopePaths` / `scope_paths` field carrying the expanded cap scope.
- **`matchScopePath` deny rules now cover descendants and canonicalize the request path** (TS + Python). A deny like `!<col>/_keyring` previously matched only the exact string, so a superstring request path — a trailing slash (`<col>/_keyring/`), an extra segment (`<col>/_keyring/x`), a `.` segment (`<col>/./_keyring`), or a double slash (`<col>//_keyring`) — could slip past it while still matching a `<col>/**` allow. The request path is now canonicalized (empty/`.` segments collapsed) and a deny `!path` covers both `path` and any descendant `path/...`. **Behavior change for custom scopes:** a deployment that intentionally relied on `!path` *not* covering `path/...` descendants will see new denials; the built-in `readOnly`/`writer`/`admin` presets and the single-document `_keyring`/`_members` layout are unaffected.

### Notes

- The `afterWrite` / `interceptPush` plugin event payload for append-only collections is **unchanged** — it still carries the raw pushed item, not the `{ ts, data }` storage envelope. Queue consumers (`starfish-queuing`) and audit/replica plugins need no changes.

### Migration

- **No reader compatibility for the old append-only format.** Existing alpha append-only documents (raw items + parallel `timestamps`) are not auto-migrated and must be wiped.
- Replace `appendOnly: {}` / `appendOnly: { … }` with `appendOnly: { type: "by_timestamp", … }` (or just `appendOnly: true`). Remove any `checkLastItem`. From `queueOnly`: `appendOnly: { type: "by_timestamp", persist: false }`.
- Regular collections lose incremental/delta sync — pull returns the full document. Only append-only logs support `?checkpoint=`.

## 3.0.0-alpha.1 — Public links

Second alpha of 3.0.0. Adds the public-link API (audience caps) on top of alpha.0. See the 3.0.0 entry below for the full v3 changelog.

### Added

- **Public links with optional expiry + identity allow-list** (TS + Python). `createPublicLink` / `parsePublicLink` / `redeemPublicLink` (`create_public_link` / `parse_public_link` / `redeem_public_link` in Python) in `starfish-sharing`, backed by a new **`audience`** cap kind that binds no single subject: every redeemer signs requests with their own key (named via a new `X-Starfish-Pub` header), so links carry no embedded private key and writes are attributable. Optional `allowedIdentities` (server-enforced via the cap's `aud`; omit for "anyone") and optional `expiresAt` / `ttlSec`. Adds `mintAudienceCap` / `assertAudienceCapShape`, exports `userIdFromPubHex` / `user_id_from_pub_hex`, and `sharingServerPlugin` now validates the `audience` kind. Locked by the `audienceCapOpen` / `audienceCapRestricted` cross-language vectors in `tests/test-vectors/cap-cert.json`. (See the 3.0.0 entry for the full description.)

### Changed

- **`CapCert.sub` / `subKem` / `subUserId` are now optional** (absent on `audience` caps), with a new optional `aud` allow-list and the additive `X-Starfish-Pub` request header. TypeScript consumers that destructure `cert.sub` / `cert.subKem` as a definite `string` must narrow on `cert.kind`.

### Fixed

- **Revocation store**: an empty subject (`sub: ""`, the audience-cap revocation sentinel) no longer matches subject-wide revocation, so a stray `revokedSubjects: [{ sub: "" }]` entry can't blanket-revoke every audience cap from an issuer. Per-nonce revocation (the documented audience path) is unaffected. (TS + Python.)

### Documentation

- **Why cap-certs are not JWTs/JWS** — added a "Why not JWT?" section to `docs/ts/client/25-capability-certs.md`: cap-certs are subject-bound capabilities with per-request proof-of-possession (not bearer tokens), so plain JWT is the wrong tool; a JWS envelope can't drop the protocol's `stableStringify` canonicalization (it's required for content hashing and 6 other signed objects regardless); and the matching prior art is UCAN / Biscuit / macaroons, not JWT.
- **Public-link security considerations** — added a "Security considerations" section to `docs/ts/sharing/02-public-links.md`: an *open* `scopes.writer` link grants collection-wide writes (confine with `allowedIdentities` or an `{identity}`-templated scope); open-link attribution is only as strong as a self-asserted, possibly-throwaway identity; a cap grants authority, not decryption (don't point a public link at an `encryption: "delegated"` collection); and prefer short TTLs for "anyone" links.

## 3.0.0-alpha.0 — First alpha of 3.0.0

Pre-release for testing. See 3.0.0 entry below for full changelog.

## 3.0.0 — Capability-based E2E (BREAKING)

This is a major redesign of the encryption and authorization model. The server no longer holds any encryption keys, identity is now a real Ed25519+X25519 keypair (rather than a passphrase hash), and authorization is carried by signed capability certificates (cap-certs) issued by the user's root identity. Multi-device and group access now share a single multi-recipient primitive — `"group"` encryption mode is folded into `"delegated"`.

### Changed (BREAKING)

- **Package split into 12 lockstep-versioned packages**. Cap-aware code moved out of `starfish-client` / `starfish-sdk` into three new extension packages per language:
  - **`@drakkar.software/starfish-keyring`** / **`starfish-keyring`** (Py): multi-recipient encryption layer (`keyring`, `recipients`, AES-GCM payload encryption, locked HKDF/AES-GCM constants).
  - **`@drakkar.software/starfish-identities`** / **`starfish-identities`** (Py): root + device identity model (`deriveRootIdentity`, `bootstrapRootIdentity`, `mintDeviceCap`, `scopes.rootAll`, all pairing flows, the per-user `_devices` directory, `identitiesServerPlugin`).
  - **`@drakkar.software/starfish-sharing`** / **`starfish-sharing`** (Py): member-cap extension (`mintMemberCap`, `scopes.readOnly`/`writer`/`admin`, the per-collection `_members` directory, `sharingServerPlugin`).
  - `starfish-client` / `starfish-sdk` keep transport + sync + storage adapters + bindings only. **The hard break is complete: there are no transitional re-exports.** The old `import { mintDeviceCap } from "@drakkar.software/starfish-client"` no longer resolves — use the per-extension import below.
  - New import paths: `import { mintDeviceCap } from "@drakkar.software/starfish-identities"`, `import { mintMemberCap, scopes } from "@drakkar.software/starfish-sharing"`, `import { createKeyring } from "@drakkar.software/starfish-keyring"`.
  - The plugin contract types (`ServerPlugin`, `CapCertValidator`) live in `starfish-protocol`; `starfish-server` provides the runtime helpers (`composePluginValidators`, `defaultServerPlugin`). Extensions ship `identitiesServerPlugin` / `sharingServerPlugin` and never import `starfish-server`. Apps wire them: `createCapCertRoleResolver({ plugins: [identitiesServerPlugin, sharingServerPlugin] })`.
  - **Member-cap structural rules live in `starfish-sharing`, not the protocol.** `assertCapCertWellFormed` (protocol) now enforces only the kind-agnostic iss/sub-userId relations; the member-specific barriers (`member-self`, `member-private-path`, `member-multi-collection`, `member-members-not-denied`, `member-keyring-not-denied`, `member-wildcard-collections`) are owned by `assertMemberCapShape` in `starfish-sharing`. The server enforces them through `sharingServerPlugin`; with strict-kind dispatch a `member` cap is rejected outright unless that plugin is installed. Note: a consumer calling `verifyCapCert` standalone (without the sharing plugin) no longer rejects malformed member caps — install the plugin (the server path does).
  - `starfish-client` / `starfish-server` have **no compile-time dependency on the extensions** (verified: zero `starfish-{keyring,identities,sharing}` imports in their source). Extensions depend one-way on `starfish-client` for HTTP I/O.
  - All packages release together — every tag bumps all packages to the same version.
- **Entitlements extracted into its own package** — **`@drakkar.software/starfish-entitlements`** / **`starfish-entitlements`** (Py). The client-side `pullEntitlements` reader (was in `starfish-client` / `starfish-sdk`) and the server-side `createEntitlementRoleEnricher` (was in `starfish-server`) now live in this extension. **Clean break: no re-exports** — `import { pullEntitlements, createEntitlementRoleEnricher } from "@drakkar.software/starfish-entitlements"` (`from starfish_entitlements import ...` in Python). Unlike the cap extensions, `starfish-entitlements` depends on `starfish-server` (the enricher uses `ObjectStore` / `RoleEnricher` / `AuthResult`) and wires in through `SyncRouterOptions.roleEnricher`, not a `ServerPlugin`. The generic `composeEnrichers` and the group role enricher stay in `starfish-server`.
- **Queue change-events extracted into their own package** — **`@drakkar.software/starfish-queuing`** / **`starfish-queuing`** (Py). The `Queue` / `AbstractQueue` interface, the `MemoryQueue` / `CustomQueue` / `NatsQueue` backends, `QueueMessage`, and the per-collection queue config now live in this extension. Publishing is **no longer wired via `SyncRouterOptions.queue` or `CollectionConfig.queue`** (both removed). Instead the `ServerPlugin` contract (in `starfish-protocol`) gained an additive **`afterWrite` write-path hook** (`WriteEvent` payload) plus a `shutdown` hook; the queuing plugin implements them. Wire it with `plugins: [createQueuingServerPlugin({ queue, collections: { posts: { includeParams: true } } })]` (`create_queuing_server_plugin(...)` in Python) — the plugin **owns its per-collection config** (moved off `CollectionConfig.queue`) and its `shutdown` hook closes the queue when `plugins` is passed to `createGracefulShutdown` / `GracefulShutdownOptions`. `starfish-server` has **no dependency on `starfish-queuing`**; the `nats` optional extra moved from `starfish-server[nats]` to `starfish-queuing[nats]`. **Clean break: `starfish-server` no longer exports `Queue` / `QueueMessage` / `MemoryQueue` / `CustomQueue`** — `import { MemoryQueue, createQueuingServerPlugin } from "@drakkar.software/starfish-queuing"` (`from starfish_queuing import ...` in Python). The `appendOnly.persist=false` ("queue-only") mode stays a server feature; the server now warns at startup if such a collection is configured with no `afterWrite` plugin to consume the event.
- **Audit logging extracted into its own package** — **`@drakkar.software/starfish-audit`** / **`starfish-audit`** (Py). The console/callback/no-op loggers (`createConsoleAuditLogger` / `createCallbackAuditLogger` / `createNoopAuditLogger`; `ConsoleAuditLogger` / `CallbackAuditLogger` / `NoopAuditLogger` in Python) now live in this extension. The `AuditEntry` / `AuditLogger` **contract** moved to `starfish-protocol` (the shared layer) so the server can emit events and the extension can supply loggers without a dependency cycle. **Clean break: `starfish-server` / `starfish-server` (Py) no longer export the audit symbols** — `import { createConsoleAuditLogger } from "@drakkar.software/starfish-audit"` (`from starfish_audit import ConsoleAuditLogger` in Python). The wiring is unchanged: pass a logger via `SyncRouterOptions.auditLogger` (`audit_logger=`). `starfish-audit` depends only on `starfish-protocol` and registers no `ServerPlugin`.
- **Replication extracted into its own package** — **`@drakkar.software/starfish-replica`** / **`starfish-replica`** (Py). `ReplicaManager` and the replica config types (`RemoteConfig` / `WriteMode` / `SyncTrigger`) moved out of `starfish-server`. Replica behavior is **no longer wired via `SyncRouterOptions.replicaManager` or `CollectionConfig.remote`** (both removed). Instead the `ServerPlugin` contract (in `starfish-protocol`) gained two additive **route hooks** — `beforePull` (reject write-only pulls; sync from the primary on the `on_pull` trigger) and `interceptPush` (reject read-only pushes; proxy `push_through` writes to the primary) — that return framework-neutral directives the host translates to responses. The plugin **owns its per-collection config**: `createReplicaServerPlugin({ store, syncConfig, collections: { posts: { url, pullPath, writeMode, … } } })` (`create_replica_server_plugin(...)` in Python), validating the cross-cutting rules (appendOnly/binary/delegated/static-path/pushOnly/bundle/`push_through`-needs-`pushPath`) at construction. Its `shutdown` hook stops the sync timers when the plugin is passed to `createGracefulShutdown` / `GracefulShutdownOptions(plugins=[...])`; call `plugin.manager.start()` (`replica.manager.start()` in Python) to begin scheduled/initial syncs. Unlike the cap extensions, `starfish-replica` depends on `starfish-server` (the manager writes through `push()` / `ObjectStore`). **Clean break: `starfish-server` no longer exports `ReplicaManager` / `RemoteConfig` / `WriteMode` / `SyncTrigger`** — `import { createReplicaServerPlugin } from "@drakkar.software/starfish-replica"` (`from starfish_replica import create_replica_server_plugin` in Python).
- **Encryption modes reduced to `"none"` and `"delegated"`**. `"identity"`, `"server"`, and `"group"` are removed. `"delegated"` now supports N recipients via a sibling keyring document (subsumes the old group encryption).
- **v2 single-secret "vault" encryptor removed**. The single-key `createEncryptor` / `create_encryptor` factory and the `SyncManager` `encryptionSecret` / `encryptionSalt` / `encryptionInfo` shorthand are deleted — they mapped to no v3 mode (delegated ≡ the per-collection keyring). The React `useSyncInit` binding's `SyncInitConfig.encryptionSecret` / `encryptionSalt` fields are likewise removed in favor of a pre-built `encryptor`. The `Encryptor` *contract type* and `ENCRYPTED_KEY` now live in `starfish-protocol` (`@drakkar.software/starfish-protocol` / `starfish-protocol`); `starfish-client` / `starfish-sdk` re-export both for source compatibility, but supply a keyring-built `encryptor` via `createKeyringEncryptor` instead. The generic `deriveKey` / `derive_key` HKDF primitive stays in `starfish-protocol`.
- **`userId` derivation changed**: now `sha256(rootEdPub)[0:32]` (was `sha256(passphrase)[0:16]`). Existing storage keys whose path contains `{identity}` must be migrated — see `docs/migration/v2-to-v3.md`.
- **`Authorization` header format**: was `Bearer <hex>`, now `Cap <base64(stableStringify(cap-cert))>`.
- **Every authenticated request now requires** `X-Starfish-Sig`, `X-Starfish-Ts`, `X-Starfish-Nonce` headers (per-request Ed25519 signature + replay-protection metadata).
- **`StoredDocument.authorPubkey` / `authorSignature` become mandatory for delegated writes**. They identify the device that wrote the document (`authorPubkey = cap.sub`) and a signature over the encrypted payload.
- **`SyncRouterOptions` removed**: `encryptionSecret`, `serverEncryptionSecret`, `serverIdentity`, `identityEncryptionInfo`, `serverEncryptionInfo`, `signatureVerifier`. Use `roleResolver: createCapCertRoleResolver(...)` instead.
- **`CollectionConfig` removed**: `clientEncrypted`, `publicKey`. Added: optional `keyringPath` (defaults to `<storagePath>/_keyring`).
- **Keyring document schema v: 1**: `wrappedKeys` is now a list (not a map) of entries `{subKem, ephKem, ct, addedBy, addedSig, addedAt}`. Each entry uses per-entry ephemeral ECDH (HPKE-DHKEM-style), eliminating the per-epoch `issuerKem` field and removing the 64-bit recipientId collision risk.
- **`group-crypto` module replaced by `keyring`** (TS + Python). Function renames: `wrapGroupKey` → `wrapForRecipient`, `unwrapGroupKey` → `unwrapFromEntry`, `createGroupKeyring` → `createKeyring`, `addGroupMember` → `addRecipient`, `rotateGroupKey` → `rotateEpoch`, `createGroupEncryptor` → `createKeyringEncryptor`. **The v2 `group-crypto` module is removed in 3.0** — no side-by-side period. Follow the algorithm in `docs/migration/v2-to-v3.md` to rewrite stored keyring documents into the new shape; automated migration tooling is a deferred follow-up.
- **Cap-cert `kind` distinction**: `"device"` caps act as proxy for the issuer (URL `{identity}` resolves to `issUserId`); `"member"` caps keep the subject's own identity and grant scoped roles only. Member caps are structurally barred from covering the issuer's `users/<issUserId>/*` namespace. A third kind, **`"audience"`**, binds no single subject (used by public links — see _Added_): `CapCert.sub` / `subKem` / `subUserId` are now **optional** (absent on audience caps), and a new optional `aud` string list carries the allow-list. TypeScript consumers that destructure `cert.sub` / `cert.subKem` as a definite `string` must narrow on `cert.kind` (or use optional chaining) — the type is now `string | undefined`.
- **Request signature now binds the target host** — the canonical signing input gained an `h` field (`stableStringify({m, p, b, h, ts, nonce})`); `h` is the host the client signed for (e.g. `"api.example.com"`) and is always present in canonical form (encoded as `""` when omitted). Verifiers on the server side reconstruct host from the inbound request URL and refuse a signature minted against a different host. Closes a cross-server replay vector where a captured signature could be replayed against a different Starfish server sharing no nonce cache. Cross-language test vector `tests/test-vectors/request-signature.json` regenerated with the new shape; pre-release v3 signatures from older builds will not verify.

### Added

- **Plaintext, cap-only sharing** (TS + Python). A second sharing option alongside the E2E-encrypted (`"delegated"` + keyring) one: a `encryption: "none"` shared collection authorized purely by signed member caps + expiry, with **no keyring and no wrapped keys**. Two delivery styles — stateless (cap forwarded out-of-band, nothing stored) and owner-published (the owner publishes every member's full signed cap into the single `<col>/_members` list, from which members fetch their own — no forwarding). New sharing helpers `publishMemberCap` / `fetchMemberCaps` / `fetchMyMemberCap` / `unpublishMemberCap` (`publish_member_cap` / `fetch_member_caps` / `fetch_my_member_cap` / `unpublish_member_cap` in Python); `DirectoryEntry` now carries the full signed `cert`. `evictMember` / `evict_member` gained **revoke-only** support (keyring params optional when `rotate: false`). Safe because caps are subject-bound — the server verifies each request against `cert.sub`, so a readable roster of caps never lets one member act as another.
- **Public links with optional expiry + identity allow-list** (TS + Python). A first-class public-link API for plaintext sharing in `starfish-sharing`: `createPublicLink` / `parsePublicLink` / `redeemPublicLink` (`create_public_link` / `parse_public_link` / `redeem_public_link` in Python). A link packs a new **`audience` cap-cert** into a URL `#fragment` (base64url). Unlike a member cap it binds **no** single subject — every redeemer signs requests with **their own** identity key (named via a new `X-Starfish-Pub` header), so writes are attributable per user and no private key is ever embedded in the link. An optional `allowedIdentities` list restricts who may redeem (server-enforced against the cap's `aud`); omit it for "any identity". Optional expiry via `expiresAt` (absolute unix seconds) or `ttlSec`, both mapping to the cap's `exp` (also added to `mintMemberCap`). New protocol export `userIdFromPubHex` / `user_id_from_pub_hex` plus the `mintAudienceCap` / `assertAudienceCapShape` (`mint_audience_cap` / `assert_audience_cap_shape`) sharing helpers; `sharingServerPlugin` now also validates the `audience` kind. Whole-link revocation works through the existing `RevocationList` keyed on the cap's nonce (`sub: ""`). Locked by two new cross-language vectors (`audienceCapOpen` / `audienceCapRestricted` in `tests/test-vectors/cap-cert.json`).
- **Capability-based authorization** — signed cap-certs issued by a root identity grant scoped access (read/write/list × collections × paths) to devices and members. Pluggable via `createCapCertRoleResolver` (TS + Python).
- **Multi-device support** — each device generates its own Ed25519+X25519 keypair locally; private keys never leave the device.
- **Pairing helpers** — `bootstrapRootIdentity` (first device), `buildPairingQr`/`parsePairingQr`/`assemblePairingBundle`/`installPairingBundle` (in-person QR), `buildPairingRequest`/`readPairingRequest`/`buildPairingResponse`/`readPairingResponse` (server-relay invite). All client-side; server is a passive relay at most.
- **One-way device provisioning with configurable caps + expiry** — `provisionDevice` / `installProvisionedDevice` / `generateDeviceKeys` (TS) and `provision_device` / `install_provisioned_device` / `generate_device_keys` (Python, with `ProvisionDeviceOpts` / `ProvisionedDevice`). The root device generates the new device's keypair, mints its `device` cap with a **required** `scope` (no silent root default) and an optional `ttlSec` / `ttl_sec` expiry, and assembles the bundle in one hand-off blob. The chosen scope is enforced server-side (a cap whose `ops` omit `write` synthesizes no write role → 403). Promotes the example app's one-way flow into the library so any consumer can bound a provisioned device. Security: the new device's private keys are generated off-device and travel in the blob — use only over a channel trusted with the collection keys. The two-way QR / relay flow gets the same scope + expiry knobs via `assemblePairingBundle({ grantedScope, ttlSec })`.
- **QR-in / auto-return device pairing (anonymous rendezvous)** — a camera-free pairing path for a device that cannot scan (e.g. a laptop): the **new** device shows its pairing QR, the **root** device scans it and pushes the assembled bundle to a small anonymous, TTL'd rendezvous slot, and the new device fetches + installs it with a single trigger (no manual bundle-back, no polling). New helpers in `starfish-identities`: `pushPairingBundle` / `fetchPairingBundle` / `clearPairingBundle` / `rendezvousPathFor` (TS) and `push_pairing_bundle` / `fetch_pairing_bundle` / `clear_pairing_bundle` / `rendezvous_path_for` (Python). The rendezvous slot is keyed by the hex of the QR's `qrNonce` (no new QR field), and both sides reach it with an anonymous client because the new device has no cap yet — safe because the bundle's CEKs are E2E-wrapped to the new device's KEM and the channel needs only delivery. `installPairingBundle` gains an `expectedRootEdPub` / `expected_root_ed_pub` pin (rejects a bundle minted by a *different* root, closing a wrong-root provisioning vector over an open rendezvous). The app/server owns the slot: a `_pairing/{rendezvousId}` collection with `encryption:"none"`, `public` read/write, a short `ttlMs`, and a tight body cap; one-shot is the new device overwriting the slot after install, with TTL as the backstop.
- **Passphrase-sealed envelopes** — `sealWithPassphrase` / `openWithPassphrase` / `isSealedEnvelope` (TS) and `seal_with_passphrase` / `open_with_passphrase` / `is_sealed_envelope` (Python) in `starfish-identities`. A generic primitive that seals an arbitrary byte payload under a user-chosen PIN/passphrase: `key = Argon2id(NFC(passphrase), random-salt, ARGON2_PARAMS)` → `AES-256-GCM`, emitted as a JSON-serialisable `SealedEnvelope` (`{v, enc:"passphrase", kdf, iv, ct}`). `openWithPassphrase` validates the envelope's KDF parameters against an allow-list **before** running Argon2id (so a hostile envelope can't force a multi-GiB memory-hard computation on paste), and collapses every failure — wrong passphrase, tampered ciphertext, disallowed params — into one generic error so nothing leaks. Locked by a cross-language conformance vector (`tests/test-vectors/passphrase-seal.json`): TS and Python produce byte-identical envelopes and open each other's. Intended use: optionally PIN-seal a one-way device setup code so the code alone is useless without the PIN (sent over a different channel) — strength is bounded by passphrase entropy, so the seal buys a revocation window, not permanent safety. Wired into the example app's "Setup code" flow (an optional PIN + strength hint on the owner side; manual PIN entry on the new device).
- **Recipient-management helpers** — `addCollectionRecipient` (no rotation), `removeRecipient` (mandatory `rotateEpoch`), `listRecipients`, `currentEpoch` — usable by any cap-bearing device subject to its scope. Revocation is handled separately via signed `RevocationList` documents posted to the server-side `RevocationStore.acceptList()`.
- **Revocation store** — `createInMemoryRevocationStore` (+ pluggable interface) consults signed `RevocationList` documents.
- **Revocation-list builder** — `buildRevocationList` / `build_revocation_list` in `starfish-protocol` mints a signed `RevocationList` (`{v, iss, issUserId, generation, revoked, revokedSubjects?, sig}`) from an issuer keypair, deriving `issUserId = sha256(edPub)[0:32]` and signing the canonical input. Previously every caller (including the example app) hand-rolled this signing; the shared `tests/test-vectors/revocation-list.json` vector guards TS/Python byte-for-byte. Also exports `revocationListCanonicalSigningInput`.
- **One-call member eviction** — `evictMember` / `evict_member` in `starfish-sharing` composes the three steps of a full eviction behind explicit `rotate` / `revoke` flags: build + submit a `RevocationList` (caller-supplied `submitRevocation` transport + revocation generation), `removeRecipient` (epoch rotation → forward secrecy), and `removeMemberEntry` (de-roster). Removes the operational footgun where `removeRecipient` alone stops *decryption* but not *writes* (the member's cap stays valid). Transport- and ledger-agnostic so any app can wire it; the example app's `revokeMember` now uses it.
- **Root-only collections** — a per-collection `rootOnly` flag (TS `CollectionConfig.rootOnly` / Python `root_only`) restricts a collection to the **root device** only: any paired/delegated device cap or member cap is rejected with 403 server-side, on standalone pull/list/push and on bundle pulls. The root device is detected by the new `isRootDeviceCap` / `is_root_device_cap` predicate (a self-signed device cap, `iss === sub`) in `starfish-protocol` (re-exported from `starfish-identities`), surfaced to the route layer as the synthesized `ROLE_ROOT_DEVICE` role. Config load rejects `rootOnly` combined with a `public` read/write role. As part of this, the bundle-pull handler now shares one access-decision helper (`isAccessAllowed`) with `checkAuth`, so per-collection rules (read/write roles, public, rootOnly) can no longer diverge between the standalone and bundle routes.
- **Request signing & replay protection** — `signRequest` / `verifyRequestSignature` in protocol; nonce LRU + ±5 min clock-skew check on the server.
- **Cross-language test vectors** — `tests/test-vectors/{identity-derivation,cap-cert,request-signature,multi-recipient-wrap,revocation-list,pairing-bundle}.json` lock canonical encodings and signatures.
- **End-to-end pipeline tests** — `packages/ts/server/tests/e2e/full-pipeline.test.ts` and `packages/python/server/tests/e2e/test_full_pipeline.py` exercise the full v3 chain (bootstrap → cap-cert → signed request → resolver → keyring encryptor → push/pull) through an in-memory transport and an in-process FastAPI/Hono app, including a Bob-pairing recipient-add round-trip.
- **Cap-cert directory helpers** (`directory` module on both client SDKs) — `addDeviceEntry` / `listDevices` / `removeDeviceEntry` maintain a single document at `users/{rootUserId}/_devices` listing every device cap the root has issued; `addMemberEntry` / `listMembers` / `removeMemberEntry` do the same for `<collectionPath>/_members`. The members directory is owner-only by scope (the new `member-members-not-denied` well-formedness rule and the updated `scopes.readOnly`/`scopes.writer` presets keep member caps out). Both helpers retry on `ConflictError` so concurrent issuers don't lose writes, filter expired entries by default, and accept an optional `revokedNonces` set for cross-checking against `_revocations/{rootUserId}`. The directory is purely audit/UI metadata — authorization continues to flow through the cap-cert + revocation list, never `_members`.
- **Full-stack example app** (`examples/app/`) — a runnable chat app (Vite/React frontend using the zustand binding + FastAPI backend with a filesystem store) that wires all six extensions end-to-end: identities (passphrase login + multi-device add — two-way QR pairing, one-way provisioning from a single setup code with a per-device cap-scope + expiry picker and an optional PIN/passphrase seal, or the camera-free "Phone scans" rendezvous flow where the new device shows a QR and the root pushes the bundle back through an anonymous `_pairing/{rendezvousId}` slot), keyring (E2E rooms), sharing (per-room read-only / read-write member invites), entitlements (client-side paid-feature unlock via `pullEntitlements`), audit (`GET /audit` panel), and queuing (`create_queuing_server_plugin` → SSE for live updates). Also demonstrates **multiple rooms** (`chat/rooms/<id>`, each with its own keyring/member directory and per-room caps) and **public profiles** (`user/<id>/profile` — public read; write restricted to the user's **main device** via the synthesized `device:root` role in `writeRoles`, so paired / one-way-provisioned devices and members get 403 on a profile edit even with a full `cap:write:*` scope, while pseudos stay publicly readable. `rootOnly` itself isn't used here because it would also make reads private — `device:root` in `writeRoles` gives root-device-only writes with public reads). It also demonstrates **member/device revocation** (a signed `RevocationList` posted to `POST /revocations` → cap 401, plus a `removeRecipient` epoch rotation and directory removal — "full re-key"), a **linked-device directory** (`users/<id>/_devices`, listed and revocable in the Devices drawer), and a member **leaving a room** locally (members can't write the keyring/directory, so true removal is the owner's revoke). Adding a member or device after a revoke **re-keys** the room at the current epoch (`reSealRoomAtCurrentEpoch`) so the newcomer can still read existing history. The frontend is a polished, real-chat ("tidepool") UI — a rooms sidebar, message bubbles with avatars and profile-pseudo attribution, a profile modal, a live member list with per-member Revoke, and invite / devices / premium / activity drawers. Ships an instrumented regression suite (`examples/app/TESTING.md`): 27 backend pytest e2e tests (including the camera-free rendezvous round-trip + a wrong-root rejection) + 72 adversarial edge/security tests (`backend/tests/test_edge.py`) + a Playwright frontend spec (owner+member sharing, read-only enforcement, room isolation, entitlements, a clear membership-error message when a non-recipient opens an existing room, member revocation, device list/revoke, device provisioning with a configurable read-only scope (403 on write) and an expired-cap rejection (401), a PIN-sealed setup code needing the right PIN to install, root-device-only profile writes (a delegated device covering the profile path is still 403), and member leave-room). The edge suite probes cap-cert tampering / forged-issuer / stolen-cap rejection, request replay + host/path/body binding, revocation issuer-scoping & stale-generation, keyring forward secrecy, the `trusted_adders` provenance pin (a member can overwrite the keyring but cannot substitute an attacker-chosen CEK, and relabeling a forged entry's `addedBy` is caught by the `addedSig` check), explicit-`granted_scope` pairing (echoing a hostile QR's requested scope re-introduces the gap), future-`nbf` rejection, roomId path-traversal containment, author-identity pinning (a spoofed `authorPubkey` is overridden with the authenticated identity), `{identity}`-bound device-directory reads+writes, `deep_sanitize` stripping `__proto__`/`constructor` keys, an owner-only + signature-validated member directory (`list_members` filters forged entries), request-signature freshness (a forged-signature request does not burn its nonce), exact role matching (a wildcard `collections:["*"]` does not match a concrete `cap:<op>:chat` role), malformed-document/empty-ops rejection, and server-authoritative timestamps. The gaps the suite originally surfaced have since been **fixed** (owner-binding for the keyring + member directory, fail-closed `trusted_adders` on `list_recipients`, an epoch-rollback guard, graceful `?withKeyring=1`, audit-on-denial, a demo-secret gate on `/demo/*` + `/audit`, entitlements made client-read-only, and the body-size guard raised to the collection ceiling — see **Security (gap-fix pass)** below); the edge tests now assert the hardened behavior, with a few by-design residuals (room-doc overwrite, the optional library root-pin which the app makes required, and end-to-end-only `authorSignature` verification). See `examples/app/README.md`.

### Documentation

- **Keyring epoch/recipient semantics.** Documented (README + `addRecipient`/`add_recipient` docstrings, TS + Py) that a newly-added recipient is wrapped into the **current epoch only** — content sealed under an earlier epoch (e.g. after a revoke rotated the epoch) needs re-sealing at the current epoch to share. The `No key available for epoch N` decrypt error now explains the cause and the fix. Pinned by a keyring regression test in both implementations.
- **Identities cryptographic rationale.** `packages/ts/identities/README.md` now explains the design end-to-end: the server-holds-no-keys constraint, the Argon2id → HKDF → Ed25519/X25519 root-identity pipeline, why authority lives in signed cap-certs (a `device` cap is an authorization proxy while the device keeps its own keypair), the ephemeral-static ECDH pairing wrap (HPKE Base mode — per-wrap key independence, **not** forward-secret against recipient static-key compromise), the QR vs. server-relay bindings (`qrNonce` replay-bind, PBKDF2 + proof-of-possession, and the short-code brute-force limit), and why the device directory is not an authority source.
- **Doc sweep — v2 → v3** in `docs/ts/client/{05,06,09,13,15,16,17,18,19,20,22}-*.md` and `docs/ts/server/append-only-collections.md`. Replaced Bearer-token / `deriveCredentials` / `createEncryptor` / `encryptionSecret` snippets with the v3 `bootstrapRootIdentity` + `capProvider` + `createKeyringEncryptor` patterns. `encryption: "identity"` collection configs rewritten to `encryption: "delegated"`. v2 group-encryption-by-shared-key narrative replaced by per-collection-keyring recipient management.
- **Multi-device membership — the shared-identity model.** `docs/ts/client/24-pairing.md` gained a "Same identity on every device" section (§5): re-entering the passphrase re-derives the identical root identity, so every device is the same principal and KEM recipient — it can present member caps minted to the root and unwrap CEKs wrapped to the root KEM, and (unlike a paired per-device key) keeps reading **across the owner's epoch rotations**. Documents what is shared for free via the passphrase vs. the app-level state that must still travel (member caps from other owners, the room list), and the trade-off (no per-device revocation; master key on every device). Comparison table extended with per-device-revocation and survives-rotation rows; pointers added to the `starfish-identities` READMEs (TS + Py) and the example-app multi-device flow.

### Security (gap-fix pass)

Closes the gaps surfaced by the example app's adversarial suite (`examples/app/backend/tests/test_edge.py`). Library fixes ship in both `packages/python` and `packages/ts` with unit tests; app-level fixes live in `examples/app`.

- **`listRecipients` / `list_recipients` is provenance-filtered (fail closed)** — now takes a required `trustedAdders` / `trusted_adders` and returns only entries whose `addedBy` is trusted and whose `addedSig` verifies, mirroring `createKeyringEncryptor`. Closes a gap where the membership/admin listing surface trusted whatever a hostile server stored, even though decryption was already pinned. (TS + Python.)
- **Keyring epoch-rollback guard** — `createKeyringEncryptor` / `create_keyring_encryptor` gained an optional `minEpoch` / `min_epoch`; it rejects a keyring whose `currentEpoch` is below the caller's last-seen epoch, so a hostile server cannot serve a STALE keyring to undo a rotation. (TS + Python.)
- **`?withKeyring=1` degrades gracefully** — the sibling-keyring projection now wraps the store read in try/except and returns `keyring: null` on any store error (e.g. a filesystem store hitting a leaf-file data path), instead of letting the exception propagate as an unhandled HTTP 500. (TS + Python server.)
- **Auth denials are audited** — the router now emits an `AuditEntry` with `success: false` when the cap-resolver / role check rejects a request (401/403), so denied attempts are observable in the audit trail rather than only requests that reach the handler. (TS + Python server.)
- **Example app — owner-binding for the keyring + member directory** — `server.py` adds an `owner_role_enricher` (a `RoleEnricher`) that grants a `chat:owner` role only to the room's owner (the keyring's genesis adder); `chatkeyring` / `chatmembers` now require `chat:owner` to write. Stops members and self-signed strangers from overwriting the keyring, rolling it back, or wiping the roster (the room document stays member-writable by design). A follow-up adversarial pass found one more gap in this enricher — an **unparseable keyring** written during the TOFU create-race derived `owner=None` and locked the room's keyring + member docs for *everyone* (including the real owner), a squat-and-brick DoS. Fixed: a keyring that yields no derivable owner is treated as "unowned" (TOFU stays open), so the legitimate owner's valid write still lands (recoverable-DoS, not a permanent brick).
- **Example app — misc wiring fixes** — entitlements are now client-read-only (write role is an unreachable `billing:webhook`, so a user can't self-grant `premium`); `/demo/grant`, `/demo/revoke`, and `GET /audit` require an `X-Demo-Secret` header and are disabled when `STARFISH_DEMO_SECRET` is unset; the cap-resolver is built with `max_body_bytes=262_144` so the `chat` 256 KB ceiling is reachable; the audit ring buffer was raised to 10 000; and the frontend's rendezvous device-session builder now **requires** `expectedRootEdPub` (throws without it) so the app never performs an unpinned, MITM-able install.

### Security (second gap-fix pass)

> **⚠ WIRE-FORMAT BREAKING:** this pass widens the userId from 64 to 128 bits (`sha256(edPub)[:32]`), which changes `issUserId`/`subUserId` on every cap-cert, regenerates all cross-language test vectors, and makes pre-existing 64-bit caps/userIds incompatible. Treat it as a major break even though it's recorded under 3.0.0 (not yet released).

Closes the remaining gaps surfaced by later adversarial rounds (`test_edge.py` R1–R6). Library fixes ship in both `packages/python` and `packages/ts` with unit tests + cross-language parity.

- **Deeply-nested-JSON DoS fixed** — a small (~30 KB) but deeply-nested push body passed the Content-Length guard and the per-request signature, then crashed the push handler: `request.json()` and the recursive `deep_sanitize` / `deepSanitize` both overflowed the stack (`RecursionError` → HTTP 500; `RangeError` in Node). The push path now parses defensively and enforces a hard nesting bound (`MAX_DOC_DEPTH = 64`) via an iterative `json_depth_within` / `jsonDepthWithin` check before sanitizing → **400**. (TS + Python server.)
- **`/batch/pull` robustness** — a collection whose `storage_path` has an unresolved `{param}` is now reported `"Collection requires path parameters; not batch-pullable"` instead of attempting a doomed store read on the literal template (a masked `"Internal error"`). (TS + Python server.)
- **BREAKING — userId widened 64 → 128 bits** — a userId is now `sha256(edPub)[:32]` (32 hex chars / 16 bytes) instead of `[:16]`. Impersonating a *specific* identity (which underpins owner-binding, the `{identity}` path binding, and `_bind_auth_identity`) now requires a second-preimage on a 128-bit truncated hash (~2^128 work) rather than 64-bit. Changes `issUserId`/`subUserId` on every cap-cert (so all cross-language test vectors were regenerated) and the userId derivation in `protocol`/`identities`/`sharing` (TS + Python). Existing 64-bit caps/userIds are incompatible.
- **Example app — room-document writes are membership-bound (Level 3)** — the `chat` collection's write role is now `chat:owner` / `chat:member` (was `cap:write:chat`). The enricher grants `chat:member` only to a write-capable caller listed in the room's member directory, so a self-signed stranger can no longer clobber an established room's encrypted document, while read-only members (no `cap:write:chat`) still cannot post. Fully evicting a member now means removing them from the directory and/or revoking their cap (keyring rotation alone never stopped writes).

### Security hardening (post-review pass)

- **Argon2id passphrase stretching** — `deriveRootIdentity` now runs Argon2id (OWASP-recommended defaults: m=19456 KiB, t=2, p=1) over the passphrase before HKDF. Raises offline brute-force cost from ~10 M/sec to ~10/sec for low-entropy passphrases. Pipeline: `Argon2id(passphrase) → HKDF-SHA256 → Ed25519 + X25519`.
- **`scope.paths` glob `**` extension** — `**` now matches across slashes (matches `path/segment/anything`); `*` stays single-segment.
- **Per-signer nonce sub-cap** — each signer's nonces sit in their own sub-cache, so a noisy signer can never displace another signer's entries. (Eviction semantics were later changed to fail-closed — see the follow-up pass below.)
- **`deepMerge` UNSAFE_KEYS filter (H4)** — drops `__proto__` / `constructor` / `prototype` keys from server responses to block prototype-pollution attacks via plaintext pulls.
- **Pre-auth body length cap (H1)** — the cap-resolver enforces `Content-Length ≤ maxBodyBytes` on writes before buffering the body; rejects 413 on missing/malformed/oversize headers.
- **Authorization header length cap (M3)** — 8 KB hard limit before base64 decode.
- **Cap-cert verification ordering (M1)** — cheap header-presence + clock-skew checks run BEFORE the Ed25519 cap-cert signature verify.
- **O(1) revocation lookup + issuer cap (M4)** — `acceptList` builds a per-issuer `Set<"sub|nonce">` so `isRevoked` is constant time; new issuers beyond `maxIssuers` (default 10 000) are rejected.
- **`addedSig` verification on unwrap (H2)** — `createKeyringEncryptor` runs `verifyEntrySignature` on each wrap entry before unwrapping, so a tampered `addedBy` / `addedAt` / `epoch` causes the entry to be skipped.
- **Member-cap keyring deny** — `assertMemberCapShape` (in `starfish-sharing`, run server-side via `sharingServerPlugin`) structurally rejects member caps that grant write access without a matching `!<col>/_keyring` denylist entry. Enforced on the server because strict-kind dispatch routes every `member` cap through that validator (see the follow-up pass below).
- **Member caps tightened to exactly one collection** — `assertCapCertWellFormed` now raises `member-multi-collection` if `scope.collections` has any length other than 1. Mirrors the design intent that member caps are collection-scoped (only device caps span multiple collections via `"*"`). `mintMemberCap` API gained a positional `collection: string` argument; it forces `scope.collections = [collection]` internally.
- **Member-cap `_members` deny (always-on)** — every member cap (read or write) is now required to deny `<col>/_members` whenever its `paths` would otherwise reach the directory; `assertCapCertWellFormed` raises `member-members-not-denied`. The members directory is owner-only by design and members do not need it for cryptographic operations (the keyring is the source of truth for "who can decrypt"). `scopes.readOnly` and `scopes.writer` presets now include the `!<col>/_members` deny automatically.
- **X25519 small-subgroup rejection** — wrap and unwrap reject the all-zero shared secret (RFC 7748 §6.1). Defends against a malicious-server-planted `ephKem` forcing a predictable wrap key.
- **Best-effort key wiping** — `argon2id` master, ephemeral X25519 priv keys, and derived wrap keys are zeroed before they fall out of scope.

### Security (follow-up review pass)

- **Cap-resolver is secure by default** — strict-kind dispatch now runs on *every* request, not only when `plugins` is supplied. With no plugins the resolver falls back to a built-in **device-only** default, so a `member` cap (whose structural barriers — `member-self`, `member-private-path`, `!<col>/_keyring`, …) live in `sharingServerPlugin`) is **rejected** until that plugin is wired. Previously, omitting `plugins` skipped dispatch entirely and a forged member cap was accepted with baseline checks only. `defaultServerPlugin` is reduced to device-only (its no-op `member` validator is removed). An explicit `plugins: []` accepts no cap kinds (anonymous-only). The example servers now wire `[identitiesServerPlugin, sharingServerPlugin]`.
- **`bindAuthIdentity` fails closed** — a `member` cap missing `subUserId` now raises `CapAuthError(401)` in both languages (was: TS bound an `undefined` identity; Python raised an uncaught `KeyError` → HTTP 500).
- **Cap-resolver runs on non-Node runtimes** — `parseCapHeader` decodes the `Authorization` header via the injectable `getBase64()` instead of Node's `Buffer`, so cap auth works on Cloudflare Workers / Deno without `nodejs_compat`.
- **Keyring hostile-server hardening** — `createKeyringEncryptor` (and the adder's `recoverCurrentCek`) reject an epoch whose recipient `subKem` appears more than once (a server-injected duplicate entry), failing closed instead of adopting an attacker-chosen CEK. `createKeyringEncryptor` gained an optional `trustedAdders` / `trusted_adders` allowlist: when supplied, an entry whose self-attesting `addedBy` is not a trusted issuer is skipped (defends against single-entry replacement, which the audit signature alone cannot catch). Follow-up: threading `trustedAdders` end-to-end through the client `SyncManager` (so callers don't pass it manually) is not yet wired — the unconditional duplicate-`subKem` guard is the active default defense until then.
- **Pairing relay proof-of-possession** — the encrypted relay request now carries an Ed25519 `popSig` over `{devEdPub, devKemPub, requestNonce}` signed with the device's `edPriv`; `readPairingRequest` verifies it, so a relay (even one that learns the code) cannot substitute a `devKemPub` it controls to harvest the wrapped CEKs. `buildPairingRequest` now requires `edPriv`. PBKDF2 iterations raised 200 000 → 600 000 (OWASP-2023 floor). The code remains a short shared secret — the relay MUST enforce one-shot use + rate-limiting; prefer a longer code or a PAKE for high-threat deployments.
- **Nonce cache never evicts a live nonce** — a non-expired nonce is no longer dropped to make room (which re-opened a replay slot); the cache reclaims expired entries and otherwise fails closed when a cap is hit. The acceptance window default is raised to 10 min (≥ 2× the 5-min request clock-skew) so a clock-ahead request's nonce cannot expire while still skew-acceptable. **Default caps raised** to keep fail-closed rejections rare under normal load: `perSignerLimit` 64 → 4 096, `maxEntries` 10 000 → 100 000 (≈1.5 MB → ≈15 MB at full saturation). Operators who tuned these explicitly should re-check their values; high-throughput or multi-instance deployments should back the cache with a shared store.
- **Config lint warnings** — `collectConfigWarnings` / `collect_config_warnings` (run at config load) flags a `public` entry in `writeRoles` (anonymous writes) and a `cap:<op>:<other>` role naming a different collection (a copy-paste typo that grants cross-collection access). Non-fatal.
- **Cross-language number canonicalization** — `stable_stringify` (Python) now renders numbers the way JavaScript's `JSON.stringify` does: whole-number floats lose the trailing `.0` (`1.0` → `1`) and `-0.0` renders as `0`, so a document carrying such a value hashes and signs identically across languages. Locked by a new `tests/test-vectors/hash.json` case.
- **`deepMerge` denylist parity** — the TypeScript `UNSAFE_KEYS` set now also includes the Python dunder vectors `__class__` / `__dict__`, and `deepMerge` filters unsafe keys out of the *local* document too (not only `remote`), matching the Python implementation.
- **`deriveKey` byte-locked in TypeScript** — the protocol test now asserts the exact derived key bytes against the shared `crypto.json` vector (was: round-trip only), closing a one-sided cross-language lock.

### Security (second review pass)

- **Member-cap `_keyring`/`_members` barrier no longer bypassable via `**`** — the mint/validation barrier (`assertMemberCapShape`, run server-side via `sharingServerPlugin`) decided whether a `!<col>/_keyring` / `!<col>/_members` deny was required using `pathGlobMatch`, where `**` did not cross `/`, while the resolver enforces scope with the opposite rule (`**` → `.*`). A member cap with an allow like `**` or `notes**` therefore cleared the barrier with no deny yet was granted `_keyring`/`_members` access at request time (key material + owner directory → recipient injection / key rotation / owner lockout). `pathGlobMatch` now treats `**` as crossing slashes, and the resolver's `matchScopePath` / `match_scope_path` delegates to it, so the mint barrier and the request-path enforcement share one matcher and cannot drift. (TS + Python.)
- **`scopes.admin` documented as device-only** — the admin preset (`<col>/**`, no deny) cannot be minted as a `member` cap (the barrier correctly forbids member caps from reaching `_keyring`/`_members`); it is valid only for a `device` cap (`mintDeviceCap`), where the subject proxies for the owner. Doc comments corrected and the behavior pinned by tests (`mintDeviceCap` accepts it; `mintMemberCap` rejects it).
- **Nonce-cache replay slot at exactly 2× skew closed** — the replay check used a strict `existing > now` comparison, so at the exact expiry instant (`now == exp`, reachable at the `2× clock-skew` boundary the window is sized for) a captured request could be replayed once. The check (and the reclaim loop) now treat `exp == now` as still-live. (TS + Python.)
- **`installPairingBundle` fully verifies the cap-cert** — it previously checked only the signature, so an expired/not-yet-valid bundle, or a signed `member` cap (which binds identity to its subject, not the issuer), could be installed and treated as a root-proxy device credential. It now runs the full `verifyCapCert` (signature + not-before/expiry window + well-formedness), requires `kind === "device"`, and requires the cap-cert issuer to equal `bundle.rootEdPub`. An optional `now` makes the window check deterministic for tests. (TS + Python.)
- **Pairing bundle bound to its QR session** — `assemblePairingBundle` echoes the QR's `qrNonce` into the bundle, and `installPairingBundle` accepts an `expectedQrNonce` (the value the device put in its own QR) that must match, so a stale/replayed bundle captured from another session is rejected. (TS + Python.)
- **Paired-device scope can be bounded by the root** — `assemblePairingBundle` gained `grantedScope` / `granted_scope`, which overrides the peer-supplied (QR/relay) `requestedScope`. Because a `device` cap is a root proxy regardless of its paths, a tampered QR requesting root-all access would otherwise yield a full root proxy; callers that do not fully trust the QR source pass `grantedScope` to clamp the delegated authority. (TS + Python.)
- **Recipient helpers accept `trustedAdders`** — `addRecipient` / `add_recipient` (and `removeRecipient` / `remove_recipient`) now take the same `trustedAdders` pin as `createKeyringEncryptor`. The `addedSig` is self-attesting, so a hostile server can replace the adder's own keyring entry with one wrapping an attacker-chosen CEK to the adder's public KEM key; `recoverCurrentCek` would then unwrap that forged CEK and re-wrap it for the new recipient. Pinning the trusted adders skips entries signed by an untrusted key; `removeRecipient` likewise drops untrusted-injected entries on rotation. (Continues the `trustedAdders` end-to-end threading noted in the previous pass.)
- **Cap-cert runtime shape validation** — `assertCapCertWellFormed` / `assert_cap_cert_well_formed` now validate the parsed cap-cert structure (kind, `iss`/`sub`/`subKem`/`issUserId`/`nonce` strings, numeric `nbf`/`exp`, and `scope.ops` ∈ {read,write,list} / `scope.collections` / `scope.paths` as string arrays) and raise `malformed-shape`. A self-signed cert with a string `scope.ops` previously slipped through and was iterated character-by-character into fabricated roles. `verifyCapCert` now runs well-formedness before the time-window comparison so a malformed `nbf`/`exp` fails closed identically on both sides. (TS + Python.)
- **`X-Starfish-Ts` / `Content-Length` parsed identically across runtimes** — the resolver validates these headers as base-10 integers with a shared `^-?\d+$` rule. JS `Number()` accepted `0x10` / `1e3` / `12.5`, and Python `int()` accepted whitespace-padded / `_`-separated / signed values; the same request now authenticates the same way on either server. (TS + Python.)
- **Python keyring wrap scrubs secret intermediates** — `wrap_for_recipient` now holds the ephemeral private key, ECDH shared secret, and derived wrap key in `bytearray`s and zeroes them after use (a caller-supplied ephemeral key is copied and left intact), matching the TypeScript wrap's best-effort wipe.
- **Revocation retention contract clarified** — a revoked cap is honored by the resolver until `exp + clockSkewSec`, so a persistence/compaction layer that pruned a revocation entry at its `exp` would un-revoke a still-acceptable cap. The `RevocationEntry.exp` doc now states this, and `revocationRetainUntilSec` / `revocation_retain_until_sec` (+ `REVOCATION_RETAIN_SKEW_SEC`) expose the earliest safe prune time. The in-memory store already retains by generation, not time. (TS + Python.)

### Security (third review pass)

- **Bundle pull no longer leaks unauthorized collections** — the bundle pull endpoint authorized only the bundle's *first* collection and then returned every member's data, and it skipped authorization entirely if *any* member was public. It now resolves the caller's roles once (the resolver consumes the request nonce, so it must run at most once) and authorizes **each** member independently: a member is returned only when it is public or the caller holds one of its `readRoles`. Denied members are omitted, and a public member never exposes a private sibling. (TS + Python.) For a homogeneous-roles bundle the response is unchanged; clients reading bundle members should optional-chain (`collections.x?.data`) — a member absent from `collections` now means the caller is not authorized for it (previously such a member was leaked).
- **Field-read filtering applied on bundle and batch pulls** — `fieldPermissions` read restrictions were enforced only on the standalone pull path; the bundle pull and the TS `/batch/pull` handler returned restricted fields. A shared filter helper now runs on all three paths. (TS bundle + batch; Python bundle — the Python batch path already filtered.)
- **Field-write permissions enforced on bundle pushes** — the field-write check lived inline in the standalone push handler, so the TS bundle push path (which calls `runPush` directly) skipped it; a non-privileged caller could write an admin-only field via the bundle endpoint. The check moved into `runPush`, covering both paths, and the bundle push now passes the resolved roles into its store context. (Python's `_run_push` already enforced it.)
- **`cap-cert` `nbf`/`exp` reject `Infinity`/`NaN`** — TS validated them with `typeof === "number"`, which accepts `Infinity` (a wire `exp: 1e400` parses to `Infinity` and passes the `now > exp + skew` gate, effectively disabling expiry). It now uses `Number.isInteger`, matching Python's `_is_int`.
- **Replica strips prototype-pollution keys from ingested primary data** — the pull-only / push-through sync wrote the primary's `data` verbatim (only the bidirectional merge stripped unsafe keys). It now runs `deepSanitize` / `deep_sanitize` on the data before writing, so a compromised primary cannot plant `__proto__` / `constructor` / `prototype` into the replica store. (TS + Python.) This matches the server's stored-data sanitize policy (the JS-prototype keys); apps that also want the Python-dunder vectors (`__class__` / `__dict__`, which `deep_merge` strips) removed should layer their own `ObjectStore` wrapper.
- **Replica validates the primary's push response shape** — `proxyPush` relayed the primary's response body to the client verbatim; it now requires a 2xx response to be an object with a string `hash`, returning HTTP 502 otherwise. (TS + Python.)
- **Push-through (proxied) writes are audited** — a write a plugin proxies to a primary (the `interceptPush` `respond`/`reject` path) returned before the audit call, leaving it invisible to the audit log. It now records a `push` audit entry (no `WriteEvent` is emitted — the write lands on the primary, which owns that change event). (TS + Python.)
- **Entitlement enricher does not cache a corrupt-document result** — the Python enricher cached the empty result after a corrupt entitlement document, denying entitlement roles for the whole cache TTL even after the document was repaired. It now returns without caching on the corrupt path, matching the TypeScript enricher.
- **Config-load warning for `self` without `{identity}`** — `collectConfigWarnings` / `collect_config_warnings` now flags a collection that uses the `self` role but whose `storagePath` has no `{identity}` segment (e.g. a `{owner}`/`{userId}` typo): `self` is granted only when the `{identity}` path param equals the caller, so it could never be granted there. (TS + Python.)

### Security (fourth review pass)

- **Pairing `grantedScope` and keyring `trustedAdders` are now REQUIRED (fail closed)** — `assemblePairingBundle` / `assemble_pairing_bundle` no longer defaults the granted scope to the peer-supplied QR `requestedScope`. A hostile/tampered QR could request root-all access and — because a `device` cap is a root proxy regardless of its paths — mint a full-account proxy; the root must now pass an explicit `grantedScope` / `granted_scope` or the call throws. Likewise `createKeyringEncryptor` / `create_keyring_encryptor` and the collection-scoped `addRecipient` / `removeRecipient` (`add_recipient` / `remove_recipient`) now throw without a `trustedAdders` / `trusted_adders` pin — the per-entry `addedSig` is self-attesting, so without a provenance pin a hostile server can substitute a wrapped-key entry that wraps an attacker-chosen CEK. Upgrades the optional versions added in earlier passes to fail-closed defaults. (TS + Python; examples updated to pass the owner's root edPub / requested scope.)
- **Path-traversal guard on bundle-pull and binary-pull** — the standalone JSON pull re-checked the resolved key with the `UNSAFE_KEY` (`..` / `//` / control-char) guard, but the binary `getBytes` branch and the bundle-pull loop read the store directly. A non-`{identity}` path param carrying `..` (which passes the per-segment charset check) composed a traversal key the cap scope `col/**` happily matched. The guard — now exported as `isUnsafeDocumentKey` / `is_unsafe_document_key` — runs on the resolved key for both paths and returns 400. (Batch-pull was already safe: it substitutes `_batch_` for params.) (TS + Python.)
- **Cross-language canonical encoder hardened** — `stableStringify` / `stable_stringify` now sort object keys by Unicode code point (TS previously used UTF-16 code-unit order, which diverges for a non-BMP key vs. a BMP char ≥ U+E000), and Python now renders integers outside ±2^53 / ≥ 1e21 the way JS `JSON.stringify` does (precision-lossy / exponent form). A document body carrying such keys or large integers now hashes identically across languages; new `tests/test-vectors/hash.json` cases lock both. (Extends the number-canonicalization fix from an earlier pass.)
- **Cap-cert validation hardened** — `assertCapCertWellFormed` / `assert_cap_cert_well_formed` now enforce that `nonce` decodes to exactly 16 bytes of base64 (was: any string — a degenerate or reused nonce weakened the per-`(iss, sub, nonce)` revocation key), and accept a whole-number-float `nbf`/`exp` (e.g. `1700000000.0`) on both sides — JS cannot distinguish it from the integer after JSON parse, so Python now matches via `_is_js_integer`, closing a cert that authenticated on a TS server but was rejected by a Python one. The TS `capCertCanonicalSigningInput` also strips `sig` internally (matching Python), so passing a signed cert can never fold `sig` into the signing bytes. (TS + Python.)
- **X25519 small-subgroup rejection extended to pairing** — pairing's CEK wrap/unwrap now reject the all-zero shared secret (RFC 7748 §6.1), the guard the keyring layer already applied; the two ECDH paths are aligned. (TS + Python.)
- **Subject-level revocation** — `RevocationList` gained an optional `revokedSubjects` list (`{sub, exp}` entries) that invalidates **every** cap for a subject regardless of nonce — the incident-response primitive for a compromised device/member, where re-minting under a fresh nonce would slip past a per-nonce `RevocationEntry`. Backward compatible: lists without the field verify and behave exactly as before, and `isRevoked` / `is_revoked` consults it transparently so the resolver needs no change. New `RevokedSubject` type exported from both servers. (TS + Python.)
- **Argon2id cost raised above the OWASP interactive-login minimum** — root-identity derivation and passphrase-sealed envelopes now use **m = 47104 KiB (≈ 46 MiB), t = 3, p = 1** (was m = 19456, t = 2): a root identity — and a sealed envelope carrying private device keys — is a higher-value, longer-lived secret than a session login. TS (`hash-wasm`) and Python (`argon2-cffi`) produce byte-identical output, and the seal open-side parameter allow-list tracks the new values automatically. All cross-language fixture vectors (`identity-derivation`, `cap-cert`, `multi-recipient-wrap`, `pairing-bundle`, `request-signature`, `revocation-list`, `passphrase-seal`) were regenerated, along with the hardcoded fixture key in the cap-verify tests. (TS + Python.)
- **Batch-pull TTL parity** — the TS `/batch/pull` handler returned documents past their collection `ttlMs`; it now applies the same stored-timestamp expiry check as the standalone pull and the Python batch handler.
- **`listable` validation parity** — a `listable` collection whose `storagePath` ends in a trailing slash was rejected by the TS validator but accepted by the Python one; both now strip the trailing slash before checking the last segment.
- **Python root-derivation scrubs the master secret** — `derive_root_identity` holds the Argon2id master in a `bytearray` and zeroes it after deriving both seeds, matching the TS `master.fill(0)` (best-effort — Argon2/HKDF may keep internal copies Python cannot reach).
- **Removed orphan `tests/test-vectors/http-errors.json`** — it was loaded by no test in either language, so it locked nothing; removed rather than leave a vector implying error-shape parity is tested.

### Security (residual-items pass)

Closes / mitigates several items the example app's edge suite previously documented as by-design residuals (`examples/app/TESTING.md`).

- **Membership-bound room writes (example app)** — the `chat` collection's write role was a bare `cap:write:chat`, so any self-signed stranger holding a chat-scoped cap could clobber an established room's encrypted document (a DoS on merge-protected content). Room writes now require the synthesized `chat:owner` **or** `chat:member` role: the `owner_role_enricher` grants `chat:member` only to a writer who is listed in the room's member directory **and** holds `cap:write:chat`, so a stranger (not in the roster) gets 403 while read-only members still cannot post. Brand-new rooms stay TOFU-open (the first valid keyring write establishes the owner). `test_stranger_self_signed_cap_can_overwrite_room` was inverted (200 → **403**) accordingly; this is an app-layer change (the Python backend), no TS twin. (Reconsiders the previously-declined "Level 3" binding.)
- **Rate-limited rendezvous slot (example app)** — the public `_pairing/{rendezvousId}` slot now sets a per-collection `rate_limit` (30 writes/min per source) so a flood of overwrites is bounded; a single overwrite still works (the slot is public by design). The same `CollectionConfig.rate_limit` mechanism is recommended for `chatkeyring` in production to blunt the TOFU room-id squat window. Pinned by `test_rendezvous_slot_is_rate_limited`.
- **Required root-pin in the pairing UI (example app)** — the camera-free "Phone scans" flow's join button is now disabled until the first device's root key is pasted, matching the library's required `expectedRootEdPub` (which throws without it), so a user can't attempt an unpinned install over the anonymously-overwritable slot.
- See **Added** for the `buildRevocationList` / `evictMember` library helpers that make full, footgun-free eviction a single call.

### Security (review follow-up — example app)

- **Three new edge-suite pins** (`examples/app/backend/tests/test_edge.py`, now 94 tests): demo/admin endpoints return **403** when `STARFISH_DEMO_SECRET` is unset (`test_demo_endpoints_disabled_when_secret_unset`); a write-only cap can TOFU-squat a keyring without read access but the owner recovers (`test_write_only_cap_can_tofu_squat_keyring_but_owner_recovers`); `GET /events` over HTTP broadcasts metadata only (`test_events_sse_over_http_metadata_only`).
- **Production-oriented server env** (`examples/app/backend/server.py`): `STARFISH_CORS_ORIGIN` (comma-separated origins), `STARFISH_ENABLE_KEYRING_RATE_LIMIT=1` (opt-in `chatkeyring` 30 writes/min per source), and documented guidance to gate `/events` when activity metadata is sensitive. Deployment table in `examples/app/TESTING.md` and `examples/app/README.md`.
- **Deployment docs: `X-Forwarded-For` spoofing risk made explicit** (`examples/app/README.md`, `examples/app/TESTING.md`) — the deploy guides previously noted that the rate limiter keys anonymous traffic by the first `X-Forwarded-For` hop but framed it as a correctness concern. The docs now state the security implication: `X-Forwarded-For` is client-supplied, so a directly-reachable deployment lets an attacker spoof/rotate the hop to evade per-source limits. The required mitigation — deploy behind a trusted proxy that *overwrites* (not appends) XFF, never expose the app port directly — and the TS-vs-Python socket-IP fallback difference are spelled out explicitly.

### Tests (adversarial regression sweep)

A further three-round gap hunt across the library and the example app. The security guards probed were already in place, so this is mostly regression-pinning; it also surfaced and fixed one (non-security) TS↔Python parity divergence. New tests (TS + Python parity where applicable):

- **Parsing boundaries** — `Content-Length` obeys the same canonical `-?\d+` rule as the timestamp header (`+64` / ` 64` / `1e3` / `0x10` / `""` → 413; leading zeros accepted); the JSON depth guard is an inclusive ceiling at *exactly* `MAX_DOC_DEPTH` (64 ok, 65 → 400), pinned both as a unit test and end-to-end through a real push; batch `?collections=` empty slots are dropped (Python).
- **Argon2id DoS guard** — added the missing inflated-`iter` and inflated-`par` cases (alongside the existing inflated-`memKiB` / unknown-`alg` / unknown-`enc` / short-salt) to both `seal-dos.test.ts` and `test_seal.py`, proving a hostile sealed envelope is rejected *before* the KDF runs in both languages.
- **Nonce binding** — the request nonce is signed as a verbatim base64 *string*, so a byte-equivalent re-encoding (padded↔unpadded) fails verification and cannot dodge the string-keyed replay cache.
- **Unicode / homograph / RTL containment** — path params are pinned to an ASCII charset before auth, so a Cyrillic-`а` look-alike, an RTL-override, or a non-ASCII identity/roomId is rejected 400 (lib + example app).
- **Field-permission `null`** — setting an admin-only field to `null` is still a write (presence, not truthiness) → 403.
- **Fixed — `/batch/pull` CSV parity (TS≠Python, robustness only):** the TS handler kept empty CSV slots, so `?collections=,a,,` produced spurious `""` → "Collection not found" entries; the Python handler dropped them. The TS handler now guards on the raw param and filters empty slots exactly like Python — a present-but-all-empty `,,` resolves to `200 { collections: {} }` (not 400), and empty slots around real names are ignored. Pinned by regression tests in both `batch-and-field-perms.test.ts` and `test_router.py`. Not a security hole (the stray `""` lookup only errored; no data leaked).

A further three-round sweep covered TTL/ETag, keyring/sharing internals, and integration cases. One Python-only correctness bug was found and fixed; everything else is robust and now pinned:

- **Fixed (Python-only correctness): field-permission collections used to drop the ETag.** The Python pull handler strips restricted fields by rebuilding the `JSONResponse`, which discarded the hash-derived ETag header — so `If-None-Match` → 304 conditional caching silently never fired for field-permission collections (profiles, etc.). The rebuild now carries the ETag (and Cache-Control) forward (field filtering changes the body view, not the document version), matching the TS server, which filters `data` in place and never loses the ETag. Pinned by `test_etag_conditional_survives_field_permission_filtering` (Python) and a positive twin in `batch-and-field-perms.test.ts` (TS).
- **Robust (pinned):** batch pull honors TTL expiry (Python parity with the existing TS test); the keyring unwrap rejects a structurally malformed entry (ciphertext shorter than the IV); `removeMemberEntry` / `remove_member_entry` on an unknown nonce is an idempotent no-op; **owner self-eviction keeps the owner role but revoking the owner's own cap overrides it** (revocation is evaluated before the role enricher → 401); and **concurrent member-directory adds both land** (the 409 optimistic-concurrency retry resolves a real `asyncio.gather` race — no lost update).

A three-round sweep of the protocol core (merge, cap-cert verification, the scope matcher) and the keyring's binary surface surfaced one cross-language **parity gap** and one hardening, **both now fixed**; everything else was robust or already covered:

- **Fixed (cross-language parity): the Python keyring now has `seal_bytes`/`open_bytes`.** The TS `KeyringEncryptor` seals raw bytes as a self-describing blob (`[u32 BE epoch][12B iv][AES-256-GCM ct‖tag]`) with the storage path bound as AAD (anti-relocation / anti-replay), the only way to E2E-protect attachments in a `encryption: "none"` binary collection — and Python lacked any equivalent. `KeyringEncryptor.seal_bytes(data, aad=None)` / `open_bytes(blob, aad=None)` now mirror it byte-for-byte (same header, IV size, and `starfish-blob:{epoch}:{aad}` AAD rule), so a blob sealed in one language opens in the other. Pinned by `test_keyring_encryptor_seals_and_opens_binary_blobs_with_path_aad` (Python) and the existing TS twin in `keyring.test.ts`.
- **Fixed (hardening): `verify_cap_cert` rejects an inverted / zero-width validity window.** Without an explicit `exp > nbf` check, a cap whose `exp` is at or before its `nbf` could still pass both time gates during the instant where the skew margins overlap (`nbf - exp ≤ 2·skew`). Both languages now reject `exp <= nbf` (reason `inverted-window`) before the time-window comparisons. Issuer-self-signed and nonsensical rather than an escalation, but closed regardless. Pinned at the protocol layer (`test_cap_verify.py` / `cap-verify.test.ts`) and the integration layer (`test_inverted_validity_window_cap_is_rejected`). Follow-up: the mint helpers could also reject a negative `ttl_sec` so such a cert is never produced.
- **Robust (pinned, TS + Python parity):** `deep_merge` type transitions (scalar↔object replace wholesale; arrays never element-merge) and the dunder-scrub boundary (dropped at the root and inside nested objects, but an array-nested dunder rides along — identical in both languages); cap-cert validity windows are inclusive at *exactly* `exp + skew` / `nbf - skew` (off-by-one pinned); an empty `scope.ops: []` is well-formed and authorizes nothing (not a wildcard); `path_glob_match` keeps `*` from crossing a slash, lets `**` cross, escapes regex specials (a literal `.`), and requires a full match.
- **Cleared hypotheses (no gap):** append-only "duplicate idempotency" is by design (no dedup contract; the nonce is per-entry uniqueness); the entitlements `expires_at` is the resolver's cache TTL, not a per-feature expiry; astral-key ordering is already defended (code-point sort) and pinned in the shared `hash.json` vector; revocation `generation` monotonicity is already covered in `test_revocation_store.py`.

Another three-round sweep covered the replica extension's sync loop and the client `SyncManager`'s conflict/concurrency paths, with cross-language parity checks. One cross-language gap found (pinned, not fixed); the client paths are robust:

- **Fixed (cross-language): a corrupt local replica document was never recovered.** `ReplicaManager._doSync` / `_do_sync` intends to treat a corrupt local doc as empty and overwrite it, but coerced `baseHash = currentLocalHash || null` (TS) / `current_local_hash if current_local_hash else None` (Python) — both turned `""` → `null`/`None`. `push()` recovers a corrupt doc only when `baseHash === ""`; with `baseHash == null` and a present (corrupt) doc it returns HASH_MISMATCH. So sync raised "Concurrent write — will retry" on every cycle (a transient-looking error that never recovered), leaving the replica permanently stuck on that collection, in **both languages**. Fixed by passing `currentLocalHash` / `current_local_hash` verbatim (no `""`→`null` coercion); a valid local doc still yields its real hash, so genuine concurrent-write detection is preserved. Pinned by regression tests in `manager.test.ts` + `test_manager.py`.
- **Robust (pinned, TS + Python parity):** repeated bidirectional replica sync converges (idempotent, lossless re-merge); two concurrent `push()` calls on one `SyncManager` both land with no lost write (the loser conflict-retries and the default deep-merge unions them); a stale/corrupt rehydrated `lastHash` self-heals via the conflict-retry loop (the server treats any non-matching `baseHash` as a 409). Verified **identical** across TS and Python — no concurrency or self-heal divergence.

A three-round sweep covered the incremental-sync core (`compute_timestamps`, `filter_by_checkpoint`, `max_leaf_timestamp`), previously only conformance-vector-tested. **No reachable gap:**

- **Robust (pinned, TS + Python parity):** per-field LWW — an unchanged leaf keeps its old timestamp, a changed leaf gets `now`, a new key gets `now` while a removed key is omitted, leaf↔object transitions stamp `now`, and an identical list keeps its ts but a reorder counts as a change; `filter_by_checkpoint` is strict at the boundary (`ts == checkpoint` excluded), drops a field with no timestamp, and prunes an empty nested subtree while keeping changed sub-fields. Pinned in `test_timestamps.py` / `timestamps.test.ts`.
- **Cleared (no gap):** a `number[]` (per-item append-only) timestamp is handled differently by the two generic filters (TS drops the field, Python passes it through), but the path is **unreachable** — `compute_timestamps` never emits a `number[]`, and real append-only docs route to `handle_append_only_pull` (custom per-item filtering). Pinned as a tripwire in both languages so the divergence is flagged if the routing ever changes.

A three-round sweep covered the extension plugins — queuing, audit, entitlements, the merge primitive, and the sharing member-directory under churn. It surfaced **two cross-language parity divergences, both now fixed:**

- **Fixed (cross-language parity): an empty-string queue `topic` published to the empty subject in TS.** The TS queuing plugin used `cfg.topic ?? event.collection`, so a `topic: ""` config published to subject `""` (a broker footgun), while Python's `config.topic or event.collection` coalesced it to the collection name. TS now uses `cfg.topic || event.collection`, matching Python — an empty/unset topic falls back to the collection name in both. Pinned by `plugin.test.ts` / `test_plugin.py`.
- **Fixed (cross-language parity + latent failure mode): the TS server did not await `auditLogger.record()`.** The TS push/pull handlers called `opts.auditLogger.record(...)` without `await` (fire-and-forget), while the Python server awaits it. Two consequences in TS: an async audit logger's write could be lost (the response returned before it completed, so a crash right after dropped the entry), and a logger that *rejected* became an unhandled promise rejection (process-crash risk under Node's `--unhandled-rejections=throw`). All five call sites (the auth-denial path + pull + push-through + binary-push + json-push) now `await` the record call, matching Python — audit is durable before the response and a failing logger surfaces consistently. Pinned by `router-emission.test.ts` / `test_audit_router.py`.
- **Robust (pinned, TS + Python parity):** queuing omits `params` when the storage path has no placeholders and preserves Unicode in topic + body; `deepMerge` lets a remote `null`/`None` overwrite a local object and a remote object replace a local null; the entitlement cache TTL boundary is strict (`expires_at > now`, re-reads at exactly `t == expires_at`) and an empty-string feature slug yields a bare-prefix role in both languages; the member directory upserts by nonce (re-add does not duplicate) and converges on *present* after add → remove → re-add.
- **Cleared (no gap):** the queuing body `!== undefined` vs `is not None` difference sits on an unreachable path (the server never emits `body=null`), pinned as a tripwire; `proxyPush` 409 + response-shape handling and the `UNSAFE_KEYS` denylist are already at full parity; the entitlement cache time source (`Date.now()` vs `time.monotonic()`) differs only under wall-clock adjustment — a benign design choice, not a divergence.

A three-round sweep covered the auth internals — cap-resolver request-signature verification, the nonce cache, the revocation store, keyring epoch/recipient churn, and the canonical-encoding float path. It surfaced **one correctness/interop gap, now fixed:**

- **Fixed (cross-language interop): binary blob uploads were unauthenticatable on a Python cap-auth server.** Clients sign a blob upload with an EMPTY body — the large/streamed blob bytes are not folded into the per-request signature (blob integrity comes from the content seal + the signed path). The TS server mirrors this: it detects `application/octet-stream` and verifies against an empty body (`cap-resolver.ts`, pinned by `cap-resolver.test.ts:186`). The Python server (`cap_resolver.py`) had no such detection and verified against the full body, so a cap-signed blob upload failed with `bad request signature` (401). It went unnoticed because the Python binary-collection test uses a *static* role resolver, bypassing the signature path entirely. **Fixed:** the Python resolver now mirrors TS. Both servers were then broadened (follow-up) to treat **any non-JSON content type** as a blob upload signed over an empty body — not just `application/octet-stream` — since clients sign *any* blob (`image/png`, etc.) with an empty body. The media type is compared on its prefix (parameters stripped), and an empty/missing content type is treated as non-blob (signs the body) so a missing header can't dodge body-signing; JSON collections still reject a non-JSON content type at the handler's MIME check. Pinned by `test_cap_resolver.py::test_blob_upload_signed_with_empty_body_is_accepted` plus an `image/png` case in both `cap-resolver.test.ts` and `test_cap_resolver.py`.
- **Robust (pinned, TS + Python parity):** the clock-skew gate is inclusive at exactly `±maxSkewMs` and excludes one ms beyond (strict `<=`, both sides); a generation-0 revocation list is accepted as the first list for an issuer (a gen-0 replay is then stale); a rotated-out keyring recipient regains access when re-added to the new epoch, and rotating out *every* recipient yields an empty epoch whose encryptor then fails for a former recipient.
- **Cleared (no gap):** TS↔Python `stableStringify` float rendering is byte-identical for arithmetic results (`0.1 + 0.2` → `0.30000000000000004`), `1e-7`, and max-double — now locked by `hash.json` vectors; the nonce-cache `signer|nonce` key cannot collide (hex signer + base64 nonce contain no `|`); root-identity derivation and the pairing bundles are already cross-language vector-locked.

Another three-round sweep covered the server router internals and storage — field permissions, the rate limiter, batch/bundle pull, and `push()` conflict handling. It surfaced **two more cross-language gaps, both now fixed:**

- **Fixed (cross-language + internal inconsistency): the Python field-WRITE permission check ignored `ROLE_PUBLIC`.** A field marked `writeRoles: ["public"]` (i.e. unrestricted) is writable by an authenticated user on the TS server (`route-builder.ts:439`, `r === ROLE_PUBLIC`) but returned **403 on Python** (`route_builder.py`) — because the Python field-write check omitted the `ROLE_PUBLIC` short-circuit that its *own* field-READ check (line 294) and the TS write check both have. An authenticated cap user carries cap roles, not the literal `"public"`, so the unrestricted field was wrongly denied. **Fixed:** added `or r == ROLE_PUBLIC` to the Python write check, mirroring its read check and the TS server; pinned by the now-passing `test_ttl_and_field_permissions.py::test_field_write_public_role_allows_authenticated_user` with the TS reference in `batch-and-field-perms.test.ts`.
- **Fixed (cross-language DoS): the Python `RateLimiter` had no bucket cap.** The TS limiter caps `_buckets` at `maxBuckets` (default 10 000) and evicts the oldest entry (`middleware.ts`); the Python limiter (`middleware.py`) grew its dict without bound, so a flood of distinct keys (e.g. spoofed `X-Forwarded-For` on an anonymous endpoint) was a memory-exhaustion DoS vector. **Fixed:** the Python limiter now takes a `max_buckets` argument (default 10 000) and evicts the oldest bucket at capacity, mirroring TS; pinned by the now-passing `test_rate_limit_and_cache.py::test_rate_limiter_bounds_bucket_count` with the TS twin in `middleware.test.ts`. The per-source key fallback was also converged (follow-up): both `check` methods now take an explicit `(identity, forwarded_for, client_ip)` and apply the *identical* precedence — identity → first `X-Forwarded-For` hop → client IP → shared `"anonymous"`. The limiter is runtime-agnostic (keys on plain strings); the call site supplies what it has — the Python server passes the socket `request.client.host` as `client_ip` (preserving per-IP isolation for direct deployments), while the TS server passes `null` because Hono has no portable socket IP (a proxy must set `X-Forwarded-For` for per-client limiting). Pinned by a key-precedence test in both `middleware.test.ts` and `test_rate_limit_and_cache.py`.
- **Robust (pinned, TS + Python parity):** the `RateLimiter` allows up to the limit then 429s and isolates counters per bucket key; a corrupt stored document does not crash `push()` (returns a conflict) and is overwritable with `baseHash=""` (added the TS twins of the existing Python `test_push.py` corrupt-doc tests).
- **Cleared (no gap):** `StoreContext` is populated consistently across the pull/push/list/bundle/batch handlers in both languages; the `push()` conflict + corrupt-recovery logic is byte-identical; batch/bundle partial-denial transparency matches.

A three-round sweep of the client SyncManager and the lower-level protocol (MIME matching, path-key safety, `deepSanitize`, append-only build) surfaced **one cross-language divergence, now fixed:**

- **Fixed (cross-language divergence): the Python MIME matcher used `fnmatch`.** Both servers strip content-type parameters and lowercase, and agree on exact types, `type/*`, and `*/*`. But the TS matcher (`mime.ts`) does component-only wildcarding (only a whole `*` component is a wildcard), while the Python matcher (`mime.py`) used `fnmatch.fnmatch`, so partial globs — `image/p*`, `application/*json`, `text/?ml`, `[seq]` character classes, and a bare `*` — all matched in Python but not TS, so the same `allowedMimeTypes` config accepted/rejected differently across a TS vs Python server (and an allowlist over-matching via glob metacharacters is the riskier direction). **Fixed:** the Python matcher is converged to TS's component-only semantics (`fnmatch` dropped); pinned by `test_mime.py` / `mime.test.ts`. MIME pattern matching is now `type/subtype`, `type/*`, and `*/*` only (the standard MIME-pattern conventions) in both languages.
- **Robust (pinned, TS + Python parity):** MIME exact / `type/*` / `*/*` matching, parameter-stripping, and case-insensitivity; `isJsonCollection`; the client incremental pull replaces an array wholesale (deepMerge is not element-wise) while preserving local-only keys; a custom conflict resolver that throws propagates its error (not swallowed). New dedicated MIME unit tests (`mime.test.ts` / `test_mime.py`) in both languages.
- **Cleared (no gap):** the client SyncManager has **no** TS↔Python divergence (checkpoint advance, conflict-retry, encryptor integration, and baseHash handling are all identical); `deepSanitize` / `deep_sanitize` are identical (both recurse only into plain objects/dicts and copy arrays + array-nested dunders verbatim, matching the earlier deepMerge finding — the recon's "TS scrubs array-nested dunders" claim was a misread); `validate_path_segment` / `is_unsafe_document_key` use byte-identical regexes; append-only timestamp filtering (`bisect_right` vs manual binary search) and backfill are equivalent.

A sweep probed Unicode/encoding edges across header parsing, the SSRF guard, and path-segment validation. It surfaced two genuine cross-language divergences and one latent finding, **all now fixed (both servers converged); the pins flipped from `xfail`/`it.fails` to passing parity tests:**

- **Fixed (cross-language SSRF, bidirectional): the public `validateUrlNotPrivate` / `validate_url_not_private` guard gave opposite verdicts on loopback spellings.** The helper is exported for consumers to gate outbound URLs; each implementation had a bypass the other blocked. **TS allowed IPv4-mapped IPv6 loopback** — `new URL("http://[::ffff:127.0.0.1]/")` compresses the host to `::ffff:7f00:1` (hex), which the dotted-quad `::ffff:(\d+\.\d+\.\d+\.\d+)` regex missed → "public". **Python allowed alternate IPv4 notations** — `2130706433` (decimal) / `0x7f000001` (hex) / `0177.0.0.1` (octal) / `127.1` (short) all resolve to 127.0.0.1, but `urlparse` keeps the raw host and `ipaddress.ip_address()` rejects the non-dotted-quad form → fell through to "public". **Fixed:** TS gained a hex IPv4-mapped branch that decodes the embedded IPv4 (`::ffff:7f00:1` → `127.0.0.1`); Python canonicalises the host via `socket.inet_aton` before the `ipaddress` check (genuine domain names still raise → treated as public). Every loopback spelling is now blocked on both, public IPs still allowed. Pinned by new files `test_url_ssrf_guard.py` + `url-ssrf-guard.test.ts` (no SSRF tests existed before).
- **Fixed (cross-language auth): a Unicode-digit `X-Starfish-Ts` authenticated on Python but was rejected by TS.** The shared `-?\d+` rule (pinned earlier) was *not* shared for non-ASCII digits: Python's `\d` + `int()` are Unicode-aware, so a `Ts` header transcoded to Arabic-Indic/Devanagari/Persian digits parsed to the *same* integer — the request's signature still verified and it authenticated — while TS's ASCII-only `\d` rejected it at parse with `invalid X-Starfish-Ts`. The same wire request authenticated differently per server. **Fixed:** the Python `_INTEGER_HEADER_RE` now uses the ASCII class `[0-9]` instead of `\d`, rejecting non-ASCII digits at parse exactly as TS does. Pinned by `test_cap_resolver.py::test_unicode_digit_timestamp_rejected_identically_to_typescript` + a TS reference in `cap-resolver.test.ts`.
- **Fixed (latent validator-level divergence): `validate_path_segment` admitted a trailing newline.** Refines the earlier "byte-identical regexes" note: the regex *source* was identical, but Python's `$` matches *before* a trailing `\n` (and `SAFE_PARAM` was applied with `.match()`), so `validate_path_segment("alice\n")` was `True` where TS's `validatePathSegment` is `false`. End-to-end it was masked by `is_unsafe_document_key` (`[\x00-\x1f]`), so it was **not** a live request-level bypass — but a real validator-level divergence. **Fixed:** the Python `$`-anchored validators now use `re.fullmatch` (not `.match()`), closing the same root cause across all four sites — `SAFE_PARAM` (`validate_path_segment`), `_NS_NAME_RE`, `_CAP_ROLE_RE`, and the filesystem store's `_VALID_KEY`. Pinned by `test_path_traversal.py::test_path_segment_rejects_trailing_newline` + a TS reference in `path-traversal.test.ts`.
- **Cleared (no gap, robust + parity verified):** seal-envelope Argon2id parameter validation is TS↔Python identical and already pinned inline (`test_seal.py` / `seal-dos.test.ts`); the `?limit` round-trip guard (`String(parsed) !== raw`) is identical; batch-collection CSV splitting; the JSON-depth boundary (already pinned at exactly 64 on both); nonce-cache keying (raw base64 string — re-encoding a nonce changes the signed payload, so not a replay vector); and keyring epoch/rollback, `trustedAdders=[]` fail-closed, revocation generation, and `userId` derivation (all already covered in both languages, revocation additionally by cross-language vectors).

Further sweeps probed the pairing/rendezvous protocol, cap-cert scope composition, and the keyring's adversarial-wrap path — among the least-probed surfaces. **All cleared with no new gap; one regression pin added.**

- **Pairing / rendezvous — cleared.** `install_pairing_bundle` fully verifies the bundle (cap-cert signature + window + well-formedness, `kind=="device"`, `iss==rootEdPub`, optional `expected_root_ed_pub` pin, `sub`/`subKem`, optional `qrNonce` session binding); `assemble_pairing_bundle` fails closed without an explicit `granted_scope`; the relay request carries an Ed25519 proof-of-possession binding `devKemPub`↔`devEdPub`. The relay `deriveCodeKey` (PBKDF2-HMAC-SHA256, 600 000 iters, `"starfish-pair"` salt) is **byte-identical** TS↔Python (verified), so code-derived relay encryption interops; relay PoP/roundtrip/wrong-code/KEM-substitution/missing-PoP are tested in both languages; QR/bundle install is cross-language vector-locked. No gap.
- **Cap-cert scope composition — cleared.** Not `path_glob_match` (covered earlier) but the composition: `synthesizeRoles` (the `collections × ops` cross-product → `cap:{op}:{col}`, plus `delegated:{issUserId}:{col}` and the root-device role) and `matchScopePath` (empty→allow, `!`-deny, ≥1 allow AND no deny) are byte-identical; `{identity}` substitution replaces **all** occurrences on both sides — Python `str.replace`, TS `split("{identity}").join(identity)` (deliberately not `String.replace`, which replaces only the first). A multi-`{identity}` path behaves identically. No gap.
- **Keyring adversarial wrap — cleared + pinned.** `recoverCurrentCek` / `_recover_current_cek` enforce identically in both languages: a non-existent-epoch throw, a **duplicate-subKem fail-closed** check (a tampered epoch with two entries for one subKem is rejected, not probed past — closing a forged-CEK substitution), the `trustedAdders` filter, and `addedSig` verification; `requireTrustedAdders` is fail-closed both ways. The trusted-adder/forged-entry cases were already tested; the duplicate-subKem defense was present in both but **untested** — now pinned by `test_recipients.py::test_add_recipient_fails_closed_on_duplicate_subkem_in_epoch` + the TS twin in `recipients.test.ts`.

Across all the sweeps the parsing, auth, crypto, SSRF, pairing, cap-scope, and keyring surfaces are mature with verified cross-language parity; no still-open gaps remain.

### Removed

- **`EncryptedObjectStore`** (server-side encryption wrapper, TS + Python).
- **v2 `group-crypto` module** (`packages/ts/client/src/group-crypto.ts`, `packages/python/client/starfish_sdk/group.py`) and its tests. Replaced by `keyring`.
- **v2 identity helpers** `deriveCredentials` / `generatePassphrase` (TS + Python). Replaced by `bootstrapRootIdentity` / `deriveRootIdentity`.
- **v2 Bearer-token auth path** on `StarfishClient`. The `authProvider` option is removed; use `capProvider` exclusively.
- **`signData` / `signatureVerifier` hooks** on client and server. Per-request Ed25519 signatures via cap-cert replace them.
- **`createEncryptor` factory** (TS + Python) — orphaned now that all delegated collections use `createKeyringEncryptor`.
- **HKDF info constants** `HKDF_INFO_IDENTITY` / `HKDF_INFO_SERVER`.
- **`tests/test-vectors/group-crypto.json`** — superseded by `multi-recipient-wrap.json`.
- **Group role enricher** — `createGroupRoleEnricher` / `create_group_role_enricher` and `GroupRoleEnricherOptions` removed (TS + Python). It was a server-evaluated, list-based RBAC enricher (`groups/{groupId}/members` → `group-member`) plus a candidacy/request-to-join flow — at odds with v3's "authority is a signed capability, the server holds no membership lists" model. Use member capability certificates (`@drakkar.software/starfish-sharing` / `starfish-sharing`) for collaboration; `composeEnrichers` / `compose_enrichers` and the entitlement enricher are unchanged. Bulk membership becomes one member cap per recipient; candidacy/request-to-join is an app-level recipe (a `<col>/_requests` collection + owner-side `mintMemberCap`). For a server-authoritative allow-list, write your own `RoleEnricher`. See [`docs/migration/v2-to-v3.md`](docs/migration/v2-to-v3.md#removed-group-role-enricher).

### Migration from 2.x

Lockstep upgrade across all twelve packages — no mixed-version deployments. High-level path:

1. **Package imports & server plugins** — cap-aware code moved out of `starfish-client` / `starfish-sdk` into three extension packages (hard break, no transitional re-exports). Update imports: `bootstrapRootIdentity` / `deriveRootIdentity` / `mintDeviceCap` / pairing helpers / `listDevices` → `@drakkar.software/starfish-identities` (`starfish-identities` in Py); `mintMemberCap` / `scopes` / `listMembers` → `@drakkar.software/starfish-sharing` (`starfish-sharing`); `createKeyring` / `createKeyringEncryptor` / `addRecipient` / `rotateEpoch` → `@drakkar.software/starfish-keyring` (`starfish-keyring`). On the server, install the per-kind validators: `createCapCertRoleResolver({ nonceCache, revocationStore, plugins: [identitiesServerPlugin, sharingServerPlugin] })` — with strict-kind dispatch (the default) a `device` or `member` cap is rejected 401 unless its plugin is installed.
2. **Identity & userId** — call `bootstrapRootIdentity(passphrase)` once at startup to derive root keypair, persist `DeviceCredentials`. Rewrite storage keys for collections whose path contains `{identity}` following the algorithm in `docs/migration/v2-to-v3.md` (no shipped migration tool — operators run their own offline rewriter).
3. **Encryption-mode collapse** — `"identity"` / `"server"` collections must be decrypted once and re-encrypted under `"delegated"` with the user's new X25519 key as sole recipient. `"group"` collections are renamed to `"delegated"`; existing keyring documents are rewritten into the new shape. See `docs/migration/v2-to-v3.md` for the per-collection algorithm.
4. **Auth header** — the SyncManager wires `Cap` + `X-Starfish-Sig`/`-Ts`/`-Nonce` automatically once `capProvider` is configured. No per-call code change for typical callers.
5. **Server config** — drop the listed `SyncRouterOptions` fields, swap in `roleResolver: createCapCertRoleResolver({nonceCache, revocationStore, plugins: [identitiesServerPlugin, sharingServerPlugin]})`. Drop `clientEncrypted` / `publicKey` from each `CollectionConfig`; rename `encryption: "group"` → `encryption: "delegated"`.
6. **Test vectors** — old `group-crypto.json` removed; six new vector files added.

Full step-by-step migration runbook: [`docs/migration/v2-to-v3.md`](docs/migration/v2-to-v3.md).

## 2.3.0

### Added

#### Server (TypeScript + Python)

- **`StoreContext`** — new type/dataclass (`collection`, `namespace?`, `params`, `identity`, `roles`, `action`) passed as an optional trailing parameter to every `ObjectStore` / `AbstractObjectStore` method (`getString`, `put`, `listKeys`, `delete`, `deleteMany`, `getBytes`, `putBytes`). Route handlers build and forward context so callbacks can inspect the collection name, path parameters, authenticated caller, roles, and operation type for each request. Exported from the top-level package.
- **`CustomObjectStore` backward-compatible context forwarding** — existing 1-arg callbacks continue to work unchanged. In TypeScript, the extra argument is silently ignored. In Python, callback arity is sniffed once at construction via `inspect.signature`; old lambdas and functions are called without context while new callbacks that declare an extra positional argument receive the full `StoreContext`.
- **`EncryptedObjectStore` context pass-through** — the encrypted wrapper forwards the same `StoreContext` object unchanged to its inner store.
- **Namespace routes expose `ctx.namespace`** — routes mounted under a namespace (via `mountNamespace` / `_mount_namespace`) populate the `namespace` field with the namespace name.
- **Bundle/batch handlers construct per-collection context** — each collection in a bundle or batch response gets its own `StoreContext` with the correct `collection` name rather than sharing a single context object.
- **System callers use `undefined`/`None`** — internal subsystems (replica sync, config loader, role enrichers) pass explicit `undefined`/`None` so callbacks can distinguish "no request context" from a public-route context.

## 2.2.0

### Added

#### Client (TypeScript + Python)

- **`SyncManager.abort()`** — cancels any in-flight `pull()` or `push()` immediately. The in-flight coroutine/promise rejects with `AbortError`. Subsequent calls to `push()` or `pull()` on an aborted manager also throw `AbortError` without making a network request.
- **`SyncManager.isAborted` / `SyncManager.is_aborted`** — getter that reflects current abort state.
- **`AbortError`** — new error class exported from `@drakkar.software/starfish-client` (TypeScript) and `starfish_sdk` (Python). Consumers can distinguish abort errors from network/protocol errors with `err instanceof AbortError` / `isinstance(err, AbortError)`.

#### Server (Python)

- **`SyncRouterOptions.audit_logger`** — optional `AuditLogger` instance passed to the sync router. When set, the push handler calls `audit_logger.log(entry)` after every push attempt (both success and 409 conflict), giving operators a record of who pushed what and when.

### Fixed

#### Server (TypeScript)

- **Concurrent-push TOCTOU eliminated** — concurrent pushes to the same document key are now serialised via a per-key Promise chain. Previously, two clients with the same `baseHash` could both pass the hash-check window and the second write would silently overwrite the first. Now the second caller always receives a deterministic 409 conflict response.

#### Server (Python)

- **TTL-expired pull returned a real hash alongside empty data** — a client receiving `{ data: {}, hash: "<real-hash>" }` could use the stale hash as `baseHash` on the next push and accidentally overwrite the (intentionally empty) document. The pull response now returns `hash: ""` when TTL expiry strips data, signalling "no prior write" to the client.
- **Concurrent-push TOCTOU eliminated** — per-document-key `asyncio.Lock` serialises concurrent push handlers so only one writer passes the `baseHash` check at a time; the other receives a deterministic 409.

## 2.0.0

### Breaking

- **`queueOnly` removed** — replaced by the unified `appendOnly` + `persist` model. Migrate: `queueOnly: true` → `appendOnly: { persist: false }` (Python: `queue_only=True` → `append_only=AppendOnlyConfig(persist=False)`). The `/config` response no longer includes `queueOnly`; clients now receive `appendOnly` with optional `persist` and `checkLastItem` fields instead.

### Added

- **Append-only collections** (`appendOnly: {}`, persist defaults `true`) — every push appends `body.data` to a stored array (default field: `"items"`). No conflict detection; `baseHash` ignored. Configurable via `appendField`/`field`.
- **`AppendOnlyConfig` object** — `{ field?, persist?, checkLastItem? }`. Pass `true` as shorthand for `{}`.
- **`checkLastItem` mode** — `appendOnly: { checkLastItem: true }` validates the client's `baseHash` against the stored document hash before appending. Returns `409` on mismatch. Client should pass the `hash` field from the last pull response as `baseHash`.
- **Server-side retry loop** (max 3) for concurrent appenders to absorb storage races. Returns `500 { error: "append_retry_exhausted" }` after exhaustion.
- **Append-only pull via `client.pull`** — `pull(path, { appendField, since?, last? })` (TS) and `pull(path, append_field=, since=, last=)` (Python) return `T[]` / `list` directly. No separate helper needed; `push(path, item, null)` / `push(path, item, None)` handles append pushes.
- **Incremental checkpoint pull** for `appendOnly persist=true` — each item is stored with its own timestamp. `?checkpoint=<ts>` returns only items appended after `ts`, decoupling pull payload size from total array length.
- **`?last=K` pull parameter** for `appendOnly persist=true` — returns only the last K items (applied after `?checkpoint` filter). Useful for "latest N entries" queries without a tracked checkpoint. Exposed as `last?: number` in `AppendPullOptions` (TS: `client.pull(path, { last: K })`) and `last=` kwarg in `client.pull(path, last=K)` (Python).
- New doc: [`docs/ts/server/append-only-collections.md`](docs/ts/server/append-only-collections.md).

### Changed

#### Client (Python)

- **`namespace` send-path now matches sign-path** — `StarfishClient` previously sent HTTP requests to `/sync/{namespace}/v1/...` while signing the canonical over `/v1/{namespace}/...`, requiring a server-side rewrite (nginx or `NamespaceRewriteMiddleware`) to bridge the gap. Both paths now use the same `/v1/{namespace}/...` format, so no rewrite layer is needed and the URL the client hits is identical to the URL the signature covers. Servers that relied on the old `/sync/{namespace}/v1/...` incoming URL must update their routing to expect `/v1/{namespace}/...` instead.

#### Server (TypeScript + Python)

- Author signature verification is skipped for all `appendOnly` collections (stored data is a transformed wrapper; signatures cannot be meaningfully verified).
- **`appendOnly persist=true` stored hash** is now `hash({ n: items.length, last: lastItem })` (was `hash(fullDoc)`). Push CPU dropped from O(N) to O(1). ETag/304 and `checkLastItem` semantics preserved — length-tagging ensures duplicate pushes of identical items still produce distinct hashes.
- **`pushAppend` / `pullAppendList`** (TS) and **`push_append` / `pull_append_list`** (Python) standalone helpers removed — append-only push/pull is now handled directly by `StarfishClient.push` / `StarfishClient.pull` (see Added above).
- **`checkLastItem` race fix** — the stored-hash comparison now happens inside the retry loop, using the same document read that feeds the write. Previously the check ran once before the loop, so a concurrent write that arrived between the pre-loop check and the actual store write would slip through on a retry. Now every attempt re-reads and re-validates; the loser returns `409` deterministically. Also saves one storage read per `checkLastItem` push.
- **Checkpoint filter uses binary search** — `?checkpoint=<ts>` on `appendOnly persist=true` documents now uses `bisect_right` / binary search on the monotonically non-decreasing per-item timestamps array (O(log N)) instead of a linear scan (O(N)).

## 1.19.2

### Fixed

#### Client (TypeScript)

- **`zustand/middleware` now actually bundled** — 1.19.1 listed `zustand` in esbuild's `external`, but esbuild treats a package-name external as covering every subpath under it (so `zustand/middleware` was unintentionally external too, and `devtoolsImpl` + `import.meta.env` survived in the consumer bundle). The build now uses an esbuild plugin (`zustand-selective-external`) that externalizes only `zustand` and `zustand/vanilla` while letting `zustand/middleware` be bundled and tree-shaken. Verified: published `dist/bindings/zustand.js` contains zero `import.meta` / `devtoolsImpl` references.

## 1.19.1

### Fixed

#### Client (TypeScript)

- **`import.meta.env` eliminated from published bundle** — the build now uses esbuild with tree-shaking instead of `tsc --build`. Previously, `tsc` preserved bare `import` statements verbatim, causing consumer bundlers (Metro/Hermes, Expo web) to load the entire `zustand/middleware` ESM file — including `devtoolsImpl`, whose `import.meta.env.MODE` reference throws `Uncaught SyntaxError: Cannot use 'import.meta' outside a module`. esbuild inlines and tree-shakes `zustand/middleware` at publish time, so only the middleware we actually use (`persist`, `subscribeWithSelector`, `createJSONStorage`) appears in the dist. Consumers no longer need any metro-config workaround.

### Internal

- New `build.mjs` (esbuild) emits the 8 published entry points as ESM bundles.
- New `tsconfig.build.json` (`emitDeclarationOnly: true`) generates `.d.ts` files without re-emitting JS.
- Peer deps (`react`, `zustand`, `zustand/vanilla`, `@legendapp/state*`, `immer`) and the `@drakkar.software/starfish-protocol` workspace dep remain external.

## 1.19.0

### Changed

#### Client (TypeScript)

- **`devtools` option signature changed** — previously accepted `boolean | DevtoolsOptions`; now accepts a middleware wrapper function `(storeCreator) => storeCreator`. Import `devtools` from `'zustand/middleware'` yourself and pass it directly. This removes the static `import { devtools } from 'zustand/middleware'` from the library bundle, preventing `import.meta.env` from being included in environments that don't support it (Metro/Hermes, Expo web).

  Migration:
  ```ts
  // Before
  createStarfishStore({ devtools: true })
  createStarfishStore({ devtools: { name: 'my-store' } })

  // After
  import { devtools } from 'zustand/middleware'
  createStarfishStore({ devtools: (fn) => devtools(fn) })
  createStarfishStore({ devtools: (fn) => devtools(fn, { name: 'my-store' }) })
  ```

## 1.18.1

### Added

#### Client (Python)

- **`namespace` parameter on `StarfishClient`** — when the sync server is deployed behind a namespace-aware reverse proxy (e.g. nginx rewriting `/sync/{ns}/v1/push/...` to `/v1/{ns}/push/...` before forwarding), pass `namespace="my-ns"` to `StarfishClient`. The client will prepend `/sync/{namespace}` to the URL it sends while signing the canonical path in its post-rewrite form (`/v1/{namespace}/push/...`), matching what the upstream server validates. Callers still pass plain `/v1/push/...` paths — the namespace transformation is fully internal. Default is `None` (no transformation, backward-compatible).

## 1.18.0

### Added

#### Server (TypeScript + Python)

- **Group candidacy** — `createGroupRoleEnricher` / `create_group_role_enricher` now optionally supports an application/candidacy flow. Set `candidacyPath` (TS) / `candidacy_path` (Python) to a `storagePath` template (e.g. `"groups/{groupId}/candidacies/{identity}"`) to enable the feature globally. Enable it per-group by adding `candidacyEnabled: true` to the members document. Users apply by pushing `{ status: "pending", message: "..." }` to their own candidacy document (gated by the built-in `"self"` role); pending applicants receive a configurable `candidacyRole` (default `"group-candidate"`). Admins accept/deny by pushing `{ status: "accepted" }` / `{ status: "denied" }` and manually adding accepted users to the members list. Candidacy documents are cached separately from membership documents with their own configurable TTL (`candidacyCacheTtlMs` / `candidacy_cache_ttl_ms`). Disabling: remove `candidacyPath` globally, or set `candidacyEnabled: false` in a specific group's members document.

## 1.17.1

### Fixed

#### Server (TypeScript)

- **TTL expiry was completely non-functional**: the pull route compared `Date.now()` against itself (always ~0 ms), so documents never expired. Fixed to read the stored timestamp tree via `maxLeafTimestamp` — a new exported helper in `timestamps.ts` — and compare the actual write time against the current time.
- **Replica manager corrupt document recovery**: `JSON.parse` on a corrupt local document in `_doSync` now logs the error and treats the document as empty instead of throwing into the `_syncSafe` catch loop, allowing primary data to overwrite the corrupt record on the next sync.
- **Proxy push error leaks internal host/port details**: `Failed to reach primary: ${e}` replaced with a generic `"Failed to reach primary"` message; full error is now logged server-side only.
- **Config endpoint role-resolver exception now logged** before silently returning empty collections.
- **Polling errors no longer silently discarded**: `.catch(() => {})` replaced with `.catch((err) => console.error(...))` in both `startPolling` and `startAdaptivePolling`.
- **Mobile lifecycle flush/pull errors no longer silently discarded**: same fix in `createMobileLifecycle` background flush and foreground pull paths.

#### Server (Python)

- **Field-level read permission stripping was wrapped in `except Exception: pass`**, silently leaking privileged fields on any error. Removed the try/except — field stripping is pure dict manipulation and must not fail silently.
- **`"public"` role not honored in Python field-level read permissions**: authenticated users had public fields stripped (they saw less than anonymous callers). Fixed to check `r == ROLE_PUBLIC` alongside `r in effective_roles`, matching TypeScript behaviour.
- **TTL check read from base store instead of encrypted store**: for identity/server-encrypted collections the TTL timestamp extraction always failed silently. Fixed to use the resolved (decrypted) `store` variable.
- **Bare `except: pass` on TTL check**: any storage/parse error silently skipped the expiry check, serving expired documents. Removed the try/except.
- **Push crashes on corrupt stored document**: `json.loads(raw)` raised an unhandled exception that made the push endpoint permanently return 500 for that key. Wrapped in try/except with logging; corrupt records are treated as empty (recoverable via `baseHash=""`).
- **Pull crashes on corrupt stored document**: same fix — returns `{data: {}, hash: ""}` with an error log instead of raising.
- **`role_enricher` call not wrapped in try/except**: an exception from a user-supplied enricher propagated as an unhandled 500 with a raw traceback. Now caught, logged, and returned as a structured `{"error": "Authorization error"}` 500.
- **`_check_auth` swallowed role-resolver exceptions with no logging**: operators could not distinguish misconfiguration from legitimate auth failures. Exception is now logged at error level before returning 401.
- **Proxy push leaks internal host/port**: same fix as TypeScript.
- **Config endpoint role-resolver exception now logged** at error level before returning empty collections.
- **Fire-and-forget replica sync task lost exceptions**: `asyncio.create_task(replica_manager.sync_now(...))` had no done callback. Added one that logs any exception at error level.
- **Replica manager corrupt document recovery**: `json.loads` on a corrupt local document in `_do_sync` now logs and treats the document as empty, matching TypeScript behaviour.
- **Enricher `except` blocks silenced errors**: `group_role_enricher` and `entitlement_role_enricher` caught `JSONDecodeError`/`AttributeError` with no logging. Now logs at error level with the storage key and error message.

#### Documentation

- **`audit.md`**: fixed `audit:` → `auditLogger:` option name in all TypeScript examples (the old name was silently ignored at runtime). Added note that Python audit logging is not yet implemented.
- **`config-endpoint.md`**: added missing `"group"` encryption mode to the `EncryptionMode` value list.
- **`03-sync-manager.md`**: documented four previously undocumented `SyncManagerOptions` fields: `encryptor`, `logger`, `loggerName`, `validate`.
- **`docs/python/server/storage.md`**: fixed `CustomObjectStore` constructor argument names (`get` → `on_get`, `put` → `on_put`, `list` → `on_list`, `delete` → `on_delete`; removed non-existent `delete_many`). The old names raised `TypeError` at construction time.

## 1.17.0

### Added

#### Server (TypeScript + Python)

- **`createEntitlementRoleEnricher` / `create_entitlement_role_enricher`** — new built-in `RoleEnricher` factory that grants roles based on a per-user entitlement document stored in the ObjectStore. Reads a standard Starfish document at a configurable `path` template (default `"users/{identity}/entitlements"`), extracts a list of feature slugs from the configured `field` (default `"features"`), and returns roles of the form `"${rolePrefix}:${slug}"` (default prefix `"entitlement"`). Collections gate access using these roles in `readRoles`/`writeRoles`. Ships with an in-memory per-user cache (default TTL 1 min, set `cacheTtlMs: 0` / `cache_ttl_ms=0` to disable). TypeScript: `import { createEntitlementRoleEnricher } from "@drakkar.software/starfish-server"`. Python: `from starfish_server import create_entitlement_role_enricher, EntitlementRoleEnricherOptions`.

- **`composeEnrichers` / `compose_enrichers`** — utility that merges multiple `RoleEnricher` functions into one. Runs all enrichers in parallel and returns a flat union of their role arrays. Needed when `SyncRouterOptions.roleEnricher` must combine several enrichers (e.g. group membership + entitlement). TypeScript: `composeEnrichers(groupEnricher, entitlementEnricher)`. Python: `compose_enrichers(group_enricher, entitlement_enricher)`.

#### Client (TypeScript + Python)

- **`pullEntitlements` / `pull_entitlements`** — standalone helper that fetches the list of feature slugs from a user's entitlement document. Returns `[]` on 404 (document not yet created); re-throws all other errors so billing-critical failures are never silently swallowed. TypeScript: `import { pullEntitlements } from "@drakkar.software/starfish-client"`. Python: `from starfish_sdk import pull_entitlements`.

- **`pull_blob` / `push_blob`** (Python `starfish-sdk`) — binary document methods for the Python client, reaching parity with the TypeScript SDK. Returns `BlobPullResult` / `BlobPushResult`. Exported from `starfish_sdk`.

#### Documentation

- New guide: [`docs/ts/server/entitlements.md`](docs/ts/server/entitlements.md) — entitlement system setup, `createEntitlementRoleEnricher` options, admin grant/revoke patterns with hash-based conflict safety, client-side feature discovery, self-write override.
- New guide: [`docs/ts/client/22-binary-collections.md`](docs/ts/client/22-binary-collections.md) — server config, `allowedMimeTypes` patterns, client API, conflict model, caching, and feature constraints table.
- New guide: [`docs/ts/server/audit.md`](docs/ts/server/audit.md) — `AuditLogger` setup, `AuditEntry` fields, three built-in loggers, custom callback logger pattern (TypeScript + Python).
- New guide: [`docs/python/server/storage.md`](docs/python/server/storage.md) — Python storage backends: Filesystem, S3/MinIO/R2, Memory, custom store.
- Updated [`docs/ts/server/group-access.md`](docs/ts/server/group-access.md) — added owner-managed whitelist pattern (operator-controlled per-collection member lists without full group encryption).
- Updated [`docs/ts/client/19-collection-patterns.md`](docs/ts/client/19-collection-patterns.md) — Pattern 8: owner-managed whitelist.
- Updated [`docs/ts/client/11-identity-key-derivation.md`](docs/ts/client/11-identity-key-derivation.md) — invite links section (`buildInviteUrl` / `parseInviteUrl`).
- Updated [`docs/ts/client/09-integration-patterns.md`](docs/ts/client/09-integration-patterns.md) — corrected `pruneTombstones` usage to use the exported utility.

## 1.16.0

### Added

#### Client (TypeScript + Python)

- **Group encryption** — new `"group"` encryption mode for multi-user encrypted collections. Each member holds their own X25519 key pair (derived deterministically from their passphrase via SHA-256); a shared Group Encryption Key (GEK) is distributed per-member using ECDH key wrapping. Wire format: `{ _encrypted: "base64(IV || ciphertext)", _epoch: N }`. Epoch rotation revokes a removed member's access to new documents without affecting past documents.

  TypeScript API (`@drakkar.software/starfish-client/group`):
  - `deriveGroupKeyPair(passphrase, userId)` — deterministic X25519 key pair
  - `generateGroupKey()` — random 256-bit GEK as hex string
  - `wrapGroupKey(gek, memberPublicKey, wrapperPrivateKey)` — ECDH wrap
  - `unwrapGroupKey(wrapped, memberPrivateKey, adminPublicKey)` — ECDH unwrap
  - `createGroupKeyring(adminKeyPair, members, gek?)` — epoch-1 keyring
  - `addGroupMember(keyring, adminKeyPair, currentGek, newMemberId, newMemberPublicKey)` — add to current epoch
  - `rotateGroupKey(keyring, adminKeyPair, remainingMembers, newGek?)` — new epoch
  - `createGroupEncryptor(keyring, myIdentity, myPrivateKey)` — returns `Encryptor` for use with `SyncManager`

  Python API (`starfish_sdk.group`): identical snake_case API.

- **`deriveCredentials` now includes `groupPublicKey` and `groupPrivateKey`** — the ECDH key pair is derived automatically alongside auth and encryption credentials (TypeScript). Call `derive_group_key_pair(passphrase, user_id)` separately in Python.

- **`SyncManager` accepts `encryptor` option** — pass any `Encryptor` (including a `GroupEncryptor`) directly instead of `encryptionSecret`/`encryptionSalt`. TypeScript: `encryptor` option on `SyncManagerOptions`. Python: `encryptor` parameter on `SyncManager.__init__`.

#### Server (TypeScript + Python)

- **`encryption: "group"` collection flag** — new encryption mode identical to `"delegated"` on the server (full fetch, opaque blobs, no server-side crypto). Validation rejects `"group"` on public collections, binary collections, and remote (pull-only) collections.

#### Test vectors

- **`tests/test-vectors/group-crypto.json`** — cross-language compatibility vectors: fixed X25519 key pairs (derived from known passphrases), pre-generated wrapped keys. Both the TypeScript and Python test suites verify key pair derivation and GEK unwrapping against these vectors, proving ECDH+HKDF+AES-GCM compatibility across implementations.

#### Documentation

- New guide: `docs/ts/client/21-group-encryption.md` — full group encryption reference (key derivation, keyring lifecycle, epoch rotation, API reference, security considerations).
- Updated: `docs/ts/client/04-encryption.md` — added group encryption overview and link.
- Updated: `docs/ts/client/19-collection-patterns.md` — Pattern 7: encrypted group chat (E2E, per-member keys).
- Updated: `docs/ts/server/group-access.md` — encrypted group chat section with server config and comparison table.

## 1.15.0

### Added

#### Server (TypeScript + Python)

- **`listable` collection flag** — new boolean field on `CollectionConfig` (`listable` in both TS/JSON and Python). When `true`, the server registers a `GET /list/...` endpoint for the collection. The list route derives from `storagePath` by dropping the last path parameter, and returns the existing values of that parameter as `{ items: string[], hasMore: boolean }`. Supports cursor-based pagination via `?limit=N` (default 100, max 1000) and `?after=<item>`. Auth uses the collection's `readRoles`. Incompatible with `queueOnly`, `bundle`, and collections whose last path segment is not a `{param}`.

- **`createGroupRoleEnricher` / `create_group_role_enricher`** — new built-in `RoleEnricher` factory that grants a role to users who appear in a group membership document stored in the ObjectStore. Reads a standard Starfish document at a configurable `membersPath` template, checks the caller's identity against `data.members` (field name configurable), and returns the configured role (default `"group-member"`) if they are a member. Ships with an in-memory cache (default TTL 1 min, set `cacheTtlMs: 0` to disable). TypeScript: `import { createGroupRoleEnricher } from "@drakkar.software/starfish-server"`. Python: `from starfish_server import create_group_role_enricher, GroupRoleEnricherOptions`.

#### Documentation

- New guide: `docs/ts/server/list-endpoint.md` — list endpoint configuration, route patterns, pagination, and auth behaviour.
- New guide: `docs/ts/server/group-access.md` — group-based access control with `createGroupRoleEnricher`, including a full chat collection pattern.
- New pattern in `docs/ts/client/19-collection-patterns.md` — showing per-day partitioning, group-member access, list discovery, and queue integration.

## 1.14.0

### Added

#### Server (TypeScript + Python)

- **`GET /config` endpoint** — opt-in endpoint that returns a per-collection client manifest. Enable via `configEndpoint: { auth: "public" | "role-filtered" }` in `SyncRouterOptions` (TypeScript: `configEndpoint`, Python: `config_endpoint`). Response includes collection name, `maxBodyBytes`, `encryption`, `allowedMimeTypes`, and optional capability flags (`pullOnly`, `pushOnly`, `queueOnly`, `clientEncrypted`, `ttlMs`, `forceFullFetch`). Omitted when not configured. `"role-filtered"` mode runs the `roleResolver` and returns only collections whose `readRoles` or `writeRoles` intersect the caller's roles; resolver errors silently return empty collections. New types exported: `ConfigEndpointOptions`, `CollectionClientInfo`, `ConfigResponse`.
- **`publicKey` field on `CollectionConfig`** — optional base64-encoded string exposed through `GET /config`. Clients use it to encrypt data before pushing without a pre-shared secret. Stored verbatim; encryption protocol is application-defined.

#### Client (TypeScript + Python)

- **`fetchServerConfig(baseUrl, options?)`** (TypeScript: `@drakkar.software/starfish-client`) — fetches `GET {baseUrl}/config` and returns a typed `ConfigResponse`. Accepts optional `headers` for auth. Throws on non-2xx.
- **`fetch_server_config(base_url, headers?)`** (Python: `starfish-sdk`) — async equivalent. Raises `httpx.HTTPStatusError` on non-2xx. New types exported: `ConfigResponse`, `CollectionClientInfo`, `NamespaceClientConfig`.

## 1.13.0

### Added

#### Server (TypeScript + Python)

- **`queueOnly` collection flag** — new boolean field on `CollectionConfig` (`queueOnly` in TypeScript/JSON, `queue_only` in Python). When `true`, pushes compute and return a hash but skip all storage reads and writes. `baseHash` from the client is ignored — there is no conflict detection. Pull endpoints return empty data. Use for event-only or ephemeral collections where only the queue consumer matters. Cannot be combined with binary collections (config validation error).

## 1.12.0

### Added

#### Server (TypeScript + Python)

- **`QueueConfig.includeBody`** — new opt-in flag on `QueueConfig`. When `includeBody: true` (TypeScript) / `include_body=True` (Python), the queue message includes a `body` field containing the full document data as written to storage. Useful for consumers that need document content without a follow-up pull (e.g. search indexers, audit logs). Only applies to JSON collections — binary push events never include body. `body` is absent when the flag is unset (default).
- **`QueueMessage` type** — exported interface/TypedDict that describes the exact wire shape of queue messages (`collection`, `hash`, `timestamp`, optional `params`, optional `body`). TypeScript: `import type { QueueMessage } from "@drakkar.software/starfish-server"`. Python: `from starfish_server import QueueMessage`.

## 1.11.0

### Added

#### Server (TypeScript)

- **S3ObjectStore** — new `./s3` subpath export (`@drakkar.software/starfish-server/s3`) provides an `S3ObjectStore` class that stores documents in any S3-compatible object store (AWS S3, MinIO, Cloudflare R2, Tigris, etc.). Requires `@aws-sdk/client-s3 >= 3` as an optional peer dependency. Supports `getString`, `put`, `getBytes`, `putBytes`, `listKeys`, `delete`, `deleteMany`, and a `destroy()` method to release HTTP connections. Mirrors the Python `S3ObjectStore` / `aiobotocore` implementation. See `docs/ts/server/storage.md` for configuration examples.

## 1.10.0

### Added

#### Infrastructure

- **Ansible role** — `infra/ansible/roles/starfish` deploys a Starfish sync server on any Debian/Ubuntu or RedHat/CentOS host. Supports both `python` (FastAPI + uvicorn) and `typescript` (Hono + Node.js) variants via a single `starfish_variant` variable. Installs the runtime, creates a dedicated system user, deploys a templated server and `config.json` (from Ansible vars), and registers a systemd service with basic hardening. Includes an example playbook (`playbooks/deploy.yml`) and inventory template (`inventory/hosts.example`).

## 1.9.0

### Added

#### Server (TypeScript)

- **Version bump to 1.6.0** — reflects the namespace feature added in 1.8.0 (package version was not bumped at that time).

#### Server (Python)

- **Version bump to 1.4.0** — brings the Python server to feature parity with TypeScript 1.6.0.
- **Collection namespaces** — Optional `namespaces` field on `SyncConfig` mirrors the TypeScript feature: collections grouped under `/{namespace}/pull/...` and `/{namespace}/push/...`, each with its own `/{namespace}/batch/pull` endpoint. `NamespaceConfig` type exported from the package. Namespace names must match `[a-zA-Z0-9_-]+` and cannot use reserved names (`pull`, `push`, `health`, `batch`).
- **TTL enforcement in router** — `ttlMs` field added to `CollectionConfig` (Python snake_case alias: `ttl_ms`). Expired documents return empty data on pull. The utility `is_expired()` was already exported; it is now wired into the pull and batch-pull handlers.
- **Field-level permissions** — `fieldPermissions` field added to `CollectionConfig` (alias: `field_permissions`). New `FieldPermission` model with `readRoles`/`writeRoles`. Restricted fields are stripped from pull responses and rejected on push. `FieldPermission` exported from the package.
- **Batch pull endpoint** — `GET /batch/pull?collections=col1,col2` endpoint added at root and per-namespace, matching the TypeScript API.

## 1.8.0

### Added

#### Server (TypeScript)

- **Queue documentation** — Added `docs/ts/server/queue.md` covering `QueueConfig` fields (`topic`, `includeParams`), the `Queue` interface, `MemoryQueue` / `CustomQueue` built-in implementations, server wiring, custom backend guide, and Python equivalents. Updated README queue section with TypeScript examples alongside the existing Python ones.

#### Server (TypeScript)

- **Collection namespaces** — Optional `namespaces` field on `SyncConfig` groups collections under a URL prefix: `/{namespace}/pull/...` and `/{namespace}/push/...`. Each namespace has its own `/{namespace}/batch/pull` endpoint that only searches within that namespace. Root-level collections (under `collections`) are unaffected and continue to work at `/pull/...` and `/push/...`. Collection names must be unique within each scope (root or a given namespace), but the same name may appear in different namespaces — enabling multi-tenant configs where every tenant has a `"settings"` collection. Namespace names must match `[a-zA-Z0-9_-]+` and cannot use reserved names (`pull`, `push`, `health`, `batch`). New `NamespaceConfig` type exported from the package. See `docs/ts/client/20-namespaces.md` for the full guide.

## 1.7.0

### Added

#### Client (TypeScript)

- **`createDebouncedPush(syncManager, options)`** — Store-less debounced push for one-way publishing workflows (public pages, derived snapshots). Calls `syncManager.push(doc)` directly without requiring a Zustand store. Options: `serialize` (required), `delayMs`, `warnBytes`, `maxBytes`, `onSizeWarning`, `onSizeExceeded`, `onError`. Includes the same encrypted payload size guard as `createDebouncedSync`. `onError` defaults to `console.warn` on push failure.
- **`createMobileLifecycle(store, deps, options?)`** — Wires React Native `AppState` and `NetInfo` events to a Starfish store. Uses dependency injection (pass `AppState` from `react-native` and optionally `NetInfo` from `@react-native-community/netinfo`) so no React Native imports are needed in this package. Background → flush dirty data; foreground → pull remote changes (only if online + not syncing); NetInfo → `setOnline()`. Returns a cleanup function. Options: `pullOnForeground` (default `true`), `flushOnBackground` (default `true`).

## 1.6.0

### Added

#### Client (TypeScript)

- **Passphrase identity kit** (`./identity` subpath) — Serverless/passwordless auth from a single secret. `generatePassphrase(wordCount?, wordlist?)` produces a crypto-secure BIP-39-style passphrase (default 12 words, 96 bits of entropy). `deriveCredentials(passphrase)` deterministically derives `{ authToken, userId, encryptionSecret, encryptionSalt }` — plug directly into `StarfishClient` auth header and `SyncManager` encryption options. `buildInviteUrl(baseUrl, payload)` / `parseInviteUrl(url)` encode/decode arbitrary invite payloads as URL-safe base64 tokens.
- **`onRemoteUpdate` callback on `createStarfishStore`** — Fires only when remote data arrives via `pull()`, never on local `set()`. Eliminates the manual `isRestoring` guard pattern that prevented subscribe-triggered re-push loops. Pass `onRemoteUpdate: (data) => restore(data)` instead of wiring a store subscription that checks `!state.dirty`.
- **`subscribeSyncStatus(store, callback)`** — Framework-agnostic (non-React) subscription to derived sync status changes. Fires immediately with current status, then on every transition. Deduplicates consecutive equal values. Returns an unsubscribe function. Complements the existing `useSyncStatus` React hook for non-React environments.
- **`createDebouncedSync(store, options?)`** — Debounces push calls triggered by rapid user edits. Returns `{ notify, cancel }`. Default 2000ms delay; resets on each `notify()`. Pre-push size guard: estimates encrypted payload size (JSON byte count × 1.34 for base64 overhead), calls `onSizeWarning(bytes)` above `warnBytes` (default 900KB) and blocks the push with `onSizeExceeded(bytes)` above `maxBytes` (default 1MB). Falls back to `console.warn`/`console.error` when no callback is provided.
- **`createMultiStoreSync(options)`** — Serializes multiple domain Zustand stores into a single versioned Starfish document and restores them back. Options: `slices` (map of store slice keys to `{ getState, restore }` helpers), `version` (current schema version), `migrations` (map of `fromVersion` → migration function). Migrations run sequentially on restore when the document version is behind. Useful for apps that sync more than one logical domain (guests, vendors, planning…) in one Starfish collection.
- **Collection pattern guide** (`docs/ts/client/19-collection-patterns.md`) — Five ready-to-use server + client configuration recipes: Private Vault (self r/w + E2E encryption), Public Page (public r, owner w), Public Roster (per-record tokens), Submission Inbox (owner r, public w, TTL), and Claim Tracker. Includes a section on combining patterns, idempotent anonymous submissions with `update()`, conflict retry, and error handling.

## 1.5.0

### Added

#### Server (TypeScript + Python)

- **CORS middleware** — Configurable CORS with origin whitelist, credentials, methods, headers, and max-age. Pass `cors: true` (permissive) or `cors: { origin: "https://app.example.com", credentials: true }` to `SyncRouterOptions`. Rejects `credentials: true` with wildcard origin at startup (CORS spec violation). Python: `configure_middleware(app, cors=CorsConfig(...))`.
- **Security headers** — Adds `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, `X-XSS-Protection`, and `Referrer-Policy` to all responses. Pass `securityHeaders: true` or customize per-header. Python: `SecurityHeadersMiddleware`.
- **Response compression** — GZip middleware for Python via `configure_middleware(app, compression=True)`.
- **ETag / conditional requests** — Pull responses include an `ETag` header with the document hash. Clients sending `If-None-Match` receive `304 Not Modified` when the hash matches, avoiding redundant data transfer. Works for both JSON and binary collections.
- **Request timeout** — Per-request timeout middleware (returns `408` on expiry). Pass `requestTimeoutMs` to `SyncRouterOptions`. Python: `RequestTimeoutMiddleware`.
- **Graceful shutdown** — `createGracefulShutdown({ replicaManager, queue, onShutdown })` registers SIGTERM/SIGINT handlers and cleanly stops replicas, queues, and custom resources. Python: `GracefulShutdown` class with `register()`/`unregister()`.
- **Structured server logging** — `ServerLogger` interface with `createConsoleLogger()`, `createJsonLogger()`, and `createNoopLogger()`. Pass `logger` to `SyncRouterOptions`. Python: `ConsoleLogger`, `JsonLogger`, `NoopLogger`.
- **Audit logging** — `AuditLogger` interface records who pulled/pushed which collection, when, and whether it succeeded. Pass `auditLogger` to `SyncRouterOptions`. Built-in: `createConsoleAuditLogger()`, `createCallbackAuditLogger(cb)`. Python: async-compatible `ConsoleAuditLogger`, `CallbackAuditLogger` (accepts sync or async callbacks).
- **Field-level permissions** — Optional `fieldPermissions` on collections: per-field `readRoles` (strip fields on pull) and `writeRoles` (reject push if user modifies restricted fields). Example: `fieldPermissions: { email: { readRoles: ["admin"], writeRoles: ["admin"] } }`.
- **Batch pull endpoint** — `GET /batch/pull?collections=col1,col2` pulls multiple collections in one request. Enforces per-collection auth; unauthorized collections return `{ error: "Forbidden" }`.
- **TTL / document expiration** — Optional `ttlMs` on collections. Expired documents return empty data on pull. TTL is check-on-read only (no background cleanup). `isExpired(timestamp, ttlMs)` utility exported.
- **OpenAPI spec generation** — `generateOpenApiSpec(config, { title, version, serverUrl })` produces an OpenAPI 3.0.3 spec from `SyncConfig`. Python: `generate_openapi_spec()`.
- **Docker support** — Dockerfiles for both TS and Python servers, `docker-compose.yml` for local development, and `.dockerignore`.

#### Client (TypeScript)

- **Request deduplication** — `createDedupFetch(baseFetch?)` wraps fetch to deduplicate concurrent identical GET requests. Multiple callers awaiting the same URL share one network request.
- **IndexedDB storage adapter** — `createIndexedDBStorage({ dbName, storeName })` implements Zustand's `StateStorage` interface backed by IndexedDB for data larger than localStorage's 5-10MB limit. Retries on DB open failure.
- **Extended performance metrics** — `SyncMetrics` interface adds `bytesTransferred`, `compressedSize`, `conflictCount`, `retryCount`, `cacheHit` to `pullSuccess`/`pushSuccess` logger calls (backward compatible). `createMetricsCollector()` accumulates per-store totals/averages with `getSummary()` and `reset()`.
- **Conflict field indicators** — `withConflictMeta(resolver)` wraps any `ConflictResolver` to return `ConflictMeta` alongside merged data: `{ conflictedFields: string[], resolvedBy: "local" | "remote" | "merged", timestamp }`. Uses structural comparison (not JSON.stringify).
- **Background Sync API** — `registerBackgroundSync({ tag })` registers a sync tag with the service worker. `isBackgroundSyncSupported()` checks browser support. Note: actual sync event handling must be implemented in your service worker.
- **React Suspense integration** — `createSuspenseResource(fetcher)` creates a resource that throws a Promise while loading (Suspense protocol). After resolution, `read()` returns data synchronously.
- **Data export/import** — `exportData(data, { format, pretty })` and `importData(raw, format)` for JSON and CSV. `exportToBlob(data, opts)` creates a downloadable Blob.
- **Service Worker utilities** — `registerServiceWorker(scriptUrl, { scope, onUpdate })`, `unregisterServiceWorkers()`, and `isServiceWorkerSupported()`.

### Fixed

- **Rate limiter unbounded memory** — `RateLimiter` now caps bucket count at `maxBuckets` (default 10,000), evicting oldest entries when full. Prevents memory exhaustion via `X-Forwarded-For` header spoofing.

## 1.4.1

### Added

- **Snapshot history** — `SnapshotHistory` class for maintaining labeled snapshots of document state with optional `localStorage` persistence. Methods: `take(label, data)`, `restore(index)`, `list()`, `clear()`. Configurable `maxSnapshots` (default 20).
- **Polling utilities** — `startPolling(pullFn, getState, intervalMs?)` for periodic sync with cleanup. `startAdaptivePolling(pullFn, getState, options?)` adapts interval to `navigator.connection.effectiveType` with `pause`/`resume`/`stop` controls. Framework-agnostic via `PollableState` interface.
- **React hooks** (in `./zustand` subpath) — `useCrossTabSync(store, name)` wraps `setupCrossTabSync` with React lifecycle. `useConnectivity(store)` binds browser online/offline events to `setOnline`. `useLastSynced(store)` returns a human-readable label ("Just now", "15s ago", "2m ago") that auto-updates.
- **`aggregateSyncStatus(statuses)`** — Pure function to combine multiple `SyncStatus` values into a worst-case aggregate (error > syncing > pending > offline > synced).

### Fixed

- **`pruneTombstones` silently dropped string timestamps** — Now handles both numeric epoch and ISO-8601 string `_deletedAt` values, consistent with the rest of the resolvers module.
- **`createSoftDeleteResolver` rejected string `_deletedAt`** — Now accepts both numeric and string timestamps for tombstone detection.
- **`SyncManager.pull()` returned delta on incremental pulls** — Now returns the full merged document in `result.data`, not just the server's delta.
- **Conflict resolution state corruption** — `lastHash`/`lastCheckpoint` are now updated after successful decryption, preventing inconsistent state if decryption fails during conflict retry.
- **`classifyError` did not handle `status: 0`** — Now classifies as `"network"`. Also validates that `status` is a number before comparing.
- **`BlobPullResult.hash` was empty string for missing ETag** — Now `string | null` to make the absence explicit.
- **Empty `Retry-After` header caused tight retry loop** — `Retry-After: ""` now falls back to exponential backoff instead of 0ms delay.
- **Circuit breaker stuck in half-open on 4xx** — Non-5xx responses now record success (server is reachable), preventing the breaker from staying in half-open permanently.
- **Compression fallback on stream errors** — `createCompressedFetch` now catches compression errors and falls back to uncompressed request.
- **Unhandled promise rejections** — Fire-and-forget `flush()` calls in Zustand and Legend `set()`/`setOnline()` actions, and `pullFn()` in polling utilities, now have `.catch()` handlers.
- **Unsafe error casts** — All `(err as Error).message` patterns replaced with `err instanceof Error ? err.message : String(err)` across Zustand, Legend, and SyncManager.
- **Migration errors lacked context** — Migration function failures now include the version step that failed (e.g., "Migration from version 2 to 3 failed: ...").
- **`SnapshotHistory` corrupted data handling** — Constructor validates parsed localStorage is an array. `restore()` catches JSON parse errors and returns `undefined`.
- **Broadcast storage fallback payload validation** — `setupStorageFallback` now validates the shape of parsed JSON before applying it to the store.

## 1.4.0

### Added

- **Structured logging** — `SyncLogger` interface with `consoleSyncLogger` and `noopSyncLogger` implementations. Integrated into `SyncManager` via optional `logger` and `loggerName` options. Emits `pullStart`, `pullSuccess`, `pullError`, `pushStart`, `pushSuccess`, `pushError`, and `conflict` events with timing data.
- **Retry / Circuit Breaker** (`./fetch` subpath) — `createRetryFetch` with exponential backoff and `Retry-After` header support (both seconds and HTTP-date formats). `CircuitBreaker` class with CLOSED/OPEN/HALF-OPEN state machine (failure during half-open immediately re-opens). `createResilientFetch` combines both. `createCompressedFetch` for gzip request body compression via `CompressionStream`.
- **Error classification** — `classifyError(err)` categorizes errors into `network`, `auth`, `conflict`, `rate-limited`, `server`, `client`, or `unknown`. Exported from main entrypoint.
- **Schema migration** — `createMigrator(config)` applies versioned migration chains with eager validation at construction and forward-compatibility guard. Uses `_schemaVersion` field convention.
- **Pre-push validation** — `validate` option on `SyncManagerOptions` accepts a `Validator` function. Throws `ValidationError` before any network call. `createSchemaValidator(ajv, schema)` factory for Ajv integration.
- **Binary blob sync** — `StarfishClient.pullBlob(path)` and `pushBlob(path, data, contentType)` for binary collections. Returns `BlobPullResult` (ArrayBuffer + hash from ETag + contentType) and `BlobPushResult` (hash). Last-write-wins (no conflict detection).
- **Conflict resolvers** — `createUnionMerge()` for ID-based array union with per-item `updatedAt` comparison (handles both numeric and ISO-8601 timestamps). `createSoftDeleteResolver()` extends union merge with tombstone awareness. `timestampWinner()` for document-level winner-take-all. `pruneTombstones()` utility removes expired soft-deleted items with configurable TTL.
- **Cross-tab sync** (`./broadcast` subpath) — Framework-agnostic `BroadcastableStore` interface. `setupBroadcastSync` (BroadcastChannel), `setupStorageFallback` (localStorage events), and `setupCrossTabSync` (auto-detect). Works with both Zustand and Legend State stores.
- **React hooks** (in `./zustand` subpath) — `useStarfish(store)`, `useStarfishData(store, selector?)`, `useSyncStatus(store)`, and `deriveSyncStatus(state)`. `useSyncInit(config | null)` manages the full sync lifecycle (create client/manager/store, pull on mount, `onData` callback for domain restoration, teardown on unmount/config change).
- **`restore()` method** on `StarfishStore` — Updates store data without marking dirty or triggering flush. Prevents pull-to-push feedback loops.
- **Testing utilities** (`./testing` subpath) — `createMockClient(overrides?)` with call tracking (`pullCalls`, `pushCalls`). `createMockFetch(pullResponse?, pushResponse?)` and `createConflictFetch(conflictPullResponse, successPushResponse?)` for integration tests.
- **Snapshot history** — `SnapshotHistory` class for maintaining labeled snapshots of document state with optional `localStorage` persistence. Methods: `take(label, data)`, `restore(index)`, `list()`, `clear()`. Configurable `maxSnapshots` (default 20).
- **Polling utilities** — `startPolling(pullFn, getState, intervalMs?)` for periodic sync with cleanup. `startAdaptivePolling(pullFn, getState, options?)` adapts interval to `navigator.connection.effectiveType` with `pause`/`resume`/`stop` controls. Framework-agnostic via `PollableState` interface.
- **React hooks** (in `./zustand` subpath) — `useCrossTabSync(store, name)` wraps `setupCrossTabSync` with React lifecycle. `useConnectivity(store)` binds browser online/offline events to `setOnline`. `useLastSynced(store)` returns a human-readable label ("Just now", "15s ago", "2m ago") that auto-updates.
- **`aggregateSyncStatus(statuses)`** — Pure function to combine multiple `SyncStatus` values into a worst-case aggregate (error > syncing > pending > offline > synced).

### Changed

- **`SyncManagerOptions.name` renamed to `loggerName`** — Avoids ambiguity with the store `name` field.
- **`./react` subpath removed** — React hooks moved into `./zustand` subpath (they are zustand-specific).
- **Version bump** — `@drakkar.software/starfish-client` 1.3.2 → 1.4.0.

### New subpath exports

| Subpath | Contents |
|---------|----------|
| `./fetch` | `createRetryFetch`, `CircuitBreaker`, `createResilientFetch`, `createCompressedFetch` |
| `./broadcast` | `setupBroadcastSync`, `setupStorageFallback`, `setupCrossTabSync`, `BroadcastableStore` |
| `./testing` | `createMockClient`, `createMockFetch`, `createConflictFetch` |

## 1.3.2

Re-release of 1.3.1 (CI publishing fix — no code changes).

## 1.3.1

### Changed

- **TS packages published under `@drakkar.software` scope** — Packages renamed to `@drakkar.software/starfish-protocol`, `@drakkar.software/starfish-client`, `@drakkar.software/starfish-server`.

## 1.3.0

### Added

- **TypeScript server** (`@drakkar.software/starfish-server`) — Full TypeScript port of the Python server, built with [Hono](https://hono.dev/) for Cloudflare Workers / edge runtime compatibility. Replicates all Python server features: config system, pull/push protocol, timestamps, encryption (AES-256-GCM via Web Crypto API), role-based auth, rate limiting, binary collections, bundled collections, queue events, and replica management.
- **Cross-language protocol test vectors** — New shared test vector files (`tests/test-vectors/protocol-push.json`, `protocol-timestamps.json`, `http-errors.json`) consumed by both Python (pytest) and TypeScript (vitest) to guarantee identical protocol behavior across implementations.
- **`setAjv()` for serverless JSON Schema validation** — In environments without `require()` (e.g. Cloudflare Workers), call `setAjv(ajvInstance)` to provide an Ajv instance for `objectSchema` validation.
- **`FilesystemObjectStore` (Node.js)** — Available via `@drakkar.software/starfish-server/node` subpath export. Atomic writes, sidecar metadata for binary content types, recursive directory listing.

### Fixed

- **`workspace:*` not resolved on npm publish** — The CI publish workflow now explicitly sets the `@drakkar.software/starfish-protocol` dependency version from the git tag before publishing client and server packages.

## 1.2.0

### Added

- **Generic queue abstraction** — New `AbstractQueue` interface (ABC) for publishing data-change events after successful pushes, following the same pattern as `AbstractObjectStore`. Built-in implementations: `MemoryQueue` (testing), `CustomQueue` (callback-based), `NatsQueue` (NATS).
- **Per-collection queue config** (`queue`) — Collections can opt in to change events with `"queue": true` (topic defaults to collection name) or `"queue": { "topic": "…", "includeParams": true }` for custom topic and path parameter inclusion.
- **NATS support** — `NatsQueue` with `NatsQueueOptions` for publishing to a NATS server. Install with `pip install starfish-server[nats]`.
- **Binary and bundled push events** — Queue events now fire for binary collection pushes and bundled collection pushes (previously, only JSON pushes triggered notifications).

### Removed

- **Webhook/notify system** — Removed `NotificationPublisher`, `SubscriptionStore`, `Subscription`, `create_replica_router`, and the `POST /replica/subscribe` and `POST /replica/notify` HTTP endpoints. Replaced by the queue abstraction above.
- **`SyncTrigger.WEBHOOK`** — The `"webhook"` sync trigger is removed. Replicas can use `"scheduled"` or `"on_pull"` triggers; for push-triggered replication, subscribe to the queue directly.
- **`RemoteConfig.webhookSecret`** — No longer needed without webhook endpoints.
- **`ReplicaManager.on_notification()`** and **`ReplicaManager._subscribe()`** — Removed along with the `self_base_url` constructor parameter.

### Changed

- **`SyncRouterOptions.notification_publisher`** replaced by **`SyncRouterOptions.queue`** — Pass an `AbstractQueue` instance to enable change-event publishing.
- **TS packages now publish to npm** instead of GitHub Packages. Renamed from `@starfish/protocol` / `@starfish/client` to `@drakkar.software/starfish-protocol` / `@drakkar.software/starfish-client`.

## 1.1.1

### Fixed

- **`SyncManager.push()` signed plaintext instead of encrypted payload** — affects both `starfish-sdk` (Python) and `starfish-client` (TypeScript). When both encryption and signing were active, the signature was computed over `stableStringify(pendingData)` (plaintext) while the server verified against `stableStringify(payload)` (encrypted wrapper), causing every push to be rejected with `HTTP 400 "Invalid author signature"`. Fixed in `starfish_sdk/sync.py:99` and `src/sync.ts:91`. The server required no changes.

## 1.1.0

### Added

- **Per-collection rate limit overrides** — The `rateLimit` field on a collection now accepts an object `{ "windowMs": …, "maxRequests": … }` to override the global defaults. `true` still works for global defaults, `false`/`null` disables.
- **Cache duration** (`cacheDurationMs`) — Optional `Cache-Control: max-age` header on pull responses. Non-public collections use the `private` directive.
- **Object schema validation** (`objectSchema`) — Optional JSON Schema on a collection. When set, push payloads are validated against it before writing; invalid data returns `400`. The `jsonschema` package is now a default dependency of `starfish-server`.
- **Binary collections** (`allowedMimeTypes`) — Collections can declare accepted MIME types with wildcard patterns (e.g. `["image/*"]`). Binary collections accept raw file uploads on push and return raw bytes on pull, with simple overwrite semantics (no conflict detection). Defaults to `["application/json"]` (existing JSON sync protocol).
- **COLLECTION.md** — Full parameter reference for all collection config fields.

### Changed

- **Health endpoint** — `GET /health` now returns `{ "ok": true, "ts": <epoch_ms> }` instead of `{ "status": "ok" }`.

### Fixed

- **Rate limiter not persisting state across requests** — FastAPI's dependency injection was re-creating `RateLimiter` instances on every request instead of reusing the one created at startup. Push handlers now use a factory function to capture the rate limiter in a proper closure.
