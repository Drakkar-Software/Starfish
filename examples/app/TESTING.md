# Regression testing — instrumented full-lib e2e

This app doubles as an **end-to-end regression harness** for the Starfish
library. Because it wires every extension together, driving the app exercises
the whole stack — so a behavioral regression anywhere in `protocol`, `server`,
the SDKs, or any of the six extensions surfaces as a failing app test.

## Layers

| Layer | Tests | Instruments | Status |
| --- | --- | --- | --- |
| **Backend (Python lib)** | `backend/tests/test_e2e.py` | `server.app` driven in-process via `httpx.ASGITransport` + the **Python SDK** (`starfish-sdk`) + `identities` / `keyring` / `sharing` / `entitlements`, plus the `queuing` + `audit` plugins wired into the app | ✅ implemented, 27 tests passing |
| **Backend edge / adversarial** | `backend/tests/test_edge.py` | same in-process harness, reusing `test_e2e.py`'s helpers + `conftest` fixtures, plus hand-crafted raw signed requests for the bytes the SDK won't emit | ✅ implemented, 94 tests passing |
| **Frontend (TS lib)** | `frontend/tests/e2e.spec.ts` | the running app (redesigned "tidepool" UI) in a real browser via **Playwright**, exercising `@drakkar.software/starfish-{client,identities,keyring,sharing,entitlements}` + the zustand binding across 9 flows (owner+member sharing with profile-pseudo attribution & live SSE, read-only enforcement, room isolation, entitlements unlock, a clear membership-error message when a non-recipient opens an existing room, owner **revoking a member** (cap 401 + epoch rotation), **listing & revoking a linked device**, **provisioning a device** from one setup code (alongside two-way pairing), a **PIN-sealed setup code** that needs the right PIN to install, and a **member leaving** a room) | ✅ spec ready (Playwright not installed by default) |
| **Cross-language conformance** | `tests/test-vectors/*.json` (repo root) | canonical encodings/signatures shared by both impls | ✅ already in the library — not duplicated here |

The two app layers cover the **Python** and **TypeScript** library implementations
respectively; together with the existing cross-language vectors they give
full-lib coverage.

> The camera-free **QR-in / auto-return ("Phone scans")** flow is covered by the
> backend e2e suite (anonymous rendezvous round-trip + wrong-root rejection). The
> Playwright frontend spec does **not** yet exercise it.

## What the backend suite asserts

Each test mirrors a real client flow against the in-process app. Happy paths:

- **transport + cap-cert auth** — a signed cap-cert request authenticates through
  ASGI (guards host-binding / request-signature regressions).
- **keyring + sync** — owner creates the keyring, pushes an encrypted message, and
  reads it back decrypted (round-trip through `createKeyringEncryptor`).
- **sharing (read/write)** — owner mints a member cap, records it in the member
  directory, and adds the member to the keyring; the member decrypts the history
  (N-recipient) and posts; the owner sees the reply.
- **entitlements** — `pullEntitlements` is empty, `/demo/grant` adds the `premium`
  slug, `/demo/revoke` clears it (client-side feature-flag pattern).
- **profile** — an account cap (with `cap:write:profile`) writes `user/<id>/profile`;
  it is then readable with **no cap** (public read).
- **multiple rooms** — an owner creates a second room; a member scoped to room A
  is **403** on room B (room isolation via `scope.paths`).
- **audit** — every push is recorded with identity + `200`.
- **queuing** — a chat push fans out a change event to an SSE-style subscriber.
- **identities (multi-device)** — a fresh device keypair is paired
  (`buildPairingQr` → `assemblePairingBundle` → `installPairingBundle`), gets a cap
  for the **same `userId`**, and decrypts the room after being added to the keyring.
- **identities (provisioning, configurable caps + exp)** — `provision_device` mints
  a device with a caller-chosen scope + expiry: a **read-only** provisioned device
  reads/decrypts but its push is **403**, and an **expired** device cap is **401**.
- **identities (QR-in / auto-return rendezvous)** — the new device's QR is parsed by
  the root, which pushes the bundle to an **anonymous** `_pairing/<id>` slot; the new
  device **fetches it anonymously** (no cap yet) and installs it, then decrypts the
  room. A second test confirms a bundle from a **different root** is rejected when
  `expected_root_ed_pub` is pinned.

Security / negative / edge paths:

- **sharing (read-only)** — a read-only member cap (no `write` op) reads/decrypts
  but its push is rejected **403**.
- **anonymous** — a request with no cap to a protected collection is denied.
- **cap scope** — a request to a path outside the cap's `scope.paths` is **403**.
- **identity isolation** — a user cannot read another user's `entitlements`.
- **profile write control** — a chat-only member cap cannot write any profile
  (**403**), and a profile-capable cap cannot write **another** user's profile
  (identity binding, **403**).
- **profile is main-device-only** — the main (root) device writes its profile, but
  a one-way-provisioned **delegated** device whose scope **covers** the profile
  path is still **403** (it lacks the `device:root` role), while reads stay public.
- **revocation** — a signed `RevocationList` revoking a member cap makes its next
  request fail **401**.
- **conflict resolution** — two writers at the same `baseHash` both succeed; the
  union-merge resolver keeps both messages (no lost write).
- **audit on failure** — a stale-`baseHash` push conflicts (**409**) and is
  recorded with `success: false`.
- **keyring access control** — recipients are listed via `listRecipients`; a cap
  holder who is **not** a keyring recipient cannot recover the CEK / decrypt.

## What the edge suite asserts (`test_edge.py`)

`test_edge.py` is a deliberately adversarial companion to `test_e2e.py`: it sets up
complicated / hostile scenarios to probe the security boundaries. The suite
originally surfaced ~15 gaps; the **fixes for those gaps have now landed** (some in
the library, some in this app's wiring — see the CHANGELOG and `server.py`), so the
tests below assert the **hardened** behavior. A handful of residual items remain by
design and are listed at the end.

A later three-round adversarial pass (15 more tests, R1–R3) probed the owner-binding
internals, the cap-vs-keyring membership seams, and the live feed. It surfaced **one
new gap — a malformed-keyring room-brick — which is now fixed** (see below), and
otherwise confirmed the remaining boundaries hold (or are documented footguns).

**Defenses it confirms hold:**

- **cap-cert integrity** — editing a held cap to widen `scope` (`ops`/`paths`),
  extend `exp`, or change `subUserId` is **401**; a cap that names someone else as
  `iss` but is signed by the attacker is **401**.
- **per-request binding** — a leaked cap presented with a request signed by a
  different key is **401**; tampering the signed **body**, **host**, or **path**
  after signing is **401**; a too-large or malformed `Authorization: Cap` header is
  **401**.
- **request freshness** — a byte-identical replay (same nonce) is **401**, a stale
  timestamp (beyond the 5-min skew) is **401**, the nonce cache is scoped **per
  signer**, and a bad-signature request does **not** burn its nonce (so an attacker
  cannot pre-claim a victim's nonces with forged requests).
- **revocation** — a list signed by a **non-issuer** does not revoke the targeted
  cap; a **stale-generation** list cannot un-revoke; revoking one device's cap
  leaves the account's **sibling devices** working (revocation is per-cap).
- **keyring forward secrecy** — removing a recipient rotates the epoch + CEK, so a
  removed-but-not-revoked reader keeps old plaintext but **cannot decrypt** content
  sealed after the rotation.
- **keyring provenance pin (`trusted_adders`)** — the encryptor AND `add`/`remove`/
  **`list_recipients`** are all fail-closed on `trusted_adders`: an entry whose
  `addedBy` is not trusted (or whose `addedSig` doesn't verify) is skipped — so even
  a hostile *server* that substitutes the stored keyring cannot inject an
  attacker-chosen CEK *or* spoof the membership listing. Relabeling a forged entry's
  `addedBy` doesn't help (the `addedSig` is checked against the claimed author).
- **keyring epoch-rollback guard (`min_epoch`)** — `create_keyring_encryptor` rejects
  a keyring whose `current_epoch` is below the caller's last-seen epoch, so a hostile
  server cannot serve a STALE keyring to undo a rotation.
- **owner-only keyring + member directory** — the `chatkeyring` and `chatmembers`
  collections require the synthesized `chat:owner` role (granted by a RoleEnricher
  only to the room's owner — the keyring's genesis adder), so neither a member nor a
  self-signed stranger can overwrite the keyring or wipe the roster (**403**). This
  also makes the **rollback** above unreachable through the API and stops the
  member-eviction / member-dir-wipe attacks.
- **owner-binding is brick-proof + rotation-stable (R1)** — an **unparseable** keyring
  written during the TOFU create-race no longer permanently locks the room: a keyring
  that yields no derivable owner is treated as "unowned" so the legitimate owner's
  *valid* write still lands (recoverable-DoS, not a brick — the fix is in
  `make_owner_role_enricher`). Ownership is anchored to the **epoch-1 genesis adder**,
  so it survives key rotation and even the owner's **self-eviction** from the recipient
  set (the owner keeps `chat:owner` after it can no longer decrypt), and a member-dir
  squat written before any keyring exists is overwritten once the real owner lands.
- **cap-membership ⟂ keyring-membership (R2)** — the two grants are independent in both
  directions: an invited member with a cap but **no keyring entry** fetches the
  ciphertext (**200**) but cannot decrypt it; a keyring recipient with **no cap** is
  refused server access (anonymous → **403/401**). A member scoped to room X cannot
  read room Y's keyring (**403**, cross-room CEK isolation).
- **scope gates are independent (R3)** — a universal `paths:["**"]` glob widens paths
  but **not** the synthesized collection role, so a `chat`-collection cap still cannot
  read `entitlements` (**403**) even on its own `{identity}`-bound doc.
- **live feed is metadata-only (R3)** — a chat push fans out only
  `{collection, hash, timestamp, params:{roomId}}` to the open `/events` stream
  (`include_body` is off): neither the plaintext nor the ciphertext envelope is
  broadcast. An anonymous public write is still **audited as `anonymous`**.
- **pairing bundle is nonce-bound (R2)** — `install_pairing_bundle` rejects a bundle
  whose `qrNonce` ≠ the device's `expected_qr_nonce`, foreclosing a cross-slot replay.
- **`list_members` is validated** — each entry's signed member cap-cert is verified,
  so a fabricated entry never surfaces as a member.
- **pairing `granted_scope` must be explicit** — `assemble_pairing_bundle` refuses to
  default to the QR-supplied `requested_scope`; the test pins that *echoing* it hands
  a hostile QR broad access while an independently bounded scope confines the device.
- **identity binding** — a self-signed root device cap whose scope names a
  **victim's** profile / entitlements / `_devices` path cannot write it (**403**),
  and the device directory is `{identity}`-bound on **read** too; authorship at rest
  is pinned to the authenticated identity (a spoofed body `authorPubkey` is ignored);
  a user **cannot self-grant entitlements** (the `entitlements` write role is an
  unreachable `billing:webhook`, so client caps are read-only there).
- **document hygiene** — `__proto__` / `constructor` keys are **stripped** from stored
  documents (`deep_sanitize`); a client-injected far-future timestamp does not become
  the stored timestamp (server-authoritative, so no LWW manipulation).
- **scope semantics** — a `!`-prefixed denylist path overrides a broad allow; a
  write-only cap is **403** on read; a `collections` ≠ target-collection cap is
  **403**; a wildcard `collections:["*"]` does **not** match a concrete role; an
  over-broad `chat` cap can READ every room's keyring/members but **cannot write**
  them (owner-only); an empty `ops:[]` cap authorizes nothing (**403**).
- **time window / containment / robustness** — a future-`nbf` cap is **401**; a
  `..`-laden room id is **404** (no escape); an anonymous profile write is denied
  while the public read works; a blind `baseHash=None` overwrite of an existing doc is
  **409**; oversized bodies are **413** (the `chat` 256 KB ceiling is now reachable —
  the resolver guard was raised from 64 KB to match); malformed `data`/`baseHash` is
  **400**.
- **`?withKeyring=1` degrades gracefully** — a store error reading the sibling keyring
  yields **200** with `keyring: null` instead of an unhandled **500**.
- **audit covers denials** — a 401/403 rejection is recorded (`success: false`), and
  the audit ring buffer was raised from 100 to 10 000 so a small flood no longer
  buries an earlier action.
- **demo/admin endpoints are gated** — `POST /demo/grant`, `POST /demo/revoke`, and
  `GET /audit` require the `X-Demo-Secret` header (and are disabled when
  `STARFISH_DEMO_SECRET` is unset), so paid slugs can't be granted/stripped and the
  audit trail can't be read anonymously. Pinned by
  `test_demo_endpoints_disabled_when_secret_unset` (403 when the env var is unset).
- **write-only cap TOFU keyring squat is recoverable** — a cap with only
  `cap:write:chat` can plant a garbage keyring on a predictable room id (no read
  needed); the real owner's valid keyring write still lands. Pinned by
  `test_write_only_cap_can_tofu_squat_keyring_but_owner_recovers`.
- **SSE `/events` metadata-only bus** — `GET /events` route registration plus the
  queuing → `sse_subscribers` payload (`{collection, hash, timestamp, params:{roomId}}`
  only; a concurrent in-process HTTP stream read + async push deadlocks under
  `ASGITransport`, so the live framing is also covered by
  `test_events_feed_broadcasts_only_metadata_never_document_content`). Pinned by
  `test_events_sse_over_http_metadata_only`.

**Residual items (by design / follow-up — see each test's docstring):**

- **room-doc writes are membership-bound (Level 3) — CLOSED** — the `chat` collection's
  write role is now `chat:owner` / `chat:member` (the enricher grants `chat:member` only
  to a write-capable caller in the room's member directory), so a self-signed stranger
  can no longer clobber an established room's encrypted document. Read-only members still
  can't post; fully evicting a member means removing them from the directory and/or
  revoking their cap. (The userId space was also widened 64→128 bits, so the identity
  binding underpinning all of this rests on 2^128, not 2^64, second-preimage resistance.)
- **rendezvous root pin is a LIBRARY option** — `install_pairing_bundle` keeps
  `expected_root_ed_pub` optional, so the library still permits an unpinned install.
  The **app** closes this: `fetchAndBuildDeviceSession` makes `expectedRootEdPub`
  **required** and throws without it, and the "Phone scans" UI now **disables the join
  button until the root key is pasted** (the Playwright spec asserts this), so a user
  can't even attempt an unpinned install. The out-of-band fingerprint-confirmation UX
  (comparing the pasted key to one shown on the first device) is still a follow-up.
- **`authorSignature` is not verified server-side** — by design (end-to-end): the
  server stores it verbatim and consumers verify. The test documents this property.
- **TOFU room ownership** — a room's owner is whoever first creates its keyring; a
  stranger who races to create a room id's keyring would own it (room ids are
  app-chosen and created up-front, so this is a documented edge). The unparseable-
  keyring **brick** that this race used to enable is now fixed (above), and the
  squat-spam window is blunted by the same per-collection `rate_limit` mechanism used
  for the rendezvous slot (left off `chatkeyring` in the demo so the test harness can
  rotate freely; recommended in production).
- **eviction is two steps (operational footgun) — now a ONE-CALL helper** — removing a
  member from the keyring (epoch rotation) stops them *decrypting* new content but does
  **not** stop them *writing*: write authority is cap-based, so the member keeps posting
  until their **cap is revoked**. The library now ships `evict_member` / `evictMember`
  (`starfish-sharing`) that does all of it in one call behind explicit `rotate` / `revoke`
  flags (build + submit a `RevocationList`, rotate the keyring, drop the directory entry);
  the app's `revokeMember` uses it. `test_keyring_removal_alone_does_not_revoke_write_access`
  still pins the *primitive* footgun, and `test_evict_member_blocks_writes_in_one_call`
  pins the one-call fix (next write → **401**, gone from keyring + directory).
- **rendezvous slot availability — now RATE-LIMITED** — `_pairing/{id}` is `public`
  read+write so a credential-less device can fetch its bundle; anyone who learns the
  (unguessable, short-TTL) id can still **wipe** a pending bundle (a single overwrite is
  by design), but a *flood* is now bounded by a per-collection `rate_limit` (30 writes/min
  per source). Confidentiality is unaffected either way. Pinned by
  `test_rendezvous_slot_is_rate_limited`.
- **value sanitization is the client's job** — the server strips dangerous object
  *keys* but stores *values* (e.g. a profile pseudo) verbatim, so the frontend MUST
  escape user-supplied strings on render (XSS is a rendering responsibility). The
  backend test pins verbatim storage; the Playwright spec now also asserts a markup
  pseudo renders as **inert text** (React/JSX escapes it; no injected `onerror` fires).

> The library fixes (`trusted_adders` on `list_recipients`, the `min_epoch` rollback
> guard, graceful `?withKeyring=1`, audit-on-denial) ship in `packages/{python,ts}`
> with their own unit tests. The app-level fixes (owner-binding RoleEnricher,
> entitlements write role, demo-secret gate, body-size limit) live in
> `examples/app/backend/server.py`.

## Adversarial sweep history

On top of the original ~15-gap edge pass, many multi-round adversarial sweeps have run.
Each probed a fresh surface and pinned the robust behaviours as regression tests. The early
passes each fixed what they found or found no reachable gap; later passes surfaced and fixed
two cross-language divergences (queuing empty-topic, audit fire-and-forget), then three
Python-side bugs plus one cross-language divergence, **all now fixed (Python converged to the
TS behavior): (1) binary blob uploads were unauthenticatable on a Python cap-auth server; (2)
the Python field-WRITE check ignored `ROLE_PUBLIC` (a `writeRoles:["public"]` field was wrongly
403 for authenticated users — an internal inconsistency, since the field-READ check already
honored it); (3) the Python `RateLimiter` had no bucket cap (unbounded-memory DoS under a key
flood); (4) the Python MIME matcher used `fnmatch`, so partial-glob patterns over-matched
relative to the TS component-only matcher**.
**A later pass surfaced two genuine cross-language divergences — a bidirectional SSRF-guard split
(highest impact) and a Unicode-digit `X-Starfish-Ts` that authenticated on Python but was
rejected by TS — plus one latent validator-level divergence (`validate_path_segment` and
trailing newlines). All three are now fixed (both servers converged) and the pins flipped from
`xfail`/`it.fails` to passing parity tests.**
Further passes probed the pairing/rendezvous protocol, cap-cert scope composition,
and the keyring's adversarial-wrap path; **all cleared with no new gap** (one regression
pin added for the keyring duplicate-subKem fail-closed defense).
**Net: every gap surfaced across all the sweeps has been fixed; the only remaining items
are the documented by-design residuals above.** Per area probed:

**Parsing boundaries, crypto DoS, Unicode/RTL containment (lib + app).** Robust,
now pinned: `Content-Length` shares the canonical `-?\d+` rule with the timestamp header
(`+64` / ` 64` / `1e3` / `0x10` / `""` → 413; leading zeros accepted); the JSON-nesting
guard is inclusive at *exactly* `MAX_DOC_DEPTH` (64 ok, 65 → 400, end-to-end); the Argon2id
guard rejects a hostile sealed envelope (inflated `memKiB`/`iter`/`par`, unknown
`alg`/`enc`, wrong-length salt) *before* the KDF in both languages; the request nonce is
signed as a verbatim base64 string (re-encoding breaks the signature); path params are
pinned to ASCII before auth (`validate_path_segment` — homograph / RTL / non-ASCII → 400);
an admin-only field set to `null` is still a write (→ 403). **Fixed (TS↔Python parity, not
a security hole):** the TS `/batch/pull` kept empty CSV slots (`?collections=,a,,` →
spurious `""`) while Python dropped them — TS now guards the raw param and filters empties
like Python (`,,` → `200 { collections: {} }`). Pinned by `batch-and-field-perms.test.ts`
+ `test_router.py`.

**TTL/ETag, keyring/sharing internals, integration.** **Fixed (Python-only
correctness):** field-permission collections dropped the hash-derived ETag — the field-strip
rebuilt the `JSONResponse` and lost the header, so `If-None-Match` → 304 never fired for
profiles; the rebuild now carries the ETag + Cache-Control forward (field filtering changes
the body view, not the document version), matching TS. Pinned by
`test_etag_conditional_survives_field_permission_filtering` + a TS twin in
`batch-and-field-perms.test.ts`. Robust, now pinned: batch pull honors TTL expiry; the
keyring unwrap rejects a ciphertext shorter than the IV; `remove_member_entry` on an unknown
nonce is an idempotent no-op; owner self-eviction keeps the owner role but revoking the
owner's own cap overrides it (→ 401); concurrent member-directory adds both land (the 409
retry resolves a real `asyncio.gather` race — no lost update).

**Merge/hash determinism, cap-cert window & scope, keyring binary surface.**
**Fixed (cross-language parity):** the Python keyring now has `seal_bytes`/`open_bytes`
(binary-blob sealing), byte-compatible with the TS `sealBytes`/`openBytes` —
`[u32 BE epoch][12B iv][AES-256-GCM ct‖tag]` with the storage path bound as AAD
(anti-relocation / anti-replay), the only way to E2E-protect attachments in a
`encryption: "none"` binary collection. Pinned by
`test_keyring_encryptor_seals_and_opens_binary_blobs_with_path_aad` (Python) + the existing
TS twin in `keyring.test.ts`. **Fixed (hardening):** `verify_cap_cert` now rejects an
inverted / zero-width window (`exp <= nbf`, reason `inverted-window`) before the time gates,
so a backwards-window cap can't slip through the skew overlap; pinned in `test_cap_verify.py`
/ `cap-verify.test.ts` and at the integration layer by
`test_inverted_validity_window_cap_is_rejected`. (Follow-up: the mint helpers could also
reject a negative `ttl_sec`.) Robust, now pinned (TS↔Python): `deep_merge` type transitions
+ the dunder-scrub boundary (root/nested scrubbed, an array-nested dunder rides along);
cap-cert window edges inclusive at exactly `exp+skew` / `nbf-skew`; an empty `scope.ops:[]`
is well-formed and authorizes nothing; `path_glob_match` keeps `*` within a segment, lets
`**` cross slashes, escapes regex specials, and requires a full match. Cleared (no gap):
append-only "duplicate idempotency" is by design (no dedup contract; the nonce is per-entry
uniqueness); the entitlements `expires_at` is the resolver's cache TTL, not a per-feature
expiry; astral-key ordering is already defended (`compareCodePoints`) and pinned in
`hash.json`; revocation `generation` monotonicity is already covered in
`test_revocation_store.py`.

**Replica sync loop, client conflict/concurrency, cross-language parity.**
**Fixed (cross-language): a corrupt local replica document was never recovered.**
`ReplicaManager._doSync` / `_do_sync` intends to treat a corrupt local doc as empty and
overwrite it, but coerced `baseHash = currentLocalHash || null` (`"" || null` → `null`);
`push()` recovers a corrupt doc only when `baseHash === ""` (with `baseHash == null` + a
present corrupt doc it returns HASH_MISMATCH). So sync threw "Concurrent write — will retry"
every cycle — a transient-looking error that never recovered, leaving the replica permanently
stuck on that collection, in **both TS and Python**. Fixed by passing `currentLocalHash`
verbatim (no `|| null` coercion); a valid local doc still yields its real hash, so genuine
concurrent-write detection is preserved. Pinned by regression tests in `manager.test.ts` +
`test_manager.py`. Robust, now pinned (TS↔Python parity): repeated
bidirectional sync converges (idempotent, lossless re-merge); two concurrent `push()` on one
SyncManager both land with no lost write (the loser conflict-retries and the default
deep-merge unions them); a stale/corrupt rehydrated `lastHash` self-heals through the
conflict-retry loop (the server treats any non-matching `baseHash` as a 409, not a 400).
The client-sync behaviours were verified **identical** in TS and Python (`sync.test.ts` /
`test_sync.py`) — no concurrency or self-heal divergence.

**Incremental-sync core (per-field LWW + checkpoint filter).** Probed
`compute_timestamps` / `filter_by_checkpoint` / `max_leaf_timestamp` (previously only
vector-tested). **0 reachable gaps.** Robust, now pinned (TS↔Python): an unchanged leaf
keeps its old timestamp, a changed leaf gets `now`, a new key gets `now` while a removed key
is omitted, leaf↔object transitions stamp `now`, and an identical list keeps its ts but a
reorder counts as a change; `filter_by_checkpoint` is strict at the boundary (`ts ==
checkpoint` excluded), drops a field with no timestamp, and prunes an empty nested subtree
while keeping changed sub-fields. Cleared (not a gap): a `number[]` (per-item append-only)
timestamp is handled differently by the two generic filters (TS drops the field, Python
passes it through), but the path is **unreachable** — `compute_timestamps` never emits a
`number[]`, and real append-only docs route to `handle_append_only_pull` (custom per-item
filtering); pinned as a tripwire in both languages so the divergence is flagged if the
routing ever changes. Pinned by `test_timestamps.py` / `timestamps.test.ts`.

**Extension plugins: queuing, audit, entitlements, merge, sharing-directory
churn. Two cross-language divergences surfaced, both now fixed:** (1) **queuing topic** —
an empty-string `topic` was kept verbatim by TS (`cfg.topic ?? collection` → published to
the empty subject `""`) but coalesced to the collection name by Python (`config.topic or
collection`); an empty broker subject is a footgun, so TS now uses `cfg.topic ||
collection` and both fall back to the collection name (`plugin.test.ts` /
`test_plugin.py`). (2) **audit durability** — TS called `auditLogger.record(...)`
**without `await`** (fire-and-forget) while Python `await`s it, so an async audit logger's
write could be lost before the response and a *rejecting* logger became an **unhandled
promise rejection** (process-crash risk under Node's `--unhandled-rejections=throw`); all
five TS call sites now `await` the record, matching Python (`router-emission.test.ts` /
`test_audit_router.py`). Robust, now pinned (TS↔Python parity): queuing omits `params` when
the storage path has no placeholders and preserves Unicode in topic + body; `deepMerge` lets
a remote `null`/`None` overwrite a local object and a remote object replace a local null; the
entitlement cache TTL boundary is strict (`expires_at > now`, so it re-reads at exactly
`t == expires_at`) and an empty-string feature slug yields a bare-prefix role in both
languages; the member directory upserts by nonce (re-add does not duplicate) and converges on
*present* after add → remove → re-add. Cleared (not a gap): the queuing body `!== undefined`
vs `is not None` difference sits on an **unreachable** path (the server never emits
`body=null`), pinned as a tripwire; `proxyPush` 409 + response-shape handling and the
`UNSAFE_KEYS` denylist are already at full parity (verified by reading); the entitlement
cache time source (`Date.now()` vs `time.monotonic()`) differs only under wall-clock
adjustment — a benign design choice, not a divergence.

**Auth internals: cap-resolver request signing, nonce cache, revocation store,
keyring churn, canonical-encoding floats. One correctness/interop gap surfaced, now
fixed:** **binary blob uploads were unauthenticatable on a Python cap-auth server.** Clients
sign a blob upload with an EMPTY body (the large/streamed bytes aren't folded into the
per-request signature; blob integrity comes from the content seal + the signed path). The TS
server mirrors this — it detects `application/octet-stream` and verifies against an empty
body (`cap-resolver.ts`; pinned by `cap-resolver.test.ts:186`). The Python server had no such
detection (`cap_resolver.py`) and verified against the full body, so a cap-signed blob upload
failed `bad request signature` (401). It was never caught because the Python binary-collection
test uses a *static* role resolver, bypassing the signature path. **Fixed:** the Python
resolver now detects `application/octet-stream` and verifies an empty body, mirroring TS;
pinned by the now-passing `test_cap_resolver.py::test_blob_upload_signed_with_empty_body_is_accepted`.
**Broader fix (follow-up, now done): clients sign *any* blob with an empty
body, but both servers used to special-case only `octet-stream`, so a non-octet binary
content-type (e.g. `image/png`) mismatched on *both* servers. Both servers now treat any
non-JSON content type as a blob upload (empty-body-signed) — the media type is compared on
its prefix (params stripped), and an empty/missing content type is non-blob (signs the body)
so a missing header can't dodge body-signing; JSON collections still reject a non-JSON
content type at the MIME check. Pinned by the `image/png` cases in `cap-resolver.test.ts` /
`test_cap_resolver.py`.** Robust, now pinned (TS↔Python parity): the clock-skew gate is
inclusive at exactly `±maxSkewMs` and excludes one ms beyond (strict `<=`); a generation-0
revocation list is accepted as the first list for an issuer (and a gen-0 replay is then
stale); a rotated-out keyring recipient regains access when re-added to the new epoch, and
rotating out *every* recipient yields an empty epoch whose encryptor fails for a former
recipient. Cleared (no gap): TS↔Python `stableStringify` float rendering is byte-identical
for arithmetic results (`0.1+0.2` → `0.30000000000000004`), `1e-7`, and max-double — locked
by new `hash.json` vectors; the nonce-cache `signer|nonce` key cannot collide (hex signer +
base64 nonce contain no `|`); root-identity derivation is already cross-language vector-locked.

**Server router internals + storage: field permissions, rate limiter, batch/bundle,
push conflict. Two cross-language gaps surfaced, both now fixed:** (1)
**field-WRITE `ROLE_PUBLIC` was ignored in Python.** A field marked `writeRoles:["public"]`
(i.e. unrestricted) is writable by an authenticated user in TS (`route-builder.ts:439`,
`r === ROLE_PUBLIC`) but was **403 in Python** (`route_builder.py`), because the Python
field-write check omitted the `ROLE_PUBLIC` short-circuit that its *own* field-READ check
(line 294) and the TS write check both have — an internal inconsistency as well as a TS
divergence. **Fixed:** added `or r == ROLE_PUBLIC` to the Python write check; pinned by the
now-passing `test_ttl_and_field_permissions.py::test_field_write_public_role_allows_authenticated_user`
with the TS reference in `batch-and-field-perms.test.ts`. (2) **the Python
`RateLimiter` had no bucket cap.** TS caps `_buckets` at `maxBuckets` (default 10k) and
evicts the oldest (`middleware.ts`); Python's dict grew unbounded, so a flood of distinct
keys (e.g. spoofed `X-Forwarded-For` on an anonymous endpoint) was a memory-exhaustion DoS
vector. **Fixed:** the Python limiter now takes `max_buckets` (default 10k) and evicts the
oldest bucket at capacity, mirroring TS; pinned by the now-passing
`test_rate_limit_and_cache.py::test_rate_limiter_bounds_bucket_count` with the TS twin in
`middleware.test.ts`. **Per-source keying (follow-up, now done): both `check` methods take
an explicit `(identity, forwardedFor, clientIp)` and apply the *identical* precedence —
identity → first X-Forwarded-For hop → client IP → shared `"anonymous"`. The limiter is now
runtime-agnostic (keys on plain strings); the call site supplies the signals it has — the
Python server passes the socket `request.client.host` as `clientIp`, while Hono has no
portable socket IP so the TS server passes `null` (a proxy MUST set X-Forwarded-For for
per-client limiting). Pinned by a key-precedence test in `middleware.test.ts` /
`test_rate_limit_and_cache.py`.** Robust, now pinned (TS↔Python parity): the rate limiter
allows up to the limit then 429s and isolates counters per key; a corrupt stored document
does not crash `push` (returns a conflict) and is overwritable with `baseHash=""` (TS twin
of the existing Python tests). Cleared (no gap): `StoreContext` is populated consistently
across pull/push/list/bundle/batch in both languages; `push()` conflict + corrupt-recovery
logic is identical; batch/bundle partial-denial transparency matches.

**Client SyncManager + lower-level protocol (MIME, path-key safety, deepSanitize,
append-only). One cross-language divergence surfaced, now fixed:** **the Python MIME matcher
used `fnmatch`.** Both servers strip content-type params and lowercase, and agree on exact
types, `type/*`, and `*/*`. But the TS matcher (`mime.ts`) does **component-only** wildcarding
— only a whole `*` component matches — while Python (`mime.py`) used `fnmatch`, so `image/p*`,
`application/*json`, `text/?ml`, `[seq]` char-classes, and a bare `*` all matched in Python
but not TS — the same `allowedMimeTypes` config accepting/rejecting differently across servers
(and an allowlist over-matching via glob metacharacters is the riskier direction). **Fixed:**
the Python matcher is converged to TS's component-only semantics (`fnmatch` dropped); pinned
by `test_mime.py` / `mime.test.ts`. Robust, now pinned (TS↔Python parity): MIME exact / `type/*` / `*/*` matching,
param-stripping, case-insensitivity; `isJsonCollection`; the client incremental pull replaces
an array wholesale (deepMerge is not element-wise) and preserves local-only keys; a custom
conflict resolver that throws propagates its error (not swallowed). Cleared (no gap): the
client SyncManager has **no** TS↔Python divergence (checkpoint advance, conflict-retry, encrypt
integration, baseHash handling all identical); `deepSanitize`/`deep_sanitize` are identical
(both recurse only into plain objects/dicts, copy arrays + array-nested dunders verbatim —
matching the earlier deepMerge finding); `validate_path_segment` / `is_unsafe_document_key`
use byte-identical regexes; append-only timestamp filtering + backfill are equivalent.

**Unicode/encoding edges across parsing, the SSRF guard, and path-segment
validation. Two genuine divergences + one latent finding, all now fixed (both servers
converged); the pins flipped from `xfail`/`it.fails` to passing parity tests:**

1. **Fixed — bidirectional SSRF-guard split in `validateUrlNotPrivate` /
   `validate_url_not_private` (highest impact; the helper is exported public API used by
   consumers to gate outbound URLs).** The two implementations gave opposite verdicts on
   loopback spelling, each leaving the *other* runtime's consumers exposed: **TS allowed
   IPv4-mapped IPv6 loopback** — `new URL("http://[::ffff:127.0.0.1]/")` compresses the host to
   `::ffff:7f00:1` (hex), which its dotted-quad `::ffff:(\d+\.\d+\.\d+\.\d+)` regex missed →
   "public"; Python's `ipaddress` flags it private. **Python allowed alternate IPv4 notations**
   — `http://2130706433/` (decimal), `0x7f000001` (hex), `0177.0.0.1` (octal), `127.1` (short)
   all resolve to 127.0.0.1, but `urlparse` keeps the raw host and `ipaddress.ip_address()`
   rejects the non-dotted-quad form, so the guard fell through to "public"; TS's `new URL`
   normalises them to 127.0.0.1 and blocks. **Fixed:** TS gained a hex IPv4-mapped branch that
   decodes the embedded IPv4; Python canonicalises the host via `socket.inet_aton` before the
   `ipaddress` check (real domains still raise → public). Every loopback spelling now blocked on
   both, public IPs still allowed. Pinned by new files `test_url_ssrf_guard.py` +
   `url-ssrf-guard.test.ts` (no SSRF tests existed before).
2. **Fixed — a Unicode-digit `X-Starfish-Ts` authenticated on Python, was rejected by TS.** The
   shared "`-?\d+`" rule (earlier pinned for `+64`/` 64`/`1e3`/`0x10`) was **not** shared
   for non-ASCII digits: Python's `\d` + `int()` are Unicode-aware, so a `Ts` header transcoded
   to Arabic-Indic/Devanagari/Persian digits parsed to the *same* integer and the request's
   signature still verified → it authenticated; TS's ASCII-only `\d` rejected it at parse with
   `invalid X-Starfish-Ts`. The same wire request authenticated differently per server.
   **Fixed:** the Python `_INTEGER_HEADER_RE` now uses the ASCII class `[0-9]` (not `\d`), so a
   non-ASCII-digit `Ts` is rejected at parse exactly as on TS. Pinned:
   `test_cap_resolver.py::test_unicode_digit_timestamp_rejected_identically_to_typescript`
   + a passing TS reference in `cap-resolver.test.ts`.
3. **Fixed — `validate_path_segment` admitted a trailing newline (latent; refines the earlier
   "byte-identical regexes" note).** The regex *source* was identical, but Python's `$` matches
   *before* a trailing `\n` (and `SAFE_PARAM` was applied with `.match()`), so
   `validate_path_segment("alice\n")` was `True` where TS's `validatePathSegment` is `false`.
   End-to-end it was masked by `is_unsafe_document_key` (`[\x00-\x1f]` catches the `\n`), so it
   was **not** a live request-level bypass — but it was a real validator-level divergence
   sharing its root cause (`.match()`/`.search()` + `$` vs `\Z`/`fullmatch`) with `_NS_NAME_RE`,
   `_CAP_ROLE_RE` (whose `(.+)$` is the same trap; cap roles come from signed certs, so lower
   reach), and the filesystem store's `_VALID_KEY`. **Fixed:** all four Python `$`-anchored
   validators now use `re.fullmatch` (not `.match()`). Pinned:
   `test_path_traversal.py::test_path_segment_rejects_trailing_newline`
   + a passing TS reference in `path-traversal.test.ts`. **Cleared (no new gap, robust + parity verified):** seal-envelope
   Argon2id param validation (TS↔Python identical, already pinned inline in `test_seal.py`);
   the `?limit` round-trip guard (`String(parsed) !== raw`) is identical; batch-collection CSV
   splitting; the JSON-depth boundary (already pinned at exactly 64 on both sides); nonce-cache
   keying (raw base64 string, and re-encoding a nonce would change the signed payload, so it is
   not a replay vector); and keyring epoch/rollback, `trustedAdders=[]` fail-closed, revocation
   generation semantics, and `userId` derivation — all already covered in both languages
   (revocation additionally by cross-language vectors).

**Pairing/rendezvous, cap-cert scope composition, keyring adversarial wrap. All
cleared, no new gap; one regression pin added.** These targeted three of the least-probed
surfaces; each turned out robust with full TS↔Python parity:

- **Pairing / rendezvous.** The QR/relay onboarding path. `install_pairing_bundle`
  verifies the cap-cert (signature + window + well-formedness), `kind=="device"`, `iss==rootEdPub`,
  the optional `expected_root_ed_pub` pin, `sub`/`subKem`, and the optional `qrNonce` session
  binding; `assemble_pairing_bundle` fails closed without an explicit `granted_scope` (the
  QR-supplied `requestedScope` is attacker-influenceable and a device cap is a root proxy); the
  relay request carries an Ed25519 proof-of-possession binding `devKemPub` to `devEdPub`. **Cleared:**
  the relay's `deriveCodeKey` (PBKDF2-HMAC-SHA256, 600 000 iters, `"starfish-pair"` salt) is
  **byte-identical** across TS↔Python (verified empirically), so the code-derived encryption
  interops; the relay PoP/roundtrip, wrong-code, KEM-substitution, and missing-PoP cases are
  behaviourally tested in both languages; the QR/bundle install is cross-language vector-locked
  (`pairing-bundle.json`). No gap.
- **Cap-cert scope composition.** Not `path_glob_match` (covered earlier) but the *composition*:
  role synthesis, the allow/deny path matcher, and `{identity}` substitution. **Cleared:**
  `synthesizeRoles` (the `collections × ops` cross-product → `cap:{op}:{col}`, plus
  `delegated:{issUserId}:{col}` for member caps and the root-device role) and `matchScopePath`
  (empty→allow, `!`-deny, ≥1 allow required AND no deny) are byte-identical TS↔Python; crucially
  `{identity}` substitution replaces **all** occurrences on both sides — Python `str.replace`, and
  TS uses `split("{identity}").join(identity)` (deliberately, not `String.replace`, which would
  replace only the first). A multi-`{identity}` path therefore behaves identically. No gap.
- **Keyring adversarial wrap.** Whether the unwrap path enforces its structural
  invariants symmetrically. **Cleared + pinned:** `recoverCurrentCek` / `_recover_current_cek`
  enforce — identically in both languages — a non-existent-epoch throw, a **duplicate-subKem
  fail-closed** check (a tampered epoch with two entries for one subKem is rejected, not probed
  past), the `trustedAdders` filter, and `addedSig` verification; `requireTrustedAdders` is
  fail-closed in both. The trusted-adder/forged-entry cases were already tested both ways; the
  duplicate-subKem defense was present in both but **untested** — now pinned by
  `test_add_recipient_fails_closed_on_duplicate_subkem_in_epoch` + the TS twin in
  `recipients.test.ts`. No gap.

**Still-missing gaps:** none surfaced. Across all the sweeps the parsing, auth, crypto, SSRF,
pairing, cap-scope, and keyring surfaces are mature with verified cross-language parity. The
remaining genuinely-unprobed areas are largely cosmetic (OpenAPI generation parity, log-format
parity) where a divergence has no security or correctness consequence; deeper value would now
come from property-based/fuzz testing of the glob and merge engines rather than more example
probes.

## Production deployment (example app)

The demo defaults favour the test harness (no `chatkeyring` rate limit, open
`/events`, localhost CORS). For a real deployment, set:

| Variable | Purpose |
| --- | --- |
| `STARFISH_DEMO_SECRET` | Required to enable `/demo/grant`, `/demo/revoke`, and `GET /audit`; leave unset to disable them (403). |
| `STARFISH_CORS_ORIGIN` | Comma-separated browser origins allowed by CORS (default `http://localhost:5173`). |
| `STARFISH_ENABLE_KEYRING_RATE_LIMIT=1` | Enables 30 writes/min per source on `chatkeyring` to blunt TOFU room-id squat spam. |
| `STARFISH_DATA_DIR` | Filesystem store root (default `./data`). |

**Rate limiting behind a reverse proxy:** the library keys anonymous limits by
`identity → first X-Forwarded-For hop → client IP`. The `X-Forwarded-For`
header is **client-supplied**, so a deployment that is reachable directly — or
sits behind a proxy that *appends to* rather than *overwrites* XFF — lets an
attacker spoof and rotate the hop to evade per-source rate limits (the
`max_buckets` cap bounds memory under such a flood but does not stop the
evasion). Deploy behind a trusted proxy that **overwrites** `X-Forwarded-For`
with the real client IP, and never expose the app port directly. Note: the
Python server can fall back to the direct-socket IP (`request.client.host`);
the TS/Hono server has no socket-IP fallback and **must** sit behind such a
proxy for per-client rate limiting to be effective.

**`/events` (SSE):** unauthenticated in the demo; broadcasts metadata only (room
id + hash), never document bodies. If that activity leak is unacceptable, gate the
route (cap-auth, room-scoped token, or network ACL) before exposing it publicly.

## Running

Backend (no servers needed — runs the app in-process against a tmp store):

```bash
cd examples/app/backend
uv sync
uv run pytest -v
```

Frontend (needs the backend + `pnpm dev` running, see `README.md`):

```bash
cd examples/app/frontend
pnpm add -D @playwright/test && npx playwright install chromium
npx playwright test
```

## Test design notes

- **Isolation**: `conftest.py` sets `STARFISH_DATA_DIR` to a tmp dir *before*
  importing `server`, so the filesystem store never touches `./data`. The shared
  single room is built up across tests, mirroring the real multi-user flow;
  assertions check membership/containment rather than exact counts.
- **Host binding through ASGI**: the SDK signs each request bound to the host in
  its `baseUrl`. `ASGITransport` synthesises host `testserver`, so the client uses
  `base_url="http://testserver"` to keep client/server host bytes identical.
- **Mount at root**: the suite (like the app) talks to the server at the origin —
  the sync router is mounted with no prefix so the signed path matches the
  verified path.

## Known library quirk pinned by a test

`pullDirectory` / `pullKeyring` in the sharing/keyring helpers treat **404** as
"empty", but this server returns **200 with `{}`** for a missing document. The app
works around it by pre-creating the member directory (`ensureMembersInitialized`)
and keyring during owner setup. `test_member_readwrite_invite` exercises that
path, so if the library is later changed to 404 (or the workaround is removed)
the mismatch is caught here. This is a **known quirk**, intentionally not fixed in
this example (separate scope).

## Suggested CI

Two jobs gated on the existing build:

```
pnpm install && pnpm build
# job 1 — backend lib regression (fast, hermetic)
cd examples/app/backend && uv sync && uv run pytest -q
# job 2 — frontend lib e2e (start servers, then Playwright)
cd examples/app/backend && uv run uvicorn server:app --port 8000 &
cd examples/app/frontend && pnpm dev &
npx playwright test
```
