# @drakkar.software/starfish-identities

Starfish root + device identity extension — passphrase-derived root identities, device cap-cert minting, multi-device pairing flows, and the per-user device directory.

## Install

```sh
pnpm add @drakkar.software/starfish-client @drakkar.software/starfish-keyring @drakkar.software/starfish-identities
```

## Usage

```ts
import { StarfishClient } from "@drakkar.software/starfish-client"
import {
  bootstrapRootIdentity,
  mintDeviceCap,
  scopes,
  addDeviceEntry,
  listDevices,
} from "@drakkar.software/starfish-identities"

const me = await bootstrapRootIdentity("correct horse battery staple")
const cap = await mintDeviceCap(
  me.device.edPriv,
  me.device.edPub,
  { edPubHex: me.device.edPub, kemPubHex: me.device.kemPub },
  scopes.rootAll(),
)
await addDeviceEntry(client, me.userId, cap, { label: "My laptop" })
const devices = await listDevices(client, me.userId)
```

## One-way device provisioning (configurable caps + expiry)

The QR / server-relay flows are *two-way*: the new device generates its own
keypair and sends a request back. `provisionDevice` is the *one-way* alternative
— the root device plays both roles, producing a single hand-off blob — and it is
where you choose **what the new device may do** (`scope`) and **how long its cap
lives** (`ttlSec`). The same two knobs are also available on the two-way flow via
`assemblePairingBundle({ grantedScope, ttlSec })`.

```ts
import {
  provisionDevice,
  installProvisionedDevice,
  scopes,
} from "@drakkar.software/starfish-identities"

// Root device: generate the new device, mint its cap with a chosen scope + exp.
const provisioned = await provisionDevice(
  { edPriv: me.device.edPriv, edPub: me.device.edPub },
  {
    scope: scopes.rootAll(),        // REQUIRED — or a narrower preset to bound the device
    ttlSec: 7 * 24 * 3600,          // optional, default 30 days
    // currentEpochByCollection: { notes: { epoch, cek } },  // optional: wrap CEKs into the bundle
  },
)
const setupCode = JSON.stringify(provisioned) // hand off out-of-band

// New device: install the blob (uses the keys carried inside it).
const installed = await installProvisionedDevice(JSON.parse(setupCode))
```

- **`scope` is required** — provisioning never silently grants root. Pass
  `scopes.rootAll()` for a full account clone, or a narrower scope (e.g. a single
  read-only collection) to bound the device. The server enforces the scope: a cap
  whose `ops` omit `write` synthesizes no write role, so writes return 403.
- **`currentEpochByCollection`** wraps existing CEKs into the bundle so the new
  device can read existing ciphertext (it lives inside `opts` here, whereas
  `assemblePairingBundle` takes it as a positional argument). Omit it and add the
  device as a keyring recipient separately instead.
- **Security:** the new device's **private keys are generated off-device** and
  travel inside the result. Whoever reads the blob owns a full clone of the
  device. Use one-way provisioning only over a channel you would trust with the
  collection keys themselves; prefer the two-way QR / relay flow otherwise.

## QR-in / auto-return pairing (anonymous rendezvous)

For a device that **can't scan** (e.g. a laptop), keep the camera on the *root*
device: the new device shows its QR, the root scans it and pushes the assembled
bundle to a small **anonymous, TTL'd rendezvous slot**, and the new device fetches
it with a single trigger — no manual bundle-back, no polling. The new device is
credential-less (no cap-cert yet), so it reaches the public slot with an anonymous
client; this is safe because the bundle's CEKs are E2E-wrapped to the new device's
KEM and the channel needs only delivery.

```ts
import {
  buildPairingQr, parsePairingQr, assemblePairingBundle, installPairingBundle,
  pushPairingBundle, fetchPairingBundle, clearPairingBundle, generateDeviceKeys,
} from "@drakkar.software/starfish-identities"

// New device: show a QR (carries qrNonce); anonClient has no capProvider.
const dev = generateDeviceKeys()
const qr = buildPairingQr(dev.edPub, dev.kemPub, requestedScope, qrNonceBytes)

// Root device: scan/parse, assemble, and push to the rendezvous slot.
const parsed = parsePairingQr(qr)
const bundle = await assemblePairingBundle(rootEdKey, parsed, {/* CEKs */}, {
  grantedScope: scopes.rootAll(), // REQUIRED — never defaulted from parsed.requestedScope
})
await pushPairingBundle(anonClient, parsed.qrNonce, bundle)

// New device, on a single "Added from root" click — null means "not there yet".
const bundle2 = await fetchPairingBundle(anonClient, qrNonce)
if (bundle2) {
  const installed = await installPairingBundle(bundle2, dev, {
    expectedQrNonce: qrNonce,
    expectedRootEdPub: knownRootPub, // pin: rejects a bundle from a different root
  })
  await clearPairingBundle(anonClient, qrNonce) // best-effort one-shot
}
```

- **`expectedRootEdPub`** pins the issuer so an attacker's own root can't answer an
  open rendezvous and provision the device into *their* account. When the new
  device doesn't know the root pubkey, show its fingerprint for the user to verify.
- The rendezvous slot is keyed by `rendezvousPathFor(qrNonce)` = `_pairing/<hex(qrNonce)>`
  — no new QR field; `qrNonce` was never secret. The app/server provides the
  collection: `encryption:"none"`, `public` read/write, a short `ttlMs`, a tight
  body cap; one-shot is the new device overwriting the slot after install.

## Cryptographic rationale

The foundational constraint is that **the server holds no keys.** Everything the
server sees is a signed cap-cert (authority) and wrapped CEKs (confidentiality);
it can verify neither document contents nor unwrap any CEK. Every primitive in
this extension exists so authority and confidentiality can be carried by clients
alone — which is why the root identity is passphrase-derived (no server-held
secret to recover from), why devices carry their own keys (the root KEM private
key never leaves the bootstrap device), and why pairing is a client-to-client
wrap rather than a server re-encryption.

The design keeps **three concerns** separate that older modes conflated: *who you
are* (root identity), *what a device may do* (cap-cert authority), and *who can
read a collection* (keyring CEKs). Each uses a primitive chosen for that job.

### Root identity: Argon2id → HKDF → two keypairs

A root identity is derived deterministically from a passphrase, so the same human
can re-derive it on any device with no stored secret:

- **Argon2id (memory-hard) first.** A passphrase is low-entropy; a memory-hard
  KDF (`m=47104 KiB ≈ 46 MiB, t=3, p=1` — above the OWASP interactive-login
  minimum, since a root identity is a higher-value, longer-lived secret than a
  session login) raises offline brute force from ~10 M guesses/sec (raw hash) to
  a few/sec. The salt is global (`starfish-v3-root`), not per-user —
  derivation must be reproducible from the passphrase alone, so it cannot depend
  on a stored per-user salt.
- **HKDF-SHA256 expands the master into two domain-separated seeds** — an Ed25519
  signing seed (`info="ed25519"`) and an X25519 KEM seed (`info="x25519"`). The
  two keypairs are independent despite sharing one master; no key bytes are ever
  reused across the sign and key-agreement algorithms.
- **Two keypair types, never one.** Ed25519 signs cap-certs and authenticates
  requests; X25519 wraps secrets (CEKs) to a recipient. A key is used for exactly
  one of {sign, key-agreement}, never both.
- The `userId` is `sha256(rootEdPub)[0:32]`: a short, collision-resistant handle
  anchored to the public signing key — the key that signs authority.

### Authority lives in signed cap-certs, not in keys

Authorization is carried by a **capability certificate** the root signs with its
Ed25519 key, not by possession of a key. This is what lets a device hold its
*own* keypair yet act with the root's authority:

- A `device` cap names the device's pubkeys as `sub`/`subKem` but resolves
  `{identity}` to the **issuer** (`issUserId`). The device is a cryptographic
  principal in its own right (its private keys never leave it) while being an
  authorization proxy for the root.
- A **self-signed** device cap (`iss === sub`) is the **root device** —
  `bootstrapRootIdentity` self-signs the first device, while every paired device
  is minted by the root (`iss !== sub`). `isRootDeviceCap(cert)` (re-exported here
  from `starfish-protocol`) detects it; the server turns it into a synthesized
  `device:root` role, which lets a collection be marked `rootOnly` to admit only
  the root device. See [`docs/ts/server/root-only-collections.md`](../../../docs/ts/server/root-only-collections.md).
- The signing input is `stableStringify` of the cert minus its signature —
  byte-identical across TypeScript and Python, so a cert signed by either side
  verifies on the other.
- Caps are **time-bounded** (`nbf`/`exp`, ±300 s skew) and carry a random
  `nonce`, so they can be revoked individually.
- Verification fails closed: `verifyCapCert` runs **well-formedness first**
  (runtime shape-checking of attacker-supplied JSON — e.g. rejecting a
  non-array `scope.ops` or an `exp` of `Infinity`), then the time window, then
  the signature. Untrusted fields are never fed into role synthesis before they
  are validated.

### Pairing wrap: ephemeral-static ECDH per CEK

When the root pairs a new device it wraps each in-scope CEK with an
**HPKE-DHKEM-style** construction (see *Adding a device does not re-encrypt
collections* below for why CEKs travel rather than being re-encrypted):

- A fresh **ephemeral X25519 sender keypair per wrap** does ECDH against the
  recipient's static KEM pubkey; the shared secret runs through HKDF-SHA256
  (`salt`/`info` = `"starfish-wrap"`) into a 32-byte AES-256-GCM key. The
  ephemeral key gives each wrap an **independent** key, so one leaked wrap key
  reveals nothing about its siblings, and AES-GCM authenticates the ciphertext
  (a tampered wrap fails to decrypt instead of yielding garbage).
- This is HPKE **Base mode** shape — it is **not** forward-secret against
  compromise of the recipient's *static* KEM private key (that key retroactively
  unwraps every CEK ever sent to it). Forward secrecy on the data side comes from
  epoch rotation on recipient removal, not from the pairing wrap.

### Two pairing channels, two different bindings

- **QR pairing** carries the new device's pubkeys in the QR plus a `qrNonce` the
  bundle echoes back; `installPairingBundle` rejects a bundle whose `qrNonce`
  doesn't match the session it started, so a stale or replayed bundle is refused.
  Because the QR-supplied `requestedScope` is attacker-influenceable, callers
  **must** pass an explicit `grantedScope` to bound the delegated authority —
  `assemblePairingBundle` fails closed (throws) without it rather than defaulting
  to the requested scope.
- **Server-relay pairing** replaces the QR with a blob through an untrusted
  relay, encrypted under a key derived from a short code via
  **PBKDF2-HMAC-SHA256 (600 000 iterations**, the OWASP-2023 SHA-256 floor). A
  **proof-of-possession** signature binds `devKemPub` to `devEdPub` under the
  device's signing key, so the relay cannot substitute a KEM pubkey it controls
  to harvest the wrapped CEKs.
  - **Honest limit:** a ~20-bit 6-digit code is brute-forceable offline once the
    relay ciphertext is captured; no KDF cost rescues it — the iteration count
    only raises the constant factor. The relay **must** rate-limit / one-shot the
    code, and high-threat deployments should use a longer code or a PAKE. See
    `docs/ts/client/24-pairing.md`.

`installPairingBundle` chains every check before trusting a bundle: full cap-cert
verification → the cap must be `kind:"device"` (a signed `member` cap is refused,
so it cannot be installed as a root proxy) → issuer must equal `rootEdPub` →
subject keys must equal this device → optional `qrNonce` bind → only then unwrap
CEKs.

### The device directory is not an authority source

`users/{rootUserId}/_devices` exists for UI ("your linked devices") and
revoke-by-sub lookup. Authority flows **only** through the cap-cert presented in
the `Authorization` header and the signed `_revocations/{rootUserId}` document.
Removing a directory entry does not revoke a cap — cryptographic revocation means
appending the `(sub, nonce, exp)` tuple to the signed revocation list.

## Adding a device does not re-encrypt collections

Pairing a new device **never re-encrypts existing collection data.** The
content-encryption keys (CEKs) move to the new device; the ciphertext stays as
it is.

When a device is paired (`assemblePairingBundle` → `installPairingBundle`, or
the server-relay variant), the root device takes the *current* CEK of each
in-scope collection and wraps it directly to the new device's X25519 (KEM)
public key inside the pairing bundle. The new device unwraps each CEK with its
own `kemPriv` and can immediately read all previously-encrypted documents in
those collections.

A device cap-cert (`kind: "device"`) is a proxy for the root **only for
authorization** — the server resolves `{identity}` to the issuer's `issUserId`.
For cryptography the device uses its **own** keypair: the root's private KEM key
never leaves the bootstrap device, which is exactly why the bundle has to carry
the CEKs.

Re-encryption (a fresh CEK via epoch rotation) happens on **removal /
revocation**, not on add — `removeRecipient` rotates the epoch and re-wraps the
new CEK for retained recipients only (forward secrecy). Adding never rotates.

Two things to keep in mind:

- The bundle only carries the collections the root device passes in
  `currentEpochByCollection` (those in scope at pairing time). A collection not
  in the bundle leaves the new device without that CEK.
- The paired device receives CEKs through the bundle; it is **not** registered
  as a recipient in each collection's `_keyring`. If a collection's epoch is
  later rotated, the device's local CEK goes stale for new writes — re-pair, or
  add the device's KEM pub as a keyring recipient (`addRecipient`). Already-
  encrypted data stays readable with the CEK it already holds.

## Same identity on every device (the simplest multi-device model)

Pairing/provisioning give each device its own key pair (so you can revoke one device), but a
per-device key is **not** a recipient in rooms owned by *other* people — its bundle CEK is a
snapshot that goes stale on the owner's next epoch rotation, and a member can't enroll its own
device in someone else's keyring. The simplest way to give every device the **same** membership is
to skip pairing and **re-enter the passphrase**: `bootstrapRootIdentity` is deterministic, so each
device re-derives the identical root identity and is the *same principal and KEM recipient*. It can
then present any cap minted to your root (including member caps), unwrap any CEK wrapped to your
root KEM, and **keep reading across the owner's rotations** (every device re-derives the same key).
The trade-off: the master key lives on every device, so there is **no per-device revocation** and
losing any device compromises the account. The member-cap JSON others issued you and the room list
are app-level state that must still travel to the new device. See
[`docs/ts/client/24-pairing.md` §5](../../../docs/ts/client/24-pairing.md).

## Sealing a setup code with a passphrase

A one-way setup code (or any secret blob) can be sealed under a user-chosen
PIN/passphrase so the code alone is useless if intercepted — send the PIN over a
**different channel** than the code:

```ts
import { sealWithPassphrase, openWithPassphrase, isSealedEnvelope } from "@drakkar.software/starfish-identities"

const env = await sealWithPassphrase(pin, new TextEncoder().encode(setupCodeJson))
const wire = JSON.stringify(env) // hand over; transmit the PIN separately

const parsed = JSON.parse(wire)
if (isSealedEnvelope(parsed)) {
  const bytes = await openWithPassphrase(pin, parsed) // one generic error on any failure
}
```

`key = Argon2id(NFC(passphrase), random-salt)` → AES-256-GCM. `openWithPassphrase`
validates the KDF parameters **before** running Argon2id (so a hostile envelope
can't force a multi-GiB computation) and collapses every failure — wrong
passphrase, tampering, bad params — into one generic error. Strength is bounded by
passphrase entropy: a short numeric PIN is still offline-brute-forceable, so the
seal buys a revocation window, not permanent safety. Locked by the cross-language
vector `tests/test-vectors/passphrase-seal.json`.

## Server plugin

```ts
import { createCapCertRoleResolver } from "@drakkar.software/starfish-server"
import { identitiesServerPlugin } from "@drakkar.software/starfish-identities"

const resolver = createCapCertRoleResolver({
  nonceCache,
  revocationStore,
  plugins: [identitiesServerPlugin],
})
```

See `docs/ts/identities/` for the full guide.
