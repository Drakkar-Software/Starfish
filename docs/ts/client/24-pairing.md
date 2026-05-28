# 24. Pairing

Starfish 3.0 has three onboarding flows. All three end with the same shape: a `DeviceCredentials` (root pub, userId, device key pair, signed cap-cert) plus the per-collection CEKs the new device is authorized to read.

> **Crypto suite:** pairing uses Ed25519 signing + X25519 KEM throughout — same primitives as everywhere else on the wire. External secp256k1 roots bootstrap into a Starfish Ed25519 identity *before* pairing (see [Identity Models](26-identity-models.md)); from pairing's point of view the resulting identity is a normal Ed25519 root.

| Flow | Network | User interaction | When to use |
|------|---------|------------------|-------------|
| **Bootstrap** | None | Type the passphrase | First device — or the same identity on every device (§5) |
| **QR pairing** | None | Camera scans a screen | Add a device while both are physically present |
| **Server-relay invite** | Relay collection on the Starfish server | Type a 6-digit code | Add a device remotely |

> **Prerequisites:** [Identity & Key Derivation](11-identity-key-derivation.md), [Capability Certificates](25-capability-certs.md), [Multi-Recipient Delegated Encryption](23-multi-recipient-delegated.md)

## 1. Bootstrap (first device)

Derive the root identity from the passphrase and self-sign a full-scope `kind: "device"` cap-cert. The device key pair is the root key pair on the first device — they are indistinguishable until additional devices are paired in.

```ts
import { bootstrapRootIdentity } from "@drakkar.software/starfish-client"

const creds = await bootstrapRootIdentity(passphrase)
// {
//   rootEdPub,                                  // hex
//   userId,                                     // hex 32 = sha256(rootEdPub)[0:32]
//   device: { edPriv, edPub, kemPriv, kemPub }, // equals the root keys here
//   capCert,                                    // self-signed kind:"device", scope: rootAll()
// }
```

There is no server round-trip. The same passphrase on another device will re-derive the same `rootEdPub` and `userId`; whether you treat that second device as a "second bootstrap" or as a "device to pair" is a UX choice — pairing keeps the device keys per-device-unique, which matters for revocation.

## 2. QR pairing (in-person, server-free)

The new device generates fresh Ed25519 + X25519 keys, displays them in a QR. The root device scans, mints a cap-cert for those keys, wraps each in-scope collection's current CEK for the new device's KEM pubkey, and shows the resulting bundle as a return-QR (or hands it back over a local-network channel). The new device installs the bundle.

```
new device                              root device
──────────                              ───────────
generate {edPriv,edPub,kemPriv,kemPub}
buildPairingQr(edPub,kemPub,scope)  ──> parsePairingQr(qrString)
                                        assemblePairingBundle(rootEdKey,
                                          parsed, {coll: {epoch, cek}, ...})
installPairingBundle(bundle, dev)  <──  (returns PairingBundle)
                                        → DeviceCredentials + recovered CEKs
```

### New device — present the QR

```ts
import { buildPairingQr, scopes } from "@drakkar.software/starfish-client"

const device = generateDeviceKeys()              // see 11-identity-key-derivation.md

const qr = buildPairingQr(
  device.edPub,
  device.kemPub,
  // Whatever access the new device is asking for. The root device decides what
  // it is willing to grant; it MAY mint a narrower scope than was requested.
  { ops: ["read", "list", "write"], collections: ["notes", "tasks"], paths: ["notes/*", "tasks/*"] },
)
// Render `qr` (a base64url string) as a QR image on screen.
```

### Root device — read the QR, hand back the bundle

```ts
import {
  parsePairingQr,
  assemblePairingBundle,
  scopes,
} from "@drakkar.software/starfish-client"

const parsed = parsePairingQr(scannedQrString)

// `currentEpochByCollection` comes from the root device's local key state:
// for each in-scope collection, look up the current CEK and epoch the root
// device unwrapped from that collection's keyring document.
const bundle = await assemblePairingBundle(
  { edPriv: rootCreds.device.edPriv, edPub: rootCreds.device.edPub },
  parsed,
  {
    notes: { epoch: 1, cek: notesCek },
    tasks: { epoch: 1, cek: tasksCek },
  },
  // REQUIRED — the exact authority to grant; never defaulted from
  // parsed.requestedScope (attacker-influenceable). See the note below.
  { grantedScope: scopes.rootAll() },
)
// Render `bundle` (a JSON object) — encode to QR, send over BLE / local-network
// websocket / NFC / etc. There is no server round-trip in this flow.
```

`assemblePairingBundle` mints a `kind: "device"` cap-cert (via `mintDeviceCap`, which runs `assertCapCertWellFormed` before signing), wraps each in-scope CEK with `wrapCekBare` (the same HPKE-DHKEM-style construction as the keyring, but without the per-entry audit signature — the cap-cert authenticates the root), echoes the QR's `qrNonce` into the bundle (so the new device can bind it to this pairing session), and returns:

```ts
interface PairingBundle {
  v: 1
  capCert: CapCert
  rootEdPub: string
  wrappedCEKs: Record<string, { epoch: number; ephKem: string; ct: string }>
  qrNonce?: string   // echoed from the QR; verified on install via expectedQrNonce
}
```

> **Bound the granted scope (required).** `parsed.requestedScope` comes from the QR (or relay) and is attacker-influenceable, and a `device` cap is a root proxy regardless of its `paths` — a tampered QR requesting root-all access would otherwise mint a full root proxy. `assemblePairingBundle` therefore **requires** `opts.grantedScope` (`AssemblePairingBundleOpts(granted_scope=...)` in Python) and throws without it — it never defaults to `requestedScope`. Pass the exact authority you intend the paired device to receive.

### New device — install the bundle

```ts
import { installPairingBundle } from "@drakkar.software/starfish-client"

const { credentials, ceks } = await installPairingBundle(bundle, device, {
  expectedQrNonce,   // the qrNonce this device put in its own QR (recommended)
})
// credentials: DeviceCredentials   — store the device keys + cap-cert securely
// ceks:        { [collection]: { epoch, cek } } — seed the local key cache
```

`installPairingBundle` does:

1. Fully verify the cap-cert with `verifyCapCert` — Ed25519 signature **and** the not-before/expiry window **and** well-formedness (the previous signature-only check accepted expired or not-yet-valid bundles). Pass `opts.now` to make the window check deterministic in tests.
2. Require `bundle.capCert.kind === "device"` — a signed `member` cap (which binds identity to its subject, not the issuer) must never be installed as a root-proxy device credential.
3. Require `bundle.capCert.iss === bundle.rootEdPub` — the cert must be issued by the root the bundle claims.
4. Check `bundle.capCert.sub === device.edPub` and `bundle.capCert.subKem === device.kemPub` (the bundle is bound to *this* device).
5. If `opts.expectedQrNonce` is given, require `bundle.qrNonce === expectedQrNonce` — binds the bundle to the pairing session that produced the QR, rejecting a replayed/stale capture.
6. Unwrap each `WrappedCekEntry` against `device.kemPriv`.

Any failure throws. The new device is now ready to build `KeyringEncryptor`s and `SyncManager`s; once the root device adds the new device as a recipient on each collection's `_keyring`, future epochs will be unwrappable through the live keyring too.

Cross-language test vectors lock the bundle format: [`tests/test-vectors/pairing-bundle.json`](../../../tests/test-vectors/pairing-bundle.json).

## 3. Server-relay invite (remote)

Same end-to-end intent as QR pairing, but the bundle travels through two TTL'd Starfish collections instead of a screen. The encryption key for that hop is derived from a short out-of-band code (a 6-digit number is the canonical UX) via PBKDF2-HMAC-SHA256.

### Code-derived key

```
salt   = utf8("starfish-pair") || requestNonceBytes
keyBits = PBKDF2-HMAC-SHA256(
           password = utf8(code),
           salt     = salt,
           iter     = 600_000,
           dkLen    = 32 bytes)
```

The `requestNonce` is a 16-byte random value chosen by the new device and travels in cleartext on the request envelope. PBKDF2 runs 600 000 iterations (OWASP-2023 SHA-256 floor). `deriveCodeKey(code, salt, iterations?)` is exported if you need to reproduce the derivation.

> **Security — the code is the trust anchor.** A 6-digit code is ~20 bits, so no iteration count makes the relay ciphertext safe against offline brute force once captured. Two defenses matter:
>
> - **The relay MUST one-shot the code and rate-limit attempts.** Starfish does not own the relay endpoint; expire the request/response documents on first read and cap retries (e.g. 5 attempts) so an online attacker cannot grind the code. The collection TTL alone is not enough.
> - **Proof of possession.** The request plaintext includes `popSig`, an Ed25519 signature over `{devEdPub, devKemPub, requestNonce}` made with the new device's `edPriv`. `readPairingRequest` verifies it, so a relay (even one that learns the code) cannot swap `devKemPub` for a key it controls to harvest the wrapped CEKs without re-signing. It does **not** stop an attacker who fully learns the code from substituting *both* device keys — for high-threat deployments use a longer code or a PAKE.

### Flow

```
new device                                          root device
──────────                                          ───────────
generate device keys
nonce = randomBytes(16)
req = buildPairingRequest(device, code, nonce)   // device incl. edPriv (signs popSig)
PUSH _pairing-requests/<nonce>  req  ──────────────────────────►   poll _pairing-requests/<nonce>
                                                                   readPairingRequest(req, code)
                                                                   → { devEdPub, devKemPub }  // popSig verified
                                                                   assemblePairingBundle(…)
                                                                   resp = buildPairingResponse(bundle, code, nonce)
poll _pairing-responses/<nonce> ◄────────────────────────────────  PUSH _pairing-responses/<nonce>  resp
readPairingResponse(resp, code)
installPairingBundle(bundle, device)
```

The two helper collections (`_pairing-requests` and `_pairing-responses`) are normal `encryption: "none"` Starfish collections with a short `ttlMs` so stale requests expire. Both sides use the same `requestNonce` as the PBKDF2 salt — the request nonce is echoed on the response.

### Code

```ts
import {
  buildPairingRequest,
  readPairingRequest,
  buildPairingResponse,
  readPairingResponse,
  installPairingBundle,
  assemblePairingBundle,
  scopes,
} from "@drakkar.software/starfish-client"

// New device ─────────────────────────────────────────────────────────────────
const device = generateDeviceKeys()
const code   = "482931"                              // shown out-of-band by the root device
const req    = await buildPairingRequest(
  { edPriv: device.edPriv, edPub: device.edPub, kemPub: device.kemPub }, // edPriv signs the popSig
  code,
)
// `req = { v: 1, requestNonce, iv, ct }`. Push to `_pairing-requests/<req.requestNonce>`.

// Root device ────────────────────────────────────────────────────────────────
// Fetch the encrypted blob from the relay collection — there is no
// dedicated `pullPairingRequest` SDK export; use the StarfishClient
// directly. The push side mirrors this: `client.push("_pairing-requests/<nonce>", req)`.
const incoming = (
  await client.pull(`_pairing-requests/${req.requestNonce}`)
).data as PairingRequestEncrypted
const { devEdPub, devKemPub } = await readPairingRequest(incoming, code)

const bundle = await assemblePairingBundle(
  { edPriv: rootCreds.device.edPriv, edPub: rootCreds.device.edPub },
  {
    v: 1,
    devEdPub,
    devKemPub,
    requestedScope: { ops: ["read", "list", "write"], collections: ["notes"], paths: ["notes/*"] },
    qrNonce: req.requestNonce,                    // any 16-byte value; the request nonce is fine
  },
  { notes: { epoch: 1, cek: notesCek } },
  // REQUIRED — the relay-supplied requestedScope is attacker-influenceable, so
  // the root states the granted authority explicitly (throws if omitted).
  { grantedScope: scopes.rootAll() },
)
const resp = await buildPairingResponse(bundle, code, req.requestNonce)
// Push to `_pairing-responses/<req.requestNonce>`.

// New device ─────────────────────────────────────────────────────────────────
// Same pattern: fetch from the relay collection via `client.pull`. There
// is no dedicated `pullPairingResponse` SDK export.
const incomingResp = (
  await client.pull(`_pairing-responses/${req.requestNonce}`)
).data as PairingResponseEncrypted
const installable  = await readPairingResponse(incomingResp, code)
const { credentials, ceks } = await installPairingBundle(installable, device)
```

`readPairingRequest` / `readPairingResponse` throw if the code is wrong or the ciphertext was tampered with — AES-GCM authentication tag failure is surfaced verbatim.

### Why a relay, not direct server auth

The new device has no cap-cert yet; it cannot authenticate to the server in the v3 sense. The relay collection makes a tiny, code-gated, TTL'd hole through which exactly the pairing handshake can flow. The bundle is end-to-end-encrypted under the code-derived key — the server sees `{requestNonce, iv, ct}` and nothing else.

## 4. One-way provisioning (single setup code)

QR and relay are *two-way*: the new device generates its own keypair and sends a request back, so its private keys never leave it. `provisionDevice` is the *one-way* alternative — the **root device plays both roles**, generating the new device's keypair, minting its cap, and assembling the bundle in one step. The output is a single blob to hand off; the new device only ever receives it.

This is the flow where you choose the new device's authority up front: `scope` (required) and `ttlSec` (the cap's lifetime).

```ts
import { provisionDevice, installProvisionedDevice, scopes } from "@drakkar.software/starfish-identities"

// Root device — generate + mint + assemble, with a chosen scope and a 7-day cap.
const provisioned = await provisionDevice(
  { edPriv: root.device.edPriv, edPub: root.device.edPub },
  { scope: scopes.rootAll(), ttlSec: 7 * 24 * 3600 },
)
const setupCode = JSON.stringify(provisioned)

// New device — install the blob (the device keys are carried inside it).
const installed = await installProvisionedDevice(JSON.parse(setupCode))
```

To bound the device instead of cloning full access, pass a narrower `scope` — e.g. `{ ops: ["read", "list"], collections: ["chat"], paths: ["chat/rooms/general"] }` for a read-only single-room device. The server enforces it: a cap whose `ops` omit `write` synthesizes no `cap:write:*` role, so writes return 403. (Same `currentEpochByCollection` / `grantedScope` / `ttlSec` semantics as `assemblePairingBundle`, but `currentEpochByCollection` lives inside `opts` here.)

> **Security trade-off:** the new device's private keys are generated **off-device** and travel inside the blob, so whoever reads it owns a full clone of the device. Use one-way provisioning only over a channel you would trust with the collection keys themselves; prefer QR / relay when key exposure is a concern.

## 5. Same identity on every device (the simplest multi-device model)

Pairing and provisioning give each device its **own** key pair — which is what makes per-device revocation possible, but also what makes membership in *other people's* rooms hard to share (see below). The simplest alternative is to skip pairing entirely: **enter the same passphrase on every device.** `bootstrapRootIdentity` is deterministic, so every device re-derives the *identical* root identity — same `rootEdPub`, same `userId`, same Ed25519/X25519 key pair. Every device is therefore the **same principal and the same KEM recipient**, with no handshake, no bundle, and no server round-trip needed to reach parity.

### What this gives you for free

Because the identity is shared at the key level:

- **Authority** — every device can present any cap whose `sub` is your root key, *including member caps other owners issued to you*. (A request signature must verify against the cap's `sub`; a device with its own key pair fails that check and so cannot present a member cap minted to the root — there is no cap chaining. A shared-identity device holds the root key, so it can.)
- **Confidentiality** — every device can unwrap any CEK wrapped to your root KEM pubkey.
- **Survives the owner's epoch rotation.** When a room owner removes someone and rotates the epoch, they re-wrap the new CEK for the remaining recipients — you, by your root KEM. Every one of your devices re-derives that same KEM private key, so they all keep reading with **no re-keying**. A paired device, by contrast, holds a *different* KEM key that was never added to the owner's keyring; its CEK is a one-time snapshot from the pairing bundle and goes **stale** on the next rotation.

### What still has to travel to the new device

The passphrase reproduces the *identity*, not the *application state* layered on top of it:

- **Member caps from other owners** are signed JSON the owner handed you out-of-band. The example app keeps them in memory only (not server-stored), so a second device must be given the cap again (re-paste, or ask the owner to re-issue). An app that wants this automatic can persist the user's own cap-set in a user-owned collection that all their devices re-pull — an app convenience, not a protocol change.
- **The room list** is per-user client state (`starfish-rooms-<userId>` in `localStorage` in the example app), recovered automatically only in the same browser.

Rooms you **own** and rooms you are a **member** of behave identically here — the difference is the cap's scope, not where anything is stored.

### The trade-off

Sharing the identity is the simplest path to "every device sees the same thing," but it puts the **master key on every device**: there is **no per-device revocation** (every device shares one signing key and one KEM recipient, so neither revoking a cap nonce nor rotating a keyring can single one device out), and **losing any device compromises the whole account**. Choose it when the devices are all equally trusted (a phone + laptop you both control); choose pairing / provisioning when you need to revoke one device without re-keying the others — accepting that cross-owner membership then transfers only as a snapshot.

## 6. QR-in / auto-return (anonymous rendezvous)

QR pairing (§2) has the camera on the **root** device scan the **new** device's QR — which is exactly right when the new device has no camera (a desktop/laptop). The awkward half is the *return*: the root mints a `PairingBundle` that must travel back to the new device, but the new device is credential-less (no cap-cert yet) and so cannot read the owner-only `users/<id>/_devices`. This flow closes the loop **without a second scan or any polling**, by delivering the bundle through a small **anonymous, TTL'd rendezvous collection**.

```
new device (no camera)                      root device
──────────                                  ───────────
generate keys; qrNonce
show QR{devEdPub,devKemPub,scope,qrNonce} ─scan─►  parsePairingQr
   + "Added from root" trigger                     assemblePairingBundle(root, parsed, {…})
                                          ◄─push─   pushPairingBundle(anonClient, qrNonce, bundle)
[user clicks "Added from root"]
fetchPairingBundle(anonClient, qrNonce)
 → installPairingBundle(bundle, dev,
     { expectedQrNonce, expectedRootEdPub })  ✓
clearPairingBundle(anonClient, qrNonce)   (one-shot)
```

The new device writes nothing and runs no timer: it shows the QR and a button. After the root scans and pushes, the user clicks the button once, which does a **single** fetch + install. If the slot is still empty (clicked too early), `fetchPairingBundle` returns `null` so the UI can prompt a retry.

### Why a public slot is safe

The rendezvous needs only **delivery**, never confidentiality: the bundle's `wrappedCEKs` are already E2E-wrapped to the new device's KEM pubkey, and `installPairingBundle` verifies the root signature + `sub`/`subKem` + `qrNonce`. An eavesdropper who reads the slot cannot use the bundle (no device `edPriv` to sign requests, no `kemPriv` to unwrap CEKs); an attacker who writes a forged bundle is rejected at install (the root signature is unforgeable). Worst case is a denial of service, bounded by a short TTL and a rate limit.

### Pin the expected root

Without a pin, the new device trusts whatever root signed the bundle — so an attacker's *own* root could answer an open rendezvous and provision the device into **their** account. Pass `expectedRootEdPub` (the account's known root pubkey) to `installPairingBundle` to reject a bundle from any other root. When the new device has no prior knowledge of the account, surface the bundle's `rootEdPub` fingerprint for the user to compare against the root device instead.

### The helpers + the collection

```ts
import {
  pushPairingBundle,    // root: write the bundle to the slot (last-write-wins, retries on conflict)
  fetchPairingBundle,   // new device: a single pull → PairingBundle | null
  clearPairingBundle,   // new device: best-effort one-shot overwrite after install
  rendezvousPathFor,    // storage path for a qrNonce: `_pairing/<hex(qrNonce)>`
} from "@drakkar.software/starfish-identities"
```

The rendezvous location derives from the QR's existing `qrNonce` (decoded to hex) — there is no new field in the QR, and `qrNonce` was never a secret. Both sides reach the slot with an **anonymous** client (no cap-cert): the new device has none, and an authenticated cap does not synthesize the `public` role the slot grants. The app/server owns the slot — a collection like:

```python
CollectionConfig(
    name="pairingrendezvous",
    storage_path="_pairing/{rendezvousId}",
    read_roles=["public"], write_roles=["public"],
    encryption="none",
    ttl_ms=300_000,          # short, self-expiring
    max_body_bytes=8_192,    # per-push cap
    # production: add a tight per-collection rate_limit
)
```

It is a **single document, last-write-wins** (so the new device can overwrite it with `{}` for one-shot cleanup). A deployment that assumes a hostile local network can instead make it `appendOnly` and have the new device enumerate candidates, at the cost of relying on TTL alone for cleanup. (Python: `push_pairing_bundle` / `fetch_pairing_bundle` / `clear_pairing_bundle` / `rendezvous_path_for`, and `install_pairing_bundle(..., expected_root_ed_pub=...)`.)

## Comparison

| | Bootstrap | QR | Relay | Provision | Rendezvous |
|---|---|---|---|---|---|
| Network round-trips | 0 | 0 | 2 (request push + response pull) | 0 | 2 (bundle push + single fetch) |
| Needs both devices online | n/a (single device) | No (offline channel) | Yes | No (offline channel) | No (TTL'd slot; new device fetches later) |
| Adversary in a position to harm | Anyone with the passphrase | Anyone in the room with the screen | Anyone who guesses the 6-digit code inside the TTL window | Anyone who reads the setup code (it carries private keys) | Anyone who can see the QR (DoS only via the open slot) |
| Per-device key generation | Same as root keys | Fresh on the new device | Fresh on the new device | Generated by the root, off-device | Fresh on the new device |
| Per-device revocation | ✗ (shared key) | ✓ | ✓ | ✓ | ✓ |
| Membership in others' rooms survives owner rotation | ✓ (same recipient) | ✗ (snapshot)¹ | ✗ (snapshot)¹ | ✗ (snapshot)¹ | ✗ (snapshot)¹ |
| Server sees | Nothing | Nothing | `{requestNonce, iv, ct}` | Nothing | The bundle (cap-cert + wrapped CEKs, opaque) |

¹ A paired / provisioned device receives the current CEK as a one-time snapshot; it is not a recipient in the owner's keyring, and a member cannot add it there, so the owner's next epoch rotation strands it. For rooms you own, you can add the device as a recipient yourself.

## Notes and limits

- Pairing only transfers the **current** epoch's CEK for each in-scope collection. Older epochs become readable when the new device is added as a recipient on the collection's `_keyring` (a separate operation — see [23. Multi-Recipient Delegated Encryption](23-multi-recipient-delegated.md) for the keyring helpers). If you want the new device to also read history, the root device must add it to past epochs before rotating.
- The cap-cert's `scope` is **never** defaulted from the attacker-influenceable `parsed.requestedScope`: `assemblePairingBundle` requires `opts.grantedScope` and throws without it. Pass the exact authority to grant (or call `mintDeviceCap` directly with a tighter `ScopePreset`). Because a `device` cap is a root proxy regardless of its `paths`, the requested scope must never be trusted blindly.
- The relay flow re-uses `requestNonce` as both the wire-format identifier and the PBKDF2 salt. Both sides MUST agree on its bytes; if you change the transport, preserve that identity.
- If you want a device to durably keep membership in *another owner's* room, share the identity (§5) rather than pair — a per-device key cannot be enrolled as a recipient in a room you do not own, so its bundle CEK goes stale on the owner's next rotation. Pairing is for devices acting under *your own* authority, where you control the keyring.

## Cross-language test vectors

- [`tests/test-vectors/identity-derivation.json`](../../../tests/test-vectors/identity-derivation.json) — passphrase → root keys → userId (used by `bootstrapRootIdentity`).
- [`tests/test-vectors/pairing-bundle.json`](../../../tests/test-vectors/pairing-bundle.json) — full QR pairing roundtrip: QR payload canonical form, minted cap-cert, wrapped CEK entries, install result.

## Next Steps

- [25. Capability Certificates](25-capability-certs.md) — cap-cert schema + validation
- [23. Multi-Recipient Delegated Encryption](23-multi-recipient-delegated.md) — keyring + recipient management
- [Migration: v2 to v3](../../migration/v2-to-v3.md) — how to migrate v2 deployments onto these flows
