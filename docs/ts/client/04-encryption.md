# Encryption

Starfish 3.0 ships **two** collection encryption modes — and nothing in between. The server never holds any encryption key.

> **Prerequisites:** [SyncManager](03-sync-manager.md), [Capability Certificates](25-capability-certs.md)

## The two modes

| `encryption` | What the server stores | Who can decrypt |
|--------------|------------------------|-----------------|
| `"none"` | Plaintext JSON | Anyone the access rules let read |
| `"delegated"` | AES-256-GCM ciphertext + a plaintext `_keyring` document listing recipient wraps | Every device or member whose X25519 pubkey appears in the keyring |

`"delegated"` is the only end-to-end encrypted mode. It supersedes the v2 `"identity"`, `"server"`, and `"group"` modes, all of which leaked the key to the server in one way or another.

## How `"delegated"` works

Each collection with `encryption: "delegated"` carries two kinds of documents on the server:

- **Data documents** — opaque `{_encrypted: "base64(IV || AES-256-GCM ciphertext)", _epoch: N}`.
- **One keyring document** at `<storagePath>/_keyring` — plaintext list of per-recipient X25519 wrap entries. The server sees who has access, never the key itself.

The keyring carries one **Content Encryption Key (CEK)** per epoch. Every wrap entry uses fresh ephemeral ECDH (HPKE-DHKEM style) plus HKDF-SHA256 plus AES-GCM, signed by the granting device's Ed25519 key for audit. Rotating the epoch invalidates access for any recipient not present in the new epoch.

The full schema, wrap algorithm, lifecycle helpers, and forward-secrecy stance live in [23. Multi-Recipient Delegated Encryption](23-multi-recipient-delegated.md).

## Wiring a `SyncManager`

The encryptor for a delegated collection is built from the keyring document plus the device's X25519 key pair (recovered at pair time — see [24. Pairing](24-pairing.md)).

```ts
import { StarfishClient, SyncManager, createKeyringEncryptor, type Keyring } from "@drakkar.software/starfish-client"

// `client` is a v3 StarfishClient wired with a CapProvider (see 25-capability-certs.md).
// `device` is the per-device key pair recovered from bootstrap / pairing.

const keyring = (await client.pull("notes/_keyring")).data as Keyring
const encryptor = await createKeyringEncryptor(keyring, {
  kemPubHex: device.kemPub,
  kemPrivHex: device.kemPriv,
})

const sync = new SyncManager({
  client,
  pullPath: `/pull/notes/${userId}`,
  pushPath: `/push/notes/${userId}`,
  encryptor,
})

await sync.push({ items: ["note 1", "note 2"] })   // payload sealed under currentEpoch
await sync.pull()                                    // decrypts every epoch the device can unwrap
```

`createKeyringEncryptor` pre-unwraps every epoch the device has a wrap for. Decryption automatically selects the matching epoch from the document's `_epoch` field, falling back to `currentEpoch` when absent. A document encrypted under an epoch the device was added after — or removed before — fails decryption with an explicit error.

## What gets encrypted

| Data | Encrypted? | Notes |
|------|------------|-------|
| Document `data` | Yes | Full document sealed as a single AES-GCM blob |
| `hash`, `timestamp`, `baseHash` | No | Computed by the server over the ciphertext |
| Auth headers (`Authorization: Cap`, `X-Starfish-Sig`, …) | No | Plaintext on the wire — signed, not encrypted |
| Keyring document | No | Plaintext: list of recipients + their wrapped CEK entries |

The server can never read, index, or query the plaintext `data`.

## Server side

Collections opt in via their `encryption` field; nothing else changes server-side.

```ts
// SyncConfig
{
  name: "notes",
  storagePath: "notes/{identity}",
  readRoles:  ["cap:read:notes"],
  writeRoles: ["cap:write:notes"],
  encryption: "delegated",
  maxBodyBytes: 65_536,
  allowedMimeTypes: ["application/json"],
  // Optional: override the default `<storagePath>/_keyring` keyring location.
  // keyringPath: "notes/_keyring",
}
```

For server configuration details see [Config Endpoint](../server/config-endpoint.md). For the cap-cert auth model that produces those `cap:<op>:<collection>` roles, see [25. Capability Certificates](25-capability-certs.md).

## Choosing between the modes

- **`"none"`** — plaintext collections. Use for public data, server-managed indexes, anything that does not need confidentiality from the server operator.
- **`"delegated"`** — every collection where the server must not see the plaintext. Single-device, multi-device, or multi-user — the keyring scales to N recipients without a separate mode.

There is no longer a separate "single-passphrase" or "group" mode: the keyring fits both shapes.

## Next Steps

- [Multi-Recipient Delegated Encryption](23-multi-recipient-delegated.md) — keyring schema, wrap algorithm, epoch rotation, FS stance
- [Capability Certificates](25-capability-certs.md) — cap-cert minting + the server-side `createCapCertRoleResolver`
- [Pairing](24-pairing.md) — bootstrap + QR + relay flows that hand the device its key pair and the initial CEK
- [Identity & Key Derivation](11-identity-key-derivation.md) — how the root identity (and therefore the X25519 KEM key) is derived from the passphrase
