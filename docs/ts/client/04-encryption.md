# Encryption

Starfish provides client-side end-to-end encryption using AES-256-GCM with HKDF-derived keys. The server never sees plaintext data.

> **Prerequisites:** [SyncManager](03-sync-manager.md)

## Overview

Encryption uses a two-layer design:

1. **Key derivation** — HKDF with SHA-256 derives a 256-bit AES key from `(secret, salt, info)`
2. **Encryption** — AES-256-GCM with a random 12-byte IV per operation

```
secret + salt + info
        │
        ▼
  HKDF-SHA256  ──►  256-bit AES-GCM CryptoKey
                            │
              plaintext ────┤
                            ▼
                    random IV (12 bytes)
                            │
                            ▼
              { _encrypted: "base64(IV || ciphertext)" }
```

## Using Encryption with SyncManager

Pass `encryptionSecret` and `encryptionSalt` — encryption is handled automatically:

```ts
const sync = new SyncManager({
  client,
  pullPath: `/pull/users/${userId}/notes`,
  pushPath: `/push/users/${userId}/notes`,
  encryptionSecret: "user-generated-secret",
  encryptionSalt: userId,
})

// push() encrypts automatically
await sync.push({ items: ["note 1", "note 2"] })

// pull() decrypts automatically
await sync.pull()
console.log(sync.getData()) // { items: ["note 1", "note 2"] }
```

The optional `encryptionInfo` parameter (default: `"starfish-e2e"`) is passed to HKDF as the info field. Change it to derive different keys from the same secret/salt pair.

## Standalone Encryptor

For encryption outside of SyncManager, use `createEncryptor`:

```ts
import { createEncryptor } from "@drakkar.software/starfish-client"

const encryptor = createEncryptor("my-secret", "user-abc")

const encrypted = await encryptor.encrypt({ hello: "world" })
// => { _encrypted: "base64..." }

const decrypted = await encryptor.decrypt(encrypted)
// => { hello: "world" }
```

### `createEncryptor(secret, salt, info?)`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `secret` | `string` | — | Encryption secret (must not be empty) |
| `salt` | `string` | — | Salt for key derivation (must not be empty) |
| `info` | `string` | `"starfish-e2e"` | HKDF info parameter |

Returns an `Encryptor`:

```ts
interface Encryptor {
  encrypt(data: Record<string, unknown>): Promise<Record<string, unknown>>
  decrypt(wrapper: Record<string, unknown>): Promise<Record<string, unknown>>
}
```

## Wire Format

Encrypted data is wrapped in a single `_encrypted` field containing base64-encoded bytes:

```json
{
  "_encrypted": "base64(IV[12 bytes] || AES-GCM-ciphertext)"
}
```

**Encrypt:**
1. JSON-serialize the document
2. Generate a random 12-byte IV
3. Encrypt with AES-256-GCM using the derived key
4. Concatenate: `IV || ciphertext`
5. Base64-encode the combined bytes
6. Wrap as `{ _encrypted: "<base64>" }`

**Decrypt:**
1. Read the base64 string from `_encrypted`
2. Decode to bytes
3. Split: first 12 bytes = IV, rest = ciphertext
4. Decrypt with AES-256-GCM
5. Parse JSON to recover the document

## What Gets Encrypted

| Data | Encrypted? | Notes |
|------|-----------|-------|
| Document contents (`data`) | Yes | The full document is encrypted as one blob |
| `hash` | No | Computed server-side on the encrypted payload |
| `timestamp` | No | Set by the server |
| `baseHash` | No | Hash of the encrypted payload, not plaintext |
| Auth headers | No | Sent as HTTP headers |

The server sees only `{ _encrypted: "..." }` — it cannot read, index, or query document contents.

## Key Derivation Details

Key derivation uses the Web Crypto HKDF algorithm:

```ts
// From starfish-protocol
async function deriveKey(secret: string, salt: string, info: string): Promise<CryptoKey>
```

1. Import `secret` as raw key material for HKDF
2. Derive a 256-bit AES-GCM key using:
   - Hash: SHA-256
   - Salt: UTF-8 encoded `salt`
   - Info: UTF-8 encoded `info`

The derived key is deterministic — same inputs always produce the same key. This allows multiple devices to derive the same key independently.

## Security Considerations

- **Secret strength**: Use a cryptographically strong secret (high entropy passphrase, derived key, or random bytes)
- **Salt uniqueness**: Use a different salt per user or per collection to prevent key reuse
- **Key rotation**: To rotate, pull and decrypt with the old key, then re-encrypt and push with the new key
- **IV uniqueness**: A fresh random IV is generated for every encrypt operation — no IV reuse
- **Tamper detection**: AES-GCM provides authenticated encryption. Tampering is detected on decryption (throws an error)

## Group Encryption

For multi-user encrypted collections (group chat, collaborative documents), where each member holds their own credentials and membership can be managed without sharing a passphrase, see [Group Encryption](21-group-encryption.md).

Group encryption uses X25519 ECDH key wrapping to distribute a shared Group Encryption Key (GEK) per-member. The server-side collection uses `encryption: "group"`, which behaves identically to `"delegated"`. The `createGroupEncryptor` helper returns an `Encryptor` that can be passed directly to `SyncManager`.

## Next Steps

- [Identity & Key Derivation](11-identity-key-derivation.md) — patterns for deriving secrets from passwords
- [SyncManager](03-sync-manager.md) — encryption integration in the sync lifecycle
- [Group Encryption](21-group-encryption.md) — per-member key wrapping for shared encrypted collections
