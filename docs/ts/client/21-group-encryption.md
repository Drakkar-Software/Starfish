# Group Encryption

Group encryption lets multiple users share an encrypted collection without sharing a single passphrase. Each member holds their own credentials; a shared Group Encryption Key (GEK) is distributed per-member using X25519 ECDH key agreement.

> **Prerequisites:** [Encryption](04-encryption.md), [Identity & Key Derivation](11-identity-key-derivation.md)

---

## Overview

Standard delegated encryption works by having all members derive the same AES key from the same passphrase. This is simple but coarse: you cannot revoke one member without redistributing a new passphrase to everyone.

Group encryption separates **data encryption** (AES-256-GCM, unchanged) from **key distribution** (new ECDH-based per-member wrapping):

```
Each member: X25519 key pair (derived deterministically from their passphrase)
                        │
             ECDH(admin_priv, member_pub) → shared secret
                        │
                  HKDF → AES wrapping key
                        │
                  AES-GCM encrypt GEK → wrapped blob stored in keyring
                        │
             Member unwraps GEK with their own private key
                        │
                   GEK → createEncryptor() → Encryptor
                        │
            { _encrypted: "...", _epoch: N }
```

The server stores opaque `{ _encrypted: "..." }` blobs — identical to `"delegated"` mode. No new server capabilities are needed.

---

## Key pair derivation

Each user derives an X25519 key pair deterministically from their passphrase and userId. Same inputs always produce the same key pair on any device — no private key storage required.

```ts
import { deriveGroupKeyPair } from "@drakkar.software/starfish-client/group"

const kp = await deriveGroupKeyPair(passphrase, userId)
// => { privateKey: "hex...", publicKey: "hex..." }
```

Or use `deriveCredentials`, which now includes the group key pair automatically:

```ts
import { deriveCredentials } from "@drakkar.software/starfish-client/identity"

const creds = await deriveCredentials(passphrase)
// creds.groupPublicKey  — safe to publish
// creds.groupPrivateKey — derived deterministically; no need to store it.
//                         Re-derive it any time from the same passphrase.
```

---

## Server configuration

Set `encryption: "group"` on the collection. This behaves identically to `"delegated"` on the server — full fetch mode, opaque blobs, no incremental sync.

```ts
// server/config.ts
const config: SyncConfig = {
  version: 1,
  collections: [
    // Keyring document — admin-managed, group-readable
    {
      name: "keyring",
      storagePath: "groups/{groupId}/keyring",
      readRoles: ["group-member"],
      writeRoles: ["group-admin"],
      encryption: "none",          // keyring is plaintext (wrapped keys are ciphertext)
      maxBodyBytes: 65_536,
      allowedMimeTypes: ["application/json"],
    },
    // Shared encrypted data
    {
      name: "notes",
      storagePath: "groups/{groupId}/notes",
      readRoles: ["group-member"],
      writeRoles: ["group-member"],
      encryption: "group",          // client handles encryption via GroupEncryptor
      maxBodyBytes: 1_048_576,
      allowedMimeTypes: ["application/json"],
    },
  ],
}
```

**Validation rules for `"group"` encryption:**
- Cannot be used on public collections (`readRoles: ["public"]`)
- Cannot be used with binary collections (non-JSON `allowedMimeTypes`)
- Cannot be used on remote (pull-only) collections

### Granting roles

`createGroupRoleEnricher` grants `"group-member"` to any user whose identity appears in the members document. The `"group-admin"` role must be granted separately — typically in your `roleResolver`:

```ts
async function roleResolver(c: Context): Promise<AuthResult> {
  const userId = getUserIdFromToken(c)
  const roles: string[] = ["user"]
  // Grant group-admin to known administrators
  if (isGroupAdmin(userId)) {
    roles.push("group-admin")
  }
  return { identity: userId, roles }
}
```

Alternatively, maintain a separate `groups/{groupId}/admins` document and read it in a custom `roleEnricher` alongside `createGroupRoleEnricher`.

---

## Admin: creating a group

The admin generates the keyring and distributes it. Each member's public key must be collected first (e.g., from a `keys/{identity}` collection each member pushes their public key to).

```ts
import {
  deriveGroupKeyPair,
  generateGroupKey,
  createGroupKeyring,
} from "@drakkar.software/starfish-client/group"

// Collect member public keys (from your key-exchange collection)
const memberPublicKeys: Record<string, string> = {
  alice: alicePubKey,
  bob:   bobPubKey,
}

const adminKp = await deriveGroupKeyPair(adminPassphrase, adminUserId)
const { keyring, gek } = await createGroupKeyring(adminKp, memberPublicKeys)

// Push keyring to Starfish (admin client)
await adminSyncManager.push(keyring)

// The admin MUST keep `gek` to add future members.
// Store it securely (e.g., encrypted in the admin's private vault).
```

---

## Member: joining and reading/writing

```ts
import {
  deriveGroupKeyPair,
  GroupKeyring,
  createGroupEncryptor,
} from "@drakkar.software/starfish-client/group"
import { SyncManager } from "@drakkar.software/starfish-client"

// Pull the keyring document
const keyringSync = new SyncManager({ client, pullPath: `/pull/groups/${groupId}/keyring`, ... })
await keyringSync.pull()
const keyringData = GroupKeyring /* parse */ // cast keyringSync.getData()

const myKp = await deriveGroupKeyPair(myPassphrase, myUserId)
const encryptor = await createGroupEncryptor(keyringData, myUserId, myKp.privateKey)

// Use the encryptor with the shared data collection
const notesSync = new SyncManager({
  client,
  pullPath: `/pull/groups/${groupId}/notes`,
  pushPath: `/push/groups/${groupId}/notes`,
  encryptor,  // <-- pass in instead of encryptionSecret/encryptionSalt
})

await notesSync.pull()
const notes = notesSync.getData()

await notesSync.push({ ...notes, entries: [...notes.entries, newNote] })
```

---

## Adding a new member

Only the admin can add members. The admin needs the current GEK (saved from `createGroupKeyring` or `rotateGroupKey`).

```ts
import { addGroupMember } from "@drakkar.software/starfish-client/group"

const adminKp = await deriveGroupKeyPair(adminPassphrase, adminUserId)

// Pull current keyring
await keyringSync.pull()
const keyring = keyringSync.getData() as GroupKeyring

const updatedKeyring = await addGroupMember(
  keyring,
  adminKp,
  currentGek,      // must be kept by admin
  "charlie",
  charliePubKey,
)

// Push updated keyring
await adminKeyringSync.push(updatedKeyring)
```

The new member can read all existing documents (same epoch) and new documents going forward.

---

## Removing a member (key rotation)

To revoke a member's access to **future** documents, rotate the group key. This creates a new epoch with a new GEK, distributed only to the remaining members.

```ts
import { rotateGroupKey } from "@drakkar.software/starfish-client/group"

const adminKp = await deriveGroupKeyPair(adminPassphrase, adminUserId)

const remainingMembers: Record<string, string> = {
  alice: alicePubKey,
  // bob is excluded — they lose access to new documents
}

const { keyring: rotatedKeyring, gek: newGek } = await rotateGroupKey(
  currentKeyring,
  adminKp,
  remainingMembers,
)

// Push rotated keyring
await adminKeyringSync.push(rotatedKeyring)

// Save newGek securely — needed to add future members to epoch 2+
```

**Important:** The removed member retains their epoch-1 key and can still decrypt epoch-1 documents. This is the same tradeoff as Signal and MLS — re-encrypting all historical data is impractical. Rotate early when membership is stable.

---

## Epoch-aware decryption

Each encrypted document stores its epoch:

```json
{ "_encrypted": "base64(IV || ciphertext)", "_epoch": 2 }
```

`createGroupEncryptor` automatically:
- **Encrypts** using the current epoch's GEK
- **Decrypts** using whichever epoch the document carries

A member who was added in epoch 2 can decrypt epoch-2 documents but not epoch-1 documents (they have no epoch-1 key).

---

## API reference

### `deriveGroupKeyPair(passphrase, userId)`

Derives a deterministic X25519 key pair. Same inputs → same keys on any device.

| Parameter | Type | Description |
|-----------|------|-------------|
| `passphrase` | `string` | User's passphrase |
| `userId` | `string` | User's identity string |

Returns `Promise<GroupKeyPair>` with `{ privateKey: string; publicKey: string }` (hex-encoded).

### `generateGroupKey()`

Generates a cryptographically random 256-bit GEK as a hex string.

### `wrapGroupKey(gek, memberPublicKey, wrapperPrivateKey)`

Encrypts the GEK for a member using ECDH. Returns `base64(IV || AES-GCM-ciphertext)`.

### `unwrapGroupKey(wrapped, memberPrivateKey, adminPublicKey)`

Decrypts a wrapped GEK. Returns the hex GEK string, or throws on invalid tag.

### `createGroupKeyring(adminKeyPair, members, gek?)`

Creates epoch-1 keyring with the given members. Generates a random GEK if `gek` is omitted.

Returns `Promise<{ keyring: GroupKeyring; gek: string }>`.

### `addGroupMember(keyring, adminKeyPair, currentGek, newMemberId, newMemberPublicKey)`

Adds a member to the current epoch without rotating. Admin must provide their key pair and the current GEK.

Returns `Promise<GroupKeyring>`.

### `rotateGroupKey(keyring, adminKeyPair, remainingMembers, newGek?)`

Creates a new epoch with a new GEK for remaining members only.

Returns `Promise<{ keyring: GroupKeyring; gek: string }>`.

### `createGroupEncryptor(keyring, myIdentity, myPrivateKey)`

Unwraps GEKs for all epochs the caller has access to. Returns a multi-epoch `Encryptor` that can be passed directly to `SyncManager`.

---

## Python equivalent

The Python `starfish-sdk` ships an identical API under `starfish_sdk.group`:

```python
from starfish_sdk.group import (
    derive_group_key_pair, create_group_keyring,
    add_group_member, rotate_group_key, create_group_encryptor,
    GroupKeyring,
)
```

Cross-language compatibility is verified by shared test vectors in `tests/test-vectors/group-crypto.json` — documents encrypted in TypeScript can be decrypted in Python and vice versa.

---

## Security considerations

- **Private key secrecy**: `groupPrivateKey` (and the raw GEK) must never be sent to the server or stored in plaintext. Store in the user's private vault (`encryption: "delegated"`) or derive on-device from their passphrase.
- **Key publication**: `groupPublicKey` is safe to publish. Store in a `keys/{identity}` collection so the admin can fetch it before wrapping.
- **GEK custody**: The admin must retain the raw GEK after `createGroupKeyring`/`rotateGroupKey`. Without it, adding new members requires re-wrapping from scratch (rotate instead).
- **Epoch history**: Removed members retain old-epoch keys and can read documents encrypted before the rotation. Minimize the blast radius by rotating frequently and keeping documents short-lived.

## Next Steps

- [Encryption](04-encryption.md) — standard delegated encryption
- [Collection Patterns](19-collection-patterns.md) — group chat patterns (Pattern 6 + encrypted variant)
- [Group Access](../server/group-access.md) — role-based group membership on the server
- [Identity & Key Derivation](11-identity-key-derivation.md) — credential derivation from passphrase
