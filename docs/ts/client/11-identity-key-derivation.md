# Identity & Key Derivation

Patterns for deriving authentication tokens and encryption keys from user credentials.

> **Prerequisites:** [StarfishClient](02-starfish-client.md), [Encryption](04-encryption.md)

## Auth Provider Patterns

The `AuthProvider` is your integration point for any authentication scheme. It receives request metadata and returns HTTP headers.

### Bearer Token (OAuth / JWT)

```ts
const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async () => ({
    Authorization: `Bearer ${await getAccessToken()}`,
  }),
})
```

The auth function is called on every request, so it can refresh expired tokens dynamically.

### Static API Key

```ts
auth: () => ({ "X-API-Key": apiKey })
```

### Password-Derived Token

Derive a deterministic token from a user password so the same password always produces the same identity:

```ts
async function deriveAuthToken(password: string): Promise<string> {
  const encoded = new TextEncoder().encode(password.trim())
  const hash = await crypto.subtle.digest("SHA-256", encoded)
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
}

const token = await deriveAuthToken(userPassword)
const userId = token.slice(0, 16)

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: () => ({ Authorization: `Bearer ${token}` }),
})
```

This allows multiple devices to derive the same token independently — no account creation or server-side registration needed.

## Encryption Key Derivation

### From a Password

Derive `encryptionSecret` from a user password, using a unique salt:

```ts
async function deriveEncryptionKey(password: string, salt: string): Promise<string> {
  const encoded = new TextEncoder().encode(`${password.trim()}:${salt}`)
  const hash = await crypto.subtle.digest("SHA-256", encoded)
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
}

const encryptionKey = await deriveEncryptionKey(userPassword, userId)

const sync = new SyncManager({
  client,
  pullPath: `/pull/users/${userId}/data`,
  pushPath: `/push/users/${userId}/data`,
  encryptionSecret: encryptionKey,
  encryptionSalt: userId,
})
```

### Key Derivation Chain

A common pattern derives both auth and encryption from a single secret:

```
password / passphrase
├── authToken = SHA-256(password)              → Bearer header
├── userId = authToken.slice(0, 16)            → server path + encryption salt
└── encryptionKey = SHA-256(password:userId)   → passed to SyncManager
```

Each derived value serves a different purpose, and the chain is deterministic — any device with the password can reconstruct all keys.

### From a Passphrase

Generate a human-readable passphrase for sharing:

```ts
function generatePassphrase(wordList: string[], wordCount = 12): string {
  const bytes = crypto.getRandomValues(new Uint8Array(wordCount))
  return Array.from(bytes)
    .map((b) => wordList[b % wordList.length])
    .join("-")
}

// "apple-arrow-atlas-bridge-canyon-drift-ember-frost-grove-haven-ivory-jade"
```

Users share the passphrase to grant access. Each device derives the same keys from it.

## Salt Best Practices

The `encryptionSalt` should be unique per user (or per collection) to ensure different keys even if two users share the same password:

| Salt Source | Example | Use Case |
|-------------|---------|----------|
| User ID | `userId` | One collection per user |
| User ID + collection | `${userId}:settings` | Multiple collections with different keys |
| Auth token prefix | `authToken.slice(0, 16)` | Derived from the same password |

## Key Rotation

To rotate encryption keys (e.g., after a password change):

```ts
// 1. Pull and decrypt with the old key
const oldSync = new SyncManager({
  client, pullPath, pushPath,
  encryptionSecret: oldKey,
  encryptionSalt: oldSalt,
})
await oldSync.pull()
const data = oldSync.getData()

// 2. Push re-encrypted with the new key
const newSync = new SyncManager({
  client, pullPath, pushPath,
  encryptionSecret: newKey,
  encryptionSalt: newSalt,
})
await newSync.push(data)
```

## Sharing Encrypted Data

To share encrypted data between users, share the `(encryptionSecret, encryptionSalt)` pair. This works with the server's "delegated" encryption mode, where the server stores encrypted blobs without knowing the key.

Sharing methods:
- **Passphrase**: share a human-readable passphrase from which both values are derived
- **Deep link**: encode credentials in a URL (`app://join?token=base64(...)`)
- **QR code**: encode the passphrase or credentials

## Next Steps

- [Encryption](04-encryption.md) — how the keys are used for AES-256-GCM
- [Platform Setup](10-platform-setup.md) — crypto provider for React Native
