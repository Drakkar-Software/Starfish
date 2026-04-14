# Binary Collections

By default every Starfish collection stores JSON documents. Setting `allowedMimeTypes` to anything other than `"application/json"` switches the collection to **binary mode**: the server stores raw bytes instead of a structured document, and the client uses `pullBlob` / `pushBlob` (TypeScript) or `pull_blob` / `push_blob` (Python) instead of `pull` / `push`.

Typical uses: user avatars, PDF attachments, audio files, pre-built WASM modules, or any opaque binary asset.

> **Prerequisites:** [StarfishClient](02-starfish-client.md), [Collection Patterns](19-collection-patterns.md)

---

## Server configuration

```ts
// TypeScript server config
{
  name: "avatars",
  storagePath: "users/{identity}/avatar",
  readRoles: ["self"],
  writeRoles: ["self"],
  encryption: "none",           // required — binary collections cannot be encrypted
  maxBodyBytes: 2_097_152,      // 2 MB limit
  allowedMimeTypes: ["image/*"], // accept any image type
}
```

```python
# Python server config
CollectionConfig(
    name="avatars",
    storage_path="users/{identity}/avatar",
    read_roles=["self"],
    write_roles=["self"],
    encryption="none",            # required — binary collections cannot be encrypted
    max_body_bytes=2_097_152,     # 2 MB limit
    allowed_mime_types=["image/*"],  # accept any image type
)
```

### `allowedMimeTypes` patterns

| Pattern | Matches |
|---|---|
| `"image/png"` | Exactly `image/png` |
| `"image/*"` | Any image subtype |
| `"application/pdf"` | PDF only |
| `"*/*"` | Any content type |

The server returns **415 Unsupported Media Type** if the `Content-Type` header doesn't match.

### Constraints

- `encryption` must be `"none"` or `"delegated"` — `"identity"`, `"server"`, and `"group"` are rejected by the config validator
- `objectSchema`, `bundle`, `remote`, and `queueOnly` cannot be combined with binary collections
- The `GET /config` endpoint exposes `allowedMimeTypes` so clients can discover it at runtime

---

## Client API

### TypeScript

```ts
import { StarfishClient } from "@drakkar.software/starfish-client"

const client = new StarfishClient({
  baseUrl: "https://api.example.com/v1",
  auth: async () => ({ Authorization: `Bearer ${token}` }),
})

// ── Push a file upload ──────────────────────────────────────────────────────

// From a browser File / Blob
async function uploadAvatar(file: File) {
  const result = await client.pushBlob(
    `/push/users/${userId}/avatar`,
    file,
    file.type,          // e.g. "image/jpeg"
  )
  console.log("stored hash:", result.hash)
}

// From an ArrayBuffer (e.g. canvas.toBlob)
async function uploadPng(buffer: ArrayBuffer) {
  await client.pushBlob(
    `/push/users/${userId}/avatar`,
    buffer,
    "image/png",
  )
}

// ── Pull and display ────────────────────────────────────────────────────────

async function loadAvatar(): Promise<string> {
  const result = await client.pullBlob(`/pull/users/${userId}/avatar`)
  // result.data      → ArrayBuffer
  // result.hash      → SHA-256 hex from ETag header (null if server omitted it)
  // result.contentType → e.g. "image/jpeg"

  const blob = new Blob([result.data], { type: result.contentType })
  return URL.createObjectURL(blob)   // use as <img src=...>
}
```

### Python

```python
from starfish_sdk import StarfishClient

async with StarfishClient("https://api.example.com/v1", auth=auth) as client:
    # Push bytes
    with open("avatar.png", "rb") as f:
        data = f.read()

    result = await client.push_blob(
        f"/push/users/{user_id}/avatar",
        data,
        "image/png",
    )
    print("stored hash:", result.hash)

    # Pull bytes
    blob = await client.pull_blob(f"/pull/users/{user_id}/avatar")
    # blob.data         → bytes
    # blob.hash         → SHA-256 hex from ETag header (None if server omitted it)
    # blob.content_type → e.g. "image/png"

    with open("downloaded.png", "wb") as f:
        f.write(blob.data)
```

---

## Conflict model

Binary collections do **not** use hash-based conflict detection. Every push unconditionally overwrites the stored bytes — there is no `baseHash` parameter.

This is the correct model for most binary assets: user avatars, thumbnails, and generated files are naturally last-write-wins. If you need versioning (e.g. allow a user to revert to a previous logo), use a versioned path pattern like `logos/{versionId}` so each push targets a new key rather than overwriting.

---

## Caching

Set `cacheDurationMs` to add a `Cache-Control` header to pull responses:

```ts
{
  name: "avatars",
  storagePath: "users/{identity}/avatar",
  readRoles: ["public"],
  writeRoles: ["self"],
  encryption: "none",
  maxBodyBytes: 2_097_152,
  allowedMimeTypes: ["image/*"],
  cacheDurationMs: 3_600_000,   // 1 hour; adds Cache-Control: max-age=3600
}
```

Pull responses also include an `ETag` header containing the SHA-256 of the stored bytes. Clients can use this for conditional requests (`If-None-Match`) to avoid re-downloading unchanged assets.

---

## Public read-only assets

To serve files that anyone can read but only certain roles can write (e.g. brand logos):

```ts
{
  name: "logo",
  storagePath: "brand/logo",
  readRoles: ["public"],
  writeRoles: ["admin"],
  encryption: "none",
  maxBodyBytes: 1_048_576,
  allowedMimeTypes: ["image/png", "image/svg+xml"],
  cacheDurationMs: 86_400_000,   // 24 hours
}
```

Because `readRoles` contains `"public"`, the `Cache-Control` header is emitted without the `private` directive, making CDN caching safe.

---

## What binary collections cannot do

| Feature | Available? |
|---|---|
| Incremental sync (checkpoint) | No — always returns full bytes |
| Hash-based conflict detection | No — last-write-wins |
| Server-side encryption | No (`encryption` must be `"none"` or `"delegated"`) |
| Group encryption | No |
| JSON Schema validation | No |
| Field-level permissions | No |
| Replica / remote collections | No |
| `queueOnly` | No |

---

## Related

- [StarfishClient](02-starfish-client.md) — `pullBlob` / `pushBlob` method signatures
- [Collection Patterns](19-collection-patterns.md) — JSON collection design patterns
- [Group Encryption](21-group-encryption.md) — incompatible with binary collections
