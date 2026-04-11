# Storage Backends

Starfish's `ObjectStore` interface abstracts over any key/value store. The library ships two built-in implementations: an in-process filesystem store for development and a self-hosted node, and an S3-compatible store for production deployments.

## FilesystemObjectStore

Stores every document as a file on disk. Suitable for single-node deployments, local development, and the Ansible-based server role.

**Import path**: `@drakkar.software/starfish-server/node`

```ts
import { FilesystemObjectStore } from "@drakkar.software/starfish-server/node"

const store = new FilesystemObjectStore({ baseDir: "/var/lib/starfish/data" })
```

| Option | Type | Description |
|--------|------|-------------|
| `baseDir` | `string` | Root directory where objects are stored. Created automatically if absent. |

## S3ObjectStore

Stores documents in any S3-compatible object store (AWS S3, MinIO, Cloudflare R2, Tigris, etc.). Suitable for horizontally-scaled or serverless deployments.

**Import path**: `@drakkar.software/starfish-server/s3`

**Peer dependency**: `@aws-sdk/client-s3 >= 3.0.0` must be installed separately.

```sh
npm install @aws-sdk/client-s3
```

```ts
import { S3ObjectStore } from "@drakkar.software/starfish-server/s3"

const store = new S3ObjectStore({
  accessKeyId: process.env.S3_ACCESS_KEY_ID!,
  secretAccessKey: process.env.S3_SECRET_ACCESS_KEY!,
  endpoint: "https://s3.amazonaws.com",
  bucket: "my-starfish-bucket",
  region: "us-east-1",
})
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `accessKeyId` | `string` | — | AWS / S3-compatible access key ID |
| `secretAccessKey` | `string` | — | AWS / S3-compatible secret access key |
| `endpoint` | `string` | — | Base URL of the S3 service |
| `bucket` | `string` | — | Bucket name |
| `region` | `string` | `"us-east-1"` | AWS region |
| `forcePathStyle` | `boolean` | `true` | Use path-style addressing (required for MinIO and most non-AWS services) |

### Cleanup

Call `store.destroy()` on shutdown to release the underlying HTTP connections:

```ts
process.on("SIGTERM", () => {
  store.destroy()
  process.exit(0)
})
```

### MinIO example

```ts
const store = new S3ObjectStore({
  accessKeyId: "minioadmin",
  secretAccessKey: "minioadmin",
  endpoint: "http://localhost:9000",
  bucket: "starfish",
  region: "us-east-1",       // MinIO ignores this but it must be set
  forcePathStyle: true,       // required for MinIO
})
```

### Cloudflare R2 example

```ts
const store = new S3ObjectStore({
  accessKeyId: process.env.R2_ACCESS_KEY_ID!,
  secretAccessKey: process.env.R2_SECRET_ACCESS_KEY!,
  endpoint: `https://${process.env.CF_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  bucket: "starfish",
  forcePathStyle: false,      // R2 uses virtual-hosted-style
})
```

## MemoryObjectStore

In-process store backed by a JavaScript `Map`. For unit tests only — data is lost on restart.

```ts
import { MemoryObjectStore } from "@drakkar.software/starfish-server"

const store = new MemoryObjectStore(new Map())
```

## Bring your own store

Implement the `ObjectStore` interface to plug in any backend:

```ts
import type { ObjectStore } from "@drakkar.software/starfish-server"

class MyStore implements ObjectStore {
  async getString(key: string) { ... }
  async put(key: string, body: string) { ... }
  async listKeys(prefix: string) { ... }
  async delete(key: string) { ... }
  async deleteMany(keys: string[]) { ... }
}
```
