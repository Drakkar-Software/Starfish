---
sidebar_position: 7
---

# Anonymous (Cap-less) Public Append

Some collections are configured with `writeRoles: ["public"]` — anyone can append
elements to them without holding a capability certificate. The canonical use case is
a public invitation inbox: senders do not need an account on the server, but the
element still carries an Ed25519 **author proof** so recipients can verify who sent it.

## API

```ts
class StarfishClient {
  appendAnonymous(
    path: string,
    element: Record<string, unknown>,
    signer: { edPubHex: string; edPrivHex: string },
  ): Promise<{ timestamp: number }>
}
```

`appendAnonymous` sends a `POST` to the server with:
- The element payload under the `data` field
- An Ed25519 author proof (`authorPubkey` + `authorSignature`) computed via
  `signAppendAuthor` from `@drakkar.software/starfish-protocol`
- **No** `Authorization` header — the request is intentionally unauthenticated

On any non-2xx response an `AppendHttpError` is thrown (status code accessible via
`.status`).

## Usage

```ts
import { StarfishClient, AppendHttpError } from "@drakkar.software/starfish-client"

const client = new StarfishClient({ baseUrl: "https://api.example.com" })

// The sender uses their own Ed25519 key — no cap required.
try {
  await client.appendAnonymous(
    "/push/invitations/user-alice/2024-06",
    { type: "space-invite", spaceId: "sp-abc", from: "bob" },
    { edPubHex: myDevice.edPubHex, edPrivHex: myDevice.edPrivHex },
  )
} catch (e) {
  if (e instanceof AppendHttpError) {
    console.error("Server rejected anonymous append:", e.status, e.message)
  }
}
```

## Server verification

The server (or the recipient) verifies the author proof using `verifyAppendAuthor`
from `@drakkar.software/starfish-protocol`:

```ts
import { verifyAppendAuthor } from "@drakkar.software/starfish-protocol"

const ok = await verifyAppendAuthor(
  "invitations/user-alice/2024-06", // documentKey (no /push/ prefix)
  element.data,
  element.authorPubkey,
  element.authorSignature,
)
```

## Error handling

| Condition | Thrown |
|---|---|
| Non-2xx HTTP response | `AppendHttpError` (`.status` = HTTP status code) |
| Network error / timeout | `TypeError` from `fetch` |

`AppendHttpError` is exported from the main `@drakkar.software/starfish-client` entry point.

## vs. `append`

| | `append` | `appendAnonymous` |
|---|---|---|
| **Authorization** | Requires a cap (device credential) | None — unauthenticated |
| **Author proof** | Cap device key, auto-signed | Caller-provided Ed25519 key |
| **Collection type** | Any write-capable collection | `writeRoles: ["public"]` only |
| **Error type** | `StarfishHttpError` | `AppendHttpError` |
