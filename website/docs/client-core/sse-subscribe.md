---
sidebar_position: 5
---

# SSE Subscribe Transport (`@drakkar.software/starfish-client/events`)

Real-time change notifications from a starfish server use Server-Sent Events (SSE).
The `/events` subpath export provides `subscribeChanges` — a typed auto-reconnecting
subscriber — plus low-level helpers for use in custom transports.

## Quick start

```ts
import { subscribeChanges } from "@drakkar.software/starfish-client/events"

const unsub = subscribeChanges<{ type: string; payload: unknown }>({
  url: "https://api.example.com/v1/myapp/events/spaces/sp-123",
  onMessage(event) {
    console.log("change:", event)
  },
  onStatus(status) {
    // 0 = connecting, 200 = connected, negative = reconnect backoff
    console.log("status:", status)
  },
})

// Later:
unsub()
```

## Signed events URL

When the server requires a signed request for the events endpoint, use
`buildSignedEventsUrl` to construct the correct URL from a client base URL and a
collection path:

```ts
import {
  subscribeChanges,
  buildSignedEventsUrl,
} from "@drakkar.software/starfish-client/events"

const url = buildSignedEventsUrl(
  "https://api.example.com/v1/myapp/events",
  { since: Date.now() - 60_000 },
  "myapp",  // optional namespace — strip if already in eventsUrl
)
```

## Auto-reconnect and backoff

`subscribeChanges` automatically reconnects after:
- A `fetch` network error (offline, DNS, timeout)
- A server close / unexpected stream end
- Any non-200 response (the status is passed to `onStatus` as the HTTP code)

Reconnect delay uses capped exponential backoff:
- Initial delay: `initialBackoffMs` (default 500 ms)
- Each failure doubles the delay
- Cap: `maxBackoffMs` (default 30 000 ms = 30 s)
- Delay is jittered ±15 % to prevent thundering-herd

## Options reference

```ts
interface SubscribeChangesOptions<T> {
  /** SSE endpoint URL (string) or a factory called on each reconnect. */
  url: string | (() => string)
  /** Called for each parsed event data object. */
  onMessage: (event: T) => void
  /** Called with the HTTP status on connection attempt (0 = connecting). */
  onStatus?: (status: number) => void
  /** Extra request headers (e.g. Authorization). */
  headers?: Record<string, string>
  /** Override the global `fetch`. */
  fetch?: typeof globalThis.fetch
  /** Initial reconnect delay in ms. Default 500. */
  initialBackoffMs?: number
  /** Max reconnect delay in ms. Default 30_000. */
  maxBackoffMs?: number
}
```

`subscribeChanges` returns an **unsubscribe function** — call it to stop listening and
prevent any further reconnects.

## Low-level frame parser

`parseSseFrames(chunk, carry)` is exposed for testing and custom transport wiring:

```ts
import { parseSseFrames } from "@drakkar.software/starfish-client/events"

let carry = ""
for await (const chunk of stream) {
  const [frames, nextCarry] = parseSseFrames(chunk, carry)
  carry = nextCarry
  for (const frame of frames) {
    process(frame)
  }
}
```

Each returned `frame` is a parsed JSON object from the `data:` field.
Multi-line `data:` blocks are joined with `\n`. Comment lines (`:`) and
`id:`/`event:` lines are ignored.

## Subpath export

The `/events` subpath is intentionally separate from the main `starfish-client`
entry point so bundlers can tree-shake it:

```ts
// Main entry — no SSE code included
import { StarfishClient } from "@drakkar.software/starfish-client"

// SSE code — separate chunk
import { subscribeChanges } from "@drakkar.software/starfish-client/events"
```
