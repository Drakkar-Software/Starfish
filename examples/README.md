# Starfish v3.0 examples

Both TypeScript (`examples/ts/`) and Python (`examples/python/`) trees mirror
each other. Each file demonstrates one slice of the v3 surface.

## Full-stack app

[`examples/app/`](./app/) is a runnable end-to-end **chat app** — a Vite/React
frontend (zustand binding) + a FastAPI backend — that wires **six extensions**
together: identities (incl. multi-device pairing), keyring (E2E room), sharing
(read-only / read-write member invites), entitlements (client-side paid-feature
unlock via `pullEntitlements`), audit, and queuing (live updates over SSE). See
[`app/README.md`](./app/README.md) to run it.

## What's new in v3

* **Encryption modes**: only `"none"` and `"delegated"`. The server holds no
  encryption keys.
* **Identity**: a user's passphrase derives an Ed25519 (signing) + X25519 (KEM)
  root key pair via Argon2id → HKDF. `userId = sha256(rootEdPub)[0:32]`.
* **Authorization**: signed cap-certs (`kind: "device"` or `"member"`) instead
  of opaque bearer tokens.
* **Multi-recipient encrypted collections**: per-collection keyring document
  at `<collection>/_keyring` holds ECDH-wrapped CEKs.
* **Pairing**: three helper flows — `bootstrapRootIdentity` (first device),
  QR pairing (server-free), server-relay invite (code-derived).

## TypeScript

| File                       | Showcases                                                                  |
| -------------------------- | -------------------------------------------------------------------------- |
| `client.ts`                | Bootstrap → cap-provider → `StarfishClient` + `SyncManager`. Delegated encryption, conflict resolution, blobs, entitlements, public reads. |
| `server.ts`                | Hono + filesystem store. `createCapCertRoleResolver` + nonce cache + revocation store. Collections with `encryption: "none"` / `"delegated"`. |
| `server-cf-worker-r2.ts`   | Same wiring on Cloudflare Workers with native R2 binding.                  |
| `react-zustand.tsx`        | Cap-provider into Zustand-backed sync via `useSyncInit` and manual stores. |
| `react-legend.tsx`         | Cap-provider + KeyringEncryptor into Legend State observables.             |
| `pairing-qr.ts` (new)      | Server-free QR pairing: `buildPairingQr` / `parsePairingQr` / `assemblePairingBundle` / `installPairingBundle`. |
| `pairing-relay.ts` (new)   | Server-relay pairing with a 6-digit code: `buildPairingRequest` / `readPairingRequest` / `buildPairingResponse` / `readPairingResponse`. |
| `group-owner.ts` (new)     | Collection-owner pattern. Alice mints `kind: "member"` cap-certs for Bob/Carol and adds them via `addCollectionRecipient`. |
| `public-link.ts` (new)     | Public links: `createPublicLink` / `parsePublicLink` / `redeemPublicLink` — open (anyone) and allow-list-restricted `audience` caps with expiry. |

### Running TypeScript examples

```bash
# Install the SDK + any peer deps mentioned in each file's header comment.
npm install @drakkar.software/starfish-client \
            @drakkar.software/starfish-protocol \
            @drakkar.software/starfish-server \
            @noble/curves \
            hono @hono/node-server   # server-side
            react zustand @legendapp/state  # React examples

# Run any example with tsx.
npx tsx examples/ts/client.ts
npx tsx examples/ts/pairing-qr.ts
npx tsx examples/ts/group-owner.ts
npx tsx examples/ts/public-link.ts
```

### Type-checking the examples (optional)

A `tsconfig.json` in `examples/ts/` uses TypeScript path mapping to resolve
the packages directly from `packages/ts/<pkg>/src/`. After installing the
peer deps listed above, you can run:

```bash
cd examples/ts && npx tsc --noEmit -p tsconfig.json
```

The examples directory is intentionally **not** part of the pnpm workspace —
top-level `pnpm typecheck` only inspects `packages/ts/{protocol,client,server}`,
so example-only edits never break the package build pipeline.

## Python

| File                   | Showcases                                                       |
| ---------------------- | --------------------------------------------------------------- |
| `client.py`            | Mirror of `client.ts`.                                          |
| `server.py`            | Mirror of `server.ts` on FastAPI.                               |
| `pairing_qr.py` (new)  | Mirror of `pairing-qr.ts`.                                      |
| `pairing_relay.py` (new) | Mirror of `pairing-relay.ts`.                                 |
| `group_owner.py` (new) | Mirror of `group-owner.ts`.                                     |
| `public_link.py` (new) | Mirror of `public-link.ts`.                                     |

### Running Python examples

```bash
pip install starfish-sdk starfish-server fastapi uvicorn cryptography
python examples/python/client.py
python examples/python/pairing_qr.py
python examples/python/group_owner.py
python examples/python/public_link.py
uvicorn examples.python.server:app --reload
```

## Common v3 plumbing seen in every example

```ts
import {
  StarfishClient,
  SyncManager,
  bootstrapRootIdentity,
  createKeyring,
  createKeyringEncryptor,
  type StarfishCapProvider,
} from "@drakkar.software/starfish-client"

// 1. Derive root identity + self-signed device cap-cert.
const creds = await bootstrapRootIdentity("correct-horse-battery-staple")

// 2. Adapt creds → StarfishCapProvider.
const capProvider: StarfishCapProvider = {
  async getCap() {
    return { cap: creds.capCert, devEdPrivHex: creds.device.edPriv }
  },
}

// 3. StarfishClient signs every request automatically.
const client = new StarfishClient({ baseUrl: "https://api.example.com/v1", capProvider })

// 4. SyncManager unchanged from v2 — except `encryptor` now comes from a keyring.
const sync = new SyncManager({ client, pullPath: "...", pushPath: "..." })
```
