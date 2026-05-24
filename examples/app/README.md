# Starfish chat — full-stack example app

A small end-to-end chat app that exercises **six Starfish extensions** with the
smallest setup that still makes each one do real, observable work:

| Extension | Where | What it does here |
| --- | --- | --- |
| **identities** | frontend login + pairing; backend `identities_server_plugin` | passphrase → root identity → device cap; **three ways to add a 2nd device** — secure **two-way pairing** (`buildPairingQr`→`assemblePairingBundle`→`installPairingBundle`), camera-free **QR-in / auto-return** (new device shows a QR; root pushes the bundle back through an anonymous `_pairing/<id>` rendezvous slot via `pushPairingBundle`/`fetchPairingBundle`), and one-way **provisioning** (one setup code, keys minted on the first device, **optionally PIN-sealed** with `sealWithPassphrase`); **list & revoke** linked devices (`addDeviceEntry`/`listDevices`/`removeDeviceEntry` + a signed `RevocationList`) |
| **keyring** | frontend | each room is end-to-end encrypted under a multi-recipient keyring (`createKeyring`, `createKeyringEncryptor`, `addCollectionRecipient`); revoking a member/device drops them with `removeRecipient` (epoch rotation) |
| **sharing** | frontend invite; backend `sharing_server_plugin` | owner invites a member to a room **read-only or read/write** (`mintMemberCap`, `addMemberEntry`) and can **revoke** them (`removeMemberEntry` + recipient drop + signed `RevocationList`); a member can **leave** a room locally |
| **entitlements** | frontend `pullEntitlements` | a paid feature is unlocked **client-side** by the `premium` slug |
| **audit** | backend `CallbackAuditLogger` + `GET /audit` | every push is recorded and shown in a live panel |
| **queuing** | backend `create_queuing_server_plugin` + `CustomQueue` → SSE | message events fan out over SSE (carrying `roomId`) for live updates |

It also demonstrates two patterns built on core collections:

- **Multiple rooms** — each room is a document at `chat/rooms/<id>` with its own
  keyring and member directory; a member/device cap is scoped to one room. Owners
  can switch/create rooms; the header shows the current `#room`.
- **Profiles** — each user's pseudo lives at `user/<id>/profile`: **public read**
  (everyone sees pseudos) but **write-restricted to the user's main device** via
  the synthesized `device:root` role (`writeRoles=["device:root"]`) — only a
  self-signed root device cap earns it, so paired / one-way-provisioned devices
  and members get **403** on a profile edit even with `cap:write:*`. (`rootOnly`
  isn't used here: it would also make reads private; `device:root` in `writeRoles`
  keeps reads public.) Message authors are shown by their profile pseudo.

Stack: **Python / FastAPI** backend (filesystem store) + **Vite / React** frontend
using the **zustand** binding (`@drakkar.software/starfish-client/zustand`) for
offline-first browser persistence. The UI ("tidepool") is a real chat layout — a
rooms sidebar, message bubbles, a profile modal, and invite / devices / premium /
activity drawers. Display type is loaded from Google Fonts, so first paint needs
network access (the app works fully offline afterwards; the server only ever sees
ciphertext).

```
examples/app/
  backend/      FastAPI app — sync router + the 6 features + SSE + demo endpoints
  frontend/     Vite + React + zustand
```

## Run it

From the repo root (builds the workspace packages the frontend imports):

```bash
pnpm install && pnpm build
```

Backend (terminal 1):

```bash
cd examples/app/backend
uv sync
uv run uvicorn server:app --port 8000
```

Frontend (terminal 2):

```bash
cd examples/app/frontend
pnpm dev          # → http://localhost:5173
```

Open <http://localhost:5173>.

> **Tests:** this app doubles as an end-to-end regression harness for the full
> library — see [`TESTING.md`](./TESTING.md). Backend: `cd backend && uv run pytest`.

## Try the flows

Open the app in **two browser tabs with different passphrases**:

1. **Owner** — tab 1: on the **Open a room** tab enter a name + passphrase +
   **room** (default `general`), click **Open room**. The room + keyring are
   created and an empty encrypted room is seeded. Click your **profile chip**
   (bottom-left) to set a **pseudo** and **Save pseudo**. Send a message from the
   composer — others see it under your pseudo.
2. **Member (sharing, read/write)** — tab 2: on the **Join** tab enter a
   *different* passphrase, click **Continue**. You land on **Join a room** — copy
   your **invite code**. In tab 1 click **Invite** (room header), paste the code,
   choose **Read & write**, click **Mint member cap**, copy the result. Bob now
   appears in the drawer's **Members** list. Back in tab 2, paste the cap under
   **Member invite** → **Activate invite** (the room comes from the cap) → the
   member decrypts the history and can post. Messages sync **live** between tabs
   (queuing → SSE). **Revoke:** in tab 1's **Invite** drawer, each member has a
   **Revoke** button — it posts a signed `RevocationList` (the member's cap then
   gets **401**), rotates the keyring epoch so they can't decrypt new messages,
   and removes their directory entry. **Leave:** a member can click **Leave room**
   (room header) → **Confirm leave** to locally forget the room; this is
   client-only (members can't write the keyring/directory, so true removal is the
   owner's **Revoke**).
3. **Member (read-only)** — invite another identity choosing **Read-only**: it
   decrypts and reads, but the composer is **locked** and its push is rejected
   **403** — its member cap omits the `write` op, so it never gets `cap:write:chat`.
4. **Multiple rooms** — as owner, click **New room** in the sidebar and type an id
   (e.g. `random`). A fresh isolated room is created; `general`'s messages do not
   appear. Click between rooms in the sidebar; members of `general` cannot read
   `random` (cap scoped to one room).
5. **Profiles** — change your pseudo in the **profile modal** and **Save pseudo**;
   other users see the new pseudo on your messages. A member's chat-only cap
   **cannot** write any profile (403).
6. **Entitlements** — open the **Premium** drawer (💎 in the sidebar footer) and
   click **Unlock premium (demo grant)**: `pullEntitlements` re-reads your slugs
   and unlocks the paid panel. **Revoke premium** clears it.
7. **Audit** — open the **Activity** drawer (sidebar footer) to watch every push
   recorded server-side with the caller's identity and status.
8. **Multi-device (identities)** — the simplest option needs no pairing at all: sign in with the
   **same passphrase** in another tab and you *are* the same user — same `userId`, same rooms, same
   access (you own and edit the same rooms, and read every room you're a member of, surviving the
   owner's epoch rotations because every device shares your root KEM). The room list persists
   per-browser (`starfish-rooms-<userId>`); a member invite someone handed you lives only in memory,
   so re-paste it on the new device. The trade-off is **no per-device revocation** and the master
   key on every device — see [`docs/ts/client/24-pairing.md` §5](../../docs/ts/client/24-pairing.md).
   When you need per-device keys + revocation instead, use one of the pairing flows:
   - **Provision (one setup code).** In tab 1 click **Devices** (room header) →
     choose the new device's **access** (full account, or this room read-write /
     read-only) and **cap expiry** → **Provision a new device** → copy the **setup
     code**. In a third tab open the **Pair device** tab, keep the **Setup code**
     method, paste, and **Install & join**. One hand-off, first device → new. The
     chosen scope is enforced server-side — a read-only device gets 403 on send.
     ⚠️ The code carries the new device's *private* keys, so share it only over a
     channel you'd trust with the room key itself.
   - **Pair (two-way, no key exposure).** In the third tab's **Pair device** tab
     pick **Request / response** → set the room → **Generate pairing request**,
     copy it. In tab 1, **Devices** → **Authorise a device**, paste the request,
     copy the returned bundle, paste it back → **Install & join**. The new device's
     private keys never leave it.
   - **Phone scans (camera-free, no bundle-back).** For a device that can't scan:
     in the third tab's **Pair device** tab pick **Phone scans** → set the room →
     **Show pairing QR**, copy the QR. In tab 1, **Devices** → **Authorise via QR
     (camera-free)**, paste it → **Authorise & send to device** (the bundle is
     pushed through an anonymous `_pairing/<id>` slot, nothing to copy back). Back
     in the third tab, click **Added from first device** → a single fetch installs
     it. Private keys never leave the new device; optionally paste the first
     device's root key to pin it.

   Either way the device authenticates as the **same `userId`** and decrypts the
   room (it's added to the keyring). The **Devices** drawer lists your **linked
   devices** (`users/<id>/_devices`): your current one is tagged **this device**;
   every other device has a **Revoke** button that revokes its cap (401), drops it
   from the keyring (epoch rotation), and removes its directory entry.

## How the pieces fit (design notes)

These reflect real constraints of the library + a filesystem store; they are the
non-obvious bits worth understanding before adapting this app.

- **Mount at root, not `/v1`.** The cap-cert request signature and the resolver's
  scope-path check are computed against the path the client signs, which is
  relative to its `baseUrl`. Keeping the sync routes at `/pull|/push|/list`
  (where the resolver strips the action prefix) avoids a path mismatch, so the
  router is mounted with no prefix and the client `baseUrl` is the origin.
- **Per-room, separate keyring/member namespaces.** Rooms are `chat/rooms/<id>`.
  With `FilesystemObjectStore` a key maps to a file, so `chat/rooms/<id>` cannot
  also be the parent directory of its keyring. Each room's keyring and member
  directory live at `chatkeyring/rooms/<id>/_keyring` and
  `chatmembers/rooms/<id>/_members`. This also keeps read/write member caps valid:
  the `member-keyring-not-denied` rule only forbids `chat/_keyring`, so a member
  cap can grant a direct read of `chatkeyring/rooms/<id>/_keyring` to decrypt.
  Opening a room only *creates* a keyring when none exists; if one already does
  (e.g. the room was first opened under a **different** passphrase), it is reused,
  so the new identity is not a recipient. The keyring then throws "no wrapped key
  for recipient …"; the app catches this and shows a clear membership message
  ("this passphrase's identity isn't a member of room X — open a different room
  id, sign in with the passphrase that first opened it, or ask the owner to
  invite you") rather than the raw crypto error.
- **Two enforcement axes.** Room **read** = `cap:read:chat`, **write** =
  `cap:write:chat`. The resolver does not check the request op against
  `scope.ops`; it only synthesizes `cap:<op>:<collection>` roles — so a read-only
  member cap (ops `[read, list]`) simply never produces `cap:write:chat`. Room
  isolation comes from `scope.paths`: a member cap lists only its room's paths.
- **Profiles: public read, identity-bound write.** `user/<id>/profile` has
  `read_roles=["public"]` (any client, no cap) and
  `write_roles=["cap:write:profile","cap:write:*"]`. The `{identity}` path binding
  limits each writer to their **own** profile, so a chat-only member cap can't
  edit profiles and nobody can edit someone else's.
- **Entitlements are client-side feature flags.** They are **not** used as
  collection read/write roles. `pullEntitlements` reads the user's slug document;
  the `premium` slug unlocks a paid feature in the UI.
- **`/demo/grant` and `/demo/revoke`** write the slug document server-side — a
  stand-in for a billing webhook. In production a trusted system writes it.
- **Revocation = full re-key.** Revoking a member/device does three things: posts
  a signed `RevocationList` to `POST /revocations` (the cap-resolver then returns
  **401** for that `(sub, nonce)`), drops the recipient from the room keyring via
  `removeRecipient` (which rotates the epoch, so the revoked party can't decrypt
  the new epoch), and removes the directory entry. The in-memory revocation store
  **replaces** an issuer's list on each accepted submission and requires a
  strictly higher `generation`, so the frontend keeps a cumulative ledger per
  identity (`starfish-revlist-<id>` in `localStorage`) and re-sends the full
  revoked set, generation-bumped, each time. The list is self-authenticating
  (signed by the root key), so `/revocations` needs no cap. (Caveat of this
  demo-grade ledger: clearing `localStorage` resets the generation to 0, so the
  next submission is rejected `stale-generation` until it exceeds the server's
  last-seen generation — a production app would read the current list back or
  track the counter server-side.)
- **Device directory.** Each device cap the root issues is recorded at
  `users/<id>/_devices` (collection `devices`, `{identity}`-bound so a cap only
  manages its own). It's audit/UI metadata — authority still flows through the
  cap-cert + revocation list, never the directory.
- **Two ways to add a device — a deliberate security trade-off.** *Pairing*
  (two-way) is the safe default: the new device generates its own keypair and
  sends only its **public** keys; the first device returns a cap + wrapped room
  key. The new device's **private keys never leave it**, so intercepting either
  blob alone yields nothing. *Provisioning* (one-way) trades that for a single
  hand-off: the first device generates the new device's keypair, mints its cap,
  and ships everything in one setup code — so **whoever reads that code owns a
  full clone of the device** (private keys + cap + room key). Both paths use the
  same `assemblePairingBundle` / `installPairingBundle` primitives; provisioning
  just has the first device play *both* roles locally (no library or server
  change). Choose provisioning only over a channel you'd trust with the room key.
- **A member can't leave server-side.** Member caps are denied `_keyring` and
  `_members`, so a member can't remove their own recipiency or directory entry.
  **Leave room** therefore only clears the local persisted room; cutting their
  access is the owner's **Revoke**.
- **Persistence.** The backend uses a filesystem store under `backend/data/`. The
  frontend persists the decrypted room per identity in `localStorage` via the
  zustand `persist` middleware (offline-first; the server only ever sees
  ciphertext).

## Production deployment

The demo is secure-by-default for admin endpoints (`STARFISH_DEMO_SECRET` unset →
`/demo/*` and `/audit` return 403). For a real deployment, also set:

- **`STARFISH_CORS_ORIGIN`** — comma-separated allowed browser origins (default
  `http://localhost:5173`).
- **`STARFISH_ENABLE_KEYRING_RATE_LIMIT=1`** — caps `chatkeyring` writes at
  30/min per source to blunt TOFU room-id squat spam (off by default so tests can
  rotate keyrings freely).
- **Reverse proxy (required for rate limiting to hold)** — the rate limiter
  keys anonymous traffic by the first `X-Forwarded-For` hop. That header is
  **client-supplied**: if the app is reachable directly, an attacker can spoof
  and rotate it to evade per-source limits entirely. Deploy behind a trusted
  proxy that **overwrites** (not merely appends) `X-Forwarded-For` with the
  real client IP, and never expose the app port directly. If there is no proxy,
  the direct-socket fallback (`request.client.host`, Python server only) is the
  only trustworthy bucket key — the TS/Hono server has no socket-IP fallback
  and **must** sit behind a proxy for per-client rate limiting to be effective.
- **`GET /events`** — open SSE with metadata-only payloads (`roomId`, hash). Gate
  this route if activity metadata leakage is unacceptable for your threat model.

See [`TESTING.md`](./TESTING.md) for the full regression harness and deployment table.
