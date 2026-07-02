---
sidebar_position: 2
---

# Sealed-write — E2EE ingestion from a keyless writer

This is the answer to: *can an external webhook post into an end-to-end-encrypted
space without holding the space's keys?* Yes — by publishing a **space write key**
and letting the webhook encrypt to it.

## The problem

Starfish's `delegated` encryption wraps content with a shared symmetric **CEK** that
every reader also holds. To produce a valid ciphertext you need the CEK — so in that
model, **anyone who can write can also read**. A webhook is exactly the party you do
*not* want to grant read access: it should be able to inject a message, never to
decrypt the history.

## The mechanism

Sealed-write builds a **write-only** party on the keyring's existing anonymous-sender
primitive (`seal`/`unseal`: ephemeral X25519 → HKDF-SHA256 → AES-256-GCM):

1. **Mint a space write key.**

   ```ts
   import { generateSpaceWriteKey } from "@drakkar.software/starfish-webhook"
   const { kemPubHex, kemPrivHex } = generateSpaceWriteKey()
   ```

   - `kemPubHex` (public) is **published openly** — e.g. in a plaintext space-config
     document any reader (and the webhook) can fetch.
   - `kemPrivHex` (private) is **distributed to members out of band** — in practice
     wrapped into the space keyring alongside the CEK, so every member recovers it
     exactly the way they already recover the CEK.

2. **The webhook seals to the public key.** Configure the route with `seal` + a
   `sealer` identity:

   ```ts
   routes: {
     bridge: {
       secret,
       transform,
       target: "/push/pubspaces/owner/space/streams/room",
       author: { edPubHex: BOT_PUB, edPrivHex: BOT_PRIV },
       seal:   { recipientKemPubHex: kemPubHex },
       sealer: { edPubHex: BOT_PUB, edPrivHex: BOT_PRIV },
     },
   }
   ```

   The message is sealed at the receiver, so a plain (`none`) collection stores only
   ciphertext (`{ entry, ct }`). The server never sees the cleartext.

3. **Members open it.**

   ```ts
   import { openSealedDocument, isSealedBlob, sealAad } from "@drakkar.software/starfish-webhook"

   // The webhook handler binds every sealed blob to its destination with an
   // `aad = sealAad(documentKey, webhookId)` (documentKey = the target path with
   // the `/push/` prefix stripped; webhookId = the route id). A member
   // reconstructs the SAME aad from those public facts — opening without the
   // matching aad throws.
   const aad = sealAad("pubspaces/owner/space/streams/room", "bridge")

   for (const el of pulledItems) {
     const msg = isSealedBlob(el.data)
       ? await openSealedDocument(el.data, kemPrivHex, BOT_PUB, { aad })
       : el.data // a plaintext write from a normal client
   }
   ```

   The expected sealer is now a **required positional argument** (`BOT_PUB` above) —
   sealer pinning is **mandatory**. The open throws unless the blob's wrap entry was
   signed by that key, so a member can trust *who* injected the message against any
   **outside** party. (The signature commits to the wrapped content key, not the
   message bytes; forging a different message under a pinned sealer would require the
   per-message content key, which is fresh-random and known only to the sealer and
   key-holders. A *member* — who can already post — is therefore out of this
   guarantee's scope; it defends against non-members, not against insiders.) Passing
   the matching `aad` additionally binds the ciphertext to its destination
   (`documentKey` + route id), so a sealed blob cannot be relocated into another
   document or route.

## What each party can do

| Party | Holds | Can write? | Can read? |
|---|---|---|---|
| Webhook | `kemPubHex` + its own signing key | ✅ seal to the space | ❌ never |
| Member | `kemPrivHex` (via keyring) | ✅ (and decrypt) | ✅ |
| Server | nothing | — | ❌ ciphertext only |

## Revocation

The space write key rotates like the CEK: mint a new pair, publish the new public
half, re-distribute the new private half to current members. A removed member who
kept the old `kemPrivHex` can read webhook messages only up to the rotation — the
same property the CEK already has.

## Trust boundary

The E2EE guarantee is "**from the receiver onward**". An external sender already
transmits cleartext to whatever URL it's given, so the webhook receiver is the
encryption edge: it holds only the public key, seals there, and from that point the
Starfish server stores and serves ciphertext that only members can open. For this to
be real E2EE the sealing must happen at that edge — **not** inside the core sync
server, which would otherwise observe plaintext. Metadata (timing, size, target
room) remains visible, exactly as for any message.

## Mixing sealed and plaintext

A collection can hold both: normal clients write plaintext (or CEK-encrypted, in a
`delegated` collection), and the webhook writes sealed blobs. `isSealedBlob` lets a
reader branch per element, so the two coexist in one log.
