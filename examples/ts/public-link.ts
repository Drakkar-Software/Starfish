/**
 * Starfish v3.0 — public links (audience caps).
 *
 * Alice owns a plaintext (`encryption: "none"`) `broadcast` collection. She
 * wants to share a link to it. Two flavors:
 *
 *   1. OPEN link — anyone who holds a Starfish identity may redeem. Each
 *      redeemer signs requests with their OWN key, so reads/writes are
 *      attributable per user (no shared anonymous identity, no embedded key).
 *
 *   2. RESTRICTED link — only a listed set of identities may redeem. The
 *      server enforces the allow-list (the cap's `aud`); a non-listed identity
 *      gets 403.
 *
 * Both are minted with `createPublicLink`, which packs an `audience` cap-cert
 * into a URL `#fragment`. A redeemer calls `parsePublicLink` + `redeemPublicLink`
 * to produce the request headers (incl. `X-Starfish-Pub`, naming their key).
 *
 * Run:
 *   npx tsx examples/ts/public-link.ts
 */

import { bootstrapRootIdentity } from "@drakkar.software/starfish-identities"
import {
  createPublicLink,
  parsePublicLink,
  redeemPublicLink,
  scopes,
} from "@drakkar.software/starfish-sharing"

async function main() {
  // Alice (owner) and two would-be readers, each with their own identity.
  const alice = await bootstrapRootIdentity("alice-passphrase")
  const bob = await bootstrapRootIdentity("bob-passphrase")
  const carol = await bootstrapRootIdentity("carol-passphrase")
  const stranger = await bootstrapRootIdentity("stranger-passphrase")

  // ── 1. OPEN link: any identity may redeem, expires in 7 days. ────────────
  const open = await createPublicLink({
    issEdPrivHex: alice.device.edPriv,
    issEdPubHex: alice.device.edPub,
    collection: "broadcast",
    scope: scopes.readOnly("broadcast"),
    ttlSec: 7 * 24 * 3600,
  })
  console.log("open link    :", `https://app.example/#${open.fragment.slice(0, 24)}…`)
  console.log("  aud        :", open.cap.aud ?? "(none → anyone)")

  // ── 2. RESTRICTED link: only Bob and Carol may redeem. ───────────────────
  const restricted = await createPublicLink({
    issEdPrivHex: alice.device.edPriv,
    issEdPubHex: alice.device.edPub,
    collection: "broadcast",
    scope: scopes.readOnly("broadcast"),
    allowedIdentities: [bob.device.edPub, carol.device.edPub],
    expiresAt: Math.floor(Date.now() / 1000) + 3600, // absolute expiry, 1h
  })
  console.log("restricted   :", `https://app.example/#${restricted.fragment.slice(0, 24)}…`)
  console.log("  aud        :", restricted.cap.aud)

  // ── 3. Bob redeems the restricted link, signing as himself. ──────────────
  // `redeemPublicLink` returns the headers to attach to the HTTP request
  // (Authorization: Cap …, X-Starfish-{Sig,Ts,Nonce,Pub}). A real client wires
  // these via its capProvider (return `pubHex` and StarfishClient sends them).
  const parsed = parsePublicLink(restricted.fragment)
  const bobHeaders = await redeemPublicLink(parsed, {
    redeemerEdPrivHex: bob.device.edPriv,
    redeemerEdPubHex: bob.device.edPub,
    method: "GET",
    pathAndQuery: "/pull/broadcast/post-1",
    host: "api.example.com",
  })
  console.log("\nBob's request headers (in `aud` → server authorizes):")
  console.log("  X-Starfish-Pub:", bobHeaders["X-Starfish-Pub"])

  // The stranger could build headers too, but is NOT in `aud`, so the server
  // rejects the request with 403 after verifying their signature.
  console.log("\nStranger's pubkey:", stranger.device.edPub, "→ NOT in aud → 403 server-side")

  // Revocation: there is no single subject. Revoke the whole link by its nonce
  // (post a signed RevocationList entry with `sub: ""` + restricted.cap.nonce),
  // or re-mint with a trimmed `allowedIdentities`.
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
