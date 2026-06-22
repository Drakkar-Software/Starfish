/**
 * Pure-identity link tokens — a shareable public link that carries ONLY an owner's
 * identity (userId + pseudo + Ed25519 pubkey + KEM pubkey), with no credential or
 * capability embedded.
 *
 * Unlike `SpaceInviteLinkToken` / `NodeInviteLinkToken` — which both embed an
 * ephemeral private key + cap-cert and are therefore BEARER CREDENTIALS — an
 * `IdentityLink` is safe to publish openly or embed in a client app. Its only
 * trust anchor is the `ownerId ↔ edPub` derivation binding (verified offline via
 * `session.userIdFromEdPub`, hardened by a live profile key cross-check when reachable).
 *
 * Primary use: the `createResourceRequest` / `scanResourceRequests` flow in
 * `resource-requests.ts` — a requester holds only the owner's identity link
 * and delivers a sealed resource-creation request to the owner's inbox. The owner
 * decides whether to accept or reject; no authority is delegated until then.
 */
import { readProfile } from "./client.js"
import { encodeLinkFragment, decodeLinkFragment } from "@drakkar.software/starfish-protocol"
import { hexToBytes } from "@drakkar.software/starfish-keyring"
import { ed25519 } from "@noble/curves/ed25519.js"
import { signKemSig } from "./request-verify.js"
import type { Session } from "./session.js"

// ── Regex constants ───────────────────────────────────────────────────────────

const HEX64 = /^[0-9a-f]{64}$/i
const ED_PUB_HEX_RE = HEX64
const KEM_PUB_HEX_RE = HEX64
const KEM_SIG_HEX_RE = /^[0-9a-f]{128}$/i
const USER_ID_HEX_RE = /^[0-9a-f]{32}$/i

// ── Token shape ───────────────────────────────────────────────────────────────

/**
 * Portable public identity — the only content of an identity link.
 * `pseudo` is a display hint only; KEYS are the trust anchor; `ownerId` is
 * deterministically bound to `edPub` by `userIdFromEdPub` (verified offline).
 * `kemSig` is an Ed25519 signature of kemPub bytes by edPriv, binding kemPub
 * to edPub in a way that can be verified offline without a server round-trip.
 */
export interface IdentityLink {
  v: 2
  ownerId: string
  pseudo: string
  edPub: string
  kemPub: string
  kemSig: string // Ed25519 sig of hexToBytes(kemPub) by edPriv
}

const MALFORMED = "That identity link is malformed or incomplete."

// ── Offline trust anchor ──────────────────────────────────────────────────────

/**
 * Verify the hard, OFFLINE binding:
 *   1. `token.ownerId === sha256(token.edPub)[0:32]`
 *   2. `token.kemSig` is a valid Ed25519 signature of `kemPub` bytes by `edPub`
 * Call this before rendering anything about the owner and before sending any request.
 */
export async function verifyIdentityLinkBinding(token: IdentityLink, session: Session): Promise<boolean> {
  const ownerIdMatch = (await session.userIdFromEdPub(token.edPub)) === token.ownerId
  if (!ownerIdMatch) return false
  try {
    return ed25519.verify(hexToBytes(token.kemSig), hexToBytes(token.kemPub), hexToBytes(token.edPub))
  } catch {
    return false
  }
}

// ── Encode / decode ───────────────────────────────────────────────────────────

/**
 * Pack an identity link into a URL: `<origin>/<path>#<base64url(token)>`.
 * The token rides in the URL fragment.
 */
export function encodeIdentityLink(origin: string, path: string, token: IdentityLink): string {
  return encodeLinkFragment(origin, path, token)
}

/**
 * Decode + shape-check a `#…` fragment (with or without the leading `#`).
 * Synchronous shape validation only — the `ownerId ↔ edPub` binding and kemSig
 * are verified asynchronously via {@link verifyIdentityLinkBinding}.
 * Rejects v:1 links (clean break — callers must re-publish with v:2).
 */
export function decodeIdentityLink(fragment: string): IdentityLink {
  const raw = decodeLinkFragment<Partial<IdentityLink>>(
    fragment,
    (tok: unknown) => {
      const t = tok as Partial<IdentityLink>
      return !!t &&
        t.v === 2 &&
        typeof t.ownerId === "string" &&
        USER_ID_HEX_RE.test(t.ownerId) &&
        typeof t.edPub === "string" &&
        ED_PUB_HEX_RE.test(t.edPub) &&
        typeof t.kemPub === "string" &&
        KEM_PUB_HEX_RE.test(t.kemPub) &&
        typeof t.kemSig === "string" &&
        KEM_SIG_HEX_RE.test(t.kemSig)
        ? t
        : null
    },
    MALFORMED,
  )
  return {
    v: 2,
    ownerId: raw.ownerId!,
    pseudo: typeof raw.pseudo === "string" ? raw.pseudo : "",
    edPub: raw.edPub!,
    kemPub: raw.kemPub!,
    kemSig: raw.kemSig!,
  }
}

// ── Own link ──────────────────────────────────────────────────────────────────

/**
 * Build this account's own identity link — derivable on ANY device, always the same.
 * The root device reads published keys straight from the session; a paired device
 * reads them from the (cached) public profile, like any peer would.
 *
 * Returns `null` only if the profile keys have not been published yet (brand-new
 * identity that has never synced). Call `ensureProfileKeys` first if needed.
 *
 * @param session  The current session.
 * @param origin   Web app base URL (e.g. `https://app.example.com`).
 * @param path     Route fragment (e.g. `request` → `…/request#token`). No leading `/`.
 */
export async function myIdentityLink(
  session: Session,
  origin: string,
  path: string,
): Promise<string | null> {
  // Root device: keys are already on the session — compute kemSig locally.
  if (session.ownerEdPub === session.keys.edPub) {
    const kemSig = signKemSig(session.keys)
    return encodeIdentityLink(origin, path, {
      v: 2,
      ownerId: session.userId,
      pseudo: session.name,
      edPub: session.keys.edPub,
      kemPub: session.keys.kemPub,
      kemSig,
    })
  }
  // Paired device: read published keys + kemSig from the profile.
  const profile = await readProfile(session.userId, { baseUrl: session.baseUrl, layout: session.layout })
  if (!profile.edPub || !profile.kemPub || !profile.kemSig) return null
  return encodeIdentityLink(origin, path, {
    v: 2,
    ownerId: session.userId,
    pseudo: session.name,
    edPub: profile.edPub,
    kemPub: profile.kemPub,
    kemSig: profile.kemSig,
  })
}

// ── Verify a received token against the live profile ─────────────────────────

/**
 * Cross-check a decoded token against the owner's published profile when the server
 * is reachable. Throws if the live profile has DIFFERENT keys than the token.
 * Succeeds silently when the profile is unreachable.
 */
export async function verifyIdentityLinkKeys(token: IdentityLink, session: Session): Promise<void> {
  const profile = await readProfile(token.ownerId, { baseUrl: session.baseUrl, layout: session.layout }).catch(() => null)
  if (!profile) return
  if (
    (profile.edPub && profile.edPub !== token.edPub) ||
    (profile.kemPub && profile.kemPub !== token.kemPub)
  ) {
    throw new Error("This identity link doesn't match the owner's published identity keys.")
  }
}
