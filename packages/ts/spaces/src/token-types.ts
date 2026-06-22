/**
 * Wire token shapes for invite flows and resource requests.
 *
 * Plain interfaces only — no logic. Shared by members.ts, nodes.ts, and resource-requests.ts.
 */

// ── Join request (requester → owner) ─────────────────────────────────────────

/** Sent by a prospective member to prove ownership of their keys. */
export interface JoinRequest {
  edPub: string
  kemPub: string
  userId: string
  /** Ed25519 signature of kemPub bytes by edPriv — proves kemPub ownership. */
  kemSig: string
}

// ── Space invite link token ───────────────────────────────────────────────────

/** A space invite link token (v:1). Encodes the ephemeral credential in the URL fragment. */
export interface SpaceInviteLinkToken {
  v: 1
  spaceId: string
  spaceName: string
  cap: unknown
  /** The throwaway ephemeral subject's Ed25519 private key (hex). */
  key: string
  /**
   * The throwaway ephemeral subject's X25519 KEM private key (hex) — needed to
   * decrypt the space keyring. Absent in legacy tokens (pre-0.8.6).
   */
  kemPriv?: string
  /**
   * The throwaway ephemeral subject's X25519 KEM public key (hex) — identifies
   * this token's recipient entry in the space keyring.
   */
  kemPub?: string
  write: boolean
}

// ── Node invite bundle ────────────────────────────────────────────────────────

/**
 * Discriminates the E2EE model for a node invite so the invitee can handle the bundle
 * correctly without reverse-engineering which caps are present.
 *
 * - `'plaintext'`  — no encryption; content is readable without any keyring.
 * - `'space-enc'`  — space-wide keyring (legacy enc invite); invitee receives a
 *                    space-level cap and uses the space keyring to decrypt.
 * - `'node-enc'`   — per-node keyring (isolated E2EE ticket); invitee receives
 *                    a `keyringCap` (READ-only) scoped to this node's keyring only.
 */
export type NodeInviteKind = "plaintext" | "space-enc" | "node-enc"

/** Bundle sent by the owner to a node invitee. */
export interface NodeInviteBundle {
  spaceId: string
  nodeId: string
  nodeName: string
  /**
   * Discriminates the invite's E2EE model. Absent in bundles produced before 0.12.9;
   * treat absent as `'plaintext'` or derive from which caps are present.
   */
  kind?: NodeInviteKind
  /**
   * Space-level member cap — grants index read access. Omitted for isolated invites
   * that must NOT grant space-wide access.
   */
  cap?: unknown
  /** Per-node content cap (`objinv`) — for `invite+plaintext` AND per-node-keyring enc nodes. */
  nodeCap?: unknown
  /** Per-node STREAM cap (`objinvlog`) — for nodes with a message log. */
  streamCap?: unknown
  /**
   * Per-node KEYRING cap (`nodekeyring`, READ-only) — present ONLY for per-node-keyring
   * E2EE nodes (`enc + isolated`). Lets the isolated requester read the node keyring to
   * decrypt content WITHOUT holding the space-wide keyring.
   */
  keyringCap?: unknown
}

// ── Node invite link token ────────────────────────────────────────────────────

/** A node invite link token (v:1). */
export interface NodeInviteLinkToken {
  v: 1
  spaceId: string
  nodeId: string
  nodeName: string
  /** Cap scope depends on the mode: spaceMemberScope for legacy space-keyring enc nodes,
   *  nodeMemberScope (objinv content) for plaintext / per-node-keyring nodes. */
  cap: unknown
  /** Per-node STREAM cap (`objinvlog`) — present for nodes with a message log. */
  streamCap?: unknown
  /** Per-node KEYRING cap (`nodekeyring`, READ-only) — present for per-node-keyring E2EE nodes. */
  keyringCap?: unknown
  /** The ephemeral subject's Ed25519 private key (hex). */
  key: string
  write: boolean
}

// ── Resource request / grant / reject ────────────────────────────────────────

/** Sealed inside an owner's inbox — "please create a node in your space". */
export interface ResourceRequest {
  v: 1
  kind: "create-resource"
  /** Stable id for dedup / idempotency. */
  reqId: string
  /** Target space owned by the link owner. */
  spaceId: string
  /** Node type string (e.g. `'room'`, `'ticket'`, `'page'`). */
  nodeType: string
  /** Human-readable node title. */
  title: string
  /** Optional app-specific metadata merged into the created node. */
  meta?: Record<string, unknown>
  /** Optional human-readable message from the requester. */
  message?: string
  /** Requester's public identity — used to mint and seal the grant-back cap. */
  requester: {
    userId: string
    edPub: string
    kemPub: string
    /** Ed25519 sig of kemPub by edPriv — proves kemPub ownership. */
    kemSig: string
  }
}

/** Sealed inside the requester's inbox — "your request was accepted, here's your cap". */
export interface ResourceGrant {
  v: 1
  kind: "grant"
  /** Matches the original `ResourceRequest.reqId`. */
  reqId: string
  /** The space containing the new node. */
  spaceId: string
  /** The newly created node. */
  nodeId: string
  /** Serialised `NodeInviteBundle` JSON — pass directly to `acceptNodeInvite`. */
  bundle: string
}

/** Sealed inside the requester's inbox — "your request was rejected". */
export interface ResourceReject {
  v: 1
  kind: "reject"
  /** Matches the original `ResourceRequest.reqId`. */
  reqId: string
  reason?: string
}

// ── Owner-side stored node invite (for revocation) ────────────────────────────

/**
 * Stored by the owner after minting caps for a node invite, so they can
 * later revoke the invitee by nonce.
 *
 * `caps.node`    — node-content cap nonce + expiry (`objinv` scope).
 * `caps.stream`  — stream cap nonce + expiry (`objinvlog` scope). Absent if no stream.
 * `caps.keyring` — per-node keyring cap nonce + expiry (`nodekeyring` scope). Absent unless per-node-enc.
 */
export interface StoredNodeInvite {
  edPub: string
  kemPub: string
  caps: {
    node?: { nonce: string; exp: number }
    stream?: { nonce: string; exp: number }
    keyring?: { nonce: string; exp: number }
  }
}
