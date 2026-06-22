/**
 * Owner trusted-adder allow-list for opening/sealing an OWNED keyring.
 *
 * When the session's owner key equals the device key (the common single-device
 * case) the allow-list is just `[selfEdPub]`; otherwise the owner key is also
 * trusted so that a paired device can open keyrings sealed by the root identity.
 *
 * Kept in its own leaf module so both `client.ts`-style helpers and session
 * builders in consuming packages can import it without risking circular deps.
 */

/**
 * Compute the trusted-adder allow-list for the caller's OWNED keyring.
 *
 * @param ownerEdPub - The Ed25519 pubkey of the owner (root identity).
 *   Undefined is treated as "same as self" (i.e., self is the owner).
 * @param selfEdPub - The Ed25519 pubkey of the current device.
 */
export function computeOwnerTrustedAdders(ownerEdPub: string | undefined, selfEdPub: string): string[] {
  const owner = ownerEdPub ?? selfEdPub
  return owner !== selfEdPub ? [owner, selfEdPub] : [selfEdPub]
}
