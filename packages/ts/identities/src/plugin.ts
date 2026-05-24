/**
 * Server plugin for the identities extension.
 *
 * Registers a no-op `device` cap-validator with the
 * `@drakkar.software/starfish-server` cap-resolver. The protocol-level
 * `assertCapCertWellFormed` no longer special-cases per-kind shape; the
 * plugin pattern lets apps opt into the kinds they accept.
 *
 * The validator is intentionally a no-op for device caps: the underlying
 * well-formedness check (run at mint time inside `mintDeviceCap`) is
 * already sufficient, and the server-side check is reserved for invariants
 * that depend on server-side state (e.g. revocation lookups handled
 * elsewhere in the resolver).
 *
 * The `ServerPlugin` type lives in `starfish-protocol` (the shared contract
 * layer), so this package needs no dependency on `starfish-server` —
 * applications wire both packages at the top level.
 */

import type { ServerPlugin } from "@drakkar.software/starfish-protocol"

export const identitiesServerPlugin: ServerPlugin = {
  name: "starfish-identities",
  capValidators: {
    device: () => {
      /* device caps are validated structurally at mint time and via the
       * resolver's signature/window/nonce checks; no extra shape rule. */
    },
  },
}
