/**
 * Server plugin for the sharing extension.
 *
 * Registers a `member` cap-validator (member-self, member-multi-collection,
 * member-private-path, member-members-not-denied, member-keyring-not-denied)
 * and an `audience` cap-validator (the public-link kind: single-collection +
 * owner-namespace barriers, no single-subject rules). The protocol-level
 * `assertCapCertWellFormed` already handles the generic checks at mint time,
 * but the server runs the kind-specific shape again at validation time so a
 * tampered cap-cert cannot reach the storage layer. Without the `audience`
 * validator, strict-kind dispatch rejects every audience cap with HTTP 401.
 *
 * The `ServerPlugin` type lives in `starfish-protocol` (the shared contract
 * layer), so this package needs no dependency on `starfish-server` —
 * applications wire both packages at the top level.
 */

import type { ServerPlugin } from "@drakkar.software/starfish-protocol"
import { assertMemberCapShape, assertAudienceCapShape } from "./cap-mint.js"

export const sharingServerPlugin: ServerPlugin = {
  name: "starfish-sharing",
  capValidators: {
    member: assertMemberCapShape,
    audience: assertAudienceCapShape,
  },
}
