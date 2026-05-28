/**
 * `@drakkar.software/starfish-identities` — root + device identity extension.
 *
 * Public surface: passphrase-derived root identities, device cap-cert minting,
 * the `scopes.rootAll` preset, all pairing flows (QR + server-relay), and the
 * per-user device directory.
 */

export {
  deriveRootIdentity,
  deriveRootIdentityFromSecp256k1Signature,
  SECP256K1_BOOTSTRAP_CHALLENGE,
} from "./identity.js"
export type {
  RootIdentity,
  RootKeyPair,
  BootstrapOrigin,
  Secp256k1BootstrapInput,
} from "./identity.js"

export { mintDeviceCap, scopes } from "./cap-mint.js"
export type { ScopePreset, MintOpts } from "./cap-mint.js"

// Re-exported from the protocol layer: distinguishes a self-signed root-device
// cap from delegated devices/members (used by server-side root-only collections).
export { isRootDeviceCap } from "@drakkar.software/starfish-protocol"

export {
  bootstrapRootIdentity,
  buildPairingQr,
  parsePairingQr,
  assemblePairingBundle,
  installPairingBundle,
  generateDeviceKeys,
  provisionDevice,
  installProvisionedDevice,
  deriveCodeKey,
  buildPairingRequest,
  readPairingRequest,
  buildPairingResponse,
  readPairingResponse,
} from "./pairing.js"
export type {
  DeviceCredentials,
  PairingQrPayload,
  PairingBundle,
  WrappedCekEntry,
  InstalledPairingResult,
  AssemblePairingBundleOpts,
  InstallPairingBundleOpts,
  GeneratedDeviceKeys,
  ProvisionDeviceOpts,
  ProvisionedDevice,
  PairingRequestEncrypted,
  PairingResponseEncrypted,
} from "./pairing.js"

export { sealWithPassphrase, openWithPassphrase, isSealedEnvelope } from "./seal.js"
export type { SealedEnvelope, SealOpts } from "./seal.js"

export {
  rendezvousPathFor,
  pushPairingBundle,
  fetchPairingBundle,
  clearPairingBundle,
  RENDEZVOUS_PREFIX,
} from "./rendezvous.js"

export {
  addDeviceEntry,
  listDevices,
  removeDeviceEntry,
  devicesPathFor,
} from "./directory.js"
export type {
  DirectoryEntry,
  Directory,
  DeviceEntry,
  ListDirectoryOpts,
} from "./directory.js"

export { identitiesServerPlugin } from "./plugin.js"
