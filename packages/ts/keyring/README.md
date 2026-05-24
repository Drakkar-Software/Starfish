# @drakkar.software/starfish-keyring

Starfish multi-recipient encryption layer — keyring documents, recipient management, AES-GCM payload encryption.

This is the **encryption extension** for Starfish v3. It is independent of starfish-client transport in the sense that the core `StarfishClient` does not import it; apps that want client-side payload encryption install this package and wire it on top.

## Install

```sh
pnpm add @drakkar.software/starfish-client @drakkar.software/starfish-keyring
```

## Usage

```ts
import { StarfishClient } from "@drakkar.software/starfish-client"
import {
  createKeyring,
  createKeyringEncryptor,
  addCollectionRecipient,
} from "@drakkar.software/starfish-keyring"

const { keyring, cek } = await createKeyring(adderKeys, [{ subKemHex: aliceKemPub }])
const encryptor = await createKeyringEncryptor(
  keyring,
  { kemPubHex, kemPrivHex },
  { trustedAdders: [adderKeys.edPubHex] },   // required — Ed25519 pubkey(s) you trust to grant access
)
```

`trustedAdders` is **required** (throws without it): the per-entry `addedSig` is self-attesting, so a provenance pin is needed to reject a server-substituted wrap entry. Pass the optional `minEpoch` (the highest `currentEpoch` you've previously seen, persisted client-side) to reject a stale keyring a hostile server might serve to undo a rotation. The recipient-management helpers (`addCollectionRecipient`, `removeRecipient`, `listRecipients`) require the same `trustedAdders` pin.

## Epochs & rotation

Revoking a recipient (`removeRecipient`) **rotates** the keyring to a new epoch and re-wraps the CEK for everyone who remains, so the revoked party can't read new content. `addCollectionRecipient` wraps a newcomer into the **current epoch only** — content sealed under an earlier epoch stays unreadable to them (you'll see `No key available for epoch N` on decrypt). To share existing content with a freshly-added recipient, **re-seal it at the current epoch** (decrypt with a key that holds the old CEK, then re-encrypt) after adding them.

See `docs/ts/keyring/` for the full guide.
