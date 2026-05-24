# 23. Multi-Recipient Delegated Encryption

Starfish 3.0 collapses the v2 `"group"` mode into a single `"delegated"` mode that supports **N recipients**. Whether you're sharing a collection with your other devices, with members of a team, or with a single subscriber, the protocol surface and the on-disk format are the same.

This module replaces the v2 "Group Encryption" doc, which was deleted in 3.0.

## Mental model

A collection with `encryption: "delegated"` has two kinds of documents on the server:

1. **Data documents** at `<collection>/<path>` — opaque ciphertext `{_encrypted: "base64...", _epoch: N}`.
2. **One keyring document** at `<collection>/_keyring` — a list of *wrap entries*, one per recipient. The keyring is plaintext on the server (it tells the server who has access, but not what they're protecting).

The keyring carries one **Content Encryption Key (CEK)** per epoch, wrapped separately for each recipient via X25519 ECDH + HKDF + AES-GCM (HPKE-DHKEM style).

## Keyring document shape

```json
{
  "v": 1,
  "currentEpoch": 3,
  "epochs": {
    "1": {
      "wrappedKeys": [
        {
          "subKem":   "<hex X25519 pub of recipient>",
          "ephKem":   "<hex X25519 pub of ephemeral wrapper>",
          "ct":       "base64(IV || AES-GCM(CEK))",
          "addedBy":  "<hex Ed25519 pub of whoever added this recipient>",
          "addedSig": "base64(Ed25519 over stableStringify({addedAt,addedBy,ct,ephKem,epoch,subKem}))",
          "addedAt":  1747000000
        },
        ...
      ],
      "createdAt": 1747000000
    },
    "2": { ... },
    "3": { ... }
  }
}
```

Key design choices:

- **`wrappedKeys` is a list, not a map.** Recipients find their entry by exact `subKem` match (full 32 bytes). This eliminates the 64-bit recipientId collision attack that affects truncated-hash keys.
- **Per-entry ephemeral ECDH** (HPKE-DHKEM style). The wrapper generates a fresh X25519 keypair for each wrap and discards the private side. A future compromise of any long-term X25519 key cannot recover historic wrap keys.
- **Each entry is signed by the adder.** `addedBy` and `addedSig` produce a cryptographic audit trail: "X granted Y access to this collection at time T". Verifiers can inspect this without rebuilding the access history from server logs.

## Wrap algorithm

```
shared    = ECDH(ephPriv, recipient.subKem)
wrapKey   = HKDF-SHA256(shared, salt = "starfish-wrap", info = "starfish-wrap", len = 32)
iv        = 12 random bytes
ct        = AES-256-GCM(wrapKey, iv, plaintext = CEK)
entry.ct  = base64(iv || ct)
```

Unwrap is the inverse: `shared = ECDH(my.kemPriv, entry.ephKem)`, same HKDF, AES-GCM decrypt.

Cross-language test vectors: [`tests/test-vectors/multi-recipient-wrap.json`](../../../tests/test-vectors/multi-recipient-wrap.json).

## Symmetric authority

Once a device has the current CEK (by unwrapping its entry), it can:

- **Encrypt** new documents under the current epoch.
- **Decrypt** any document in any epoch where it has a wrap entry.
- **Wrap the CEK for a new recipient** (any current holder can grant access — no need to be the original issuer).
- **Rotate the epoch** (mint a fresh CEK, re-wrap for chosen recipients) to revoke access for everyone not in the new set.

What still requires the **root** Ed25519 key:

- Minting a fresh cap-cert for a brand-new device or member.
- Signing the `RevocationList` for the user.

This means a non-root device can grant access (within the limits of its cap-cert scope), but it cannot grant cap-cert authority. The two-layer separation — *who holds the keyring CEK* vs *who can mint caps* — is what keeps a compromised device from issuing new authorizations.

### Bounding who can grant access

By default, `mintDeviceCap` with `scopes.writer(collection)` produces a cap whose `scope.paths` includes a denylist entry `!<collection>/_keyring`. That cap can push data but cannot rewrite the keyring document — so a "writer" device cannot grant new recipients. Only `scopes.admin(collection)` (or a wider scope) can.

## Lifecycle helpers

Two layers of helpers ship in v3.0:

**Keyring-document primitives** — work on an in-memory `Keyring` object, no HTTP:

```ts
import {
  createKeyring,
  addRecipient,           // primitive — mutates a Keyring in memory
  rotateEpoch,
  createKeyringEncryptor,
} from "@drakkar.software/starfish-client"
```

- `createKeyring(adder, recipients, cek?, addedAt?)` — first-time setup. Generates a CEK if not provided, wraps for each initial recipient, returns `{keyring, cek}`.
- `addRecipient(keyring, adder, currentCek, recipientKemHex, addedAt?)` — appends a new wrap entry to the current epoch. **The new recipient gets read access to every document already in the current epoch.** If you want history isolation, rotate the epoch first.
- `rotateEpoch(keyring, adder, retainedRecipients, addedAt?)` — mints a fresh CEK, creates a new epoch numbered `currentEpoch + 1`, wraps for the retained recipients. Old epochs stay intact (existing recipients can still decrypt history).

**HTTP-aware collection helpers** — pull the keyring through `StarfishClient`, mutate, push:

```ts
import {
  addCollectionRecipient,
  removeRecipient,
  listRecipients,
  currentEpoch,
} from "@drakkar.software/starfish-client"
```

These wrap the primitives above with read–modify–write against the collection's `_keyring` document (handling `baseHash` and conflict retries). The keyring-primitive `addRecipient` and the HTTP helper `addCollectionRecipient` are different functions: use the primitive when you already have a `Keyring` in memory; use `addCollectionRecipient` when you want the helper to fetch, mutate, and push for you. `listRecipients` returns the current epoch's recipients filtered by provenance — only entries whose `addedBy` is trusted and whose `addedSig` verifies — so it now requires the same `trustedAdders` pin.

> **`trustedAdders` is required (fail closed).** `createKeyringEncryptor`, `addCollectionRecipient`, `removeRecipient`, and `listRecipients` recover/adopt/expose a CEK or recipient view from the server-supplied keyring. Because `addedSig` is *self-attesting* (any key signs its own entry), a hostile server can **replace** the adder's own entry with one wrapping an attacker-chosen CEK to the adder's public KEM key and self-sign it — the helper would then unwrap that forged CEK and re-wrap it for the new recipient. These helpers therefore **require** a `trustedAdders` (`trusted_adders` in Python) pin and throw without one: entries whose `addedBy` is not a trusted issuer are skipped, `removeRecipient` drops untrusted-injected entries on rotation, and `listRecipients` returns only provenance-verified entries. Pass the legitimate adders — typically the collection owner's root device pubkey(s).
>
> **`minEpoch` (optional epoch-rollback guard).** The keyring is an opaque server document with no built-in epoch floor, so a hostile server could serve a *stale* keyring (lower `currentEpoch`) to undo a rotation and re-admit a removed recipient. Pass `createKeyringEncryptor`'s optional `minEpoch` (`min_epoch` in Python) — the highest `currentEpoch` the caller has previously seen, persisted client-side — to reject any keyring below it.

### Owner-only member directory (`<col>/_members`)

The owner's view of "who has access to this collection" lives in a separate document next to the keyring:

```ts
import {
  addMemberEntry,
  listMembers,
  removeMemberEntry,
} from "@drakkar.software/starfish-client"
```

- `addMemberEntry(client, collectionPath, cert, {label?})` — typically called right after `mintMemberCap` + `addCollectionRecipient`. The same nonce upserts.
- `listMembers(client, collectionPath, {includeExpired?, revokedNonces?})` — returns the directory, defaulting to filter expired and (if `revokedNonces` is supplied) revoked rows.
- `removeMemberEntry(client, collectionPath, nonce)` — drops a row. Note that this only updates the directory; cryptographic revocation requires publishing a signed `RevocationList` to `_revocations/{rootUserId}`.

Server-side, `<col>/_members` is owner-only by virtue of cap scope: the `scopes.readOnly` and `scopes.writer` presets both include `!<col>/_members`, and `assertCapCertWellFormed` raises `member-members-not-denied` if a member cap would otherwise reach the path. Authorization for the collection itself does **not** consult `_members` — the cap-cert presented in `Authorization` headers and the revocation list are the only inputs. The directory is purely audit/UI metadata.

## Encryption surface

`createKeyringEncryptor` returns an `Encryptor` compatible with `SyncManager`:

```ts
const keyring = (await client.pull("notes/_keyring")).data as Keyring
const enc = await createKeyringEncryptor(
  keyring,
  { kemPubHex: dev.kemPub, kemPrivHex: dev.kemPriv },
  { trustedAdders: ["<owner-root-ed-pubkey-hex>"] },   // required — pubkey(s) you trust to grant access
)
const sync = new SyncManager({
  client,
  pullPath: "/pull/notes",
  pushPath: "/push/notes",
  encryptor: enc,
})

await sync.push({ secret: "hello" })   // sent as {_encrypted, _epoch}
const note = await sync.pull()          // decrypted plaintext
```

The encryptor decrypts any epoch where the device has a wrap entry. It encrypts under `currentEpoch` only. If a pulled document carries `_epoch: N` and the device has no wrap for epoch N (e.g. it was added after epoch N+1 with no history-isolation rotation, OR it was removed at epoch N+1), decryption raises an error — the device is not authorized for that document.

## Forward secrecy stance

Starfish 3.0 provides **post-compromise security via epoch rotation**, not full forward secrecy.

- **PCS:** after `rotateEpoch`, a previously-removed recipient cannot decrypt new documents, even if their long-term X25519 key was compromised at the time of removal.
- **Not FS:** persistent documents stay decryptable by current recipients. A current device whose key is compromised at time T exposes every document the device could read at time T.

Stronger FS would require deleting old CEKs from the keyring, which would also delete legitimate recipients' access to history. We deliberately chose history-readability over FS. To strengthen the threat model: rotate epochs periodically (not just on membership change), keep the wrap layer's ephemeral keys disposed promptly (already done), and pair each device with a hardware-backed key store on the platforms that support it.

## Cross-language test vectors

- [`identity-derivation.json`](../../../tests/test-vectors/identity-derivation.json) — passphrase → root keypair → userId.
- [`multi-recipient-wrap.json`](../../../tests/test-vectors/multi-recipient-wrap.json) — full keyring fixture: three recipients, wrap+unwrap roundtrip, addedSig verification.

Both TS and Python implementations must produce byte-identical wrap entries given the same `cek`, `recipient.kemPub`, deterministic `ephPriv`, and `iv` — the test suites enforce this against the vector files.
