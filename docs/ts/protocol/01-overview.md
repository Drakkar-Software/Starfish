# starfish-protocol

`@drakkar.software/starfish-protocol` (TS) / `starfish-protocol` (Py) — the shared contract layer. Pure types + crypto primitives, no opinions about features.

## What it provides

- Cap-cert types (`CapCert`, `CapKind`, `CapScope`, `UnsignedCapCert`) + canonical signing input.
- Cap-cert primitives: `signCapCert`, `verifyCapCertSignature`, `verifyCapCert` (signature + nbf/exp window), and `assertCapCertWellFormed` (generic iss/sub-userId relations only — kind-specific rules are owned by extensions).
- The cap-scope glob matcher `pathGlobMatch`, reused by extensions that own kind-specific scope rules.
- The plugin contract types `ServerPlugin` and `CapCertValidator` (the runtime helpers live in `starfish-server`).
- Request signing: `signRequest`, `verifyRequestSignature`, `isWithinClockSkew`.
- Hashing / canonicalization: `stableStringify`, `computeHash`, `deepMerge`, `UNSAFE_KEYS`.

## Plugin contract

`ServerPlugin` lives here so both the server host (`starfish-server`) and the extension packages (`starfish-identities`, `starfish-sharing`) reference it without a dependency cycle:

```ts
export type CapCertValidator = (cert: CapCert) => void
export interface ServerPlugin {
  name: string
  capValidators?: Partial<Record<CapKind, CapCertValidator>>
}
```

## Deep-dive docs

- [Capability certificates](../client/25-capability-certs.md) — full cap-cert schema, the validation pipeline, and revocation.
