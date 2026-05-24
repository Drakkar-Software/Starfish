# API Keys for Starfish — Design Exploration

> Status: exploration. No implementation committed yet. This document compares options for a
> machine-to-machine API-key credential and records a recommendation.

## 1. Background & constraints

Starfish authorization is carried entirely by **capability certificates (cap-certs)** — signed tokens
issued by a root identity, verified statelessly by the server (signature + time window, no DB lookup).
Existing kinds:

| kind | subject | who signs each request | use |
|------|---------|------------------------|-----|
| `device` | issuer proxies for the device (`iss===sub` for root) | the device key | device→server |
| `member` | a distinct subject identity, scoped grant | the subject key | shared scoped access |
| `audience` | **no** single subject; optional `aud` allow-list | each redeemer's *own* key (`X-Starfish-Pub`) | public links |

Every authenticated request also carries a **per-request Ed25519 signature** over
`{method, path+query, body, host, ts, nonce}` (`X-Starfish-Sig` + `X-Starfish-Ts` + `X-Starfish-Nonce`),
giving attribution and replay protection (nonce cache). Bearer tokens are deliberately *not* used.

**Goal.** A credential a non-interactive client (backend service, sensor, edge worker) can hold to
push into a collection — ideally an append-only event log — that is:

- **Stateless** — server verifies with no key store / no per-key DB row.
- **Secure** — least privilege, time-boxed, leak-resilient, replay-resistant.
- **Easy** — ideally one copy-paste string, no keypair ceremony for the user.

## 2. Why "stateless" doesn't break the tie

All cap-based options are equally stateless: a cap is self-contained and verified by signature + `exp`.
The only thing that adds server state is **nonce-based revocation**, which is opt-in and applies to
every option equally. So statelessness is a wash; the decision is **security vs. ease**.

## 3. Options

### Option γ — Bearer cap (rejected)

Cap authenticates by *possession alone*; drop the per-request signature for these tokens.

- ✅ One string, trivial.
- ❌ The header **is** the credential: fully replayable if it leaks (proxy log, error dump). Breaks the
  nonce/attribution model. Requires new server-side handling. No real DX win over a packed key.

**Verdict: rejected.** Regresses the security model for no ease gain.

### Option α — Audience cap + holder's own key

The "API key" is a writer-scoped **audience** cap (today's public-link mechanism), optionally with an
`aud` allow-list naming the service's pubkey. The service **generates its own keypair**, shares only
its pubkey with the owner, and signs each request with its own key.

- ✅ **Most leak-resistant.** The token on the wire / at rest (the cap) carries **no secret**. Leak it
  → attacker gets a useless cap (can't forge the signature). The signing key is born at the holder and
  **never travels**, and the issuer never learns it.
- ❌ **Not "easy".** The holder must generate a keypair, exchange a pubkey out-of-band, and manage two
  artifacts (cap + private key). Not a copy-paste API key.

**Verdict: gold-standard security, weak DX.** Already supported via `createPublicLink` + `scopes.writer`.

### Option β — Packed cap + embedded key

Mint a fresh subject keypair, bind it into a `member`-style cap, and pack **cap + subject private key**
into one opaque token (`sfk_<base64url(...)>`). The client library extracts the key and signs each
request transparently. The server sees a normal member cap — **no new cap kind, no server change**.

- ✅ **Easiest** — one copy-paste string, no keypair ceremony. Classic API-key DX.
- ✅ Stateless, scoped, expirable, revocable-by-nonce.
- ⚠️ The token **contains a secret** (the private key). Leak the *token at rest* (env var, git, config)
  → compromise. Same blast radius as any normal API key (Stripe / AWS / GitHub PAT). The **issuer also
  knows** the key (it minted it).

**Crucial detail:** the embedded key is a *signing* key — it does **not** need to go on the wire. The
client lib puts only the **cap** in the `Authorization` header and uses the key **locally** to produce
`X-Starfish-Sig`. Done this way β's **wire profile equals α's**: a leaked header/request exposes only
the cap, useless without the key. β is then weaker than α in exactly one place — **issuance** (the key
is born at the minter and handed over once).

### Option β′ — Hardened β (recommended baseline)

Plain β with mandatory hardening, all stateless and DX-preserving:

1. **Key off the wire** — library contract, not an option. Header carries the cap only; the key signs
   locally. (Closes the header-leak gap; matches α on the wire.)
2. **Least privilege** — cap bound to **write-only + one collection + a path prefix**. A leaked key can
   only *append to one log* — can't read it, can't reach `_keyring`/`_members`, can't touch other data.
   (Add an append/write-only scope preset; `scopes.writer` already denies `_keyring`/`_members`.)
3. **Short `exp` + trivial rotation** — expiry baked into the cap; one-call re-mint. Stateless; shrinks
   the leak window — the standard mitigation for an at-rest secret.
4. **Recognizable prefix** (`sfk_…`) — lets gitleaks / secret scanners catch the token in commits/logs.
5. **Optional nonce revocation** — kill-switch for a known-leaked key. The *only* item that costs
   statelessness, and only when enabled.

**Residual risk (inherent to embedding a key):** the secret exists at rest in the token, and the issuer
knew it once. This is true of every stateless API key in existence; security comes from least-privilege
+ expiry + rotation (items 2–3).

### Option β″ — β with client-side keygen (α's security, β's DX)

Like β′, but the **holder generates the keypair locally** (`generateApiKey()` run by the service), and
the owner/server only ever sees the **pubkey**. The "API key" string is still one copy-paste artifact,
but the issuer never learns the private key and the key is never transmitted.

- ✅ α's issuance property (key born at holder, issuer never sees it) **with** β's one-string DX.
- ⚠️ Slightly more setup: a `generateApiKey()` step before the owner mints/authorizes. Two-step issuance
  (holder generates → owner authorizes pubkey) instead of one (owner mints → hands over).

This is "α wearing β's clothes." Best security/DX balance if the extra issuance step is acceptable.

## 4. Comparison

| | Stateless | Wire-secret-free | At-rest secret | Issuer-blind | Replay-resistant | Copy-paste DX |
|---|---|---|---|---|---|---|
| γ bearer | ✅ | ❌ (header *is* secret) | n/a | ❌ | ❌ | ✅ |
| α audience + own key | ✅ | ✅ | holder only | ✅ | ✅ | ❌ (keypair ceremony) |
| β plain | ✅ | ✅ (if key off wire) | in token | ❌ | ✅ | ✅ |
| **β′ hardened** | ✅ | ✅ | in token | ❌ | ✅ | ✅ |
| **β″ client keygen** | ✅ | ✅ | holder only | ✅ | ✅ | ✅ (one extra gen step) |

## 5. Recommendation

- **Default / ship first: β′ (hardened packed key).** Best ease, stateless, signature-bound (stronger
  than the bearer API keys developers already trust), and the hardening (least-privilege + expiry +
  rotation + prefix) covers the realistic threat model. No server changes — pure protocol/sharing/client
  packaging.
- **Offer β″ for security-sensitive users** who want issuer-blind keys without the full α ceremony.
- **α remains available** (it's just `createPublicLink` + `scopes.writer`) for the most leak-averse.
- **γ rejected.**

## 6. Open questions

- Token prefix / format: `sfk_<base64url(json)>`? Version byte?
- Where minting lives: alongside `public-link.ts` in `sharing/` (member/audience caps already live there).
- Client surface: `makeClient({ apiKey })` auto-splits the token and signs transparently.
- Do we ship β′ and β″ both, or β′ first and β″ later?
- Rotation/revocation ergonomics and docs.
- **Write-only scope preset is new.** `scopes.writer(col)` grants read+list+write. A genuine
  append/write-only preset (no read, no list) must be added and must still satisfy the member/audience
  cap validators (deny `<col>/_keyring` and `<col>/_members`). Part of the β′ build surface.
