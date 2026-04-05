# ADR-001: TypeScript Server over Rust + WASM

**Status:** Proposed  
**Date:** 2026-04-05

## Context

Starfish needs a server implementation alongside its existing Python/FastAPI server. The question: should the new server be written in TypeScript (Node.js) or Rust (with WASM compatibility)?

Current state:
- **Python server** (~2,900 lines): FastAPI, storage backends (memory, filesystem, S3), encryption, RBAC, replicas
- **`@starfish/protocol`** (TS): hash (SHA-256), crypto (HKDF + AES-256-GCM), merge, stable stringify — zero dependencies, Web Crypto API
- **`@starfish/client`** (TS): HTTP client, SyncManager, Zustand/Legend State bindings
- **No Rust/WASM** in the codebase

## Decision

Use **TypeScript** with **Hono** as the server framework.

## Rationale

### 1. Direct Code Reuse

A TS server imports `@starfish/protocol` directly — `computeHash`, `stableStringify`, `deepMerge`, `deriveKey` are already implemented and tested. This eliminates one entire cross-language implementation surface. A Rust server would require a fourth implementation of these primitives, plus WASM bindings to expose them back to JS.

### 2. Performance Is I/O-Bound

The server hot path (push): `store.get()` (I/O, 5-50ms for S3) -> JSON parse -> `compute_timestamps()` -> `computeHash()` -> `store.put()` (I/O). Storage I/O dominates. SHA-256 and AES-256-GCM are hardware-accelerated in Node.js (OpenSSL / AES-NI) just like in Rust. On individual JSON documents (kilobytes), Rust's CPU advantage is unmeasurable.

### 3. WASM Adds Complexity Without Benefit

- Edge runtimes: TS runs natively on Cloudflare Workers, Vercel Edge, Deno Deploy
- Browser server: no use case for a sync server in-browser
- Portable core: `@starfish/protocol` already runs everywhere JS runs via `configurePlatform`
- WASM would add wasm-pack, wasm-bindgen, and JS glue code for portability that already exists

### 4. Developer Experience and Audience Fit

Target audience is JS/TS developers (Zustand, Legend State, React). They want:
- `npm install @starfish/server`, not `cargo build`
- JS callbacks for custom storage/auth, not FFI bindings
- Same language across client, protocol, and server

| Aspect | TypeScript | Rust + WASM |
|--------|-----------|-------------|
| Deploy | `npm install` + `node` | Compile per arch or Docker |
| Extend | JS callbacks | FFI bindings |
| Maintain | Same lang as client/protocol | Third language in monorepo |
| CI | Existing pnpm/vitest | +Rust toolchain, +wasm-pack |

### 5. Framework: Hono

Hono is already a devDependency in `@starfish/client`. It runs on Node.js, Deno, Bun, Cloudflare Workers, and Vercel Edge with zero adapter changes. Router API is similar to FastAPI's pattern.

### 6. Implementation Effort

- TS port: ~2,000 lines (protocol layer is free via reuse)
- Rust port: ~3,500-4,000 lines + ~500 lines WASM glue — roughly 2x effort for zero user-facing benefit

## When Rust Would Be Reconsidered

- Bulk data processing (millions of documents per request)
- Standalone binary distribution requirement
- Systems engineer target audience
- CPU-bound protocol primitives (not the case — SHA-256 is hardware-accelerated)

## Consequences

- The TS server becomes the primary server, Python server remains for Python-native deployments
- Protocol code is shared directly, reducing cross-language divergence risk
- Server is deployable to any JS runtime (Node.js, Deno, Bun, edge)
- Contributors only need TS + Python expertise (not Rust)
