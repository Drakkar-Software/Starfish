---
sidebar_position: 2
sidebar_label: "Client Overview"
---

# Starfish TypeScript Client

`@drakkar.software/starfish-client` is a TypeScript SDK for document-level cloud sync. It provides end-to-end encryption, automatic conflict resolution, and reactive state management bindings — all with zero production dependencies beyond the protocol package.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Your Application                        │
│                                                             │
│  ┌─────────────────┐     ┌──────────────────────────────┐  │
│  │  State Binding   │     │  SyncManager                 │  │
│  │  (Zustand or     │────▶│  Encryption, conflict retry, │  │
│  │   Legend State)   │     │  signing, checkpoint tracking│  │
│  └─────────────────┘     └──────────┬───────────────────┘  │
│                                      │                      │
│                           ┌──────────▼───────────────────┐  │
│                           │  StarfishClient              │  │
│                           │  Low-level HTTP pull / push  │  │
│                           └──────────┬───────────────────┘  │
└──────────────────────────────────────┼──────────────────────┘
                                       │ HTTPS
                                       ▼
                              ┌──────────────────┐
                              │  Starfish Server  │
                              └──────────────────┘
```

**Three layers, use what you need:**

| Layer | Class / Function | Purpose |
|-------|-----------------|---------|
| Low-level | `StarfishClient` | Direct HTTP pull/push with auth |
| Mid-level | `SyncManager` | Encryption, conflict resolution, retry |
| High-level | `createStarfishStore` / `createStarfishObservable` | Reactive state with persistence |

## Reading Paths

### Quick start (sync data in 10 minutes)

1. [Getting Started](/getting-started/intro) — install, first pull/push
2. [Zustand Binding](/state-offline/state-zustand) or [Legend State Binding](/state-offline/state-legend) — reactive state
3. [Offline & Connectivity](/state-offline/offline-connectivity) — handle network changes

### Full deep dive

1. [Getting Started](/getting-started/intro) — install, first pull/push
2. [StarfishClient](/client-core/starfish-client) — low-level HTTP client API
3. [SyncManager](/client-core/sync-manager) — high-level sync orchestrator
4. [Encryption](/encryption-identity/encryption) — `"none"` vs `"delegated"` E2E encryption
5. [Conflict Resolution](/client-core/conflict-resolution) — strategies and retry mechanics
6. [Zustand Binding](/state-offline/state-zustand) and/or [Legend State Binding](/state-offline/state-legend)
7. [Offline & Connectivity](/state-offline/offline-connectivity) — offline-first, sync status, polling
8. [Integration Patterns](/integration-operations/integration-patterns) — optimistic UI, lifecycle hooks, validation, compression
9. [Platform Setup](/getting-started/platform-setup) — React Native, custom crypto
10. [Identity & Key Derivation](/encryption-identity/identity-key-derivation) — passphrase → root key pair → device keys
11. [Schema Versioning](/data-modeling/schema-versioning) — evolving document formats
12. [Testing Strategies](/integration-operations/testing) — mocking, unit tests, integration tests
13. [Multi-Tab Sync](/state-offline/multi-tab-sync) — BroadcastChannel, cross-tab state
14. [Error Classification & Retry](/client-core/error-retry) — retry, circuit breaker, auth refresh
15. [Logging & Observability](/integration-operations/logging-observability) — structured logging, sync metrics
16. [Data Export / Import](/data-modeling/data-export-import) — GDPR export, account migration
17. [Multi-Document Architecture](/data-modeling/multi-document-architecture) — partitioning, URL design, dynamic docs
18. [Collection Patterns](/data-modeling/collection-patterns) — RBAC and access-control patterns
19. [Namespaces](/data-modeling/namespaces) — tenant-style namespace routing
20. [Binary Collections](/data-modeling/binary-collections) — opaque-blob collections
21. [Multi-Recipient Delegated Encryption](/encryption-identity/multi-recipient-delegated) — keyring, epochs, recipient management
22. [Pairing](/encryption-identity/pairing) — bootstrap, in-person QR, and server-relay invite flows
23. [Capability Certificates](/encryption-identity/capability-certs) — cap-cert schema, validation, minting
24. [Identity Models](/encryption-identity/identity-models) — ed25519-only wire; secp256k1 root bootstrap via signature derivation
25. [SSE Subscribe Transport](/client-core/sse-subscribe) — real-time change notifications via Server-Sent Events
26. [Anonymous Append](/encryption-identity/anonymous-append) — unauthenticated append-only writes
27. [KV Pull Cache](/state-offline/kv-pull-cache) — persist pull results in any async KV store
28. [WAL Client Adapters](/integration-operations/wal-client-adapters) — WAL-backed sync adapters
29. [Bulk & Multi-Content Sync](/data-modeling/bulk-multi-content-sync) — `batchPull`, bundles, projection, fan-out push patterns

Migrating from 2.x? Start with the runbook: [Migration: v2 to v3](/migration/v2-to-v3).

## Page Index

| Page | Description |
|------|-------------|
| [Getting Started](/getting-started/intro) | Install and first sync in under 2 minutes |
| [StarfishClient](/client-core/starfish-client) | Low-level HTTP transport, cap providers, custom fetch |
| [SyncManager](/client-core/sync-manager) | Encryption, conflict retry, signing, incremental sync |
| [Encryption](/encryption-identity/encryption) | Two modes: `"none"` and `"delegated"` (E2E AES-256-GCM via keyring) |
| [Zustand Binding](/state-offline/state-zustand) | Reactive store with persistence, devtools, Immer |
| [Legend State Binding](/state-offline/state-legend) | Fine-grained observable state |
| [Conflict Resolution](/client-core/conflict-resolution) | Default merge, ID + timestamp strategies, soft-delete-aware merge |
| [Offline & Connectivity](/state-offline/offline-connectivity) | Dirty tracking, flush-on-reconnect, sync status, polling |
| [Integration Patterns](/integration-operations/integration-patterns) | Debounced push, soft delete, local history, optimistic UI, validation, compression |
| [Platform Setup](/getting-started/platform-setup) | React Native, Node.js, custom crypto/fetch |
| [Identity & Key Derivation](/encryption-identity/identity-key-derivation) | Root identity Argon2id → HKDF derivation, per-device generated keys |
| [Schema Versioning](/data-modeling/schema-versioning) | Document migrations across app versions |
| [Testing Strategies](/integration-operations/testing) | Mocking, conflict resolver tests, integration tests |
| [Multi-Tab Sync](/state-offline/multi-tab-sync) | BroadcastChannel, cross-tab state consistency |
| [Error Classification & Retry](/client-core/error-retry) | Retry, circuit breaker, auth token refresh |
| [Logging & Observability](/integration-operations/logging-observability) | Structured logging, performance metrics |
| [Data Export / Import](/data-modeling/data-export-import) | GDPR export, account migration, encrypted export |
| [Multi-Document Architecture](/data-modeling/multi-document-architecture) | Partitioning, URL design, dynamic documents |
| [Collection Patterns](/data-modeling/collection-patterns) | Server-side RBAC and access-control patterns |
| [Namespaces](/data-modeling/namespaces) | Tenant-style namespace routing |
| [Binary Collections](/data-modeling/binary-collections) | Opaque-blob collections |
| [Multi-Recipient Delegated Encryption](/encryption-identity/multi-recipient-delegated) | Keyring schema, wrap/unwrap, epoch rotation |
| [Pairing](/encryption-identity/pairing) | Bootstrap, in-person QR, and server-relay invite flows |
| [Capability Certificates](/encryption-identity/capability-certs) | Cap-cert schema, validation, mint helpers |
| [Identity Models](/encryption-identity/identity-models) | Ed25519-only wire; secp256k1 root bootstrap via signature derivation |
| [SSE Subscribe Transport](/client-core/sse-subscribe) | Real-time change notifications, auto-reconnect, backoff |
| [Anonymous Append](/encryption-identity/anonymous-append) | Unauthenticated append-only writes |
| [KV Pull Cache](/state-offline/kv-pull-cache) | Persist pull results in MMKV, AsyncStorage, localStorage, etc. |
| [WAL Client Adapters](/integration-operations/wal-client-adapters) | WAL-backed sync adapters |
| [Bulk & Multi-Content Sync](/data-modeling/bulk-multi-content-sync) | `batchPull`, bundles, projection, fan-out push patterns, freshness |

For migration guidance, see [`docs/migration/v2-to-v3.md`](/migration/v2-to-v3).
