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

1. [Getting Started](01-getting-started.md) — install, first pull/push
2. [Zustand Binding](05-state-zustand.md) or [Legend State Binding](06-state-legend.md) — reactive state
3. [Offline & Connectivity](08-offline-connectivity.md) — handle network changes

### Full deep dive

1. [Getting Started](01-getting-started.md) — install, first pull/push
2. [StarfishClient](02-starfish-client.md) — low-level HTTP client API
3. [SyncManager](03-sync-manager.md) — high-level sync orchestrator
4. [Encryption](04-encryption.md) — `"none"` vs `"delegated"` E2E encryption
5. [Conflict Resolution](07-conflict-resolution.md) — strategies and retry mechanics
6. [Zustand Binding](05-state-zustand.md) and/or [Legend State Binding](06-state-legend.md)
7. [Offline & Connectivity](08-offline-connectivity.md) — offline-first, sync status, polling
8. [Integration Patterns](09-integration-patterns.md) — optimistic UI, lifecycle hooks, validation, compression
9. [Platform Setup](10-platform-setup.md) — React Native, custom crypto
10. [Identity & Key Derivation](11-identity-key-derivation.md) — passphrase → root key pair → device keys
11. [Schema Versioning](12-schema-versioning.md) — evolving document formats
12. [Testing Strategies](13-testing.md) — mocking, unit tests, integration tests
13. [Multi-Tab Sync](14-multi-tab-sync.md) — BroadcastChannel, cross-tab state
14. [Error Classification & Retry](15-error-retry.md) — retry, circuit breaker, auth refresh
15. [Logging & Observability](16-logging-observability.md) — structured logging, sync metrics
16. [Data Export / Import](17-data-export-import.md) — GDPR export, account migration
17. [Multi-Document Architecture](18-multi-document-architecture.md) — partitioning, URL design, dynamic docs
18. [Collection Patterns](19-collection-patterns.md) — RBAC and access-control patterns
19. [Namespaces](20-namespaces.md) — tenant-style namespace routing
20. [Binary Collections](22-binary-collections.md) — opaque-blob collections
21. [Multi-Recipient Delegated Encryption](23-multi-recipient-delegated.md) — keyring, epochs, recipient management
22. [Pairing](24-pairing.md) — bootstrap, in-person QR, and server-relay invite flows
23. [Capability Certificates](25-capability-certs.md) — cap-cert schema, validation, minting

Migrating from 2.x? Start with the runbook: [Migration: v2 to v3](../../migration/v2-to-v3.md).

## Page Index

| Page | Description |
|------|-------------|
| [Getting Started](01-getting-started.md) | Install and first sync in under 2 minutes |
| [StarfishClient](02-starfish-client.md) | Low-level HTTP transport, cap providers, custom fetch |
| [SyncManager](03-sync-manager.md) | Encryption, conflict retry, signing, incremental sync |
| [Encryption](04-encryption.md) | Two modes: `"none"` and `"delegated"` (E2E AES-256-GCM via keyring) |
| [Zustand Binding](05-state-zustand.md) | Reactive store with persistence, devtools, Immer |
| [Legend State Binding](06-state-legend.md) | Fine-grained observable state |
| [Conflict Resolution](07-conflict-resolution.md) | Default merge, ID + timestamp strategies, soft-delete-aware merge |
| [Offline & Connectivity](08-offline-connectivity.md) | Dirty tracking, flush-on-reconnect, sync status, polling |
| [Integration Patterns](09-integration-patterns.md) | Debounced push, soft delete, local history, optimistic UI, validation, compression |
| [Platform Setup](10-platform-setup.md) | React Native, Node.js, custom crypto/fetch |
| [Identity & Key Derivation](11-identity-key-derivation.md) | Root identity Argon2id → HKDF derivation, per-device generated keys |
| [Schema Versioning](12-schema-versioning.md) | Document migrations across app versions |
| [Testing Strategies](13-testing.md) | Mocking, conflict resolver tests, integration tests |
| [Multi-Tab Sync](14-multi-tab-sync.md) | BroadcastChannel, cross-tab state consistency |
| [Error Classification & Retry](15-error-retry.md) | Retry, circuit breaker, auth token refresh |
| [Logging & Observability](16-logging-observability.md) | Structured logging, performance metrics |
| [Data Export / Import](17-data-export-import.md) | GDPR export, account migration, encrypted export |
| [Multi-Document Architecture](18-multi-document-architecture.md) | Partitioning, URL design, dynamic documents |
| [Collection Patterns](19-collection-patterns.md) | Server-side RBAC and access-control patterns |
| [Namespaces](20-namespaces.md) | Tenant-style namespace routing |
| [Binary Collections](22-binary-collections.md) | Opaque-blob collections |
| [Multi-Recipient Delegated Encryption](23-multi-recipient-delegated.md) | Keyring schema, wrap/unwrap, epoch rotation |
| [Pairing](24-pairing.md) | Bootstrap, in-person QR, and server-relay invite flows |
| [Capability Certificates](25-capability-certs.md) | Cap-cert schema, validation, mint helpers |

For migration guidance, see [`docs/migration/v2-to-v3.md`](../../migration/v2-to-v3.md).
