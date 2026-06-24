---
slug: /
sidebar_position: 0
---

# Starfish

**Starfish** is a generic document sync library with hash-based conflict detection, incremental sync via timestamps, and role-based access control. It supports any storage backend (S3, MongoDB, in-memory) and any auth model.

Dual implementation in **TypeScript** and **Python**.

## What you get

- **Conflict-free sync** — optimistic concurrency with hash-based detection and automatic three-way merge
- **End-to-end encryption** — delegated AES-256-GCM; server holds no keys
- **Cap-cert auth** — Ed25519-signed capability certificates, per-device or per-member scope
- **Incremental sync** — checkpoint-based pulls; only changed fields travel over the wire
- **Batch operations** — `batchPull` reads many collections and documents in one round-trip
- **Real-time** — SSE change stream with auto-reconnect
- **Any backend** — bring your own `ObjectStore` (S3, MongoDB, in-memory, …)

## Getting started

```bash
npm install @drakkar.software/starfish-client @drakkar.software/starfish-protocol
```

→ [TypeScript client guide](ts/client/01-getting-started.md)

```bash
pip install starfish-sdk
```

→ [Python server guide](python/server/storage.md)

## Sections

| Section | Description |
|---------|-------------|
| [TypeScript Client](ts/client/01-getting-started.md) | 31-page guide: sync, encryption, auth, offline, patterns |
| [TypeScript Server](ts/server/storage.md) | Server setup, storage, extensions |
| [TypeScript WAL](ts/wal/01-overview.md) | Write-Ahead Log extension |
| [TypeScript Spaces](ts/spaces/01-overview.md) | Multi-tenant spaces |
| [Python Server](python/server/storage.md) | Python FastAPI server |
| [Migration v2 → v3](migration/v2-to-v3.md) | Upgrade guide |
| [Packages](/packages) | Per-package API references (TS + Python) |
