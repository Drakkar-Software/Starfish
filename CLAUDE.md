# CLAUDE.md

## Project Overview

Starfish is a generic document sync library with hash-based conflict detection, incremental sync via timestamps, and role-based access control. It supports any storage backend (S3, MongoDB, in-memory) and any auth model. Dual implementation in TypeScript and Python.

## Repository Structure

```
packages/
  ts/                    # TypeScript packages (pnpm workspaces)
    protocol/            # @drakkar.software/starfish-protocol
    client/              # @drakkar.software/starfish-client
    server/              # @drakkar.software/starfish-server
    keyring/             # @drakkar.software/starfish-keyring (extension)
    identities/          # @drakkar.software/starfish-identities (extension)
    sharing/             # @drakkar.software/starfish-sharing (extension)
    entitlements/        # @drakkar.software/starfish-entitlements (extension)
    queuing/             # @drakkar.software/starfish-queuing (extension)
    audit/               # @drakkar.software/starfish-audit (extension)
    replica/             # @drakkar.software/starfish-replica (extension)
  python/                # Python packages
    protocol/            # starfish-protocol
    client/              # starfish-sdk
    server/              # starfish-server
    keyring/             # starfish-keyring (extension)
    identities/          # starfish-identities (extension)
    sharing/             # starfish-sharing (extension)
    entitlements/        # starfish-entitlements (extension)
    queuing/             # starfish-queuing (extension)
    audit/               # starfish-audit (extension)
    replica/             # starfish-replica (extension)
docs/                    # Documentation (Markdown)
  ts/client/             # Client guides (01-25)
examples/                # Usage examples (ts/ and python/)
tests/
  test-vectors/          # Cross-language protocol conformance vectors (JSON)
.github/workflows/       # CI/CD pipelines
```

## Build & Test Commands

### TypeScript (pnpm + Vitest)

```bash
pnpm install             # Install dependencies
pnpm build               # Build all packages (tsc --build)
pnpm test                # Run all tests (vitest)
pnpm typecheck           # Type-check without emitting (tsc --noEmit)
```

### Python (uv + pytest)

```bash
cd packages/python/<pkg>
uv sync                  # Install dependencies
uv run pytest -v         # Run tests
```

## Conventions

- **TypeScript**: strict mode, ESNext target, bundler module resolution
- **Python**: async/await, FastAPI, Pydantic v2, asyncio_mode = "auto" for tests
- **Encryption modes**: `"none"` (plaintext) and `"delegated"` (client-side AES-256-GCM, N-recipient via per-collection keyring). Server holds no keys. Legacy `"identity"` / `"server"` / `"group"` modes were removed in v3.0.
- **Identity**: Ed25519 (sign) + X25519 (KEM) keypairs. Root identity is derived from a passphrase via Argon2id → HKDF-SHA256; per-device keypairs are generated locally and never leave the device. Authorization is carried by signed capability certificates (cap-certs) issued by the root identity. Cap-certs have a `kind`: `"device"` (proxy for issuer) or `"member"` (subject keeps own identity, scoped grant).
- **Versioning**: semver, tag-triggered releases (v*). **All twenty packages use lockstep versioning** — every release bumps all packages to the same version number, even if a package has no changes. Packages: `packages/ts/protocol`, `packages/ts/server`, `packages/ts/client`, `packages/ts/keyring`, `packages/ts/identities`, `packages/ts/sharing`, `packages/ts/entitlements`, `packages/ts/queuing`, `packages/ts/audit`, `packages/ts/replica`, `packages/python/protocol`, `packages/python/server`, `packages/python/client`, `packages/python/keyring`, `packages/python/identities`, `packages/python/sharing`, `packages/python/entitlements`, `packages/python/queuing`, `packages/python/audit`, `packages/python/replica`.
- **CHANGELOG**: `## X.Y.Z` headers with `### Added`, `### Changed`, `### Fixed` sections

## Mandatory Post-Change Checklist

After every change, you **must**:

1. **Run tests** — all existing tests must pass; add tests for new behavior
   - TypeScript: `pnpm test` from repo root
   - Python: `uv run pytest -v` in the relevant `packages/python/<pkg>` directory
2. **Update documentation** — update or add relevant files in `docs/`
3. **Update README.md** — reflect any new features, changed APIs, or removed functionality
4. **Update CHANGELOG.md** — add an entry under the correct `### Added` / `### Changed` / `### Fixed` section for the current version at the top of the file
