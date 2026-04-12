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
  python/                # Python packages
    protocol/            # starfish-protocol
    client/              # starfish-sdk
    server/              # starfish-server
docs/                    # Documentation (Markdown)
  ts/client/             # Client guides (01-18)
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
- **Versioning**: semver, tag-triggered releases (v*). **All six packages use lockstep versioning** — every release bumps all packages to the same version number, even if a package has no changes. Packages: `packages/ts/protocol`, `packages/ts/server`, `packages/ts/client`, `packages/python/protocol`, `packages/python/server`, `packages/python/client`.
- **CHANGELOG**: `## X.Y.Z` headers with `### Added`, `### Changed`, `### Fixed` sections

## Mandatory Post-Change Checklist

After every change, you **must**:

1. **Run tests** — all existing tests must pass; add tests for new behavior
   - TypeScript: `pnpm test` from repo root
   - Python: `uv run pytest -v` in the relevant `packages/python/<pkg>` directory
2. **Update documentation** — update or add relevant files in `docs/`
3. **Update README.md** — reflect any new features, changed APIs, or removed functionality
4. **Update CHANGELOG.md** — add an entry under the correct `### Added` / `### Changed` / `### Fixed` section for the current version at the top of the file
