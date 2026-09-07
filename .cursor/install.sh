#!/usr/bin/env bash
# Idempotent Cloud Agent bootstrap for the Starfish monorepo.
# - TypeScript workspace: pnpm install + build (the example frontend imports the
#   built workspace packages, so a build is required for a working dev setup).
# - Python example backend: uv sync resolves the workspace packages editable.
set -euo pipefail

cd "$(dirname "$0")/.."

# uv is the pinned Python package manager but is not in the default image.
if ! command -v uv >/dev/null 2>&1; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi
export PATH="$HOME/.local/bin:$PATH"

# Node package manager is provided via corepack in the default image.
corepack enable >/dev/null 2>&1 || true

# TypeScript packages (lockfile is committed and authoritative).
pnpm install --frozen-lockfile
pnpm build

# Python example backend + all workspace Python packages (editable).
# The example uses plain `uv sync` (per examples/app/backend/README.md); the
# committed lock predates the current workspace version so a fresh resolve is
# expected here.
( cd examples/app/backend && uv sync )
