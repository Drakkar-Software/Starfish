#!/usr/bin/env bash
# Idempotent Cloud Agent bootstrap for the Starfish monorepo.
# - TypeScript workspace: pnpm install + build (the example frontend imports the
#   built workspace packages, so a build is required for a working dev setup).
# - Python example backend: uv sync resolves the workspace packages editable.
# Any failing step stops the script with a non-zero exit code.
set -euo pipefail

cd "$(dirname "$0")/.."

UV_VERSION="0.12.23"

export PATH="$HOME/.local/bin:$PATH"

installed_uv_version() {
  uv --version | awk '{print $2}'
}

# uv is the pinned Python package manager but is not in the default image.
if ! command -v uv >/dev/null 2>&1 || [ "$(installed_uv_version)" != "$UV_VERSION" ]; then
  curl -LsSf "https://astral.sh/uv/${UV_VERSION}/install.sh" | sh
fi
if [ "$(installed_uv_version)" != "$UV_VERSION" ]; then
  echo "expected uv ${UV_VERSION}, found: $(uv --version 2>/dev/null || echo none)" >&2
  exit 1
fi

# Node package manager is provided via corepack in the default image.
corepack enable >/dev/null

# TypeScript packages (lockfile is committed and authoritative).
pnpm install --frozen-lockfile
pnpm build

# Python example backend + all workspace Python packages (editable).
# --frozen installs from the committed uv.lock without rewriting it. The lock
# is known to be stale; refreshing it is tracked separately, not in this script.
( cd examples/app/backend && uv sync --frozen )
