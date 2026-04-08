FROM node:22-slim
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.json ./
COPY packages/ts/protocol/ packages/ts/protocol/
COPY packages/ts/server/ packages/ts/server/
RUN corepack enable && pnpm install --frozen-lockfile \
    && pnpm --filter @drakkar.software/starfish-protocol build \
    && pnpm --filter @drakkar.software/starfish-server build
EXPOSE 3000
# The server library does not ship a standalone entrypoint; point CMD at your
# own compiled server file, e.g.:
#   CMD ["node", "packages/ts/server/dist/my-server.js"]
CMD ["node", "--version"]
