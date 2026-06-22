import { build } from "esbuild"

const ENTRIES = {
  index: "src/index.ts",
}

const EXTERNAL = [
  "@drakkar.software/starfish-protocol",
  "@drakkar.software/starfish-client",
  "@drakkar.software/starfish-keyring",
  "@drakkar.software/starfish-sharing",
  "@drakkar.software/starfish-identities",
  "@drakkar.software/starfish-server",
  "@noble/curves",
  "@noble/hashes",
  "@scure/bip39",
]

await Promise.all(
  Object.entries(ENTRIES).map(([out, entry]) =>
    build({
      entryPoints: [entry],
      outfile: `dist/${out}.js`,
      bundle: true,
      format: "esm",
      target: "es2022",
      platform: "neutral",
      external: EXTERNAL,
      sourcemap: true,
      treeShaking: true,
      logLevel: "info",
    }),
  ),
)
