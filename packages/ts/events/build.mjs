import { build } from "esbuild"

const ENTRIES = {
  index: "src/index.ts",
}

const EXTERNAL = [
  "@drakkar.software/starfish-protocol",
  "@drakkar.software/starfish-server",
]

await Promise.all(
  Object.entries(ENTRIES).map(([out, entry]) =>
    build({
      entryPoints: [entry],
      outfile: `dist/${out}.js`,
      bundle: true,
      format: "esm",
      target: "es2022",
      platform: "node",
      external: EXTERNAL,
      sourcemap: true,
      treeShaking: true,
      logLevel: "info",
    }),
  ),
)
