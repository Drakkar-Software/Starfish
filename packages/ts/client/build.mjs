import { build } from "esbuild"

const ENTRIES = {
  "index":            "src/index.ts",
  "bindings/zustand": "src/bindings/zustand.ts",
  "bindings/legend":  "src/bindings/legend.ts",
  "fetch":            "src/fetch.ts",
  "broadcast":        "src/broadcast.ts",
  "testing":          "src/testing.ts",
}

// Peer deps and the workspace dep stay external so consumers' bundlers dedupe
// them. zustand/middleware is intentionally bundled — see the plugin below.
const EXTERNAL = [
  "react",
  "react/*",
  "@legendapp/state",
  "@legendapp/state/*",
  "immer",
  "@drakkar.software/starfish-protocol",
]

// esbuild treats `zustand` external as covering all `zustand/*` subpaths.
// We need `zustand` + `zustand/vanilla` external (consumers ship their own
// peer-dep copy — duplicating would split state) but `zustand/middleware`
// MUST be bundled so esbuild can tree-shake `devtoolsImpl` (and its
// `import.meta.env`) out of the published file.
const zustandSelectiveExternal = {
  name: "zustand-selective-external",
  setup(b) {
    b.onResolve({ filter: /^zustand($|\/vanilla$)/ }, (args) => ({
      path: args.path,
      external: true,
    }))
  },
}

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
      plugins: [zustandSelectiveExternal],
      sourcemap: true,
      treeShaking: true,
      logLevel: "info",
    }),
  ),
)
