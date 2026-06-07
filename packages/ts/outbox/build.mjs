import { build } from "esbuild"

await build({
  entryPoints: ["src/index.ts"],
  outfile: "dist/index.js",
  bundle: true,
  format: "esm",
  target: "es2022",
  platform: "neutral",
  sourcemap: true,
  treeShaking: true,
  logLevel: "info",
})
