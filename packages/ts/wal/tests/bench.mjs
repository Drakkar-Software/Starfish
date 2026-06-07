/**
 * Micro-benchmarks for the starfish-wal CRDT fold / merge / reconcile.
 *
 * Run from the package directory:  pnpm --filter @drakkar.software/starfish-wal bench
 * (the `bench` script builds the package first). Numbers are indicative
 * single-thread Node timings with one warmup pass, not a statistical benchmark.
 *
 * These guard the characteristics documented in docs/ts/wal/02-crdt-model.md and
 * 04-reconcile.md, and are how the materialize() stack-overflow and the O(N^2)
 * reconcile regressions were originally found.
 */
import { configurePlatform } from "@drakkar.software/starfish-protocol"
import { WalCrdt, WalDocument, createEd25519Signer, noopEncryptor } from "../dist/index.js"
import { ed25519 } from "@noble/curves/ed25519.js"

configurePlatform({
  base64: {
    encode: d => Buffer.from(d).toString("base64"),
    decode: s => new Uint8Array(Buffer.from(s, "base64")),
  },
})

const ms = fn => {
  const t = process.hrtime.bigint()
  const r = fn()
  return [Number(process.hrtime.bigint() - t) / 1e6, r]
}
const msAsync = async fn => {
  const t = process.hrtime.bigint()
  const r = await fn()
  return [Number(process.hrtime.bigint() - t) / 1e6, r]
}
const rate = (n, t) => Math.round(n / (t / 1000)).toLocaleString()
const fix = (x, d = 1) => x.toFixed(d)
const bytesToHex = b => [...b].map(x => x.toString(16).padStart(2, "0")).join("")

function signer() {
  const priv = ed25519.utils.randomSecretKey()
  return createEd25519Signer(bytesToHex(ed25519.getPublicKey(priv)), bytesToHex(priv))
}
class FakeTransport {
  els = []
  seq = 0
  async append(_k, body) {
    this.seq++
    this.els.push({ ts: this.seq, ...body })
    return { ts: this.seq }
  }
  async pull(_k, cp) {
    return this.els.filter(e => e.ts > cp)
  }
}
const DOC = "spaces/s/docs/d"
const linearInserts = N => {
  const ops = []
  for (let i = 0; i < N; i++)
    ops.push({ t: "ins", list: "b", id: `${i}@a`, after: i === 0 ? "" : `${i - 1}@a`, clock: { c: i + 1, r: "a" }, value: "x" })
  return ops
}

// Warmup (JIT) so the first reported case is not penalised.
{
  const c = new WalCrdt()
  c.fold(linearInserts(2000))
  c.text("b")
}

console.log("starfish-wal benchmarks —", process.version, "\n")

console.log("## 1. Fold a linear text/list (N sequential RGA inserts)")
for (const N of [1000, 10000, 50000]) {
  const ops = linearInserts(N)
  let c
  const [tf] = ms(() => { c = new WalCrdt(); c.fold(ops) })
  const [tm] = ms(() => c.text("b"))
  console.log(`  N=${N}: fold ${fix(tf)}ms (${rate(N, tf)} ops/s) | materialize ${fix(tm)}ms`)
}

console.log("\n## 2. Merge two concurrent replicas (each M head-inserts), folded shuffled")
for (const M of [5000, 20000]) {
  const ops = []
  for (const r of ["a", "b"]) for (let i = 0; i < M; i++)
    ops.push({ t: "ins", list: "l", id: `${i}@${r}`, after: "", clock: { c: i + 1, r }, value: r })
  for (let i = ops.length - 1; i > 0; i--) { const j = (Math.random() * (i + 1)) | 0;[ops[i], ops[j]] = [ops[j], ops[i]] }
  let c
  const [tf] = ms(() => { c = new WalCrdt(); c.fold(ops) })
  console.log(`  2×M=${2 * M} ops: fold ${fix(tf)}ms (${rate(2 * M, tf)} ops/s) | len=${c.listValues("l").length}`)
}

console.log("\n## 3. Reconcile setText() — localized 1-char edit on an N-char text")
for (const N of [1000, 2000, 4000]) {
  const doc = new WalDocument({ documentKey: DOC, transport: new FakeTransport(), signer: signer() })
  await doc.open()
  const base = "x".repeat(N)
  doc.setText("body", base)
  await doc.commit()
  const edited = base.slice(0, N / 2) + "Z" + base.slice(N / 2)
  const [t] = ms(() => doc.setText("body", edited))
  console.log(`  N=${N}: setText edit ${fix(t)}ms`)
}

console.log("\n## 4. End-to-end cold replay — open() verifies every element's Ed25519 sig + folds")
for (const N of [1000, 2000]) {
  const transport = new FakeTransport()
  const s = signer()
  const writer = new WalDocument({ documentKey: DOC, transport, signer: s })
  await writer.open()
  for (let i = 0; i < N; i++) { writer.setField("k" + i, i); await writer.commit() }
  const reader = new WalDocument({ documentKey: DOC, transport, signer: signer() })
  const [t] = await msAsync(() => reader.open())
  console.log(`  N=${N} elements: open ${fix(t)}ms (${rate(N, t)} elem/s incl. verify) | ~${fix(t / N, 3)}ms/elem`)
}
