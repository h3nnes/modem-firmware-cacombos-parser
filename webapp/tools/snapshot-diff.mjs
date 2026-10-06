// Compares two `tools/bench.mjs --out` snapshots: the parity contract is the
// `snapshot` array (recordJson + per-record web-table SHA-256), which must stay
// byte-identical across every performance step. Metrics (timings, read counts)
// are printed side by side for the handoff table; only the snapshot decides the
// exit code.
//
// Usage: node tools/snapshot-diff.mjs <before.json> <after.json>
import { readFile } from "node:fs/promises";

const [beforePath, afterPath] = process.argv.slice(2);
if (!beforePath || !afterPath) {
  console.error("usage: node tools/snapshot-diff.mjs <before.json> <after.json>");
  process.exit(2);
}

const load = async (p) => JSON.parse(await readFile(p, "utf8"));
const [before, after] = await Promise.all([load(beforePath), load(afterPath)]);

const metricRows = [
  ["records", (m) => m.records],
  ["scan ms", (m) => m.scanMs],
  ["extractContainer ms", (m) => m.extractContainerMs ?? "-"],
  ["parse ms", (m) => m.parseMs],
  ["tables ms", (m) => m.tablesMs],
  ["mtkDecode ms", (m) => m.mtkDecodeMs ?? "-"],
  ["scan reads", (m) => m.phases.scan.reads],
  ["scan bytes", (m) => m.phases.scan.bytes],
  ["extract reads", (m) => m.phases.extractContainer?.reads ?? "-"],
  ["extract bytes", (m) => m.phases.extractContainer?.bytes ?? "-"],
];
console.log(`# ${before.input}`);
console.log(`${"metric".padEnd(22)} ${"before".padStart(14)} ${"after".padStart(14)}`);
for (const [label, pick] of metricRows) {
  const b = pick(before);
  const a = pick(after);
  const flag = String(b) === String(a) ? "" : "  *";
  console.log(`${label.padEnd(22)} ${String(b).padStart(14)} ${String(a).padStart(14)}${flag}`);
}

const bSnap = JSON.stringify(before.snapshot);
const aSnap = JSON.stringify(after.snapshot);
if (bSnap === aSnap) {
  console.log(`PARITY OK — ${before.snapshot.length} record snapshot(s) identical`);
  process.exit(0);
}

// Find the first divergent record for a readable failure.
const n = Math.max(before.snapshot.length, after.snapshot.length);
for (let i = 0; i < n; i++) {
  const b = JSON.stringify(before.snapshot[i]);
  const a = JSON.stringify(after.snapshot[i]);
  if (b !== a) {
    console.error(`PARITY FAIL at record ${i}:`);
    console.error(`  before: ${b.slice(0, 400)}`);
    console.error(`  after:  ${a.slice(0, 400)}`);
    break;
  }
}
process.exit(1);
