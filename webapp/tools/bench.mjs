// Step 0 baseline harness (WEBAPP_PERFORMANCE_REVIEW.md): a Node-only benchmark
// and parity snapshotter. For a given input path it:
//   - wraps the source in counting wrappers (read() calls, total bytes,
//     read-size histogram) for each phase (scan / container extraction /
//     per-record parse);
//   - times scanSource, container extraction, parseModule and generateWebTables;
//   - writes a JSON snapshot of recordJson(record) for every record plus a
//     SHA-256 of JSON.stringify(generateWebTables(...)) per record.
//
// The snapshot is the parity contract for every later performance step: the
// record list and the generated web tables must stay byte-identical.
//
// Usage:
//   node tools/bench.mjs <image> [--out snapshot.json] [--json]
//
// The script is deliberately free of worker/DOM dependencies; it mirrors the
// worker's blob resolution (direct MBN / FAT16 findFile / container extraction)
// so it can parse records from every input shape in the local corpus.
import { writeFile } from "node:fs/promises";
import { basename } from "node:path";
import { NodeFileSource } from "../js/lib/source.js";
import { Fat16Image } from "../js/lib/fat16.js";
import {
  scanSource,
  parseModule,
  generateWebTables,
  recordJson,
  matchesCandidate,
  normalizeInnerPath,
} from "../js/lib/analyzer.js";
import { extractContainer, discoverCandidates } from "../js/lib/extractor.js";
import { requireValidBank, generateAppleTables } from "../js/lib/apple_cr.js";
import { unwrapBytes } from "../js/lib/mtk_containers.js";
import { decodeMtkSummary, mtkCardCombos } from "../js/lib/mtk_scan.js";
import { generateMtkTables } from "../js/lib/mtk_tables.js";
import { Reporter } from "../js/lib/mtk_universal.js";
import { sha256HexAsync } from "../js/lib/hash.js";

// Wraps a RandomAccessSource and records read counts/bytes plus a coarse size
// histogram. Reads are forwarded untouched, so downstream results cannot change.
class CountingSource {
  constructor(source) {
    this.source = source;
    this.size = source.size;
    this.reads = 0;
    this.bytes = 0;
    this.histogram = new Map(); // bucket label -> count
  }

  static #bucket(length) {
    if (length <= 4096) return "<=4KB";
    if (length <= 64 * 1024) return "<=64KB";
    if (length <= 1024 * 1024) return "<=1MB";
    if (length <= 16 * 1024 * 1024) return "<=16MB";
    return ">16MB";
  }

  async read(offset, length) {
    const data = await this.source.read(offset, length);
    this.reads += 1;
    this.bytes += data.byteLength;
    const b = CountingSource.#bucket(length);
    this.histogram.set(b, (this.histogram.get(b) ?? 0) + 1);
    return data;
  }

  async close() {
    return this.source.close();
  }

  summary() {
    return { reads: this.reads, bytes: this.bytes, histogram: Object.fromEntries([...this.histogram.entries()].sort()) };
  }
}

const round = (n) => Number(n.toFixed(1));

// Resolves the exact bytes a record was scanned from; mirrors worker.js
// readRecordBlob. Returns null when the record cannot be resolved.
async function resolveBlob(source, fat, containerBlobs, record) {
  if (record.external && record.inner_path === record.name && matchesCandidate(record.name)) {
    return source.read(0, source.size);
  }
  if (fat) {
    const entry = await fat.findFile(record.inner_path);
    if (entry) return (await fat.readClusters(entry.firstCluster)).slice(0, entry.size);
  }
  if (containerBlobs) {
    const blob = containerBlobs.get(`${record.name}\u0000${normalizeInnerPath(record.inner_path)}`);
    if (blob !== undefined) return blob;
  }
  return null;
}

export async function bench(inputPath, { quiet = false, onPhase } = {}) {
  const name = basename(inputPath);
  const inner = await NodeFileSource.open(inputPath);
  const metrics = { input: inputPath, name, phases: {} };

  const scanSourceCounter = new CountingSource(inner);
  const t0 = performance.now();
  const { records, warnings } = await scanSource(scanSourceCounter, name);
  metrics.scanMs = round(performance.now() - t0);
  metrics.records = records.length;
  metrics.warnings = warnings.length;
  metrics.phases.scan = scanSourceCounter.summary();

  // FAT16 records share one image; container records share one extraction.
  let fat = null;
  try {
    const candidate = new Fat16Image(inner);
    await candidate.init();
    fat = candidate;
  } catch {
    fat = null;
  }

  const needsContainer = records.some(
    (r) => !r.apple && !r.mtk && r.external && r.inner_path !== r.name && !fat,
  );
  let containerBlobs = null;
  if (needsContainer) {
    const counter = new CountingSource(inner);
    const start = performance.now();
    const { outputs } = await extractContainer(counter, name);
    metrics.extractContainerMs = round(performance.now() - start);
    const { mbns } = discoverCandidates(outputs);
    containerBlobs = new Map();
    for (const { vfile, path } of mbns) {
      containerBlobs.set(`${vfile.name}\u0000${normalizeInnerPath(path)}`, vfile.read());
    }
    metrics.phases.extractContainer = counter.summary();
  }

  // MTK DRDI records: one unwrap+decode serves every card of the source (the
  // worker memoizes this image state; here it is hoisted out of the record
  // loop for the same reason). Timed separately from the per-record parse.
  let mtkSummary = null;
  if (records.some((r) => r.mtk)) {
    const counter = new CountingSource(inner);
    const start = performance.now();
    const parts = await unwrapBytes(await counter.read(0, counter.size), name);
    mtkSummary = await decodeMtkSummary(parts, new Reporter());
    metrics.mtkDecodeMs = round(performance.now() - start);
    metrics.phases.mtkDecode = counter.summary();
  }

  const parseCounter = new CountingSource(inner);
  const recordSnapshots = [];
  let parseMsTotal = 0;
  let tableMsTotal = 0;
  for (const record of records) {
    let parsed;
    try {
      const p0 = performance.now();
      if (record.mtk) {
        // No blob resolution: mtkCardCombos reads the memoized image state.
        parsed = mtkCardCombos(mtkSummary, record.mtk.bankIndex, record.mtk.profile);
      } else {
        const blob = await resolveBlob(parseCounter, fat, containerBlobs, record);
        if (!blob) throw new Error("blob unresolved");
        parsed = parseModule(record, blob);
      }
      parseMsTotal += performance.now() - p0;
      if (record.apple) requireValidBank(parsed);
    } catch (err) {
      recordSnapshots.push({ name: record.name, error: `${err.message}` });
      continue;
    }
    try {
      const t1 = performance.now();
      const tables = record.apple
        ? generateAppleTables(parsed)
        : record.mtk
          ? generateMtkTables(parsed.combos, parsed.lteCombos)
          : generateWebTables(parsed.combinations, parsed.components);
      const text = JSON.stringify(tables);
      tableMsTotal += performance.now() - t1;
      recordSnapshots.push({
        name: record.name,
        json: recordJson(record),
        tablesSha256: await sha256HexAsync(new TextEncoder().encode(text)),
        tablesChars: text.length,
      });
    } catch (err) {
      recordSnapshots.push({ name: record.name, error: `tables: ${err.message}` });
    }
  }
  metrics.parseMs = round(parseMsTotal);
  metrics.tablesMs = round(tableMsTotal);
  metrics.phases.parse = parseCounter.summary();
  metrics.snapshot = recordSnapshots;

  if (!quiet) {
    console.log(`# ${inputPath}`);
    console.log(`records=${metrics.records} warnings=${metrics.warnings}`);
    console.log(`scan=${metrics.scanMs}ms parse=${metrics.parseMs}ms tables=${metrics.tablesMs}ms`);
    if (metrics.extractContainerMs !== undefined) console.log(`extractContainer=${metrics.extractContainerMs}ms`);
    console.log(`scan reads=${metrics.phases.scan.reads} bytes=${metrics.phases.scan.bytes}`, metrics.phases.scan.histogram);
    if (metrics.phases.extractContainer) {
      console.log(
        `extract reads=${metrics.phases.extractContainer.reads} bytes=${metrics.phases.extractContainer.bytes}`,
        metrics.phases.extractContainer.histogram,
      );
    }
    console.log(`parse reads=${metrics.phases.parse.reads} bytes=${metrics.phases.parse.bytes}`);
  }
  onPhase?.(metrics);
  await inner.close();
  return metrics;
}

// --- CLI ---------------------------------------------------------------------

const invokedDirectly =
  process.argv[1] !== undefined && /bench\.mjs$/.test(process.argv[1].replace(/\\/g, "/"));
if (invokedDirectly) {
  const args = process.argv.slice(2);
  const input = args.find((a) => !a.startsWith("--"));
  const outIdx = args.indexOf("--out");
  const out = outIdx >= 0 ? args[outIdx + 1] : null;
  if (!input) {
    console.error("usage: node tools/bench.mjs <image> [--out snapshot.json] [--json]");
    process.exit(2);
  }
  const metrics = await bench(input, { quiet: args.includes("--json") });
  if (out) {
    await writeFile(out, JSON.stringify(metrics, null, 2) + "\n");
    console.log(`snapshot -> ${out}`);
  }
}
