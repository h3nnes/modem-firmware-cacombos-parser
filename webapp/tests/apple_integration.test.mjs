// Apple C-series integration tests (plan Task 4): scanSource FTAB/bbfw branch,
// the card-open blob path (slice compressed stream -> lzfseDecode -> parse ->
// audit -> tables), and the export dispatch shapes the worker produces.
import test from "node:test";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { CORPUS_DIR, deepEqualOrdered } from "./helpers.mjs";
import { scanSource } from "../js/lib/analyzer.js";
import { toCsvText } from "../js/lib/analyzer.js";
import { NodeFileSource } from "../js/lib/source.js";
import { lzfseDecode } from "../js/lib/lzfse.js";
import {
  parseAppleBank,
  requireValidBank,
  generateAppleTables,
  exportAppleDiag,
} from "../js/lib/apple_cr.js";
import { isFtab, extractFtabMember } from "../js/lib/apple_ftab.js";

const REF = join(CORPUS_DIR, "apple-c-modem-parser");
const corpusAvailableForApple = () =>
  existsSync(join(REF, "c1", "ftab.bin")) && existsSync(join(REF, "c2", "ftab_cr_banks"));
// tables.json/diag.json are oversized reference dumps (317/142 MB) excluded
// from git; regenerate locally from the corpus — tests skip without them.
const appleGoldenDumpsAvailable = () =>
  existsSync(new URL("../goldens/apple/tables.json", import.meta.url)) &&
  existsSync(new URL("../goldens/apple/diag.json", import.meta.url));
const appleDifferentialAvailable = () => corpusAvailableForApple() && appleGoldenDumpsAvailable();
const sha256Hex = (u8) => createHash("sha256").update(u8).digest("hex");
const loadGolden = (name) => readFile(new URL(`../goldens/apple/${name}.json`, import.meta.url)).then(JSON.parse);
const loadManifest = () => readFile(new URL("../goldens/apple/manifest.json", import.meta.url)).then(JSON.parse);

// Per-record scan pins against the python goldens: layout name and the
// expanded pre-dedupe inspect counts (apple_cr_parser.py inspect_bank).
async function assertRecordMatchesManifest(records, layout, manifest) {
  for (const rec of records) {
    const key = `${layout}/${rec.inner_path}`;
    const entry = manifest[key];
    assert.ok(entry, `${key}: manifest entry`);
    assert.equal(rec.apple.profileId, entry.profile_id, key);
    assert.equal(rec.apple.layout, entry.layout, key);
    assert.deepEqual(rec.apple.counts, {
      lte: entry.inspect.lte_count,
      endc: entry.inspect.endc_count,
      nrca: entry.inspect.nrca_count,
      nrdc: entry.inspect.nrdc_count,
    }, key);
  }
}

test("apple integration: scanSource on golden c2 ftab -> 37 records, deferred counts", { skip: !corpusAvailableForApple() }, async () => {
  const src = await NodeFileSource.open(join(REF, "c2", "ftab.bin"));
  const { records, warnings } = await scanSource(src, "ftab.bin");
  assert.equal(records.length, 37);
  assert.deepEqual(warnings, []);
  const first = records[0];
  assert.ok(first.name.startsWith("CR04 (profile 0x1f2126)"), first.name);
  assert.equal(first.inner_path, "CR04");
  assert.equal(first.lte_combos, null);
  assert.equal(first.nr_combos, null);
  assert.equal(first.combo_counts_deferred, true);
  assert.equal(first.size, 0x590d00);
  // sha256 = COMPRESSED stream: compute inline from the ftab like the scan does.
  const ftab = await readFile(join(REF, "c2", "ftab.bin"));
  const dv = new DataView(ftab.buffer, ftab.byteOffset, ftab.byteLength);
  assert.equal(first.apple.offset, 0x66b9228);
  const comp = dv.getUint32(first.apple.offset + 8, true);
  const stream = ftab.subarray(first.apple.offset + 12, first.apple.offset + 12 + comp);
  assert.equal(first.apple.compSize, comp);
  assert.equal(first.sha256, sha256Hex(stream));
  for (const r of records) {
    assert.ok(r.apple, `${r.name}: apple block`);
    assert.match(r.name, /^CR\d+ \(profile 0x[0-9a-f]{6}\)$/);
  }
  await assertRecordMatchesManifest(records, "c2", await loadManifest());
});

test("apple integration: scanSource on golden c1 ftab -> 21 records, first CR11", { skip: !corpusAvailableForApple() }, async () => {
  const src = await NodeFileSource.open(join(REF, "c1", "ftab.bin"));
  const { records } = await scanSource(src, "ftab.bin");
  assert.equal(records.length, 21);
  assert.ok(records[0].name.startsWith("CR11 (profile 0x10548c)"), records[0].name);
  assert.equal(records[0].size, 0x5776e0);
  await assertRecordMatchesManifest(records, "c1", await loadManifest());
});

test("apple integration: full open path (blob -> parse -> audit -> tables) for all 58 banks", { skip: !appleDifferentialAvailable() }, async () => {
  const golden = await loadGolden("tables");
  let checked = 0;
  for (const layout of ["c1", "c2"]) {
    const src = await NodeFileSource.open(join(REF, layout, "ftab.bin"));
    const { records } = await scanSource(src, "ftab.bin");
    for (const record of records) {
      // The worker's apple blob path: slice the compressed stream from the
      // source (offset+12, compSize), decode with the uncompSize hint, parse.
      const comp = await src.read(record.apple.offset + 12, record.apple.compSize);
      const bank = lzfseDecode(comp, record.apple.uncompSize);
      assert.equal(bank.length, record.apple.uncompSize, `${record.inner_path}: decoded size`);
      const parsed = parseAppleBank(bank, record.inner_path);
      requireValidBank(parsed);
      deepEqualOrdered(generateAppleTables(parsed), golden[`${layout}/${record.inner_path}`]);
      checked++;
    }
  }
  assert.equal(checked, 58);
});

test("apple integration: export dispatch — DIAG byte-equal + json shape (worker path)", { skip: !appleDifferentialAvailable() }, async () => {
  const golden = await loadGolden("diag");
  const src = await NodeFileSource.open(join(REF, "c2", "ftab.bin"));
  const { records } = await scanSource(src, "ftab.bin");
  const record = records[0]; // CR04
  const comp = await src.read(record.apple.offset + 12, record.apple.compSize);
  const bank = lzfseDecode(comp, record.apple.uncompSize);
  const parsed = parseAppleBank(bank, record.inner_path);
  requireValidBank(parsed);
  // b0cd/b826 -> exportAppleDiag texts, byte-equal goldens.
  const [b0cd] = exportAppleDiag(parsed, "b0cd");
  const [b826] = exportAppleDiag(parsed, "b826");
  assert.equal(b0cd.text, golden["c2/CR04"].b0cd);
  assert.equal(b826.text, golden["c2/CR04"].b826);
  assert.equal(b0cd.filename, "CR04_0xB0CD_v41.txt");
  assert.equal(b826.filename, "CR04_0xB826_v22.txt");
  // json path: { name, profile_id, tables } — parseable, profile_id 0x1F2126.
  const tables = generateAppleTables(parsed);
  const jsonText = JSON.stringify({ name: record.name, profile_id: parsed.profile_id, tables }, null, 2) + "\n";
  const back = JSON.parse(jsonText);
  assert.equal(back.profile_id, 0x1f2126);
  assert.equal(back.name, record.name);
  assert.equal(back.tables.endc.length, tables.endc.length);
  // csv/webcsv shape: per-table CSV text via the shared toCsvText writer.
  const csv = toCsvText(tables.endc);
  assert.ok(csv.startsWith("\uFEFF"));
  assert.ok(csv.includes("LTE DL"));
});

// --- synthetic bbfw through scanSource (Task 2's hand-rolled zip) ------------------

function crc32(u8) {
  let table = crc32.table;
  if (!table) {
    table = crc32.table = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[n] = c;
    }
  }
  let crc = -1;
  for (let i = 0; i < u8.length; i++) crc = (crc >>> 8) ^ table[(crc ^ u8[i]) & 0xff];
  return (crc ^ -1) >>> 0;
}

function storedZip(members) {
  const enc = new TextEncoder();
  const chunks = [];
  const central = [];
  let offset = 0;
  for (const { name, data } of members) {
    const nameBytes = enc.encode(name);
    const crc = crc32(data);
    const local = new Uint8Array(30 + nameBytes.length);
    const dv = new DataView(local.buffer);
    dv.setUint32(0, 0x04034b50, true);
    dv.setUint16(4, 20, true);
    dv.setUint16(8, 0, true); // stored
    dv.setUint32(14, crc, true);
    dv.setUint32(18, data.length, true);
    dv.setUint32(22, data.length, true);
    dv.setUint16(26, nameBytes.length, true);
    local.set(nameBytes, 30);
    chunks.push(local, data);
    const cen = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(cen.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(10, 0, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, data.length, true);
    cv.setUint32(24, data.length, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint32(42, offset, true);
    cen.set(nameBytes, 46);
    central.push(cen);
    offset += local.length + data.length;
  }
  const cdStart = offset;
  const cdSize = central.reduce((n, c) => n + c.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, members.length, true);
  ev.setUint16(10, members.length, true);
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, cdStart, true);
  const all = [...chunks, ...central, eocd];
  const out = new Uint8Array(all.reduce((n, c) => n + c.length, 0));
  let p = 0;
  for (const c of all) {
    out.set(c, p);
    p += c.length;
  }
  return out;
}

// Synthetic ftab whose CR stream carries the bvx2 magic so the scan enumerates
// it. The 32-byte stream cannot decode (and detectLayout requires an exact
// C4000/C4020 bank size), so under the decompress-at-scan contract the bank is
// warned and skipped — the warning still proves the bbfw walk found the ftab
// member and enumerated its CR entry.
function syntheticFtabBytes() {
  const stream = new Uint8Array(32);
  const sv = new DataView(stream.buffer);
  sv.setUint32(0, 0x32787662, true); // bvx2
  const envOffset = 0x30 + 16;
  const envSize = 12 + stream.length;
  const ftab = new Uint8Array(envOffset + envSize);
  const dv = new DataView(ftab.buffer);
  ftab.set(new TextEncoder().encode("rkosftab"), 0x20);
  ftab.set(new TextEncoder().encode("CR07"), 0x30);
  dv.setUint32(0x34, envOffset, true);
  dv.setUint32(0x38, envSize, true);
  dv.setUint32(0x3c, 0, true);
  dv.setUint32(envOffset, 0xabcdef, true);
  dv.setUint32(envOffset + 4, 4096, true);
  dv.setUint32(envOffset + 8, stream.length, true);
  ftab.set(stream, envOffset + 12);
  return ftab;
}

test("apple integration: synthetic bbfw through scanSource enumerates the inner ftab", async () => {
  const ftab = syntheticFtabBytes();
  const zip = storedZip([{ name: "022-22116-011__ftab.bin", data: ftab }]);
  // wrap the zip bytes in a minimal File-like (slice + size), like a browser File
  const fileLike = {
    name: "baseband.bbfw",
    size: zip.length,
    slice: (a, b) => new Blob([zip.subarray(a, b)]),
  };
  const { BrowserFileSource } = await import("../js/lib/source.js");
  const { records, warnings } = await scanSource(new BrowserFileSource(fileLike), "baseband.bbfw");
  assert.equal(records.length, 0); // fake bvx2 stream: warned and skipped at scan
  assert.equal(warnings.length, 1);
  assert.match(warnings[0].message, /apple CR bank CR07: unreadable/);
});

test("apple integration: non-bvx2 CR stream is skipped with a warning", async () => {
  // raw ftab whose CR stream has a bogus magic
  const stream = new Uint8Array(16);
  const envOffset = 0x30 + 16;
  const ftab = new Uint8Array(envOffset + 12 + stream.length);
  const dv = new DataView(ftab.buffer);
  ftab.set(new TextEncoder().encode("rkosftab"), 0x20);
  ftab.set(new TextEncoder().encode("CR99"), 0x30);
  dv.setUint32(0x34, envOffset, true);
  dv.setUint32(0x38, 12 + stream.length, true);
  dv.setUint32(envOffset, 1, true);
  dv.setUint32(envOffset + 4, 16, true);
  dv.setUint32(envOffset + 8, stream.length, true);
  const fileLike = {
    name: "ftab.bin",
    size: ftab.length,
    slice: (a, b) => new Blob([ftab.subarray(a, b)]),
  };
  const { BrowserFileSource } = await import("../js/lib/source.js");
  const { records, warnings } = await scanSource(new BrowserFileSource(fileLike), "ftab.bin");
  assert.equal(records.length, 0);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0].message, /CR99: unexpected compression magic/);
});

test("apple integration: non-apple inputs still scan unchanged", { skip: !corpusAvailableForApple() }, async () => {
  // a tiny non-matching file: neither apple ftab nor anything else -> container
  // path yields nothing (no apple records, no crash)
  const { BrowserFileSource } = await import("../js/lib/source.js");
  const blob = { name: "random.bin", size: 600, slice: (a, b) => new Blob([new Uint8Array(b - a)]) };
  const { records } = await scanSource(new BrowserFileSource(blob), "random.bin");
  assert.equal(records.length, 0);
});

// Regression (review CRITICAL #1): a zip WITHOUT an ftab member is a Qualcomm
// container — the apple branch must fall through to the container path, never
// abort the scan. Pre-fix, findFtabMemberInBbfw's error propagated out of
// scanSource and the whole scan failed.
test("apple integration: zip without ftab member falls through to container scan", async () => {
  const { BrowserFileSource } = await import("../js/lib/source.js");
  const zip = storedZip([
    { name: "modem_proxy.txt", data: new TextEncoder().encode("definitely not an ftab") },
    { name: "rdl.bin", data: new Uint8Array(64) },
  ]);
  const fileLike = {
    name: "modem.zip",
    size: zip.length,
    slice: (a, b) => new Blob([zip.subarray(a, b)]),
  };
  const { records, warnings } = await scanSource(new BrowserFileSource(fileLike), "modem.zip");
  assert.deepEqual(records, []);
  assert.ok(Array.isArray(warnings));
});

// Regression (review MAJOR #2): nested bbfw — the ftab lives in a zip inside a
// zip. Scan enumerates it with member "outer!inner"; the card-open member
// resolution (extractFtabMember, the code the worker uses) must re-read the
// member list per zip scope. Pre-fix it reused the outer zip's entries and
// every open threw "apple ftab member not found in source: ftab.bin".
test("apple integration: nested bbfw scan + open-path member resolution", async () => {
  const ftab = syntheticFtabBytes();
  const inner = storedZip([{ name: "ftab.bin", data: ftab }]);
  const outer = storedZip([{ name: "baseband.bbfw", data: inner }]);
  const fileLike = {
    name: "modem.zip",
    size: outer.length,
    slice: (a, b) => new Blob([outer.subarray(a, b)]),
  };
  const { BrowserFileSource } = await import("../js/lib/source.js");
  const source = new BrowserFileSource(fileLike);
  const { records, warnings } = await scanSource(source, "modem.zip");
  // The fake bvx2 stream is warned and skipped at scan, but reaching the CR07
  // warning proves the nested ftab member was found and enumerated through
  // both zip scopes.
  assert.equal(records.length, 0);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0].message, /apple CR bank CR07: unreadable/);
  // The worker's open path resolves the member through extractFtabMember.
  const memberData = await extractFtabMember(source, "baseband.bbfw!ftab.bin");
  assert.deepEqual([...memberData], [...ftab]);
});

// --- picker markup: the browse dialog must offer ftab.bin ---------------------------

test("apple integration: file input accept includes .bin (ftab pickable via browse)", async () => {
  const html = await readFile(join(dirname(fileURLToPath(import.meta.url)), "..", "index.html"), "utf8");
  const inputStart = html.indexOf('<input id="file-input"');
  assert.notEqual(inputStart, -1, "file-input missing");
  const inputTag = html.slice(inputStart, html.indexOf(">", inputStart) + 1);
  // The accept attribute must stay (it keeps the browse dialog focused); the
  // generic octet-stream entry is what makes extensionless MediaTek parts
  // (md1drdi_hdr / md1drdi_data) pickable alongside the extension list.
  const accept = /accept="([^"]*)"/.exec(inputTag)?.[1] ?? "";
  const exts = accept.split(",").map((e) => e.trim().toLowerCase());
  assert.ok(exts.includes(".bin"), `accept must include .bin (got: ${accept})`);
  assert.ok(exts.includes(".bbfw"), `accept must include .bbfw (got: ${accept})`);
  assert.ok(exts.includes("application/octet-stream"), `accept must include application/octet-stream (got: ${accept})`);
});

// --- parallel scan hook: fan-out inspect must be byte-identical to sequential -------

test("apple integration: inspectAppleBankAsync fan-out + onAppleBatch match the sequential scan", { skip: !corpusAvailableForApple() }, async () => {
  const { inspectAppleBank } = await import("../js/lib/apple_cr.js");
  const src = await NodeFileSource.open(join(REF, "c2", "ftab.bin"));
  const sequential = await scanSource(src, "ftab.bin");

  // Pool-style hook: bounded-concurrency fan-out that (like the worker pool)
  // detaches the stream buffer before decoding, completing out of order.
  const inlineInspect = (stream, uncompSize) => {
    const bank = lzfseDecode(new Uint8Array(stream.slice().buffer), uncompSize);
    const inspected = inspectAppleBank(bank);
    return {
      layout: inspected.layout,
      counts: { lte: inspected.lteCount, endc: inspected.endcCount, nrca: inspected.nrcaCount, nrdc: inspected.nrdcCount },
    };
  };
  const batches = [];
  const parallel = await scanSource(src, "ftab.bin", {
    inspectAppleBankAsync: async (stream, uncompSize) => {
      await new Promise((r) => setTimeout(r, 5)); // force out-of-order completion
      return inlineInspect(stream, uncompSize);
    },
    onAppleBatch: (batchRecords, batchWarnings) => batches.push({ batchRecords, batchWarnings }),
  });

  deepEqualOrdered(parallel.records, sequential.records);
  assert.deepEqual(parallel.warnings, sequential.warnings);
  // Batches concatenate to the full set, strictly in record order.
  deepEqualOrdered(batches.flatMap((b) => b.batchRecords), sequential.records);
  assert.deepEqual(batches.flatMap((b) => b.batchWarnings), sequential.warnings);
  assert.ok(batches.length > 1, `expected progressive batches, got ${batches.length}`);
  await src.close();
});

// --- scan progress hook: per-bank apple progress via scanSource ---------------------

test("apple integration: scanSource reports per-bank progress via onScanProgress", { skip: !corpusAvailableForApple() }, async () => {
  const src = await NodeFileSource.open(join(REF, "c1", "ftab.bin"));
  // Expected bank count derives from a plain scan: one settled outcome (record
  // or warning) per descriptor, so records + warnings is the bank total.
  const sequential = await scanSource(src, "ftab.bin");
  const expectedTotal = sequential.records.length + sequential.warnings.length;
  const infos = [];
  await scanSource(src, "ftab.bin", {
    onScanProgress: (info) => infos.push(info),
  });
  const apple = infos.filter((i) => i.stage === "apple");
  assert.ok(apple.length > 0, "expected apple-stage progress infos");
  assert.ok(
    apple.every((i) => i.total === expectedTotal),
    `every info.total === ${expectedTotal} (got: ${apple.map((i) => i.total).join(",")})`,
  );
  assert.equal(apple[0].done, 0, "first apple info reports 0 settled banks");
  for (let i = 1; i < apple.length; i++) {
    assert.ok(apple[i].done >= apple[i - 1].done, `apple done non-decreasing at info ${i}`);
  }
  assert.ok(apple.every((i) => i.done <= i.total), "no apple info exceeds total");
  assert.equal(apple[apple.length - 1].done, expectedTotal, "final apple info settles every bank");
  await src.close();
});
