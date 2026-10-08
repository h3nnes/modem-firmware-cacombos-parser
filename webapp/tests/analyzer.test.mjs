// JS API shape:
//   scanSource(source, name) -> { records: [ModuleRecord...], warnings: [{ tool, message }] }
//     ModuleRecord: plain object with snake_case fields in declaration order
//     plus identity via recordIdentity().
//   recordJson(record) -> exact tools/generate_goldens.py record_json layout
//   parseModule(record, blob) -> parseLegacyModule | parseModernModule dispatch
//   generateWebTables(combinations, components) -> { lte_ca, nr_ca, endc, nrdc }
//   exportModule(record, parsed, format) -> [{ filename, text }] (csv/json/webcsv)
//   csvField(value) / formatBw(bw) / formatBcs(bcs) / normalizeLegacyComponent(comp)
import { test } from "node:test";
import assert from "node:assert/strict";
import { zlibSync } from "../lib/vendor/fflate.js";
import { Fat16Image, ParseError } from "../js/lib/fat16.js";
import { BrowserFileSource } from "../js/lib/source.js";
import { sha256Hex } from "../js/lib/hash.js";
import {
  scanSource,
  recordJson,
  parseModule,
  generateWebTables,
  exportModule,
  csvField,
  formatBw,
  formatBcs,
  formatScsVal,
  sortRecords,
  deduplicateRecords,
  normalizeLegacyComponent,
  normalizeInnerPath,
} from "../js/lib/analyzer.js";
import { ToolError } from "../js/lib/legacy_parser.js";

// --- synthetic FAT16 fixture (geometry from fat16.test.mjs) -------------------
const BPS = 512;
const SPC = 4;
const RESERVED = 1;
const NFATS = 2;
const ROOT_ENTRIES = 512;
const SPFT = 16;
const TOTAL_SECTORS = 16405;
const FAT_OFFSET = RESERVED * BPS;
const ROOT_OFFSET = (RESERVED + NFATS * SPFT) * BPS;
const DATA_OFFSET = (RESERVED + NFATS * SPFT + (ROOT_ENTRIES * 32) / BPS) * BPS;
const CLUSTER_SIZE = BPS * SPC;
const clusterOffset = (c) => DATA_OFFSET + (c - 2) * CLUSTER_SIZE;
const pattern = (i) => (i * 7 + 13) & 0xff;

function writeDirEntry(image, off, name, ext, attr, first = 0, size = 0) {
  for (let i = 0; i < 8; i++) image[off + i] = i < name.length ? name.charCodeAt(i) : 0x20;
  for (let i = 0; i < 3; i++) image[off + 8 + i] = i < ext.length ? ext.charCodeAt(i) : 0x20;
  image[off + 11] = attr;
  const dv = new DataView(image.buffer);
  dv.setUint16(off + 26, first, true);
  dv.setUint32(off + 28, size, true);
}

function writeLfnEntry(image, off, ordinal, chars, lastPhysical = false) {
  image[off] = ordinal | (lastPhysical ? 0x40 : 0);
  image[off + 11] = 0x0f;
  const units = [];
  for (const ch of chars) units.push(ch.codePointAt(0));
  while (units.length < 13) units.push(units.length === chars.length ? 0x0000 : 0xffff);
  const slots = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
  const dv = new DataView(image.buffer);
  units.forEach((u, i) => dv.setUint16(off + slots[i], u, true));
}

// Minimal modern RF-card blob (same construction as modern_parser.test.mjs):
// one /rfc/*_res.dat Large-EFS item holding a zlib DAT with an empty rrc.
function u32le(n) {
  return [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
}

function framedItem(path, data) {
  const enc = new TextEncoder();
  const p = enc.encode(path);
  const out = new Uint8Array(4 + p.length + 1 + 6 + data.length);
  const dv = new DataView(out.buffer);
  dv.setUint16(0, 1, true);
  dv.setUint16(2, p.length + 1, true);
  out.set(p, 4);
  out[4 + p.length] = 0;
  dv.setUint16(4 + p.length + 1, 2, true);
  dv.setUint32(4 + p.length + 3, data.length, true);
  out.set(data, 4 + p.length + 1 + 6);
  return out;
}

function makeModernBlob() {
  const payload = new TextEncoder().encode("\x3a\x04\x0a\x02te");
  const stream = zlibSync(payload);
  const resDat = new Uint8Array(5 + 4 + stream.length);
  resDat.fill(0x22, 0, 5);
  new DataView(resDat.buffer).setUint32(5, payload.length, true);
  resDat.set(stream, 9);
  return framedItem("/rfc/modem_rfcard_res.dat", resDat);
}

const MODERN_BLOB = makeModernBlob();
const LEGACY_JUNK = new Uint8Array(100).map((_, i) => pattern(i));

// Root: duplicate modern MBN at /, /IMAGE/{RF2,SO}; /6_0_0.MBN is legacy but
// outside /so/ (must be dropped); /IMAGE/SO/6_0_0.MBN is inside /so/.
function buildFat16Fixture() {
  const image = new Uint8Array(TOTAL_SECTORS * BPS);
  const dv = new DataView(image.buffer);
  image.set([0xeb, 0x3c, 0x90], 0);
  dv.setUint16(11, BPS, true);
  image[13] = SPC;
  dv.setUint16(14, RESERVED, true);
  image[16] = NFATS;
  dv.setUint16(17, ROOT_ENTRIES, true);
  dv.setUint16(19, TOTAL_SECTORS, true);
  image[21] = 0xf8;
  dv.setUint16(22, SPFT, true);
  dv.setUint16(510, 0xaa55, true);
  // FAT: clusters 2..5 are directory chains (EOC), 10 is the modern MBN,
  // 11/12 are the two legacy copies.
  for (const c of [2, 3, 4, 5, 10, 11, 12]) dv.setUint16(FAT_OFFSET + c * 2, 0xffff, true);
  writeDirEntry(image, ROOT_OFFSET + 0 * 32, "SYSLABEL", "   ", 0x08);
  writeLfnEntry(image, ROOT_OFFSET + 1 * 32, 2, "_0_0.mbn", true);
  writeLfnEntry(image, ROOT_OFFSET + 2 * 32, 1, "rf_config_13");
  writeDirEntry(image, ROOT_OFFSET + 3 * 32, "RF_CON~1", "MBN", 0x20, 10, MODERN_BLOB.length);
  writeDirEntry(image, ROOT_OFFSET + 4 * 32, "IMAGE", "   ", 0x10, 2);
  writeDirEntry(image, ROOT_OFFSET + 5 * 32, "6_0_0", "MBN", 0x20, 11, LEGACY_JUNK.length);
  const d2 = clusterOffset(2); // /IMAGE
  writeDirEntry(image, d2 + 0 * 32, ".", "   ", 0x10, 2);
  writeDirEntry(image, d2 + 1 * 32, "..", "   ", 0x10);
  writeDirEntry(image, d2 + 2 * 32, "RF2", "   ", 0x10, 5);
  writeDirEntry(image, d2 + 3 * 32, "SO", "   ", 0x10, 3);
  const d5 = clusterOffset(5); // /IMAGE/RF2
  writeDirEntry(image, d5 + 0 * 32, ".", "   ", 0x10, 5);
  writeDirEntry(image, d5 + 1 * 32, "..", "   ", 0x10);
  writeLfnEntry(image, d5 + 2 * 32, 2, "_0_0.mbn", true);
  writeLfnEntry(image, d5 + 3 * 32, 1, "rf_config_13");
  writeDirEntry(image, d5 + 4 * 32, "RF_CON~1", "MBN", 0x20, 10, MODERN_BLOB.length);
  const d3 = clusterOffset(3); // /IMAGE/SO
  writeDirEntry(image, d3 + 0 * 32, ".", "   ", 0x10, 3);
  writeDirEntry(image, d3 + 1 * 32, "..", "   ", 0x10);
  writeDirEntry(image, d3 + 2 * 32, "6_0_0", "MBN", 0x20, 12, LEGACY_JUNK.length);
  image.set(MODERN_BLOB, clusterOffset(10));
  image.set(LEGACY_JUNK, clusterOffset(11));
  image.set(LEGACY_JUNK, clusterOffset(12));
  return image;
}

const fatSource = () =>
  new BrowserFileSource(new Blob([buildFat16Fixture()], { type: "application/octet-stream" }));

// --- unit: pure helpers -------------------------------------------------------

test("normalize legacy component maps NONE/ANTENNA_ sentinels", () => {
  const comp = { ul_bw_class: "NONE", dl_antenna: "ANTENNA_4", ul_antenna: "NONE" };
  const out = normalizeLegacyComponent(comp);
  assert.deepEqual(out, { ul_bw_class: "-", dl_antenna: "4", ul_antenna: "INDEX_0" });
  // key insertion order is preserved (order-sensitive golden comparison)
  assert.deepEqual(Object.keys(out), Object.keys(comp));
  // input is copied, not mutated
  assert.equal(comp.ul_bw_class, "NONE");
  assert.equal(comp.dl_antenna, "ANTENNA_4");
  // modern-shaped values pass through untouched
  assert.deepEqual(normalizeLegacyComponent({ dl_bw_class: "A", dl_antenna: "2_1" }), {
    dl_bw_class: "A",
    dl_antenna: "2_1",
  });
  // ... and untouched means the SAME object (no copy for the common modern case)
  const modern = { dl_bw_class: "A", dl_antenna: "2_1", band: 3 };
  assert.equal(normalizeLegacyComponent(modern), modern);
});

test("_format_bw strips the MHz suffix after underscore replacement", () => {
  assert.equal(formatBw("100 MHz"), "100");
  assert.equal(formatBw("20_100"), "20 + 100");
  assert.equal(formatBw("NONE"), "NONE");
  assert.equal(formatBw("not stored"), "not stored");
  assert.equal(formatBw("100_60 MHz"), "100 + 60");
  assert.equal(formatBw(""), "");
});

test("_format_bcs maps None/-1/empty to All", () => {
  assert.equal(formatBcs(0), "0");
  assert.equal(formatBcs(null), "All");
  assert.equal(formatBcs(-1), "All");
  assert.equal(formatBcs(""), "All");
  assert.equal(formatBcs(" 5 "), "5");
});

test("excel csv quirk preserved", () => {
  assert.equal(csvField("=cmd"), '"=""cmd"""');
  // csv module QUOTE_MINIMAL behaviour for the remaining shapes
  assert.equal(csvField("plain"), "plain");
  assert.equal(csvField("a,b"), '"a,b"');
  assert.equal(csvField('say "hi"'), '"say ""hi"""');
  assert.equal(csvField(""), "");
  assert.equal(csvField(null), "");
});

test("normalize_inner_path folds scratch-dir tags (generate_goldens.py parity)", () => {
  assert.equal(normalizeInnerPath("fat_gg6rsuom/image/modem_pr/so/615_0_0.mbn"), "fat/image/modem_pr/so/615_0_0.mbn");
  assert.equal(normalizeInnerPath("sparse_9Zx_A/image/modem_pr/x.mbn"), "sparse/image/modem_pr/x.mbn");
  assert.equal(normalizeInnerPath("7z_aB/image/x.mbn"), "7z/image/x.mbn");
  assert.equal(normalizeInnerPath("fat_looks_like_tag_but"), "fat_looks_like_tag_but");
  assert.equal(normalizeInnerPath("/image/modem_pr/so/615_0_0.mbn"), "/image/modem_pr/so/615_0_0.mbn");
});

test("recordJson emits the generate_goldens.py field layout", () => {
  const rec = {
    inner_path: "/image/modem_pr/so/615_0_0.MBN",
    name: "615_0_0.MBN",
    generation: "Legacy ELF",
    size: 100,
    hwid: 615,
    fsid: 0,
    bid: 0,
    external: false,
    source_path: "",
    sidecars: {},
    sha256: "ab".repeat(32),
    lte_combos: 3,
    nr_combos: "1+2+0=3",
  };
  const json = recordJson(rec);
  assert.deepEqual(Object.keys(json), [
    "name",
    "inner_path",
    "generation",
    "identity",
    "size",
    "sha256",
    "external",
    "lte_combos",
    "nr_combos",
    "sidecars",
  ]);
  assert.equal(json.identity, "615_0_0");
  // rf_config_ prefix is stripped for the identity spelling
  assert.equal(
    recordJson({ ...rec, name: "RF_CONFIG_1425_0_0_0170.mbn" }).identity,
    "1425_0_0_0170",
  );
});

// --- unit: scanSource over the synthetic FAT16 fixture ------------------------

test("scanSource walks FAT16, filters /so/, dedups and sorts like Python", async () => {
  const result = await scanSource(fatSource(), "modem.img");
  assert.deepEqual(result.warnings, []);
  assert.deepEqual(
    result.records.map((r) => [r.inner_path, r.generation]),
    [
      // sort-then-dedup: "/image/rf2/..." casefolds before "/rf_config_...",
      // so the SECOND copy wins the (name, sha256) dedup.
      ["/IMAGE/RF2/rf_config_13_0_0.mbn", "DAT/protobuf"],
      ["/IMAGE/SO/6_0_0.MBN", "Legacy ELF"],
    ],
  );
  const [modern, legacy] = result.records.map(recordJson);
  assert.deepEqual(modern, {
    name: "rf_config_13_0_0.mbn",
    inner_path: "/IMAGE/RF2/rf_config_13_0_0.mbn",
    generation: "DAT/protobuf",
    identity: "13_0_0",
    size: MODERN_BLOB.length,
    sha256: sha256Hex(MODERN_BLOB),
    external: false,
    lte_combos: 0,
    nr_combos: "0+0+0=0",
    sidecars: {},
  });
  // non-ELF legacy payload: Python _combo_counts swallows the failure
  assert.deepEqual(legacy, {
    name: "6_0_0.MBN",
    inner_path: "/IMAGE/SO/6_0_0.MBN",
    generation: "Legacy ELF",
    identity: "6_0_0",
    size: LEGACY_JUNK.length,
    sha256: sha256Hex(LEGACY_JUNK),
    external: false,
    lte_combos: -1,
    nr_combos: "—",
    sidecars: {},
  });
});

// --- unit: direct-MBN fast path + non-FAT16 structured result -----------------

test("scanSource direct MBN path classifies without FAT16", async () => {
  const src = new BrowserFileSource(new Blob([MODERN_BLOB]));
  const result = await scanSource(src, "rf_config_9_9_9.mbn");
  assert.deepEqual(result.warnings, []);
  assert.deepEqual(recordJson(result.records[0]), {
    name: "rf_config_9_9_9.mbn",
    inner_path: "rf_config_9_9_9.mbn",
    generation: "DAT/protobuf",
    identity: "9_9_9",
    size: MODERN_BLOB.length,
    sha256: sha256Hex(MODERN_BLOB),
    external: true,
    lte_combos: 0,
    nr_combos: "0+0+0=0",
    sidecars: {},
  });
  assert.equal(result.records[0].hwid, 9);
  assert.equal(result.records[0].fsid, 9);
  assert.equal(result.records[0].bid, 9);
});

test("scanSource direct path handles the optional _rev segment and hex legacy tokens", async () => {
  const junk = new BrowserFileSource(new Blob([LEGACY_JUNK]));
  const rev = await scanSource(junk, "rf_config_1425_0_0_0170.mbn");
  assert.equal(rev.records[0].generation, "DAT/protobuf");
  assert.deepEqual([rev.records[0].hwid, rev.records[0].fsid, rev.records[0].bid], [1425, 0, 0]);
  assert.equal(recordJson(rev.records[0]).identity, "1425_0_0_0170");

  const legacy = await scanSource(junk, "6_a_0.mbn");
  assert.equal(legacy.records[0].generation, "Legacy ELF");
  // "a" is alphabetic -> Python int(token, 16)
  assert.deepEqual([legacy.records[0].hwid, legacy.records[0].fsid], [6, 10]);
  assert.deepEqual([legacy.records[0].lte_combos, legacy.records[0].nr_combos], [-1, "—"]);
});

test("scanSource returns a structured warning result for non-FAT16 input", async () => {
  const junk = new BrowserFileSource(new Blob([new Uint8Array(64)]));
  const result = await scanSource(junk, "random.bin");
  assert.deepEqual(result.records, []);
  assert.equal(result.warnings.length, 1);
  assert.equal(typeof result.warnings[0].tool, "string");
  assert.equal(typeof result.warnings[0].message, "string");
});

// --- unit: container fallback (Task 9) ------------------------------------------

test("scanSource container fallback: unsupported container warns with the missing tool", async () => {
  const erofs = new Uint8Array(4096);
  erofs.set([0xe2, 0xe1, 0xf5, 0xe0], 0x400);
  const result = await scanSource(new BrowserFileSource(new Blob([erofs])), "system.img");
  assert.deepEqual(result.records, []);
  assert.equal(result.warnings.length, 1);
  assert.equal(result.warnings[0].tool, "fsck.erofs");
});

test("scanSource container fallback: Motorola wrapper -> sparse -> ext4 yields records", async () => {
  // Minimal wrapper + sparse(ext4) with one modern card and a legacy MBN
  // outside the /so tree (which must be dropped by the analyzer filter).
  const card = new Uint8Array(64).fill(0x0a);
  const mod = await import("./ext4.test.mjs");
  const ext4 = mod.buildExt4Tree({
    "/image/modem_pr/rf_config_650_0_0.mbn": card,
    "/image/other/700_0_0.mbn": new Uint8Array(16), // legacy outside /so: dropped
    "/image/modem_pr/so/615_0_0.mbn": new Uint8Array(16).fill(1), // legacy in /so: kept
  });
  const sparse = new Uint8Array(28 + 12 + ext4.length);
  const dv = new DataView(sparse.buffer);
  dv.setUint32(0, 0xed26ff3a, true);
  dv.setUint16(4, 1, true);
  dv.setUint16(8, 28, true);
  dv.setUint16(10, 12, true);
  dv.setUint32(12, 1024, true);
  const blocks = Math.ceil(ext4.length / 1024);
  dv.setUint32(16, blocks, true);
  dv.setUint32(20, 1, true);
  dv.setUint16(28, 0xcac1, true);
  dv.setUint32(32, blocks, true);
  dv.setUint32(36, 12 + ext4.length, true);
  sparse.set(ext4, 40);
  const wrapped = new Uint8Array(13568 + sparse.length);
  wrapped.set([0x53, 0x49, 0x4e, 0x47, 0x4c, 0x45, 0x5f, 0x4e, 0x5f, 0x4c, 0x4f, 0x4e, 0x45, 0x4c, 0x59, 0x00]);
  wrapped.set(sparse, 13568);
  const result = await scanSource(new BrowserFileSource(new Blob([wrapped])), "radio.img");
  assert.deepEqual(result.warnings, []);
  const json = result.records.map(recordJson);
  assert.deepEqual(
    json.map((r) => r.inner_path).sort(),
    ["sparse/image/modem_pr/rf_config_650_0_0.mbn", "sparse/image/modem_pr/so/615_0_0.mbn"],
  );
  const modern = json.find((r) => r.name === "rf_config_650_0_0.mbn");
  assert.equal(modern.generation, "DAT/protobuf");
  assert.equal(modern.external, true);
  assert.equal(modern.identity, "650_0_0");
  assert.equal(modern.size, 64);
  const legacy = json.find((r) => r.name === "615_0_0.mbn");
  assert.equal(legacy.generation, "Legacy ELF");
});

// --- unit: parseModule dispatch ------------------------------------------------

test("parseModule dispatches on generation and rejects unknown", () => {
  const blob = MODERN_BLOB;
  const modern = parseModule({ name: "rf_config_13_0_0.mbn", inner_path: "/x", generation: "DAT/protobuf" }, blob);
  assert.equal(modern.metadata.generation, "DAT/protobuf");
  const aliased = parseModule({ name: "rf_config_13_0_0.mbn", inner_path: "/x", generation: "modern" }, blob);
  assert.equal(aliased.metadata.generation, "modern");
  assert.throws(
    () => parseModule({ name: "x.mbn", inner_path: "/x", generation: "Carrier XML" }, blob),
    (err) => err instanceof ToolError && /Unknown RF-card format: Carrier XML/.test(err.message),
  );
});

// --- unit: generateWebTables ---------------------------------------------------

function comp(table, comboIndex, fields) {
  return {
    table,
    sub_capability: null,
    combo_index: comboIndex,
    position: 0,
    technology: "NR",
    band: 1,
    dl_bw_class_code: 1,
    dl_bw_class: "A",
    dl_bw_code: null,
    dl_bandwidth: "100 MHz",
    dl_antenna_index: 3,
    dl_antenna: "ANTENNA_4",
    ul_bw_class_code: 1,
    ul_bw_class: "A",
    ul_bw_code: null,
    ul_bandwidth: "100 MHz",
    ul_antenna_index: 1,
    ul_antenna: "ANTENNA_1",
    ul_qam_cap_index: 2,
    max_scs: 3,
    ...fields,
  };
}

function combo(table, comboIndex, fields) {
  return {
    table,
    table_name: "EN-DC",
    sub_capability: null,
    combo_index: comboIndex,
    expression: "X",
    component_count: 1,
    power_class: 2,
    bcs_num: 0,
    ul_tx_switch_type: 1,
    higher_power_limit: false,
    ...fields,
  };
}

test("generateWebTables sorts components descending and stable", () => {
  // Python probe: equal (band, class) components keep their original order
  // under sorted(..., reverse=True); higher band sorts first.
  const tables = generateWebTables(
    [combo("endc", 0, { bcs_num: 0 })],
    [
      comp("endc", 0, { technology: "LTE", band: 3, position: 0, ul_bw_class: "NONE" }),
      comp("endc", 0, { technology: "LTE", band: 3, position: 1, ul_antenna: "ANTENNA_1", ul_qam_cap_index: 2 }),
      comp("endc", 0, { technology: "LTE", band: 1, position: 2, ul_bw_class: "NONE" }),
      comp("endc", 0, { technology: "NR", band: 79, dl_bw_class: "A", dl_antenna: "4", max_scs: 1 }),
    ],
  );
  assert.deepEqual(Object.keys(tables), ["lte_ca", "nr_ca", "endc", "nrdc"]);
  const [row] = tables.endc;
  assert.deepEqual(Object.keys(row), [
    "LTE DL",
    "LTE MIMO DL",
    "LTE DL (QAM)",
    "NR DL",
    "NR MIMO DL",
    "NR DL (QAM)",
    "NR SCS DL (kHz)",
    "NR BW DL (MHz)",
    "LTE UL",
    "LTE MIMO UL",
    "LTE UL (QAM)",
    "NR UL",
    "NR MIMO UL",
    "NR UL (QAM)",
    "NR SCS UL (kHz)",
    "NR BW UL (MHz)",
  ]);
  assert.equal(row["LTE DL"], "3A + 3A + 1A");
  assert.equal(row["LTE MIMO DL"], "4 + 4 + 4");
  assert.equal(row["NR DL"], "79A");
  assert.equal(row["NR BW DL (MHz)"], "100");
  assert.equal(row["NR SCS DL (kHz)"], "15");
  assert.equal(row["NR MIMO UL"], "1");
});

test("generateWebTables adds BCS columns only when a real bcs_num exists", () => {
  const base = [comp("nr_ca", 0, { max_scs: 1 })];
  const noBcs = generateWebTables([combo("nr_ca", 0, { bcs_num: 0 })], base);
  assert.equal(Object.keys(noBcs.nr_ca[0]).length, 11);
  assert.equal(noBcs.nr_ca[0]["UL TX Switch"], "option 1");
  const withBcs = generateWebTables([combo("nr_ca", 0, { bcs_num: 5 })], base);
  assert.deepEqual(Object.keys(withBcs.nr_ca[0]).slice(-1), ["BCS"]);
  assert.equal(withBcs.nr_ca[0].BCS, "5");
  // bcs_num 0 / null / -1 never enable the column
  for (const bcs of [0, null, -1]) {
    assert.equal(Object.keys(generateWebTables([combo("nr_ca", 0, { bcs_num: bcs })], base).nr_ca[0]).length, 11);
  }
});

test("generateWebTables groups components by (table, combo_index) only", () => {
  // Python quirk probed from the goldens: modern high/low suffixes share the
  // combo_index namespace, so their components merge into one row.
  const tables = generateWebTables(
    [
      combo("lte_ca", 0, { sub_capability: "high", bcs_num: null }),
      combo("lte_ca", 0, { sub_capability: "low", bcs_num: null }),
    ],
    [
      comp("lte_ca", 0, { technology: "LTE", band: 41, ul_bandwidth: "40" }),
      comp("lte_ca", 0, { technology: "LTE", band: 7, position: 1, ul_bandwidth: "20" }),
    ],
  );
  assert.equal(tables.lte_ca.length, 2);
  assert.deepEqual(tables.lte_ca.map((r) => r["LTE DL"]), ["41A + 7A", "41A + 7A"]);
});

test("generateWebTables splits nrdc rows at band 257", () => {
  const tables = generateWebTables(
    [combo("nrdc", 0, { bcs_num: null })],
    [
      comp("nrdc", 0, { band: 78, dl_bandwidth: "100 MHz", max_scs: 1 }),
      comp("nrdc", 0, { band: 261, position: 1, dl_bandwidth: "400 MHz", max_scs: 4 }),
    ],
  );
  const [row] = tables.nrdc;
  assert.equal(row["FR1 DL"], "78A");
  assert.equal(row["FR2 DL"], "261A");
  assert.equal(row["FR1 BW DL (MHz)"], "100");
  assert.equal(row["FR2 BW DL (MHz)"], "400");
  assert.equal(row["FR1 DL (QAM)"], "256");
  assert.equal(row["FR2 DL (QAM)"], "256");
});

// --- unit: exportModule ---------------------------------------------------------

test("exportModule csv/json/webcsv produce Python-shaped files", () => {
  const record = { name: "rf_config_13_0_0.mbn", inner_path: "/x", generation: "DAT/protobuf" };
  const parsed = parseModule({ ...record, generation: "DAT/protobuf" }, MODERN_BLOB);

  const json = exportModule(record, parsed, "json");
  assert.deepEqual(json.map((f) => f.filename), ["rf_config_13_0_0_all_combos.json"]);
  assert.ok(json[0].text.endsWith("\n"));
  const parsedJson = JSON.parse(json[0].text);
  assert.deepEqual(Object.keys(parsedJson), ["metadata", "combinations", "components"]);

  // The empty fixture parse has no rows: Python _write_csv skips empty tables
  // (no file), so csv/webcsv produce no files for it.
  assert.deepEqual(exportModule(record, parsed, "csv"), []);
  assert.deepEqual(exportModule(record, parsed, "webcsv"), []);

  // Populated tables exercise the CSV writers (structure mirrors _write_csv).
  const fakeParsed = {
    metadata: {},
    combinations: [
      { table: "endc", expression: "DC_B3_n78", raw_hex: "aa bb" },
      { table: "endc", expression: "DC_B1_n78", extra: "only row 2 has me", note: null },
    ],
    components: [{ table: "endc", band: 3, nested: { a: [1, 2] } }],
    diag: { b0cd: [] },
  };
  const csv = exportModule(record, fakeParsed, "csv");
  assert.deepEqual(csv.map((f) => f.filename), [
    "rf_config_13_0_0_combinations.csv",
    "rf_config_13_0_0_components.csv",
  ]);
  const [header, row1, row2] = csv[0].text.slice(1).split("\r\n");
  assert.equal(header, "table,expression,raw_hex,extra,note");
  assert.equal(row1, "endc,DC_B3_n78,aa bb,,");
  assert.equal(row2, "endc,DC_B1_n78,,only row 2 has me,");
  // container values are JSON-dumped compactly, then csv-quoted
  const [compHeader] = csv[1].text.slice(1).split("\r\n");
  const compRow = csv[1].text.slice(1).split("\r\n")[1];
  assert.equal(compHeader, "table,band,nested");
  assert.equal(compRow, 'endc,3,"{""a"":[1,2]}"');

  // webcsv: one file per non-empty table, in Python's table order; the input
  // is the parsed module, so generateWebTables runs inside the export.
  const webParsed = {
    metadata: {},
    combinations: [
      { table: "endc", combo_index: 0, bcs_num: null },
      { table: "lte_ca", combo_index: 0, bcs_num: null },
    ],
    components: [
      { table: "endc", combo_index: 0, technology: "LTE", band: 3, dl_bw_class: "A", dl_antenna: "4", ul_bw_class: "A", ul_antenna: "1", ul_qam_cap_index: 2 },
      { table: "lte_ca", combo_index: 0, technology: "LTE", band: 3, dl_bw_class: "A", dl_antenna: "4", ul_bw_class: "A", ul_antenna: "1", ul_qam_cap_index: 2 },
    ],
    diag: { b0cd: [] },
  };
  const webcsv = exportModule(record, webParsed, "webcsv");
  assert.deepEqual(webcsv.map((f) => f.filename), [
    "rf_config_13_0_0_lteca.csv",
    "rf_config_13_0_0_endc.csv",
  ]);
  assert.ok(webcsv[0].text.startsWith("\uFEFF"));
  assert.ok(webcsv[0].text.endsWith("\r\n"));
  assert.equal(
    webcsv[0].text.slice(1).split("\r\n")[0],
    "LTE DL,MIMO DL,DL (QAM),LTE UL,MIMO UL,UL (QAM)",
  );

  assert.throws(() => exportModule(record, parsed, "mbn"), ToolError);
});

// --- regression: scanSource FAT read semantics --------------------------------

// Python-verified digests (probe: gui scan_source over the same fixture bytes).
const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const CHAIN2_SHA256 = "58086d49f89f82a7e063ba7e232b480c581dad245fc7a1358389c6d369ea67db";
const CONTROL_SHA256 = "816cebfc85b241baf5a0575ab65500681f073d69577925bb04c33ed99353e284";

// Root: /IMAGE/SO/6_0_0.MBN with caller-controlled firstCluster/size; FAT
// entries come from fatLinks. Geometry and pattern match the Python probe.
function buildCorruptFat16Fixture({ fatLinks, firstCluster, size }) {
  const image = new Uint8Array(TOTAL_SECTORS * BPS);
  const dv = new DataView(image.buffer);
  image.set([0xeb, 0x3c, 0x90], 0);
  dv.setUint16(11, BPS, true);
  image[13] = SPC;
  dv.setUint16(14, RESERVED, true);
  image[16] = NFATS;
  dv.setUint16(17, ROOT_ENTRIES, true);
  dv.setUint16(19, TOTAL_SECTORS, true);
  image[21] = 0xf8;
  dv.setUint16(22, SPFT, true);
  dv.setUint16(510, 0xaa55, true);
  // directory chains always terminate; fatLinks overlays the file entries
  dv.setUint16(FAT_OFFSET + 2 * 2, 0xffff, true);
  dv.setUint16(FAT_OFFSET + 3 * 2, 0xffff, true);
  for (const [cluster, next] of Object.entries(fatLinks)) {
    dv.setUint16(FAT_OFFSET + Number(cluster) * 2, next, true);
  }
  writeDirEntry(image, ROOT_OFFSET + 0 * 32, "SYSLABEL", "   ", 0x08);
  writeDirEntry(image, ROOT_OFFSET + 1 * 32, "IMAGE", "   ", 0x10, 2);
  const d2 = clusterOffset(2);
  writeDirEntry(image, d2 + 0 * 32, ".", "   ", 0x10, 2);
  writeDirEntry(image, d2 + 1 * 32, "..", "   ", 0x10);
  writeDirEntry(image, d2 + 2 * 32, "SO", "   ", 0x10, 3);
  const d3 = clusterOffset(3);
  writeDirEntry(image, d3 + 0 * 32, ".", "   ", 0x10, 3);
  writeDirEntry(image, d3 + 1 * 32, "..", "   ", 0x10);
  writeDirEntry(image, d3 + 2 * 32, "6_0_0", "MBN", 0x20, firstCluster, size);
  for (let c = 4; c < 14; c++) {
    for (let i = 0; i < CLUSTER_SIZE; i++) image[clusterOffset(c) + i] = (i * 7 + 41) & 0xff;
  }
  return image;
}

test("scanSource FAT read uses Python's raw cluster-chain semantics", async () => {
  // fat._read_clusters(entry.first_cluster)[: entry.size]: no size validation,
  // chain IS walked even for size 0. Python probe outcomes:
  //   EOC chain + size=100  -> OK record, sha256 of the empty blob, size 100
  //   reserved 1 + size=50  -> OK record, sha256 of the empty blob, size 50
  //   2-chain + size=5000   -> OK record, short blob, size field stays 5000
  const cases = [
    { label: "EOC chain", fatLinks: {}, firstCluster: 0xffff, size: 100, sha: EMPTY_SHA256 },
    { label: "reserved cluster 1", fatLinks: {}, firstCluster: 1, size: 50, sha: EMPTY_SHA256 },
    {
      label: "2-cluster chain, size beyond chain",
      fatLinks: { 4: 5, 5: 0xffff },
      firstCluster: 4,
      size: 5000,
      sha: CHAIN2_SHA256,
    },
  ];
  for (const c of cases) {
    const result = await scanSource(
      new BrowserFileSource(new Blob([buildCorruptFat16Fixture(c)])),
      "modem.img",
    );
    assert.deepEqual(result.warnings, [], c.label);
    assert.equal(result.records.length, 1, c.label);
    assert.equal(result.records[0].size, c.size, c.label);
    assert.equal(result.records[0].sha256, c.sha, c.label);
  }
});

test("scanSource kills the scan on a looping cluster chain even at size 0", async () => {
  const src = new BrowserFileSource(
    new Blob([buildCorruptFat16Fixture({ fatLinks: { 6: 6 }, firstCluster: 6, size: 0 })]),
  );
  await assert.rejects(
    scanSource(src, "modem.img"),
    (err) => err instanceof ParseError && err.message === "FAT16 cluster chain loops at 6.",
  );
});

test("scanSource control: plain file keeps cluster-prefix hashing", async () => {
  const image = buildCorruptFat16Fixture({ fatLinks: { 10: 0xffff }, firstCluster: 10, size: 100 });
  const result = await scanSource(new BrowserFileSource(new Blob([image])), "modem.img");
  assert.deepEqual(result.warnings, []);
  assert.equal(result.records.length, 1);
  assert.equal(result.records[0].sha256, CONTROL_SHA256);
  assert.equal(result.records[0].sha256, sha256Hex(image.slice(clusterOffset(10), clusterOffset(10) + 100)));
});

test("Fat16Image.readClusters exposes the raw cluster chain", async () => {
  const image = buildCorruptFat16Fixture({ fatLinks: { 4: 5, 5: 0xffff }, firstCluster: 4, size: 5000 });
  const fat = new Fat16Image(new BrowserFileSource(new Blob([image])));
  await fat.init();
  const chain = await fat.readClusters(4);
  assert.equal(chain.length, 2 * CLUSTER_SIZE);
  assert.deepEqual(chain.subarray(0, 8), image.subarray(clusterOffset(4), clusterOffset(4) + 8));
  assert.deepEqual(await fat.readClusters(0xffff), new Uint8Array(0));
  assert.deepEqual(await fat.readClusters(1), new Uint8Array(0));
  const loop = new Fat16Image(
    new BrowserFileSource(
      new Blob([buildCorruptFat16Fixture({ fatLinks: { 6: 6 }, firstCluster: 6, size: 0 })]),
    ),
  );
  await loop.init();
  await assert.rejects(loop.readClusters(6), ParseError);
});

// --- regression: formatScsVal exactness (Python (1 << (c - 1)) * 15) -----------

test("formatScsVal stays exact for large SCS codes", () => {
  // Python probe outputs; 2 ** (c - 1) * 15 goes exponential >= 1e21 in JS.
  assert.equal(formatScsVal(1), "15");
  assert.equal(formatScsVal(2), "30");
  assert.equal(formatScsVal(30), "8053063680");
  assert.equal(formatScsVal(31), "16106127360");
  assert.equal(formatScsVal(52), "33776997205278720");
  assert.equal(formatScsVal(69), "4427218577690292387840");
  assert.equal(formatScsVal(75), "283341988972178712821760");
  assert.equal(
    formatScsVal(1023),
    "674134925573368465398489446545884275106741367103364964775362804341497534270628611747656789959028260079200427049517725091220461633054062334348177864898027966416629600343245569786133323504672852947949061070318771633143065058784235805527174164528102139362564415067198618399802172269298936143132586236090840514560",
  );
  assert.equal(formatScsVal(0), "15");
  assert.equal(formatScsVal(null), "15");
  assert.equal(formatScsVal(-3), "15");
  assert.equal(formatScsVal("x"), "15");
});

// --- regression: deduplicateRecords empty-sha parity --------------------------

test("deduplicateRecords keeps falsy-sha records like the Python OSError fallback", () => {
  const emptySha = (innerPath) => ({
    name: "x.mbn",
    inner_path: innerPath,
    generation: "Legacy ELF",
    size: 1,
    hwid: 6,
    fsid: 0,
    bid: 0,
    external: false,
    source_path: "",
    sidecars: {},
    sha256: "",
    lte_combos: -1,
    nr_combos: "—",
  });
  // Empty digest + no re-hash source -> Python raises OSError and keeps all.
  const both = deduplicateRecords([emptySha("/1"), emptySha("/2")]);
  assert.deepEqual(both.map((r) => r.inner_path), ["/1", "/2"]);
  const dup = deduplicateRecords([
    { ...emptySha("/1"), sha256: "aa" },
    { ...emptySha("/2"), sha256: "aa" },
  ]);
  assert.deepEqual(dup.map((r) => r.inner_path), ["/1"]);
});

// --- regression: sortRecords BigInt ids (exact int tuple) ---------------------

test("sortRecords compares BigInt ids like Python's exact int tuple", () => {
  const rec = (innerPath, hwid, extra = {}) => ({
    inner_path: innerPath,
    name: "6_0_0.mbn",
    generation: "Legacy ELF",
    size: 1,
    hwid,
    fsid: 0,
    bid: 0,
    external: false,
    source_path: "",
    sidecars: {},
    sha256: "h",
    lte_combos: -1,
    nr_combos: "—",
    ...extra,
  });
  // 2**53 and 2**53+1 collapse to the same double; a Number-normalizing
  // comparator would tie and mis-order via inner_path. Python keeps exact ints.
  const near = sortRecords([rec("/a", 9007199254740993n), rec("/b", 9007199254740992n)]);
  assert.deepEqual(near.map((r) => r.inner_path), ["/b", "/a"]);
  // Mixed Number/BigInt magnitudes compare numerically, Python order.
  const mixed = sortRecords([rec("/x", 9007199254740993n), rec("/y", 5)]);
  assert.deepEqual(mixed.map((r) => r.inner_path), ["/y", "/x"]);
  // Generation bucket still wins; BigInt fsid tie-breaks exactly.
  const multi = sortRecords([
    rec("/legacy", 3, { fsid: 9007199254740992n }),
    rec("/modern", 9, { generation: "DAT/protobuf" }),
  ]);
  assert.deepEqual(multi.map((r) => r.inner_path), ["/modern", "/legacy"]);
});
