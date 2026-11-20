import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { Fat16Image, scanForFat16 } from "../js/lib/fat16.js";
import { BrowserFileSource, sourceFor } from "../js/lib/source.js";
import { scanSource, normalizeInnerPath } from "../js/lib/analyzer.js";
import { sha256HexAsync } from "../js/lib/hash.js";
import { CORPUS_DIR, corpusAvailable } from "./helpers.mjs";

// --- synthetic FAT16 fixture -------------------------------------------------
// Geometry: bytesPerSector=512, sectorsPerCluster=4, reserved=1, numFATs=2,
// rootEntries=512, sectorsPerFat=16, totalSectors=16405 -> exactly 4085 data
// clusters (the FAT16 lower bound). Layout:
//   root:  volume label | RF_CARDS dir | LFN pair -> RF_CON~1.MBN | EMPTY.DAT
//   cluster 2: RF_CARDS dir (".", "..", 615_0_0.MBN)
//   clusters 3-5: RF_CON~1.MBN chain (size 5000, 3 clusters)
//   cluster 6: 615_0_0.MBN data (size 100)
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
  const slots = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]; // <5H>@1 + <6H>@14 + <2H>@28
  const dv = new DataView(image.buffer);
  units.forEach((u, i) => dv.setUint16(off + slots[i], u, true));
}

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
  dv.setUint16(510, 0xaa55, true); // 0x55 at 510, 0xaa at 511
  // FAT: [0]/[1] media+EOC, [2]=EOC (RF_CARDS), 3->4->5->EOC (big file), [6]=EOC
  dv.setUint16(FAT_OFFSET + 0, 0xfff8, true);
  dv.setUint16(FAT_OFFSET + 2, 0xffff, true);
  dv.setUint16(FAT_OFFSET + 4, 0xffff, true);
  dv.setUint16(FAT_OFFSET + 6, 4, true);
  dv.setUint16(FAT_OFFSET + 8, 5, true);
  dv.setUint16(FAT_OFFSET + 10, 0xffff, true);
  dv.setUint16(FAT_OFFSET + 12, 0xffff, true);
  writeDirEntry(image, ROOT_OFFSET + 0 * 32, "SYSLABEL", "   ", 0x08); // volume label: skipped
  writeDirEntry(image, ROOT_OFFSET + 1 * 32, "RF_CARDS", "   ", 0x10, 2);
  writeLfnEntry(image, ROOT_OFFSET + 2 * 32, 2, "6_0_0.mbn", true);
  writeLfnEntry(image, ROOT_OFFSET + 3 * 32, 1, "rf_config_130");
  writeDirEntry(image, ROOT_OFFSET + 4 * 32, "RF_CON~1", "MBN", 0x20, 3, 5000);
  writeDirEntry(image, ROOT_OFFSET + 5 * 32, "EMPTY", "DAT", 0x20);
  const d = clusterOffset(2);
  writeDirEntry(image, d + 0 * 32, ".", "   ", 0x10, 2);
  writeDirEntry(image, d + 1 * 32, "..", "   ", 0x10);
  writeDirEntry(image, d + 2 * 32, "615_0_0", "MBN", 0x20, 6, 100);
  for (let i = 0; i < 5000; i++) image[clusterOffset(3) + i] = pattern(i);
  for (let i = 0; i < 100; i++) image[clusterOffset(6) + i] = pattern(i);
  return image;
}

const openFixture = () => new Fat16Image(new BrowserFileSource(new Blob([buildFat16Fixture()])));

// --- unit tests --------------------------------------------------------------

test("walk() returns entries in Python DFS order with LFN and 8.3 names", async () => {
  const fat = openFixture();
  await fat.init();
  const entries = await fat.walk();
  // pre-order: RF_CARDS contents first, then root files in directory order
  assert.deepEqual(entries.map((e) => e.path), [
    "/RF_CARDS/615_0_0.MBN",
    "/rf_config_1306_0_0.mbn", // assembled from ordinals 1+2, not the 8.3 alias
    "/EMPTY.DAT",
  ]);
  assert.deepEqual(entries[0], { path: "/RF_CARDS/615_0_0.MBN", firstCluster: 6, size: 100, isDir: false });
  assert.deepEqual(entries[1], { path: "/rf_config_1306_0_0.mbn", firstCluster: 3, size: 5000, isDir: false });
  assert.deepEqual(entries[2], { path: "/EMPTY.DAT", firstCluster: 0, size: 0, isDir: false });
});

test("readFile follows multi-cluster chains and truncates to entry.size", async () => {
  const fat = openFixture();
  await fat.init();
  const entries = await fat.walk();
  const expected = new Uint8Array(5000);
  for (let i = 0; i < 5000; i++) expected[i] = pattern(i);
  const big = entries.find((e) => e.path === "/rf_config_1306_0_0.mbn");
  const data = await fat.readFile(big);
  assert.equal(data.length, 5000);
  assert.deepEqual(data, expected);
  const inner = entries.find((e) => e.path === "/RF_CARDS/615_0_0.MBN");
  assert.deepEqual(await fat.readFile(inner), expected.subarray(0, 100));
  const empty = entries.find((e) => e.path === "/EMPTY.DAT");
  assert.deepEqual(await fat.readFile(empty), new Uint8Array(0));
});

test("readFile rejects directories", async () => {
  const fat = openFixture();
  await fat.init();
  await assert.rejects(
    () => fat.readFile({ path: "/RF_CARDS", firstCluster: 2, size: 0, isDir: true }),
    /Path is a directory inside modem.img: \/RF_CARDS/
  );
});

test("init rejects inputs too small to be FAT", async () => {
  const fat = new Fat16Image(new BrowserFileSource(new Blob([new Uint8Array(32)])));
  await assert.rejects(() => fat.init(), /Input is too small to be a FAT filesystem/);
});

test("scanForFat16 finds an embedded boot sector and validates it", async () => {
  const fat = buildFat16Fixture().slice();
  fat.set(new TextEncoder().encode("MSWIN4.1"), 3);
  const wrapped = new Uint8Array(0x3500 + fat.length);
  wrapped.set(fat, 0x3500);
  const src = new BrowserFileSource(new Blob([wrapped]));
  assert.deepEqual(await scanForFat16(src, wrapped.length, 1), [0x3500]);

  // A 0x55AA signature without a known FAT OEM is rejected.
  const noOem = fat.slice();
  noOem.fill(0, 3, 11);
  const noOemWrapped = new Uint8Array(0x3500 + noOem.length);
  noOemWrapped.set(noOem, 0x3500);
  assert.deepEqual(
    await scanForFat16(new BrowserFileSource(new Blob([noOemWrapped])), noOemWrapped.length, 1),
    [],
  );
});

test("init rejects non-FAT16 boot sectors", async () => {
  const image = buildFat16Fixture();
  image[11] = 123; // bytesPerSector not in {512,1024,2048,4096}
  const fat = new Fat16Image(new BrowserFileSource(new Blob([image])));
  await assert.rejects(() => fat.init(), /Input is not a supported FAT16 filesystem/);
});

test("init rejects FAT12-scale cluster counts", async () => {
  const image = buildFat16Fixture();
  new DataView(image.buffer).setUint16(19, 100, true); // totalSectors -> 8 data clusters
  const fat = new Fat16Image(new BrowserFileSource(new Blob([image])));
  await assert.rejects(() => fat.init(), /Filesystem has 8 data clusters; FAT16 expected/);
});

test("walk() without init() fails with a clear message", async () => {
  const fat = openFixture();
  await assert.rejects(() => fat.walk(), /call await init\(\) before walk/);
});

test("readFile rejects looping cluster chains", async () => {
  const image = buildFat16Fixture();
  new DataView(image.buffer).setUint16(FAT_OFFSET + 10, 3, true); // 5 -> 3: loop
  const fat = new Fat16Image(new BrowserFileSource(new Blob([image])));
  await fat.init();
  const big = (await fat.walk()).find((e) => e.path === "/rf_config_1306_0_0.mbn");
  await assert.rejects(() => fat.readFile(big), /FAT16 cluster chain loops at 3/);
});

test("readFile rejects sizes larger than the cluster chain", async () => {
  const image = buildFat16Fixture();
  new DataView(image.buffer).setUint32(ROOT_OFFSET + 4 * 32 + 28, 20000, true); // size > 3 clusters
  const fat = new Fat16Image(new BrowserFileSource(new Blob([image])));
  await fat.init();
  const big = (await fat.walk()).find((e) => e.path === "/rf_config_1306_0_0.mbn");
  await assert.rejects(() => fat.readFile(big), /FAT16 file is truncated/);
});

test("a deleted LFN chunk keeps the remaining partial name without 8.3 fallback", async () => {
  const image = buildFat16Fixture();
  image[ROOT_OFFSET + 2 * 32] = 0xe5; // ordinal 2 deleted, ordinal 1 survives
  const fat = new Fat16Image(new BrowserFileSource(new Blob([image])));
  await fat.init();
  const names = (await fat.walk()).map((e) => e.path);
  assert.ok(names.includes("/rf_config_130"), `partial LFN name expected, got ${names.join(", ")}`);
});

test("findFile returns the matching walk entry or null", async () => {
  const fat = openFixture();
  await fat.init();
  assert.deepEqual(await fat.findFile("/RF_CARDS/615_0_0.MBN"), {
    path: "/RF_CARDS/615_0_0.MBN",
    firstCluster: 6,
    size: 100,
    isDir: false,
  });
  assert.equal(await fat.findFile("/missing/thing.mbn"), null);
  assert.equal(await fat.findFile("/RF_CARDS"), null); // directories are not walked
});

test("findFile without init() fails with a clear message", async () => {
  const fat = openFixture();
  await assert.rejects(() => fat.findFile("/RF_CARDS/615_0_0.MBN"), /call await init\(\) before findFile/);
});

class CountingSource {
  constructor(inner) {
    this.inner = inner;
    this.size = inner.size;
    this.reads = []; // [offset, length]
  }
  async read(off, len) {
    this.reads.push([off, len]);
    return this.inner.read(off, len);
  }
}

test("readClusters coalesces a contiguous chain into one read", async () => {
  const counting = new CountingSource(new BrowserFileSource(new Blob([buildFat16Fixture()])));
  const fat = new Fat16Image(counting);
  await fat.init();
  const entry = await fat.findFile("/rf_config_1306_0_0.mbn"); // 3-4-5 chain, 5000 bytes
  counting.reads.length = 0; // drop init/walk reads
  const out = await fat.readClusters(entry.firstCluster);
  assert.equal(out.length, 3 * CLUSTER_SIZE);
  assert.equal(counting.reads.length, 1, "one merged read for a contiguous chain");
  assert.deepEqual(counting.reads[0], [clusterOffset(3), 3 * CLUSTER_SIZE]);
  for (let i = 0; i < 5000; i++) assert.equal(out[i], pattern(i));
});

test("readClusters issues one read per non-adjacent run", async () => {
  // Build a fixture whose big file chain is 3 -> 5 -> EOC (cluster 4 skipped),
  // i.e. two runs of one cluster each. Patch the FAT link after building.
  const image = buildFat16Fixture();
  const dv = new DataView(image.buffer);
  dv.setUint16(FAT_OFFSET + 6, 5, true); // 3 -> 5 (skip 4)
  const counting = new CountingSource(new BrowserFileSource(new Blob([image])));
  const fat = new Fat16Image(counting);
  await fat.init();
  const entry = await fat.findFile("/rf_config_1306_0_0.mbn");
  counting.reads.length = 0;
  await fat.readClusters(entry.firstCluster);
  assert.equal(counting.reads.length, 2, "two runs -> two reads");
  assert.deepEqual(counting.reads[0], [clusterOffset(3), CLUSTER_SIZE]);
  assert.deepEqual(counting.reads[1], [clusterOffset(5), CLUSTER_SIZE]);
});

// --- ranged reads (Step 1: the container walker sniffs heads only) ------------

test("readFileRange equals readFile().subarray() inside, across and at the end of cluster runs", async () => {
  const fat = openFixture();
  await fat.init();
  const entries = await fat.walk();
  // /rf_config_1306_0_0.mbn is a 3-cluster (3-4-5) contiguous chain, 5000 bytes;
  // /RF_CARDS/615_0_0.MBN is a single cluster truncated to 100 bytes.
  for (const path of ["/rf_config_1306_0_0.mbn", "/RF_CARDS/615_0_0.MBN"]) {
    const entry = entries.find((e) => e.path === path);
    const full = await fat.readFile(entry);
    const probes = [
      [0, 0],
      [0, 1],
      [0, Math.min(100, full.length)],
      [CLUSTER_SIZE - 5, 20], // straddles the first cluster boundary
      [CLUSTER_SIZE * 2 - 1, 2], // last byte of one run + first of the next
      [Math.max(0, full.length - 3), 3], // at the very end
      [1, Math.max(1, full.length - 2)], // most of the file in one call
    ];
    for (const [off, len] of probes) {
      if (off < 0 || len < 0 || off + len > full.length) continue;
      const got = await fat.readFileRange(entry, off, len);
      assert.deepEqual(got, full.subarray(off, off + len), `${path} [${off}, ${len})`);
    }
  }
});

test("readFileRange reads only the needed bytes and rejects out-of-range/dir reads", async () => {
  const counting = new CountingSource(new BrowserFileSource(new Blob([buildFat16Fixture()])));
  const fat = new Fat16Image(counting);
  await fat.init();
  const entry = await fat.findFile("/rf_config_1306_0_0.mbn");
  counting.reads.length = 0;
  const head = await fat.readFileRange(entry, 0, 4096); // 2 clusters' worth
  assert.equal(head.length, 4096);
  assert.equal(counting.reads.length, 1, "a contiguous range is one coalesced read");
  assert.deepEqual(counting.reads[0], [clusterOffset(3), 4096]);
  for (let i = 0; i < 4096; i++) assert.equal(head[i], pattern(i));

  await assert.rejects(() => fat.readFileRange(entry, entry.size - 2, 4), RangeError);
  await assert.rejects(() => fat.readFileRange(entry, -1, 4), RangeError);
  await assert.rejects(
    () => fat.readFileRange({ path: "/RF_CARDS", firstCluster: 2, size: 0, isDir: true }, 0, 1),
    /Path is a directory/,
  );
});

// --- scan artifacts + walk memo (Step 3) --------------------------------------

test("scanSource onCandidate hands back the exact bytes that were hashed", async () => {
  const source = new BrowserFileSource(new Blob([buildFat16Fixture()]));
  const seen = [];
  const { records } = await scanSource(source, "fixture.img", {
    onCandidate: (record, blob) => seen.push({ record, blob }),
  });
  assert.equal(records.length, 1, "only the modern root candidate survives the path gates");
  assert.equal(seen.length, records.length, "one hook call per record");
  for (const { record, blob } of seen) {
    assert.equal(await sha256HexAsync(blob), record.sha256, record.name);
  }
});

test("Signature 27 Motorola radio image -> embedded FAT16 cards", {
  skip: !existsSync(join(CORPUS_DIR, "motosignature27radio.img")),
}, async () => {
  const path = join(CORPUS_DIR, "motosignature27radio.img");
  const { records, warnings } = await scanSource(await sourceFor(path), "motosignature27radio.img");
  assert.deepEqual(warnings, []);
  assert.deepEqual(records.map((r) => r.name).sort(), [
    "rf_config_0500_0_0_0170.mbn",
    "rf_config_0501_0_0_0170.mbn",
    "rf_config_0502_0_0_0170.mbn",
    "rf_config_0503_0_0_0170.mbn",
    "rf_config_0510_0_0_0170.mbn",
    "rf_config_0511_0_0_0170.mbn",
    "rf_config_0512_0_0_0170.mbn",
    "rf_config_0513_0_0_0170.mbn",
    "rf_config_0520_0_0_0170.mbn",
  ]);
  for (const record of records) {
    assert.equal(record.generation, "DAT/protobuf");
    assert.ok(normalizeInnerPath(record.inner_path).startsWith("fat/image/modem_pr/"), record.inner_path);
    assert.ok(record.lte_combos > 0);
  }
});

test("walk() is memoized after init and cleared by a re-init", async () => {
  const counting = new CountingSource(new BrowserFileSource(new Blob([buildFat16Fixture()])));
  const fat = new Fat16Image(counting);
  await fat.init();
  counting.reads.length = 0;
  const first = await fat.walk();
  const readsAfterFirst = counting.reads.length;
  assert.ok(readsAfterFirst > 0, "the first walk reads directories");
  const second = await fat.walk();
  assert.equal(counting.reads.length, readsAfterFirst, "the second walk must not read");
  assert.equal(second, first, "the memoized entry array is returned as-is");
  await fat.init(); // clears the memo
  counting.reads.length = 0;
  await fat.walk();
  assert.ok(counting.reads.length > 0, "init() must drop the memo");
});

// --- golden (corpus-gated) ---------------------------------------------------

test("fat16 hardware entries match goldens", { skip: !corpusAvailable() }, async (t) => {
  const corpus = JSON.parse(await readFile(new URL("../goldens/corpus.json", import.meta.url)));
  for (const [img, recs] of Object.entries(corpus)) {
    if (recs.length === 0) continue;
    if (!img.endsWith(".img") || img === "radio.img") continue; // tar.md5 + radio.img are wrappers, not FAT16
    const src = await sourceFor(join(CORPUS_DIR, img));
    const fat = new Fat16Image(src);
    await fat.init();
    const paths = (await fat.walk()).map((e) => e.path);
    for (const rec of recs) assert.ok(paths.includes(rec.inner_path), `${img}: missing ${rec.inner_path}`);
    await src.close();
  }
});
