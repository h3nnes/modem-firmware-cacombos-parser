// UBI/UBIFS in-browser extraction: detection, the tree walk over all three
// compression variants, gzip recursion, end-to-end scanSource, and malformed
// input. Fixtures are real mtd-utils 2.3.0 images stored gzipped+base64 in
// ubi_fixtures.mjs; they were built with:
//
//   mkfs.ubifs -m 512 -e 15360 -c 48 -x none -r source-tree -o ubifs.img
//   mkfs.ubifs -m 512 -e 15360 -c 48 -x lzo  -r source-tree -o ubifs.img
//   mkfs.ubifs -m 512 -e 15360 -c 48 -x zlib -r source-tree -o ubifs.img
//   ubinize -o fixture-<x>.ubi -m 512 -p 16KiB -s 512 cfg.ini
//
// cfg.ini has one [modem] volume (mode=ubi, vol_id=0, vol_size=1MiB,
// vol_type=dynamic, vol_name=modem, vol_flags=autoresize). The source tree is
//   image/modem_pr/mcfg/configs/mcfg_ddr/rf/rf_config_1324_0_0.mbn  (1200 B)
//   image/modem_pr/so/549_0_1.mbn                                    (700 B)
//   image/modem_pr/lteum/payload.bin                                (40000 B)
// and the mini-* images pack a single 17-byte "legacy-card-bytes" MBN under
// image/modem_pr/so/549_0_1.mbn.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { gunzipSync, gzipSync } from "../lib/vendor/fflate.js";
import { BrowserFileSource } from "../js/lib/source.js";
import { detect, SUPPORTED_TAGS, UNSUPPORTED_TAGS } from "../js/lib/formats.js";
import { UbiImage, lzo1xDecompress } from "../js/lib/ubi.js";
import { crc32 } from "../js/lib/mtk_hash.js";
import { extractContainer, discoverCandidates } from "../js/lib/extractor.js";
import { normalizeInnerPath, scanSource } from "../js/lib/analyzer.js";
import {
  fixture_none,
  fixture_lzo,
  fixture_zlib,
  mini_none,
  mini_lzo,
  mini_zlib,
} from "./ubi_fixtures.mjs";

// --- fixtures ------------------------------------------------------------------------

const FIXTURES = {
  none: fixture_none,
  lzo: fixture_lzo,
  zlib: fixture_zlib,
};

const MINI = {
  none: mini_none,
  lzo: mini_lzo,
  zlib: mini_zlib,
};

function fixtureBytes(b64) {
  return gunzipSync(new Uint8Array(Buffer.from(b64, "base64")));
}

function sourceOf(bytes, name = "modem.ubi") {
  return new BrowserFileSource(new Blob([bytes]));
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

// expected.json from the desktop tool (gui_version/image_extractor.py).
const EXPECTED = {
  none: {
    imageSeq: 1343868883,
    files: [
      ["image/modem_pr/mcfg/configs/mcfg_ddr/rf/rf_config_1324_0_0.mbn", 1200, "8a7af0d39bfc8142d1347e17947bdc6d3eac2997404a6482a7831fef5835fc2d"],
      ["image/modem_pr/so/549_0_1.mbn", 700, "07d8b5bfaa04122a99cd15818e60cea723da0b1cb9786bc00920b8bee7d98dd8"],
      ["image/modem_pr/lteum/payload.bin", 40000, "2087a96cba41252fd76066523bde888b841e30fdbbd86281f7cbff9f6c8f4a7e"],
    ],
  },
  lzo: {
    imageSeq: 510382176,
    files: [
      ["image/modem_pr/mcfg/configs/mcfg_ddr/rf/rf_config_1324_0_0.mbn", 1200, "8a7af0d39bfc8142d1347e17947bdc6d3eac2997404a6482a7831fef5835fc2d"],
      ["image/modem_pr/so/549_0_1.mbn", 700, "07d8b5bfaa04122a99cd15818e60cea723da0b1cb9786bc00920b8bee7d98dd8"],
      ["image/modem_pr/lteum/payload.bin", 40000, "2087a96cba41252fd76066523bde888b841e30fdbbd86281f7cbff9f6c8f4a7e"],
    ],
  },
  zlib: {
    imageSeq: 1134893780,
    files: [
      ["image/modem_pr/mcfg/configs/mcfg_ddr/rf/rf_config_1324_0_0.mbn", 1200, "8a7af0d39bfc8142d1347e17947bdc6d3eac2997404a6482a7831fef5835fc2d"],
      ["image/modem_pr/so/549_0_1.mbn", 700, "07d8b5bfaa04122a99cd15818e60cea723da0b1cb9786bc00920b8bee7d98dd8"],
      ["image/modem_pr/lteum/payload.bin", 40000, "2087a96cba41252fd76066523bde888b841e30fdbbd86281f7cbff9f6c8f4a7e"],
    ],
  },
};

const MINI_HASH = "3ee6e51f3183539b14d2326776119152d609ba5379efc66fac722eba8e0c5e60";
const MINI_SEQ = { none: 727432352, lzo: 1543824125, zlib: 324633515 };

// --- detection -----------------------------------------------------------------------

test("detect() routes UBI# to the supported in-house reader", () => {
  assert.equal(detect(new Uint8Array([0x55, 0x42, 0x49, 0x23])), "ubi");
  assert.ok(SUPPORTED_TAGS.has("ubi"), "ubi must be in SUPPORTED_TAGS");
  assert.equal(UNSUPPORTED_TAGS.ubi, undefined, "ubi must not be hard-rejected");
  // Real fixture leading bytes are the EC header magic.
  assert.equal(detect(fixtureBytes(fixture_none).subarray(0, 4096)), "ubi");
});

// --- tree walk -----------------------------------------------------------------------

for (const variant of ["none", "lzo", "zlib"]) {
  test(`UbiImage walks the ${variant}-compressed fixture byte-exactly`, async () => {
    const image = new UbiImage(sourceOf(fixtureBytes(FIXTURES[variant])));
    await image.init();
    assert.deepEqual(image.warnings, []);
    assert.equal(image.pebSize, 16384);
    assert.equal(image.lebSize, 15360);
    assert.deepEqual(image.volumes.map((v) => [v.imageSeq, v.name]), [[EXPECTED[variant].imageSeq, "modem"]]);

    const entries = await image.walk();
    const byPath = new Map(entries.map((e) => [e.path, e]));
    assert.deepEqual(
      [...byPath.keys()].sort(),
      EXPECTED[variant].files.map(([p]) => `/${EXPECTED[variant].imageSeq}/modem/${p}`).sort(),
    );
    for (const [path, size, digest] of EXPECTED[variant].files) {
      const entry = byPath.get(`/${EXPECTED[variant].imageSeq}/modem/${path}`);
      assert.equal(entry.size, size, `${path}: size`);
      assert.equal(entry.isDir, false);
      const bytes = await image.readFile(entry);
      assert.equal(bytes.length, size, `${path}: read length`);
      assert.equal(sha256(bytes), digest, `${path}: sha256`);
    }
    // Ranged reads (what extractor.headOf uses) must match the full read.
    const card = byPath.get(`/${EXPECTED[variant].imageSeq}/modem/image/modem_pr/so/549_0_1.mbn`);
    const full = await image.readFile(card);
    const head = await image.readFileRange(card, 0, Math.min(64, card.size));
    assert.deepEqual(head, full.subarray(0, 64));
    const middle = await image.readFileRange(card, 100, 200);
    assert.deepEqual(middle, full.subarray(100, 300));
  });
}

test("all three compression variants produce identical file bytes", async () => {
  const results = {};
  for (const variant of ["none", "lzo", "zlib"]) {
    const image = new UbiImage(sourceOf(fixtureBytes(FIXTURES[variant])));
    await image.init();
    const map = new Map();
    for (const entry of await image.walk()) {
      const relative = entry.path.split("/").slice(3).join("/"); // strip /<seq>/modem/
      map.set(relative, await image.readFile(entry));
    }
    results[variant] = map;
  }
  const baseline = results.none;
  assert.deepEqual([...baseline.keys()].sort(), [
    "image/modem_pr/lteum/payload.bin",
    "image/modem_pr/mcfg/configs/mcfg_ddr/rf/rf_config_1324_0_0.mbn",
    "image/modem_pr/so/549_0_1.mbn",
  ]);
  for (const variant of ["lzo", "zlib"]) {
    for (const [path, bytes] of baseline) {
      assert.deepEqual(results[variant].get(path), bytes, `${variant}: ${path}`);
    }
  }
  // The multi-LEB payload exercises >1 data node per LEB and the index tree.
  assert.equal(baseline.get("image/modem_pr/lteum/payload.bin").length, 40000);
});

test("mini fixtures round-trip through every compression mode", async () => {
  for (const variant of ["none", "lzo", "zlib"]) {
    const image = new UbiImage(sourceOf(fixtureBytes(MINI[variant])));
    await image.init();
    assert.deepEqual(image.warnings, []);
    const entries = await image.walk();
    assert.deepEqual(entries.map((e) => e.path), [`/${MINI_SEQ[variant]}/modem/image/modem_pr/so/549_0_1.mbn`]);
    const bytes = await image.readFile(entries[0]);
    assert.equal(bytes.length, 17);
    assert.equal(Buffer.from(bytes).toString("latin1"), "legacy-card-bytes");
    assert.equal(sha256(bytes), MINI_HASH);
  }
});

// --- container layer -----------------------------------------------------------------

test("extractContainer discovers UBI RF cards with desktop-normalized paths", async () => {
  for (const variant of ["none", "lzo", "zlib"]) {
    const bytes = fixtureBytes(FIXTURES[variant]);
    const { root, outputs, warnings } = await extractContainer(sourceOf(bytes), "modem.ubi");
    assert.deepEqual(warnings, [], `${variant}: warnings`);
    assert.deepEqual(root.files().length > 0, true);
    const { mbns } = discoverCandidates(outputs);
    const paths = mbns.map((m) => normalizeInnerPath(m.path)).sort();
    const seq = EXPECTED[variant].imageSeq;
    assert.deepEqual(paths, [
      `ubi/${seq}/modem/image/modem_pr/mcfg/configs/mcfg_ddr/rf/rf_config_1324_0_0.mbn`,
      `ubi/${seq}/modem/image/modem_pr/so/549_0_1.mbn`,
    ]);
    // The raw scratch dir is ubi_0 and nests <image_seq>/<volume>/.
    assert.deepEqual(outputs.map((o) => o.name), ["ubi_0"]);
    const expectedBySeq = EXPECTED[variant].files;
    for (const { vfile, path } of mbns) {
      const hit = expectedBySeq.find(([relative]) => path.endsWith(relative));
      assert.ok(hit, `unexpected candidate ${path}`);
      const read = await vfile.read();
      assert.equal(read.length, hit[1]);
      assert.equal(sha256(read), hit[2], `${variant}: ${path}`);
      const normalized = normalizeInnerPath(path);
      assert.ok(normalized.startsWith(`ubi/${seq}/modem/`), normalized);
    }
  }
});

test("gzipped .ubi still works via the existing gzip recursion", async () => {
  const gz = gzipSync(fixtureBytes(fixture_lzo), { level: 9 });
  const { root, outputs, warnings } = await extractContainer(sourceOf(gz), "modem.ubi.gz");
  assert.deepEqual(warnings, []);
  // gzip_0 holds the decompressed intermediate (pyStem keeps the inner
  // ".ubi"); the UBIFS tree lands in its own sibling ubi_1 workdir, exactly
  // like gzip->ext4 nests today.
  const paths = root.files().map((f) => f.path).sort();
  const seq = EXPECTED.lzo.imageSeq;
  assert.deepEqual(paths, [
    "gzip_0/modem.ubi",
    `ubi_1/${seq}/modem/image/modem_pr/lteum/payload.bin`,
    `ubi_1/${seq}/modem/image/modem_pr/mcfg/configs/mcfg_ddr/rf/rf_config_1324_0_0.mbn`,
    `ubi_1/${seq}/modem/image/modem_pr/so/549_0_1.mbn`,
  ].sort());
  const { mbns } = discoverCandidates(outputs);
  assert.deepEqual(mbns.map((m) => normalizeInnerPath(m.path)).sort(), [
    `ubi/${seq}/modem/image/modem_pr/mcfg/configs/mcfg_ddr/rf/rf_config_1324_0_0.mbn`,
    `ubi/${seq}/modem/image/modem_pr/so/549_0_1.mbn`,
  ]);
});

// --- end to end ----------------------------------------------------------------------

test("scanSource returns both UBI RF-card records", async () => {
  const source = sourceOf(fixtureBytes(fixture_lzo));
  const result = await scanSource(source, "modem.ubi");
  assert.deepEqual(result.warnings, []);
  assert.equal(result.records.length, 2);
  const records = result.records.map((r) => ({
    name: r.name,
    inner_path: normalizeInnerPath(r.inner_path),
    generation: r.generation,
    size: r.size,
    sha256: r.sha256,
    lte_combos: r.lte_combos,
    nr_combos: r.nr_combos,
  }));
  assert.deepEqual(records, [
    {
      name: "rf_config_1324_0_0.mbn",
      inner_path: `ubi/${EXPECTED.lzo.imageSeq}/modem/image/modem_pr/mcfg/configs/mcfg_ddr/rf/rf_config_1324_0_0.mbn`,
      generation: "DAT/protobuf",
      size: 1200,
      sha256: "8a7af0d39bfc8142d1347e17947bdc6d3eac2997404a6482a7831fef5835fc2d",
      // Synthetic random-byte MBNs: the combo tables are unparseable.
      lte_combos: -1,
      nr_combos: "—",
    },
    {
      name: "549_0_1.mbn",
      inner_path: `ubi/${EXPECTED.lzo.imageSeq}/modem/image/modem_pr/so/549_0_1.mbn`,
      generation: "Legacy ELF",
      size: 700,
      sha256: "07d8b5bfaa04122a99cd15818e60cea723da0b1cb9786bc00920b8bee7d98dd8",
      lte_combos: -1,
      nr_combos: "—",
    },
  ]);
});

// --- malformed input -----------------------------------------------------------------

test("PEB geometry is recovered when the image starts at a non-zero offset", async () => {
  // A boot wrapper in front of the UBI data (common on vendor images) must not
  // break PEB detection: the start offset is the most common alignment
  // residue of the "UBI#" occurrences.
  const inner = fixtureBytes(fixture_none);
  const prefixed = new Uint8Array(7777 + inner.length);
  prefixed.set(inner, 7777);
  const image = new UbiImage(sourceOf(prefixed));
  await image.init();
  assert.equal(image.pebSize, 16384);
  assert.equal(image.startOffset, 7777);
  assert.deepEqual(image.warnings, []);
  const entries = await image.walk();
  assert.equal(entries.length, 3);
  for (const entry of entries) {
    assert.match(sha256(await image.readFile(entry)), /^[0-9a-f]{64}$/);
  }
});

test("PEB geometry is recovered behind a wrapper larger than a scan window", async () => {
  // Vendor images can hide the UBI payload behind tens of MiB of padding. The
  // anchor scan must not stop at a fixed window, or these fail with "could not
  // determine the PEB size". 17 MiB also exceeds any single read chunk.
  const inner = fixtureBytes(mini_lzo);
  const prefix = 17 * 1024 * 1024 + 1001;
  const wrapped = new Uint8Array(prefix + inner.length);
  // A decoy magic in the padding must not drag the start offset off the image.
  wrapped.set([0x55, 0x42, 0x49, 0x23], 1000);
  wrapped.set(inner, prefix);
  const image = new UbiImage(sourceOf(wrapped));
  await image.init();
  assert.equal(image.pebSize, 16384);
  // startOffset is the alignment residue the PEB grid is anchored on, not the
  // absolute first block (see the 7777-offset test); the grid must still land
  // on the payload.
  assert.equal(image.startOffset, prefix % 16384);
  assert.deepEqual(image.warnings, []);
  const entries = await image.walk();
  assert.equal(entries.length, 1);
  assert.equal(sha256(await image.readFile(entries[0])), MINI_HASH);
});

test("a UBI file with two images and two volumes reports both", async () => {
  // Concatenating two real single-image files gives one UBI stream with two
  // distinct image_seq values, which is the multi-image case.
  const a = fixtureBytes(fixture_none);
  const b = fixtureBytes(fixture_lzo);
  const both = new Uint8Array(a.length + b.length);
  both.set(a, 0);
  both.set(b, a.length);
  const image = new UbiImage(sourceOf(both));
  await image.init();
  assert.deepEqual(image.warnings, []);
  assert.deepEqual(image.images.map((i) => i.imageSeq), [1343868883, 510382176]);
  assert.deepEqual(
    image.volumes.map((v) => [v.imageSeq, v.name]),
    [[1343868883, "modem"], [510382176, "modem"]],
  );
  const entries = await image.walk();
  assert.equal(entries.length, 6);
  for (const sequence of [1343868883, 510382176]) {
    assert.equal(entries.filter((e) => e.path.startsWith(`/${sequence}/modem/`)).length, 3);
  }
});

// Builds a two-volume variant of the lzo fixture: volume 0 stays the UBIFS
// "modem" tree, volume 1 is an appended PEB of raw bytes (a UBI image may mix
// UBIFS with raw/static volumes). Only the volume-table record and the appended
// PEB's headers need to be written; the existing volume is untouched.
function buildMixedVolumeImage(bytes) {
  const pebSize = 16384;
  const dataOffset = 1024;
  const out = new Uint8Array(bytes.length + pebSize);
  out.set(bytes, 0);
  const srcPeb = bytes.subarray(2 * pebSize, 3 * pebSize);
  const dstBase = bytes.length;
  out.set(srcPeb.subarray(0, dataOffset), dstBase);
  // VID header at 512: vol_id 1, lnum 0.
  const vidOff = dstBase + 512;
  out[vidOff + 8] = 0;
  out[vidOff + 9] = 0;
  out[vidOff + 10] = 0;
  out[vidOff + 11] = 1;
  const vidCrc = ~crc32(out.subarray(vidOff, vidOff + 60)) >>> 0;
  new DataView(out.buffer).setUint32(vidOff + 60, vidCrc, false);
  // Raw LEB payload: not UBIFS on purpose.
  for (let i = 0; i < pebSize - dataOffset; i++) out[dstBase + dataOffset + i] = i & 0xff;
  // Add volume record #1 ("rawvol") to both layout PEBs and fix its CRC.
  for (const layoutPeb of [0, 1]) {
    const at = layoutPeb * pebSize + dataOffset + 172;
    out.fill(0, at, at + 172);
    new DataView(out.buffer).setUint32(at + 0, 1, false); // reserved_pebs
    out[at + 12] = 1; // dynamic
    new DataView(out.buffer).setUint16(at + 14, 6, false); // name_len
    const name = "rawvol";
    for (let i = 0; i < name.length; i++) out[at + 16 + i] = name.charCodeAt(i);
    const recCrc = ~crc32(out.subarray(at, at + 168)) >>> 0;
    new DataView(out.buffer).setUint32(at + 168, recCrc, false);
  }
  return out;
}

test("a UBI mixing UBIFS and raw volumes warns and still extracts the UBIFS tree", async () => {
  const bytes = buildMixedVolumeImage(fixtureBytes(fixture_lzo));
  const image = new UbiImage(sourceOf(bytes));
  await image.init();
  const warnings = image.warnings;
  assert.ok(
    warnings.some((w) => w.tool === "ubi" && /rawvol/.test(w.message) && /non-UBIFS/.test(w.message)),
    JSON.stringify(warnings),
  );
  const entries = await image.walk();
  assert.deepEqual(
    entries.map((e) => e.path).sort(),
    EXPECTED.lzo.files.map(([p]) => `/${EXPECTED.lzo.imageSeq}/modem/${p}`).sort(),
  );
  // The raw volume produces no entries at all.
  assert.ok(entries.every((e) => e.path.startsWith(`/${EXPECTED.lzo.imageSeq}/modem/`)));

  const { root, warnings: containerWarnings } = await extractContainer(sourceOf(bytes), "mixed.ubi");
  assert.ok(containerWarnings.some((w) => w.tool === "ubi" && /rawvol/.test(w.message)));
  assert.equal(root.files().length, 3);
});

test("an unreadable UBIFS superblock is warned about, never thrown", async () => {
  // Corrupt the UBIFS superblock magic inside volume 0's first LEB but leave
  // every UBI EC/VID header intact: the volume is then "not UBIFS".
  const bytes = fixtureBytes(fixture_lzo).slice();
  const pebSize = 16384;
  const dataOffset = 1024;
  bytes.fill(0, 2 * pebSize + dataOffset, 2 * pebSize + dataOffset + 24);
  const { root, warnings } = await extractContainer(sourceOf(bytes), "broken-fs.ubi");
  assert.deepEqual(root.files(), []);
  assert.ok(warnings.some((w) => w.tool === "ubi" && /non-UBIFS/.test(w.message)), JSON.stringify(warnings));
  assert.ok(warnings.some((w) => w.tool === "ubi" && /no readable UBIFS volumes/.test(w.message)));
});

test("zstd data nodes skip just that file with a structured zstd warning", async () => {
  // No zstd decoder ships in the browser, so a UBIFS data node with
  // compr_type 3 must warn and drop the single file instead of failing the
  // volume. Patch the rf_config data node in the real none-compressed fixture
  // (its payload is raw, so only the type byte + node CRC change).
  const bytes = fixtureBytes(fixture_none).slice();
  const dv = new DataView(bytes.buffer);
  let patched = 0;
  for (let off = 0; off + 64 <= bytes.length; off++) {
    if (bytes[off] !== 0x31 || bytes[off + 1] !== 0x18 || bytes[off + 2] !== 0x10 || bytes[off + 3] !== 0x06) continue;
    const len = dv.getUint32(off + 16, true);
    if (bytes[off + 20] !== 1 || len < 64 || off + len > bytes.length) continue;
    if (dv.getUint32(off + 40, true) !== 1200) continue; // only rf_config_1324_0_0.mbn
    dv.setUint16(off + 44, 3, true); // compr_type = UBIFS_COMPR_ZSTD
    dv.setUint32(off + 4, ~crc32(bytes.subarray(off + 8, off + len)) >>> 0, true);
    patched++;
    break;
  }
  assert.equal(patched, 1, "expected to patch exactly one data node");

  const { outputs, warnings } = await extractContainer(sourceOf(bytes), "zstd.ubi");
  assert.ok(warnings.some((w) => w.tool === "zstd" && /zstd/.test(w.message)), JSON.stringify(warnings));
  const { mbns } = discoverCandidates(outputs);
  assert.deepEqual(mbns.map((m) => normalizeInnerPath(m.path)), [
    `ubi/${EXPECTED.none.imageSeq}/modem/image/modem_pr/so/549_0_1.mbn`,
  ]);
  // The surviving file still reads byte-exactly.
  assert.equal(sha256(await mbns[0].vfile.read()), "07d8b5bfaa04122a99cd15818e60cea723da0b1cb9786bc00920b8bee7d98dd8");

  // scanSource surfaces the same warning and only the one record.
  const scanned = await scanSource(sourceOf(bytes), "zstd.ubi");
  assert.equal(scanned.records.length, 1);
  assert.equal(scanned.records[0].name, "549_0_1.mbn");
  assert.ok(scanned.warnings.some((w) => w.tool === "zstd"));
});

test("truncated UBI warns instead of throwing", async () => {
  const bytes = fixtureBytes(fixture_lzo);
  // Keep the layout PEBs plus a sliver of the first data volume PEB.
  const truncated = bytes.subarray(0, 16384 * 2 + 512);
  const { root, warnings } = await extractContainer(sourceOf(truncated), "broken.ubi");
  assert.deepEqual(root.files(), []);
  assert.ok(warnings.length > 0, "expected at least one structured warning");
  assert.ok(warnings.every((w) => typeof w.tool === "string" && typeof w.message === "string"));
  assert.ok(warnings.some((w) => w.tool === "ubi" && /UBI/.test(w.message)));
});

test("UBI magic with garbage headers warns instead of throwing", async () => {
  const garbage = new Uint8Array(64 * 1024);
  garbage.set([0x55, 0x42, 0x49, 0x23], 0); // UBI# at 0
  garbage.set([0x55, 0x42, 0x49, 0x23], 16384); // and at 16384
  const { root, warnings } = await extractContainer(sourceOf(garbage), "fake.ubi");
  assert.deepEqual(root.files(), []);
  assert.ok(warnings.some((w) => w.tool === "ubi"));
});

test("a sub-512-byte UBI stub is rejected by the container size floor", async () => {
  const stub = new Uint8Array(64);
  stub.set([0x55, 0x42, 0x49, 0x23]);
  await assert.rejects(
    () => extractContainer(sourceOf(stub), "stub.ubi"),
    /too small to be a container/,
  );
});

// --- LZO decoder unit ----------------------------------------------------------------

// Compressed streams produced by liblzo2's lzo1x_1_compress (mtd-utils uses the
// linux-kernel lzo1x encoder, same format). Plaintexts are hex so the vectors
// stay exact; they cover the literal run, M2 and M1 encodings, and the
// 40000-byte fixture payload above covers the M4 far-match form byte-exactly.
const LZO_VECTORS = [
  {
    label: "initial literal run only",
    plain: "6162636465666768696a6b6c6d6e6f707172", // "abcdefghijklmnopqr"
    compressed: "236162636465666768696a6b6c6d6e6f707172110000",
  },
  {
    label: "M2 back-reference into the literal block",
    plain: "68656c6c6f20776f726c6420".repeat(20),
    compressed: "0968656c6c6f20776f726c642020b32c000d726c642068656c6c6f20776f726c6420110000",
  },
  {
    label: "M1 short matches",
    plain:
      "6162630061626304616263086162630c6162631061626314616263186162631c6162632061626324" +
      "616263286162632c6162633061626334616263386162633c6162630061626304616263086162630c" +
      "6162631061626314616263186162631c6162632061626324616263286162632c6162633061626334" +
      "616263386162633c6162630061626304616263086162630c6162631061626314616263186162631c" +
      "6162632061626324616263286162632c6162633061626334616263386162633c6162630061626304" +
      "616263086162630c6162631061626314616263186162631c6162632061626324616263286162632c" +
      "6162633061626334616263386162633c6162630061626304616263086162630c6162631061626314" +
      "616263186162631c6162632061626324616263286162632c6162633061626334616263386162633c" +
      "6162630061626304616263086162630c6162631061626314616263186162631c6162632061626324" +
      "616263286162632c6162633061626334616263386162633c6162630061626304616263086162630c" +
      "6162630061626304616263086162630c6162631061626314616263186162631c6162632061626324" +
      "616263286162632c6162633061626334616263386162633c6162630061626304616263086162630c" +
      "6162631061626314616263186162631c6162632061626324616263286162632c6162633061626334" +
      "616263386162633c6162630061626304616263086162630c6162631061626314616263186162631c" +
      "6162632061626324616263286162632c6162633061626334616263386162633c6162630061626304" +
      "616263086162630c6162631061626314616263186162631c6162632061626324616263286162632c" +
      "6162633061626334616263386162633c6162630061626304616263086162630c6162631061626314" +
      "616263186162631c6162632061626324616263286162632c6162633061626334616263386162633c" +
      "6162630061626304616263086162630c6162631061626314616263186162631c6162632061626324" +
      "616263286162632c6162633061626334616263386162633c6162630061626304616263086162630c",
    compressed:
      "002e6162630061626304616263086162630c6162631061626314616263186162631c6162632061626324" +
      "616263286162632c6162633061626334616263386162633c200033fe00006120005c3c060c6263006162" +
      "6304616263086162630c110000",
  },
];

test("lzo1xDecompress decodes real liblzo2 streams", () => {
  for (const vector of LZO_VECTORS) {
    const input = new Uint8Array(Buffer.from(vector.compressed, "hex"));
    const expected = new Uint8Array(Buffer.from(vector.plain, "hex"));
    const decoded = lzo1xDecompress(input, expected.length);
    assert.equal(Buffer.from(decoded).toString("hex"), vector.plain, vector.label);
  }
});

test("lzo1xDecompress rejects malformed streams instead of looping or overrunning", () => {
  // A back-reference that points before the output start.
  const badOffset = new Uint8Array([17 + 2, 0x41, 0x42, 0x00, 0xff]);
  assert.throws(() => lzo1xDecompress(badOffset, 32), /LZO1X/);
  // Truncated literal run.
  const truncated = new Uint8Array([17 + 100, 0x41, 0x42]);
  assert.throws(() => lzo1xDecompress(truncated, 100), /truncated LZO1X/);
  // Stream that stops short of the expected size.
  const short = new Uint8Array([17 + 4, 0x41, 0x42, 0x43, 0x44, 0x11, 0x00, 0x00]);
  assert.throws(() => lzo1xDecompress(short, 8), /produced 4 of 8/);
});
