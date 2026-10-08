// Container orchestration over a virtual file tree: tar incl. .tar.md5 tails,
// zip incl. the .bbfw member filter, gzip, lz4, unsupported-container
// warnings, and the two corpus chains
// in miniature (Motorola wrapper -> sparse -> ext4; tar -> lz4 -> FAT16).
import { test } from "node:test";
import assert from "node:assert/strict";
import { BrowserFileSource } from "../js/lib/source.js";
import { extractContainer, discoverCandidates, headOf, RFCARD_RE, SIDECAR_RES, VFile } from "../js/lib/extractor.js";
import { normalizeInnerPath } from "../js/lib/analyzer.js";
import { hexToBytes } from "../js/lib/bytes.js";
import { zipSync, strToU8 } from "../lib/vendor/fflate.js";
import { buildExt4Tree } from "./ext4.test.mjs";
import { randomBytes } from "node:crypto";

// --- builders -----------------------------------------------------------------

function u32(n) {
  return Uint8Array.of(n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255);
}

// Minimal ustar writer: members = [{ name, data, type?, longName? }]; a md5
// tail after the 1024-byte end marker mirrors Samsung .tar.md5 files.
function buildUstar(members, { tail = "", longNames = false } = {}) {
  const blocks = [];
  const octal = (n, width) => n.toString(8).padStart(width - 1, "0") + "\0";
  const header = (name, size, type) => {
    const h = new Uint8Array(512);
    const write = (off, s) => { for (let i = 0; i < s.length; i++) h[off + i] = s.charCodeAt(i); };
    write(0, name.slice(0, 100));
    write(100, "0000644\0");
    write(108, "0000000\0");
    write(116, "0000000\0");
    write(124, octal(size, 12));
    write(136, octal(0, 12));
    for (let i = 0; i < 8; i++) h[148 + i] = 0x20;
    h[156] = type.charCodeAt(0);
    write(257, "ustar\0");
    write(263, "00");
    let sum = 0;
    for (const b of h) sum += b;
    write(148, octal(sum, 8));
    return h;
  };
  for (const m of members) {
    if (longNames && m.name.length > 100) {
      const nameData = strToU8(m.name + "\0");
      blocks.push(header("././@LongLink", nameData.length, "L"), pad512(nameData));
    }
    blocks.push(header(m.name, m.data.length, m.type ?? "0"), pad512(m.data));
  }
  blocks.push(new Uint8Array(1024));
  if (tail) blocks.push(strToU8(tail));
  const total = blocks.reduce((n, b) => n + b.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const b of blocks) { out.set(b, off); off += b.length; }
  return out;
}

function pad512(data) {
  const out = new Uint8Array(Math.ceil(data.length / 512) * 512 || 512);
  out.set(data);
  return out;
}

async function gzipBytes(data) {
  const stream = new Blob([data]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

// A valid LZ4 frame holding one all-literal block (no compression needed to
// exercise the real decoder path in chains).
function lz4FrameAllLiterals(data) {
  const ext = [];
  let n = data.length - 15;
  while (n >= 255) { ext.push(255); n -= 255; }
  ext.push(n);
  const block = new Uint8Array(1 + ext.length + data.length);
  block[0] = 0xf0;
  block.set(ext, 1);
  block.set(data, 1 + ext.length);
  const header = new Uint8Array(19);
  header.set([0x04, 0x22, 0x4d, 0x18, 0x68, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  new DataView(header.buffer).setUint32(6, data.length, true);
  new DataView(header.buffer).setUint32(15, block.length, true);
  const out = new Uint8Array(19 + block.length + 4);
  out.set(header);
  out.set(block, 19);
  out.set(u32(0), 19 + block.length);
  return out;
}

// --- FAT16 fixture (Samsung miniature): root/IMAGE/rf_config_1181_0_306.mbn ----

const FBPS = 512;
const FSPC = 4;
const FCLUSTER = FBPS * FSPC;
const FFAT_OFFSET = 1 * FBPS;
const FROOT_OFFSET = (1 + 2 * 16) * FBPS;
const FDATA_OFFSET = (1 + 2 * 16 + (512 * 32) / FBPS) * FBPS;

function fatWriteDirEntry(image, off, name, ext, attr, first = 0, size = 0) {
  for (let i = 0; i < 8; i++) image[off + i] = i < name.length ? name.charCodeAt(i) : 0x20;
  for (let i = 0; i < 3; i++) image[off + 8 + i] = i < ext.length ? ext.charCodeAt(i) : 0x20;
  image[off + 11] = attr;
  const dv = new DataView(image.buffer);
  dv.setUint16(off + 26, first, true);
  dv.setUint32(off + 28, size, true);
}

function fatWriteLfn(image, off, ordinal, chars, lastPhysical = false) {
  image[off] = ordinal | (lastPhysical ? 0x40 : 0);
  image[off + 11] = 0x0f;
  const units = [];
  for (const ch of chars) units.push(ch.codePointAt(0));
  while (units.length < 13) units.push(units.length === chars.length ? 0x0000 : 0xffff);
  const slots = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
  const dv = new DataView(image.buffer);
  units.forEach((u, i) => dv.setUint16(off + slots[i], u, true));
}

function buildFat16Miniature(fileData) {
  // 4085 data clusters exactly (FAT16 lower bound), like the Task 5 fixture.
  const image = new Uint8Array(16405 * FBPS);
  const dv = new DataView(image.buffer);
  image.set([0xeb, 0x3c, 0x90], 0);
  image.set([0x4d, 0x53, 0x57, 0x49, 0x4e, 0x34, 0x2e, 0x31], 3); // MSWIN4.1
  dv.setUint16(11, FBPS, true);
  image[13] = FSPC;
  dv.setUint16(14, 1, true);
  image[16] = 2;
  dv.setUint16(17, 512, true);
  dv.setUint16(19, 16405, true);
  image[21] = 0xf8;
  dv.setUint16(22, 16, true);
  dv.setUint16(FFAT_OFFSET + 0, 0xfff8, true);
  dv.setUint16(FFAT_OFFSET + 2, 0xffff, true); // cluster 2: IMAGE dir EOC
  dv.setUint16(FFAT_OFFSET + 4, 0xffff, true); // cluster 2: IMAGE dir EOC
  dv.setUint16(FFAT_OFFSET + 6, 0xffff, true); // cluster 3: file data EOC
  fatWriteLfn(image, FROOT_OFFSET, 1, "image", true); // LFN for the dir name
  fatWriteDirEntry(image, FROOT_OFFSET + 32, "IMAGE", "   ", 0x10, 2);
  const d = FDATA_OFFSET;
  fatWriteDirEntry(image, d, ".", "   ", 0x10, 2);
  fatWriteDirEntry(image, d + 32, "..", "   ", 0x10, 0);
  const name = "rf_config_1181_0_306.mbn";
  fatWriteLfn(image, d + 64, 2, name.slice(13), true); // ord 2: chars 14-26 (last)
  fatWriteLfn(image, d + 96, 1, name.slice(0, 13)); // ord 1: chars 1-13
  fatWriteDirEntry(image, d + 128, "RF_CO~1", "MBN", 0x20, 3, fileData.length);
  image.set(fileData, FDATA_OFFSET + FCLUSTER);
  return image;
}

// --- shared helpers --------------------------------------------------------------

const openContainer = (bytes, name) => extractContainer(new BrowserFileSource(new Blob([bytes])), name);

// --- tar -------------------------------------------------------------------------

test("tar extraction: members, subdirectories, longnames, trailing md5 tail", async () => {
  const tar = buildUstar(
    [
      { name: "modem.bin.lz4", data: Uint8Array.of(1, 2, 3, 4) },
      { name: "dir/sub/file.txt", data: strToU8("nested") },
      { name: "a".repeat(140) + ".bin", data: Uint8Array.of(9) },
    ],
    { longNames: true, tail: "4e0419f861d8a26ce2d0023cd704caf2  CP_F976.tar\n" },
  );
  const { root, warnings } = await openContainer(tar, "CP_test.tar.md5");
  assert.deepEqual(warnings, []);
  const files = root.files();
  assert.deepEqual(
    files.map((f) => f.path).sort(),
    ["tar_0/" + "a".repeat(140) + ".bin", "tar_0/dir/sub/file.txt", "tar_0/modem.bin.lz4"],
  );
  const lz4 = files.find((f) => f.path.endsWith("modem.bin.lz4"));
  assert.deepEqual(await lz4.vfile.read(), Uint8Array.of(1, 2, 3, 4));
});

test("tar member paths escaping the destination fail extraction like filter=data", async () => {
  const tar = buildUstar([{ name: "../evil.txt", data: strToU8("x") }]);
  const { root, warnings } = await openContainer(tar, "evil.tar");
  assert.deepEqual(root.files(), []);
  assert.ok(warnings.some((w) => w.tool === "tar" && /escape/.test(w.message)));
});

// --- zip -------------------------------------------------------------------------

test("zip extraction: stored + deflated members via the central directory", async () => {
  const zip = zipSync({
    "readme.txt": strToU8("deflated member ".repeat(40)),
    "blob.bin": [new Uint8Array(600).fill(0xde), { level: 0 }],
  });
  const { root, warnings } = await openContainer(zip, "fw.zip");
  assert.deepEqual(warnings, []);
  const files = new Map(root.files().map((f) => [f.path, f.vfile]));
  assert.deepEqual([...files.keys()].sort(), ["zip_0/blob.bin", "zip_0/readme.txt"]);
  assert.deepEqual(await files.get("zip_0/blob.bin").read(), new Uint8Array(600).fill(0xde));
  assert.equal((await files.get("zip_0/readme.txt").read()).length, 40 * 16);
});

test("zip with .bbfw members extracts only those, then unwraps the nested archive", async () => {
  const innerZip = zipSync({ "bbcfg.mbn": minimalBbcfg(), "pad.bin": [new Uint8Array(600).fill(0x11), { level: 0 }] });
  const outerZip = zipSync({
    "blob.bin": [new Uint8Array(600).fill(0xde), { level: 0 }],
    "fw.bbfw": innerZip,
  });
  const { outputs, warnings } = await openContainer(outerZip, "firmware.ipsw");
  assert.deepEqual(outputs.map((d) => d.name), ["zip_0", "zip_1"]);
  assert.deepEqual(outputs[0].files().map((f) => f.path), ["fw.bbfw"]);
  assert.deepEqual(outputs[1].files().map((f) => f.path).sort(), ["bbcfg.mbn", "pad.bin"]);
  assert.deepEqual(warnings, []);
});

test("zip without .bbfw members extracts everything (Android package shape)", async () => {
  const zip = zipSync({ "modem/rf_config_123_0_0.mbn": [strToU8("card".repeat(200)), { level: 0 }] });
  const { root } = await openContainer(zip, "ota.zip");
  assert.deepEqual(root.files().map((f) => f.path), ["zip_0/modem/rf_config_123_0_0.mbn"]);
});

// Minimal BBCFG container: header + marker, no tag-0xA9 store (no cards).
function minimalBbcfg() {
  const out = new Uint8Array(0x40);
  out.set([0x00, 0x47, 0x46, 0x43], 0); // \x00GFC
  new DataView(out.buffer).setUint32(4, 3, true); // version
  new DataView(out.buffer).setUint32(0x14, out.length - 40, true);
  out.set([0x42, 0x42, 0x43, 0x46, 0x47, 0x4d, 0x42, 0x4e, 0x30], 0x28); // BBCFGMBN0
  return out;
}

// --- gzip ------------------------------------------------------------------------

test("gzip extraction: DecompressionStream + stem naming", async () => {
  const gz = await gzipBytes(randomBytes(600));
  const { root, warnings } = await openContainer(gz, "payload.img.gz");
  assert.deepEqual(warnings, []);
  const files = root.files();
  assert.deepEqual(files.map((f) => f.path), ["gzip_0/payload.img"]);
  assert.equal(files[0].vfile.size, 600);
});

test("gzip of a FAT16 image unwraps recursively into a fat workdir", async () => {
  const gz = await gzipBytes(buildFat16Miniature(strToU8("rfcard-bytes")));
  const { outputs } = await openContainer(gz, "modem.img.gz");
  // only the fat workdir registers as an output; gzip_0 holds the raw image
  const { mbns } = discoverCandidates(outputs);
  assert.deepEqual(mbns.map((m) => m.path), ["fat_1/image/rf_config_1181_0_306.mbn"]);
});

// --- lz4 -------------------------------------------------------------------------

test("lz4 extraction: output named from the stem (extract_lz4 :414-415)", async () => {
  // small_text fixture from the differential lz4 vectors (hello world x20)
  const frame = hexToBytes(
    "04224d184040c01b010000ff01303132333435363738396162636465661000ff" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd8" +
    "5062636465660a0100000f1000ffffffffffffffffffffffffffffffffffffff" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
    "ffffffffffffffffffffffffffe850626364656600000000",
  );
  const { root, warnings } = await openContainer(frame, "modem.bin.lz4");
  assert.deepEqual(warnings, []);
  assert.deepEqual(root.files().map((f) => f.path), ["lz4_0/modem.bin"]);
  assert.equal(root.files()[0].vfile.size, 131072);
});

// --- unsupported containers --------------------------------------------------------

test("unsupported containers produce structured tool warnings, no records", async () => {
  const erofs = new Uint8Array(4096);
  erofs.set([0xe2, 0xe1, 0xf5, 0xe0], 0x400);
  const { root, warnings } = await openContainer(erofs, "system.img");
  assert.deepEqual(root.files(), []);
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0].tool, "fsck.erofs");
  assert.equal(typeof warnings[0].message, "string");
});

test("extractContainer rejects inputs below the 512-byte container floor", async () => {
  await assert.rejects(() => openContainer(new Uint8Array(64), "tiny.bin"), /too small/i);
});

// SIDECAR_PATTERNS compile without re.IGNORECASE;
// RFCARD_PATTERN is the only case-insensitive one.
test("sidecar matching is case-sensitive, rfcard candidate matching is not", () => {
  assert.ok(SIDECAR_RES.some((re) => re.test("rf_config_1306_0_0_combos.xml")));
  assert.ok(SIDECAR_RES.some((re) => re.test("rf_config_1306_0_0_combos_v2.txt")));
  assert.ok(SIDECAR_RES.some((re) => re.test("mbn_ota.md5sum")));
  assert.ok(SIDECAR_RES.some((re) => re.test("rfcard_info_all.csv")));
  assert.ok(!SIDECAR_RES.some((re) => re.test("RF_CONFIG_1306_0_0_COMBOS.XML")));
  assert.ok(!SIDECAR_RES.some((re) => re.test("RF_CONFIG_1306_0_0_COMBOS_V2.TXT")));
  assert.ok(!SIDECAR_RES.some((re) => re.test("MBN_OTA.MD5SUM")));
  assert.ok(!SIDECAR_RES.some((re) => re.test("RFCARD_INFO_ALL.CSV")));
  assert.ok(RFCARD_RE.test("RF_CONFIG_1306_0_0.MBN"));
  assert.ok(!RFCARD_RE.test("rf_config_1306_0_0.mbn.txt"));
});

// --- corpus chains in miniature -----------------------------------------------------

test("Motorola wrapper -> sparse -> ext4 chain lands under sparse_<n>/ (golden shape)", async () => {
  const card = strToU8("synthetic rf card bytes");
  const ext4 = buildExt4Tree({
    "/image/modem_pr/rf_config_123_4_5.mbn": card,
    "/image/modem_pr/so/615_0_0.mbn": strToU8("legacy-in-so"),
  });
  // wrap the ext4 in a single-RAW-chunk sparse image (radio.img chunk layout)
  const sparse = new Uint8Array(28 + 12 + ext4.length);
  const dv = new DataView(sparse.buffer);
  dv.setUint32(0, 0xed26ff3a, true);
  dv.setUint16(4, 1, true);
  dv.setUint16(6, 0, true);
  dv.setUint16(8, 28, true);
  dv.setUint16(10, 12, true);
  dv.setUint32(12, 1024, true); // blockSize (unvalidated by the reader)
  const blocks = Math.ceil(ext4.length / 1024);
  dv.setUint32(16, blocks, true);
  dv.setUint32(20, 1, true);
  dv.setUint16(28, 0xcac1, true);
  dv.setUint16(30, 0, true);
  dv.setUint32(32, blocks, true);
  dv.setUint32(36, 12 + ext4.length, true);
  sparse.set(ext4, 40);
  const wrapped = new Uint8Array(13568 + sparse.length);
  wrapped.set([0x53, 0x49, 0x4e, 0x47, 0x4c, 0x45, 0x5f, 0x4e, 0x5f, 0x4c, 0x4f, 0x4e, 0x45, 0x4c, 0x59, 0x00]);
  wrapped.set(sparse, 13568);

  const { outputs, warnings } = await openContainer(wrapped, "radio.img");
  assert.deepEqual(warnings, []);
  const { mbns } = discoverCandidates(outputs);
  const paths = mbns.map((m) => m.path).sort();
  assert.deepEqual(paths, [
    "sparse_1/image/modem_pr/rf_config_123_4_5.mbn",
    "sparse_1/image/modem_pr/so/615_0_0.mbn",
  ]);
  // the golden first-component rule: SCRATCH_DIR_RE eats the workdir id
  assert.equal(normalizeInnerPath(paths[0]), "sparse/image/modem_pr/rf_config_123_4_5.mbn");
  assert.equal(normalizeInnerPath(paths[1]), "sparse/image/modem_pr/so/615_0_0.mbn");
  const card610 = mbns.find((m) => m.path.includes("rf_config_123"));
  assert.deepEqual(await card610.vfile.read(), card);
});

test("tar -> lz4 -> FAT16 chain lands under fat_<n>/ (Samsung miniature)", async () => {
  const card = new Uint8Array(120);
  for (let i = 0; i < card.length; i++) card[i] = (i * 13 + 7) & 0xff;
  const tar = buildUstar([{ name: "modem.bin.lz4", data: lz4FrameAllLiterals(buildFat16Miniature(card)) }]);
  const { outputs, warnings } = await openContainer(tar, "CP_F976.tar.md5");
  assert.deepEqual(warnings, []);
  const { mbns } = discoverCandidates(outputs);
  assert.equal(mbns.length, 1);
  assert.equal(mbns[0].path, "fat_2/image/rf_config_1181_0_306.mbn");
  assert.equal(normalizeInnerPath(mbns[0].path), "fat/image/rf_config_1181_0_306.mbn");
  assert.deepEqual(await mbns[0].vfile.read(), card);
  // Step 7: tar members are now region-backed, so there is no materialized
  // compressed member to release — extractLz4's release() is a no-op and the
  // member stays readable on demand (it was never eagerly read).
  const lz4Member = outputs[0].files().find((f) => f.path.endsWith("modem.bin.lz4")).vfile;
  assert.ok(lz4Member.region, "the tar member must be a zero-copy region");
  assert.deepEqual(await lz4Member.read(), lz4FrameAllLiterals(buildFat16Miniature(card)));
});

// --- zip64 ------------------------------------------------------------------------

// Hand-crafted zip64 (APPNOTE 4.4/4.5): local + central headers carry 0xFFFFFFFF
// sentinels and the real values live in the zip64 extra field (original size,
// then compressed size, then header offset), backed by a zip64 EOCD record +
// locator ahead of the regular EOCD. One stored member.
function buildZip64({ data, entry, forceSentinels = false, flags = 0 }) {
  const u16 = (n) => Uint8Array.of(n & 255, (n >>> 8) & 255);
  const u32 = (n) => Uint8Array.of(n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255);
  const u64 = (n) => {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
    return b;
  };
  const enc = (v) => (forceSentinels || v >= 2 ** 32 ? { sentinel: true, slot: u64(v) } : { sentinel: false, slot: null });
  const un = enc(entry.uncompressed);
  const co = enc(entry.compressed);
  const off = enc(entry.offset);
  const name = strToU8("big.bin");
  // Local header: zip64 writers always place BOTH sizes (sentinel) in the
  // local extra field; the decoder derives dataStart from this extraLen.
  const localExtra = new Uint8Array(20);
  new DataView(localExtra.buffer).setUint16(0, 0x0001, true);
  new DataView(localExtra.buffer).setUint16(2, 16, true);
  localExtra.set(u64(entry.uncompressed), 4);
  localExtra.set(u64(entry.compressed), 12);
  const local = new Uint8Array(30);
  const lv = new DataView(local.buffer);
  lv.setUint32(0, 0x04034b50, true);
  lv.setUint16(4, 45, true);
  lv.setUint16(6, flags, true);
  lv.setUint16(8, 0, true); // method: stored
  lv.setUint32(14, 0, true); // crc (never verified by the decoder)
  lv.setUint32(18, 0xffffffff, true);
  lv.setUint32(22, 0xffffffff, true);
  lv.setUint16(26, name.length, true);
  lv.setUint16(28, localExtra.length, true);
  // Central directory: a zip64 slot exists only when its u32 field is the
  // sentinel (APPNOTE 4.5.3 slot order: original, compressed, offset).
  const slots = [un, co, off].filter((s) => s.sentinel);
  const cdExtra = new Uint8Array(slots.length ? 4 + 8 * slots.length : 0);
  if (slots.length) {
    new DataView(cdExtra.buffer).setUint16(0, 0x0001, true);
    new DataView(cdExtra.buffer).setUint16(2, cdExtra.length - 4, true);
    slots.forEach((s, i) => cdExtra.set(s.slot, 4 + 8 * i));
  }
  const cdSize = 46 + name.length + cdExtra.length;
  const cdOffset = 30 + localExtra.length + name.length + data.length;
  const cd = new Uint8Array(46);
  const cv = new DataView(cd.buffer);
  cv.setUint32(0, 0x02014b50, true);
  cv.setUint16(4, 45, true);
  cv.setUint16(6, 45, true);
  cv.setUint16(8, flags, true);
  cv.setUint16(10, 0, true); // method: stored
  cv.setUint32(16, 0, true); // crc
  cv.setUint32(20, co.sentinel ? 0xffffffff : entry.compressed, true);
  cv.setUint32(24, un.sentinel ? 0xffffffff : entry.uncompressed, true);
  cv.setUint16(28, name.length, true);
  cv.setUint16(30, cdExtra.length, true);
  cv.setUint32(42, off.sentinel ? 0xffffffff : entry.offset, true);
  const z64Offset = cdOffset + cdSize;
  const z64 = new Uint8Array(56);
  const zv = new DataView(z64.buffer);
  zv.setUint32(0, 0x06064b50, true);
  zv.setBigUint64(4, 44n, true);
  zv.setUint16(12, 45, true);
  zv.setUint16(14, 45, true);
  zv.setUint32(16, 0, true);
  zv.setUint32(20, 0, true);
  zv.setBigUint64(24, 1n, true);
  zv.setBigUint64(32, 1n, true);
  zv.setBigUint64(40, BigInt(cdSize), true);
  zv.setBigUint64(48, BigInt(cdOffset), true);
  const locator = new Uint8Array(20);
  const lo = new DataView(locator.buffer);
  lo.setUint32(0, 0x07064b50, true);
  lo.setBigUint64(8, BigInt(z64Offset), true);
  lo.setUint32(16, 1, true);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, 0xffff, true);
  ev.setUint16(10, 0xffff, true);
  ev.setUint32(12, 0xffffffff, true);
  ev.setUint32(16, 0xffffffff, true);
  const total = cdOffset + cdSize + z64.length + locator.length + eocd.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const part of [local, localExtra, name, data, cd, name, cdExtra, z64, locator, eocd]) {
    out.set(part, o);
    o += part.length;
  }
  return out;
}

test("zip64: 0xFFFFFFFF sentinel sizes + APPNOTE-order extra field extract correctly", async () => {
  const data = new Uint8Array(600);
  for (let i = 0; i < data.length; i++) data[i] = (i * 7 + 3) & 0xff;
  const zip = buildZip64({ data, entry: { uncompressed: data.length, compressed: data.length, offset: 0 }, forceSentinels: true });
  const { root, warnings } = await openContainer(zip, "big64.zip");
  assert.deepEqual(warnings, []);
  const files = root.files();
  assert.deepEqual(files.map((f) => f.path), ["zip_0/big.bin"]);
  assert.deepEqual(await files[0].vfile.read(), data);
});

test("zip: encrypted member is skipped with a warning instead of emitting ciphertext", async () => {
  const data = new Uint8Array(600).fill(0x77);
  const zip = buildZip64({ data, entry: { uncompressed: data.length, compressed: data.length, offset: 0 }, flags: 1 });
  const { root, warnings } = await openContainer(zip, "enc.zip");
  assert.deepEqual(root.files(), []);
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0].tool, "zip");
  assert.match(warnings[0].message, /encrypted/i);
});

test("zip: member declaring >=2GiB uncompressed is refused before any read", async () => {
  const data = new Uint8Array(600).fill(0x5a);
  // 2**31 declared uncompressed (no zip64 sentinel needed, it fits a u32):
  // Node's handle.read would overflow on such lengths (native abort), so the
  // guard must refuse it before the data read — now via the whole-buffer cap.
  const zip = buildZip64({ data, entry: { uncompressed: 2 ** 31, compressed: data.length, offset: 0 } });
  const { root, warnings } = await openContainer(zip, "bomb.zip");
  assert.deepEqual(root.files(), []);
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0].tool, "zip");
  assert.match(warnings[0].message, /whole-buffer limit|2GiB/);
});

// --- tar PAX -----------------------------------------------------------------------

// POSIX 1003.1-2001 extended header record: "<len> key=value\n" where len
// counts the digits, the space, the body and the newline.
function paxRecord(key, value) {
  const body = `${key}=${value}\n`;
  let digits = 1;
  for (;;) {
    const total = digits + 1 + body.length;
    if (String(total).length === digits) return `${total} ${key}=${value}\n`;
    digits = String(total).length;
  }
}

test("tar PAX 'x' header: path override applies to the next member", async () => {
  const tar = buildUstar([
    { name: "PaxHeader", data: strToU8(paxRecord("path", "renamed_dir/renamed.bin")), type: "x" },
    { name: "original.bin", data: strToU8("pax-moved") },
  ]);
  const { root, warnings } = await openContainer(tar, "pax.tar");
  assert.deepEqual(warnings, []);
  assert.deepEqual(root.files().map((f) => f.path), ["tar_0/renamed_dir/renamed.bin"]);
  assert.deepEqual(await root.files()[0].vfile.read(), strToU8("pax-moved"));
});

test("tar PAX: per-member 'x' overrides global 'g' path; globals persist", async () => {
  const tar = buildUstar([
    { name: "GlobalHead", data: strToU8(paxRecord("path", "from_g.bin")), type: "g" },
    { name: "PaxHeader", data: strToU8(paxRecord("path", "from_x.bin")), type: "x" },
    { name: "first.bin", data: strToU8("1") },
    { name: "second.bin", data: strToU8("2") },
  ]);
  const { root, warnings } = await openContainer(tar, "pax.tar");
  assert.deepEqual(warnings, []);
  assert.deepEqual(
    root.files().map((f) => f.path).sort(),
    ["tar_0/from_g.bin", "tar_0/from_x.bin"],
  );
});

// --- tar header tolerance -----------------------------------------------------------

test("tar size field with leading spaces parses like tarfile.nti", async () => {
  // Python: nts() strips NULs, then int(s.strip(), 8) - so "  1200" + NULs is
  // 640, while a byte-position parser that breaks at the first space reads 0.
  const tar = buildUstar([{ name: "spaced.bin", data: strToU8("x".repeat(640)) }]);
  const sizeField = strToU8("  1200");
  tar.set(sizeField, 124);
  tar.fill(0, 124 + sizeField.length, 136);
  const { root, warnings } = await openContainer(tar, "spaced.tar");
  assert.deepEqual(warnings, []);
  const files = root.files();
  assert.deepEqual(files.map((f) => f.path), ["tar_0/spaced.bin"]);
  assert.equal(files[0].vfile.size, 640);
});

// --- header sniffing (Step 1: ranged readers never materialize a tree file) -----

test("headOf prefers a ranged reader over the full-file loader", async () => {
  const size = 0x4000;
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i++) bytes[i] = (i * 5 + 1) & 0xff;
  let fullLoads = 0;
  let rangeCalls = 0;
  const vfile = new VFile(
    "tree.bin",
    () => {
      fullLoads += 1;
      return bytes;
    },
    size,
    null,
    async (offset, length) => {
      rangeCalls += 1;
      assert.equal(offset, 0);
      return bytes.subarray(offset, offset + length);
    },
  );
  const head = await headOf(vfile);
  assert.equal(head.length, 4096);
  assert.deepEqual(head, bytes.subarray(0, 4096));
  assert.equal(rangeCalls, 1, "the ranged reader must serve the sniff");
  assert.equal(fullLoads, 0, "the whole-file loader must not run for a header sniff");
});

test("headOf falls back to a region window and then to the whole-file loader", async () => {
  const size = 8192;
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i++) bytes[i] = i & 0xff;
  const base = {
    size,
    async read(offset, length) {
      return bytes.subarray(offset, offset + length);
    },
  };
  const regionFile = VFile.slice("region.bin", base, 1024, 4096);
  assert.deepEqual(await headOf(regionFile), bytes.subarray(1024, 1024 + 4096));

  const small = VFile.mem("small.bin", bytes.subarray(0, 100));
  assert.deepEqual(await headOf(small), bytes.subarray(0, 100));
});

// --- large-archive handling (Step 7) --------------------------------------------

test("tar members are zero-copy regions of the archive source", async () => {
  const payload = strToU8("rf_config_1306_0_0.mbn-contents");
  const tar = buildUstar([{ name: "nested/rf_config_1306_0_0.mbn", data: payload }]);
  const { root, warnings } = await openContainer(tar, "archive.tar");
  assert.deepEqual(warnings, []);
  const files = root.files();
  assert.equal(files.length, 1);
  const vfile = files[0].vfile;
  assert.ok(vfile.region, "tar members must stay region-backed (no eager materialization)");
  assert.equal(vfile.size, payload.length);
  assert.deepEqual(await vfile.read(), payload);
  // release() is a no-op for region-backed files: the bytes stay readable.
  vfile.release();
  assert.deepEqual(await vfile.read(), payload);
});

test("oversized whole-buffer containers warn instead of throwing", async () => {
  const { gzipSync } = await import("node:zlib");
  const gz = gzipSync(randomBytes(2000)); // incompressible -> > MIN_CONTAINER_SIZE
  // Compressed input over the limit: the gzip member is skipped with a warning.
  const skipped = await extractContainer(new BrowserFileSource(new Blob([gz])), "big.gz", { wholeBufferLimit: 4 });
  assert.equal(skipped.outputs.length, 0);
  assert.ok(
    skipped.warnings.some((w) => w.tool === "gzip" && /whole-buffer limit/.test(w.message)),
    JSON.stringify(skipped.warnings),
  );
  // Compressed input is fine but the decompressed output is over the limit: the
  // capped stream reader aborts it as a decompress failure, not a crash.
  const block = randomBytes(700);
  const payload = Buffer.alloc(100000);
  for (let i = 0; i < payload.length; i += block.length) block.copy(payload, i);
  const bomb = gzipSync(payload);
  assert.ok(bomb.length >= 512, "the compressed input must pass the container floor");
  const capped = await extractContainer(new BrowserFileSource(new Blob([bomb])), "bomb.gz", { wholeBufferLimit: bomb.length });
  assert.equal(capped.outputs.length, 0);
  assert.ok(
    capped.warnings.some((w) => w.tool === "gzip" && /exceeds|failed/.test(w.message)),
    JSON.stringify(capped.warnings),
  );
  // Default limit: the same input extracts normally.
  const ok = await openContainer(gz, "small.gz");
  assert.deepEqual(ok.warnings, []);
  assert.ok(ok.root.files().length >= 1, "the gzip output file must exist");
});
