// MTK container unwrapping tests (Stage A): synthetic fixtures — hand-rolled
// MTK-partition containers, gzip members, HBLR, Android sparse, a tiny ext4
// image, budget/limit violations and role/set-completion errors. All
// corpus-independent.
import test from "node:test";
import assert from "node:assert/strict";
import { gzipSync, gunzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import {
  unwrapBytes,
  Limits,
  UnwrapError,
  role,
  kindOf,
} from "../js/lib/mtk_containers.js";
import { crc32 } from "../js/lib/mtk_hash.js";

const sha256Hex = (u8) => createHash("sha256").update(u8).digest("hex");

function fill(len, seed) {
  const a = new Uint8Array(len);
  let s = seed >>> 0;
  for (let i = 0; i < len; i++) {
    s = (Math.imul(s, 1103515245) + 12345) >>> 0;
    a[i] = s >>> 24;
  }
  return a;
}

function concatParts(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

const u32le = (n) => {
  const a = new Uint8Array(4);
  new DataView(a.buffer).setUint32(0, n, true);
  return a;
};

// One 512-byte header block (<II32s10I> with mirror magic fields[5] and data
// offset fields[6] = 512) followed by the member data, per MTK partition member.
function mtkPartition(members) {
  const parts = [];
  for (const { name, data, dataOffset = 512, sizeHi = 0 } of members) {
    const header = new Uint8Array(Math.max(dataOffset, 80));
    header[0] = 0x88; header[1] = 0x16; header[2] = 0x88; header[3] = 0x58;
    const dv = new DataView(header.buffer);
    dv.setUint32(4, data.length, true);
    for (let i = 0; i < name.length; i++) header[8 + i] = name.charCodeAt(i) & 0x7f;
    dv.setUint32(48, 0x58891689, true);
    dv.setUint32(52, dataOffset, true);
    dv.setUint32(72, sizeHi, true);
    parts.push(header, data);
  }
  return concatParts(parts);
}

// HBLR: 64-byte header ("HBLR", u32 total size at 4, u32 count at 48),
// 48-byte SEGM records ("SEGM", name[32], src, logical, stored), payload data.
function hblrContainer(segments) {
  const start = 64 + segments.length * 48;
  let src = start;
  const records = [];
  for (const seg of segments) {
    records.push({ ...seg, src });
    src += seg.stored;
  }
  const total = src;
  const buf = new Uint8Array(total);
  buf.set([0x48, 0x42, 0x4c, 0x52]); // HBLR
  const dv = new DataView(buf.buffer);
  dv.setUint32(4, total, true);
  dv.setUint32(48, segments.length, true);
  for (let i = 0; i < records.length; i++) {
    const off = 64 + i * 48;
    buf.set([0x53, 0x45, 0x47, 0x4d], off); // SEGM
    const { name, logical, stored, payload } = records[i];
    for (let j = 0; j < name.length; j++) buf[off + 4 + j] = name.charCodeAt(j) & 0x7f;
    dv.setUint32(off + 36, records[i].src, true);
    dv.setUint32(off + 40, logical, true);
    dv.setUint32(off + 44, stored, true);
    buf.set(payload.subarray(0, logical), records[i].src);
  }
  return { buf, records, dv };
}

// Android sparse: 28-byte header + chunks (12-byte chunk header + payload).
function sparseImage(block, outBlocks, chunkSpecs, checksum) {
  // chunkSpecs: [{ kind, nblocks, payload }] — payload already sized.
  const header = new Uint8Array(28);
  const dv = new DataView(header.buffer);
  dv.setUint32(0, 0xed26ff3a, true);
  dv.setUint16(4, 1, true); // major
  dv.setUint16(6, 0, true); // minor
  dv.setUint16(8, 28, true); // file header len
  dv.setUint16(10, 12, true); // chunk header len
  dv.setUint32(12, block, true);
  dv.setUint32(16, outBlocks, true);
  dv.setUint32(20, chunkSpecs.length, true);
  dv.setUint32(24, checksum ?? 0, true);
  const parts = [header];
  for (const c of chunkSpecs) {
    const chunkHeader = new Uint8Array(12);
    const cdv = new DataView(chunkHeader.buffer);
    cdv.setUint16(0, c.kind, true);
    cdv.setUint32(4, c.nblocks, true);
    cdv.setUint32(8, 12 + c.payload.length, true);
    parts.push(chunkHeader, c.payload);
  }
  return concatParts(parts);
}

// Tiny but real ext4: 8 KiB, one group, root dir with md1rom + md1drdi files.
// Layout: block 1 superblock, block ~1 group descriptors, blocks 2-3 inode
// table, block 4 root directory, blocks 5-6 file data.
function buildExt4({ incompat = 0x42, inodeSize = 128, blockSizeExp = 0, romFlags = 0x80000 } = {}) {
  const block = 1024 << blockSizeExp;
  const total = 8 * block;
  const buf = new Uint8Array(total);
  const dv = new DataView(buf.buffer);
  const SB = 1024;
  dv.setUint32(SB + 0, 16, true); // inodes count
  dv.setUint32(SB + 4, 8, true); // blocks count
  dv.setUint32(SB + 20, 0, true); // first data block -> gdt = 1 * block
  dv.setUint32(SB + 24, blockSizeExp, true);
  dv.setUint32(SB + 40, 16, true); // inodes per group
  dv.setUint16(SB + 56, 0xef53, true); // magic at 1080
  dv.setUint16(SB + 88, inodeSize, true);
  dv.setUint32(SB + 96, incompat, true);
  dv.setUint32(1024 + 8, 2, true); // group descriptor: inode table block 2
  const INO = (n) => 2048 + (n - 1) * inodeSize;
  const setExtentFile = (n, size, dataBlock) => {
    dv.setUint16(INO(n), 0x8000, true);
    dv.setUint32(INO(n) + 4, size, true);
    dv.setUint32(INO(n) + 32, 0x80000, true);
    dv.setUint16(INO(n) + 40, 0xf30a, true);
    dv.setUint16(INO(n) + 42, 1, true);
    dv.setUint16(INO(n) + 44, 4, true);
    dv.setUint16(INO(n) + 46, 0, true);
    dv.setUint32(INO(n) + 52, 0, true);
    dv.setUint16(INO(n) + 56, 1, true);
    dv.setUint16(INO(n) + 58, 0, true);
    dv.setUint32(INO(n) + 60, dataBlock, true);
  };
  // inode 2: root directory with one extent -> block 4.
  dv.setUint16(INO(2), 0x4000, true);
  dv.setUint32(INO(2) + 4, block, true);
  dv.setUint32(INO(2) + 32, 0x80000, true);
  dv.setUint16(INO(2) + 40, 0xf30a, true);
  dv.setUint16(INO(2) + 42, 1, true);
  dv.setUint16(INO(2) + 44, 4, true);
  dv.setUint16(INO(2) + 46, 0, true);
  dv.setUint32(INO(2) + 52, 0, true);
  dv.setUint16(INO(2) + 56, 1, true);
  dv.setUint16(INO(2) + 58, 0, true);
  dv.setUint32(INO(2) + 60, 4, true);
  setExtentFile(3, 8, 5);
  setExtentFile(4, 16, 6);
  // root directory block
  let pos = 4 * block;
  // ext2/4 directory entry: inode u32, rec_len u16, name_len u8 @+6,
  // file_type u8 @+7 (incompat filetype), name @+8.
  const dirEntry = (ino, name, rec, filetype) => {
    dv.setUint32(pos, ino, true);
    dv.setUint16(pos + 4, rec, true);
    buf[pos + 6] = name.length;
    buf[pos + 7] = filetype;
    for (let i = 0; i < name.length; i++) buf[pos + 8 + i] = name.charCodeAt(i);
    pos += rec;
  };
  dirEntry(2, ".", 12, 2);
  dirEntry(2, "..", 12, 2);
  dirEntry(3, "md1rom", 16, 1);
  dirEntry(4, "md1drdi", block - 40, 1);
  buf.set([0x4d, 0x44, 0x31, 0x52, 0x4f, 0x4d, 0x21, 0x21], 5 * block); // "MD1ROM!!"
  buf.set(fill(16, 9), 6 * block);
  if (romFlags === 0) dv.setUint32(INO(3) + 32, 0, true);
  return buf;
}

const expectUnwrapError = async (data, message, name = "image", limits = undefined, hooks = undefined) => {
  await assert.rejects(
    () => unwrapBytes(data, name, limits, hooks),
    (e) => {
      assert.ok(e instanceof UnwrapError, `expected UnwrapError, got ${e?.constructor?.name}: ${e?.message}`);
      assert.equal(e.message, message);
      assert.ok(e.report, "UnwrapError carries the report");
      return true;
    },
  );
};

test("mtk containers: role token regex boundary semantics", () => {
  assert.equal(role("md1rom"), "md1rom");
  assert.equal(role("MD1ROM.bin"), "md1rom");
  assert.equal(role("md1drdi_data_1"), "md1drdi_data");
  assert.equal(role("x.md1drdi_hdr.y"), "md1drdi_hdr");
  assert.equal(role("/a/b/md1drdi.gz"), "md1drdi");
  assert.equal(role("cert1md"), null);
  assert.equal(role("md1dsp"), null);
  assert.equal(role("md1_mddbmetaodb"), null);
  assert.equal(role("sub/md1rom/md1rom"), "md1rom");
});

test("mtk containers: kind sniffing", () => {
  assert.equal(kindOf(new Uint8Array([0x3a, 0xff, 0x26, 0xed, 0, 0, 0, 0])), "android-sparse");
  assert.equal(kindOf(new Uint8Array([0x1f, 0x8b, 8, 0])), "gzip");
  assert.equal(kindOf(new Uint8Array([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])), "xz");
  assert.equal(kindOf(new Uint8Array([0x48, 0x42, 0x4c, 0x52])), "hblr");
  assert.equal(kindOf(new Uint8Array([0x88, 0x16, 0x88, 0x58])), "mtk");
  assert.equal(kindOf(new Uint8Array(1082).fill(0).map((b, i) => (i === 1080 ? 0x53 : i === 1081 ? 0xef : b))), "ext4");
  assert.equal(kindOf(new Uint8Array([1, 2, 3])), null);
});

test("mtk containers: mtk partition -> gzip -> mtk partition unwraps fully with report", async () => {
  const rom = fill(4096, 1);
  const drdi = fill(2048, 2);
  const inner = mtkPartition([{ name: "md1rom", data: rom }, { name: "md1drdi", data: drdi }]);
  const gz = new Uint8Array(gzipSync(inner));
  const outer = mtkPartition([{ name: "inner", data: gz }]);
  const parts = await unwrapBytes(outer, "image");
  assert.deepEqual(parts.report.layers.map((l) => l.format), ["mtk", "gzip", "mtk"]);
  assert.equal(parts.report.packaging, "single-drdi");
  assert.equal(parts.report.identical_sets, 1);
  assert.equal(parts.rom.length, rom.length);
  assert.equal(parts.drdi.length, drdi.length);
  assert.ok(Buffer.from(parts.rom).equals(rom));
  assert.ok(Buffer.from(parts.drdi).equals(drdi));
  assert.equal(parts.drdi_data, null);
  assert.deepEqual(parts.report.partial_sets, []);
  assert.deepEqual(parts.report.candidate_sets, [{
    sources: ["image!/inner!/gzip"],
    sha256: { md1drdi: sha256Hex(drdi), md1rom: sha256Hex(rom) },
  }]);
  assert.deepEqual(parts.report.selected, {
    md1rom: { bytes: rom.length, sha256: sha256Hex(rom), sources: ["image!/inner!/gzip!/md1rom"] },
    md1drdi: { bytes: drdi.length, sha256: sha256Hex(drdi), sources: ["image!/inner!/gzip!/md1drdi"] },
  });
  assert.equal(parts.report.processed_bytes, outer.length + gz.length + inner.length + rom.length + drdi.length);
  assert.deepEqual(parts.report.input, { source: "image", bytes: outer.length, sha256: sha256Hex(outer) });
});

test("mtk containers: role-named gzip member captures the expanded role", async () => {
  const rom = fill(1024, 3);
  const drdi = fill(512, 4);
  const outer = mtkPartition([
    { name: "md1drdi", data: new Uint8Array(gzipSync(drdi)) },
    { name: "md1rom", data: rom },
  ]);
  const parts = await unwrapBytes(outer, "image");
  assert.deepEqual(parts.report.layers.map((l) => l.format), ["mtk", "gzip"]);
  assert.ok(Buffer.from(parts.drdi).equals(drdi));
  assert.deepEqual(parts.report.selected.md1drdi.sources, ["image!/md1drdi!/gzip"]);
  assert.deepEqual(parts.report.selected.md1rom.sources, ["image!/md1rom"]);
});

test("mtk containers: gzip strictness (trailing data, multi-member, truncated)", async () => {
  const payload = fill(512, 5);
  const member = new Uint8Array(gzipSync(payload));
  const build = (data) => mtkPartition([{ name: "md1drdi", data }, { name: "md1rom", data: fill(64, 6) }]);
  await expectUnwrapError(
    build(concatParts([member, new Uint8Array([0x4a, 0x55, 0x4e, 0x4b])])),
    "trailing data/multiple streams in gzip wrapper",
  );
  await expectUnwrapError(
    build(concatParts([member, member])),
    "trailing data/multiple streams in gzip wrapper",
  );
  await expectUnwrapError(build(member.subarray(0, member.length - 5)), "truncated or oversized gzip stream");
  await expectUnwrapError(build(new Uint8Array([0x1f, 0x8b])), "truncated or oversized gzip stream");
  // A clean single member passes strictness.
  const parts = await unwrapBytes(build(member), "image");
  assert.ok(Buffer.from(parts.drdi).equals(payload));
});

test("mtk containers: inflateGzip hook seam accepts an injected implementation", async () => {
  const payload = fill(256, 7);
  const member = new Uint8Array(gzipSync(payload));
  const outer = mtkPartition([{ name: "md1drdi", data: member }, { name: "md1rom", data: fill(32, 8) }]);
  const zlibHook = async (bytes, maximum) => {
    assert.ok(maximum > 0);
    return { out: new Uint8Array(gunzipSync(bytes)), eof: true, unusedData: false };
  };
  const parts = await unwrapBytes(outer, "image", new Limits(), { inflateGzip: zlibHook });
  assert.ok(Buffer.from(parts.drdi).equals(payload));
  const strictHook = async () => ({ out: payload, eof: true, unusedData: true });
  await expectUnwrapError(outer, "trailing data/multiple streams in gzip wrapper", "image", new Limits(), { inflateGzip: strictHook });
});

test("mtk containers: HBLR valid container, roundup16 padding, overlap and size rejects", async () => {
  const rom = fill(16, 11);
  const drdi = fill(33, 12);
  const good = hblrContainer([
    { name: "md1rom", logical: 16, stored: 16, payload: rom },
    { name: "md1drdi", logical: 33, stored: 48, payload: drdi }, // stored == roundup16(33)
  ]);
  const parts = await unwrapBytes(good.buf, "h");
  assert.ok(Buffer.from(parts.rom).equals(rom));
  assert.ok(Buffer.from(parts.drdi).equals(drdi));
  assert.deepEqual(parts.report.layers[0].members, [
    { name: "md1rom", offset: good.records[0].src, bytes: 16, stored_bytes: 16, padding_bytes: 0 },
    { name: "md1drdi", offset: good.records[1].src, bytes: 33, stored_bytes: 48, padding_bytes: 15 },
  ]);
  // Overlap: point the second segment back into the first one's span.
  const overlapped = hblrContainer([
    { name: "md1rom", logical: 16, stored: 16, payload: rom },
    { name: "md1drdi", logical: 33, stored: 48, payload: drdi },
  ]);
  overlapped.dv.setUint32(64 + 48 + 36, good.records[1].src - 4, true);
  await expectUnwrapError(overlapped.buf, "overlapping HBLR segments", "h");
  // stored=40 is neither logical (33) nor roundup16(33)=48.
  const badRoundup = hblrContainer([
    { name: "md1rom", logical: 16, stored: 16, payload: rom },
    { name: "md1drdi", logical: 33, stored: 40, payload: drdi },
  ]);
  await expectUnwrapError(badRoundup.buf, "unsupported HBLR segment size relationship: md1drdi", "h");
  const badSize = hblrContainer([
    { name: "md1rom", logical: 16, stored: 16, payload: rom },
    { name: "md1drdi", logical: 33, stored: 48, payload: drdi },
  ]);
  badSize.dv.setUint32(4, badSize.buf.length + 1, true);
  await expectUnwrapError(badSize.buf, "HBLR declared size mismatch", "h");
});

test("mtk containers: android sparse CAC1/CAC2/CAC4 with CRC verification", async () => {
  const block = 4;
  const raw = new Uint8Array([1, 2, 3, 4]);
  const fillValue = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
  // First pass: compute the running CRC the way the parser does.
  const out = new Uint8Array(12);
  out.set(raw, 0);
  let crc = crc32(out.subarray(0, 4));
  for (let o = 4; o < 12; o += 4) { out.set(fillValue, o); }
  crc = crc32(out.subarray(4, 12), crc) >>> 0;
  const image = sparseImage(block, 3, [
    { kind: 0xcac1, nblocks: 1, payload: raw },
    { kind: 0xcac2, nblocks: 2, payload: fillValue },
    { kind: 0xcac4, nblocks: 0, payload: u32le(crc) },
  ], crc);
  const outer = mtkPartition([{ name: "md1rom", data: image }, { name: "md1drdi", data: fill(8, 13) }]);
  const parts = await unwrapBytes(outer, "image");
  assert.deepEqual(parts.report.layers.map((l) => l.format), ["mtk", "android-sparse"]);
  assert.ok(Buffer.from(parts.rom).equals(out));
  // Corrupt chunk CRC.
  const badChunk = sparseImage(block, 3, [
    { kind: 0xcac1, nblocks: 1, payload: raw },
    { kind: 0xcac2, nblocks: 2, payload: fillValue },
    { kind: 0xcac4, nblocks: 0, payload: u32le(crc ^ 1) },
  ], 0);
  await expectUnwrapError(badChunk, "Android sparse chunk CRC32 mismatch", "s");
  // Corrupt image-level checksum.
  const badImage = sparseImage(block, 3, [
    { kind: 0xcac1, nblocks: 1, payload: raw },
    { kind: 0xcac2, nblocks: 2, payload: fillValue },
    { kind: 0xcac4, nblocks: 0, payload: u32le(crc) },
  ], crc ^ 0xff);
  await expectUnwrapError(badImage, "Android sparse image CRC32 mismatch", "s");
  // CAC1 payload length must match the block span.
  const badRaw = sparseImage(block, 3, [
    { kind: 0xcac1, nblocks: 1, payload: new Uint8Array(3) },
  ], 0);
  await expectUnwrapError(badRaw, "unsupported/malformed sparse chunk 0xcac1", "s");
  await expectUnwrapError(sparseImage(block, 3, []).subarray(0, 20), "truncated Android sparse header", "s");
});

test("mtk containers: ext4 extent walk recovers role-named files from a tiny filesystem", async () => {
  const fs = buildExt4();
  const parts = await unwrapBytes(fs, "fs.img");
  assert.deepEqual(parts.report.layers.map((l) => l.format), ["ext4"]);
  assert.equal(parts.report.layers[0].metadata_checksums_verified, false);
  assert.ok(Buffer.from(parts.rom).equals(new Uint8Array([0x4d, 0x44, 0x31, 0x52, 0x4f, 0x4d, 0x21, 0x21])));
  assert.equal(parts.drdi.length, 16);
  assert.equal(parts.report.packaging, "single-drdi");
  assert.deepEqual(parts.report.selected.md1rom.sources, ["fs.img!/md1rom"]);
  assert.deepEqual(parts.report.selected.md1drdi.sources, ["fs.img!/md1drdi"]);
});

test("mtk containers: ext4 superblock validation rejects", async () => {
  const badIncompat = buildExt4({ incompat: 0x42 | 0x20000 });
  await expectUnwrapError(badIncompat, "unsupported ext4 incompat features 0x20000", "f");
  const badInodeSize = buildExt4({ inodeSize: 100 });
  await expectUnwrapError(badInodeSize, "invalid ext4 inode/group descriptor geometry", "f");
  const badBlockSize = buildExt4({ blockSizeExp: 6 });
  await expectUnwrapError(badBlockSize, "unsupported ext4 block size (maximum 32 KiB)", "f");
  const truncated = new Uint8Array(1082);
  truncated[1080] = 0x53;
  truncated[1081] = 0xef;
  await expectUnwrapError(truncated, "truncated ext4 superblock", "f");
  // File inode without the extents flag and nonzero size.
  const noExtents = buildExt4({ romFlags: 0 });
  await expectUnwrapError(noExtents, "ext4 inode needs extents; inline/indirect blocks are unsupported", "f");
});

test("mtk containers: byte budgets, entry and depth limits", async () => {
  const data = fill(2048, 14);
  await expectUnwrapError(
    data,
    "unwrapping byte limit exceeded (requested 2048 bytes)",
    "x",
    new Limits({ maxLayerBytes: 1024 }),
  );
  // Entry limit: more MTK members than max_entries allows.
  const members = [];
  for (let i = 0; i < 10; i++) members.push({ name: `part${i}`, data: fill(8, 20 + i) });
  await expectUnwrapError(
    mtkPartition(members),
    "unwrapping entry limit exceeded",
    "x",
    new Limits({ maxEntries: 8 }),
  );
  // Depth limit: nested gzip beyond maxDepth.
  let nested = fill(64, 30);
  for (let i = 0; i < 4; i++) nested = new Uint8Array(gzipSync(nested));
  await expectUnwrapError(
    nested,
    "unwrapping depth limit exceeded",
    "x",
    new Limits({ maxDepth: 2 }),
  );
  assert.throws(() => new Limits({ maxLayerBytes: 0 }), /all unwrapping limits must be positive/);
});

test("mtk containers: set-completion errors", async () => {
  const romA = fill(128, 40);
  const drdiA = fill(64, 41);
  const romB = fill(128, 42);
  const drdiB = fill(64, 43);
  await expectUnwrapError(
    mtkPartition([{ name: "other", data: romA }]),
    "no complete modem set found (need md1rom and md1drdi, or md1rom and both split-CDF parts)",
  );
  let partial = null;
  try {
    await unwrapBytes(mtkPartition([{ name: "md1rom", data: romA }]), "image");
  } catch (e) {
    partial = e;
  }
  assert.ok(partial instanceof UnwrapError, `expected UnwrapError, got ${partial?.constructor?.name}: ${partial?.message}`);
  assert.deepEqual(partial.report.partial_sets, [{ source: "image", parts: ["md1rom"] }]);
  await expectUnwrapError(
    mtkPartition([
      { name: "a", data: mtkPartition([{ name: "md1rom", data: romA }, { name: "md1drdi", data: drdiA }]) },
      { name: "b", data: mtkPartition([{ name: "md1rom", data: romB }, { name: "md1drdi", data: drdiB }]) },
    ]),
    "2 different modem sets found; pass the intended image or parts directory explicitly",
  );
  await expectUnwrapError(
    mtkPartition([
      { name: "md1rom", data: romA },
      { name: "md1drdi", data: drdiA },
      { name: "md1drdi_hdr", data: fill(32, 44) },
    ]),
    "both flat and split DRDI parts present in image",
  );
  await expectUnwrapError(
    mtkPartition([
      { name: "md1rom", data: romA },
      { name: "md1rom", data: romB },
      { name: "md1drdi", data: drdiA },
    ]),
    "conflicting md1rom parts in image",
  );
  // Two byte-identical sets collapse into one with identical_sets = 2.
  const twin = mtkPartition([{ name: "md1rom", data: romA }, { name: "md1drdi", data: drdiA }]);
  const doubled = mtkPartition([
    { name: "a", data: twin },
    { name: "b", data: twin },
  ]);
  const parts = await unwrapBytes(doubled, "image");
  assert.equal(parts.report.identical_sets, 2);
  assert.equal(parts.report.candidate_sets.length, 1);
});

test("mtk containers: xz layers are refused at the sniff site", async () => {
  const xz = new Uint8Array([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 1, 2, 3, 4]);
  await expectUnwrapError(xz, "xz layer not supported in webapp", "x");
  const wrapped = mtkPartition([{ name: "md1drdi", data: xz }, { name: "md1rom", data: fill(16, 50) }]);
  await expectUnwrapError(wrapped, "xz layer not supported in webapp", "x");
});

test("mtk containers: invalid MTK partition headers are rejected with offsets", async () => {
  const bad = mtkPartition([{ name: "md1rom", data: fill(16, 51), dataOffset: 8 }]);
  await expectUnwrapError(bad, "invalid/truncated MTK partition at 0x0", "x");
});

test("mtk containers: crc32 matches the standard check vector", () => {
  const ascii = (s) => new Uint8Array([...s].map((c) => c.charCodeAt(0)));
  assert.equal(crc32(ascii("123456789")), 0xcbf43926);
  assert.equal(crc32(new Uint8Array(0)), 0);
  assert.equal(crc32(ascii("56789"), crc32(ascii("1234"))), crc32(ascii("123456789")));
});
