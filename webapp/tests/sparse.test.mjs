// Android sparse image layer: header parse/validate, chunk-table SparseReader
// (never materializes the unsparsed image), and the embedded-container scan
// (incl. the Motorola SINGLE_N_LONELY wrapper).
//
// Chunk header layout was decoded empirically from corpus radio.img (12 chunks,
// block sum == totalBlocks == 101120): <HHII> type/reserved/output-blocks/
// total-size-including-12-byte-header, data at +12.
import { test } from "node:test";
import assert from "node:assert/strict";
import { BrowserFileSource } from "../js/lib/source.js";
import {
  parseSparseHeader,
  validSparseHeader,
  SparseReader,
  scanForSparse,
} from "../js/lib/sparse.js";
import { CORPUS_DIR, corpusAvailable } from "./helpers.mjs";

// --- builders -----------------------------------------------------------------

// <IHHHHIIII> file header: magic, major, minor, fileHdrSz, chunkHdrSz,
// blockSize, totalBlocks, totalChunks (all LE), then the image checksum.
function buildSparseHeader({ blocks, chunkCount, blockSize, major = 1, minor = 0, fileHdrSz = 28, chunkHdrSz = 12 }) {
  const h = new Uint8Array(28);
  const dv = new DataView(h.buffer);
  dv.setUint32(0, 0xed26ff3a, true); // LE bytes 3a ff 26 ed
  dv.setUint16(4, major, true);
  dv.setUint16(6, minor, true);
  dv.setUint16(8, fileHdrSz, true);
  dv.setUint16(10, chunkHdrSz, true);
  dv.setUint32(12, blockSize, true);
  dv.setUint32(16, blocks, true);
  dv.setUint32(20, chunkCount, true);
  return h;
}

// chunks: [{ type, blocks, data?, fill? }] per the radio.img layout.
function buildSparseImage({ blockSize, chunks }) {
  const totalBlocks = chunks.reduce((n, c) => n + c.blocks, 0);
  const parts = [buildSparseHeader({ blocks: totalBlocks, chunkCount: chunks.length, blockSize })];
  for (const c of chunks) {
    const hdr = new Uint8Array(12);
    const dv = new DataView(hdr.buffer);
    dv.setUint16(0, c.type, true);
    dv.setUint16(2, 0, true);
    dv.setUint32(4, c.blocks, true);
    const dataLen = c.type === 0xcac1 || c.type === 0xcac2 ? c.blocks * blockSize : c.type === 0xcac3 ? 0 : 4;
    dv.setUint32(8, 12 + dataLen, true);
    parts.push(hdr);
    if (c.type === 0xcac1 || c.type === 0xcac2) {
      const data = new Uint8Array(c.blocks * blockSize);
      if (c.data) data.set(c.data.subarray(0, Math.min(c.data.length, data.length)));
      for (let i = 0; i < data.length; i++) if (data[i] === 0) data[i] = (i * 7 + 3) & 0xff; // non-zero filler
      parts.push(data);
    } else if (c.type === 0xcac4) {
      parts.push(new Uint8Array(new Uint32Array([c.fill]).buffer));
    }
  }
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function buildMotorolaWrapper(sparseOffset, sparseBytes) {
  const out = new Uint8Array(sparseOffset + sparseBytes.length);
  out.set([0x53, 0x49, 0x4e, 0x47, 0x4c, 0x45, 0x5f, 0x4e, 0x5f, 0x4c, 0x4f, 0x4e, 0x45, 0x4c, 0x59, 0x00]); // SINGLE_N_LONELY\0
  out.set(sparseBytes, sparseOffset);
  return out;
}

// Expected bytes of a buildSparseImage result (unsparsed reference).
function sparseReference({ blockSize, chunks }) {
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.blocks * blockSize, 0));
  let off = 0;
  for (const c of chunks) {
    const span = c.blocks * blockSize;
    if (c.type === 0xcac1 || c.type === 0xcac2) {
      const data = new Uint8Array(span);
      if (c.data) data.set(c.data.subarray(0, Math.min(c.data.length, span)));
      for (let i = 0; i < span; i++) if (data[i] === 0) data[i] = (i * 7 + 3) & 0xff;
      out.set(data, off);
    } else if (c.type === 0xcac4) {
      const dv = new DataView(new Uint8Array(4).buffer);
      dv.setUint32(0, c.fill, true);
      for (let i = 0; i < span; i++) out[off + i] = dv.getUint8(i % 4);
    } // dont-care stays zero
    off += span;
  }
  return out;
}

// --- header parse/validate ------------------------------------------------------

test("sparse header parse (plan case)", () => {
  const hdr = buildSparseHeader({ blocks: 100, chunkCount: 2, blockSize: 4096 });
  const h = parseSparseHeader(hdr);
  assert.equal(h.blockSize, 4096);
  assert.equal(h.totalChunks, 2);
  assert.equal(h.totalBlocks, 100);
  assert.equal(h.major, 1);
  assert.equal(h.minor, 0);
  assert.equal(h.fileHdrSz, 28);
  assert.equal(h.chunkHdrSz, 12);
});

test("sparse header validation mirrors _sparse_headers :197-206", () => {
  assert.ok(validSparseHeader(parseSparseHeader(buildSparseHeader({ blocks: 1, chunkCount: 1, blockSize: 512 }))));
  for (const bs of [1024, 2048, 4096, 8192, 16384, 32768]) {
    assert.ok(validSparseHeader(parseSparseHeader(buildSparseHeader({ blocks: 1, chunkCount: 1, blockSize: bs }))), bs);
  }
  assert.ok(!validSparseHeader(parseSparseHeader(buildSparseHeader({ blocks: 1, chunkCount: 1, blockSize: 256 }))));
  assert.ok(!validSparseHeader(parseSparseHeader(buildSparseHeader({ blocks: 0, chunkCount: 1, blockSize: 4096 }))));
  assert.ok(!validSparseHeader(parseSparseHeader(buildSparseHeader({ blocks: 1, chunkCount: 0, blockSize: 4096 }))));
  assert.ok(!validSparseHeader(parseSparseHeader(buildSparseHeader({ blocks: 1, chunkCount: 1, blockSize: 4096, major: 2 }))));
  assert.ok(!validSparseHeader(parseSparseHeader(buildSparseHeader({ blocks: 1, chunkCount: 1, blockSize: 4096, minor: 1 }))));
  assert.ok(!validSparseHeader(parseSparseHeader(buildSparseHeader({ blocks: 1, chunkCount: 1, blockSize: 4096, fileHdrSz: 32 }))));
  assert.ok(!validSparseHeader(parseSparseHeader(buildSparseHeader({ blocks: 1, chunkCount: 1, blockSize: 4096, chunkHdrSz: 16 }))));
});

// --- SINGLE_N_LONELY / scan -----------------------------------------------------

test("SINGLE_N_LONELY offset (plan case)", async () => {
  const sparse = buildSparseImage({ blockSize: 4096, chunks: [{ type: 0xcac1, blocks: 2 }] });
  const wrapped = buildMotorolaWrapper(13568, sparse);
  const src = new BrowserFileSource(new Blob([wrapped]));
  assert.deepEqual(await scanForSparse(src, wrapped.length), [13568]);
});

test("scanForSparse finds headers at byte-unaligned offsets", async () => {
  const sparse = buildSparseImage({ blockSize: 4096, chunks: [{ type: 0xcac1, blocks: 1 }] });
  const prefix = new Uint8Array([0xde, 0xad, 0xbe]); // magic would start at offset 3, unaligned to 4
  const image = concat([prefix, sparse]);
  const src = new BrowserFileSource(new Blob([image]));
  assert.deepEqual(await scanForSparse(src, image.length, 8), [3]);
});

test("scanForSparse reports all valid offsets, capped at 8, skipping invalid headers", async () => {
  const good = buildSparseImage({ blockSize: 4096, chunks: [{ type: 0xcac1, blocks: 1 }] });
  const bad = buildSparseHeader({ blocks: 1, chunkCount: 1, blockSize: 4096, major: 2 }); // never validates
  const out = new Uint8Array(3 * 1024 * 1024);
  out.set(good, 100);
  out.set(bad, 2 * 1024 * 1024);
  const src = new BrowserFileSource(new Blob([out]));
  assert.deepEqual(await scanForSparse(src, out.length), [100]);
  // two valid + one straddling the 1MB chunk boundary (the scan must not lose it)
  const out2 = new Uint8Array(3 * 1024 * 1024);
  out2.set(good, 1024 * 1024 - 14); // straddles the window boundary
  out2.set(good, 100);
  const src2 = new BrowserFileSource(new Blob([out2]));
  assert.deepEqual(await scanForSparse(src2, out2.length), [100, 1024 * 1024 - 14]);
  // cap: nine valid headers -> eight offsets
  const out3 = new Uint8Array(9 * 100 * 4096 + 28);
  for (let i = 0; i < 9; i++) out3.set(good, i * 100 * 4096);
  const src3 = new BrowserFileSource(new Blob([out3]));
  assert.equal((await scanForSparse(src3, out3.length)).length, 8);
});

test("scanForSparse finds the real radio.img offset (corpus-gated)", { skip: !corpusAvailable() }, async () => {
  const { NodeFileSource } = await import("../js/lib/source.js");
  const { join } = await import("node:path");
  const src = await NodeFileSource.open(join(CORPUS_DIR, "radio.img"));
  try {
    assert.deepEqual(await scanForSparse(src, src.size), [13568]);
  } finally {
    await src.close();
  }
});

// --- SparseReader chunk resolution ----------------------------------------------

function mixedImage() {
  const blockSize = 4096;
  const raw1 = new Uint8Array(8192);
  for (let i = 0; i < raw1.length; i++) raw1[i] = (i * 11 + 1) & 0xff;
  return {
    blockSize,
    chunks: [
      { type: 0xcac1, blocks: 2, data: raw1 }, // bytes 0..8191
      { type: 0xcac3, blocks: 3 }, // zeros 8192..20479
      { type: 0xcac4, blocks: 2, fill: 0xdeadbeef }, // 20480..28671
      { type: 0xcac1, blocks: 1 }, // filler pattern 28672..32767
      { type: 0xcac3, blocks: 1 }, // zeros 32768..36863
    ],
  };
}

async function openReader(bytes) {
  return SparseReader.open(new BrowserFileSource(new Blob([bytes])), 0);
}

test("SparseReader resolves raw/fill/dont-care chunks with straddling reads", async () => {
  const spec = mixedImage();
  const reader = await openReader(buildSparseImage(spec));
  const expected = sparseReference(spec);
  assert.equal(reader.size, expected.length);
  // boundary-straddling probes around every chunk edge
  const edges = [0, 1, 8190, 8192, 8193, 20479, 20480, 20484, 28671, 28672, 32767, 32768, 36863];
  for (const edge of edges) {
    for (const [o, l] of [[edge - 3, 7], [edge, 5], [edge - 5, 10]]) {
      if (o < 0 || o + l > expected.length) continue;
      const got = await reader.read(o, l);
      assert.deepEqual(got, expected.slice(o, o + l), `read(${o}, ${l})`);
    }
  }
  // full-image read in odd-sized slices equals the materialized reference
  let pos = 0;
  const full = [];
  while (pos < expected.length) {
    const n = Math.min(1000, expected.length - pos);
    full.push(await reader.read(pos, n));
    pos += n;
  }
  assert.deepEqual(concat(full), expected);
});

test("SparseReader fill reads are 4-byte-phase correct at unaligned offsets", async () => {
  const spec = mixedImage();
  const reader = await openReader(buildSparseImage(spec));
  const expected = sparseReference(spec);
  for (const o of [20481, 20482, 20483, 25000, 28669]) {
    const got = await reader.read(o, 8);
    assert.deepEqual(got, expected.slice(o, o + 8), `fill phase at ${o}`);
  }
});

test("SparseReader rejects out-of-range reads", async () => {
  const spec = mixedImage();
  const reader = await openReader(buildSparseImage(spec));
  await assert.rejects(() => reader.read(reader.size - 2, 4), RangeError);
  await assert.rejects(() => reader.read(-1, 4), RangeError);
});

test("SparseReader byte-equals a materialized reference on a synthetic image", async () => {
  const spec = mixedImage();
  const bytes = buildSparseImage(spec);
  const reader = await openReader(bytes);
  // materialize through the public read API in one go
  const materialized = await reader.read(0, reader.size);
  assert.deepEqual(materialized, sparseReference(spec));
  // reader-over-reader: the sparse content itself is a valid source for a nested scan
  assert.deepEqual(await scanForSparse(reader, reader.size), []);
});

function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}
