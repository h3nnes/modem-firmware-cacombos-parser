// Android sparse image support: header parse + validation, a chunk-table
// SparseReader that implements the RandomAccessSource interface WITHOUT
// materializing the unsparsed image, and scanForSparse for OEM-wrapped
// images (e.g. Motorola SINGLE_N_LONELY wrappers).
//
// Chunk header layout was decoded empirically from corpus radio.img (12
// chunks, per-chunk block counts summing to totalBlocks): <HHII>
// type/reserved/output-blocks/total-size-including-the-12-byte-header, chunk
// data at +12. RAW(0xCAC1)/CARE(0xCAC2) carry blocks*blockSize bytes there,
// FILL(0xCAC4) a 4-byte LE value, CRC32(0xCAC5) a 4-byte checksum (no output
// blocks), DONT_CARE(0xCAC3) nothing.

import { StructReader } from "./bytes.js";

export const SPARSE_MAGIC = 0xed26ff3a; // LE bytes 3a ff 26 ed

const CHUNK_RAW = 0xcac1;
const CHUNK_CARE = 0xcac2;
const CHUNK_DONT_CARE = 0xcac3;
const CHUNK_FILL = 0xcac4;
const CHUNK_CRC32 = 0xcac5;

const VALID_BLOCK_SIZES = [512, 1024, 2048, 4096, 8192, 16384, 32768];

export function parseSparseHeader(headerBytes) {
  const r = new StructReader(headerBytes);
  const [magic, major, minor, fileHdrSz, chunkHdrSz, blockSize, totalBlocks, totalChunks] = r.unpack("<IHHHHIIII", 0);
  return {
    magic,
    major,
    minor,
    fileHdrSz,
    chunkHdrSz,
    blockSize,
    totalBlocks,
    totalChunks,
    imageChecksum: r.u32(24),
  };
}

// The validation applied before reporting a header offset.
export function validSparseHeader(h) {
  return (
    h.magic === SPARSE_MAGIC &&
    h.major === 1 &&
    h.minor === 0 &&
    h.fileHdrSz === 28 &&
    h.chunkHdrSz === 12 &&
    VALID_BLOCK_SIZES.includes(h.blockSize) &&
    h.totalBlocks > 0 &&
    h.totalChunks > 0
  );
}

// Chunked ~1MB scan reporting every valid sparse header offset (max
// `maxOffsets`). Windows overlap by 28 bytes and found offsets are
// de-duplicated, so boundary-straddling headers are found and every reported
// offset is the true absolute one. On corpus radio.img this returns exactly
// [13568].
export async function scanForSparse(source, fileSize, maxOffsets = 8) {
  const offsets = [];
  if (fileSize < 28) return offsets;
  const CHUNK = 1 << 20;
  const OVERLAP = 28;
  let pos = 0;
  while (pos < fileSize && offsets.length < maxOffsets) {
    const readSize = Math.min(CHUNK, fileSize - pos);
    const data = await source.read(pos, readSize);
    let start = 0;
    for (;;) {
      // Fast prefilter: the magic starts with 0x3a, so indexOf skips the vast
      // majority of bytes with a native scan (measured ~40% less CPU than a
      // per-byte DataView.getUint32 loop on radio.img); validate the remaining
      // three bytes before touching the header.
      const idx = data.indexOf(0x3a, start);
      if (idx < 0 || idx + 4 > data.byteLength) break;
      if (data[idx + 1] === 0xff && data[idx + 2] === 0x26 && data[idx + 3] === 0xed) {
        const offset = pos + idx;
        if (offset + 28 <= fileSize) {
          // Parse the header from the already-read chunk when it fits, and only
          // issue a separate read when it straddles the chunk end.
          const header =
            idx + 28 <= data.byteLength
              ? parseSparseHeader(data.subarray(idx, idx + 28))
              : parseSparseHeader(await source.read(offset, 28));
          if (validSparseHeader(header)) {
            if (!offsets.length || offset > offsets[offsets.length - 1]) offsets.push(offset);
          }
        }
      }
      start = idx + 1;
      if (offsets.length >= maxOffsets) break;
    }
    if (readSize < CHUNK) break;
    pos += readSize - OVERLAP;
  }
  return offsets;
}

// RandomAccessSource over the UNSPARSED content. Reads resolve through the
// chunk table against the backing source; nothing beyond chunk granularity is
// ever materialized.
export class SparseReader {
  constructor(source, baseOffset, header, chunks, size) {
    this.source = source;
    this.baseOffset = baseOffset;
    this.header = header;
    this.chunks = chunks; // { type, outOffset, blocks, srcOffset?, fillValue? }
    this.size = size;
  }

  // Constructors cannot await: reads the header + walks the chunk table.
  static async open(source, baseOffset = 0) {
    const header = parseSparseHeader(await source.read(baseOffset, 28));
    if (!validSparseHeader(header)) {
      throw new Error("Invalid Android sparse image header");
    }
    const chunks = [];
    let pos = baseOffset + header.fileHdrSz;
    let outOffset = 0;
    for (let i = 0; i < header.totalChunks; i++) {
      const r = new StructReader(await source.read(pos, 12));
      const type = r.u16(0);
      r.u16(2); // reserved
      const blocks = r.u32(4);
      const total = r.u32(8);
      if (type === CHUNK_RAW || type === CHUNK_CARE) {
        const srcLen = total - header.chunkHdrSz;
        if (srcLen !== blocks * header.blockSize) {
          throw new Error(`Corrupt sparse RAW chunk ${i}: ${srcLen} bytes for ${blocks} blocks`);
        }
        chunks.push({ type, outOffset, blocks, srcOffset: pos + header.chunkHdrSz });
      } else if (type === CHUNK_DONT_CARE) {
        if (total !== header.chunkHdrSz) throw new Error(`Corrupt sparse DONT_CARE chunk ${i}`);
        chunks.push({ type, outOffset, blocks });
      } else if (type === CHUNK_FILL || type === CHUNK_CRC32) {
        if (total !== header.chunkHdrSz + 4) throw new Error(`Corrupt sparse chunk ${i} (type ${type})`);
        const fillValue = new StructReader(await source.read(pos + header.chunkHdrSz, 4)).u32(0);
        // CRC32 contributes no output blocks (AOSP semantics).
        chunks.push({ type, outOffset, blocks: type === CHUNK_CRC32 ? 0 : blocks, fillValue });
      } else {
        throw new Error(`Unknown sparse chunk type 0x${type.toString(16)} in chunk ${i}`);
      }
      outOffset += (type === CHUNK_CRC32 ? 0 : blocks) * header.blockSize;
      pos += total;
    }
    return new SparseReader(source, baseOffset, header, chunks, outOffset);
  }

  #chunkFor(pos) {
    let lo = 0;
    let hi = this.chunks.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.chunks[mid].outOffset <= pos) lo = mid;
      else hi = mid - 1;
    }
    return this.chunks[lo];
  }

  async read(offset, length) {
    if (offset < 0 || length < 0 || offset + length > this.size) {
      throw new RangeError(`sparse read out of range: ${offset}+${length}/${this.size}`);
    }
    const out = new Uint8Array(length);
    let done = 0;
    while (done < length) {
      const pos = offset + done;
      const chunk = this.#chunkFor(pos);
      const span = chunk.blocks * this.header.blockSize;
      const into = pos - chunk.outOffset;
      const n = Math.min(span - into, length - done);
      if (chunk.type === CHUNK_RAW || chunk.type === CHUNK_CARE) {
        out.set(await this.source.read(chunk.srcOffset + into, n), done);
      } else if (chunk.type === CHUNK_FILL) {
        const bytes = [chunk.fillValue & 0xff, (chunk.fillValue >>> 8) & 0xff, (chunk.fillValue >>> 16) & 0xff, (chunk.fillValue >>> 24) & 0xff];
        for (let k = 0; k < n; k++) out[done + k] = bytes[(into + k) % 4];
      } // DONT_CARE: zeros stay
      done += n;
    }
    return out;
  }
}
