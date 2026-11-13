// Google/QCOM FBPK ("FastBoot PacK") container headers. Pixel radio images
// for MediaTek modems are FBPK v1 wrappers whose single `modem` entry is an
// ext4 filesystem; the modem bundle itself lives inside that filesystem.
//
// Only the header/entry table is decoded here so callers can either walk the
// payloads (mtk_containers.js) or expose them as zero-copy virtual files
// (extractor.js). Payload formats are detected by the callers, not by name.
//
// v1 layout (little endian):
//   0x00 "FBPK", 0x04 u32 version = 1,
//   0x08 name[68], 0x4c u32 entry count, 0x50 u32 total container size,
//   0x54 entry table. Each entry is 0x38 bytes:
//     +0x00 u32 type, +0x04 name[32], +0x24 u32 reserved,
//     +0x28 u32 payload size, +0x2c u32 reserved,
//     +0x30 u32 next-entry offset (absolute; past EOF for the last entry),
//     +0x34 u32 CRC32 of the payload, +0x38 payload bytes.
// The reserved words and CRC are validated by neither imjtool nor this reader;
// the payload bounds and every entry-table extent are always checked.

export const FBPK_MAGIC = new Uint8Array([0x46, 0x42, 0x50, 0x4b]); // "FBPK"
const V1_HEADER_SIZE = 0x54;
const V1_ENTRY_SIZE = 0x38;

export class FbpkError extends Error {
  constructor(message) {
    super(message);
    this.name = "FbpkError";
  }
}

function startsWith(data, bytes) {
  if (data.length < bytes.length) return false;
  for (let i = 0; i < bytes.length; i++) if (data[i] !== bytes[i]) return false;
  return true;
}

function u32(data, off) {
  if (off < 0 || off + 4 > data.length) throw new FbpkError(`truncated FBPK header at 0x${off.toString(16)}`);
  return (data[off] | (data[off + 1] << 8) | (data[off + 2] << 16) | (data[off + 3] << 24)) >>> 0;
}

// NUL-terminated ASCII/Latin-1 string bounded to `max` bytes.
function cstring(data, off, max) {
  const end = Math.min(data.length, off + max);
  let len = 0;
  while (off + len < end && data[off + len] !== 0) len++;
  let out = "";
  for (let i = 0; i < len; i++) out += String.fromCharCode(data[off + i]);
  return out;
}

export function isFbpk(data) {
  return startsWith(data, FBPK_MAGIC);
}

// Parse the FBPK header and entry table. `containerSize` is the declared
// container size when only a header prefix is available; entry payloads are
// bounds-checked against it but not read.
export function parseFbpkHeader(data, containerSize = data.length) {
  if (!isFbpk(data)) throw new FbpkError("not an FBPK container");
  const version = u32(data, 4);
  if (version !== 1) {
    throw new FbpkError(`unsupported FBPK version ${version} (only v1 is supported)`);
  }
  if (data.length < V1_HEADER_SIZE) throw new FbpkError("truncated FBPK v1 header");
  const name = cstring(data, 8, V1_HEADER_SIZE - 8);
  const count = u32(data, 0x4c);
  const totalSize = u32(data, 0x50);
  if (totalSize > containerSize) {
    throw new FbpkError(`FBPK declares ${totalSize} bytes but only ${containerSize} are available`);
  }
  const maxEntries = Math.floor((totalSize - V1_HEADER_SIZE) / V1_ENTRY_SIZE);
  if (count > maxEntries) {
    throw new FbpkError(`FBPK entry count ${count} exceeds the container's ${maxEntries} entry slots`);
  }
  const entries = [];
  let off = V1_HEADER_SIZE;
  for (let i = 0; i < count; i++) {
    if (off + V1_ENTRY_SIZE > data.length) {
      throw new FbpkError(`truncated FBPK entry table at entry ${i}`);
    }
    const type = u32(data, off);
    const entryName = cstring(data, off + 4, 32);
    const size = u32(data, off + 0x28);
    const payloadOffset = off + V1_ENTRY_SIZE;
    if (payloadOffset + size > totalSize) {
      throw new FbpkError(`FBPK entry ${entryName || i} extends beyond the container`);
    }
    entries.push({ type, name: entryName, offset: payloadOffset, size });
    if (i + 1 < count) {
      const next = u32(data, off + 0x30);
      // Interior entries carry the absolute offset of the next entry header.
      // Only trust it when it neither overlaps this payload nor runs past the
      // container; otherwise fall back to the contiguous layout. The last
      // entry's hint points just past EOF and is intentionally ignored.
      off = next >= payloadOffset + size && next + V1_ENTRY_SIZE <= totalSize
        ? next
        : Math.ceil((payloadOffset + size) / 4) * 4;
    }
  }
  return { version, name, totalSize, entries };
}

// Full parse: attaches a zero-copy view of each entry's payload.
export function parseFbpk(data) {
  const header = parseFbpkHeader(data, data.length);
  for (const entry of header.entries) {
    entry.data = data.subarray(entry.offset, entry.offset + entry.size);
  }
  return header;
}
