// Container detection table: same branch order, magic offsets/bytes and tag
// strings throughout. Tags routed to an in-house reader are listed in
// SUPPORTED_TAGS; every remaining tag gets an UNSUPPORTED_TAGS descriptor
// naming the external tool that would handle it (ext4/erofs/7z/super/payload,
// plus the hard-rejected f2fs/ubi).
// xz/zstd have no browser decoder, so they stay unsupported here.

const MAGIC_MAX = 4096;

function startsWith(head, bytes) {
  if (head.length < bytes.length) return false;
  for (let i = 0; i < bytes.length; i++) {
    if (head[i] !== bytes[i]) return false;
  }
  return true;
}

// bytes in [start, end) equal `bytes`
function regionEquals(head, start, bytes) {
  if (head.length < start + bytes.length) return false;
  for (let i = 0; i < bytes.length; i++) {
    if (head[start + i] !== bytes[i]) return false;
  }
  return true;
}

// bytes indexOf over the head window
function findBytes(head, bytes, limit) {
  const end = Math.min(head.length, limit) - bytes.length;
  outer: for (let i = 0; i <= end; i++) {
    for (let j = 0; j < bytes.length; j++) {
      if (head[i + j] !== bytes[j]) continue outer;
    }
    return i;
  }
  return -1;
}

// The last dot suffix including the dot, lowercased.
function pySuffix(name) {
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(dot).toLowerCase() : "";
}

// OEM name field at offset 3, trailing NULs/spaces stripped before comparison.
function fatOem(head) {
  let end = 11;
  while (end > 3 && (head[end - 1] === 0 || head[end - 1] === 0x20)) end--;
  return String.fromCharCode(...head.slice(3, end));
}

const FAT_OEMS = new Set(["MSDOS5.0", "MSWIN4.1", "mkfs.fat", "FAT     ", "MSDOS"]);

// detect(path): head is the first MAGIC_MAX bytes (empty head -> "empty").
export function detect(head, name = "") {
  if (!head.length) return "empty";

  if (startsWith(head, [0x3a, 0xff, 0x26, 0xed])) return "sparse";
  if (startsWith(head, [0x43, 0x72, 0x41, 0x55])) return "payload"; // CrAU
  if (startsWith(head, [0x41, 0x4e, 0x44, 0x52, 0x4f, 0x49, 0x44, 0x21])) return "bootimg";
  // Android super.img: LP_METADATA_GEOMETRY_MAGIC at offset 0x1000.
  if (startsWith(head, [0x67, 0x73, 0x6c, 0x61]) || regionEquals(head, 0x1000, [0x67, 0x73, 0x6c, 0x61])) return "super";
  if (startsWith(head, [0x1f, 0x8b])) return "gzip";
  if (startsWith(head, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) return "xz";
  if (startsWith(head, [0x28, 0xb5, 0x2f, 0xfd])) return "zstd";
  if (startsWith(head, [0x04, 0x22, 0x4d, 0x18])) return "lz4";
  // Apple baseband config container; checked before the archive tags.
  if (startsWith(head, [0x00, 0x47, 0x46, 0x43]) || findBytes(head, [0x42, 0x42, 0x43, 0x46, 0x47, 0x4d, 0x42, 0x4e], 64) !== -1) return "bbcfg";
  if (startsWith(head, [0x50, 0x4b, 0x03, 0x04]) || pySuffix(name) === ".bbfw" || pySuffix(name) === ".ipsw") return "zip";
  if (startsWith(head, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return "7z";
  if (startsWith(head, [0x68, 0x73, 0x71, 0x73]) || startsWith(head, [0x73, 0x71, 0x73, 0x68])) return "squashfs";
  // tar (ustar magic at offset 257).
  if (regionEquals(head, 257, [0x75, 0x73, 0x74, 0x61, 0x72])) return "tar";
  // ext2/3/4 - superblock magic 0x53EF at offset 0x438.
  if (regionEquals(head, 0x438, [0x53, 0xef])) return "ext4";
  // EROFS - superblock magic 0xE0F5E1E2 at offset 0x400.
  if (regionEquals(head, 0x400, [0xe2, 0xe1, 0xf5, 0xe0])) return "erofs";
  // F2FS - superblock magic 0xF2F52010 at offset 0x400 (LE).
  if (regionEquals(head, 0x400, [0x10, 0x20, 0xf5, 0xf2])) return "f2fs";
  if (startsWith(head, [0x55, 0x42, 0x49, 0x23])) return "ubi";
  // FAT12/16/32: OEM name at offset 3.
  if (head.length >= 11 && FAT_OEMS.has(fatOem(head))) return "fat";
  // Last-resort MBR-style boot signature; likely FAT or a partition table.
  if (regionEquals(head, 0x1fe, [0x55, 0xaa])) return "fat_or_mbr";
  return "unknown";
}

export function readMagicHead(source) {
  return source.read(0, Math.min(MAGIC_MAX, source.size));
}

// Tool descriptors: the webapp has no subprocess, so extraction beyond the
// in-house readers reports the missing tool instead.
export const UNSUPPORTED_TAGS = {
  payload: { tool: "payload-dumper-go", message: "looks like an OTA payload; install payload-dumper-go or the 'payload_dumper' Python package and rerun." },
  super: { tool: "lpunpack", message: "Android dynamic partition (super) image; lpunpack is not available in the browser." },
  erofs: { tool: "fsck.erofs", message: "EROFS image; fsck.erofs is not available in the browser." },
  squashfs: { tool: "unsquashfs", message: "SquashFS image; unsquashfs is not available in the browser." },
  "7z": { tool: "7z", message: "7z archive; 7z is not available in the browser." },
  xz: { tool: "xz", message: "xz stream; no xz decoder is available in the browser." },
  zstd: { tool: "zstd", message: "zstd stream; no zstd decoder is available in the browser." },
  f2fs: { tool: null, message: "looks like an F2FS image; F2FS extraction is not supported by this tool" },
  ubi: { tool: null, message: "looks like a UBI image; UBI extraction is not supported by this tool" },
};

// Tags with an in-house reader (extractor.js): sparse (sparse.js),
// gzip (DecompressionStream), lz4 (lz4.js), zip/tar (extractor.js),
// fat/fat_or_mbr (fat16.js), ext4 (ext4.js), bbcfg (iphone.js).
export const SUPPORTED_TAGS = new Set(["sparse", "gzip", "lz4", "zip", "tar", "fat", "fat_or_mbr", "ext4", "bbcfg"]);
