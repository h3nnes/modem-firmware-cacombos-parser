// Read-only UBI + UBIFS walker, mirroring the desktop tool's ubi-reader path
// (gui_version/image_extractor.py extract_ubi). UBI is the MTD wear-levelling
// container Qualcomm ships .ubi modem images in; this file enumerates the
// UBIFS tree(s) inside it and reads file bytes through the index B-tree.
//
// On-flash layout (all UBI headers big-endian, UBIFS headers little-endian):
//   UBI image = whole PEBs (physical erase blocks, typically 16K..256K).
//   PEB       = EC header at offset 0 (magic "UBI#", CRC over the first 60
//               bytes), VID header at ec.vid_hdr_offset (magic "UBI!", CRC),
//               then volume data at ec.data_offset. The data area is the LEB:
//               leb_size = peb_size - data_offset.
//   Volumes   = 172-byte volume-table records inside the internal layout
//               volume (vol_id 0x7FFFEFFF) at data_offset. Every data PEB's
//               VID header names its vol_id + lnum, so a volume is the set of
//               PEBs with matching image_seq/vol_id ordered by lnum.
//   UBIFS     = LEB 0 holds the superblock node, LEBs 1-2 hold two master
//               nodes; the newest master's root_lnum/root_offs points at the
//               index B-tree. Its leaves are inode/data/dent nodes, whose
//               common header is magic 0x06101831 + CRC over bytes 8..len.
//
// Data nodes may be uncompressed (0), LZO1X (1), raw-deflate zlib (2) or zstd
// (3). LZO1X is decoded below; zlib uses the vendored fflate inflateSync.
//
// Deliberately unsupported: encrypted UBIFS volumes (no key plumbing) are
// skipped with a warning; zstd data nodes are skipped per file with a warning
// (no browser decoder); symlinks/device nodes/FIFOs are not extracted (only
// regular files and directories feed the RF-card scan); HMAC-authenticated
// images parse but signatures are not verified. Multiple UBI images
// (image_seq) and multiple dynamic/static volumes in one file are handled.
import { ParseError } from "./fat16.js";
import { bump } from "./debug.js";
import { crc32 } from "./mtk_hash.js";
import { inflateSync } from "../../lib/vendor/fflate.js";

const UBI_EC_MAGIC = "UBI#";
const UBI_VID_MAGIC = "UBI!";
const UBI_INTERNAL_VOL_START = 2147479551; // 0x7FFFEFFF
const UBI_MAX_VOLUMES = 128;
const UBI_EC_HDR_SZ = 64;
const UBI_VID_HDR_SZ = 64;
const UBI_VTBL_REC_SZ = 172;
const UBI_VID_STATIC = 2;

const UBIFS_NODE_MAGIC = 0x06101831;
const UBIFS_COMMON_HDR_SZ = 24;
const UBIFS_INO_NODE = 0;
const UBIFS_DATA_NODE = 1;
const UBIFS_DENT_NODE = 2;
const UBIFS_XENT_NODE = 3;
const UBIFS_PAD_NODE = 5;
const UBIFS_SB_NODE = 6;
const UBIFS_MST_NODE = 7;
const UBIFS_IDX_NODE = 9;
const UBIFS_DATA_KEY = 1;
const UBIFS_DENT_KEY = 2;
const UBIFS_S_KEY_BLOCK_SHIFT = 29;
const UBIFS_S_KEY_BLOCK_MASK = 0x1fffffff;
const UBIFS_BLOCK_SIZE = 4096;
const UBIFS_ITYPE_REG = 0;
const UBIFS_ITYPE_DIR = 1;
const UBIFS_FLG_ENCRYPTION = 16;
const UBIFS_FLG_AUTHENTICATION = 32;
const UBIFS_COMPR_NONE = 0;
const UBIFS_COMPR_LZO = 1;
const UBIFS_COMPR_ZLIB = 2;
const UBIFS_COMPR_ZSTD = 3;

const PEB_CANDIDATES = [16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304];
// Scan the whole input for "UBI#" (ubi-reader does the same: it reads the file
// in FILE_CHUNK_SZ steps to EOF). A fixed window is not enough - vendor images
// wrap the UBI payload behind large headers, and a truncated scan would fail
// with "could not determine the PEB size" instead of finding the data.
// The scan stops early once enough anchors are collected (see below).
const PEB_SCAN_STOP_ANCHORS = 256;
// UBIFS file names are UTF-8; replacement semantics match ubi-reader's decode().
const NAME_DECODER = new TextDecoder("utf-8", { ignoreBOM: true });

// --- primitive readers ---------------------------------------------------------------

function u16be(u8, o) {
  return (u8[o] << 8) | u8[o + 1];
}

function u32be(u8, o) {
  return u8[o] * 0x1000000 + ((u8[o + 1] << 16) | (u8[o + 2] << 8) | u8[o + 3]);
}

function u64be(u8, o) {
  return u32be(u8, o) * 0x100000000 + u32be(u8, o + 4);
}

function u16le(u8, o) {
  return u8[o] | (u8[o + 1] << 8);
}

function u32le(u8, o) {
  return u8[o] + u8[o + 1] * 0x100 + u8[o + 2] * 0x10000 + u8[o + 3] * 0x1000000;
}

function u64le(u8, o) {
  const value = u32le(u8, o + 4) * 0x100000000 + u32le(u8, o);
  if (!Number.isSafeInteger(value)) throw new ParseError("UBIFS 64-bit field exceeds the JavaScript safe-integer range.");
  return value;
}

// ubi-reader's CRC convention: ~zlib.crc32(buf[:-4]) & 0xFFFFFFFF.
function headerCrc(buf) {
  return ~crc32(buf.subarray(0, buf.length - 4)) >>> 0;
}

function magicEquals(u8, off, text) {
  for (let i = 0; i < text.length; i++) {
    if (u8[off + i] !== text.charCodeAt(i)) return false;
  }
  return true;
}

function asciiName(u8, start, end) {
  let out = "";
  for (let i = start; i < end && u8[i] !== 0; i++) out += String.fromCharCode(u8[i]);
  return out;
}

// Filesystem-safe single path component (image_extractor.py _safe_output_component).
function safeComponent(value, fallback) {
  const base = String(value).split("/").pop().replace(/[^0-9A-Za-z_.-]+/g, "_").replace(/^[._]+|[._]+$/g, "");
  return base || fallback;
}

// --- LZO1X ---------------------------------------------------------------------------

// Raw LZO1X decode loop (the UBIFS data-node payload, no lzop header). Ported
// from lzo1x_decompress_safe's structure: an initial literal run, then the
// M2/M3/M4 match encodings plus the M1 short-match form. `0x11 0x00 0x00` is
// the optional LZO EOF code; UBIFS streams simply end, and the 16-bit-zero M4
// form is treated as EOF too.
export function lzo1xDecompress(input, expectedLen) {
  const out = new Uint8Array(expectedLen);
  const inLen = input.length;
  let ip = 0;
  let op = 0;
  const requireInput = (n) => {
    if (ip + n > inLen) throw new ParseError("truncated LZO1X stream");
  };
  const requireOutput = (n) => {
    if (op + n > out.length) throw new ParseError("LZO1X stream expands past the expected size");
  };
  const copyLiterals = (n) => {
    if (n <= 0) return;
    requireInput(n);
    requireOutput(n);
    out.set(input.subarray(ip, ip + n), op);
    ip += n;
    op += n;
  };
  const copyMatch = (offset, n) => {
    if (offset <= 0 || op - offset < 0) throw new ParseError("LZO1X match offset points before the output");
    requireOutput(n);
    let from = op - offset;
    // Overlapping copies must go byte by byte (offset < length is legal).
    for (let i = 0; i < n; i++) out[op++] = out[from++];
  };
  // Length extension shared by M3/M4: 255-run then a final byte.
  const extendedLength = (base, extra) => {
    let len = base;
    if (len === 0) {
      requireInput(1);
      while (input[ip] === 0) {
        len += 255;
        ip++;
        requireInput(1);
      }
      len += extra + input[ip++];
    }
    return len;
  };

  // Flat port of lzo1x_decompress_safe's labels. The C decoder is a
  // two-level loop: the outer level reads literal-run tokens, the inner level
  // decodes one match and then falls back to the outer level at match_done.
  // `label` reproduces the gotos without recursion.
  if (inLen === 0) {
    if (expectedLen !== 0) throw new ParseError("empty LZO1X stream");
    return out;
  }
  // Initial token: >17 selects a literal run of (token - 17) bytes, of which
  // lengths 1..3 go straight to match_next; <=17 is the ordinary outer-loop
  // token (and can itself be a match).
  let label = "outer";
  let token = input[ip++];
  if (token > 17) {
    const t = token - 17;
    copyLiterals(t);
    if (t < 4) {
      requireInput(1);
      token = input[ip++];
      label = "match";
    } else {
      label = "first_literal";
    }
  } else if (token >= 16) {
    label = "match";
  } else {
    copyLiterals(extendedLength(token, 15) + 3);
    label = "first_literal";
  }
  for (;;) {
    if (label === "match") {
      let offset;
      let len;
      if (token >= 64) {
        // M2: 3-bit high offset + 8-bit low, length in the top three bits.
        requireInput(1);
        offset = 1 + ((token >> 2) & 7) + (input[ip++] << 3);
        len = (token >> 5) + 1;
      } else if (token >= 32) {
        // M3: 11-bit offset, length +2 with a 255-run extension.
        len = extendedLength(token & 31, 31) + 2;
        requireInput(2);
        offset = 1 + (input[ip] >> 2) + (input[ip + 1] << 6);
        ip += 2;
      } else if (token >= 16) {
        // M4: 16-bit offset with a 0x4000 bias, length +2. A zero offset is
        // the EOF marker (0x11 0x00 0x00), which UBIFS streams may omit.
        len = extendedLength(token & 7, 7);
        requireInput(2);
        offset = (token & 8) << 11;
        offset += (input[ip] >> 2) + (input[ip + 1] << 6);
        ip += 2;
        if (offset === 0) break;
        offset += 0x4000;
        len += 2;
      } else {
        // M1: short match, 2 bytes, offset below 1024.
        requireInput(1);
        offset = 1 + (token >> 2) + (input[ip++] << 2);
        len = 2;
      }
      copyMatch(offset, len);
      label = "match_done";
      continue;
    }
    if (label === "match_done") {
      // Trailing literals live in the low two bits of the second-to-last
      // offset byte. Zero means the literal run resumes at the outer level.
      if (ip < 2) throw new ParseError("corrupt LZO1X token stream");
      const trailing = input[ip - 2] & 3;
      if (trailing === 0) {
        label = "outer";
        continue;
      }
      copyLiterals(trailing);
      requireInput(1);
      token = input[ip++];
      label = "match";
      continue;
    }
    if (label === "first_literal") {
      // first_literal_run after the initial literal copy: either a match or a
      // fixed 3-byte M2 match with the 0x800 offset bias.
      requireInput(1);
      token = input[ip++];
      if (token >= 16) {
        label = "match";
        continue;
      }
      requireInput(1);
      const offset = 1 + 0x800 + (token >> 2) + (input[ip++] << 2);
      copyMatch(offset, 3);
      label = "match_done";
      continue;
    }
    // outer: NEED_IP(3); t = *ip++
    requireInput(1);
    token = input[ip++];
    if (token >= 16) {
      label = "match";
      continue;
    }
    // Literal run: 1..15 bytes as token+3, or an 18+ run when the token is 0.
    copyLiterals(extendedLength(token, 15) + 3);
    label = "first_literal";
  }

  if (op !== out.length) {
    throw new ParseError(`LZO1X stream produced ${op} of ${out.length} expected bytes`);
  }
  return out;
}

// --- PEB geometry ---------------------------------------------------------------------

// ubi-reader's utils.guess_peb_size: the most common distance between "UBI#"
// occurrences, with a candidate-size fallback for one-PEB images.
export async function guessPebGeometry(source) {
  const seen = new Set();
  const offsets = [];
  const chunk = 1024 * 1024;
  for (let base = 0; base < source.size; base += chunk) {
    const length = Math.min(chunk + 3, source.size - base);
    const buf = await source.read(base, length);
    for (let i = 0; i + 4 <= buf.length; i++) {
      if (!magicEquals(buf, i, UBI_EC_MAGIC)) continue;
      const at = base + i;
      if (seen.has(at)) continue;
      seen.add(at);
      offsets.push(at);
      i += 3;
    }
    if (offsets.length > PEB_SCAN_STOP_ANCHORS) break;
  }
  offsets.sort((a, b) => a - b);
  const counts = new Map();
  for (let i = 1; i < offsets.length; i++) {
    const diff = offsets[i] - offsets[i - 1];
    if (diff > 0) counts.set(diff, (counts.get(diff) ?? 0) + 1);
  }
  let pebSize = 0;
  let best = 0;
  for (const [diff, n] of counts) {
    if (n > best) {
      best = n;
      pebSize = diff;
    }
  }
  if (pebSize) {
    // Start offset = the most common alignment residue. A stray "UBI#" inside
    // volume data would otherwise drag the start to a bogus offset.
    const residues = new Map();
    for (const off of offsets) {
      const r = off % pebSize;
      residues.set(r, (residues.get(r) ?? 0) + 1);
    }
    let start = offsets[0];
    let startHits = 0;
    for (const [r, n] of residues) {
      if (n > startHits || (n === startHits && r < start)) {
        startHits = n;
        start = r;
      }
    }
    return { pebSize, startOffset: start };
  }
  // No repeated magic: an image too short to contain two PEBs. Accept the
  // first candidate whose next-block slot is missing or also starts with UBI#.
  const startOffset = offsets.length ? offsets[0] : 0;
  for (const candidate of PEB_CANDIDATES) {
    if (candidate > source.size - startOffset) return { pebSize: candidate, startOffset };
    if (startOffset + candidate + 4 <= source.size) {
      const head = await source.read(startOffset + candidate, 4);
      if (magicEquals(head, 0, UBI_EC_MAGIC)) return { pebSize: candidate, startOffset };
    }
  }
  throw new ParseError("Could not determine the UBI PEB size.");
}

// --- UBI headers ----------------------------------------------------------------------

function parseEcHeader(buf) {
  if (!magicEquals(buf, 0, UBI_EC_MAGIC)) throw new ParseError("not a UBI EC header");
  return {
    version: buf[4],
    ec: u64be(buf, 8),
    vidHdrOffset: u32be(buf, 16),
    dataOffset: u32be(buf, 20),
    imageSeq: u32be(buf, 24),
    crc: u32be(buf, 60),
  };
}

function parseVidHeader(buf) {
  if (!magicEquals(buf, 0, UBI_VID_MAGIC)) throw new ParseError("not a UBI VID header");
  return {
    version: buf[4],
    volType: buf[5],
    copyFlag: buf[6],
    compat: buf[7],
    volId: u32be(buf, 8),
    lnum: u32be(buf, 12),
    dataSize: u32be(buf, 20),
    usedEbs: u32be(buf, 24),
    dataPad: u32be(buf, 28),
    dataCrc: u32be(buf, 32),
    sqnum: u64be(buf, 40),
    crc: u32be(buf, 60),
  };
}

// Volume table records (128 slots of 172 bytes). Two on-flash layouts exist:
// the spec packs the 22016-byte table contiguously across the layout volume's
// LEBs (slot 89 starts at offset 0 of LEB 1), while ubinize duplicates the
// whole table in each layout LEB. Byte-identical layout LEBs mean the
// duplicated style (one LEB holds slots 0..88); otherwise the LEBs are joined
// into one stream. Records with a bad CRC or an empty name are holes.
function parseVolumeTable(layoutLebs) {
  const identical = layoutLebs.every((buf) => buf.length === layoutLebs[0].length && buf.every((b, i) => b === layoutLebs[0][i]));
  const buf = identical ? layoutLebs[0] : Uint8Array.from(layoutLebs.flatMap((leb) => [...leb]));
  const records = [];
  const slots = Math.min(UBI_MAX_VOLUMES, Math.floor(buf.length / UBI_VTBL_REC_SZ));
  for (let index = 0; index < slots; index++) {
    const at = index * UBI_VTBL_REC_SZ;
    const rec = buf.subarray(at, at + UBI_VTBL_REC_SZ);
    if (u32be(rec, 168) !== headerCrc(rec)) continue;
    const nameLen = u16be(rec, 14);
    if (nameLen === 0 || nameLen > 128) continue;
    const name = asciiName(rec, 16, 16 + nameLen);
    if (!name) continue;
    records.push({
      index,
      reservedPebs: u32be(rec, 0),
      alignment: u32be(rec, 4),
      dataPad: u32be(rec, 8),
      volType: rec[12],
      updMarker: rec[13],
      name,
      flags: rec[144],
    });
  }
  return records;
}

// One LEB per lnum: prefer the newest sqnum (UBI journal/copy updates), then a
// non-copy block, then the lowest PEB. Mirrors ubi-reader's rm_old_blocks.
function chooseLebBlocks(blocks) {
  const byLeb = new Map();
  for (const block of blocks) {
    const current = byLeb.get(block.vid.lnum);
    if (!current) {
      byLeb.set(block.vid.lnum, block);
      continue;
    }
    if (block.vid.sqnum !== current.vid.sqnum) {
      if (block.vid.sqnum > current.vid.sqnum) byLeb.set(block.vid.lnum, block);
    } else if (block.vid.copyFlag !== current.vid.copyFlag) {
      if (block.vid.copyFlag === 0) byLeb.set(block.vid.lnum, block);
    } else if (block.peb < current.peb) {
      byLeb.set(block.vid.lnum, block);
    }
  }
  return [...byLeb.values()].sort((a, b) => a.vid.lnum - b.vid.lnum);
}

// Logical view of one UBI volume: maps logical offsets to PEB data areas.
// Missing LEBs read as 0xFF (the erased-flash value), matching ubi-reader's
// gap handling and keeping UBIFS node offsets stable.
class UbiVolumeReader {
  constructor(source, lebSize, blocks) {
    this.source = source;
    this.lebSize = lebSize;
    this.blocks = new Map(blocks.map((block) => [block.vid.lnum, block]));
    this.lastLnum = blocks.length ? blocks[blocks.length - 1].vid.lnum : 0;
    this.size = (this.lastLnum + 1) * lebSize;
  }

  async read(offset, length) {
    if (offset < 0 || length < 0) throw new RangeError(`short read at ${offset}+${length}/${this.size}`);
    const out = new Uint8Array(length);
    let done = 0;
    while (done < length) {
      const pos = offset + done;
      const lnum = Math.floor(pos / this.lebSize);
      const into = pos - lnum * this.lebSize;
      const n = Math.min(length - done, this.lebSize - into);
      const block = this.blocks.get(lnum);
      if (!block) {
        out.fill(0xff, done, done + n);
      } else {
        const usable =
          block.vid.volType === UBI_VID_STATIC && block.vid.dataSize > 0
            ? Math.min(this.lebSize, block.vid.dataSize)
            : Math.max(0, this.lebSize - block.vid.dataPad);
        const available = Math.min(n, Math.max(0, usable - into));
        if (available > 0) {
          const data = await this.source.read(block.fileOffset + block.ec.dataOffset + into, available);
          out.set(data, done);
        }
        if (available < n) out.fill(0xff, done + available, done + n);
      }
      done += n;
    }
    return out;
  }
}

// --- UBIFS ---------------------------------------------------------------------------

class UbifsVolume {
  constructor(reader, imageSeq, name, warnings) {
    this.reader = reader;
    this.imageSeq = imageSeq;
    this.name = name;
    this.warnings = warnings;
    this.lebSize = reader.lebSize;
    this.superblock = null;
    this.master = null;
    this.walkMemo = null;
    this.warnedNodes = new Set();
  }

  async init() {
    const sbNode = await this.#readNode(0, 0);
    if (sbNode.type !== UBIFS_SB_NODE) throw new ParseError("LEB 0 is not a UBIFS superblock node.");
    if (!sbNode.valid) throw new ParseError("UBIFS superblock node CRC mismatch.");
    const sb = sbNode.buf;
    const flags = u32le(sb, UBIFS_COMMON_HDR_SZ + 4);
    const minIoSize = u32le(sb, UBIFS_COMMON_HDR_SZ + 8);
    const ubifsLebSize = u32le(sb, UBIFS_COMMON_HDR_SZ + 12);
    if (!ubifsLebSize || ubifsLebSize < 4096) {
      throw new ParseError(`UBIFS superblock LEB size ${ubifsLebSize} is implausible.`);
    }
    if (flags & UBIFS_FLG_ENCRYPTION) {
      throw new ParseError("encrypted UBIFS volumes are not supported by this tool.");
    }
    this.superblock = {
      flags,
      minIoSize,
      lebSize: ubifsLebSize,
      lebCnt: u32le(sb, UBIFS_COMMON_HDR_SZ + 16),
      maxLebCnt: u32le(sb, UBIFS_COMMON_HDR_SZ + 20),
      fanout: u32le(sb, UBIFS_COMMON_HDR_SZ + 48),
      defaultCompr: u16le(sb, UBIFS_COMMON_HDR_SZ + 60),
      roCompatVersion: u32le(sb, UBIFS_COMMON_HDR_SZ + 100),
    };
    // UBI LEB numbering is per physical erase block, so the UBIFS superblock
    // must describe exactly the UBI data area; anything else means the volume
    // was built for a different MTD geometry.
    if (ubifsLebSize !== this.lebSize) {
      throw new ParseError(
        `UBIFS LEB size ${ubifsLebSize} does not match the UBI data area ${this.lebSize}.`,
      );
    }
    if (flags & UBIFS_FLG_AUTHENTICATION) {
      this.warnings.push({
        tool: "ubi",
        message: `UBI volume ${this.imageSeq}/${this.name}: UBIFS authentication is present; signatures are not verified.`,
      });
    }

    const candidates = [];
    for (let area = 0; area < 2; area++) {
      const lnum = 1 + area;
      let offs = 0;
      let best = null;
      while (offs + UBIFS_COMMON_HDR_SZ <= this.lebSize) {
        let node;
        try {
          node = await this.#readNode(lnum, offs);
        } catch {
          break;
        }
        if (!node.valid) {
          offs += node.len;
          continue;
        }
        if (node.type === UBIFS_MST_NODE) {
          const parsed = this.#parseMaster(node.buf);
          if (!best || parsed.cmtNo > best.cmtNo) best = parsed;
          offs += node.len;
        } else if (node.type === UBIFS_PAD_NODE) {
          const padLen = node.len >= UBIFS_COMMON_HDR_SZ + 4 ? u32le(node.buf, UBIFS_COMMON_HDR_SZ) : 0;
          offs += node.len + padLen;
        } else {
          break;
        }
      }
      candidates.push(best);
    }
    // ubi-reader keeps the newest node of each master LEB and prefers LEB 1;
    // only fall back to LEB 2 when LEB 1 has no valid node.
    this.master = candidates[0] ?? candidates[1];
    if (!this.master) throw new ParseError("no valid UBIFS master node found.");
  }

  // newest master node by commit number within one LEB
  #parseMaster(buf) {
    const base = UBIFS_COMMON_HDR_SZ;
    return {
      highestInum: u64le(buf, base),
      cmtNo: u64le(buf, base + 8),
      flags: u32le(buf, base + 16),
      rootLnum: u32le(buf, base + 24),
      rootOffs: u32le(buf, base + 28),
      rootLen: u32le(buf, base + 32),
      indexSize: u64le(buf, base + 48),
    };
  }

  // Reads one UBIFS node: common header, length bound, then the CRC over
  // bytes 8..len (ubi-reader's master-node check applies to every node here).
  async #readNode(lnum, offs) {
    if (lnum < 0 || offs < 0 || offs + UBIFS_COMMON_HDR_SZ > this.lebSize) {
      throw new ParseError(`UBIFS node at LEB ${lnum}+${offs} is outside the volume.`);
    }
    const at = lnum * this.lebSize + offs;
    const head = await this.reader.read(at, UBIFS_COMMON_HDR_SZ);
    if (u32le(head, 0) !== UBIFS_NODE_MAGIC) {
      throw new ParseError(`no UBIFS node magic at LEB ${lnum}+${offs}.`);
    }
    const len = u32le(head, 16);
    const type = head[20];
    if (len < UBIFS_COMMON_HDR_SZ || offs + len > this.lebSize) {
      throw new ParseError(`UBIFS node at LEB ${lnum}+${offs} has an invalid length ${len}.`);
    }
    const buf = await this.reader.read(at, len);
    const valid = (~crc32(buf.subarray(8)) >>> 0) === u32le(buf, 4);
    if (!valid && !this.warnedNodes.has(`${lnum}:${offs}`)) {
      this.warnedNodes.add(`${lnum}:${offs}`);
      this.warnings.push({
        tool: "ubi",
        message: `UBI volume ${this.imageSeq}/${this.name}: skipped corrupt UBIFS node at LEB ${lnum}+${offs} (CRC mismatch).`,
      });
    }
    return { buf, len, type, valid };
  }

  // Index B-tree recursion. Leaves are inode/data/dent/xent nodes, which are
  // bucketed by inode number. Data-node payload offsets are not on the node,
  // so each leaf's LEB/offset is recorded alongside it. `seen` guards against
  // corrupt branches that point back at an ancestor.
  async #walkIndex(lnum, offs, depth, inodes, seen) {
    if (depth > 64) throw new ParseError("UBIFS index tree is deeper than 64 levels.");
    const id = `${lnum}:${offs}`;
    if (seen.has(id)) return;
    seen.add(id);
    const node = await this.#readNode(lnum, offs);
    if (!node.valid) return;
    if (node.type === UBIFS_IDX_NODE) {
      const childCnt = u16le(node.buf, UBIFS_COMMON_HDR_SZ);
      if (childCnt === 0) return;
      const branchesStart = UBIFS_COMMON_HDR_SZ + 4;
      // Branch = {lnum, offs, len, key[8]}. Authenticated images append a
      // hash, so the stride comes from the node length (ubi-reader does the
      // same) instead of a fixed 20 bytes.
      const stride = (node.len - branchesStart) / childCnt;
      if (!Number.isInteger(stride) || stride < 20) throw new ParseError("corrupt UBIFS index node.");
      for (let i = 0; i < childCnt; i++) {
        const base = branchesStart + i * stride;
        if (u32le(node.buf, base + 8) === 0) continue;
        await this.#walkIndex(u32le(node.buf, base), u32le(node.buf, base + 4), depth + 1, inodes, seen);
      }
      return;
    }
    this.#collectNode(node.buf, node.type, lnum, offs, inodes);
  }

  // Buckets one leaf node into its inode record by the node's own key.
  #collectNode(buf, nodeType, lnum, offs, inodes) {
    const base = UBIFS_COMMON_HDR_SZ;
    const inoNum = u32le(buf, base) & UBIFS_S_KEY_BLOCK_MASK;
    const keyType = u32le(buf, base + 4) >>> UBIFS_S_KEY_BLOCK_SHIFT;
    // The four keyed node types share their numeric values with INO/DATA/DENT/
    // XENT_KEY; anything else in the tree (trun/ref/pad) is not file data.
    const KEYED_NODE_TYPES = [UBIFS_INO_NODE, UBIFS_DATA_NODE, UBIFS_DENT_NODE, UBIFS_XENT_NODE];
    if (nodeType !== keyType || !KEYED_NODE_TYPES.includes(keyType)) return;
    let record = inodes.get(inoNum);
    if (!record) {
      record = { ino: null, data: [], dent: [] };
      inodes.set(inoNum, record);
    }
    if (keyType === 0) {
      // Inode node fields after the 16-byte key: size, nlink, mode,
      // data_len, compr_type (offsets from ubifs/defines.py).
      record.ino = {
        ino: inoNum,
        size: u64le(buf, base + 24),
        nlink: u32le(buf, base + 68),
        mode: u32le(buf, base + 80),
        dataLen: u32le(buf, base + 88),
        comprType: u16le(buf, base + 108),
        // Inline payload for symlink targets / xattr values (unused here).
        inlineData: buf.subarray(base + 136),
      };
    } else if (keyType === UBIFS_DATA_KEY) {
      record.data.push({
        block: u32le(buf, base + 4) - (UBIFS_DATA_KEY << UBIFS_S_KEY_BLOCK_SHIFT),
        size: u32le(buf, base + 16),
        comprType: u16le(buf, base + 20),
        comprLen: buf.length - base - 24,
        lnum,
        offs,
      });
    } else if (keyType === UBIFS_DENT_KEY) {
      const nameLen = u16le(buf, base + 26);
      // dent name is NUL-terminated right after the 32-byte fixed part.
      if (nameLen === 0 || base + 32 + nameLen > buf.length) return;
      const nameBytes = buf.subarray(base + 32, base + 32 + nameLen);
      record.dent.push({
        block: u32le(buf, base + 4) - (UBIFS_DENT_KEY << UBIFS_S_KEY_BLOCK_SHIFT),
        inum: u64le(buf, base + 16),
        type: buf[base + 25],
        name: NAME_DECODER.decode(nameBytes),
      });
    }
    // xent nodes carry xattrs only; the scan has no use for them.
  }

  async enumerate() {
    if (this.walkMemo) return this.walkMemo;
    const inodes = new Map();
    const seen = new Set();
    await this.#walkIndex(this.master.rootLnum, this.master.rootOffs, 0, inodes, seen);
    const root = inodes.get(1);
    if (!root || !root.ino) throw new ParseError("UBIFS root inode not found.");

    const out = [];
    const visiting = new Set();
    const visit = (inoNum, parent, depth) => {
      if (depth > 256) {
        this.warnings.push({
          tool: "ubi",
          message: `UBI volume ${this.imageSeq}/${this.name}: directory nesting is deeper than 256 levels.`,
        });
        return;
      }
      if (visiting.has(inoNum)) {
        this.warnings.push({
          tool: "ubi",
          message: `UBI volume ${this.imageSeq}/${this.name}: skipped a directory cycle at inode ${inoNum}.`,
        });
        return;
      }
      visiting.add(inoNum);
      const record = inodes.get(inoNum);
      const dents = [...record.dent].sort((a, b) => a.block - b.block);
      for (const dent of dents) {
        const name = dent.name;
        if (!name || name === "." || name === ".." || name.includes("/") || name.includes("\0")) {
          this.warnings.push({
            tool: "ubi",
            message: `UBI volume ${this.imageSeq}/${this.name}: skipped unsafe UBIFS name ${JSON.stringify(name)}.`,
          });
          continue;
        }
        const child = inodes.get(dent.inum);
        if (!child || !child.ino) {
          this.warnings.push({
            tool: "ubi",
            message: `UBI volume ${this.imageSeq}/${this.name}: inode ${dent.inum} for ${name} is missing.`,
          });
          continue;
        }
        const path = `${parent}/${name}`;
        if (dent.type === UBIFS_ITYPE_DIR) {
          visit(dent.inum, path, depth + 1);
        } else if (dent.type === UBIFS_ITYPE_REG) {
          // zstd nodes cannot be decoded in the browser; skip just this file.
          if (child.data.some((node) => node.comprType === UBIFS_COMPR_ZSTD)) {
            this.warnings.push({
              tool: "zstd",
              message: `UBI volume ${this.imageSeq}/${this.name}: skipped ${path}; its UBIFS data nodes are zstd-compressed.`,
            });
            continue;
          }
          child.data.sort((a, b) => a.block - b.block);
          out.push({ path, name, size: child.ino.size, isDir: false, inode: child });
        }
        // Symlinks, devices, FIFOs and sockets are not RF-card files.
      }
      visiting.delete(inoNum);
    };
    visit(1, "", 0);
    this.walkMemo = out;
    return out;
  }

  async #blockData(inode, block) {
    // No result cache: a Modem image can hold multi-hundred-MB files and the
    // container walker reads them once. Pinning every decompressed 4 KB block
    // would retain the whole file in memory for the session (ext4.js/fat16.js
    // cache nothing either). Re-reads are cheap: the data node is located by
    // binary search and only that LEB slice is fetched.
    // Binary search the sorted data-node list for this file block.
    let lo = 0;
    let hi = inode.data.length - 1;
    let found = null;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const node = inode.data[mid];
      if (node.block === block) {
        found = node;
        break;
      }
      if (node.block < block) lo = mid + 1;
      else hi = mid - 1;
    }
    if (!found) {
      // Missing blocks are holes and read as zeros (process_reg_file's gap fill).
      return new Uint8Array(0);
    }
    const at = found.lnum * this.lebSize + found.offs + UBIFS_COMMON_HDR_SZ + 24;
    const payload = await this.reader.read(at, found.comprLen);
    let data;
    if (found.comprType === UBIFS_COMPR_NONE) {
      data = payload.subarray(0, found.size);
    } else if (found.comprType === UBIFS_COMPR_LZO) {
      data = lzo1xDecompress(payload, found.size);
    } else if (found.comprType === UBIFS_COMPR_ZLIB) {
      data = inflateSync(payload);
    } else if (found.comprType === UBIFS_COMPR_ZSTD) {
      throw new ParseError("zstd-compressed UBIFS data nodes are not supported in the browser.");
    } else {
      throw new ParseError(`unknown UBIFS compression type ${found.comprType}.`);
    }
    if (data.length !== found.size) {
      throw new ParseError(`UBIFS data block ${block} decompressed to ${data.length} of ${found.size} bytes.`);
    }
    return data;
  }

  async readInodeRange(inode, offset, length) {
    if (!inode.ino) throw new ParseError("UBIFS inode record is incomplete.");
    if (offset < 0 || length < 0 || offset + length > inode.ino.size) {
      throw new RangeError(`ubi read beyond inode ${inode.ino.ino} size: ${offset}+${length}/${inode.ino.size}`);
    }
    const out = new Uint8Array(length);
    let done = 0;
    while (done < length) {
      const pos = offset + done;
      const block = Math.floor(pos / UBIFS_BLOCK_SIZE);
      const into = pos - block * UBIFS_BLOCK_SIZE;
      const n = Math.min(UBIFS_BLOCK_SIZE - into, length - done);
      const data = await this.#blockData(inode, block);
      const available = Math.min(n, Math.max(0, data.length - into));
      if (available > 0) out.set(data.subarray(into, into + available), done);
      // Short/absent blocks stay zero-filled (UBIFS sparse/gap semantics).
      done += n;
    }
    return out;
  }
}

// --- public image walker --------------------------------------------------------------

export class UbiImage {
  constructor(source) {
    this.source = source;
    this.initialized = false;
    this.images = []; // [{ imageSeq, volumes: [{ name, volId, blocks }] }]
    this.volumes = []; // [{ imageSeq, name, index, ubifs }]
    this.warnings = [];
    this.walkMemo = null;
    this.pebSize = 0;
    this.lebSize = 0;
    this.startOffset = 0;
  }

  async init() {
    if (this.initialized) return;
    this.walkMemo = null;
    this.warnings = [];
    this.images = [];
    this.volumes = [];
    const { pebSize, startOffset } = await guessPebGeometry(this.source);
    this.pebSize = pebSize;
    this.startOffset = startOffset;

    const blocks = [];
    let badHeaders = 0;
    let lebSize = 0;
    for (let off = startOffset; off + UBI_EC_HDR_SZ <= this.source.size; off += pebSize) {
      const ecBuf = await this.source.read(off, UBI_EC_HDR_SZ);
      if (!magicEquals(ecBuf, 0, UBI_EC_MAGIC)) continue; // bad/erased PEB
      const ec = parseEcHeader(ecBuf);
      if (headerCrc(ecBuf) !== ec.crc) {
        badHeaders++;
        continue;
      }
      if (
        ec.vidHdrOffset < UBI_EC_HDR_SZ ||
        ec.vidHdrOffset + UBI_VID_HDR_SZ > pebSize ||
        ec.dataOffset < UBI_EC_HDR_SZ ||
        ec.dataOffset >= pebSize
      ) {
        badHeaders++;
        continue;
      }
      let vid;
      try {
        const vidBuf = await this.source.read(off + ec.vidHdrOffset, UBI_VID_HDR_SZ);
        vid = parseVidHeader(vidBuf);
        if (headerCrc(vidBuf) !== vid.crc) {
          badHeaders++;
          continue;
        }
      } catch {
        badHeaders++;
        continue;
      }
      if (!lebSize) {
        lebSize = pebSize - ec.dataOffset;
        if (lebSize <= 0) throw new ParseError("UBI data offset leaves no LEB space.");
      }
      const block = {
        peb: Math.floor((off - startOffset) / pebSize),
        fileOffset: off,
        ec,
        vid,
        isInternal: vid.volId >= UBI_INTERNAL_VOL_START,
        layoutData: null,
      };
      if (block.isInternal) {
        // The layout volume's data area holds the 172-byte volume records; a
        // truncated image may expose fewer bytes than the full table.
        const dataStart = off + ec.dataOffset;
        const tableLength = Math.min(UBI_MAX_VOLUMES * UBI_VTBL_REC_SZ, pebSize - ec.dataOffset, Math.max(0, this.source.size - dataStart));
        if (tableLength >= UBI_VTBL_REC_SZ) block.layoutData = await this.source.read(dataStart, tableLength);
      }
      blocks.push(block);
    }
    if (!blocks.length) throw new ParseError("no valid UBI erase blocks found.");
    this.lebSize = lebSize;
    if (badHeaders) {
      this.warnings.push({
        tool: "ubi",
        message: `UBI image: skipped ${badHeaders} erase block(s) with corrupt headers.`,
      });
    }

    // Group layout blocks (their volume table defines the image) by image_seq.
    const layoutsBySeq = new Map();
    for (const block of blocks) {
      if (!block.isInternal || !block.layoutData) continue;
      let list = layoutsBySeq.get(block.ec.imageSeq);
      if (!list) {
        list = [];
        layoutsBySeq.set(block.ec.imageSeq, list);
      }
      list.push(block);
    }
    const seqsWithVolumes = [...layoutsBySeq.keys()].filter((seq) =>
      blocks.some((block) => !block.isInternal && block.ec.imageSeq === seq),
    );
    if (seqsWithVolumes.length === 0) {
      throw new ParseError("no valid UBI volume table (layout volume) found.");
    }

    for (const [imageSeq, layoutBlocks] of layoutsBySeq) {
      const ordered = [...layoutBlocks].sort((a, b) => a.vid.lnum - b.vid.lnum);
      // The layout volume's LEB 0 (and its mirror LEB 1) hold the table; the
      // 22016-byte table only fits across both when they are not duplicates.
      const records = parseVolumeTable(ordered.map((block) => block.layoutData));
      const image = { imageSeq, volumes: [] };
      for (const record of records) {
        // A volume whose update never finished carries an update marker; its
        // data may be half-written, so warn but still attempt UBIFS (the
        // superblock CRC decides whether it is readable).
        if (record.updMarker) {
          this.warnings.push({
            tool: "ubi",
            message: `UBI image ${imageSeq}, volume ${record.name}: incomplete volume update (upd_marker set).`,
          });
        }
        const volumeBlocks = chooseLebBlocks(
          blocks.filter(
            (block) =>
              !block.isInternal &&
              block.ec.imageSeq === imageSeq &&
              block.vid.volId === record.index &&
              block.vid.volType !== 0,
          ),
        );
        if (!volumeBlocks.length) continue;
        image.volumes.push({ name: record.name, volId: record.index, blocks: volumeBlocks });
      }
      this.images.push(image);
      for (let index = 0; index < image.volumes.length; index++) {
        const volume = image.volumes[index];
        const reader = new UbiVolumeReader(this.source, lebSize, volume.blocks);
        const ubifs = new UbifsVolume(reader, imageSeq, volume.name, this.warnings);
        try {
          await ubifs.init();
        } catch (err) {
          this.warnings.push({
            tool: "ubi",
            message: `UBI image ${imageSeq}, volume ${volume.name}: skipped non-UBIFS or unreadable volume: ${err.message}`,
          });
          continue;
        }
        this.volumes.push({ imageSeq, name: volume.name, index, ubifs });
      }
    }
    if (!this.volumes.length) {
      throw new ParseError("UBI image contains no readable UBIFS volumes.");
    }
    this.initialized = true;
  }

  #assertInit() {
    if (!this.initialized) throw new ParseError("UbiImage not initialised: call await init() first.");
  }

  // Aggregated file list across every image_seq / volume. Paths are absolute
  // and already carry the `/<image_seq>/<volume>/` prefix, so the extractor
  // can drop them straight into its `ubi_<n>` workdir.
  async walk() {
    this.#assertInit();
    if (this.walkMemo) return this.walkMemo;
    bump("ubiWalk");
    const out = [];
    for (const volume of this.volumes) {
      let entries;
      try {
        entries = await volume.ubifs.enumerate();
      } catch (err) {
        this.warnings.push({
          tool: "ubi",
          message: `UBI image ${volume.imageSeq}, volume ${volume.name}: tree walk failed: ${err.message}`,
        });
        continue;
      }
      const safeName = safeComponent(volume.name, `volume_${volume.index}`);
      for (const entry of entries) {
        out.push({
          path: `/${volume.imageSeq}/${safeName}${entry.path}`,
          name: entry.name,
          size: entry.size,
          isDir: false,
          inode: entry.inode,
          ubifs: volume.ubifs,
        });
      }
    }
    this.walkMemo = out;
    return out;
  }

  async readFile(entry) {
    if (entry.isDir) {
      throw new ParseError(`Path is a directory inside the UBI/UBIFS filesystem: ${entry.path ?? entry.name}`);
    }
    return this.readFileRange(entry, 0, entry.size);
  }

  async readFileRange(entry, offset, length) {
    if (entry.isDir) {
      throw new ParseError(`Path is a directory inside the UBI/UBIFS filesystem: ${entry.path ?? entry.name}`);
    }
    if (!entry.ubifs) throw new ParseError("UBI entry has no backing filesystem.");
    return entry.ubifs.readInodeRange(entry.inode, offset, length);
  }

  async findFile(path) {
    this.#assertInit();
    const entries = await this.walk();
    return entries.find((entry) => entry.path === path) ?? null;
  }
}
