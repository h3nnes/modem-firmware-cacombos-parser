// Read-only, bounded modem-container unwrapping — port of
// mtk-drdi-combo-parser/mtk_containers.py. Recognizes MTK partition headers,
// HBLR, extent-based ext4, Android sparse, and single-stream gzip. No mounts,
// external programs, temporary files, or filename-specific dispatch.
//
// Deviations from the python (all documented here, one per line):
// - xz is NOT ported: encountering an xz layer throws
//   Error("xz layer not supported in webapp") at the sniff site below.
// - gzip decompression goes through DecompressionStream("gzip") by default,
//   injectable via hooks.inflateGzip(bytes, maximum) ->
//   Promise<{out, eof, unusedData}> for Node-zlib-based tests. The default
//   implementation restores python's strict decompressobj(31) semantics
//   (eof / unused_data) because DecompressionStream silently concatenates
//   multi-member gzip streams and loses the member boundary.
// - unwrap_path()/directory() (filesystem traversal) are not ported; the
//   webapp only unwraps in-memory images via unwrapBytes().
// - ext4 names decode via non-fatal TextDecoder (replacement chars) instead
//   of python's surrogateescape; names here are ASCII in practice.
import { sha256HexAsync } from "./hash.js";
import { indexOfBytes, utf8 } from "./bytes.js";
import { crc32 } from "./mtk_hash.js";

export const MTK_MAGIC = new Uint8Array([0x88, 0x16, 0x88, 0x58]);
const SPARSE_MAGIC = new Uint8Array([0x3a, 0xff, 0x26, 0xed]);
const HBLR_MAGIC = new Uint8Array([0x48, 0x42, 0x4c, 0x52]); // "HBLR"
const SEGM_MAGIC = new Uint8Array([0x53, 0x45, 0x47, 0x4d]); // "SEGM"
// (?:^|[_\-.])(md1drdi_hdr|md1drdi_data|md1drdi|md1rom)(?=$|[.\-_]) — alternation
// order matters: md1drdi_hdr/md1drdi_data must win over the md1drdi prefix.
export const ROLE_RE = /(?:^|[_\-.])(md1drdi_hdr|md1drdi_data|md1drdi|md1rom)(?=$|[.\-_])/i;
const MTK_HEADER_SIZE = 80; // <II32s10I>

export class UnwrapError extends Error {
  constructor(message, report = {}) {
    super(message);
    this.name = "UnwrapError";
    this.report = report;
  }
}

export class Limits {
  constructor({ maxLayerBytes = 1024 * 1024 * 1024, maxTotalBytes = 3 * 1024 * 1024 * 1024, maxDepth = 12, maxEntries = 4096 } = {}) {
    this.maxLayerBytes = maxLayerBytes;
    this.maxTotalBytes = maxTotalBytes;
    this.maxDepth = maxDepth;
    this.maxEntries = maxEntries;
    if (Math.min(this.maxLayerBytes, this.maxTotalBytes, this.maxDepth, this.maxEntries) <= 0) {
      throw new RangeError("all unwrapping limits must be positive");
    }
  }
}

export class ModemParts {
  constructor(rom, drdi, drdiData, report) {
    this.rom = rom;
    this.drdi = drdi;
    this.drdi_data = drdiData;
    this.report = report;
  }
}

function chk(data, off, size) {
  // python struct.unpack_from bounds error, message-for-message.
  if (off + size > data.length) {
    throw new Error(`unpack_from requires a buffer of at least ${off + size} bytes for unpacking ${size} bytes at offset ${off} (actual buffer size is ${data.length})`);
  }
}

export function u16(data, off) {
  chk(data, off, 2);
  return data[off] | (data[off + 1] << 8);
}

export function u32(data, off) {
  chk(data, off, 4);
  return (data[off] | (data[off + 1] << 8) | (data[off + 2] << 16) | (data[off + 3] << 24)) >>> 0;
}

const hex = (n) => "0x" + n.toString(16);

export function role(name) {
  const base = String(name).split("/").pop();
  const m = ROLE_RE.exec(base);
  return m ? m[1].toLowerCase() : null;
}

function startsWith(data, magic) {
  if (data.length < magic.length) return false;
  for (let i = 0; i < magic.length; i++) if (data[i] !== magic[i]) return false;
  return true;
}

export function kindOf(data) {
  if (startsWith(data, SPARSE_MAGIC)) return "android-sparse";
  if (data.length >= 2 && data[0] === 0x1f && data[1] === 0x8b) return "gzip";
  // xz is sniffed but not expanded: the layer chain throws when it reaches it.
  if (startsWith(data, new Uint8Array([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]))) return "xz";
  if (startsWith(data, HBLR_MAGIC)) return "hblr";
  if (data.length >= 1082 && data[1080] === 0x53 && data[1081] === 0xef) return "ext4";
  if (startsWith(data, MTK_MAGIC)) return "mtk";
  return null;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function asciiDecode(bytes) {
  let end = bytes.length;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] === 0) { end = i; break; }
    if (bytes[i] > 0x7f) {
      // python bytes.decode("ascii") strict error text.
      throw new Error(`'ascii' codec can't decode byte 0x${bytes[i].toString(16)} in position ${i}: ordinal not in range(128)`);
    }
  }
  let s = "";
  for (let i = 0; i < end; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

// ---------------------------------------------------------------------------
// Default gzip hook: DecompressionStream("gzip") with python decompressobj(31)
// semantics. Python raises "truncated or oversized" when the member never ends
// (eof false) and "trailing data/multiple streams" when bytes follow the first
// member (unused_data). DecompressionStream cannot express either: it errors
// on trailing garbage and *silently concatenates* a following valid member, so
// the first member boundary is recovered here — first via the gzip trailer
// (CRC32 + ISIZE match), then by re-inflating candidate prefixes at gzip
// header positions.
// ---------------------------------------------------------------------------

async function dsInflate(data, cap) {
  const chunks = [];
  let total = 0;
  let err = null;
  let capped = false;
  const ds = new DecompressionStream("gzip");
  const reader = ds.readable.getReader();
  const writer = ds.writable.getWriter();
  const reading = (async () => {
    for (;;) {
      let res;
      try { res = await reader.read(); } catch (e) { err = err ?? e; return; }
      if (res.done) return;
      chunks.push(res.value);
      total += res.value.length;
      if (total > cap) {
        capped = true;
        try { await reader.cancel(); } catch {}
        try { writer.abort(new Error("gzip output cap")).catch(() => {}); } catch {}
        return;
      }
    }
  })();
  const writing = (async () => {
    try {
      if (data.length) await writer.write(data);
      try { await writer.close(); } catch {}
    } catch (e) { err = err ?? e; }
  })();
  await Promise.all([reading, writing]);
  let out;
  if (chunks.length === 1) out = chunks[0];
  else {
    out = new Uint8Array(total);
    let o = 0;
    for (const c of chunks) { out.set(c, o); o += c.length; }
  }
  return { out, err, capped };
}

function le32(data, off) {
  // Unsigned: CRC32 trailers have the high bit set ~50% of the time; a signed
  // read would never match crc >>> 0 and misclassify trailing-data detection.
  return (data[off] | (data[off + 1] << 8) | (data[off + 2] << 16) | (data[off + 3] << 24)) >>> 0;
}

function gzipTrailerEnd(data, out) {
  // End of the member whose trailer is CRC32(out) + ISIZE(out), or -1.
  if (!out || !out.length) return -1;
  const crc = crc32(out) >>> 0;
  const isize = out.length % 0x100000000;
  for (let p = 10; p + 8 <= data.length; p++) {
    if (le32(data, p) === crc && le32(data, p + 4) === isize) return p + 8;
  }
  return -1;
}

async function gzipHeaderCandidateEnd(data, cap) {
  // First member boundary found by re-inflating prefixes that start with a
  // plausible gzip header (magic + CM=8). Capped to bound adversarial input.
  let tries = 0;
  for (let p = 18; p + 18 <= data.length && tries < 256; p++) {
    if (data[p] !== 0x1f || data[p + 1] !== 0x8b || data[p + 2] !== 0x08) continue;
    tries++;
    const r = await dsInflate(data.subarray(0, p), cap);
    if (!r.err && !r.capped) return { end: p, out: r.out };
  }
  return null;
}

async function gzipMemberEndBySearch(data, cap) {
  // member + non-gzip garbage: the transform-side Z_DATA error discards the
  // already-decompressed output, so the member boundary is recovered by binary
  // search over prefix length. Probes that fail at flush (Z_BUF_ERROR) still
  // deliver their output; once a probe's output is complete, its CRC32+ISIZE
  // matches the member trailer inside the input, which pins the boundary.
  const codeOf = (e) => e?.cause?.code ?? e?.code;
  const probe = async (p) => {
    const r = await dsInflate(data.subarray(0, p), cap);
    if (!r.err && !r.capped) return { done: true, out: r.out };
    if (codeOf(r.err) === "Z_BUF_ERROR") {
      const end = gzipTrailerEnd(data, r.out);
      if (end >= 0 && end <= data.length) return { done: true, out: r.out };
      return { done: false, short: true }; // incomplete deflate: grow the prefix
    }
    return { done: false, short: false }; // past the member end: shrink
  };
  let lo = 18;
  let hi = data.length;
  const first = await probe(lo);
  if (first.done) return { end: lo, out: first.out };
  if (!first.short) return null; // corrupt from the start
  while (hi - lo > 1) {
    const mid = (lo + hi) >> 1;
    const c = await probe(mid);
    if (c.done) return { end: mid, out: c.out };
    if (c.short) lo = mid;
    else hi = mid;
  }
  const last = await probe(hi);
  return last.done ? { end: hi, out: last.out } : null;
}

export async function inflateGzipDefault(data, maximum) {
  // Output is capped at maximum+1 bytes exactly like python's
  // decompress(data, maximum + 1); the caller's charge() then rejects it.
  const cap = maximum + 1;
  const r = await dsInflate(data, cap);
  if (r.capped) return { out: r.out, eof: false, unusedData: false };
  if (!r.err) {
    const end = gzipTrailerEnd(data, r.out);
    if (end >= 0 && end < data.length) return { out: r.out, eof: true, unusedData: true };
    const cand = end >= 0 ? null : await gzipHeaderCandidateEnd(data, cap);
    if (cand && cand.end < data.length) return { out: cand.out, eof: true, unusedData: true };
    return { out: r.out, eof: true, unusedData: false };
  }
  const end = gzipTrailerEnd(data, r.out);
  if (end >= 0 && end <= data.length) return { out: r.out, eof: true, unusedData: end < data.length };
  const cand = await gzipHeaderCandidateEnd(data, cap);
  if (cand && cand.end < data.length) return { out: cand.out, eof: true, unusedData: true };
  const found = await gzipMemberEndBySearch(data, cap);
  if (found && found.end < data.length) return { out: found.out, eof: true, unusedData: true };
  return { out: r.out, eof: false, unusedData: false };
}

// ---------------------------------------------------------------------------
// ext4: extent/inode traversal only; deliberately not a filesystem repair tool.
// ---------------------------------------------------------------------------

class Ext4 {
  constructor(data, owner) {
    this.data = data;
    this.owner = owner;
    if (data.length < 2048) throw new UnwrapError("truncated ext4 superblock");
    const incompat = u32(data, 1120);
    // meta_bg, compression, journal-device, recovery, inline data,
    // encryption and casefold need semantics this reader does not provide.
    const allowed = 0x2 | 0x40 | 0x80 | 0x200 | 0x2000; // filetype, extents, 64bit, flex_bg, csum_seed
    if (incompat & ~allowed) throw new UnwrapError(`unsupported ext4 incompat features ${hex((incompat & ~allowed) >>> 0)}`);
    const exponent = u32(data, 1048);
    if (exponent > 5) throw new UnwrapError("unsupported ext4 block size (maximum 32 KiB)");
    this.block = 1024 << exponent;
    let blocks = u32(data, 1028);
    if (incompat & 0x80) blocks += u32(data, 1360) * 0x100000000;
    if (blocks * this.block > data.length || !blocks) throw new UnwrapError("ext4 declared filesystem extends beyond input");
    this.end = blocks * this.block;
    this.inodes = u32(data, 1024);
    this.ipg = u32(data, 1064);
    this.isize = u16(data, 1112);
    this.dsize = incompat & 0x80 ? u16(data, 1278) : 32;
    if (!this.ipg || !this.inodes || !(128 <= this.isize && this.isize <= this.block) || this.isize % 4 || !(32 <= this.dsize && this.dsize <= this.block) || this.dsize % 8) {
      throw new UnwrapError("invalid ext4 inode/group descriptor geometry");
    }
    if (incompat & 0x80 && this.dsize < 64) throw new UnwrapError("64-bit ext4 needs 64-byte group descriptors");
    this.gdt = (u32(data, 1044) + 1) * this.block;
    this.filetype = Boolean(incompat & 2);
  }

  inode(number) {
    if (!(1 <= number && number <= this.inodes)) throw new UnwrapError(`ext4 inode ${number} is outside the inode table`);
    const group = Math.floor((number - 1) / this.ipg);
    const index = (number - 1) % this.ipg;
    const gd = this.gdt + group * this.dsize;
    if (gd + this.dsize > this.end) throw new UnwrapError("ext4 group descriptor outside filesystem");
    let block = u32(this.data, gd + 8);
    if (this.dsize >= 64) block += u32(this.data, gd + 40) * 0x100000000;
    const off = block * this.block + index * this.isize;
    if (!block || off + this.isize > this.end) throw new UnwrapError("ext4 inode outside filesystem");
    return this.data.subarray(off, off + this.isize);
  }

  contents(inode) {
    const size = u32(inode, 4) + u32(inode, 108) * 0x100000000;
    this.owner.charge(size);
    if (!(u32(inode, 32) & 0x80000)) {
      if (size === 0) return new Uint8Array(0);
      throw new UnwrapError("ext4 inode needs extents; inline/indirect blocks are unsupported");
    }
    const extents = [];
    const seen = new Set();
    const visit = (node, expected = null) => {
      this.owner.entry();
      if (node.length < 12 || u16(node, 0) !== 0xf30a) throw new UnwrapError("invalid ext4 extent header");
      const n = u16(node, 2);
      const capacity = u16(node, 4);
      const depth = u16(node, 6);
      if (n > capacity || 12 + capacity * 12 > node.length || depth > 5 || (expected !== null && depth !== expected)) {
        throw new UnwrapError("invalid ext4 extent count/depth");
      }
      let lastKey = -1;
      for (let i = 0; i < n; i++) {
        const off = 12 + i * 12;
        const logical = u32(node, off);
        if (logical <= lastKey) throw new UnwrapError("unordered ext4 extent keys");
        lastKey = logical;
        if (depth) {
          const physical = u32(node, off + 4) + u16(node, off + 8) * 0x100000000;
          if (seen.has(physical)) throw new UnwrapError("cyclic/shared ext4 extent node");
          seen.add(physical);
          const disk = physical * this.block;
          if (!physical || disk + this.block > this.end) throw new UnwrapError("ext4 extent node outside filesystem");
          visit(this.data.subarray(disk, disk + this.block), depth - 1);
        } else {
          const raw = u16(node, off + 4);
          const count = raw > 32768 ? raw - 32768 : raw;
          const physical = u32(node, off + 8) + u16(node, off + 6) * 0x100000000;
          if (!count || !physical || (physical + count) * this.block > this.end) throw new UnwrapError("invalid/out-of-range ext4 extent");
          extents.push([logical, physical, count, raw > 32768]);
        }
      }
    };
    visit(inode.subarray(40, 100));
    let end = 0;
    for (const [logical, , count] of extents) {
      if (logical < end) throw new UnwrapError("overlapping/unordered ext4 extents");
      end = logical + count;
    }
    const out = new Uint8Array(Number(size));
    for (const [logical, physical, count, unwritten] of extents) {
      const dst = logical * this.block;
      const n = Math.min(count * this.block, Math.max(0, size - dst));
      if (n && !unwritten) out.set(this.data.subarray(physical * this.block, physical * this.block + n), dst);
    }
    return out;
  }

  *directories(number = 2, path = "", depth = 0, seen = null) {
    this.owner.depth(depth);
    seen = seen ?? new Set();
    if (seen.has(number)) throw new UnwrapError("cyclic/shared ext4 directory");
    seen.add(number);
    const inode = this.inode(number);
    if ((u16(inode, 0) & 0xf000) !== 0x4000) throw new UnwrapError("ext4 directory entry does not reference a directory");
    const directory = this.contents(inode);
    const entries = [];
    const children = [];
    const names = new Set();
    let pos = 0;
    while (pos < directory.length) {
      this.owner.entry();
      if (pos + 8 > directory.length) throw new UnwrapError("truncated ext4 directory entry");
      const ino = u32(directory, pos);
      const rec = u16(directory, pos + 4);
      const n = this.filetype ? directory[pos + 6] : u16(directory, pos + 6);
      if (rec < 8 || rec % 4 || rec > this.block - (pos % this.block) || pos + rec > directory.length || n > rec - 8) {
        throw new UnwrapError("invalid ext4 directory entry length");
      }
      const raw = directory.subarray(pos + 8, pos + 8 + n);
      pos += rec;
      const isDot = raw.length === 1 && raw[0] === 0x2e;
      const isDotDot = raw.length === 2 && raw[0] === 0x2e && raw[1] === 0x2e;
      if (!ino || isDot || isDotDot) continue;
      let key = "";
      let bad = !raw.length;
      for (let i = 0; i < raw.length; i++) {
        if (raw[i] === 0x2f || raw[i] === 0) { bad = true; break; }
        key += String.fromCharCode(raw[i]);
      }
      if (bad || names.has(key)) throw new UnwrapError("invalid/duplicate ext4 filename");
      names.add(key);
      const name = utf8(raw, 0, raw.length);
      const child = this.inode(ino);
      const mode = u16(child, 0) & 0xf000;
      if (mode === 0x4000) children.push([ino, path + name + "/"]);
      else if (mode === 0x8000) entries.push([name, child]);
      // Symlinks and special files are never followed.
    }
    const self = this;
    yield [path, (function* () {
      for (const [name, child] of entries) yield [name, self.contents(child)];
    })()];
    for (const [ino, childPath] of children) yield* self.directories(ino, childPath, depth + 1, seen);
  }
}

// ---------------------------------------------------------------------------

class Unwrapper {
  constructor(limits, hooks = {}) {
    this.limits = limits;
    this.hooks = hooks;
    this.total = 0;
    this.entries = 0;
    this.report = { layers: [], partial_sets: [], ignored: [] };
    this.bundles = [];
  }

  charge(size) {
    if (size < 0 || size > this.limits.maxLayerBytes || this.total + size > this.limits.maxTotalBytes) {
      throw new UnwrapError(`unwrapping byte limit exceeded (requested ${size} bytes)`);
    }
    this.total += size;
  }

  entry() {
    this.entries += 1;
    if (this.entries > this.limits.maxEntries) throw new UnwrapError("unwrapping entry limit exceeded");
  }

  depth(depth) {
    if (depth > this.limits.maxDepth) throw new UnwrapError("unwrapping depth limit exceeded");
  }

  // A sibling collection is one namespace; never join parts across sets.
  async collect(entries, source, depth) {
    this.depth(depth);
    const parts = {};
    const origins = {};
    for (const [name, data0] of entries) {
      this.entry();
      const roleFound = role(name);
      let data = data0;
      let path = source + "!/" + name;
      // Named raw parts are terminal unless they have an outer signature.
      // In particular, do not carve MTK-looking literals inside md1rom.
      let kind = kindOf(data);
      let layerDepth = depth + 1;
      while (kind === "gzip" || kind === "xz" || kind === "android-sparse") {
        this.depth(layerDepth);
        this.report.layers.push({ format: kind, source: path, bytes: data.length });
        data = await this.expand(data, kind);
        path += "!/" + kind;
        kind = kindOf(data);
        layerDepth += 1;
        this.depth(layerDepth);
      }
      if (roleFound && kind === null) {
        if (roleFound in parts && !bytesEqual(parts[roleFound], data)) {
          throw new UnwrapError(`conflicting ${roleFound} parts in ${source}`);
        }
        parts[roleFound] = data;
        if (!(roleFound in origins)) origins[roleFound] = [];
        origins[roleFound].push(path);
      } else {
        await this.walk(data, path, layerDepth);
      }
    }
    if (!Object.keys(parts).length) return;
    const split = "md1drdi_hdr" in parts && "md1drdi_data" in parts;
    if ("md1rom" in parts && ("md1drdi" in parts || split)) {
      if ("md1drdi" in parts && ("md1drdi_hdr" in parts || "md1drdi_data" in parts)) {
        throw new UnwrapError(`both flat and split DRDI parts present in ${source}`);
      }
      const selected = split
        ? { md1rom: parts.md1rom, md1drdi_hdr: parts.md1drdi_hdr, md1drdi_data: parts.md1drdi_data }
        : { md1rom: parts.md1rom, md1drdi: parts.md1drdi };
      this.bundles.push([selected, origins, source]);
    } else {
      this.report.partial_sets.push({ source, parts: Object.keys(parts).sort() });
    }
  }

  async expand(data, kind) {
    if (kind === "android-sparse") return this.sparse(data);
    const maximum = Math.min(this.limits.maxLayerBytes, this.limits.maxTotalBytes - this.total);
    let out, eof, unusedData;
    if (kind === "gzip") {
      const inflate = this.hooks.inflateGzip ?? inflateGzipDefault;
      ({ out, eof, unusedData } = await inflate(data, maximum));
    } else {
      // xz has no dependency-free JS decompressor in this project and the
      // corpus never needs it (documented spec decision).
      throw new Error("xz layer not supported in webapp");
    }
    this.charge(out.length);
    if (!eof) throw new UnwrapError(`truncated or oversized ${kind} stream`);
    if (unusedData) throw new UnwrapError(`trailing data/multiple streams in ${kind} wrapper`);
    return out;
  }

  sparse(data) {
    if (data.length < 28) throw new UnwrapError("truncated Android sparse header");
    const major = u16(data, 4);
    const fh = u16(data, 8);
    const ch = u16(data, 10);
    const block = u32(data, 12);
    const blocks = u32(data, 16);
    const chunks = u32(data, 20);
    const checksum = u32(data, 24);
    if (major !== 1 || fh < 28 || ch < 12 || fh > data.length || !block || block % 4) {
      throw new UnwrapError("unsupported/invalid Android sparse geometry");
    }
    this.charge(blocks * block);
    const out = new Uint8Array(blocks * block);
    let pos = fh;
    let cursor = 0;
    let crc = 0;
    for (let i = 0; i < chunks; i++) {
      this.entry();
      if (pos + ch > data.length) throw new UnwrapError("truncated sparse chunk header");
      const kind = u16(data, pos);
      const nblocks = u32(data, pos + 4);
      const size = u32(data, pos + 8);
      if (size < ch || pos + size > data.length) throw new UnwrapError("invalid sparse chunk extent");
      const length = nblocks * block;
      if (cursor + length > out.length) throw new UnwrapError("sparse chunk exceeds declared output");
      const payload = data.subarray(pos + ch, pos + size);
      if (kind === 0xcac1 && payload.length === length) {
        out.set(payload, cursor);
      } else if (kind === 0xcac2 && payload.length === 4) {
        for (let o = cursor; o < cursor + length; o += 4) {
          out[o] = payload[0]; out[o + 1] = payload[1]; out[o + 2] = payload[2]; out[o + 3] = payload[3];
        }
      } else if (kind === 0xcac3 && !payload.length) {
        // Android specifies zero bytes for don't-care CRC calculation.
      } else if (kind === 0xcac4 && payload.length === 4 && nblocks === 0) {
        if (u32(payload, 0) !== crc) throw new UnwrapError("Android sparse chunk CRC32 mismatch");
      } else {
        throw new UnwrapError(`unsupported/malformed sparse chunk ${hex(kind)}`);
      }
      if (length) crc = crc32(out.subarray(cursor, cursor + length), crc) >>> 0;
      cursor += length;
      pos += size;
    }
    if (cursor !== out.length || pos !== data.length) throw new UnwrapError("sparse extent/input exhaustion failed");
    if (checksum && checksum !== crc) throw new UnwrapError("Android sparse image CRC32 mismatch");
    return out;
  }

  *hblr(data) {
    const layer = this.report.layers[this.report.layers.length - 1];
    layer.members = [];
    if (data.length < 64 || u32(data, 4) !== data.length) throw new UnwrapError("HBLR declared size mismatch");
    const count = u32(data, 48);
    const start = 64 + count * 48;
    if (!(1 <= count && count <= 128) || start > data.length) throw new UnwrapError("invalid HBLR segment count");
    const names = new Set();
    const spans = [];
    const records = [];
    for (let i = 0; i < count; i++) {
      this.entry();
      const off = 64 + i * 48;
      if (!(data[off] === SEGM_MAGIC[0] && data[off + 1] === SEGM_MAGIC[1] && data[off + 2] === SEGM_MAGIC[2] && data[off + 3] === SEGM_MAGIC[3])) {
        throw new UnwrapError("missing HBLR SEGM signature");
      }
      const name = asciiDecode(data.subarray(off + 4, off + 36));
      const src = u32(data, off + 36);
      const logical = u32(data, off + 40);
      const stored = u32(data, off + 44);
      if (!name || names.has(name)) throw new UnwrapError("invalid/duplicate HBLR segment name");
      // HBLR may round stored extents up to 16 bytes. The extra bytes
      // are padding (not necessarily zero), not compressed payload.
      const rounded = Math.floor((logical + 15) / 16) * 16;
      if (logical !== stored && stored !== rounded) {
        throw new UnwrapError(`unsupported HBLR segment size relationship: ${name}`);
      }
      if (src < start || src + stored > data.length) throw new UnwrapError("HBLR segment outside container");
      names.add(name);
      spans.push([src, src + stored]);
      records.push([name, src, logical]);
      layer.members.push({ name, offset: src, bytes: logical, stored_bytes: stored, padding_bytes: stored - logical });
    }
    spans.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    for (let i = 1; i < spans.length; i++) {
      if (spans[i][0] < spans[i - 1][1]) throw new UnwrapError("overlapping HBLR segments");
    }
    for (const [name, off, size] of records) {
      this.charge(size);
      yield [name, data.subarray(off, off + size)];
    }
  }

  *mtk(data) {
    const layer = this.report.layers[this.report.layers.length - 1];
    layer.members = [];
    let pos = 0;
    for (;;) {
      pos = indexOfBytes(data, MTK_MAGIC, pos);
      if (pos < 0) break;
      this.entry();
      if (pos + MTK_HEADER_SIZE > data.length) break;
      // <II32s10I>: fields[1]=size lo, fields[2]=name, fields[5]=mirror magic,
      // fields[6]=data offset, fields[11]=size hi (64-bit via fields[1]).
      const sizeLo = u32(data, pos + 4);
      const mirror = u32(data, pos + 48);
      if (mirror !== 0x58891689) {
        pos += 4;
        continue;
      }
      const name = asciiDecode(data.subarray(pos + 8, pos + 40));
      const size = sizeLo + u32(data, pos + 72) * 0x100000000;
      const off = u32(data, pos + 52);
      if (!name || off < 512 || pos + off + size > data.length) {
        throw new UnwrapError(`invalid/truncated MTK partition at ${hex(pos)}`);
      }
      this.charge(size);
      layer.members.push({ name, header_offset: pos, offset: pos + off, bytes: size });
      yield [name, data.subarray(pos + off, pos + off + size)];
      pos += off + size; // Inner containers are visited recursively, not carved twice.
    }
  }

  async walk(data, source, depth) {
    this.depth(depth);
    let kind = kindOf(data);
    if (kind === null && indexOfBytes(data, MTK_MAGIC, 0) >= 0) kind = "mtk";
    if (kind === null) {
      this.report.ignored.push({ source, bytes: data.length });
      return;
    }
    this.report.layers.push({ format: kind, source, bytes: data.length });
    if (kind === "gzip" || kind === "xz" || kind === "android-sparse") {
      await this.walk(await this.expand(data, kind), source + "!/" + kind, depth + 1);
    } else if (kind === "hblr") {
      await this.collect(this.hblr(data), source, depth);
    } else if (kind === "mtk") {
      await this.collect(this.mtk(data), source, depth);
    } else {
      const fs = new Ext4(data, this);
      this.report.layers[this.report.layers.length - 1].metadata_checksums_verified = false;
      for (const [path, entries] of fs.directories(2, "", depth, null)) {
        const containerPath = source + (path ? "!/" + path.replace(/\/+$/, "") : "");
        let count = 0;
        for (let i = 0; i < path.length; i++) if (path[i] === "/") count++;
        await this.collect(entries, containerPath, depth + count + 1);
      }
    }
  }

  async finish() {
    const unique = new Map();
    for (const [parts, origins, source] of this.bundles) {
      const names = Object.keys(parts).sort();
      const shas = {};
      for (const name of names) shas[name] = await sha256HexAsync(parts[name]);
      const key = names.map((n) => `${n}\u0000${shas[n]}`).join("\u0001");
      if (!unique.has(key)) unique.set(key, []);
      unique.get(key).push([parts, origins, source, shas]);
    }
    this.report.candidate_sets = [...unique.values()].map((copies) => ({
      sources: copies.map((c) => c[2]),
      sha256: copies[0][3],
    }));
    this.report.processed_bytes = this.total;
    if (!unique.size) {
      throw new UnwrapError("no complete modem set found (need md1rom and md1drdi, or md1rom and both split-CDF parts)");
    }
    if (unique.size !== 1) {
      throw new UnwrapError(`${unique.size} different modem sets found; pass the intended image or parts directory explicitly`);
    }
    const copies = [...unique.values()][0];
    const [parts, origins] = copies[0];
    const split = "md1drdi_hdr" in parts;
    this.report.packaging = split ? "tensor-split" : "single-drdi";
    this.report.selected = {};
    for (const name of Object.keys(parts)) {
      this.report.selected[name] = {
        bytes: parts[name].length,
        sha256: await sha256HexAsync(parts[name]),
        sources: origins[name],
      };
    }
    this.report.identical_sets = copies.length;
    return new ModemParts(parts.md1rom, split ? parts.md1drdi_hdr : parts.md1drdi, parts.md1drdi_data ?? null, this.report);
  }
}

export async function unwrapBytes(data, name = "image", limits = new Limits(), hooks = {}) {
  // Unwrap one in-memory container. The name is provenance, not format selection.
  const worker = new Unwrapper(limits, hooks);
  try {
    worker.charge(data.length);
    worker.report.input = { source: String(name), bytes: data.length, sha256: await sha256HexAsync(data) };
    await worker.walk(data, String(name), 0);
    return await worker.finish();
  } catch (e) {
    worker.report.error = e.message;
    throw new UnwrapError(e.message, worker.report);
  }
}
