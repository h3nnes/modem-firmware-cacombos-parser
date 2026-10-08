// Container orchestration: recursive unwrap and per-tag extractor dispatch
// over a virtual file tree. Stages materialize sibling virtual dirs named
// `<tag>_<n>` under a single root, and MBN paths are recorded relative to
// that root. The analyzer's record_json SCRATCH_DIR_RE then normalizes
// `sparse_<n>/...` to the golden `sparse/...` first component.
//
// In-house readers replace the external tools:
//   sparse 7z path        -> SparseReader + Fat16Image/Ext4Image tree walk
//     (radio.img's sparse payload is an ext4 filesystem - verified against
//     7-Zip and the goldens; the tree lands in the sparse workdir)
//   ext4 debugfs          -> ext4.js tree walk (same workdir shape)
//   fat/fat_or_mbr 7z     -> Fat16Image walk
//   lz4 CLI/lz4.frame     -> lz4.js
//   gzip module           -> DecompressionStream
// Everything without an in-house reader surfaces an UNSUPPORTED_TAGS warning.
import { detect, UNSUPPORTED_TAGS, SUPPORTED_TAGS } from "./formats.js";
import { SparseReader, scanForSparse } from "./sparse.js";
import { decompressLz4Frame } from "./lz4.js";
import { Fat16Image } from "./fat16.js";
import { Ext4Image } from "./ext4.js";
import { SlicedSource } from "./source.js";
import { extractBbcfgTree, extractEfsPathnames } from "./iphone.js";
import { inflateSync } from "../../lib/vendor/fflate.js";

const MAGIC_MAX = 4096;
const MAX_RECURSION_DEPTH = 8;
const MIN_CONTAINER_SIZE = 512;
// Whole-buffer extractors (gzip/lz4/zip member/raw sparse fallback) allocate
// the compressed input AND the decompressed output at once. Past this budget the
// container is skipped with a warning instead of aborting the tab/process on an
// ArrayBuffer allocation (the 12.7 GB Xiaomi .tgz used to do exactly that).
// 1 GiB still admits the corpus' biggest real case (the Samsung .tar.md5's
// ~97 MB lz4 member -> ~190 MB FAT16 image).
const MAX_WHOLE_BUFFER_BYTES = 1 << 30;

// Candidate/sidecar filename filters; the analyzer's stricter matchesCandidate
// runs again per MBN.
export const RFCARD_RE = /^(?:rf_config_[0-9A-Fa-f]{3,6}_[0-9A-Fa-f]{1,4}_[0-9A-Fa-f]{1,4}(?:_(?:\d+))?|[0-9A-Fa-f]+_[0-9A-Fa-f]+(?:_[0-9A-Fa-f]+)?)\.mbn$/i;
export const SIDECAR_RES = [/^rf_config_.*_combos\.xml$/, /^rf_config_.*_combos_.*\.txt$/, /^mbn_ota\.md5sum$/, /^rfcard_info_all\.(?:csv|json)$/];

export class ExtractionError extends Error {
  constructor(message) {
    super(message);
    this.name = "ExtractionError";
  }
}

// --- virtual file tree -------------------------------------------------------------

// A regular file inside the virtual tree. Backed either by in-memory bytes or
// by a region of a RandomAccessSource (zero-copy slices; large containers are
// never materialized unless an extractor must own the bytes).
export class VFile {
  // load: () => Promise<Uint8Array>; region: { source, offset, size } | null;
  // readRange: ((offset, length) => Promise<Uint8Array>) | null — a ranged
  // reader over the backing filesystem (tree files), used by headOf so sniffing
  // a file's magic never materializes the whole file.
  constructor(name, load, size, region = null, readRange = null) {
    this.name = name;
    this.#load = load;
    this.size = size;
    this.region = region;
    this.readRange = readRange;
  }

  #load;
  #memData = undefined;
  #released = false;

  static mem(name, data) {
    // Holder indirection instead of a captured constant so release() can drop
    // the buffer later (see release()).
    const file = new VFile(name, () => file.#memData, data.length, null);
    file.#memData = data;
    return file;
  }

  static text(name, text) {
    const data = new TextEncoder().encode(text);
    return new VFile(name, () => data, data.length, null);
  }

  static slice(name, source, offset, size) {
    return new VFile(name, () => source.read(offset, size), size, { source, offset, size });
  }

  // Source over this file's bytes (region views stay zero-copy).
  asSource() {
    if (this.region) return new SlicedSource(this.region.source, this.region.offset, this.region.size);
    return new MemorySourceSync(this);
  }

  read() {
    if (this.#released) throw new Error(`${this.name}: bytes released after container extraction`);
    return this.#load();
  }

  // Drops the materialized buffer of a mem-backed file so it can be collected
  // once the container's extracted output exists - extract_tar materializes
  // every member eagerly, and the Samsung .tar.md5 must not keep its ~97MB
  // modem.bin.lz4 pinned underneath the ~190MB lz4 output. Region-backed
  // files keep their source window (release is a no-op for them); reading a
  // released file throws so a stale consumer fails loudly instead of
  // silently seeing empty bytes.
  release() {
    if (this.#memData !== undefined) {
      this.#memData = undefined;
      this.#released = true;
    }
  }
}

// Lazy MemorySource: materializes on first read (only reached when an
// extractor must own bytes of a region-backed file, e.g. lz4 over a tar
// member).
class MemorySourceSync {
  constructor(vfile) {
    this.vfile = vfile;
    this.size = vfile.size;
  }

  async read(offset, length) {
    if (!this.data) this.data = await this.vfile.read();
    if (offset < 0 || length < 0 || offset + length > this.size) {
      throw new RangeError(`short read at ${offset}+${length}/${this.size}`);
    }
    return this.data.subarray(offset, offset + length);
  }

  async close() {}
}

export class VDir {
  constructor(name) {
    this.name = name;
    this.entries = new Map(); // name -> VDir | VFile
  }

  dir(name) {
    let d = this.entries.get(name);
    if (!d) {
      d = new VDir(name);
      this.entries.set(name, d);
    }
    return d;
  }

  // addFile(dir, "a/b.txt", bytesLike) helper used by iphone.js callbacks
  addFile(path, vfile) {
    const parts = path.split("/").filter(Boolean);
    let dir = this;
    for (const part of parts.slice(0, -1)) dir = dir.dir(part);
    dir.entries.set(parts[parts.length - 1], vfile);
  }

  // Pre-order DFS over files; paths are relative to this dir, "/"-separated.
  files(prefix = "") {
    const out = [];
    for (const entry of this.entries.values()) {
      if (entry instanceof VFile) {
        out.push({ vfile: entry, path: prefix + entry.name });
      } else {
        out.push(...entry.files(`${prefix}${entry.name}/`));
      }
    }
    return out;
  }
}

// Sibling workdirs under one root, named `<tag>_<n>`.
class ExtractContext {
  constructor({ wholeBufferLimit = MAX_WHOLE_BUFFER_BYTES } = {}) {
    this.root = new VDir("");
    this.outputs = [];
    this.warnings = [];
    this.counter = 0;
    this.wholeBufferLimit = wholeBufferLimit;
  }

  warnWholeBuffer(tool, name, size) {
    this.warnings.push({
      tool,
      message: `${name}: size ${size} exceeds the ${this.wholeBufferLimit}-byte whole-buffer limit — skipped instead of risking an out-of-memory failure`,
    });
  }

  newWorkdir(tag) {
    const dir = new VDir(`${tag}_${this.counter++}`);
    this.root.entries.set(dir.name, dir);
    return dir;
  }

  addFile(dir, path, data, size, kind) {
    dir.addFile(path, kind === "text" ? VFile.text(path.split("/").pop(), data) : VFile.mem(path.split("/").pop(), data));
  }
}

// --- unwrap recursion -----------------------------------------------------------------

export async function unwrap(vfile, ctx, depth = 0) {
  if (depth > MAX_RECURSION_DEPTH) {
    ctx.warnings.push({ tool: "container", message: `Max recursion depth reached at ${vfile.name}` });
    return;
  }
  if (vfile.size < MIN_CONTAINER_SIZE) return;

  const head = await headOf(vfile);
  const tag = detect(head, vfile.name);

  if (tag === "empty" || tag === "unknown" || tag === "bootimg") {
    // For unrecognized top-level images, scan for known containers hidden
    // behind OEM wrappers.
    if (tag === "unknown" && depth === 0) await unwrapEmbeddedContainers(vfile, ctx, depth);
    return;
  }

  const produced = await extractTagged(vfile, tag, ctx);
  if (produced === null) return;

  if (produced instanceof VDir) {
    ctx.outputs.push(produced);
    for (const { vfile: child } of produced.files()) {
      await maybeUnwrapChild(child, ctx, depth + 1);
    }
  } else {
    await unwrap(produced, ctx, depth + 1);
  }
}

async function maybeUnwrapChild(vfile, ctx, depth) {
  // Files below the container floor cannot unwrap (unwrap would return at its
  // size check) — skip the header read entirely.
  if (vfile.size < MIN_CONTAINER_SIZE) return;
  // Only recurse into children whose magic clearly identifies a container.
  const tag = detect(await headOf(vfile), vfile.name);
  if (SUPPORTED_TAGS.has(tag) || UNSUPPORTED_TAGS[tag]) {
    await unwrap(vfile, ctx, depth);
  }
}

// Scan an unrecognized top-level image for embedded sparse containers.
async function unwrapEmbeddedContainers(vfile, ctx, depth) {
  for (const offset of await scanForSparse(vfile.asSource(), vfile.size)) {
    const workdir = ctx.newWorkdir("sliced");
    const stem = pyStem(vfile.name) || "inner";
    const sliced = VFile.slice(`${stem}.sparse`, vfile.asSource(), offset, vfile.size - offset);
    workdir.addFile(sliced.name, sliced);
    await unwrap(sliced, ctx, depth + 1);
  }
}

// Exported for the header-sniffing unit test: headOf must use vfile.readRange
// (tree-backed files) without ever calling the full-file loader.
export async function headOf(vfile) {
  const n = Math.min(MAGIC_MAX, vfile.size);
  if (n <= 0) return new Uint8Array(0);
  // Prefer a ranged reader (tree-backed files): the 4 KB sniff must not read
  // the whole file. Then a region window (zero-copy slice), then the whole-file
  // fallback (mem/text files, e.g. extracted archive members).
  if (typeof vfile.readRange === "function") return vfile.readRange(0, n);
  if (vfile.region) return vfile.region.source.read(vfile.region.offset, n);
  return (await vfile.read()).subarray(0, n);
}

function pyStem(name) {
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(0, dot) : name;
}

function warnUnsupported(ctx, node, tag) {
  const desc = UNSUPPORTED_TAGS[tag];
  ctx.warnings.push({
    tool: desc.tool ?? tag,
    message: `${node.name}: ${desc.message}`,
  });
}

// --- extractors -------------------------------------------------------------------------

async function extractTagged(vfile, tag, ctx) {
  switch (tag) {
    case "sparse":
      return extractSparse(vfile, ctx);
    case "fat":
    case "fat_or_mbr":
      return extractFat(vfile, tag, ctx);
    case "ext4":
      return extractExt4(vfile, ctx);
    case "gzip":
      return extractGzip(vfile, ctx);
    case "lz4":
      return extractLz4(vfile, ctx);
    case "tar":
      return extractTar(vfile, ctx);
    case "zip":
      return extractZip(vfile, ctx);
    case "bbcfg":
      return extractBbcfg(vfile, ctx);
    default:
      if (UNSUPPORTED_TAGS[tag]) {
        warnUnsupported(ctx, vfile, tag);
        return null;
      }
      return null;
  }
}

// Walks a filesystem image source and places every file into the workdir
// (the tree 7-Zip/debugfs would have produced in the same scratch dir).
async function placeTree(dir, image, label, ctx) {
  try {
    await image.init();
    for (const entry of await image.walk()) {
      // A ranged reader lets headOf sniff the magic without reading the file in
      // full (both images expose readFileRange; the full readFile loader stays
      // for actual content reads).
      dir.addFile(
        entry.path.replace(/^\//, ""),
        new VFile(
          entry.path.split("/").pop(),
          () => image.readFile(entry),
          entry.size,
          null,
          (offset, length) => image.readFileRange(entry, offset, length),
        ),
      );
    }
    return dir;
  } catch (err) {
    ctx.warnings.push({ tool: label, message: `${label} tree walk failed: ${err.message}` });
    return null;
  }
}

// Sparse extraction: the filesystem tree lands directly in the sparse workdir
// (golden radio.img records are `sparse/image/...`). Non-filesystem sparse
// payloads keep their raw image in the workdir for recursive unwrap, like
// simg2img's <stem>.raw output.
async function extractSparse(vfile, ctx) {
  let reader;
  try {
    reader = await SparseReader.open(vfile.asSource(), 0);
  } catch (err) {
    ctx.warnings.push({ tool: "sparse", message: `sparse extraction failed for ${vfile.name}: ${err.message}` });
    return null;
  }
  const dir = ctx.newWorkdir("sparse");
  const inner = detect(await reader.read(0, Math.min(MAGIC_MAX, reader.size)), "");
  if (inner === "ext4") return placeTree(dir, new Ext4Image(reader), "ext4", ctx);
  if (inner === "fat" || inner === "fat_or_mbr") return placeTree(dir, new Fat16Image(reader), inner, ctx);
  const rawName = `${pyStem(vfile.name) || "inner"}.raw`;
  // Raw fallback must be materialized to recurse; skip oversized payloads with a
  // warning rather than allocating the whole (often multi-GB) unsparsed image.
  if (reader.size > ctx.wholeBufferLimit) {
    ctx.warnWholeBuffer("sparse", `${vfile.name} -> ${rawName}`, reader.size);
    return null;
  }
  dir.addFile(rawName, new VFile(rawName, () => streamSource(reader), reader.size, { source: reader, offset: 0, size: reader.size }));
  return dir;
}

// Reads a whole source into memory (used for raw sparse fallbacks that are
// small enough to unwrap further). The caller has already applied the
// whole-buffer size cap.
async function streamSource(source) {
  const out = new Uint8Array(source.size);
  let done = 0;
  while (done < source.size) {
    const n = Math.min(1 << 22, source.size - done);
    out.set(await source.read(done, n), done);
    done += n;
  }
  return out;
}

// FAT extraction via the in-house FAT walk.
async function extractFat(vfile, tag, ctx) {
  const dir = ctx.newWorkdir(tag);
  return placeTree(dir, new Fat16Image(vfile.asSource()), tag, ctx);
}

// ext4 extraction via the in-house walk.
async function extractExt4(vfile, ctx) {
  const dir = ctx.newWorkdir("ext4");
  return placeTree(dir, new Ext4Image(vfile.asSource()), "ext4", ctx);
}

// Gzip extraction: output file named <stem or inner.bin> inside the gzip
// workdir; the FILE is returned so unwrap recurses into it (the workdir
// itself is not an output).
async function extractGzip(vfile, ctx) {
  if (vfile.size > ctx.wholeBufferLimit) {
    ctx.warnWholeBuffer("gzip", vfile.name, vfile.size);
    return null;
  }
  try {
    const data = await gunzipStream(await vfile.read(), ctx.wholeBufferLimit);
    const name = `${pyStem(vfile.name) || "inner.bin"}`;
    const dir = ctx.newWorkdir("gzip");
    const out = VFile.mem(name, data);
    dir.addFile(name, out);
    vfile.release();
    return out;
  } catch (err) {
    ctx.warnings.push({ tool: "gzip", message: `gzip decompress failed for ${vfile.name}: ${err.message}` });
    return null;
  }
}

// Reads a ReadableStream fully but aborts once `cap` bytes accumulate, so a
// decompression bomb / oversized member warns instead of allocating without
// bound. (`Response.arrayBuffer()` would happily try to allocate everything.)
async function readStreamCapped(stream, cap) {
  const reader = stream.getReader();
  const parts = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > cap) throw new Error(`decompressed output exceeds the ${cap}-byte limit`);
      parts.push(value);
    }
  } finally {
    try {
      await reader.cancel();
    } catch {
      // already closed / cancelled
    }
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const part of parts) {
    out.set(part, off);
    off += part.byteLength;
  }
  return out;
}

// Multi-member tolerant gzip via DecompressionStream ("gzip" handles
// concatenated members).
async function gunzipStream(data, cap = MAX_WHOLE_BUFFER_BYTES) {
  const stream = new Blob([data]).stream().pipeThrough(new DecompressionStream("gzip"));
  return readStreamCapped(stream, cap);
}

// LZ4 extraction via the in-house frame decoder. Memory: the Samsung
// member is 101,488,514 bytes compressed and 199,233,005 bytes (~190MB) out.
// Tar members are now region-backed (step 7), so the compressed bytes are read
// on demand here and nothing is materialized before this call; the output is
// the only steady-state allocation.
// (The radio.img sparse is NOT materialized at all - SparseReader resolves
// it chunk-wise.)
async function extractLz4(vfile, ctx) {
  if (vfile.size > ctx.wholeBufferLimit) {
    ctx.warnWholeBuffer("lz4", vfile.name, vfile.size);
    return null;
  }
  try {
    const data = decompressLz4Frame(await vfile.read());
    if (data.length > ctx.wholeBufferLimit) {
      ctx.warnWholeBuffer("lz4", `${vfile.name} (decompressed)`, data.length);
      return null;
    }
    const name = `${pyStem(vfile.name) || "inner.bin"}`;
    const dir = ctx.newWorkdir("lz4");
    const out = VFile.mem(name, data);
    dir.addFile(name, out);
    vfile.release();
    return out;
  } catch (err) {
    ctx.warnings.push({ tool: "lz4", message: `lz4 decompress failed for ${vfile.name}: ${err.message}` });
    return null;
  }
}

// Tar extraction: ustar reader with GNU longname and POSIX PAX ('x'/'g')
// path-override support; extraction failure (bad paths, truncation) returns
// null with a warning.
// Samsung .tar.md5: everything after the 1024-byte end marker (the md5 tail)
// is ignored — the reader stops at the end-of-archive marker.
async function extractTar(vfile, ctx) {
  const out = ctx.newWorkdir("tar");
  try {
    const source = vfile.asSource();
    let pos = 0;
    let pendingName = null;
    let pendingPax = null;
    const globalPax = new Map();
    for (;;) {
      const header = await source.read(pos, 512);
      if (isZeroBlock(header)) break;
      const name = readTarString(header, 0, 100);
      const prefix = readTarString(header, 345, 155);
      const size = readTarSize(header, 124);
      const type = String.fromCharCode(header[156]);
      pos += 512;
      if (type === "L") {
        // GNU long name: the data holds the next member's name.
        pendingName = latinish(await source.read(pos, size));
        pos += Math.ceil(size / 512) * 512;
        continue;
      }
      if (type === "x" || type === "g") {
        // POSIX extended headers: 'x' overrides the NEXT member, 'g' sets
        // defaults for every following one; tarfile merges global + per-member
        // records with the per-member value winning.
        const records = parsePaxRecords(await source.read(pos, size));
        if (type === "x") {
          if (pendingPax === null) pendingPax = new Map();
          for (const [key, value] of records) pendingPax.set(key, value);
        } else {
          for (const [key, value] of records) globalPax.set(key, value);
        }
        pos += Math.ceil(size / 512) * 512;
        continue;
      }
      const pax = new Map(globalPax);
      if (pendingPax !== null) for (const [key, value] of pendingPax) pax.set(key, value);
      pendingPax = null;
      // tarfile applies pax 'path' over the ustar name (GNU longnames fill the
      // name field first, so the override wins there too).
      const ustarName = pendingName ?? (prefix ? `${prefix}/${name}` : name);
      pendingName = null;
      const memberName = tarMemberPath(pax.get("path") ?? ustarName);
      if (type === "0" || type === "\0") {
        // tar is uncompressed: keep members as zero-copy regions of the source
        // instead of materializing each one. The ~97 MB Samsung modem member is
        // then read only if an extractor actually consumes it, and release() is
        // a no-op for region-backed files (nothing was materialized to drop).
        out.addFile(memberName, VFile.slice(memberName.split("/").pop(), source, pos, size));
      } else if (type === "5") {
        let dir = out;
        for (const part of memberName.split("/")) dir = dir.dir(part);
      }
      pos += Math.ceil(size / 512) * 512;
    }
    return out;
  } catch (err) {
    ctx.warnings.push({ tool: "tar", message: `tar extract failed for ${vfile.name}: ${err.message}` });
    return null;
  }
}

// Member paths: absolute paths and ".." escape attempts raise, failing the
// whole extraction; "./" segments are normalized away.
function tarMemberPath(name) {
  if (name.startsWith("/")) throw new Error(`tar member path is absolute: ${name}`);
  const parts = [];
  for (const part of name.split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") throw new Error(`tar member path escapes the destination: ${name}`);
    parts.push(part);
  }
  return parts.join("/");
}

function isZeroBlock(block) {
  for (let i = 0; i < block.length; i++) {
    if (block[i] !== 0) return false;
  }
  return true;
}

function readTarString(header, off, len) {
  let end = off;
  const limit = off + len;
  while (end < limit && header[end] !== 0) end++;
  return String.fromCharCode(...header.subarray(off, end)).trimEnd();
}

// Size-field tolerance: NUL/space-padded octal — leading padding is stripped
// before the digits, and any non-octal remainder raises (GNU base-256 sizes,
// the documented gap, land there too instead of parsing as garbage octal).
function readTarSize(header, off) {
  let i = 0;
  while (i < 12 && (header[off + i] === 0 || header[off + i] === 0x20)) i++;
  let size = 0;
  for (; i < 12; i++) {
    const c = header[off + i];
    if (c === 0 || c === 0x20) break;
    if (c < 0x30 || c > 0x37) throw new Error(`tar size field at ${off} is not octal`);
    size = size * 8 + (c - 0x30);
  }
  return size;
}

// POSIX PAX record payload: "<len> key=value\n" repeated, len counting from
// the first digit through the trailing newline. Malformed records stop the
// scan rather than failing the whole tar (the corpus carries only well-formed
// headers).
function parsePaxRecords(u8) {
  const records = new Map();
  let pos = 0;
  while (pos < u8.length) {
    let space = pos;
    while (space < u8.length && u8[space] !== 0x20) space++;
    if (space === pos || space >= u8.length) break;
    const len = parseInt(latinish(u8.subarray(pos, space)), 10);
    if (!Number.isInteger(len) || len <= space - pos || pos + len > u8.length) break;
    const record = latinish(u8.subarray(space + 1, pos + len));
    const eq = record.indexOf("=");
    if (eq > 0) {
      const value = record.slice(eq + 1);
      records.set(record.slice(0, eq), value.endsWith("\n") ? value.slice(0, -1) : value);
    }
    pos += len;
  }
  return records;
}

function latinish(u8) {
  return String.fromCharCode(...u8.subarray(0, u8.length)).replace(/\0+$/, "");
}

// Zip extraction: central-directory read; when .bbfw members exist only those
// are extracted (IPSW shape), otherwise the full archive.
async function extractZip(vfile, ctx) {
  const out = ctx.newWorkdir("zip");
  try {
    const source = vfile.asSource();
    const entries = await zipEntries(source);
    const basebands = entries.filter((e) => e.name.toLowerCase().endsWith(".bbfw"));
    const selected = basebands.length ? basebands : entries;
    for (const entry of selected) {
      // Encrypted members are refused; never emit ciphertext as payload.
      if (entry.flags & 0x1) {
        ctx.warnings.push({ tool: "zip", message: `${entry.name}: encrypted zip member skipped, password required for extraction` });
        continue;
      }
      // Zip members must be inflated in memory; skip oversized ones with a
      // warning instead of letting the allocation fail.
      if (entry.compressedSize > ctx.wholeBufferLimit || entry.uncompressedSize > ctx.wholeBufferLimit) {
        ctx.warnWholeBuffer("zip", entry.name, Math.max(entry.compressedSize, entry.uncompressedSize));
        continue;
      }
      const data = await zipEntryData(source, entry);
      const path = zipMemberPath(entry.name);
      if (!path) continue; // directory entries
      out.addFile(path, VFile.mem(path.split("/").pop(), data));
    }
    return out;
  } catch (err) {
    ctx.warnings.push({ tool: "zip", message: `zip extraction failed for ${vfile.name}: ${err.message}` });
    return null;
  }
}

// zipfile.extract sanitizes by DROpping "", ".", ".." segments (unlike tar's
// data filter, which raises). Returns "" for pure-directory entries.
function zipMemberPath(name) {
  const parts = [];
  for (const part of name.split("/")) {
    if (!part || part === "." || part === "..") continue;
    parts.push(part);
  }
  return parts.join("/");
}

// EOCD + central directory (with zip64 fallbacks; per-entry inflate happens
// in zipEntryData so only requested members are ever decompressed).
// Exported for apple_ftab.js's bbfw member walk (same central-directory read
// as extractZip — one implementation, no divergence).
export async function zipEntries(source) {
  const maxComment = 22 + 65535;
  const tailSize = Math.min(maxComment, source.size);
  const tail = await source.read(source.size - tailSize, tailSize);
  let eocd = -1;
  for (let i = tail.length - 22; i >= 0; i--) {
    if (tail[i] === 0x50 && tail[i + 1] === 0x4b && tail[i + 2] === 0x05 && tail[i + 3] === 0x06) {
      eocd = i;
      break;
    }
  }
  if (eocd === -1) throw new Error("zip end-of-central-directory not found");
  let entryCount = tail[eocd + 10] | (tail[eocd + 11] << 8);
  let cdStart = u32leAt(tail, eocd + 16);
  // zip64 locator sits 20 bytes before the EOCD; its values win when present.
  if (eocd >= 20 && tail[eocd - 20] === 0x50 && tail[eocd - 19] === 0x4b && tail[eocd - 18] === 0x06 && tail[eocd - 17] === 0x07) {
    const z64 = u64leAt(tail, eocd - 20 + 8);
    const z64Block = await source.read(z64, 56);
    if (u32leAt(z64Block, 0) === 0x06064b50) {
      entryCount = u64leAt(z64Block, 32);
      cdStart = u64leAt(z64Block, 48);
    }
  }
  return zipDirectory(source, cdStart, entryCount);
}

async function zipDirectory(source, start, entryCount) {
  const entries = [];
  let pos = start;
  for (let i = 0; i < entryCount; i++) {
    const h = await source.read(pos, 46);
    if (u32leAt(h, 0) !== 0x02014b50) throw new Error(`corrupt central directory at ${pos}`);
    const flags = h[8] | (h[9] << 8);
    const method = h[10] | (h[11] << 8);
    let compressedSize = u32leAt(h, 20);
    let uncompressedSize = u32leAt(h, 24);
    let localOffset = u32leAt(h, 42);
    const nameLen = h[28] | (h[29] << 8);
    const extraLen = h[30] | (h[31] << 8);
    const name = latinish(await source.read(pos + 46, nameLen));
    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localOffset === 0xffffffff) {
      // zip64 extra field (header id 0x0001) overrides the u32 fields. APPNOTE
      // 4.5.3 fixes the slot order - original (uncompressed) size, compressed
      // size, local header offset, disk start - and a slot exists only when
      // its u32 field carries the 0xFFFFFFFF sentinel.
      const extra = await source.read(pos + 46 + nameLen, extraLen);
      let e = 0;
      while (e + 4 <= extra.length) {
        const id = extra[e] | (extra[e + 1] << 8);
        const sz = extra[e + 2] | (extra[e + 3] << 8);
        if (id === 0x0001) {
          let f = e + 4;
          const end = e + 4 + sz;
          if (uncompressedSize === 0xffffffff && f + 8 <= end) {
            uncompressedSize = u64leAt(extra, f);
            f += 8;
          }
          if (compressedSize === 0xffffffff && f + 8 <= end) {
            compressedSize = u64leAt(extra, f);
            f += 8;
          }
          if (localOffset === 0xffffffff && f + 8 <= end) localOffset = u64leAt(extra, f);
          break;
        }
        e += 4 + sz;
      }
    }
    entries.push({ name, flags, method, compressedSize, uncompressedSize, localOffset });
    pos += 46 + nameLen + extraLen;
  }
  return entries;
}

// Node's handle.read/slice length is a native call: a >=2GiB length aborts the
// process uncatchably, so declared member sizes beyond this cap must throw a
// catchable ExtractionError before any data is read.
const MAX_ZIP_ENTRY_BYTES = 2 ** 31 - 1;

// Exported for apple_ftab.js's bbfw member walk (see zipEntries above).
export async function zipEntryData(source, entry) {
  if (entry.compressedSize > MAX_ZIP_ENTRY_BYTES || entry.uncompressedSize > MAX_ZIP_ENTRY_BYTES) {
    throw new ExtractionError(`${entry.name}: zip member size ${entry.compressedSize}/${entry.uncompressedSize} exceeds the 2GiB extraction cap`);
  }
  const h = await source.read(entry.localOffset, 30);
  if (u32leAt(h, 0) !== 0x04034b50) throw new Error(`corrupt local header for ${entry.name}`);
  const nameLen = h[26] | (h[27] << 8);
  const extraLen = h[28] | (h[29] << 8);
  const dataStart = entry.localOffset + 30 + nameLen + extraLen;
  const compressed = await source.read(dataStart, entry.compressedSize);
  if (entry.method === 0) return compressed;
  if (entry.method === 8) return inflateSync(compressed);
  throw new Error(`unsupported zip method ${entry.method} for ${entry.name}`);
}

// Unsigned little-endian reads; results are exact doubles up to 2^53, so
// composing u32 pairs into u64 (u64leAt) is safe for any zip64 offset.
function u32leAt(u8, off) {
  return u8[off] + u8[off + 1] * 0x100 + u8[off + 2] * 0x10000 + u8[off + 3] * 0x1000000;
}

function u64leAt(u8, off) {
  // lo is unsigned since u32leAt stopped using the int32 `|` coercion; the
  // sum stays exact in doubles (zip64 offsets are far below 2^53).
  const lo = u32leAt(u8, off);
  const hi = u32leAt(u8, off + 4);
  return hi * 0x100000000 + lo;
}

// BBCFG: iphone card recovery + the EFS pathname scan.
async function extractBbcfg(vfile, ctx) {
  if (vfile.size > ctx.wholeBufferLimit) {
    ctx.warnWholeBuffer("bbcfg", vfile.name, vfile.size);
    return null;
  }
  const out = ctx.newWorkdir("bbcfg");
  const blob = await vfile.read();
  let cards = [];
  try {
    cards = await extractBbcfgTree(blob, out, (dir, path, data, size, kind) => ctx.addFile(dir, path, data, size, kind));
  } catch (err) {
    ctx.warnings.push({ tool: "bbcfg", message: `iPhone RF card recovery failed for ${vfile.name}: ${err.message}` });
  }
  let written = 0;
  try {
    written = extractEfsPathnames(blob, out, (dir, path, data) => ctx.addFile(dir, path, data));
  } catch (err) {
    ctx.warnings.push({ tool: "bbcfg", message: `bbcfg EFS scan failed for ${vfile.name}: ${err.message}` });
  }
  return cards.length || written ? out : null;
}

// --- public API -----------------------------------------------------------------------

// Recursively unwrap and return the virtual tree. Hard failures (not a
// file-like source, below the size floor) throw ExtractionError;
// per-container problems accumulate in warnings.
export async function extractContainer(source, name, options = {}) {
  if (typeof source.size !== "number") throw new ExtractionError(`Not a readable source: ${name}`);
  if (source.size < MIN_CONTAINER_SIZE) {
    throw new ExtractionError(`File too small to be a container: ${name}`);
  }
  const ctx = new ExtractContext(options);
  await unwrap(VFile.slice(name, source, 0, source.size), ctx);
  return { root: ctx.root, outputs: ctx.outputs, warnings: ctx.warnings };
}

// Discover candidates over the registered output workdirs ONLY; intermediate
// file staging dirs like gzip_xxx/ are never discovered.
export function discoverCandidates(outputs) {
  const mbns = [];
  const sidecars = [];
  const files = outputs.flatMap((dir) => dir.files(`${dir.name}/`));
  for (const { vfile, path } of files) {
    if (RFCARD_RE.test(vfile.name)) mbns.push({ vfile, path });
    else if (SIDECAR_RES.some((re) => re.test(vfile.name))) sidecars.push({ name: vfile.name, path });
  }
  return { mbns, sidecars };
}

// {name: virtual path} for sidecars sharing the MBN's directory (the browser
// has no filesystem paths, so the virtual tree path stands in).
export function sidecarsInDirectory(mbnPath, sidecars) {
  const parent = mbnPath.slice(0, mbnPath.lastIndexOf("/"));
  const out = {};
  for (const sidecar of sidecars) {
    if (sidecar.path.slice(0, sidecar.path.lastIndexOf("/")) === parent) out[sidecar.name] = sidecar.path;
  }
  return out;
}
