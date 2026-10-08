// Apple baseband RF-card recovery from BBCFG containers plus the EFS
// pathname scan that the bbcfg extractor runs inline.
//
// BER tag guard: the tag-is-multibyte check is intentionally `blob[pos] & 1`
// (odd low bit), NOT `& 0x1F`: single-byte tags with odd values (e.g. the
// 0xA9 blob-store tag) are parsed as multi-byte tags and never match, so
// real containers take the MAVZ byte-scan fallback.
import { Elf32Image } from "./elf.js";
import { rfcardNameFromSymbols } from "./legacy_parser.js";
import { sha256Hex } from "./hash.js";
import { inflateZlibChecked } from "./modern_parser.js";

export class IPhoneRFError extends Error {
  constructor(message) {
    super(message);
    this.name = "IPhoneRFError";
  }
}

const BBCFG_MARKER = [0x42, 0x42, 0x43, 0x46, 0x47, 0x4d, 0x42, 0x4e, 0x30]; // BBCFGMBN0
const KNOWN_FOURCC = [[0x00, 0x47, 0x46, 0x43], [0x00, 0x57, 0x4f, 0x50]]; // \x00GFC, \x00WOP
const RECORDS_START = 0x28;
const STORE_TAG = "a9";
const NAME_TAG = "9f64";
const PAYLOAD_TAG = "9f65";
const EFS_PATH_TAG = [0x9f, 0x83, 0x74];
const EFS_VALUE_TAG = [0x9f, 0x83, 0x76];
const MAVZ_MAGIC = [0x4d, 0x41, 0x56, 0x5a]; // MAVZ
const ELF32_MAGIC = [0x7f, 0x45, 0x4c, 0x46, 0x01, 0x01];

function regionEquals(blob, offset, bytes) {
  if (blob.length < offset + bytes.length) return false;
  for (let i = 0; i < bytes.length; i++) {
    if (blob[offset + i] !== bytes[i]) return false;
  }
  return true;
}

function u32le(blob, pos) {
  return blob[pos] | (blob[pos + 1] << 8) | (blob[pos + 2] << 16) | (blob[pos + 3] * 0x1000000);
}

// Latin-1 decode: bijective byte <-> char mapping so string offsets are byte
// offsets and byte-oriented regexes work directly on strings.
export function latin1(u8, start = 0, end = u8.length) {
  let s = "";
  const CHUNK = 0x8000;
  for (let i = start; i < end; i += CHUNK) {
    s += String.fromCharCode.apply(null, u8.subarray(i, Math.min(i + CHUNK, end)));
  }
  return s;
}

function indexOfBytes(hay, needle, from = 0, to = hay.length) {
  outer: for (let i = Math.max(0, from); i <= Math.min(to, hay.length) - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (hay[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

// latin1 string regexes for the res/cmn DAT paths; \d matches ASCII digits
// and the search semantics (first match) are identical.
const RES_DAT_RE = /\/rfc\/(\d+)_(\d+)_res\.dat/;
const CMN_DAT_RE = /\/rfc\/(\d+)_(\d+)_cmn\.dat/;
const LEGACY_RFCARD_RE = /^rfc_hwid(\d+)(?:_|$)/i;
const CONTENT_NAME_RE = /[0-9a-f]{40}/g;

// --- BER helpers -----------------------------------------------------------------

export function readTlv(blob, pos) {
  const start = pos;
  if (blob[pos] === undefined) throw new IPhoneRFError("BER tag out of range");
  // Deliberate quirk: the tag check is `& 1`, not `& 0x1F` (see file header
  // note).
  if ((blob[pos] & 1) === 1) {
    pos += 1;
    while (blob[pos] !== undefined && (blob[pos] & 0x80) !== 0) pos += 1;
    if (blob[pos] === undefined) throw new IPhoneRFError("BER tag out of range");
  }
  pos += 1;
  let tag = "";
  for (let i = start; i < pos; i++) tag += blob[i].toString(16).padStart(2, "0");
  let length = blob[pos];
  if (length === undefined) throw new IPhoneRFError("BER length out of range");
  pos += 1;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (!(1 <= count && count <= 4)) throw new IPhoneRFError(`unsupported BER length form at 0x${start.toString(16)}`);
    if (pos + count > blob.length) throw new IPhoneRFError("BER length out of range");
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + blob[pos + i];
    pos += count;
  }
  return { tag, length, body: pos };
}

// Yields { tag, offset, length, body } for [start, end).
function* walkTlv(blob, start, end) {
  let pos = start;
  while (pos < end) {
    const { tag, length, body } = readTlv(blob, pos);
    if (body + length > end) throw new IPhoneRFError(`record at 0x${pos.toString(16)} overruns its container`);
    yield { tag, offset: pos, length, body };
    pos = body + length;
  }
}

// --- container access --------------------------------------------------------------

export function isBbcfg(blob) {
  return blob.length >= 0x31 && regionEquals(blob, 0x28, BBCFG_MARKER);
}

export function containerInfo(blob, sha256 = null) {
  if (!isBbcfg(blob)) throw new IPhoneRFError("not an Apple BBCFG container (no BBCFGMBN0 marker)");
  const fourcc = latin1(blob, 0, 4);
  const version = u32le(blob, 4);
  const declared = u32le(blob, 0x14);
  return { fourcc, version, payload_size: declared, size: blob.length, sha256 };
}

// (start, end) of the tag-0xA9 store body, or null. Because of the tag quirk
// the store record never matches on real firmware and the MAVZ scan below is
// the effective path.
function storeBounds(blob) {
  try {
    for (const rec of walkTlv(blob, RECORDS_START, blob.length)) {
      if (rec.tag === STORE_TAG) return [rec.body, rec.body + rec.length];
    }
  } catch (err) {
    if (err instanceof IPhoneRFError) return null;
    throw err;
  }
  return null;
}

export function iterStoreBlobs(blob) {
  const bounds = storeBounds(blob);
  if (bounds === null) return [...scanMavzBlobs(blob)];
  const out = [];
  let index = 0;
  for (const rec of walkTlv(blob, bounds[0], bounds[1])) {
    let name = null;
    let payload = null;
    for (const child of walkTlv(blob, rec.body, rec.body + rec.length)) {
      if (child.tag === NAME_TAG) name = latin1(blob, child.body, child.body + child.length);
      else if (child.tag === PAYLOAD_TAG) payload = { body: child.body, length: child.length };
    }
    if (payload === null) {
      index += 1;
      continue;
    }
    out.push({ index, offset: rec.offset, name: name ?? "", payloadOffset: payload.body, payloadLen: payload.length });
    index += 1;
  }
  return out;
}

// MAVZ payloads without the record grammar.
function* scanMavzBlobs(blob) {
  let index = 0;
  let pos = 0;
  for (;;) {
    const offset = indexOfBytes(blob, MAVZ_MAGIC, pos);
    if (offset === -1) break;
    const window = latin1(blob, Math.max(0, offset - 300), offset);
    const names = [...window.matchAll(CONTENT_NAME_RE)];
    const name = names.length ? names[names.length - 1][0] : "";
    yield { index: index++, offset, name, payloadOffset: offset, payloadLen: blob.length - offset };
    pos = offset + 1;
  }
}

// MAVZ decompression: the adler32 trailer is consumed and verified;
// unused_data is everything after the stream. inflateZlibChecked
// (modern_parser.js) provides exactly that.
export function decompressMavz(blob, offset) {
  const declared = u32le(blob, offset + 4);
  const data = blob.subarray(offset + 8);
  const { raw, consumed } = inflateZlibChecked(data);
  if (raw.length !== declared) {
    throw new IPhoneRFError(`MAVZ at 0x${offset.toString(16)}: ${raw.length} bytes != declared ${declared}`);
  }
  const compressedLen = consumed;
  return { raw, compressedLen };
}

// --- RF card recovery ----------------------------------------------------------------

function legacyRfcardIdentity(raw) {
  if (!regionEquals(raw, 0, ELF32_MAGIC)) return null;
  let cardName;
  try {
    cardName = rfcardNameFromSymbols(new Elf32Image(raw));
  } catch {
    return null;
  }
  if (cardName === null) return null;
  const match = LEGACY_RFCARD_RE.exec(cardName);
  if (match === null) return null;
  return [parseInt(match[1], 10), cardName];
}

export function* iterRfcards(blob) {
  let ordinal = 0;
  for (const { index, name, payloadOffset } of iterStoreBlobs(blob)) {
    if (!regionEquals(blob, payloadOffset, MAVZ_MAGIC)) continue;
    let raw;
    let compressedLen;
    try {
      ({ raw, compressedLen } = decompressMavz(blob, payloadOffset));
    } catch {
      continue;
    }
    const res = RES_DAT_RE.exec(latin1(raw));
    const cmn = res ? CMN_DAT_RE.exec(latin1(raw)) : null;
    let hwid;
    let fset;
    let filename;
    let generation;
    let rfcardName;
    let fsetIsSynthetic;
    if (res) {
      hwid = parseInt(res[1], 10);
      fset = parseInt(res[2], 10);
      filename = `rf_config_${hwid}_${fset}_${ordinal}.mbn`;
      generation = "DAT/protobuf";
      rfcardName = null;
      fsetIsSynthetic = false;
    } else {
      const identity = legacyRfcardIdentity(raw);
      if (identity === null) continue;
      hwid = identity[0];
      rfcardName = identity[1];
      fset = 0;
      filename = `${hwid}_${fset}_${ordinal}.mbn`;
      generation = "Legacy ELF";
      fsetIsSynthetic = true;
    }
    yield {
      ordinal,
      hwid,
      fset,
      syntheticBid: ordinal,
      filename,
      bbcfgOffset: payloadOffset,
      storeIndex: index,
      contentName: name,
      compressedLen,
      rawSize: raw.length,
      sha256: sha256Hex(raw),
      generation,
      rfcardName,
      fsetIsSynthetic,
      resDat: res ? res[0] : null,
      cmnDat: cmn ? cmn[0] : null,
      raw,
    };
    ordinal += 1;
  }
}

// --- extraction -----------------------------------------------------------------------

// Cards land in outDir/rfcards/ next to the rfcard_info_all sidecars (which
// the analyzer's sidecar scan then attaches per record).
export async function extractBbcfgTree(blob, outDir, addFile) {
  const rfcards = outDir.dir("rfcards");
  const cards = [];
  for (const card of iterRfcards(blob)) {
    addFile(rfcards, card.filename, card.raw, card.rawSize);
    cards.push(card);
  }
  if (cards.length) {
    // sha256Hex is async; the analyzer computes the authoritative per-record
    // digests itself, this only fills the rfcard_info_all sidecar rows.
    for (const card of cards) card.sha256 = await sha256Hex(card.raw);
    await writeSidecars(cards, rfcards, blob, addFile);
  }
  return cards;
}

function asRow(card) {
  return {
    ordinal: card.ordinal,
    hwid: card.hwid,
    fset: card.fset,
    synthetic_bid: card.syntheticBid,
    filename: card.filename,
    bbcfg_offset: `0x${card.bbcfgOffset.toString(16).padStart(8, "0")}`,
    store_index: card.storeIndex,
    content_name: card.contentName,
    compressed_len: card.compressedLen,
    raw_size: card.rawSize,
    sha256: card.sha256,
    generation: card.generation,
    rfcard_name: card.rfcardName,
    fset_is_synthetic: card.fsetIsSynthetic,
    res_dat: card.resDat,
    cmn_dat: card.cmnDat,
  };
}

async function writeSidecars(cards, rfcardsDir, blob, addFile) {
  const rows = cards.map(asRow);
  // CSV: QUOTE_MINIMAL, \r\n terminator.
  const fields = Object.keys(rows[0]);
  const cell = (v) => {
    let s = v === null || v === undefined ? "" : String(v);
    if (/[",\r\n]/.test(s)) s = `"${s.replaceAll('"', '""')}"`;
    return s;
  };
  const csv = [fields.join(",")].concat(rows.map((r) => fields.map((f) => cell(r[f])).join(","))).join("\r\n") + "\r\n";
  addFile(rfcardsDir, "rfcard_info_all.csv", csv, undefined, "text");
  const info = JSON.stringify(
    {
      source: "",
      container: containerInfo(blob, sha256Hex(blob)),
      bid_note: "synthetic_bid is this tool's ordinal, not a value read from the firmware; Apple RF cards carry no BID",
      legacy_fset_note: "fset is synthesised as zero for legacy ELF cards; use rfcard_name for their full generated identity",
      cards: rows,
    },
    (key, value) => (typeof value === "bigint" ? value.toString() : value),
    2,
  );
  addFile(rfcardsDir, "rfcard_info_all.json", info, undefined, "text");
}

// EFS pathname/value scan (tags 9f8374/9f8376) run after card recovery; it
// writes into the bbcfg workdir root and does not dedup.
export function extractEfsPathnames(blob, outDir, addFile) {
  let written = 0;
  let pos = 0;
  for (;;) {
    const idx = indexOfBytes(blob, EFS_PATH_TAG, pos);
    if (idx === -1) break;
    const path = berLength(blob, idx + 3);
    if (path.length === null) {
      pos = idx + 3;
      continue;
    }
    let name;
    try {
      name = new TextDecoder("utf-8", { fatal: true })
        .decode(blob.subarray(path.body, path.body + path.length))
        .replace(/^\x00+|\x00+$/g, "");
    } catch {
      pos = idx + 3;
      continue;
    }
    const valueIdx = indexOfBytes(blob, EFS_VALUE_TAG, path.body + path.length, path.body + path.length + 64);
    if (valueIdx === -1) {
      pos = path.body + path.length;
      continue;
    }
    const value = berLength(blob, valueIdx + 3);
    if (value.length === null) {
      pos = idx + 3;
      continue;
    }
    const rel = name.replace(/^\/+/, "");
    if (!rel || rel.split("/").includes("..")) {
      // An EFS pathname is attacker-controlled data; never escape the scratch dir.
      pos = value.body + value.length;
      continue;
    }
    addFile(outDir, rel, blob.subarray(value.body, value.body + value.length), value.length);
    written += 1;
    pos = value.body + value.length;
  }
  return written;
}

function berLength(blob, pos) {
  if (pos >= blob.length) return { length: null, body: pos };
  const first = blob[pos];
  if (first < 0x80) return { length: first, body: pos + 1 };
  const count = first & 0x7f;
  if (!(1 <= count && count <= 4)) return { length: null, body: pos };
  const start = pos + 1;
  if (start + count > blob.length) return { length: null, body: pos };
  let length = 0;
  for (let i = 0; i < count; i++) length = length * 256 + blob[start + i];
  return { length, body: start + count };
}
