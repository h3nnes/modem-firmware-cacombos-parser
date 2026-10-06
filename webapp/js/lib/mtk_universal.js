// Stage-A + Stage-B port of mtk-drdi-combo-parser/mtk_universal.py:
// module constants, Reporter, ROM dictionary discovery, Image/Bank records,
// GridLoader (modern 12-byte descriptor matrix), FlatLoader (MD800 legacy
// pointer-run family) and TensorCdfLoader (split CDF) from Stage A; from
// Stage B the shared combo row model, the grammar parser
// (CandidateNode/descriptor decode), FeatureResolver, profile decode, the
// LTE CA row-table scanners, supported-band lists and the Tensor secondary
// bank-8 decoder (mtk_tensor_secondary.py). Scan orchestration lives in
// mtk_scan.js; the NR15 family (mtk_nr15.py) lives in mtk_nr15.js.
//
// Scalar loops only (no numpy); the numpy prefilter variants of the python
// collapse into the same bounds-checked scalar scans.
//
// Injection seams (stable API for Stage B):
// - loader.capabilityBank(prove): `prove(image)` must return the candidate
//   count (>= 1) when the image contains a structurally valid CandidateNode
//   array, or null when the grammar rejects it (python's find_candidate_array
//   raising UniversalError). Stage B installs it as
//   (im) => { try { return parser.findCandidateArray(im)[2].count; } catch { return null; } }.
//   capabilityBank() without a hook throws a dedicated configuration error.
// - TensorCdfLoader creation is async (SHA-384 slot digests via crypto.subtle):
//   use `await TensorCdfLoader.create(rom, header, data, rep)`.
import { indexOfBytes, hex as toHex } from "./bytes.js";
import { sha384HexAsync } from "./mtk_hash.js";

export const VERSION = "0.4-universal";

// Two bandwidth-enum families are proven in the corpus. They are disjoint at
// index 10 (100 vs 90), so a hit is never ambiguous. A third family must be
// added here explicitly -- the tool refuses to extrapolate an enum it has not
// seen, because a wrong bandwidth dictionary produces plausible-looking but
// wrong output, which is the exact failure mode this project treats as worst.
export const BW_FAMILIES = {
  modern20: [5, 10, 15, 20, 25, 30, 40, 50, 60, 80, 100, 200, 400, 35, 45, 70, 90, 800, 1600, 2000],
  legacy14: [5, 10, 15, 20, 25, 30, 40, 50, 60, 80, 90, 100, 200, 400],
  // NR15 (MT6833/MT6877) firmware stores the enum as (index, u16 bandwidth)
  // pairs with a count terminator instead of a plain u16 run, so a plain
  // nr15_13 match can only succeed where the terminator byte holds — it can
  // never collide with a modern20/legacy14 site (their 14th entry is nonzero).
  nr15_13: [5, 10, 15, 20, 25, 30, 40, 50, 60, 80, 100, 200, 400],
};
export const BW20 = BW_FAMILIES.modern20;

export const LTE_WEIGHT_PREFIX = new Uint8Array([1, 2, 2, 3, 4, 5]);
export const NR_WEIGHT_PREFIX = new Uint8Array([1, 2, 2, 3, 4, 2, 3, 4, 5, 6, 7, 8]);
export const LTE_WEIGHTS_EXPECTED = [1, 2, 2, 3, 4, 5];
export const BANDMAP_PREFIX = (() => {
  const out = [];
  for (let i = 0; i < 49; i++) out.push(i);
  for (let i = 65; i < 72; i++) out.push(i);
  return new Uint8Array(out);
})();
export const BANDMAP_LEN = 96;
export const MAX_CLASS_WEIGHT = 32; // no observed class aggregates more than 32 carriers
export const MAX_LTE_BAND = 90; // highest real entry in every observed band map
// Entry 0 of a FeatureObj table is an "unsupported" object: mimo_status == 3.
// This literal is only the modern spelling of it (bandwidth code 0x14 is one
// past a 20-entry enum); MD800 writes 03 0d 01 instead. Used as a cheap
// prefilter for modern bank selection only -- never as the universal anchor.
export const FEATURE_SENTINEL = new Uint8Array([0x03, 0x14, 0x01]);
export const SCS = { 0: 15, 1: 30, 2: 60, 3: 120, 4: 240 };
export const DL_MIMO = { 0: 2, 1: 4, 2: 8 };
export const UL_MIMO = { 0: 1, 1: 2, 2: 4 };
export const LTE_UL_ABSENT = 6;
export const NR_UL_ABSENT_CANON = 0x1c; // value the shared exporter expects; see RomTables.nr_ul_absent
export const VA_LO = 0x60000000; // DRDI runtime address window (all solved devices)
export const VA_HI = 0x80000000;
export const SUPPORTED_BAND_SLOTS = 40;
export const SUPPORTED_BAND_PAD = 0xfffd;

const hex = (n) => "0x" + n.toString(16);

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

export function findAll(buf, pat, limit = null) {
  const out = [];
  let start = 0;
  for (;;) {
    const p = indexOfBytes(buf, pat, start);
    if (p < 0) break;
    out.push(p);
    if (limit !== null && out.length >= limit) break;
    start = p + 1;
  }
  return out;
}

// np.frombuffer(buf, "<u4", count=len//4): little-endian words from `offset`.
// Aligned views on little-endian platforms borrow the underlying buffer;
// anything else falls back to an explicit byte-compose copy.
export function wordsOf(buf, offset = 0, count = Math.floor((buf.length - offset) / 4)) {
  if (count <= 0) return new Uint32Array(0);
  if (LITTLE_ENDIAN) {
    if ((buf.byteOffset + offset) % 4 === 0) {
      return new Uint32Array(buf.buffer, buf.byteOffset + offset, count);
    }
    const copy = new Uint8Array(count * 4);
    copy.set(buf.subarray(offset, offset + count * 4));
    return new Uint32Array(copy.buffer);
  }
  const out = new Uint32Array(count);
  for (let i = 0; i < count; i++) out[i] = u32(buf, offset + i * 4);
  return out;
}

export function packU32(v) {
  return new Uint8Array([v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]);
}

// NR15 firmware's indexed bandwidth-enum spelling: (index, u16 bandwidth)
// pairs followed by the entry count as a u32 terminator.
export function nr15Pattern() {
  const tbl = BW_FAMILIES.nr15_13;
  const pat = new Uint8Array(tbl.length * 4 + 4);
  tbl.forEach((bw, i) => {
    pat[i * 4] = i;
    pat[i * 4 + 2] = bw & 0xff;
    pat[i * 4 + 3] = (bw >>> 8) & 0xff;
  });
  pat[tbl.length * 4] = tbl.length;
  return pat;
}

// Little-endian word views for hot scalar scans. Typed arrays use the
// platform byte order, so guard once; unaligned subarray offsets fall back
// to the byte-compose u32().
const LITTLE_ENDIAN = (() => {
  const b = new ArrayBuffer(4);
  new Uint32Array(b)[0] = 1;
  return new Uint8Array(b)[0] === 1;
})();

function alignedWords32(u8) {
  if (!LITTLE_ENDIAN || u8.byteOffset % 4 !== 0) return null;
  return new Uint32Array(u8.buffer, u8.byteOffset, u8.length >> 2);
}

export class UniversalError extends Error {
  constructor(message) {
    super(message);
    this.name = "UniversalError";
  }
}

export class CheckError extends UniversalError {}

export class Issue {
  constructor(level, code, message, context = {}) {
    this.level = level;
    this.code = code;
    this.message = message;
    this.context = context;
  }
}

const formatPyValue = (v) => {
  if (typeof v === "string") return `'${v}'`;
  if (typeof v === "boolean") return v ? "True" : "False";
  if (v === null || v === undefined) return "None";
  if (v instanceof Uint8Array) {
    // Python bytes repr: printable ASCII literal, everything else \xNN.
    let out = "b'";
    for (const byte of v) {
      if (byte === 0x5c) out += "\\\\";
      else if (byte === 0x27) out += "\\'";
      else if (byte >= 0x20 && byte < 0x7f) out += String.fromCharCode(byte);
      else out += "\\x" + byte.toString(16).padStart(2, "0");
    }
    return out + "'";
  }
  if (Array.isArray(v)) return `[${v.map(formatPyValue).join(", ")}]`;
  return String(v);
};
const formatPyDict = (obj) =>
  "{" + Object.entries(obj).map(([k, v]) => `'${k}': ${formatPyValue(v)}`).join(", ") + "}";

export class Reporter {
  constructor() {
    this.issues = [];
    this.checks = [];
  }
  info(code, msg, ctx = {}) { this.issues.push(new Issue("info", code, msg, ctx)); }
  warn(code, msg, ctx = {}) { this.issues.push(new Issue("warning", code, msg, ctx)); }
  fail(code, msg, ctx = {}) { this.issues.push(new Issue("error", code, msg, ctx)); }
  check(name, passed, data = {}) {
    this.checks.push({ name, passed: Boolean(passed), ...data });
    if (!passed) throw new CheckError(`check failed: ${name}: ${formatPyDict(data)}`);
  }
  asDict() {
    return {
      issues: this.issues.map((x) => ({ level: x.level, code: x.code, message: x.message, context: x.context })),
      checks: this.checks,
    };
  }
}

// ---------------------------------------------------------------------------

export class RomTables {
  constructor(bw, nrWeights, lteWeights, lteBandMap, bwOff, nrWeightsOff, lteWeightsOff, bandMapOff, { bwFamily = "modern20", bandMapOffAlternatives = [] } = {}) {
    this.bw = bw;
    this.nr_weights = nrWeights;
    this.lte_weights = lteWeights;
    this.lte_band_map = lteBandMap;
    this.bw_off = bwOff;
    this.nr_weights_off = nrWeightsOff;
    this.lte_weights_off = lteWeightsOff;
    this.band_map_off = bandMapOff;
    this.bw_family = bwFamily;
    this.band_map_off_alternatives = bandMapOffAlternatives;
  }

  // UL-class byte values meaning "this component carries no uplink".
  // Firmware-dependent, and never to be hardcoded: 0x1c on modern Dimensity,
  // additionally 0xff on Tensor, 0x11 on the MD800 legacy family. The rule
  // that generalises is structural rather than numeric -- a UL byte with no
  // weight in the discovered NR class table cannot denote carriers, so it
  // must be an absent marker. The claim is then *proved* per profile by the
  // UL feature-closure check in FeatureResolver (Stage B).
  get nr_ul_absent() {
    const w = this.nr_weights;
    const out = new Set();
    for (let v = 0; v < 256; v++) if (v >= w.length || w[v] === 0) out.add(v);
    return out;
  }

  asDict() {
    const d = {
      bw: [...this.bw],
      nr_weights: [...this.nr_weights],
      lte_weights: [...this.lte_weights],
      lte_band_map: [...this.lte_band_map],
      bw_off: hex(this.bw_off),
      nr_weights_off: hex(this.nr_weights_off),
      lte_weights_off: hex(this.lte_weights_off),
      band_map_off: hex(this.band_map_off),
      bw_family: this.bw_family,
      band_map_off_alternatives: this.band_map_off_alternatives.map(hex),
    };
    d.nr_class_table_len = this.nr_weights.length;
    d.nr_ul_absent_low_values = [...this.nr_ul_absent].filter((v) => v < 64).sort((a, b) => a - b).slice(0, 12);
    return d;
  }
}

// Locate every occurrence of a known bandwidth enum family.
export function bwSites(rom) {
  const out = [];
  for (const [fam, tbl] of Object.entries(BW_FAMILIES)) {
    const pat = new Uint8Array(tbl.length * 2);
    for (let i = 0; i < tbl.length; i++) {
      pat[i * 2] = tbl[i] & 0xff;
      pat[i * 2 + 1] = (tbl[i] >>> 8) & 0xff;
    }
    for (const o of findAll(rom, pat)) {
      // A short family must be terminated, otherwise we would clip a
      // longer table that merely shares a prefix.
      if (tbl.length < 20) {
        if (o + pat.length + 2 > rom.length || u16(rom, o + pat.length) !== 0) continue;
      }
      out.push([fam, o, tbl]);
    }
  }
  // NR15 firmware stores the enum as (index, u16 bandwidth) pairs; only
  // consult that spelling when no plain u16 family matched anywhere.
  if (!out.length) {
    const tbl = BW_FAMILIES.nr15_13;
    for (const o of findAll(rom, nr15Pattern())) out.push(["nr15_13", o, tbl]);
  }
  return out;
}

// Read the NR class-weight table without assuming a terminator byte.
// Modern firmware ends the table with 0xff. The MD800 legacy family does
// not -- it simply runs into unrelated data. The portable rule is that a
// class weight is a small carrier count, so the table ends at the first byte
// that cannot be one. Interior zeros are kept: they are unused class slots,
// and dropping them would shift every later class index.
export function readNrWeights(rom, off, cap = 96) {
  const vals = [];
  for (let i = 0; i < cap; i++) {
    if (off + i >= rom.length) break;
    const b = rom[off + i];
    if (b === 0xff || b > MAX_CLASS_WEIGHT) break;
    vals.push(b);
  }
  while (vals.length > NR_WEIGHT_PREFIX.length && vals[vals.length - 1] === 0) {
    // Trailing zeros carry no information; keeping the table minimal makes
    // "no weight" and "index out of range" the same statement.
    vals.pop();
  }
  return vals;
}

export function lteWeightSites(rom) {
  return findAll(rom, LTE_WEIGHT_PREFIX).filter(
    (o) => o + 8 <= rom.length && rom[o + 6] === 0 && (rom[o + 7] === 0 || rom[o + 7] === 0xff),
  );
}

export function bandMapSites(rom) {
  return findAll(rom, BANDMAP_PREFIX).filter((o) => {
    if (o + BANDMAP_LEN > rom.length) return false;
    // Byte 95 terminates the map. Both 0x00 and 0xff are observed.
    return rom[o + BANDMAP_LEN - 1] === 0 || rom[o + BANDMAP_LEN - 1] === 0xff;
  });
}

function prefixMatches(vals, prefix) {
  if (vals.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) if (vals[i] !== prefix[i]) return false;
  return true;
}

function eq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// Discover and validate the ROM dictionaries without device offsets.
export function discoverRomTables(rom, rep) {
  const bws = bwSites(rom);
  if (!bws.length) {
    throw new UniversalError(
      "no known MTK bandwidth enum found in md1rom. Known families: "
      + Object.entries(BW_FAMILIES).map(([k, v]) => `${k}(${v.length} entries)`).join(", ")
      + ". A new family must be added explicitly rather than inferred.",
    );
  }
  const fams = [...new Set(bws.map(([f]) => f))].sort();
  if (fams.length > 1) {
    throw new UniversalError("md1rom matches more than one bandwidth enum family: [" + fams.map((f) => `'${f}'`).join(", ") + "]");
  }

  const maps = bandMapSites(rom);
  if (!maps.length) throw new UniversalError("no validated 96-byte LTE internal-band map found in md1rom");
  const ltes = lteWeightSites(rom);
  const nrs = new Set(findAll(rom, NR_WEIGHT_PREFIX));
  if (!nrs.size) throw new UniversalError("NR class-weight prefix 1,2,2,3,4,2,3,4,5,6,7,8 not found in md1rom");

  // Pick the bandwidth site whose surroundings resolve into a complete,
  // self-consistent dictionary. Distance is only a tiebreak, never a gate:
  // the observed enum-to-map distance ranges from 0x378 to 0xe93c.
  const errors = [];
  for (const [fam, bwOff, tbl] of bws) {
    const bwEnd = bwOff + 2 * tbl.length;
    // NR weights sit immediately after the enum on Tensor/Oppo/17T-Pro, or
    // eight bytes past a detached LTE table on 17T/Poco/Samsung/MD800.
    let nrOff = null;
    const adj = ltes.filter((l) => nrs.has(l + 8));
    if (nrs.has(bwEnd)) nrOff = bwEnd;
    else if (adj.length === 1) nrOff = adj[0] + 8;
    else if (nrs.size === 1) nrOff = [...nrs][0];
    else if (adj.length) {
      let best = adj[0];
      for (const l of adj) if (Math.abs(l - bwOff) < Math.abs(best - bwOff)) best = l;
      nrOff = best + 8;
    }
    if (nrOff === null) {
      errors.push(`${fam}@${hex(bwOff)}: could not disambiguate ${nrs.size} NR class-weight candidates`);
      continue;
    }
    let lteOff;
    if (ltes.includes(nrOff - 8)) lteOff = nrOff - 8;
    else if (ltes.length === 1) lteOff = ltes[0];
    else if (ltes.length) {
      lteOff = ltes[0];
      for (const o of ltes) if (Math.abs(o - bwOff) < Math.abs(lteOff - bwOff)) lteOff = o;
    } else {
      errors.push(`${fam}@${hex(bwOff)}: no validated LTE class-weight table`);
      continue;
    }

    const nrw = readNrWeights(rom, nrOff);
    const ltew = Array.from(rom.subarray(lteOff, lteOff + 6));
    const bw = tbl.slice();
    if (nrw.length < NR_WEIGHT_PREFIX.length || !prefixMatches(nrw, NR_WEIGHT_PREFIX)) {
      errors.push(`${fam}@${hex(bwOff)}: NR weights failed prefix validation: (${nrw.slice(0, 16).join(", ")})`);
      continue;
    }
    if (!eq(ltew, LTE_WEIGHTS_EXPECTED)) {
      errors.push(`${fam}@${hex(bwOff)}: LTE class weights invalid: (${ltew.join(", ")})`);
      continue;
    }

    // Band map: prefer the copy nearest the enum. The copies are NOT
    // identical -- on Xiaomi 17T the far copy stores 252..255 where the
    // near copy stores 0 at indices 56..59, and 252..255 are reserved
    // markers rather than bands. The near copy keeps those slots
    // rejectable; MAX_LTE_BAND rejects them either way.
    const ordered = maps.slice().sort((a, b) => Math.abs(a - bwOff) - Math.abs(b - bwOff));
    const mapOff = ordered[0];
    const bandmap = Array.from(rom.subarray(mapOff, mapOff + BANDMAP_LEN));

    rep.info("rom_tables", "discovered and validated ROM dictionaries", {
      bw_family: fam,
      bw_entries: bw.length,
      bw_off: hex(bwOff),
      nr_weights_off: hex(nrOff),
      lte_weights_off: hex(lteOff),
      band_map_off: hex(mapOff),
      nr_class_table_len: nrw.length,
      band_map_alternatives: ordered.slice(1).map(hex),
      enum_to_map_distance: hex(Math.abs(mapOff - bwOff)),
    });
    return new RomTables(bw, nrw, ltew, bandmap, bwOff, nrOff, lteOff, mapOff, {
      bwFamily: fam,
      bandMapOffAlternatives: ordered.slice(1),
    });
  }
  throw new UniversalError("no bandwidth-enum site produced a complete dictionary: " + errors.join("; "));
}

// ---------------------------------------------------------------------------

export class Image {
  constructor(bankVa, profile, sourceOffset, length, relocation, drdi, label = "", alias = 0, candidateHint = null) {
    this.bank_va = bankVa;
    this.profile = profile;
    this.source_offset = sourceOffset;
    this.length = length;
    this.relocation = relocation;
    this.drdi = drdi;
    this.label = label;
    this.alias = alias;
    this.candidate_hint = candidateHint;
  }

  get end_source() { return this.source_offset + this.length; }
  get end_va() { return this.bank_va + this.length; }

  // Runtime pointers may carry a loader-defined alias (Tensor uses 0x60000000).
  resolve(va, size = 1) {
    const raw = this.alias && va >= this.alias ? va - this.alias : va;
    const off = raw - this.relocation;
    if (this.source_offset <= off && off + size <= this.end_source) return off;
    return null;
  }

  containsVa(va, size = 1) { return this.resolve(va, size) !== null; }

  read(va, size) {
    const o = this.resolve(va, size);
    return o === null ? null : this.drdi.subarray(o, o + size);
  }

  u32(va) {
    const o = this.resolve(va, 4);
    return o === null ? null : u32(this.drdi, o);
  }

  u16(va) {
    const o = this.resolve(va, 2);
    return o === null ? null : u16(this.drdi, o);
  }

  toDict() {
    return {
      bank_va: hex(this.bank_va),
      profile: this.profile,
      source_offset: hex(this.source_offset),
      length: this.length,
      relocation: hex(this.relocation),
      alias: hex(this.alias),
      label: this.label,
    };
  }
}

export class Bank {
  constructor(bankVa, images, tableIndex = -1) {
    this.bank_va = bankVa;
    this.images = images;
    this.table_index = tableIndex;
  }

  get live_profiles() { return this.images.map((x) => x.profile); }

  toDict() {
    return {
      table_index: this.table_index,
      bank_va: hex(this.bank_va),
      live_profiles: this.live_profiles,
      images: this.images.map((x) => x.toDict()),
    };
  }
}

export class BaseLoader {
  name = "base";

  constructor(rom, drdi, rep) {
    this.rom = rom;
    this.drdi = drdi;
    this.rep = rep;
    this.tables = discoverRomTables(rom, rep);
    this.banks = [];
    // Full findCandidateArray results keyed by Image object: bank selection
    // and extraction share one cache so the proof result is reused, exactly
    // like the python loader._candidate_arrays dict keyed by id(im).
    this._candidateArrays = new Map();
  }

  listBanks() { return this.banks; }

  // LTE CA namespace tables, container-specific like everything else a loader
  // owns: grid and CDF families store contiguous rows in sibling banks.
  lteTables(cap, rep) {
    return chooseLteBank(this, cap, rep);
  }
}

function countBytes(hay, needle, start, end) {
  // python bytes.count semantics: non-overlapping within [start, end).
  let n = 0;
  let p = start;
  while (p < end) {
    const i = indexOfBytes(hay, needle, p);
    if (i < 0 || i + needle.length > end) break;
    n++;
    p = i + needle.length;
  }
  return n;
}

function containsBytes(hay, needle, start, end) {
  if (start >= end) return false;
  const i = indexOfBytes(hay, needle, start);
  return i >= 0 && i + needle.length <= end;
}

// ---------------------------------------------------------------------------

// GridLoader._discover, shared with the NR15 loader (mtk_nr15.js): builds
// loader.banks from a raw descriptor-hit list on any loader carrying
// { drdi, rep, banks }.
export function gridDiscover(loader, raw) {
  if (!raw.length) throw new UniversalError("no modern bank descriptors found");
  // Dense cluster: real table is 12-byte-stride but small gaps can exist in false scans.
  const clusters = [];
  let cur = [raw[0]];
  for (let i = 1; i < raw.length; i++) {
    const a = raw[i - 1];
    const b = raw[i];
    if (0 < b[0] - a[0] && b[0] - a[0] <= 0x40) cur.push(b);
    else {
      if (cur.length >= 4) clusters.push(cur);
      cur = [b];
    }
  }
  if (cur.length >= 4) clusters.push(cur);
  if (!clusters.length) throw new UniversalError("raw bank-descriptor hits did not form a coherent table");
  // max(clusters, key=len): python max returns the first maximal element.
  let table = clusters[0];
  for (const c of clusters) if (c.length > table.length) table = c;
  // Require a uniform matrix: each distinct bank VA has same declared column count.
  const byVa = new Map();
  for (const x of table) {
    if (!byVa.has(x[2])) byVa.set(x[2], []);
    byVa.get(x[2]).push(x);
  }
  // Counter.most_common(1)[0]: max count, ties keep first-encountered order.
  const counts = new Map();
  for (const xs of byVa.values()) counts.set(xs.length, (counts.get(xs.length) ?? 0) + 1);
  let colCount = -1;
  let freq = -1;
  for (const [k, v] of counts) {
    if (v > freq) { freq = v; colCount = k; }
  }
  const coherent = new Map();
  for (const [va, xs] of byVa) if (xs.length === colCount) coherent.set(va, xs);
  if (coherent.size < 1) throw new UniversalError("descriptor table does not contain a coherent bank/profile matrix");

  loader.descriptor_table_off = table[0][0];
  loader.columns = colCount;
  loader.banks = [];
  const bankVas = [...coherent.keys()].sort((a, b) => {
    let ma = Infinity;
    let mb = Infinity;
    for (const x of coherent.get(a)) if (x[0] < ma) ma = x[0];
    for (const x of coherent.get(b)) if (x[0] < mb) mb = x[0];
    return ma - mb;
  });
  for (let bi = 0; bi < bankVas.length; bi++) {
    const va = bankVas[bi];
    const xs = coherent.get(va).slice().sort((a, b) => a[0] - b[0]);
    const images = [];
    let seenStub = false;
    for (let pi = 0; pi < xs.length; pi++) {
      const src = xs[pi][1];
      const ln = xs[pi][3];
      if (ln <= 0x40) {
        seenStub = true;
        continue;
      }
      if (seenStub) {
        // Live profiles are a contiguous prefix by observed MTK contract.
        throw new UniversalError(`bank ${hex(va)} has live profile ${pi} after a stub; descriptor geometry is likely wrong`);
      }
      images.push(new Image(va, pi, src, ln, va - src, loader.drdi, `bank${bi}/profile${pi}`));
    }
    loader.banks.push(new Bank(va, images, bi));
  }
  loader.rep.info("grid_loader", "discovered modern bank/profile descriptor matrix", {
    descriptor_table_off: hex(loader.descriptor_table_off),
    columns: loader.columns,
    banks: loader.banks.length,
    live_counts: loader.banks.map((b) => b.images.length),
  });
}

// Modern {source_field, bank_va, bank_len} 12-byte descriptor matrix.
export class GridLoader extends BaseLoader {
  name = "grid";

  constructor(rom, drdi, rep, { descriptorHits = null } = {}) {
    super(rom, drdi, rep);
    this._discover(descriptorHits);
  }

  // Scan aligned descriptors once, without copying the ROM. The scan includes
  // a descriptor ending exactly at EOF and ignores an incomplete trailing
  // word; bounds and runtime-address requirements are the scalar mirror of
  // the python numpy prefilter.
  static descriptorHits(rom, drdi) {
    const hits = [];
    for (let off = 0; off < rom.length - 11; off += 4) {
      const sf = u32(rom, off);
      const va = u32(rom, off + 4);
      const ln = u32(rom, off + 8);
      const src = (sf & 0x0fffffff) >>> 0;
      if ((sf >>> 28) === 3 && ln >= 0x10 && ln <= 0x800000 && src + ln <= drdi.length && va >= VA_LO && va < VA_HI) {
        hits.push([off, src, va, ln]);
      }
    }
    return hits;
  }

  static _denseScore(hits) {
    let last = -100;
    let run = 0;
    let best = 0;
    for (const h of hits) {
      const off = h[0];
      run = off - last <= 0x40 ? run + 1 : 1;
      if (run > best) best = run;
      last = off;
    }
    return best;
  }

  static probe(rom, drdi) {
    return GridLoader._denseScore(GridLoader.descriptorHits(rom, drdi));
  }

  _discover(descriptorHits = null) {
    gridDiscover(this, descriptorHits ?? GridLoader.descriptorHits(this.rom, this.drdi));
  }

  // Preserve the existing ranking as a search order, but require grammar
  // evidence before accepting it. A sentinel is not a container contract;
  // try banks without it too if none of the preferred banks validate.
  capabilityBank(prove = null) {
    if (this._capabilityBank) return this._capabilityBank;
    if (!prove) throw new UniversalError("capability bank selection needs a CandidateNode proof hook (installed by the Stage B grammar)");
    const candidates = [];
    for (const b of this.banks) {
      if (!b.images.length) continue;
      let sent = 0;
      for (const im of b.images) sent += countBytes(this.drdi, FEATURE_SENTINEL, im.source_offset, im.end_source);
      const avg = b.images.reduce((s, i) => s + i.length, 0) / b.images.length;
      candidates.push({ avg, sent, bank: b });
    }
    const keyOf = (t) => [t.sent > 0 ? 1 : 0, t.avg, t.sent];
    const ordered = candidates.slice().sort((a, b) => {
      const ka = keyOf(a);
      const kb = keyOf(b);
      for (let i = 0; i < 3; i++) {
        if (ka[i] > kb[i]) return -1;
        if (ka[i] < kb[i]) return 1;
      }
      return 0;
    });
    for (const { avg, sent, bank: b } of ordered) {
      for (const im of b.images) {
        const count = prove(im);
        if (count == null) continue;
        this._capabilityBank = b;
        this.rep.info("capability_bank", "selected grid capability bank by CandidateNode validation", {
          bank_va: hex(b.bank_va),
          live_profiles: b.images.length,
          sentinel_hits: sent,
          average_live_length: Math.floor(avg),
          proof_profile: im.profile,
          proof_candidate_count: count,
        });
        return b;
      }
      this.rep.info("capability_bank_rejected", "bank has no validated CandidateNode array", {
        bank_va: hex(b.bank_va),
        sentinel_hits: sent,
      });
    }
    throw new UniversalError("no live grid bank contains a structurally valid CandidateNode array");
  }
}

// ---------------------------------------------------------------------------

// Tensor/Pixel split CDF: 0x30000 header + concatenated DRDI slot data.
// The loader exposes CDF slots as the same Image abstraction used by the
// modern descriptor grid. Runtime VAs are aliased by 0x60000000; the shared
// grammar parser never needs to know this.
export class TensorCdfLoader extends BaseLoader {
  name = "tensor";

  constructor(rom, header, data, rep) {
    if (!TensorCdfLoader.probe(header)) {
      throw new UniversalError("split-CDF header failed section geometry (expected 0x30000, 641 offsets, 11 bounds, 640 SHA-384 digests)");
    }
    super(rom, data, rep);
    this.header = header;
    this.sections = [];
    for (let i = 0; i < 20; i++) this.sections.push([u32(header, 4 + i * 8), u32(header, 8 + i * 8)]);
    const [oo] = this.sections[0];
    this.slot_offsets = [];
    for (let i = 0; i < 641; i++) this.slot_offsets.push(u32(header, oo + i * 4));
    const [bo] = this.sections[1];
    this.bank_bounds = [];
    for (let i = 0; i < 11; i++) this.bank_bounds.push(u32(header, bo + i * 4));
  }

  // Async factory: _validate_slots needs SHA-384 (crypto.subtle is async).
  static async create(rom, header, data, rep) {
    const loader = new TensorCdfLoader(rom, header, data, rep);
    await loader._validateSlots();
    loader._buildBanks();
    return loader;
  }

  static probe(header) {
    if (header.length !== 0x30000) return false;
    const sections = [];
    try {
      for (let i = 0; i < 20; i++) sections.push([u32(header, 4 + i * 8), u32(header, 8 + i * 8)]);
    } catch {
      return false;
    }
    if (!(sections[0][1] === 641 * 4 && sections[1][1] === 11 * 4 && sections[2][1] === 640 * 48)) return false;
    return sections.slice(0, 3).every(([off, size]) => 164 <= off && off <= header.length && size <= header.length - off);
  }

  async _validateSlots() {
    // Bounds and offsets must be monotone; every slot gets cryptographic
    // validation against the header before any capability bytes are trusted.
    for (let i = 1; i < this.bank_bounds.length; i++) {
      if (this.bank_bounds[i - 1] >= this.bank_bounds[i]) throw new UniversalError("CDF bank bounds are not strictly increasing");
    }
    for (let i = 1; i < this.slot_offsets.length; i++) {
      if (this.slot_offsets[i - 1] > this.slot_offsets[i]) throw new UniversalError("CDF slot offsets are not monotone");
    }
    const last = this.slot_offsets[this.slot_offsets.length - 1];
    if (last > this.drdi.length) {
      throw new UniversalError(`CDF final slot offset ${hex(last)} exceeds data size ${hex(this.drdi.length)}`);
    }
    if (last < this.drdi.length) {
      this.rep.info("cdf_trailing_data", "CDF data contains bytes after the 640 indexed slots", {
        indexed_end: hex(last),
        data_size: hex(this.drdi.length),
        trailing_bytes: this.drdi.length - last,
      });
    }
    const [digestOff] = this.sections[2];
    let ok = 0;
    let bad = 0;
    for (let slot = 0; slot < 640; slot++) {
      const st = this.slot_offsets[slot];
      const en = this.slot_offsets[slot + 1];
      const exp = toHex(this.header.subarray(digestOff + slot * 48, digestOff + (slot + 1) * 48));
      const got = await sha384HexAsync(this.drdi.subarray(st, en));
      if (got === exp) ok++;
      else bad++;
    }
    if (bad) throw new UniversalError(`CDF SHA-384 validation failed for ${bad}/640 slots`);
    this.rep.info("cdf_integrity", "validated all split-CDF slot SHA-384 digests", { ok, bad });
  }

  _buildBanks() {
    const banks = [];
    for (let bi = 0; bi < 10; bi++) {
      const va = this.bank_bounds[bi];
      const images = [];
      let seenStub = false;
      for (let pi = 0; pi < 64; pi++) {
        const slot = bi * 64 + pi;
        const src = this.slot_offsets[slot];
        const ln = this.slot_offsets[slot + 1] - src;
        if (ln <= 0x40) {
          seenStub = true;
          continue;
        }
        if (seenStub) throw new UniversalError(`CDF bank ${bi} has live image after stub at profile ${pi}`);
        images.push(new Image(va, pi, src, ln, va - src, this.drdi, `cdf-bank${bi}/profile${pi}`, TensorCdfLoader.ALIAS));
      }
      banks.push(new Bank(va, images, bi));
    }
    this.banks = banks;
    this.rep.info("tensor_loader", "discovered split-CDF banks/profiles", {
      banks: banks.length,
      live_counts: banks.map((b) => b.images.length),
      alias: hex(TensorCdfLoader.ALIAS),
    });
  }

  // Sentinel is a cheap prefilter; CandidateNode structural validity is
  // the authority. This avoids choosing a physically larger unrelated CDF
  // bank that happens to contain the same 3-byte sentinel.
  capabilityBank(prove = null) {
    if (!prove) throw new UniversalError("capability bank selection needs a CandidateNode proof hook (installed by the Stage B grammar)");
    const candidates = [];
    for (const b of this.banks) {
      const sentinelImages = b.images.filter((im) => containsBytes(this.drdi, FEATURE_SENTINEL, im.source_offset, im.end_source));
      if (!sentinelImages.length) continue;
      let bestCount = 0;
      let provedProfile = null;
      for (const im of sentinelImages) {
        const count = prove(im);
        if (count != null && count > bestCount) {
          bestCount = count;
          provedProfile = im.profile;
        }
      }
      if (bestCount) {
        const avg = b.images.reduce((s, i) => s + i.length, 0) / b.images.length;
        candidates.push({ bestCount, avg, bank: b, provedProfile, ns: sentinelImages.length });
      }
    }
    if (!candidates.length) {
      throw new UniversalError("no CDF bank containing feature sentinels also contains a 100%-valid CandidateNode array");
    }
    // max(key=(count, avg)): python max keeps the first maximal element.
    let best = candidates[0];
    for (const c of candidates) {
      if (c.bestCount > best.bestCount || (c.bestCount === best.bestCount && c.avg > best.avg)) best = c;
    }
    this.rep.info("capability_bank", "selected CDF capability bank by sentinel + CandidateNode proof", {
      bank_index: best.bank.table_index,
      bank_va: hex(best.bank.bank_va),
      live_profiles: best.bank.images.length,
      proof_profile: best.provedProfile,
      proof_candidate_count: best.bestCount,
      sentinel_profiles: best.ns,
    });
    return best.bank;
  }
}

TensorCdfLoader.ALIAS = 0x60000000;

// ---------------------------------------------------------------------------
// Flat (MD800-class) legacy container: no 12-byte bank descriptor matrix
// (python mtk_universal.FlatLoader). Profiles are regions of md1drdi, each
// mounted at its own relocation; the geometry is recovered from two structural
// facts: a profile's CandidateNode pointer array is a maximal run of runtime-
// window words whose node objects immediately follow it (4-byte bias), and the
// shared grammar must then close on the adjacency-derived relocation — a wrong
// relocation produces essentially zero valid nodes, so the sample proof below
// is a proof rather than a fit.
// ---------------------------------------------------------------------------

function runsFromWords(words, minrun) {
  const out = [];
  let start = -1;
  let prev = -1;
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (w >= VA_LO && w < VA_HI) {
      if (start < 0) start = i;
      else if (i !== prev + 1) {
        if (prev - start + 1 >= minrun) out.push([start * 4, prev - start + 1]);
        start = i;
      }
      prev = i;
    }
  }
  if (start >= 0 && prev - start + 1 >= minrun) out.push([start * 4, prev - start + 1]);
  return out;
}

export class FlatLoader extends BaseLoader {
  name = "flat";

  static MIN_ARRAY = 64;
  static SAMPLE = 48;
  static SAMPLE_RATE = 0.9;

  static probe(drdi) {
    return runsFromWords(wordsOf(drdi), FlatLoader.MIN_ARRAY).length;
  }

  constructor(rom, drdi, rep) {
    super(rom, drdi, rep);
    this._words = wordsOf(drdi);
    this.runs = runsFromWords(this._words, FlatLoader.MIN_ARRAY);
    this._discover();
  }

  _probeImage(reloc) {
    return new Image(reloc, -1, 0, this.drdi.length, reloc, this.drdi, "flat-probe");
  }

  // Relocation hypotheses for one pointer run, cheapest first: nodes
  // immediately follow the array; the 4-byte bias is the observed packing on
  // every MD800 profile examined, with the no-bias variant kept so a repack
  // does not silently defeat discovery.
  *_hypotheses(off, n) {
    const v0 = this._words[off / 4];
    for (const bias of [4, 0]) {
      const r = v0 - (off + 4 * n + bias);
      if (r > 0 && r < VA_HI && r + this.drdi.length < 2 ** 32) yield [r, bias];
    }
  }

  _discover() {
    const parser = new GrammarParser(this, this.rep);
    const found = [];
    for (const [off, n] of this.runs) {
      for (const [reloc, bias] of this._hypotheses(off, n)) {
        const im = this._probeImage(reloc);
        const k = Math.min(n, FlatLoader.SAMPLE);
        let ok = 0;
        for (let i = 0; i < k; i++) {
          if (parser.parseCandidateVa(im, this._words[off / 4 + i]) !== null) ok++;
        }
        if (ok >= k * FlatLoader.SAMPLE_RATE) {
          found.push({ array_off: off, count: n, relocation: reloc, bias, array_va: off + reloc });
          break;
        }
      }
    }
    if (!found.length) {
      throw new UniversalError(
        `flat loader found no pointer run whose adjacency-derived relocation yields `
        + `structurally valid CandidateNodes (scanned ${this.runs.length} runs of >=${FlatLoader.MIN_ARRAY} words)`,
      );
    }

    const [order, tableOff] = this._romProfileOrder(found.map((f) => f.array_va));
    if (order) {
      const rank = (f) => (order.has(f.array_va) ? order.get(f.array_va) : 10000);
      found.sort((a, b) => rank(a) - rank(b));
      for (const f of found) f.profile = order.has(f.array_va) ? order.get(f.array_va) : null;
    }
    // The ROM table can name the same runtime array twice; vendor numbering is
    // kept when present, but every image needs a unique profile key.
    const used = new Set();
    let nxt = Math.max(...found.map((f) => f.profile || 0)) + 1;
    for (const f of found) {
      let v = f.profile ?? null;
      if (v === null || used.has(v)) v = nxt++;
      used.add(v);
      f.profile = v;
    }
    const images = found.map((f) => new Image(
      f.relocation, f.profile, 0, this.drdi.length, f.relocation, this.drdi,
      `flat/profile${f.profile}`, 0, [f.array_off, f.count],
    ));
    this.banks = [new Bank(Math.min(...found.map((f) => f.array_va)), images, 0)];
    this.discovery = found;
    this.rom_profile_table_off = tableOff;
    this.rep.info("flat_loader", "recovered flat capability profiles by relocation proof", {
      profiles: found.length,
      rom_profile_table: tableOff === null ? null : hex(tableOff),
      corroborated: order ? found.filter((f) => order.has(f.array_va)).length : 0,
      detail: found.map((f) => ({
        profile: f.profile,
        array_off: hex(f.array_off),
        count: f.count,
        relocation: hex(f.relocation),
        array_va: hex(f.array_va),
        bias: f.bias,
      })),
    });
  }

  // Corroborate the recovered arrays against md1rom's profile pointer table:
  // the longest consecutive run of ROM words that all equal recovered array
  // addresses supplies the vendor's own profile numbering.
  _romProfileOrder(arrayVas) {
    // numpy: np.fromiter(sorted(want), "<u8").astype("<u4") wraps to 32 bits.
    const want = new Set(arrayVas.map((v) => v >>> 0));
    if (!want.size) return [null, null];
    const rw = wordsOf(this.rom);
    const idx = [];
    for (let i = 0; i < rw.length; i++) if (want.has(rw[i])) idx.push(i);
    if (!idx.length) return [null, null];
    // Longest run of consecutive word indexes all holding a wanted address.
    let best = [0, 0, 0];
    let start = idx[0];
    let prev = idx[0];
    for (const z of [...idx.slice(1), null]) {
      if (z !== prev + 1) {
        const ln = prev - start + 1;
        if (ln > best[0]) best = [ln, start, prev];
        if (z === null) break;
        start = z;
      }
      prev = z;
    }
    const [ln, w0] = best;
    if (ln < 2) return [null, null];
    const order = new Map();
    for (let i = 0; i < ln; i++) {
      const va = rw[w0 + i];
      if (!order.has(va)) order.set(va, i);
    }
    return [order, w0 * 4];
  }

  capabilityBank() {
    const b = this.banks[0];
    this.rep.info("capability_bank", "flat container exposes one synthetic capability bank", {
      bank_va: hex(b.bank_va),
      live_profiles: b.images.length,
    });
    return b;
  }

  // LTE CA rows in this family are a pointer array of row objects
  // (parseLteFields at row bias 4/0), not contiguous row-table banks.
  lteTables(cap, rep) {
    const chosen = [];
    for (const [off, n] of this.runs) {
      for (const [reloc] of this._hypotheses(off, n)) {
        const im = this._probeImage(reloc);
        for (const rowBias of [4, 0]) {
          let combos = [];
          let okall = true;
          const probe = Math.min(n, 32);
          for (let i = 0; i < probe; i++) {
            const base = im.resolve(this._words[off / 4 + i], 4);
            if (base === null || parseLteFields(im, base + rowBias, this.tables) === null) {
              okall = false;
              break;
            }
          }
          if (!okall) continue;
          for (let i = 0; i < n; i++) {
            const base = im.resolve(this._words[off / 4 + i], 4);
            const cb = base === null ? null : parseLteFields(im, base + rowBias, this.tables);
            if (cb === null) {
              combos = [];
              break;
            }
            combos.push(cb);
          }
          if (combos.length) {
            chosen.push({ array_off: off, count: n, relocation: reloc, row_bias: rowBias, rows: combos });
            break;
          }
        }
        if (chosen.length && chosen[chosen.length - 1].array_off === off) break;
      }
    }
    if (!chosen.length) {
      rep.warn("lte_table_missing", "flat loader found no fully valid LTE CA pointer array");
      return [null, new Map()];
    }
    chosen.sort((a, b) => b.rows.length - a.rows.length);
    const results = new Map();
    chosen.forEach((c, i) => results.set(i, c.rows));
    rep.info("lte_table", "flat LTE CA row arrays recovered by relocation proof", {
      arrays: chosen.map((c, i) => ({
        index: i,
        array_off: hex(c.array_off),
        rows: c.rows.length,
        relocation: hex(c.relocation),
        row_bias: c.row_bias,
      })),
    });
    return [this.banks[0], results];
  }
}

// ---------------------------------------------------------------------------
// Stage B: shared combo row model (mtk_export.Combo and friends). Field names
// mirror the python dataclasses so the Stage D exporters serialize rows
// without translation; dedup/classification semantics are python-exact.
// ---------------------------------------------------------------------------

// Physical carriers per LTE bandwidth class, indexed by the 0-based class byte.
// A=1 B=2 C=2 D=3 E=4 F=5. LTE_UL_ABSENT (6) marks "no uplink".
export class LteComponent {
  constructor(band, dl_class, ul_class, dl_mimo = []) {
    this.band = band;
    this.dl_class = dl_class;
    this.ul_class = ul_class;
    this.dl_mimo = dl_mimo;
  }

  get has_ul() { return this.ul_class < LTE_UL_ABSENT; }
}

// One physical NR carrier, already resolved through the feature tables.
export class NrCC {
  constructor(scs_khz, dl_mimo, dl_bw_mhz, ul_mimo = null, ul_bw_mhz = null) {
    this.scs_khz = scs_khz;
    this.dl_mimo = dl_mimo;
    this.dl_bw_mhz = dl_bw_mhz;
    this.ul_mimo = ul_mimo;
    this.ul_bw_mhz = ul_bw_mhz;
  }
}

export class NrComponent {
  constructor(band, dl_class, ul_class, ccs = []) {
    this.band = band;
    this.dl_class = dl_class;
    this.ul_class = ul_class;
    this.ccs = ccs;
  }

  get has_ul() { return this.ul_class !== NR_UL_ABSENT_CANON; }
}

export class MtkCombo {
  constructor(lte = [], nr = []) {
    this.lte = lte;
    this.nr = nr;
  }

  get kind() {
    if (this.lte.length && this.nr.length) return "ENDC";
    if (this.nr.length) return "NR";
    return "LTE";
  }

  get nr_physical_ccs() {
    return this.nr.reduce((s, c) => s + c.ccs.length, 0);
  }
}

// Split a flat combo list into (endc, nrca, lte_only) — mtk_export.classify.
export function classify(combos, nrcaMinCcs = 1) {
  const endc = combos.filter((c) => c.kind === "ENDC");
  const nrca = combos.filter((c) => c.kind === "NR" && c.nr_physical_ccs >= nrcaMinCcs);
  const lte = combos.filter((c) => c.kind === "LTE");
  return [endc, nrca, lte];
}

// python combo_key tuple rendered as a stable string; field order is fixed so
// dedup is insertion-ordered keep-first (a Set would collapse structurally
// equal rows identically, but the string keeps the key printable in diffs).
export function comboKey(cb) {
  const lte = cb.lte.map((c) => `${c.band},${c.dl_class},${c.ul_class},${c.dl_mimo.join(":")}`);
  const nr = cb.nr.map((c) => `${c.band},${c.dl_class},${c.ul_class},${
    c.ccs.map((x) => `${x.scs_khz}:${x.dl_mimo}:${x.dl_bw_mhz}:${x.ul_mimo}:${x.ul_bw_mhz}`).join(":")}`);
  return `L${lte.join(";")}|N${nr.join(";")}`;
}

export function dedupExact(combos) {
  const seen = new Set();
  const out = [];
  for (const cb of combos) {
    const k = comboKey(cb);
    if (!seen.has(k)) {
      seen.add(k);
      out.push(cb);
    }
  }
  return out;
}

// Separate mixed FR1/FR2 NR-only rows for the GUI's NRDC column and single-
// carrier NR rows for the NR-SA column. These are band/CC-based presentation
// classifications, not proof of separate firmware namespaces; the export
// classification stays intact.
export function guiFamilyCounts(combos) {
  const [endc, nr, lte] = classify(combos, 1);
  let nrdc = 0;
  let nrSa = 0;
  for (const row of nr) {
    if (row.nr.some((c) => c.band < 257) && row.nr.some((c) => c.band >= 257)) nrdc++;
    if (row.nr_physical_ccs === 1) nrSa++;
  }
  return { endc: endc.length, nr_sa: nrSa, nrca: nr.length - nrdc - nrSa, nrdc, lte: lte.length };
}

// ---------------------------------------------------------------------------

export class RawDescriptor {
  constructor(count, records_ptr, variant_count, variant_ptr, records, units, fsc, is_nr) {
    this.count = count;
    this.records_ptr = records_ptr;
    this.variant_count = variant_count;
    this.variant_ptr = variant_ptr;
    this.records = records;
    this.units = units;
    this.fsc = fsc;
    this.is_nr = is_nr;
  }

  get variants() {
    return this.units ? Math.floor(this.variant_count / this.units) : 0;
  }
}

export class RawCandidate {
  constructor(va, meta0, meta1, lte, nr) {
    this.va = va;
    this.meta0 = meta0;
    this.meta1 = meta1;
    this.lte = lte;
    this.nr = nr;
  }
}

export class GrammarParser {
  constructor(loader, rep) {
    this.loader = loader;
    this.tables = loader.tables;
    this.rep = rep;
    // Nodes share descriptors extensively. The cache is scoped to the actual
    // Image object: profiles can reuse VAs with different source bytes. Only
    // one image is retained so relocation probes cannot accumulate.
    this._descriptorImage = null;
    this._descriptors = new Map();
  }

  _parseDesc(im, ptr, nr, strictFsc = true) {
    if (this._descriptorImage !== im) {
      this._descriptors.clear();
      this._descriptorImage = im;
    }
    const key = `${ptr}|${nr ? 1 : 0}|${strictFsc ? 1 : 0}`;
    if (!this._descriptors.has(key)) this._descriptors.set(key, this._decodeDesc(im, ptr, nr, strictFsc));
    return this._descriptors.get(key);
  }

  _decodeDesc(im, ptr, nr, strictFsc = true) {
    const doff = im.resolve(ptr, 16);
    if (doff === null) return null;
    const cnt = u32(im.drdi, doff);
    const rp = u32(im.drdi, doff + 4);
    const vc = u32(im.drdi, doff + 8);
    const vp = u32(im.drdi, doff + 12);
    if (!(cnt >= 1 && cnt <= 16)) return null;
    const recsz = nr ? 4 : 3;
    const ro = im.resolve(rp, cnt * recsz);
    if (ro === null) return null;
    const records = [];
    let units = 0;
    if (nr) {
      const absent = this.tables.nr_ul_absent;
      const w = this.tables.nr_weights;
      for (let k = 0; k < cnt; k++) {
        const band = u16(im.drdi, ro + 4 * k);
        const ul = im.drdi[ro + 4 * k + 2];
        const dl = im.drdi[ro + 4 * k + 3];
        if (!(band >= 1 && band <= 1024)) return null;
        if (!(dl >= 0 && dl < w.length) || w[dl] <= 0) return null;
        if (!absent.has(ul)) {
          if (!(ul >= 0 && ul < w.length) || w[ul] <= 0) return null;
        }
        records.push([band, ul, dl]);
        units += w[dl];
      }
    } else {
      const bm = this.tables.lte_band_map;
      const w = this.tables.lte_weights;
      for (let k = 0; k < cnt; k++) {
        const idx = im.drdi[ro + 3 * k];
        const ul = im.drdi[ro + 3 * k + 1];
        const dl = im.drdi[ro + 3 * k + 2];
        if (!(idx >= 0 && idx < bm.length)) return null;
        const band = bm[idx];
        // 0 and 0xff terminate/void a slot; 252..255 are reserved markers
        // present in one of the two band-map copies. No real LTE band exceeds
        // MAX_LTE_BAND, so anything above it is a mis-resolved index.
        if (band === 0 || band > MAX_LTE_BAND) return null;
        if (!(dl >= 0 && dl < w.length) || w[dl] <= 0) return null;
        if (ul !== LTE_UL_ABSENT && !(ul >= 0 && ul < w.length)) return null;
        records.push([band, ul, dl]);
        units += w[dl];
      }
    }
    if (units <= 0 || vc <= 0 || vc % units !== 0) return null;
    const vo = im.resolve(vp, vc * (nr ? 3 : 2));
    if (vo === null) return null;
    const fsc = [];
    if (nr) {
      for (let k = 0; k < vc; k++) {
        fsc.push([im.drdi[vo + 3 * k], im.drdi[vo + 3 * k + 1], im.drdi[vo + 3 * k + 2]]);
      }
      if (strictFsc && fsc.some((t) => !(t[0] in SCS))) return null;
    } else {
      for (let k = 0; k < vc; k++) {
        fsc.push([im.drdi[vo + 2 * k], im.drdi[vo + 2 * k + 1]]);
      }
      // Second byte is code-proven DL-MIMO status; reject unknown/unsupported.
      if (strictFsc && fsc.some((t) => t[1] !== 0 && t[1] !== 1 && t[1] !== 2 && t[1] !== 3)) return null;
    }
    return new RawDescriptor(cnt, rp, vc, vp, records, units, fsc, nr);
  }

  parseCandidateVa(im, va) {
    const o = im.resolve(va, 16);
    if (o === null) return null;
    const meta0 = u32(im.drdi, o);
    const meta1 = u32(im.drdi, o + 4);
    const lp = u32(im.drdi, o + 8);
    const nptr = u32(im.drdi, o + 12);
    const lte = lp ? this._parseDesc(im, lp, false) : null;
    const nr = nptr ? this._parseDesc(im, nptr, true) : null;
    if (lte === null && nr === null) return null;
    // A nonzero *in-image* descriptor pointer that failed is evidence this is
    // not a candidate.
    if (lp && im.containsVa(lp, 16) && lte === null) return null;
    if (nptr && im.containsVa(nptr, 16) && nr === null) return null;
    return new RawCandidate(va, meta0, meta1, lte, nr);
  }

  // Aligned runs of u32 values pointing into this same image.
  _pointerRuns(im, minrun = 4) {
    const out = [];
    let o = im.source_offset;
    while (o + 4 <= im.end_source) {
      if (im.containsVa(u32(im.drdi, o), 1)) {
        const st = o;
        let n = 0;
        while (o + 4 <= im.end_source && im.containsVa(u32(im.drdi, o), 1)) {
          n++;
          o += 4;
        }
        if (n >= minrun) out.push([st, n]);
      } else {
        o += 4;
      }
    }
    return out;
  }

  // Parse a pointer run and return its maximal fully-valid subrun:
  // [length, fileOffset, candidates, rawRunCount] or null.
  _validateRun(im, off, n) {
    const validity = [];
    const parsed = [];
    for (let k = 0; k < n; k++) {
      const va = u32(im.drdi, off + 4 * k);
      const c = this.parseCandidateVa(im, va);
      validity.push(c !== null);
      parsed.push(c);
    }
    let best = null;
    let st = null;
    for (let i = 0; i <= validity.length; i++) {
      const ok = i < validity.length ? validity[i] : false;
      if (ok && st === null) st = i;
      else if (!ok && st !== null) {
        const ln = i - st;
        if (ln >= 4) {
          const cand = [ln, off + 4 * st, parsed.slice(st, i), n];
          if (best === null || cand[0] > best[0] || (cand[0] === best[0] && cand[1] < best[1])) best = cand;
        }
        st = null;
      }
    }
    return best;
  }

  // Bank selection and extraction share the loader's cache, so the full
  // validation result (and its discovery warnings) survive the proof hook.
  findCandidateArray(im) {
    let hit = this.loader._candidateArrays.get(im);
    if (!hit) {
      hit = [im, this._findCandidateArray(im)];
      this.loader._candidateArrays.set(im, hit);
    }
    return hit[1];
  }

  // Summary info shared by both discovery paths (python shape, differential-
  // pinned): the hinted path reports the same fields, with source flipped.
  _candidateArrayInfo(im, off, rows, rawrun, source) {
    let nrDesc = 0;
    let lteDesc = 0;
    for (const c of rows) {
      if (c.nr !== null) nrDesc++;
      if (c.lte !== null) lteDesc++;
    }
    return [off, rows, {
      file_offset: off,
      relative_offset: off - im.source_offset,
      count: rows.length,
      raw_pointer_run_count: rawrun,
      nr_descriptors: nrDesc,
      lte_descriptors: lteDesc,
      invariant_pass: rows.length,
      invariant_total: rows.length,
      invariant_rate: 1.0,
      source,
    }];
  }

  _findCandidateArray(im) {
    // Flat/legacy loaders prove a profile's relocation while discovering it
    // and hand the validated array in as a hint; every pointer is still
    // re-validated here and the run trimmed to its maximal valid subrun.
    if (im.candidate_hint) {
      const [hoff, hn] = im.candidate_hint;
      const best = this._validateRun(im, hoff, hn);
      if (best === null) {
        throw new UniversalError(`${im.label}: loader-supplied candidate array at ${hex(hoff)} (${hn} entries) contains no structurally valid CandidateNode subrun`);
      }
      const [ln, off, rows, rawrun] = best;
      return this._candidateArrayInfo(im, off, rows, rawrun, "loader_hint");
    }
    let best = null;
    const allValid = [];
    for (const [off, n] of this._pointerRuns(im, 4)) {
      // Maximal valid subruns trim unrelated neighbours at either end.
      const cand = this._validateRun(im, off, n);
      if (cand === null) continue;
      allValid.push(cand);
      if (best === null || cand[0] > best[0] || (cand[0] === best[0] && cand[1] < best[1])) best = cand;
    }
    if (best === null) {
      throw new UniversalError(`no structurally valid CandidateNode pointer array found in ${im.label}`);
    }
    // The longest valid subrun wins, but say so when there was competition: on
    // the current corpus there never is, and if that changes the union is
    // probably incomplete rather than the runner-up being noise.
    if (allValid.length > 1) {
      this.rep.warn("candidate_subrun_discarded",
        "more than one structurally valid CandidateNode subrun in this image; "
        + "only the longest is decoded, so the result may be incomplete",
        { image: im.label, subrun_lengths: allValid.map((c) => c[0]).sort((a, b) => b - a).slice(0, 8) });
    }
    const [ln, off, rows, rawrun] = best;
    return this._candidateArrayInfo(im, off, rows, rawrun, "scan");
  }
}

// ---------------------------------------------------------------------------

// Entry 0 of every feature table is an "unsupported" object (mimo_status == 3);
// what identifies one is its meaning, not a byte pattern (modern firmware
// writes 03 14 01, MD800 writes 03 0d 01).
export class FeatureObj {
  constructor(mimo_status, bw_code, channel_bw_90) {
    this.mimo_status = mimo_status;
    this.bw_code = bw_code;
    this.channel_bw_90 = channel_bw_90;
  }
}

export class FeatureTable {
  constructor(root_off, root_va, objects) {
    this.root_off = root_off;
    this.root_va = root_va;
    this.objects = objects;
  }

  get length() { return this.objects.length; }
}

export class FeatureResolver {
  constructor(parser) {
    this.p = parser;
  }

  _validObj(b) {
    if (b.length !== 3) return false;
    const [st, bw, b90] = b;
    if ((st !== 0 && st !== 1 && st !== 2 && st !== 3) || (b90 !== 0 && b90 !== 1)) return false;
    if (st === 3) return true; // sentinel deliberately has a BW code outside the enum
    return bw >= 0 && bw < this.p.tables.bw.length;
  }

  // File offsets of FeatureObj values that mean "not supported". Entry 0 of
  // every feature table is such an object, so these offsets are the only
  // possible table anchors.
  _absentObjects(im) {
    const lo = im.source_offset;
    const hi = im.end_source;
    const maxBw = this.p.tables.bw.length + 8;
    const out = [];
    for (let o = lo; o < hi - 2; o++) {
      if (im.drdi[o] === 3 && im.drdi[o + 1] <= maxBw && im.drdi[o + 2] <= 1) out.push(o);
    }
    return out;
  }

  // Locate FeatureObj pointer tables, anchored on the table's entry-0 object
  // rather than swept word by word: the only words that can root a table are
  // those holding the runtime address of an "unsupported" object.
  findTables(im, minLen = 4) {
    const data = im.drdi;
    const anchors = this._absentObjects(im);
    if (!anchors.length) return [];
    // file offset -> runtime address is exactly the inverse of Image.resolve.
    const wantSet = new Set(anchors.map((o) => o + im.relocation + im.alias));
    const so = im.source_offset;
    const nWords = Math.floor((im.end_source - so) / 4);
    const roots = [];
    for (let h = 0; h < nWords; h++) {
      const off = so + h * 4;
      if (wantSet.has(u32(data, off))) roots.push(off);
    }
    roots.sort((a, b) => a - b);
    const out = [];
    let covered = 0;
    for (const off of roots) {
      // A long array in which every entry happens to address an absent object
      // makes every one of its positions look like a table root, and each
      // suffix then looks like a shorter table. Only the longest one can be
      // real, so skip roots already inside an accepted table.
      if (off < covered) continue;
      const objs = [];
      let k = 0;
      while (off + 4 * k + 4 <= im.end_source) {
        const q = u32(data, off + 4 * k);
        const qo = im.resolve(q, 3);
        if (qo === null) break;
        const raw = [data[qo], data[qo + 1], data[qo + 2]];
        if (!this._validObj(raw)) break;
        objs.push(new FeatureObj(raw[0], raw[1], raw[2]));
        k++;
      }
      if (objs.length < minLen) continue;
      covered = off + 4 * objs.length;
      // A table of nothing but absent objects carries no capability and cannot
      // be the DL or UL side of anything.
      if (objs.every((o) => o.mimo_status === 3)) continue;
      out.push(new FeatureTable(off, off + im.relocation + im.alias, objs));
    }
    return out;
  }

  // Walk the grammar once and record every feature reference; the walk result
  // does not depend on which tables are assigned, so it runs once and every
  // pair is then scored against it.
  collectRefs(rows) {
    const dlIds = [];
    const ulIds = [];
    const compStart = [];
    const compExpect = [];
    const w = this.p.tables.nr_weights;
    const absent = this.p.tables.nr_ul_absent;
    for (const c of rows) {
      if (!c.nr) continue;
      const d = c.nr;
      for (let v = 0; v < d.variants; v++) {
        let cur = v * d.units;
        for (const [, ulcls, dlcls] of d.records) {
          const n = w[dlcls];
          const sl = d.fsc.slice(cur, cur + n);
          cur += n;
          if (sl.length !== n) return null;
          compStart.push(ulIds.length);
          compExpect.push(absent.has(ulcls) ? 0 : w[ulcls]);
          for (const [, ui, di] of sl) {
            dlIds.push(di);
            ulIds.push(ui);
          }
        }
        if (cur !== (v + 1) * d.units) return null;
      }
    }
    if (!dlIds.length) return null;
    return {
      dl: dlIds,
      ul: ulIds,
      start: compStart,
      expect: compExpect,
      uniq_dl: [...new Set(dlIds)].sort((a, b) => a - b),
      uniq_ul: [...new Set(ulIds)].sort((a, b) => a - b),
    };
  }

  _evaluatePair(refs, dl, ul) {
    const dlStatus = dl.objects.map((o) => o.mimo_status);
    const ulStatus = ul.objects.map((o) => o.mimo_status);
    const maxdi = refs.dl.reduce((m, x) => (x > m ? x : m));
    const maxui = refs.ul.reduce((m, x) => (x > m ? x : m));
    if (maxdi >= dl.length || maxui >= ul.length) {
      return [false, { reason: "feature_id_oob", max_dl: maxdi, max_ul: maxui }];
    }
    if (refs.dl.some((i) => dlStatus[i] === 3)) {
      return [false, { reason: "dl_references_unsupported" }];
    }
    const starts = refs.start.concat([refs.ul.length]);
    let checks = 0;
    let ok = 0;
    for (let i = 0; i < refs.expect.length; i++) {
      const e = refs.expect[i];
      let act = 0;
      for (let j = starts[i]; j < starts[i + 1]; j++) {
        if (ulStatus[refs.ul[j]] !== 3) act++;
      }
      checks++;
      if (act !== e) return [false, { reason: "ul_class_feature_mismatch", expected: e, active: act }];
      ok++;
    }
    const slack = (dl.length - (maxdi + 1)) + (ul.length - (maxui + 1));
    const exact = (dl.length === maxdi + 1 ? 1 : 0) + (ul.length === maxui + 1 ? 1 : 0);
    return [true, {
      refs: refs.dl.length,
      max_dl_id: maxdi,
      max_ul_id: maxui,
      ul_checks: checks,
      ul_checks_ok: ok,
      slack,
      exact_lengths: exact,
    }];
  }

  // Does this table satisfy the UL class check for every component? Depends
  // only on the UL table, so the check is answered per table instead of per
  // (DL, UL) ordering.
  _ulClosure(refs, ul) {
    const maxui = refs.uniq_ul.reduce((m, x) => (x > m ? x : m));
    if (ul.length <= maxui) return false;
    const status = ul.objects.map((o) => o.mimo_status);
    const starts = refs.start.concat([refs.ul.length]);
    for (let i = 0; i < refs.expect.length; i++) {
      let act = 0;
      for (let j = starts[i]; j < starts[i + 1]; j++) {
        if (status[refs.ul[j]] !== 3) act++;
      }
      if (act !== refs.expect[i]) return false;
    }
    return true;
  }

  _dlAdmissible(refs, dl) {
    const maxdi = refs.uniq_dl.reduce((m, x) => (x > m ? x : m));
    if (dl.length <= maxdi) return false;
    return !refs.uniq_dl.some((i) => dl.objects[i].mimo_status === 3);
  }

  // Rank DL/UL feature-table assignments that survive every check. Every
  // condition reads either the DL table or the UL table, never both, so the
  // admissible tables are found in O(T) per side. Only the best `cap` tables
  // per side (fewest unused entries first) are combined and scored in full.
  pairCandidates(rows, tables, cap = 16) {
    const refs = this.collectRefs(rows);
    if (refs === null) {
      this.lastPairStats = { reason: "grammar_walk_failed" };
      return [];
    }
    const maxdi = refs.uniq_dl.reduce((m, x) => (x > m ? x : m));
    const maxui = refs.uniq_ul.reduce((m, x) => (x > m ? x : m));
    const bySlack = (t) => t.length - (maxdi + 1);
    const dls = tables.filter((t) => this._dlAdmissible(refs, t))
      .map((t) => [bySlack(t), t])
      .sort((a, b) => a[0] - b[0] || a[1].root_off - b[1].root_off);
    const uls = tables.filter((t) => this._ulClosure(refs, t))
      .map((t) => [bySlack(t), t])
      .sort((a, b) => a[0] - b[0] || a[1].root_off - b[1].root_off);
    this.lastPairStats = {
      tables: tables.length,
      dl_admissible: dls.length,
      ul_admissible: uls.length,
      max_dl_id: maxdi,
      max_ul_id: maxui,
      capped: dls.length > cap || uls.length > cap,
    };
    const good = [];
    for (const [, dl] of dls.slice(0, cap)) {
      for (const [, ul] of uls.slice(0, cap)) {
        if (dl === ul) continue;
        const [ok, detail] = this._evaluatePair(refs, dl, ul);
        if (!ok) continue;
        // Lower slack, more exact boundaries, closer roots preferred.
        good.push({
          score: [detail.slack, -detail.exact_lengths, Math.abs(dl.root_off - ul.root_off)],
          dl,
          ul,
          detail,
        });
      }
    }
    return good.sort(cmpScore);
  }
}

function cmpScore(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a.score[i] < b.score[i]) return -1;
    if (a.score[i] > b.score[i]) return 1;
  }
  return 0;
}

export class ProfileState {
  constructor(image, candidates, candidate_info, feature_tables, feature_pairs) {
    this.image = image;
    this.candidates = candidates;
    this.candidate_info = candidate_info;
    this.feature_tables = feature_tables;
    this.feature_pairs = feature_pairs;
    this.dl_table = null;
    this.ul_table = null;
    this.feature_detail = {};
    this.pair_stats = {};
  }
}

// Resolve DL/UL feature-table direction across all live profiles. Usually one
// assignment passes; if a profile has a symmetric tie, use the unanimous
// root-order direction proved by the unambiguous sibling profiles.
export function establishFeaturePairs(states, rep) {
  const orientations = [];
  for (const s of states) {
    if (s.feature_pairs.length === 1) {
      const { dl, ul } = s.feature_pairs[0];
      orientations.push(dl.root_off < ul.root_off ? "DL_FIRST" : "UL_FIRST");
    } else if (s.feature_pairs.length) {
      const bestscore = s.feature_pairs[0].score;
      const tied = s.feature_pairs.filter((x) => x.score[0] === bestscore[0] && x.score[1] === bestscore[1]);
      if (tied.length === 1) {
        const { dl, ul } = tied[0];
        orientations.push(dl.root_off < ul.root_off ? "DL_FIRST" : "UL_FIRST");
      }
    }
  }
  // Counter(...).most_common(1)[0]: highest count, ties keep first-inserted.
  let hint = null;
  {
    const counts = new Map();
    for (const o of orientations) counts.set(o, (counts.get(o) ?? 0) + 1);
    let bestCount = 0;
    for (const [o, c] of counts) {
      if (c > bestCount) {
        bestCount = c;
        hint = o;
      }
    }
  }
  const unresolved = [];
  for (const s of states) {
    if (!s.feature_pairs.length) {
      // No table pair satisfies domain closure and the UL class check for this
      // profile, so its candidate array is not proved and it must not
      // contribute rows; the union is recorded as incomplete instead.
      unresolved.push(s);
      rep.fail("feature_pair_unresolved",
        "no DL/UL feature-table assignment passes domain and UL-class closure; "
        + "this profile is excluded from the union",
        {
          profile: s.image.profile,
          image: s.image.label,
          candidates: s.candidate_info.count,
          feature_tables: s.feature_tables.length,
        });
      continue;
    }
    let candidates = s.feature_pairs;
    if (hint) {
      const matching = candidates.filter((x) => (x.dl.root_off < x.ul.root_off ? "DL_FIRST" : "UL_FIRST") === hint);
      if (matching.length) candidates = matching;
    }
    const best = candidates[0];
    s.dl_table = best.dl;
    s.ul_table = best.ul;
    // score[1] is -exact_lengths; when nothing is exact that is -0, which
    // python serializes as 0 — normalize so the JSON differential stays exact.
    s.feature_detail = {
      ...best.detail,
      score: best.score.slice().map((v) => (v === 0 ? 0 : v)),
      order_hint: hint,
      dl_root_relative: best.dl.root_off - s.image.source_offset,
      ul_root_relative: best.ul.root_off - s.image.source_offset,
      dl_len: best.dl.length,
      ul_len: best.ul.length,
    };
  }
  const unresolvedSet = new Set(unresolved);
  const resolved = states.filter((s) => !unresolvedSet.has(s));
  if (!resolved.length) {
    throw new UniversalError("no capability profile could be resolved: no DL/UL feature-table "
      + "assignment passes domain and UL-class closure on any profile");
  }
  rep.info("feature_orientation", "resolved DL/UL feature-table orientation across capability profiles",
    { hint, profiles: resolved.length, unresolved: unresolved.map((x) => x.image.profile) });
  return [resolved, unresolved.map((x) => x.image.profile)];
}

export function decodeProfileCombos(p, s) {
  if (!s.dl_table || !s.ul_table) throw new UniversalError("profile has no resolved DL/UL feature pair");
  const absent = p.tables.nr_ul_absent;
  const out = [];
  for (const cand of s.candidates) {
    const nvar = cand.nr ? cand.nr.variants : 1;
    const lvar = cand.lte ? cand.lte.variants : 1;
    if (nvar !== lvar && nvar !== 1 && lvar !== 1) {
      throw new UniversalError(`${s.image.label}: LTE/NR variant cardinalities incompatible: LTE=${lvar} NR=${nvar}`);
    }
    const variants = Math.max(nvar, lvar);
    for (let v = 0; v < variants; v++) {
      const lteComps = [];
      const nrComps = [];
      if (cand.lte) {
        const d = cand.lte;
        const vr = lvar === 1 ? 0 : v;
        let cur = vr * d.units;
        for (const [band, ul, dl] of d.records) {
          const n = p.tables.lte_weights[dl];
          const sl = d.fsc.slice(cur, cur + n);
          cur += n;
          if (sl.length !== n) throw new UniversalError("LTE cursor underflow");
          const mm = [];
          for (const [, b1] of sl) {
            if (!(b1 in DL_MIMO)) {
              throw new UniversalError(`${s.image.label}: LTE DL MIMO status ${b1} is unsupported/rejected`);
            }
            mm.push(DL_MIMO[b1]);
          }
          lteComps.push(new LteComponent(band, dl, ul, mm));
        }
        if (cur !== (vr + 1) * d.units) throw new UniversalError("LTE cursor exhaustion failed");
      }
      if (cand.nr) {
        const d = cand.nr;
        const vr = nvar === 1 ? 0 : v;
        let cur = vr * d.units;
        for (const [band, ul, dl] of d.records) {
          const n = p.tables.nr_weights[dl];
          const sl = d.fsc.slice(cur, cur + n);
          cur += n;
          const ccs = [];
          let activeUl = 0;
          for (const [scs, ui, di] of sl) {
            if (!(scs in SCS)) throw new UniversalError(`invalid NR SCS enum ${scs}`);
            if (di >= s.dl_table.length || ui >= s.ul_table.length) {
              throw new UniversalError("feature id escaped table");
            }
            const dob = s.dl_table.objects[di];
            const uob = s.ul_table.objects[ui];
            if (!(dob.mimo_status in DL_MIMO)) {
              throw new UniversalError("DL feature references unsupported object");
            }
            const dlBw = p.tables.bw[dob.bw_code];
            let um = null;
            let ub = null;
            if (uob.mimo_status in UL_MIMO) {
              activeUl++;
              um = UL_MIMO[uob.mimo_status];
              ub = p.tables.bw[uob.bw_code];
            }
            ccs.push(new NrCC(SCS[scs], DL_MIMO[dob.mimo_status], dlBw, um, ub));
          }
          const exp = absent.has(ul) ? 0 : p.tables.nr_weights[ul];
          if (activeUl !== exp) {
            throw new UniversalError(`UL feature/class mismatch after pair resolution: band n${band}, active=${activeUl}, expected=${exp}`);
          }
          // Normalize all discovered absent sentinels to the canonical 0x1c.
          const ulNorm = absent.has(ul) ? NR_UL_ABSENT_CANON : ul;
          nrComps.push(new NrComponent(band, dl, ulNorm, ccs));
        }
        if (cur !== (vr + 1) * d.units) throw new UniversalError("NR cursor exhaustion failed");
      }
      out.push(new MtkCombo(lteComps, nrComps));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------

export class LteRow {
  constructor(off, combo, layout = "legacy32") {
    this.off = off;
    this.combo = combo;
    this.layout = layout;
  }
}

// Validate one LTE CA row starting at the absolute offset of its count field.
// Two packagings of the same six fields are proven in the corpus (modern grid
// contiguous 32-byte row with c0 at row+8; MD800 legacy pointer array with c0
// at (va - relocation) + 4); only the framing differs.
export function parseLteFields(im, c0Off, tables) {
  if (c0Off < im.source_offset || c0Off + 24 > im.end_source) return null;
  const c0 = u32(im.drdi, c0Off);
  const p0 = u32(im.drdi, c0Off + 4);
  const c1 = u32(im.drdi, c0Off + 8);
  const p1 = u32(im.drdi, c0Off + 12);
  if (!(c0 >= 1 && c0 <= 16)) return null;
  const ro = im.resolve(p0, c0 * 3);
  const mo = im.resolve(p1, c1);
  if (ro === null || mo === null) return null;
  const recs = [];
  let units = 0;
  for (let k = 0; k < c0; k++) {
    const idx = im.drdi[ro + 3 * k];
    const ul = im.drdi[ro + 3 * k + 1];
    const dl = im.drdi[ro + 3 * k + 2];
    if (idx >= tables.lte_band_map.length) return null;
    const band = tables.lte_band_map[idx];
    if (band === 0 || band > MAX_LTE_BAND || dl >= 6 || (ul !== LTE_UL_ABSENT && ul >= 6)) return null;
    units += tables.lte_weights[dl];
    recs.push([band, ul, dl]);
  }
  if (c1 !== units || c1 <= 0) return null;
  const mmraw = Array.from(im.drdi.subarray(mo, mo + c1));
  if (mmraw.some((x) => x !== 2 && x !== 3 && x !== 4)) return null;
  // Proven common encoding in the LTE row table is actual-ish status
  // 2->2Rx, 3->4Rx; 4->8Rx is allowed for forward compatibility.
  const mmap = { 2: 2, 3: 4, 4: 8 };
  let cur = 0;
  const comps = [];
  for (const [band, ul, dl] of recs) {
    const n = tables.lte_weights[dl];
    const sl = mmraw.slice(cur, cur + n);
    cur += n;
    comps.push(new LteComponent(band, dl, ul, sl.map((x) => mmap[x])));
  }
  if (cur !== c1) return null;
  return new MtkCombo(comps, []);
}

// Modern contiguous 32-byte row: flags, sub, then the six shared fields.
export function parseLteRow(im, off, tables) {
  if (off < im.source_offset || off + 32 > im.end_source) return null;
  const cb = parseLteFields(im, off + 8, tables);
  return cb === null ? null : new LteRow(off, cb);
}

// Extended contiguous LTE row used by newer grid firmware: nine u32s
// (word0, flags, selector, component_count, component_ptr, mimo_count,
// dl_mimo_ptr, companion_mimo_ptr, component_count_copy). The selector and
// companion vector are not needed for the LTE CA projection, but both counts
// must agree and both MIMO vectors must be in-range — that keeps the scanner
// from accepting a plausible six-field window inside unrelated data.
export function parseLteRow36(im, off, tables) {
  if (off < im.source_offset || off + 36 > im.end_source) return null;
  const flags = u32(im.drdi, off + 4);
  const c0 = u32(im.drdi, off + 12);
  const p0 = u32(im.drdi, off + 16);
  const c1 = u32(im.drdi, off + 20);
  const p1 = u32(im.drdi, off + 24);
  const p2 = u32(im.drdi, off + 28);
  const c2 = u32(im.drdi, off + 32);
  if ((flags >>> 16) !== 0xffff || !(c0 >= 1 && c0 <= 16) || c2 !== c0) return null;
  const ro = im.resolve(p0, c0 * 3);
  const mo = im.resolve(p1, c1);
  const companion = im.resolve(p2, c1);
  if (ro === null || mo === null || companion === null || c1 <= 0) return null;
  const recs = [];
  let units = 0;
  for (let k = 0; k < c0; k++) {
    const idx = im.drdi[ro + 3 * k];
    const ul = im.drdi[ro + 3 * k + 1];
    const dl = im.drdi[ro + 3 * k + 2];
    if (idx >= tables.lte_band_map.length) return null;
    const band = tables.lte_band_map[idx];
    if (band === 0 || band > MAX_LTE_BAND || dl >= 6 || (ul !== LTE_UL_ABSENT && ul >= 6)) return null;
    units += tables.lte_weights[dl];
    recs.push([band, ul, dl]);
  }
  if (c1 !== units) return null;
  const mmraw = Array.from(im.drdi.subarray(mo, mo + c1));
  const companionRaw = Array.from(im.drdi.subarray(companion, companion + c1));
  if (mmraw.some((x) => x !== 2 && x !== 3 && x !== 4) || companionRaw.some((x) => x !== 2 && x !== 3 && x !== 4)) {
    return null;
  }
  const mmap = { 2: 2, 3: 4, 4: 8 };
  let cur = 0;
  const comps = [];
  for (const [band, ul, dl] of recs) {
    const n = tables.lte_weights[dl];
    const sl = mmraw.slice(cur, cur + n);
    cur += n;
    comps.push(new LteComponent(band, dl, ul, sl.map((x) => mmap[x])));
  }
  if (cur !== c1) return null;
  return new LteRow(off, new MtkCombo(comps, []), "extended36");
}

// Find supported contiguous LTE row tables by 100% invariant runs. Older
// grid/CDF images use 32-byte rows, newer grid images the extended 36-byte
// layout; layout selection is structural (scan every four-byte phase for each
// stride, retain the longest fully valid run). A winning run's layout is also
// recorded on the image (im.lte_row_layout) — python surfaces the same fact
// through the lte_row_table info issue.
export function scanLteRowsBank(bank, tables, rep) {
  const result = new Map();
  for (const im of bank.images) {
    // The count prefilter below walks every stride position of the whole
    // image — read it through a little-endian word view (identical values to
    // the byte-compose u32, ~an order of magnitude faster at this volume).
    const words = alignedWords32(im.drdi);
    let best = [];
    for (const [stride, countDelta, parser] of [[32, 8, parseLteRow], [36, 12, parseLteRow36]]) {
      // Source offsets need not be stride-aligned, so cover every four-byte
      // phase relative to the complete DRDI image.
      for (let residue = 0; residue < stride; residue += 4) {
        const start = im.source_offset + ((((residue - im.source_offset) % stride) + stride) % stride);
        const rows = [];
        let cur = [];
        let previous = null;
        for (let off = start; off <= im.end_source - stride; off += stride) {
          // Skipped impossible rows still terminate invariant runs; the count
          // is only a prefilter, full acceptance stays with the parser. Walk
          // offsets stay 4-aligned (start ≡ residue ≡ 0 mod 4, stride % 4 === 0).
          if (previous !== null && off !== previous + stride) {
            if (cur.length >= 4) rows.push(cur);
            cur = [];
          }
          previous = off;
          let r = null;
          const count = words !== null ? words[(off + countDelta) >> 2] : u32(im.drdi, off + countDelta);
          if (count >= 1 && count <= 16) r = parser(im, off, tables);
          if (r) cur.push(r);
          else {
            if (cur.length >= 4) rows.push(cur);
            cur = [];
          }
        }
        if (cur.length >= 4) rows.push(cur);
        if (rows.length) {
          let m = rows[0];
          for (const r of rows) if (r.length > m.length) m = r;
          if (m.length > best.length) best = m;
        }
      }
    }
    if (best.length) {
      result.set(im.profile, best.map((r) => r.combo));
      im.lte_row_layout = best[0].layout;
      rep.info("lte_row_table", "found invariant-valid LTE CA row table", {
        bank_va: hex(bank.bank_va),
        profile: im.profile,
        relative_off: hex(best[0].off - im.source_offset),
        rows: best.length,
        row_layout: best[0].layout,
        row_stride: best[0].layout === "extended36" ? 36 : 32,
      });
    }
  }
  return result;
}

// Collect LTE CA rows from EVERY bank that contains invariant-valid ones.
// A bank whose rows satisfy the class weight invariant, MIMO encoding and
// cursor exhaustion has earned its place in the output; the primary bank is
// still identified and reported. Returns [primaryBank, Map(profile -> combos)].
export function chooseLteBank(loader, cap, rep) {
  const pool = loader.banks.filter((b) => b.images.length);
  const found = [];
  for (const b of pool) {
    const rows = scanLteRowsBank(b, loader.tables, rep);
    if (rows.size) {
      const lens = [...rows.values()].map((v) => v.length);
      found.push({
        score: [Math.max(...lens), lens.reduce((a, x) => a + x, 0), rows.size],
        bank: b,
        rows,
      });
    }
  }
  // Preserve physical provenance; the merged projection remains available below.
  loader.lte_rows_by_bank = {};
  for (const { bank, rows } of found) loader.lte_rows_by_bank[bank.table_index] = rows;
  if (!found.length) {
    rep.warn("lte_bank_missing", "no invariant-valid modern 32-byte LTE CA table found");
    return [null, new Map()];
  }
  // sorted(key=score, reverse=True) is stable: equal keys keep bank order.
  found.sort((a, b) => cmpTupleDesc(a.score, b.score));
  const primary = found[0];
  const merged = new Map();
  for (const { rows } of found) {
    for (const [prof, combos] of rows) {
      if (!merged.has(prof)) merged.set(prof, []);
      merged.get(prof).push(...combos);
    }
  }
  const mergedOrdered = new Map(
    [...merged.entries()].sort((a, b) => a[0] - b[0]).map(([k, v]) => [k, dedupExact(v)]),
  );
  rep.info("lte_bank", "collected LTE CA rows from every bank with invariant-valid rows", {
    primary_bank: hex(primary.bank.bank_va),
    banks: found.length,
    per_bank: found.map(({ bank, rows }) => ({
      bank_va: hex(bank.bank_va),
      primary: bank.bank_va === primary.bank.bank_va,
      profiles: Object.fromEntries(
        [...rows.keys()].sort((a, b) => a - b).map((k) => [String(k), rows.get(k).length]),
      ),
    })),
    merged_profiles: Object.fromEntries(
      [...mergedOrdered.keys()].map((k) => [String(k), mergedOrdered.get(k).length]),
    ),
  });
  return [primary.bank, mergedOrdered];
}

function cmpTupleDesc(a, b) {
  for (let i = 0; i < a.length; i++) {
    if (a[i] > b[i]) return -1;
    if (a[i] < b[i]) return 1;
  }
  return 0;
}

// ---------------------------------------------------------------------------

// Recover a firmware-authentic standalone supported-band list: a fixed
// 40-entry u16 table (strictly increasing 3GPP band numbers, then 0xfffd
// padding) whose runtime address must also be referenced by an aligned word
// in md1rom, independently proving it is an initialized firmware object.
export function discoverSupportedBandList(loader, bank, rat, rep) {
  if (!bank || !bank.images.length) return {};
  rat = rat.toUpperCase();
  const maxBand = rat === "LTE" ? MAX_LTE_BAND : 1024;
  const slotBytes = 2 * SUPPORTED_BAND_SLOTS;
  const rom = loader.rom;
  const profiles = {};
  // One rom word pass per BANK: per-image windows are [lo, lo + maxLen), so a
  // union-window collection followed by the exact per-image window filter is
  // identical to the former per-image full scans (ptr values, order included).
  const maxLen = Math.max(...bank.images.map((x) => x.length));
  const imageLo = new Map();
  let scanLo = Infinity;
  let scanHi = -Infinity;
  for (const im of bank.images) {
    const lo = im.bank_va + im.alias;
    imageLo.set(im, lo);
    if (lo < scanLo) scanLo = lo;
    if (lo + maxLen > scanHi) scanHi = lo + maxLen;
  }
  const unionPtrValues = [];
  if (scanHi > scanLo && bank.images.length) {
    const words = alignedWords32(rom);
    if (words !== null) {
      for (let i = 0; i < words.length; i++) {
        const v = words[i];
        if (v >= scanLo && v + slotBytes <= scanHi) unionPtrValues.push(v);
      }
    } else {
      for (let o = 0; o + 4 <= rom.length; o += 4) {
        const v = u32(rom, o);
        if (v >= scanLo && v + slotBytes <= scanHi) unionPtrValues.push(v);
      }
    }
  }
  for (const im of bank.images) {
    // (Window-filtered candidate pointers; see the bank-wide scan above.)
    const lo = imageLo.get(im);
    const hiMax = lo + maxLen;
    const ptrValues = [];
    for (const v of unionPtrValues) {
      if (v >= lo && v + slotBytes <= hiMax) ptrValues.push(v);
    }
    ptrValues.sort((a, b) => a - b);
    const candidates = [];
    for (const va of new Set(ptrValues)) {
      const off = im.resolve(va, slotBytes);
      if (off === null) continue;
      const vals = [];
      for (let i = 0; i < SUPPORTED_BAND_SLOTS; i++) vals.push(u16(im.drdi, off + 2 * i));
      const used = vals.indexOf(SUPPORTED_BAND_PAD);
      if (used < 0) continue;
      const bands = vals.slice(0, used);
      if (!(bands.length >= 8 && bands.length < SUPPORTED_BAND_SLOTS)) continue;
      if (bands.some((b) => !(b >= 1 && b <= maxBand))) continue;
      if (bands.some((b, i) => i > 0 && bands[i - 1] >= b)) continue;
      if (vals.slice(used).some((v) => v !== SUPPORTED_BAND_PAD)) continue;
      const refs = findAll(rom, new Uint8Array([va & 0xff, (va >>> 8) & 0xff, (va >>> 16) & 0xff, (va >>> 24) & 0xff]));
      candidates.push([off, va, bands, refs]);
    }
    // More than one differently-valued object would make the role ambiguous;
    // report it instead of silently selecting a convenient table.
    const distinct = new Set(candidates.map((c) => c[2].join(",")));
    if (distinct.size > 1) {
      rep.warn("supported_band_list_ambiguous",
        "multiple differently-valued ROM-referenced supported-band lists in one profile",
        { rat, bank_index: bank.table_index, profile: im.profile, candidates: candidates.length });
      continue;
    }
    if (candidates.length) {
      let pick = candidates[0];
      for (const c of candidates) if (c[0] < pick[0]) pick = c;
      const [off, va, bands, refs] = pick;
      profiles[String(im.profile)] = {
        bands: bands.slice(),
        relative_off: hex(off - im.source_offset),
        runtime_va: hex(va),
        rom_pointer_refs: refs.map(hex),
      };
      rep.info("supported_band_list", "recovered ROM-referenced standalone supported-band list", {
        rat,
        bank_index: bank.table_index,
        profile: im.profile,
        relative_off: hex(off - im.source_offset),
        bands: bands.slice(),
        rom_pointer_refs: refs.map(hex),
      });
    }
  }
  if (!Object.keys(profiles).length) return {};
  const sets = Object.values(profiles).map((v) => new Set(v.bands));
  const union = [...sets.reduce((acc, s) => {
    for (const x of s) acc.add(x);
    return acc;
  }, new Set())].sort((a, b) => a - b);
  const intersection = [...sets.reduce((acc, s) => {
    return new Set([...acc].filter((x) => s.has(x)));
  })].sort((a, b) => a - b);
  return {
    rat,
    bank_index: bank.table_index,
    bank_va: hex(bank.bank_va),
    profiles,
    union,
    intersection,
    profiles_consistent: sets.every((s) => s.size === sets[0].size && [...s].every((x) => sets[0].has(x))),
  };
}

// Return standalone LTE/NR support separately from combination rows.
export function discoverSupportedBands(loader, cap, lteBank, rep) {
  const out = {};
  const lte = discoverSupportedBandList(loader, lteBank, "LTE", rep);
  const nr = discoverSupportedBandList(loader, cap, "NR", rep);
  // python tests the returned dicts for truthiness; an empty JS object is
  // truthy, so only non-empty lists are attached.
  if (Object.keys(lte).length) out.lte = lte;
  if (Object.keys(nr).length) out.nr = nr;
  return out;
}

// Add combination participation without treating support as a combo.
export function annotateBandParticipation(support, capabilityCombos, lteCombos) {
  if (support.lte) {
    const participating = [...new Set(lteCombos.flatMap((row) => row.lte.map((c) => c.band)))].sort((a, b) => a - b);
    support.lte.combination_participating = participating;
    support.lte.supported_without_lte_ca_row = support.lte.union.filter((b) => !participating.includes(b));
  }
  if (support.nr) {
    const participating = [...new Set(capabilityCombos.flatMap((row) => row.nr.map((c) => c.band)))].sort((a, b) => a - b);
    support.nr.combination_participating = participating;
    support.nr.supported_without_nr_combination_row = support.nr.union.filter((b) => !participating.includes(b));
  }
  return support;
}

// Per-profile summary exactly in the shape of mtk_universal's
// serialize_profile_summary (key order matters; goldens compare it).
export function serializeProfileSummary(states, perProfile) {
  const out = [];
  for (const s of states) {
    const combos = perProfile.get(s.image.profile);
    if (!combos) continue;
    const [en, nr, lt] = classify(combos, 1);
    out.push({
      profile: s.image.profile,
      image: s.image.toDict(),
      candidate_array: s.candidate_info,
      feature_tables_found: s.feature_tables.length,
      feature_tables: s.feature_tables
        .slice()
        .sort((a, b) => b.length - a.length)
        .slice(0, 12)
        .map((t) => ({ root_relative: hex(t.root_off - s.image.source_offset), length: t.length })),
      feature_resolution: s.feature_detail,
      feature_pair_search: s.pair_stats,
      decoded_rows: combos.length,
      kinds: { endc: en.length, nrca: nr.length, lte: lt.length },
      gui_counts: guiFamilyCounts(combos),
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Tensor secondary bank decoder (port of mtk_tensor_secondary.py). Pixel/
// Tensor images keep the ordinary FR1 grammar in the capability bank but root
// the FR2/NR-DC catalogue in a sibling bank (normally bank 8) via small
// pointer tables in md1rom, with a different NR class-weight namespace.
// ---------------------------------------------------------------------------

// Tensor FR2 uses a native G..M namespace whose multiplicity is not the
// generic FR1 table. These are raw firmware class bytes, not B826 letters.
export const FR2_WEIGHT = { 0: 1, 6: 2, 7: 3, 8: 4, 9: 5, 10: 6, 11: 7, 12: 8 };
export const NR_OMIT_UL = new Set([0x1c, 0xff]);

export class SecondaryProfile {
  constructor(bank_index, bank_va, profile, combos, candidate_count, expanded_rows, excluded_single_fr2, roots) {
    this.bank_index = bank_index;
    this.bank_va = bank_va;
    this.profile = profile;
    this.combos = combos;
    this.candidate_count = candidate_count;
    this.expanded_rows = expanded_rows;
    this.excluded_single_fr2 = excluded_single_fr2;
    this.roots = roots;
  }
}

function fr2Weight(band, cls, generic) {
  if (band >= 257) return FR2_WEIGHT[cls] ?? 0;
  return cls >= 0 && cls < generic.length ? generic[cls] : 0;
}

// Read a zero-terminated pointer array wholly contained by `im`.
function readPtrArray(im, ptr, alias, maxCount) {
  const raw = alias && ptr >= alias ? ptr - alias : ptr;
  const off = raw - im.relocation;
  if (off < im.source_offset || off + 4 > im.end_source) return null;
  const out = [];
  for (let i = 0; i < maxCount; i++) {
    const pos = off + i * 4;
    if (pos + 4 > im.end_source) return null;
    const value = u32(im.drdi, pos);
    if (value === 0) return out;
    out.push(value);
  }
  return null;
}

class TensorSecondaryDecoder {
  constructor(loader, bank, reporter) {
    this.loader = loader;
    this.bank = bank;
    this.reporter = reporter;
    this.alias = (loader.constructor && loader.constructor.ALIAS) ?? TensorCdfLoader.ALIAS;
    this.images = new Map(bank.images.map((im) => [im.profile, im]));
    this.genericNrWeight = loader.tables.nr_weights;
    this.lteBandMap = loader.tables.lte_band_map;
    this.bw = loader.tables.bw;
    this._descCache = new Map();
  }

  // ROM words that can point into this bank (small, bounded search set).
  _candidateValues() {
    const lo = this.bank.bank_va;
    const hi = lo + Math.max(...this.images.values().map((im) => im.length));
    const alo = lo + this.alias;
    const ahi = hi + this.alias;
    const aliased = new Set();
    const rawVals = new Set();
    const rom = this.loader.rom;
    for (let o = 0; o + 4 <= rom.length; o += 4) {
      const v = u32(rom, o);
      if (v >= alo && v < ahi) aliased.add(v);
      else if (v >= lo && v < hi) rawVals.add(v);
    }
    const vals = aliased.size ? aliased : rawVals;
    return [...vals].sort((a, b) => a - b);
  }

  _decodeDesc(im, ptr, nr) {
    const key = `${im.profile}|${ptr}|${nr ? 1 : 0}`;
    if (this._descCache.has(key)) return this._descCache.get(key);
    const off = im.resolve(ptr, 16);
    if (off === null) return null;
    const count = u32(im.drdi, off);
    const recordsPtr = u32(im.drdi, off + 4);
    const fscCount = u32(im.drdi, off + 8);
    const fscPtr = u32(im.drdi, off + 12);
    if (!(count >= 1 && count <= 16) || fscCount <= 0) return null;
    const recSize = nr ? 4 : 3;
    const recordsOff = im.resolve(recordsPtr, count * recSize);
    if (recordsOff === null) return null;
    const records = [];
    let units = 0;
    for (let i = 0; i < count; i++) {
      if (nr) {
        const band = u16(im.drdi, recordsOff + i * 4);
        const ul = im.drdi[recordsOff + i * 4 + 2];
        const dl = im.drdi[recordsOff + i * 4 + 3];
        const w = fr2Weight(band, dl, this.genericNrWeight);
        if (!(band >= 1 && band <= 1024) || w <= 0) return null;
        if (!NR_OMIT_UL.has(ul) && fr2Weight(band, ul, this.genericNrWeight) <= 0) return null;
        records.push([band, ul, dl]);
        units += w;
      } else {
        const idx = im.drdi[recordsOff + i * 3];
        const ul = im.drdi[recordsOff + i * 3 + 1];
        const dl = im.drdi[recordsOff + i * 3 + 2];
        if (!(idx >= 0 && idx < this.lteBandMap.length)) return null;
        const band = this.lteBandMap[idx];
        if (!(band >= 1 && band <= MAX_LTE_BAND) || !(dl >= 0 && dl < LTE_WEIGHTS_EXPECTED.length)) return null;
        if (ul !== LTE_UL_ABSENT && !(ul >= 0 && ul < LTE_WEIGHTS_EXPECTED.length)) return null;
        records.push([band, ul, dl]);
        units += LTE_WEIGHTS_EXPECTED[dl];
      }
    }
    const fscSize = nr ? 3 : 2;
    const fscOff = fscPtr ? im.resolve(fscPtr, fscCount * fscSize) : null;
    if (units <= 0 || fscOff === null || fscCount % units) return null;
    const result = {
      count,
      records,
      fsc_count: fscCount,
      fsc_off: fscOff,
      units,
      variants: Math.floor(fscCount / units),
      nr,
    };
    this._descCache.set(key, result);
    return result;
  }

  _candidateShape(im, ptr) {
    const off = im.resolve(ptr, 16);
    if (off === null) return null;
    const meta0 = u32(im.drdi, off);
    const meta1 = u32(im.drdi, off + 4);
    const ltePtr = u32(im.drdi, off + 8);
    const nrPtr = u32(im.drdi, off + 12);
    if (nrPtr === 0) return null;
    const nr = this._decodeDesc(im, nrPtr, true);
    if (nr === null) return null;
    const lte = ltePtr ? this._decodeDesc(im, ltePtr, false) : null;
    if (ltePtr && lte === null) return null;
    return { ptr, meta0, meta1, lte, nr };
  }

  _candidateRoots(values) {
    const found = new Map();
    for (const [profile, im] of this.images) {
      let best = null;
      for (const root of values) {
        const pointers = readPtrArray(im, root, this.alias, 100000);
        // A secondary capability root is a large array; this excludes feature
        // arrays and incidental pointer lists early.
        if (!pointers || pointers.length < 32) continue;
        const sample = pointers.slice(0, Math.min(128, pointers.length));
        if (sample.some((p) => this._candidateShape(im, p) === null)) continue;
        const decoded = [];
        for (const p of pointers) {
          const shape = this._candidateShape(im, p);
          if (shape === null) {
            decoded.length = 0;
            break;
          }
          decoded.push(shape);
        }
        if (decoded.length && (best === null || decoded.length > best[1].length)) best = [root, decoded];
      }
      if (best !== null) found.set(profile, best);
    }
    return found;
  }

  _featureRoots(values) {
    const found = new Map();
    for (const [profile, im] of this.images) {
      const choices = [];
      for (const root of values) {
        const pointers = readPtrArray(im, root, this.alias, 128);
        if (!pointers || pointers.length < 8 || pointers.length > 64) continue;
        const rows = [];
        for (const p of pointers) {
          const off = im.resolve(p, 3);
          if (off === null) {
            rows.length = 0;
            break;
          }
          const status = im.drdi[off];
          const bw = im.drdi[off + 1];
          const bw90 = im.drdi[off + 2];
          // Unsupported feature objects conventionally carry a sentinel BW
          // index, so only supported rows use the ROM dictionary domain check.
          if ((status !== 0 && status !== 1 && status !== 2 && status !== 3)
            || (status !== 3 && bw >= this.bw.length)) {
            rows.length = 0;
            break;
          }
          rows.push([status, bw, bw90 ? 1 : 0]);
        }
        if (rows.length) choices.push([root, rows]);
      }
      if (choices.length) found.set(profile, choices);
    }
    return found;
  }

  _decodeProfile(im, candidates, dlFeatures, ulFeatures) {
    const combos = [];
    let singleFr2 = 0;
    for (const candidate of candidates) {
      const nr = candidate.nr;
      const lte = candidate.lte;
      const lteVariants = lte ? lte.variants : 1;
      const nrVariants = nr.variants;
      if (lte && lteVariants !== 1 && lteVariants !== nrVariants && nrVariants !== 1) return null;
      const variants = Math.max(lteVariants, nrVariants);
      const lteRaw = lte ? im.drdi.subarray(lte.fsc_off, lte.fsc_off + lte.fsc_count * 2) : null;
      const nrRaw = im.drdi.subarray(nr.fsc_off, nr.fsc_off + nr.fsc_count * 3);
      const bands = nr.records.map((r) => r[0]);
      const hasFr1 = bands.some((b) => b < 257);
      const hasFr2 = bands.some((b) => b >= 257);
      if (!lte && !(hasFr1 && hasFr2)) {
        singleFr2 += variants;
        continue;
      }
      for (let variant = 0; variant < variants; variant++) {
        const outLte = [];
        if (lte) {
          const lv = lteVariants === 1 ? 0 : variant;
          let cursor = lv * lte.units;
          for (const [band, ul, dl] of lte.records) {
            const mimo = [];
            for (let i = 0; i < LTE_WEIGHTS_EXPECTED[dl]; i++) {
              const status = lteRaw[cursor * 2 + 1];
              if (status !== 0 && status !== 1 && status !== 2) return null;
              mimo.push(status === 0 ? 2 : status === 1 ? 4 : 8);
              cursor++;
            }
            outLte.push({ band, dl_class: dl, ul_class: ul, dl_mimo: mimo });
          }
          if (cursor !== (lv + 1) * lte.units) return null;
        }
        const outNr = [];
        const nv = nrVariants === 1 ? 0 : variant;
        let cursor = nv * nr.units;
        for (const [band, ul, dl] of nr.records) {
          const ccCount = fr2Weight(band, dl, this.genericNrWeight);
          const activeUlExpected = NR_OMIT_UL.has(ul) ? 0 : fr2Weight(band, ul, this.genericNrWeight);
          const ccs = [];
          let active = 0;
          for (let i = 0; i < ccCount; i++) {
            const scs = nrRaw[cursor * 3];
            const ui = nrRaw[cursor * 3 + 1];
            const di = nrRaw[cursor * 3 + 2];
            cursor++;
            if (!(scs in SCS) || di >= dlFeatures.length || ui >= ulFeatures.length) return null;
            const [dstatus, dbw] = dlFeatures[di];
            const [ustatus, ubw] = ulFeatures[ui];
            if (!(dstatus in DL_MIMO) || dbw >= this.bw.length) return null;
            if (ustatus !== 0 && ustatus !== 1 && ustatus !== 2 && ustatus !== 3) return null;
            if (ustatus !== 3) active++;
            ccs.push({
              scs_khz: SCS[scs],
              dl_mimo: DL_MIMO[dstatus],
              dl_bw_mhz: this.bw[dbw],
              ul_mimo: ustatus !== 3 ? (UL_MIMO[ustatus] ?? null) : null,
              ul_bw_mhz: ustatus !== 3 && ubw < this.bw.length ? this.bw[ubw] : null,
            });
          }
          if (active !== activeUlExpected) return null;
          outNr.push({ band, dl_class: dl, ul_class: NR_OMIT_UL.has(ul) ? NR_UL_ABSENT_CANON : ul, ccs });
        }
        if (cursor !== (nv + 1) * nr.units) return null;
        combos.push({ lte: outLte, nr: outNr });
      }
    }
    return [combos, singleFr2];
  }

  decode() {
    const values = this._candidateValues();
    const roots = this._candidateRoots(values);
    const featureRoots = this._featureRoots(values);
    const results = [];
    for (const [profile, im] of this.images) {
      if (!roots.has(profile) || !featureRoots.has(profile)) continue;
      const candidates = roots.get(profile)[1];
      const choices = featureRoots.get(profile);
      let best = null;
      // There are normally two choices (DL and UL); try both directions and
      // retain only the one for which all FSC references close.
      for (const [dlRoot, dl] of choices) {
        for (const [ulRoot, ul] of choices) {
          if (dlRoot === ulRoot) continue;
          const decoded = this._decodeProfile(im, candidates, dl, ul);
          if (decoded !== null) {
            const [combos, excluded] = decoded;
            if (best === null || combos.length > best.combos.length) {
              best = { combos, excluded, dlRoot, ulRoot };
            }
          }
        }
      }
      if (best === null) continue;
      const sp = new SecondaryProfile(
        this.bank.table_index, this.bank.bank_va, profile, best.combos,
        candidates.length, best.combos.length + best.excluded, best.excluded,
        { candidate: roots.get(profile)[0], dl_features: best.dlRoot, ul_features: best.ulRoot },
      );
      results.push(sp);
      if (this.reporter !== null) {
        this.reporter.info("tensor_secondary_bank", "decoded Tensor secondary FR2/NRDC bank", {
          bank_index: this.bank.table_index,
          profile,
          candidate_count: candidates.length,
          expanded_rows: sp.expanded_rows,
          exported_rows: best.combos.length,
          excluded_single_fr2: best.excluded,
          roots: { candidate: hex(sp.roots.candidate), dl_features: hex(sp.roots.dl_features), ul_features: hex(sp.roots.ul_features) },
        });
      }
    }
    return results;
  }
}

// Return validated secondary-bank profiles, or an empty list. Secondary banks
// are optional across Tensor releases; a failed proof is a warning and leaves
// the ordinary capability extraction untouched.
export function decodeTensorSecondary(loader, bankIndex = 8, rep = null) {
  const bank = loader.banks.find((b) => b.table_index === bankIndex && b.images.length) ?? null;
  if (!bank) return [];
  let results;
  try {
    results = new TensorSecondaryDecoder(loader, bank, rep).decode();
  } catch (err) {
    if (err instanceof TypeError) throw err; // a genuine bug must not masquerade as "unresolved"
    if (rep !== null) {
      rep.warn("tensor_secondary_unresolved", "secondary Tensor bank did not pass structural proof",
        { bank_index: bankIndex, reason: String(err && err.message ? err.message : err) });
    }
    return [];
  }
  if (!results.length && rep !== null) {
    rep.warn("tensor_secondary_unresolved", "secondary Tensor bank roots or FSC tables were not proved",
      { bank_index: bankIndex });
  }
  return results;
}

// Convert the secondary decoder's cycle-free dictionaries to shared rows.
export function secondaryCombos(profile) {
  const out = [];
  for (const row of profile.combos) {
    const lte = (row.lte ?? []).map((c) => new LteComponent(c.band, c.dl_class, c.ul_class, [...(c.dl_mimo ?? [])]));
    const nr = (row.nr ?? []).map((c) => new NrComponent(
      c.band, c.dl_class, c.ul_class,
      (c.ccs ?? []).map((cc) => new NrCC(cc.scs_khz, cc.dl_mimo, cc.dl_bw_mhz ?? null, cc.ul_mimo ?? null, cc.ul_bw_mhz ?? null)),
    ));
    out.push(new MtkCombo(lte, nr));
  }
  return dedupExact(out);
}

// Return the Bank-5 rows selected by the split-CDF profile map. Tensor keeps
// independent selector maps for each bank; a secondary profile may legitimately
// pair with more than one Bank-5 profile, so the union is preserved.
export function tensorRelatedLte(loader, secondaryProfile, lteProfiles) {
  const all = () => dedupExact([...lteProfiles.values()].flat());
  if (!(loader instanceof TensorCdfLoader) || !lteProfiles.size) return all();
  let target;
  let source;
  try {
    const [targetOff, targetSize] = loader.sections[6 + 8];
    const [sourceOff, sourceSize] = loader.sections[6 + 5];
    if (targetSize < 2 * 128 || sourceSize < 2 * 128) {
      throw new Error("CDF selector maps are shorter than 128 entries");
    }
    target = [];
    source = [];
    for (let i = 0; i < 128; i++) {
      target.push(u16(loader.header, targetOff + i * 2));
      source.push(u16(loader.header, sourceOff + i * 2));
    }
  } catch (err) {
    if (err instanceof TypeError) throw err; // a genuine bug must not masquerade as "no selector map"
    return all();
  }
  const related = new Set();
  for (let i = 0; i < 128; i++) {
    if (target[i] === secondaryProfile && lteProfiles.has(source[i])) related.add(source[i]);
  }
  if (!related.size) return all();
  return dedupExact([...related].sort((a, b) => a - b).flatMap((p) => lteProfiles.get(p)));
}
