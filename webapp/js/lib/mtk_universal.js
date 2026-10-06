// Stage-A part of the port of mtk-drdi-combo-parser/mtk_universal.py:
// module constants, Reporter, ROM dictionary discovery, Image/Bank records,
// GridLoader (modern 12-byte descriptor matrix) and TensorCdfLoader (split
// CDF). The grammar parser, feature resolver, decoders, supported-band lists,
// flat loader and scan orchestration are Stage B+ and are NOT ported here.
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
  if (Array.isArray(v)) return `[${v.map(formatPyValue).join(", ")}]`;
  if (v instanceof Uint8Array) return String([...v]);
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
    this._candidateArrays = {};
  }

  listBanks() { return this.banks; }
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
    const raw = descriptorHits ?? GridLoader.descriptorHits(this.rom, this.drdi);
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

    this.descriptor_table_off = table[0][0];
    this.columns = colCount;
    this.banks = [];
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
        images.push(new Image(va, pi, src, ln, va - src, this.drdi, `bank${bi}/profile${pi}`));
      }
      this.banks.push(new Bank(va, images, bi));
    }
    this.rep.info("grid_loader", "discovered modern bank/profile descriptor matrix", {
      descriptor_table_off: hex(this.descriptor_table_off),
      columns: this.columns,
      banks: this.banks.length,
      live_counts: this.banks.map((b) => b.images.length),
    });
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
