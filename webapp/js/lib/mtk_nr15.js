// NR15 decoder: NR15 grids (MT6833 / MT6877), ROM-resident profile roots,
// the older two-byte MIMO grammar, and the firmware bandwidth-pair /
// SCS projection. There is NO ground truth for this family in the reference
// copy we differentiate against, so the decoder ships as-is and
// is covered by synthetic probe/activation tests only.
//
// MEMORY NOTE (deliberate, do not "fix" without ground truth): Nr15Decoder
// concatenates rom+drdi into one buffer (2x input footprint) and builds a
// full-ROM PC-relative reference index — both match the reference algorithm
// exactly; a leaner rewrite would be untestable against any decoder.
import {
  BaseLoader,
  Image,
  UniversalError,
  BW_FAMILIES,
  VA_LO,
  VA_HI,
  MAX_LTE_BAND,
  LTE_UL_ABSENT,
  NR_UL_ABSENT_CANON,
  SCS,
  DL_MIMO,
  UL_MIMO,
  RawDescriptor,
  RawCandidate,
  ProfileState,
  MtkCombo,
  LteComponent,
  NrComponent,
  NrCC,
  dedupExact,
  gridDiscover,
  findAll,
  wordsOf,
  packU32,
  u16,
  u32,
  nr15Pattern,
} from "./mtk_universal.js";
import { indexOfBytes } from "./bytes.js";

const findBytes = (hay, needle, from = 0) => indexOfBytes(hay, needle, from);

// --- bandwidth-pair tables -------------------------------------------------------

const PAIR_TABLES = {
  1: [[10, 5], [9, 7], [7, 9], [5, 10]],
  3: [[10, 3], [9, 6], [8, 7], [7, 8], [6, 9], [3, 10]],
  2: [[10, 5], [9, 6], [9, 7], [7, 9], [6, 9], [5, 10], [13, 13], [13, 13]],
  4: [[10, 3], [9, 5], [9, 6], [8, 7], [7, 8], [6, 9], [5, 9], [3, 10]],
  6: [[9, 3], [8, 5], [8, 6], [7, 7], [6, 8], [5, 8], [3, 9], [13, 13]],
};

function tableSignature() {
  const out = [];
  for (const mode of [1, 3, 2, 4, 6]) for (const pair of PAIR_TABLES[mode]) out.push(...pair);
  return out;
}

export function bandwidthPairs(limits, mode, bandwidths) {
  if (!(limits.length === 1 || limits.length === 2) || limits.some((c) => !(c >= 0 && c <= 10))) {
    throw new UniversalError("NR15 requires one or two validated <=100-MHz band limits");
  }
  const intra = limits.length === 1;
  if (mode === 0) return intra ? [[limits[0], limits[0]]] : [[...limits]];
  if (!(intra ? [1, 3, 5] : [2, 4, 6]).includes(mode)) throw new UniversalError("NR15 bandwidth mode does not match intra/inter-band shape");
  const total = intra ? bandwidths[limits[0]] * 2 : limits.reduce((n, c) => n + bandwidths[c], 0);
  const budget = { 1: 130, 2: 130, 3: 120, 4: 120, 5: 100, 6: 100 }[mode];
  if (total <= budget) return intra ? [[limits[0], limits[0]]] : [[...limits]];
  if (mode === 5) {
    const code = limits[0] > 6 ? 7 : 10;
    return [[code, code]];
  }
  let result;
  if (intra) {
    result = PAIR_TABLES[mode].filter((p) => p[0] <= limits[0]);
  } else {
    const reverse = limits[1] < limits[0];
    const [low, high] = [...limits].sort((a, b) => a - b);
    result = [];
    for (const [a, b] of PAIR_TABLES[mode]) {
      if (a > low || b > high) continue;
      const [threshold, excluded] = mode === 6 ? [8, [5, 8]] : mode === 2 ? [9, [6, 9]] : [9, [5, 9]];
      let reject;
      if (low >= threshold) {
        reject = high > excluded[0] && ((a === excluded[0] && b === excluded[1]) || (a === excluded[1] && b === excluded[0]));
      } else {
        reject = low > excluded[0] && high >= threshold && a === excluded[0] && b === excluded[1];
      }
      if (reject) continue;
      result.push(reverse ? [b, a] : [a, b]);
    }
  }
  return result.length || mode === 6 ? result : [[10, 10]];
}

// --- NR15 grid decoder -----------------------------------------------------------

const BW_MODE_INTER = 4;
const BW_MODE_INTRA = 3;
const SCS15_MAX_CODE = 7;
const DL_SCS_BUDGET = 160;

const i16 = (d, o) => (u16(d, o) << 16) >> 16;
const wrap32 = (v) => ((v % 2 ** 32) + 2 ** 32) % 2 ** 32;

function pcrel48(rom, off, reg) {
  if (off < 0 || off + 6 > rom.length) return null;
  const h = u16(rom, off), lo = u16(rom, off + 2), hi = i16(rom, off + 4);
  if (h !== (0x6003 | (reg << 5))) return null;
  return wrap32(off + 6 + hi * 65536 + lo);
}

function discoverCopyRegions(rom) {
  const regions = [];
  let start = 0;
  const sig = [0xa5, 0x80, 0xc0, 0xf6];
  for (;;) {
    const off = findBytes(rom, [0xe3, 0x60], start);
    if (off < 0) break;
    start = off + 2;
    if (off % 2 || off + 40 > rom.length) continue;
    const length = pcrel48(rom, off, 7);
    let source = pcrel48(rom, off + 16, 5);
    const destination = pcrel48(rom, off + 30, 4);
    if (length === null || source === null || destination === null || !sig.every((b, i) => rom[off + 26 + i] === b)) continue;
    source &= 0x0fffffff;
    const len = length & 0x0fffffff;
    if (len && source + len <= rom.length && destination >= 0x90000000 && destination < 0xe0000000) {
      regions.push({ source, destination, length: len, instruction: off });
    }
  }
  return regions;
}

export function headerGeometry(rom, drdiLen) {
  const size = 0x200;
  const off = rom.length - size;
  const magic = [...("CHECK_HEADER")].map((c) => c.charCodeAt(0));
  if (off < 0 || !magic.every((b, i) => rom[off + i] === b) || u32(rom, off + 12) !== 6 || u32(rom, rom.length - 4) !== size) {
    throw new UniversalError("NR15 requires a validated CHECK_HEADER v6 trailer");
  }
  const source = u32(rom, off + 0x16c);
  const length = u32(rom, off + 0x170);
  if (!(source > 0 && source <= off) || length !== drdiLen) throw new UniversalError("CHECK_HEADER DRDI source/length does not match the input");
  return [off, source];
}

// Returns Map(band -> code) in insertion order, or null.
function bandBwPairs(data, off, bwCount) {
  const result = new Map();
  let previous = 0;
  while (off + 2 <= data.length) {
    const band = data[off], code = data[off + 1];
    off += 2;
    if (band === 0) return code === bwCount && result.size >= 10 ? result : null;
    if (!(previous < band && band <= 255) || code >= bwCount) return null;
    result.set(band, code);
    previous = band;
  }
  return null;
}

// The MOLY.NR15. firmware marker: either this string in md1rom or a validated
// CHECK_HEADER trailer + indexed bandwidth enum activates the NR15 family.
export const MOLY_NR15 = new Uint8Array([..."MOLY.NR15."].map((c) => c.charCodeAt(0)));

export function nr15Probe(rom, drdi) {
  try {
    headerGeometry(rom, drdi.length);
  } catch {
    return false;
  }
  return findBytes(rom, nr15Pattern()) >= 0;
}

// Image whose pointers may also resolve into initialized ROM objects (through
// the copy-region map or the 0x90000000 window).
class RegionImage extends Image {
  constructor(bankVa, profile, sourceOffset, length, relocation, drdi, label, decoder) {
    super(bankVa, profile, sourceOffset, length, relocation, drdi, label);
    this.decoder = decoder;
  }

  resolve(va, size = 1) {
    const off = super.resolve(va, size);
    if (off !== null) return off;
    const r = this.decoder.resolve_rom(va, size);
    return r === null ? null : this.decoder.rom_start + r;
  }
}

class Nr15Decoder {
  constructor(loader) {
    this.loader = loader;
    this.rom = loader.rom;
    this.drdi = loader.drdi;
    this.rep = loader.rep;
    this.regions = discoverCopyRegions(this.rom);
    if (!this.regions.length) throw new UniversalError("NR15: no validated ROM-to-RAM copy regions found");
    // Deliberate 2x footprint (rom+drdi concatenated) — see the file header.
    this.data = new Uint8Array(this.drdi.length + this.rom.length);
    this.data.set(this.drdi, 0);
    this.data.set(this.rom, this.drdi.length);
    this.rom_start = this.drdi.length;
    this.words = wordsOf(this.rom);
    for (const bank of loader.banks) {
      bank.images = bank.images.map((im) => new RegionImage(
        im.bank_va, im.profile, im.source_offset, im.length, im.relocation,
        this.data, im.label, this,
      ));
    }
    this.arrays = new Map();
    this._descriptors = new Map();
    this._image = null;
    const choices = [];
    for (const bank of loader.banks) {
      if (!bank.images.length) continue;
      const options = new Map();
      for (const im of bank.images) {
        const found = this.complete_arrays(im, (i, va) => this.candidate(i, va));
        if (!found.length) break;
        options.set(im.profile, new Map(found));
      }
      if (options.size === bank.images.length) {
        for (const [root, arrays] of this.profile_tables(bank.images, options)) choices.push([bank, root, arrays]);
      }
    }
    if (choices.length !== 1) throw new UniversalError("NR15: expected one complete, firmware-corroborated profile root table");
    const [cap, profileTable, arrays] = choices[0];
    this.cap = cap;
    this.profile_table = profileTable;
    this.profile_count = cap.images.length;
    cap.images.forEach((im, i) => this.arrays.set(im.profile, arrays[i]));
    const bwCount = loader.tables.bw.length;
    for (const im of cap.images) {
      const ptr = u32(this.rom, this.profile_table - 3 * this.profile_count * 4 + 4 * im.profile);
      const off = this.resolve_rom(ptr, 2);
      const limits = off === null ? null : bandBwPairs(this.rom, off, bwCount);
      if (limits === null) throw new UniversalError("NR15: invalid profile-specific per-band bandwidth root");
    }
    [this.rf_limits_off, this.rf_limits] = this.discover_rf_limits();
    [this.bb_default_off, this.bb_default] = this.discover_default_bb();
    const pairs = findAll(this.rom, new Uint8Array(tableSignature()));
    this.pair_table_off = pairs.length === 1 ? pairs[0] : null;
    this.bw_overrides = new Map(); // runtime policy; always empty in the static projection
  }

  array_aliases(off) {
    const aliases = new Set([0x90000000 + off]);
    for (const r of this.regions) {
      if (r.source <= off && off < r.source + r.length) {
        const runtime = r.destination + off - r.source;
        const masked = (runtime & 0x1fffffff) + 0x80000000; // (runtime & 0x1FFFFFFF) | 0x80000000
        aliases.add(runtime);
        aliases.add(masked);
        aliases.add(masked - 0x70000000);
      }
    }
    return aliases;
  }

  pcrel_refs(off) {
    if (!this._pcrel_index) {
      // Full-ROM PC-relative reference index — deliberate cost, see file header.
      this._pcrel_index = new Map();
      const rom = this.rom;
      const n = Math.floor(rom.length / 2);
      for (let i = 0; i < n - 2; i++) {
        const h = u16(rom, i * 2);
        if ((h & 0xfc1f) !== 0x6003) continue;
        const value = wrap32(i * 2 + 6 + u16(rom, i * 2 + 2) + i16(rom, i * 2 + 4) * 65536);
        if (!this._pcrel_index.has(value)) this._pcrel_index.set(value, []);
        this._pcrel_index.get(value).push(i * 2);
      }
    }
    const aliases = this.array_aliases(off);
    aliases.add(off);
    const refs = new Set();
    for (const v of aliases) for (const r of this._pcrel_index.get(v) || []) refs.add(r);
    return [...refs].sort((a, b) => a - b);
  }

  profile_tables(images, options) {
    if (!images.every((im, i) => im.profile === i)) return [];
    const firstRefs = new Set();
    for (const off of options.get(images[0].profile).keys()) {
      for (const value of this.array_aliases(off)) {
        for (const ref of findAll(this.rom, packU32(value))) if (ref % 4 === 0) firstRefs.add(ref);
      }
    }
    const found = [];
    const span = 4 * images.length;
    const bwCount = this.loader.tables.bw.length;
    for (const root of [...firstRefs].sort((a, b) => a - b)) {
      if (root < 3 * span || root + 2 * span > this.rom.length) continue;
      const arrays = [];
      for (const im of images) {
        const off = this.resolve_rom(u32(this.rom, root + 4 * im.profile), 4);
        if (off === null || !options.get(im.profile).has(off)) break;
        const bb = this.resolve_rom(u32(this.rom, root - 3 * span + 4 * im.profile), 2);
        if (bb === null || bandBwPairs(this.rom, bb, bwCount) === null) break;
        arrays.push([off, options.get(im.profile).get(off)]);
      }
      if (arrays.length !== images.length) continue;
      if (![root, root + span, root - 3 * span].every((o) => this.pcrel_refs(o).length)) continue;
      found.push([root, arrays]);
    }
    return found;
  }

  discover_rf_limits() {
    const t = this.loader.tables;
    const start = t.bw_off + 4 * (t.bw.length + 1);
    const found = [];
    for (let off = start + 4; off < Math.min(start + 24, this.rom.length - 1); off += 2) {
      const limits = bandBwPairs(this.rom, off, t.bw.length);
      if (limits !== null && this.pcrel_refs(off).length) found.push([off, limits]);
    }
    if (found.length !== 1) throw new UniversalError("NR15: RF per-band bandwidth list lacks a unique consuming pointer");
    return found[0];
  }

  discover_default_bb() {
    const span = 4 * this.profile_count;
    const bwCount = this.loader.tables.bw.length;
    const found = new Set();
    for (const ref of this.pcrel_refs(this.profile_table - 3 * span)) {
      for (let off = ref + 6; off < Math.min(ref + 64, this.rom.length - 5); off += 2) {
        for (let reg = 0; reg < 32; reg++) {
          const target = pcrel48(this.rom, off, reg);
          if (target !== null && target < this.rom.length && bandBwPairs(this.rom, target, bwCount) !== null) found.add(target);
        }
      }
    }
    if (found.size !== 1) throw new UniversalError("NR15: default per-band BB bandwidth table is not uniquely referenced");
    const off = found.values().next().value;
    return [off, bandBwPairs(this.rom, off, bwCount)];
  }

  resolve_rom(va, size = 1) {
    if (!(va > 0 && va <= 0xffffffff) || size < 0) return null;
    if (va >= 0x90000000 && va - 0x90000000 + size <= this.rom.length) return va - 0x90000000;
    const raw = va >= 0x20000000 && va < 0x30000000 ? va + 0x70000000 : va;
    const physical = raw % 0x20000000; // raw & 0x1FFFFFFF
    for (const r of this.regions) {
      const delta = physical - (r.destination % 0x20000000);
      if (delta >= 0 && delta + size <= r.length) return r.source + delta;
    }
    return null;
  }

  complete_arrays(im, parse) {
    const w = this.words;
    const lo = im.bank_va;
    const hi = im.end_va;
    const runs = [];
    let start = -1;
    let previous = -1;
    for (let i = 0; i < w.length; i++) {
      if (w[i] >= lo && w[i] < hi) {
        if (start < 0) start = i;
        else if (i !== previous + 1) {
          runs.push([start * 4, previous - start + 1]);
          start = i;
        }
        previous = i;
      }
    }
    if (start >= 0) runs.push([start * 4, previous - start + 1]);
    const found = [];
    for (const [off, count] of runs) {
      if (count < 4 || off + count * 4 + 4 > this.rom.length || u32(this.rom, off + count * 4)) continue;
      const rows = [];
      for (let k = 0; k < count; k++) {
        const row = parse(im, u32(this.rom, off + 4 * k));
        if (row === null) break;
        rows.push(row);
      }
      if (rows.length === count) found.push([off, rows]);
    }
    return found;
  }

  local_arrays(im, parse) {
    const roots = new Set();
    for (const v of this.words) if (v >= im.bank_va && v < im.end_va) roots.add(v);
    const result = [];
    for (const root of [...roots].sort((a, b) => a - b)) {
      const start = im.resolve(root, 4);
      if (start === null || start < im.source_offset || start + 4 > im.end_source) continue;
      if (start >= im.source_offset + 4 && im.containsVa(u32(im.drdi, start - 4))) continue;
      const rows = [];
      let off = start;
      while (off + 4 <= im.end_source) {
        const ptr = u32(im.drdi, off);
        if (ptr === 0) {
          if (rows.length) result.push([start, rows]);
          break;
        }
        const row = parse(im, ptr);
        if (row === null) break;
        rows.push(row);
        off += 4;
      }
    }
    return result;
  }

  descriptor(im, ptr, nr) {
    if (this._image !== im) {
      this._descriptors.clear();
      this._image = im;
    }
    const key = `${ptr}|${nr ? 1 : 0}`;
    if (!this._descriptors.has(key)) this._descriptors.set(key, this._descriptor(im, ptr, nr));
    return this._descriptors.get(key);
  }

  _descriptor(im, ptr, nr) {
    const t = this.loader.tables;
    const d = im.drdi;
    const off = im.resolve(ptr, 16);
    if (off === null) return null;
    const count = u32(d, off), rp = u32(d, off + 4), vc = u32(d, off + 8), vp = u32(d, off + 12);
    if (!(count >= 1 && count <= 6) || !(vc >= 1 && vc <= 32)) return null;
    const ro = im.resolve(rp, count * 3);
    const vo = im.resolve(vp, vc * 2);
    if (ro === null || vo === null) return null;
    const weights = nr ? t.nr_weights : t.lte_weights;
    const records = [];
    let units = 0;
    for (let k = 0; k < count; k++) {
      let band = d[ro + 3 * k];
      const ul = d[ro + 3 * k + 1], dl = d[ro + 3 * k + 2];
      if (!nr) {
        if (band >= t.lte_band_map.length) return null;
        band = t.lte_band_map[band];
      }
      if (!(band >= 1 && band <= (nr ? 255 : MAX_LTE_BAND)) || dl >= weights.length || !weights[dl]) return null;
      const absent = nr ? t.nr_ul_absent.has(ul) : ul === LTE_UL_ABSENT;
      if (!absent && (ul >= weights.length || !weights[ul])) return null;
      if (!absent && weights[ul] > weights[dl]) return null;
      records.push([band, ul, dl]);
      units += weights[dl];
    }
    if (vc !== units) return null;
    const mimo = [];
    for (let k = 0; k < vc; k++) {
      const ulm = d[vo + 2 * k], dlm = d[vo + 2 * k + 1];
      if (!(dlm in DL_MIMO) || !(ulm <= 3)) return null;
      mimo.push([ulm, dlm]);
    }
    return new RawDescriptor(count, rp, vc, vp, records, units, mimo, nr);
  }

  candidate(im, va) {
    const off = im.resolve(va, 16);
    if (off === null || !(im.source_offset <= off && off < im.end_source)) return null;
    const d = im.drdi;
    const m0 = u32(d, off), m1 = u32(d, off + 4), lp = u32(d, off + 8), np = u32(d, off + 12);
    const ld = lp ? this.descriptor(im, lp, false) : null;
    const nd = np ? this.descriptor(im, np, true) : null;
    if (nd === null || (lp && ld === null)) return null;
    return new RawCandidate(va, m0, m1, ld, nd);
  }

  lte_row(im, va) {
    const off = im.resolve(va, 20);
    if (off === null || !(im.source_offset <= off && off <= im.end_source - 20)) return null;
    const d = im.drdi;
    const count = u32(d, off + 4), rp = u32(d, off + 8), units = u32(d, off + 12), mp = u32(d, off + 16);
    if (!(count >= 1 && count <= 6) || !(units >= 1 && units <= 6)) return null;
    const ro = im.resolve(rp, count * 3);
    const mo = im.resolve(mp, count);
    if (ro === null || mo === null) return null;
    const t = this.loader.tables;
    const records = [];
    let total = 0;
    for (let k = 0; k < count; k++) {
      let band = d[ro + 3 * k];
      const ul = d[ro + 3 * k + 1], dl = d[ro + 3 * k + 2];
      if (band >= t.lte_band_map.length || dl >= 6 || (ul !== 6 && ul >= 6)) return null;
      band = t.lte_band_map[band];
      if (!(band >= 1 && band <= MAX_LTE_BAND)) return null;
      records.push([band, ul, dl]);
      total += t.lte_weights[dl];
    }
    const mimo = d.subarray(mo, mo + count);
    if (total !== units || mimo.some((v) => !(v === 2 || v === 3 || v === 4))) return null;
    const mmap = { 2: 2, 3: 4, 4: 8 };
    const comps = records.map(([band, ul, dl], i) => new LteComponent(band, dl, ul, Array(t.lte_weights[dl]).fill(mmap[mimo[i]])));
    return new MtkCombo(comps, []);
  }

  lte_single(im, va) {
    const off = im.resolve(va, 2);
    if (off === null) return null;
    let band = im.drdi[off];
    const mimo = im.drdi[off + 1];
    const t = this.loader.tables;
    if (band >= t.lte_band_map.length || !(mimo === 2 || mimo === 3)) return null;
    band = t.lte_band_map[band];
    if (!(band >= 1 && band <= MAX_LTE_BAND)) return null;
    const ul = band === 29 || band === 32 ? LTE_UL_ABSENT : 0;
    return new MtkCombo([new LteComponent(band, 0, ul, [mimo === 2 ? 2 : 4])], []);
  }

  lte_tables() {
    if (this._lte_result) return this._lte_result;
    const results = new Map();
    let primary = null;
    let best = 0;
    const roots = new Map();
    for (const bank of this.loader.banks) {
      for (const im of bank.images) {
        const arrays = this.local_arrays(im, (i, va) => this.lte_row(i, va));
        if (!arrays.length) continue;
        let rows = arrays.flatMap(([, array]) => array);
        let singleArrays = this.local_arrays(im, (i, va) => this.lte_single(i, va));
        singleArrays = singleArrays.filter(([, array]) => array.length >= 1 && array.length <= 25
          && array.every((a, k) => k === 0 || array[k - 1].lte[0].band < a.lte[0].band));
        if (singleArrays.length !== 1) throw new UniversalError("NR15: expected one complete LTE single-band array per profile");
        if (arrays.length !== 2) throw new UniversalError("NR15: both LTE CA root arrays must close completely");
        const [so, singleRows] = singleArrays[0];
        if (!roots.has(bank.table_index)) roots.set(bank.table_index, new Map());
        roots.get(bank.table_index).set(im.profile, [so + im.relocation, ...arrays.map(([off]) => off + im.relocation)]);
        rows = [...rows, ...singleRows];
        if (!results.has(im.profile)) results.set(im.profile, []);
        results.get(im.profile).push(...rows);
        if (rows.length > best) {
          primary = bank;
          best = rows.length;
        }
      }
    }
    if (!results.size) throw new UniversalError("NR15: no complete LTE row pointer arrays found");
    const primaryRoots = roots.get(primary.table_index);
    const profiles = new Set(primary.images.map((im) => im.profile));
    if (roots.size !== 1 || primaryRoots.size !== profiles.size || ![...primaryRoots.keys()].every((p) => profiles.has(p))) {
      throw new UniversalError("NR15: ambiguous or incomplete LTE profile bank");
    }
    const ordered = primary.images.map((im) => primaryRoots.get(im.profile));
    const pattern = [];
    for (let column = 0; column < 3; column++) for (const row of ordered) pattern.push(...packU32(row[column]));
    const sites = findAll(this.rom, new Uint8Array(pattern)).filter((o) => o % 4 === 0);
    if (sites.length !== 1) throw new UniversalError("NR15: LTE arrays lack an unambiguous ROM profile root block");
    const out = new Map();
    for (const [p, rows] of results) out.set(p, dedupExact(rows));
    this._lte_result = [primary, out];
    return this._lte_result;
  }

  decode(im, candidates) {
    const t = this.loader.tables;
    const out = [];
    for (const cand of candidates) {
      const lte = [];
      if (cand.lte) {
        let cur = 0;
        for (const [band, ul, dl] of cand.lte.records) {
          const n = t.lte_weights[dl];
          lte.push(new LteComponent(band, dl, ul, cand.lte.fsc.slice(cur, cur + n).map((x) => DL_MIMO[x[1]])));
          cur += n;
        }
      }
      out.push(...this.nr_variants(lte, cand.nr));
    }
    return dedupExact(out);
  }

  nr_limits(records) {
    const limits = [];
    let ceiling = this.loader.tables.bw.length;
    for (const [band] of records.slice(0, 2)) {
      if (!this.rf_limits.has(band)) throw new UniversalError(`NR15: n${band} has no validated RF bandwidth limit`);
      if (this.bb_default.has(band)) ceiling = Math.min(this.rf_limits.get(band), this.bb_default.get(band));
      if (ceiling === this.loader.tables.bw.length) ceiling = this.rf_limits.get(band);
      limits.push(ceiling);
    }
    if (limits.some((c) => c > 10)) throw new UniversalError("NR15 carrier bandwidth above 100 MHz is not validated");
    return limits;
  }

  nr_variants(lte, nd) {
    const t = this.loader.tables;
    const records = nd.records;
    if (records.length > 2 || nd.units > 2) throw new UniversalError("NR15: more than two NR carriers is not validated");
    const limits = this.nr_limits(records);
    let pairs;
    if (nd.units === 1) pairs = [[...limits]];
    else {
      if (this.pair_table_off === null) throw new UniversalError("NR15: firmware bandwidth-pair tables were not found uniquely");
      const mode = records.length === 2 ? BW_MODE_INTER : BW_MODE_INTRA;
      pairs = bandwidthPairs(limits, mode, t.bw);
    }
    const shapes = [];
    for (const pair of pairs) {
      const ccs = [];
      let cur = 0;
      records.forEach(([, ul, dl], index) => {
        const uplinks = t.nr_ul_absent.has(ul) ? 0 : t.nr_weights[ul];
        for (let k = 0; k < t.nr_weights[dl]; k++) {
          const [um, dm] = nd.fsc[cur + k];
          if ((k >= uplinks) !== (um === 3)) throw new UniversalError("NR15 UL class/MIMO closure failed");
          const code = records.length === 2 ? pair[index] : pair[k];
          ccs.push([index, code, dm, k >= uplinks ? null : um]);
        }
        cur += t.nr_weights[dl];
      });
      shapes.push(ccs);
    }
    // itertools.product((0, 1), repeat=units): last position varies fastest.
    const products = [];
    for (let m = 0; m < 2 ** nd.units; m++) {
      const scs = [];
      for (let bit = nd.units - 1; bit >= 0; bit--) scs.push((m >> bit) & 1);
      products.push(scs);
    }
    const ordered = shapes.map((ccs) => [ccs, Array(nd.units).fill(0)]);
    for (const ccs of shapes) for (const scs of products) if (scs.some(Boolean)) ordered.push([ccs, scs]);
    const out = [];
    for (const [ccs, assignment] of ordered) {
      let total = 0;
      const perRecord = records.map(() => []);
      ccs.forEach(([index, code0, dm, um], i) => {
        const scs = assignment[i];
        let code = code0;
        const key = `${records[index][0]}|${scs}`;
        const override = this.bw_overrides.has(key) ? this.bw_overrides.get(key) : code;
        code = Math.min(code, override);
        if (scs === 0) code = Math.min(code, SCS15_MAX_CODE);
        const bw = t.bw[code];
        total += bw * (scs === 0 ? 2 : 1);
        perRecord[index].push(new NrCC(SCS[scs], DL_MIMO[dm], bw, um === null ? null : UL_MIMO[um], um === null ? null : bw));
      });
      if (total > DL_SCS_BUDGET) continue;
      const nr = records.map(([band, ul, dl], i) => new NrComponent(band, dl, t.nr_ul_absent.has(ul) ? NR_UL_ABSENT_CANON : ul, perRecord[i]));
      out.push(new MtkCombo(lte, nr));
    }
    return out;
  }

  extract_capability(profile) {
    const states = [];
    const perProfile = new Map();
    for (const im of this.cap.images) {
      if (profile !== "all" && im.profile !== Number(profile)) continue;
      const [off, rows] = this.arrays.get(im.profile);
      states.push(new ProfileState(im, rows, { file_offset: off, count: rows.length, source: "nr15_rom_root" }, [], []));
      perProfile.set(im.profile, this.decode(im, rows));
    }
    if (!states.length) throw new UniversalError(`requested profile ${profile} is not live in capability bank`);
    const union = dedupExact([...perProfile.values()].flat());
    const [lteBank, lteProfiles] = this.lte_tables();
    if (profile !== "all") lteProfiles = new Map([...lteProfiles].filter(([p]) => p === Number(profile)));
    const lteUnion = dedupExact([...lteProfiles.values()].flat());
    return { cap: this.cap, states, perProfile, union, lteBank, lteProfiles, lteUnion, unresolved: [] };
  }
}

export class Nr15Loader extends BaseLoader {
  name = "nr15";

  constructor(rom, drdi, rep) {
    super(rom, drdi, rep);
    if (this.tables.bw_family !== "nr15_13") throw new UniversalError("NR15 loader requires the indexed 13-entry bandwidth enum");
    const [, source] = headerGeometry(rom, drdi.length);
    const words = wordsOf(rom);
    const hits = [];
    for (let i = 0; i + 2 < words.length; i++) {
      const sf = words[i], va = words[i + 1], ln = words[i + 2];
      if (sf >= source && sf + ln <= source + drdi.length && ln >= 0x10 && ln <= 0x800000 && va >= VA_LO && va < VA_HI) {
        hits.push([i * 4, sf - source, va, ln]);
      }
    }
    gridDiscover(this, hits);
    this.decoder = new Nr15Decoder(this);
  }

  capabilityBank() {
    return this.decoder.cap;
  }

  lteTables() {
    return this.decoder.lte_tables();
  }
}
