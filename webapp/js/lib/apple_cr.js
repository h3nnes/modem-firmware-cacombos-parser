// Apple C-series (C4000 / C4020) CR capability bank parser, audit, viewer
// tables and DIAG (0xB0CD v41 / 0xB826 v22) export.
// Numeric semantics: all multi-byte loads are little-endian DataView reads;
// the u64 candidate / companion header fields stay BigInt until their bit
// fields are extracted (every extracted field fits a double exactly).
//
// The export helpers' dynamic ANTENNA_/BW_ extension tables are created FRESH
// per exportAppleDiag call: the webapp exports one bank per operation, and
// the golden DIAG texts were generated under exactly that per-bank fresh
// state.

import { hex } from "./bytes.js";

// --- layout tables and detect_layout -----------------------------------------------

function makeTable(countOffset, base, stride, capacity) {
  return {
    count_offset: countOffset,
    base,
    stride,
    capacity,
    count(data, dv = new DataView(data.buffer, data.byteOffset, data.byteLength)) {
      return dv.getUint32(this.count_offset, true);
    },
  };
}

export const C4000 = {
  name: "C4000",
  size: 0x5776e0,
  physical: makeTable(0x4e2334, 0x4e2338, 40, 1024),
  matrix_nr: makeTable(0x4ecc48, 0x4ecc4c, 11, 32000),
  matrix_endc: makeTable(0x55b1f0, 0x55b1f4, 11, 6400),
  ul_matrix_nr: makeTable(0x542b4c, 0x542b50, 10, 10000),
  ul_matrix_endc: makeTable(0x56c4f4, 0x56c4f8, 10, 3200),
  dl_groups: makeTable(0x5741f8, 0x5741fc, 20, 255),
  ul_groups: makeTable(0x5755e8, 0x5755ec, 20, 255),
  dl_descriptors: makeTable(0x576aa0, 0x576aa4, 4, 64),
  ul_descriptors: makeTable(0x576ba4, 0x576ba8, 2, 64),
  bands: makeTable(0x576c50, 0x576c58, 40, 64),
  lte_dl_feature_sets: makeTable(0x5769d8, 0x5769dc, 6, 16),
  lte_ul_feature_sets: makeTable(0x576a3c, 0x576a40, 6, 16),
  lte_dl_descriptors: makeTable(0x576c28, 0x576c2c, 4, 4),
  lte_ul_descriptors: makeTable(0x576c3c, 0x576c40, 4, 4),
  physical_index_bits: 10,
};

export const C4020 = {
  name: "C4020",
  size: 0x590d00,
  physical: makeTable(0x4e2df4, 0x4e2df8, 40, 2048),
  matrix_nr: makeTable(0x4f7808, 0x4f780c, 11, 32000),
  matrix_endc: makeTable(0x574810, 0x574814, 11, 6400),
  ul_matrix_nr: makeTable(0x54d70c, 0x54d710, 10, 16000),
  ul_matrix_endc: makeTable(0x585b14, 0x585b18, 10, 3200),
  dl_groups: makeTable(0x58d818, 0x58d81c, 20, 255),
  ul_groups: makeTable(0x58ec08, 0x58ec0c, 20, 255),
  dl_descriptors: makeTable(0x5900c0, 0x5900c4, 4, 64),
  ul_descriptors: makeTable(0x5901c4, 0x5901c8, 2, 64),
  bands: makeTable(0x590270, 0x590278, 40, 64),
  lte_dl_feature_sets: makeTable(0x58fff8, 0x58fffc, 6, 16),
  lte_ul_feature_sets: makeTable(0x59005c, 0x590060, 6, 16),
  lte_dl_descriptors: makeTable(0x590248, 0x59024c, 4, 4),
  lte_ul_descriptors: makeTable(0x59025c, 0x590260, 4, 4),
  physical_index_bits: 11,
};

export const LAYOUTS = [C4000, C4020];

export const HEAD_TABLES = {
  lte_candidates: makeTable(0x8, 0xc, 40, 4000),
  lte_references: makeTable(0x2710c, 0x27110, 2, 8000),
  nr_candidates: makeTable(0x2ee14, 0x2ee18, 40, 16000),
  companions: makeTable(0xcb218, 0xcb21c, 28, 128000),
};

function layoutMatrix(layout, category) {
  if (category !== 1 && category !== 2) {
    throw new Error(`Unsupported CR candidate category: ${category}`);
  }
  return category === 1 ? layout.matrix_nr : layout.matrix_endc;
}

function layoutUlMatrix(layout, category) {
  layoutMatrix(layout, category);
  return category === 1 ? layout.ul_matrix_nr : layout.ul_matrix_endc;
}

function layoutMetadata(layout) {
  return {
    name: layout.name,
    image_size: layout.size,
    offset_evidence: "FIRMWARE_DERIVED",
    physical_semantics:
      layout.name === "C4000"
        ? "C4000_ORACLE_VALIDATED"
        : "STRONG_INFERENCE_C4000_GRAMMAR; C4020_DEVICE_ORACLE_PENDING",
  };
}

export function detectLayout(data) {
  // Select a known image layout by size and validate table boundary bounds.
  const layout = LAYOUTS.find((l) => l.size === data.length);
  if (!layout) {
    const expected = LAYOUTS.map((l) => `${l.name} (0x${l.size.toString(16).toUpperCase()} bytes)`).join(", ");
    throw new Error(
      `Unsupported CR image size 0x${data.length.toString(16).toUpperCase()} (${data.length.toLocaleString("en-US")} bytes); expected ${expected}`,
    );
  }
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const tables = { ...HEAD_TABLES };
  for (const key of [
    "physical", "matrix_nr", "matrix_endc", "ul_matrix_nr", "ul_matrix_endc",
    "dl_groups", "ul_groups", "dl_descriptors", "ul_descriptors", "bands",
    "lte_dl_feature_sets", "lte_ul_feature_sets", "lte_dl_descriptors", "lte_ul_descriptors",
  ]) {
    tables[key] = layout[key];
  }
  for (const [name, table] of Object.entries(tables)) {
    const count = dv.getUint32(table.count_offset, true);
    if (count > table.capacity || table.base + count * table.stride > data.length) {
      throw new Error(
        `${layout.name} ${name}: count ${count} at 0x${table.count_offset.toString(16)} exceeds table capacity ${table.capacity}`,
      );
    }
  }
  return layout;
}

// --- parser constants --------------------------------------------------------------

export const CLASS_MAP = { 1: ["A", 1], 2: ["B", 2], 3: ["C", 2], 4: ["D", 3], 5: ["E", 4], 6: ["F", 5] };
const UL_CLASS_BASE = { 1: "A", 2: "B", 3: "C", 4: "D", 5: "E", 6: "F" };
// TS 38.101-2 table 5.3A.4-1; FR2 classes have different CC counts.
const FR2_CLASS_MAP = {
  1: ["A", 1], 2: ["B", 2], 3: ["C", 3], 4: ["D", 2],
  5: ["E", 3], 6: ["F", 4],
  ...Object.fromEntries(Array.from({ length: 7 }, (_, i) => [7 + i, [String.fromCharCode(64 + 7 + i), 7 + i - 5]])),
  15: ["O", 2], 16: ["P", 3], 17: ["Q", 4],
  ...Object.fromEntries(Array.from({ length: 11 }, (_, i) => [18 + i, [`R${2 + i}`, 2 + i]])),
};
export const UL_CLASS = { ...UL_CLASS_BASE };
for (const [code, value] of Object.entries(FR2_CLASS_MAP)) UL_CLASS[code] = value[0];

// Slot-1 mask encoding: MSB-first bitmask over 15 known FR1 channel bandwidths.
export const NR_CHANNEL_BW_FR1 = [5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 60, 70, 80, 90, 100];
export const SLOT1_RESERVED_MASK = (1 << (32 - NR_CHANNEL_BW_FR1.length)) - 1;
// Slot-2 (TDD) bandwidth steps: 2 bits per entry, MSB-first, 10 MHz steps.
export const SLOT2_BW_STEPS = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];

// Standalone LTE combinations table offsets.
export const LTE_COUNT_OFF = 0x08;
export const LTE_BASE_OFF = 0x0c;
export const LTE_STRIDE = 0x28;
export const LTE_COMP_OFF = 0x10;
export const LTE_MAX_COMPONENTS = 5;
export const LTE_CLASS_MAP = { 1: ["A", 1], 2: ["B", 2], 4: ["C", 2], 8: ["D", 3], 16: ["E", 4] };
export const LTE_REF_COUNT_OFF = 0x2710c;
export const LTE_REF_BASE_OFF = 0x27110;

// NR / EN-DC candidate combinations table offsets.
export const NR_COUNT_OFF = 0x02ee14;
export const NR_BASE_OFF = 0x02ee18;
export const NR_STRIDE = 0x28;

// Variant-local 0x1C companion array offsets.
export const COMPANION_COUNT_OFF = 0x0cb218;
export const COMPANION_BASE = 0x0cb21c;
export const COMPANION_STRIDE = 0x1c;

export const FR1_BANDWIDTH_MHZ = [5, 10, 15, 20, 25, 30, 40, 50, 60, 80, 100];
export const FR2_BANDWIDTH_MHZ = [50, 100, 200, 400];

// FUN_00C51560 / FUN_00C517E0: codes 12..14 index the firmware 15-entry list at
// 0x0186A9DC = [6, 8, 11] -> 35, 45, 70 MHz.
export const SPECIAL_FR1_BANDWIDTH_MHZ = { 12: 35, 13: 45, 14: 70 };

export const SCS_KHZ = [15, 30, 60, 120, 240, 480, 960];
export const DL_MIMO_LAYERS = [2, 4, 8];
export const UL_MIMO_LAYERS = [1, 2, 4];

// LTE per-CC descriptor word -> MIMO layers for LTE legs of EN-DC combinations.
// The word's bit grammar is not decoded; these are the only words present in any
// C4000 / C4020 bank, and the mapping matches every LTE leg of the on-device
// EN-DC UE capability report (CR39). Unknown words resolve to null and fail audit.
export const LTE_DL_MIMO_LAYERS_BY_WORD = { 0x0a0d: 4, 0x0000: 2 };
export const LTE_UL_MIMO_LAYERS_BY_WORD = { 0x0004: 1 };

export function decodeBwMaskSlot1(mask) {
  const valid = (mask & SLOT1_RESERVED_MASK) === 0;
  const bws = [];
  NR_CHANNEL_BW_FR1.forEach((bw, k) => {
    if ((mask >>> (31 - k)) & 1) bws.push(bw);
  });
  return [bws, valid];
}

export function decodeBwMaskSlot2Inferred(mask) {
  const out = [];
  SLOT2_BW_STEPS.forEach((mhz, k) => {
    if ((mask >>> (30 - 2 * k)) & 3) out.push(mhz);
  });
  return out;
}

export function decodeBandwidth(code, fr2) {
  const values = fr2 ? FR2_BANDWIDTH_MHZ : FR1_BANDWIDTH_MHZ;
  if (code >= 1 && code <= values.length) return values[code - 1];
  if (!fr2) return SPECIAL_FR1_BANDWIDTH_MHZ[code] ?? null;
  return null;
}

export function componentClass(code, rat, band) {
  const table = rat === "NR" && band > 256 ? FR2_CLASS_MAP : CLASS_MAP;
  return table[code] ?? ["?", 0];
}

function slot2Bw(mask) {
  const out = [];
  for (let i = 0; i < 10; i++) {
    if ((mask >>> (30 - 2 * i)) & 3) out.push(10 + i * 10);
  }
  return out;
}

function decodePerCcDescriptor(word, uplink) {
  const fr2 = (word & 1) === 1;
  const scsCode = (word >>> 1) & 7;
  const bandwidthCode = (word >>> 4) & 0xf;
  const mimoCode = (word >>> 9) & 3;
  const mimoValues = uplink ? UL_MIMO_LAYERS : DL_MIMO_LAYERS;
  return {
    raw: word,
    frequency_range: fr2 ? "FR2" : "FR1",
    scs_code: scsCode,
    scs_khz: scsCode >= 1 && scsCode <= SCS_KHZ.length ? SCS_KHZ[scsCode - 1] : null,
    bandwidth_code: bandwidthCode,
    bandwidth_mhz: decodeBandwidth(bandwidthCode, fr2),
    mimo_code: mimoCode,
    mimo_layers: mimoCode >= 1 && mimoCode <= mimoValues.length ? mimoValues[mimoCode - 1] : null,
    modulation_code: (word >>> 11) & (uplink ? 3 : 7),
  };
}

// --- band capability table ---------------------------------------------------------

function bandCapabilityTable(data, dv, layout) {
  const table = layout.bands;
  const count = dv.getUint32(table.count_offset, true);
  const records = [];
  const byBand = new Map();
  const encodingViolations = [];
  for (let i = 0; i < count; i++) {
    const off = table.base + i * table.stride;
    const band = data[off];
    const flagB1 = data[off + 1];
    const flagB2 = data[off + 2];
    const s1Dl = dv.getUint32(off + 8, true);
    const s1Ul = dv.getUint32(off + 12, true);
    const s2Dl = dv.getUint32(off + 16, true);
    const s2Ul = dv.getUint32(off + 20, true);
    const [dlBws, dlOk] = decodeBwMaskSlot1(s1Dl);
    const [ulBws, ulOk] = decodeBwMaskSlot1(s1Ul);
    for (const [tag, m, ok] of [["slot1_dl", s1Dl, dlOk], ["slot1_ul", s1Ul, ulOk]]) {
      if (m && !ok) encodingViolations.push([band, tag, m]);
    }
    const kind = s1Dl || s1Ul || s2Dl || s2Ul ? "BANDWIDTH_DESCRIPTOR" : "TRAILER_UNRESOLVED";
    const rec = {
      index: i,
      offset: off,
      band,
      flag_b1: flagB1,
      dl_mimo_layers: flagB1 === 0x08 ? 2 : flagB1 === 0x10 ? 4 : null,
      flag_b2: flagB2,
      record_kind: kind,
      slot1_dl_mask: s1Dl,
      slot1_ul_mask: s1Ul,
      slot2_dl_mask: s2Dl,
      slot2_ul_mask: s2Ul,
      dl_bw_mhz: dlBws,
      ul_bw_mhz: ulBws,
      dl_bw_valid: dlOk,
      ul_bw_valid: ulOk,
      slot2_present: Boolean(s2Dl || s2Ul),
      raw_hex: hex(data.subarray(off, off + table.stride)),
    };
    records.push(rec);
    if (kind === "BANDWIDTH_DESCRIPTOR" && !byBand.has(band)) byBand.set(band, rec);
  }
  return { count, records, by_band: byBand, encoding_violations: encodingViolations };
}

// --- LTE candidate table ------------------------------------------------------------

function lteCandidateTable(data, dv) {
  const count = dv.getUint32(LTE_COUNT_OFF, true);
  const records = [];
  for (let i = 0; i < count; i++) {
    const off = LTE_BASE_OFF + i * LTE_STRIDE;
    const row = data.subarray(off, off + LTE_STRIDE);
    const rowType = dv.getUint32(off, true);
    const bcsBitmap = dv.getUint32(off + 8, true);
    const refOrSentinel = dv.getUint16(off + 12, true);
    const unk0c = dv.getUint16(off + 14, true);
    const unk0e = dv.getUint16(off + 16, true);
    const comps = [];
    for (let j = 0; j < LTE_MAX_COMPONENTS; j++) {
      const cOff = off + LTE_COMP_OFF + j * 4;
      const band = data[cOff];
      const byte1 = data[cOff + 1];
      const byte2 = data[cOff + 2];
      const byte3 = data[cOff + 3];
      if (band === 0) break;
      const clsBits = byte1 & 0x3f;
      const [clsLetter, ccWeight] = LTE_CLASS_MAP[clsBits] ?? ["?", 1];
      const ulCode = ((byte1 >> 6) & 0x03) | ((byte2 & 0x01) << 2);
      const ulClassLetter = ulCode ? (LTE_CLASS_MAP[ulCode]?.[0] ?? "?") : null;
      const isUl = ulCode !== 0;
      const dlMimoNibble = byte2 >> 4;
      let dlMimo;
      if (dlMimoNibble === 1) dlMimo = 2;
      else if (dlMimoNibble === ccWeight + 1) dlMimo = 4;
      else dlMimo = null;
      comps.push({
        component_index: j,
        band,
        class_letter: clsLetter,
        cc_weight: ccWeight,
        is_ul: isUl,
        ul_class_letter: ulClassLetter,
        dl_mimo_layers: dlMimo,
        byte1_raw: byte1,
        byte2_raw: byte2,
        byte3_raw: byte3,
        raw_hex: hex(data.subarray(cOff, cOff + 4)),
      });
    }
    const bcsSets = [];
    for (let b = 0; b < 16; b++) if ((bcsBitmap >>> b) & 1) bcsSets.push(b);
    const exprParts = [];
    for (const c of comps) {
      let part = `B${c.band}${c.class_letter}`;
      if (c.dl_mimo_layers) part += `${c.dl_mimo_layers}`;
      if (c.is_ul) part += `${c.ul_class_letter}`;
      exprParts.push(part);
    }
    records.push({
      source_index: i,
      offset: off,
      row_type: rowType,
      bcs_bitmap: bcsBitmap,
      bcs_sets: bcsSets,
      ref_or_sentinel: refOrSentinel,
      unk_0c: unk0c,
      unk_0e: unk0e,
      components: comps,
      component_count: comps.length,
      total_cc: comps.reduce((n, c) => n + c.cc_weight, 0),
      structural_expression: exprParts.join("+"),
      raw_hex: hex(row),
    });
  }
  const refCount = dv.getUint32(LTE_REF_COUNT_OFF, true);
  const refs = [];
  for (let i = 0; i < refCount; i++) refs.push(dv.getUint16(LTE_REF_BASE_OFF + i * 2, true));
  const refsOutOfRange = refs.reduce((n, r) => n + (r >= count ? 1 : 0), 0);
  return { count, records, ref_count: refCount, refs, refs_out_of_range: refsOutOfRange };
}

// --- physical rows + band properties -----------------------------------------------

function physicalRow(data, dv, index, layout) {
  const table = layout.physical;
  const count = dv.getUint32(table.count_offset, true);
  if (!(index >= 0 && index < count)) return { index, out_of_range: true };
  const off = table.base + index * table.stride;
  const components = [];
  for (let w = 0; w < 10; w++) {
    const value = dv.getUint32(off + w * 4, true);
    components.push({
      raw: value,
      low_index: value & 0x7f,
      run_count: (value >>> 7) & 0xf,
      field_11_14: (value >>> 11) & 0xf,
      field_18_23: (value >>> 18) & 0x3f,
      field_24_29: (value >>> 24) & 0x3f,
    });
  }
  return { index, raw_hex: hex(data.subarray(off, off + table.stride)), components };
}

function nrBandProperties(bandTable, band, includeSlot2) {
  const row = bandTable.by_band.get(band);
  if (!row) {
    return {
      dl_mimo_layers: null,
      supported_dl_bw_mhz: [],
      supported_ul_bw_mhz: [],
      bandwidth_confidence: "NO_BAND_DESCRIPTOR",
    };
  }
  let dl, ul, confidence;
  if (row.slot2_present) {
    if (includeSlot2) {
      dl = slot2Bw(row.slot2_dl_mask);
      ul = slot2Bw(row.slot2_ul_mask);
      confidence = "STRONG_INFERENCE_SLOT2";
    } else {
      dl = [];
      ul = [];
      confidence = "UNRESOLVED_SLOT2";
    }
  } else {
    dl = [...row.dl_bw_mhz];
    ul = [...row.ul_bw_mhz];
    confidence = "PROVEN_SLOT1";
  }
  return {
    dl_mimo_layers: row.dl_mimo_layers,
    supported_dl_bw_mhz: dl,
    supported_ul_bw_mhz: ul,
    bandwidth_confidence: confidence,
    band_descriptor_index: row.index,
    band_descriptor_raw: row.raw_hex,
  };
}

// --- feature groups + UL catalog ----------------------------------------------------

function featureGroup(data, dv, layout, index, uplink) {
  const table = uplink ? layout.ul_groups : layout.dl_groups;
  const base = table.base;
  const count = dv.getUint32(table.count_offset, true);
  if (!(index >= 0 && index < count)) return { index, out_of_range: true, per_cc: [] };
  const rawStart = base + index * 0x14;
  const refCount = dv.getUint16(rawStart + 8, true) >> 12;
  if (refCount > 9) return { index, out_of_range: true, per_cc: [], raw_hex: hex(data.subarray(rawStart, rawStart + 0x14)) };
  const refs = [];
  for (let i = 0; i < refCount; i++) refs.push(data[rawStart + 10 + i]);
  const descriptors = uplink ? layout.ul_descriptors : layout.dl_descriptors;
  const descBase = descriptors.base;
  const descStride = uplink ? 2 : 4;
  const descCount = dv.getUint32(descriptors.count_offset, true);
  const perCc = [];
  for (const ref of refs) {
    if (ref >= descCount) {
      perCc.push({ descriptor_ref: ref, out_of_range: true });
      continue;
    }
    const word = uplink ? dv.getUint16(descBase + ref * descStride, true) : dv.getUint32(descBase + ref * descStride, true);
    perCc.push({ descriptor_ref: ref, ...decodePerCcDescriptor(word, uplink) });
  }
  return { index, raw_hex: hex(data.subarray(rawStart, rawStart + 0x14)), descriptor_refs: refs, per_cc: perCc };
}

// Resolve an LTE feature set (EN-DC LTE leg) to per-CC descriptors. 6-byte
// row: [0] CC count (1..5), then that many descriptor refs into the 4-byte
// LTE descriptor-word table.
function lteFeatureSet(data, dv, layout, index, uplink) {
  const table = uplink ? layout.lte_ul_feature_sets : layout.lte_dl_feature_sets;
  const count = dv.getUint32(table.count_offset, true);
  if (!(index >= 0 && index < count)) {
    return { index, out_of_range: true, per_cc: [] };
  }
  const rawStart = table.base + index * table.stride;
  const ccCount = data[rawStart];
  if (!(ccCount >= 1 && ccCount < table.stride)) {
    return { index, out_of_range: true, per_cc: [], raw_hex: hex(data.subarray(rawStart, rawStart + table.stride)) };
  }
  const refs = [];
  for (let i = 0; i < ccCount; i++) refs.push(data[rawStart + 1 + i]);
  const descriptors = uplink ? layout.lte_ul_descriptors : layout.lte_dl_descriptors;
  const descCount = dv.getUint32(descriptors.count_offset, true);
  const mimoByWord = uplink ? LTE_UL_MIMO_LAYERS_BY_WORD : LTE_DL_MIMO_LAYERS_BY_WORD;
  const perCc = [];
  for (const ref of refs) {
    if (ref >= descCount) {
      perCc.push({ descriptor_ref: ref, out_of_range: true });
      continue;
    }
    const word = dv.getUint32(descriptors.base + ref * descriptors.stride, true);
    perCc.push({ descriptor_ref: ref, raw: word, mimo_layers: mimoByWord[word] ?? null });
  }
  return { index, raw_hex: hex(data.subarray(rawStart, rawStart + table.stride)), descriptor_refs: refs, per_cc: perCc };
}

function ulDescriptorCatalog(data, dv, layout) {
  const table = layout.ul_descriptors;
  const result = new Map();
  const count = dv.getUint32(table.count_offset, true);
  for (let index = 0; index < count; index++) {
    const word = dv.getUint16(table.base + index * 2, true);
    const item = { descriptor_ref: index, ...decodePerCcDescriptor(word, true) };
    const key = `${item.frequency_range}|${item.scs_khz}|${item.bandwidth_mhz}`;
    if (!result.has(key)) result.set(key, []);
    result.get(key).push(item);
  }
  return result;
}

// --- feature matrix expansion -------------------------------------------------------

function expandFeatureMatrix(data, dv, layout, category, variant) {
  const table = layoutMatrix(layout, category);
  const base = table.base;
  const tableCount = dv.getUint32(table.count_offset, true);
  const directUl = layout.name === "C4020";
  const ulTable = layoutUlMatrix(layout, category);
  const ulCatalog = directUl ? null : ulDescriptorCatalog(data, dv, layout);
  const ulTableCount = dv.getUint32(ulTable.count_offset, true);
  const result = [];
  for (let ordinal = 0; ordinal < variant.matrix_count; ordinal++) {
    const matrixIndex = variant.matrix_start + ordinal;
    if (matrixIndex >= tableCount) {
      result.push({
        feature_ordinal: ordinal,
        matrix_index: matrixIndex,
        out_of_range: true,
        components: [],
      });
      continue;
    }
    const rawStart = base + matrixIndex * 0x0b;
    const rawByte0 = data[rawStart];
    const componentCount = rawByte0 & 0xf;
    const groupIndices = [];
    for (let i = 0; i < componentCount; i++) groupIndices.push(data[rawStart + 1 + i]);
    const ulMatrixIndex = variant.ul_matrix_start + ordinal;
    const ulMatrixOob = ulMatrixIndex >= ulTableCount;
    // Both generations index the UL matrix for LTE legs; NR legs use it only
    // on C4020 (the row attribute below stays C4020-only).
    const ulRawStart = !ulMatrixOob ? ulTable.base + ulMatrixIndex * 10 : -1;
    const components = [];
    const pairCount = Math.min(variant.components.length, groupIndices.length);
    for (let componentIndex = 0; componentIndex < pairCount; componentIndex++) {
      const component = variant.components[componentIndex];
      const groupIndex = groupIndices[componentIndex];
      const resolved = { ...component, feature_group_index: groupIndex };
      if (component.rat === "NR") {
        const group = featureGroup(data, dv, layout, groupIndex, false);
        const dlPerCc = group.per_cc;
        resolved.dl_feature_group = group;
        resolved.combo_dl_bw_per_cc_mhz = dlPerCc.map((x) => x.bandwidth_mhz);
        resolved.combo_dl_mimo_per_cc_layers = dlPerCc.map((x) => x.mimo_layers);
        resolved.combo_dl_scs_per_cc_khz = dlPerCc.map((x) => x.scs_khz);
        if (component.is_ul) {
          const ulCcCount = componentClass(component.ul_class_code, component.rat, component.band)[1];
          const ulPerCc = [];
          if (directUl) {
            const ulGroupIndex = ulRawStart >= 0 ? data[ulRawStart + componentIndex] : 255;
            const ulGroup = featureGroup(data, dv, layout, ulGroupIndex, true);
            resolved.ul_feature_group_index = ulGroupIndex;
            resolved.ul_feature_group = ulGroup;
            ulPerCc.push(...ulGroup.per_cc);
          } else {
            for (const dlCc of dlPerCc.slice(0, ulCcCount)) {
              const key = `${dlCc.frequency_range}|${dlCc.scs_khz}|${dlCc.bandwidth_mhz}`;
              const matches = ulCatalog.get(key) ?? [];
              ulPerCc.push(
                matches.length
                  ? { ...matches[0] }
                  : {
                      frequency_range: dlCc.frequency_range,
                      scs_khz: dlCc.scs_khz,
                      bandwidth_mhz: dlCc.bandwidth_mhz,
                      mimo_layers: null,
                      unresolved_descriptor: true,
                    },
              );
            }
          }
          resolved.combo_ul_bw_per_cc_mhz = ulPerCc.map((x) => x.bandwidth_mhz);
          resolved.combo_ul_mimo_per_cc_layers = ulPerCc.map((x) => x.mimo_layers);
          resolved.combo_ul_scs_per_cc_khz = ulPerCc.map((x) => x.scs_khz);
          resolved.ul_per_cc_descriptors = ulPerCc;
        } else {
          resolved.combo_ul_bw_per_cc_mhz = [];
          resolved.combo_ul_mimo_per_cc_layers = [];
          resolved.combo_ul_scs_per_cc_khz = [];
        }
      } else {
        // LTE legs index the LTE feature-set table, not the NR DL groups.
        const dlSet = lteFeatureSet(data, dv, layout, groupIndex, false);
        resolved.lte_dl_feature_set = dlSet;
        resolved.combo_dl_mimo_per_cc_layers = dlSet.per_cc.map((x) => x.mimo_layers);
        if (component.is_ul) {
          const ulSetIndex = ulRawStart >= 0 ? data[ulRawStart + componentIndex] : 255;
          const ulSet = lteFeatureSet(data, dv, layout, ulSetIndex, true);
          resolved.lte_ul_feature_set_index = ulSetIndex;
          resolved.lte_ul_feature_set = ulSet;
          resolved.combo_ul_mimo_per_cc_layers = ulSet.per_cc.map((x) => x.mimo_layers);
        } else {
          resolved.combo_ul_mimo_per_cc_layers = [];
        }
      }
      components.push(resolved);
    }
    const row = {
      feature_ordinal: ordinal,
      matrix_index: matrixIndex,
      matrix_raw: hex(data.subarray(rawStart, rawStart + 0x0b)),
      matrix_aux_nibble: rawByte0 >> 4,
      component_count: componentCount,
      group_indices: groupIndices,
      components,
    };
    if (directUl) {
      row.ul_matrix_index = ulMatrixIndex;
      row.ul_matrix_raw = ulRawStart >= 0 ? hex(data.subarray(ulRawStart, ulRawStart + 10)) : "";
      row.ul_matrix_out_of_range = ulMatrixOob;
    }
    result.push(row);
  }
  return result;
}

// --- NR candidate expansion ---------------------------------------------------------

function expandNrCandidate(data, dv, layout, bandTable, cntCompanions, candidate, includeSlot2) {
  const header = candidate.header0; // BigInt
  const first = Number((header >> 32n) & 0xfffffn);
  const count = Number((header >> 52n) & 0xffn);
  if (first + count > cntCompanions) {
    throw new Error(`${candidate.profile_name} candidate ${candidate.source_index}: companion range out of bounds`);
  }
  const variants = [];
  for (let ordinal = 0; ordinal < count; ordinal++) {
    const index = first + ordinal;
    const off = COMPANION_BASE + index * COMPANION_STRIDE;
    const companionH0 = dv.getBigUint64(off, true);
    const featureWord = dv.getBigUint64(off + 8, true);
    const ulCodes = [];
    for (let i = 0; i < 10; i++) ulCodes.push(data[off + 0x10 + i]);
    const featureRowIndex = Number(featureWord & ((1n << BigInt(layout.physical_index_bits)) - 1n));
    const variant = {
      variant_ordinal: ordinal,
      companion_index: index,
      companion_raw: hex(data.subarray(off, off + COMPANION_STRIDE)),
      companion_header: companionH0,
      companion_feature_word: featureWord,
      per_component_physical_row_index: featureRowIndex,
      feature_flags_row_index: Number((featureWord >> 16n) & 0x3fn),
      matrix_start: Number((companionH0 >> 12n) & 0xfffffn),
      ul_matrix_start: Number((companionH0 >> 32n) & 0xfffffn),
      matrix_count: Number((companionH0 >> 52n) & 0xffn),
      relation_ordinal: Number((companionH0 >> 6n) & 0x3fn),
      ul_class_codes: ulCodes,
      physical_row: physicalRow(data, dv, featureRowIndex, layout),
      components: candidate.components.map((component, i) => {
        const merged = { ...component };
        if (component.rat === "NR") {
          Object.assign(merged, nrBandProperties(bandTable, component.band, includeSlot2));
        }
        merged.ul_class_code = ulCodes[i];
        merged.ul_class_letter = UL_CLASS[ulCodes[i]] ?? null;
        merged.is_ul = ulCodes[i] !== 0;
        return merged;
      }),
    };
    variant.feature_variants = expandFeatureMatrix(data, dv, layout, candidate.category, variant);
    variants.push(variant);
  }
  return {
    profile: candidate.profile_name,
    profile_id: candidate.profile_id,
    source_index: candidate.source_index,
    category: candidate.category,
    category_name: candidate.category_name,
    enabled_gate: candidate.enabled_gate,
    total_cc: candidate.total_cc,
    structural_expression: candidate.structural_expression,
    bcs_nr_sets: candidate.bcs_nr_sets,
    bcs_lte_sets: candidate.bcs_lte_sets,
    header0: header,
    q1: candidate.q1,
    w2: candidate.w2,
    variant_start: first,
    variant_count: count,
    variants,
  };
}

// --- Fast inspect ------------------------------------------------------------------
//
// Header-only summary WITHOUT full combinatorial expansion: counts are the
// EXPANDED PRE-DUEDUPE numbers (each base candidate expands through
// companions; each companion contributes matrix_count feature-set rows == one
// B826 row). These may differ from post-dedupe generateAppleTables row
// counts — the UI displays the same pre-dedupe numbers.

export function inspectAppleBank(data) {
  const layout = detectLayout(data);
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const lteCount = dv.getUint32(LTE_COUNT_OFF, true);
  const nrCount = dv.getUint32(NR_BASE_OFF - 4, true); // NR_COUNT_OFF = 0x2EE14 (u32 right before the first row)
  const companionCount = dv.getUint32(COMPANION_COUNT_OFF, true);

  const baseCounts = { endc: 0, nrca: 0, nrdc: 0 };
  const expanded = { endc: 0, nrca: 0, nrdc: 0 };
  for (let i = 0; i < nrCount; i++) {
    const off = NR_BASE_OFF + i * NR_STRIDE;
    const h0 = dv.getBigUint64(off, true);
    const cat = Number((h0 >> 5n) & 3n);
    let kind;
    if (cat === 2) {
      kind = "endc";
    } else if (cat === 1) {
      let hasFr1 = false;
      let hasFr2 = false;
      for (let w = 0; w < 10; w++) {
        const val = dv.getUint16(off + 0x14 + w * 2, true);
        if (val === 0) continue;
        const band = (val >> 1) & 0x3ff;
        if (band <= 256) hasFr1 = true;
        else hasFr2 = true;
      }
      kind = hasFr1 && hasFr2 ? "nrdc" : "nrca";
    } else {
      continue;
    }
    baseCounts[kind] += 1;
    const first = Number((h0 >> 32n) & 0xfffffn);
    const count = Number((h0 >> 52n) & 0xffn);
    for (let index = first; index < Math.min(first + count, companionCount); index++) {
      const ch0 = dv.getBigUint64(COMPANION_BASE + index * COMPANION_STRIDE, true);
      expanded[kind] += Number((ch0 >> 52n) & 0xffn);
    }
  }

  return {
    layout: layout.name,
    lteCount,
    endcCount: expanded.endc,
    nrcaCount: expanded.nrca,
    nrdcCount: expanded.nrdc,
    baseCounts,
    companionCount,
  };
}

// --- bank parse ---------------------------------------------------------------------

export function parseAppleBank(data, name = null, includeSlot2 = true) {
  const layout = detectLayout(data);
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const profileId = dv.getUint32(0, true);
  const profile = name ?? `CR_0x${profileId.toString(16).toUpperCase().padStart(6, "0")}`;

  const bandTable = bandCapabilityTable(data, dv, layout);
  const lteTable = lteCandidateTable(data, dv);

  const cnt0x28 = dv.getUint32(NR_COUNT_OFF, true);
  const cnt0x1c = dv.getUint32(COMPANION_COUNT_OFF, true);

  // Base NR / EN-DC candidates (candidate-table loop).
  const candidates = [];
  for (let i = 0; i < cnt0x28; i++) {
    const off = NR_BASE_OFF + i * NR_STRIDE;
    const h0 = dv.getBigUint64(off, true);
    const q1 = dv.getBigUint64(off + 8, true);
    const w2 = dv.getUint32(off + 16, true);
    const hw = [];
    for (let k = 0; k < 10; k++) hw.push(dv.getUint16(off + 0x14 + k * 2, true));
    const cat = Number((h0 >> 5n) & 3n);
    layoutMatrix(layout, cat); // throws for unsupported categories
    const gate = Number((h0 >> 7n) & 1n);
    const totalCc = Number(h0 & 0x1fn);
    const bcsLte = Number((h0 >> 8n) & 0x1fn);
    const bcsNr = Number((h0 >> 16n) & 0x1fn);
    const comps = [];
    for (let j = 0; j < hw.length; j++) {
      const val = hw[j];
      if (val === 0) break;
      const rat = val & 1 ? "NR" : "LTE";
      const band = (val >>> 1) & 0x3ff;
      const clsCode = (val >>> 11) & 0x1f;
      const [clsLetter, ccW] = componentClass(clsCode, rat, band);
      comps.push({
        component_index: j,
        rat,
        band,
        class_code: clsCode,
        class_letter: clsLetter,
        cc_count: ccW,
        raw_val: val,
      });
    }
    const sumCc = comps.reduce((n, c) => n + c.cc_count, 0);
    const expr = comps.map((c) => `${c.rat === "NR" ? "n" : "B"}${c.band}${c.class_letter}`).join("+");
    const bcsLteSets = [];
    const bcsNrSets = [];
    for (let b = 0; b < 5; b++) {
      if ((bcsLte >>> b) & 1) bcsLteSets.push(b);
      if ((bcsNr >>> b) & 1) bcsNrSets.push(b);
    }
    candidates.push({
      source_index: i,
      offset: off,
      header0: h0,
      q1,
      w2,
      category: cat,
      category_name: cat === 1 ? "NR_ONLY" : cat === 2 ? "ENDC" : `CAT_${cat}`,
      enabled_gate: gate,
      total_cc: totalCc,
      bcs_lte: bcsLte,
      bcs_nr: bcsNr,
      bcs_lte_sets: bcsLteSets,
      bcs_nr_sets: bcsNrSets,
      components: comps,
      component_count: comps.length,
      cc_sum_matches: sumCc === totalCc,
      structural_expression: expr,
      // carried for expandNrCandidate's error message
      profile_name: profile,
      profile_id: profileId,
    });
  }

  const nr = candidates.map((c) => expandNrCandidate(data, dv, layout, bandTable, cnt0x1c, c, includeSlot2));

  // Audit block; the field names are part of the output contract.
  let nrVariantCount = 0;
  let nrComponentVariantCount = 0;
  let nrFeatureVariantCount = 0;
  let nrFeatureMatrixOob = 0;
  let nrPhysicalRowOob = 0;
  let nrEmptyFeatureVariants = 0;
  let nrUlFeatureMatrixOob = 0;
  let nrFeatureGroupOob = 0;
  let nrPerCcDescriptorInvalid = 0;
  let nrFeatureComponentCountMismatch = 0;
  let nrDlDescriptorCcMismatch = 0;
  let nrUlDescriptorCcMismatch = 0;
  let nrUlDescriptorUnresolved = 0;
  let lteFeatureSetOob = 0;
  let ltePerCcDescriptorUnresolved = 0;
  let lteFeatureSetCcMismatch = 0;
  let nrVariantRangeOob = 0;
  const unknownUlClassCodes = new Set();
  for (const c of nr) {
    nrVariantCount += c.variant_count;
    nrVariantRangeOob += c.variant_start + c.variant_count > cnt0x1c ? 1 : 0;
    for (const v of c.variants) {
      nrComponentVariantCount += v.components.length;
      nrFeatureVariantCount += v.feature_variants.length;
      nrPhysicalRowOob += v.physical_row.out_of_range ? 1 : 0;
      nrEmptyFeatureVariants += v.feature_variants.length === 0 ? 1 : 0;
      for (const code of v.ul_class_codes) {
        if (!(code in UL_CLASS) && code !== 0) unknownUlClassCodes.add(code);
      }
      for (const fv of v.feature_variants) {
        nrFeatureMatrixOob += fv.out_of_range ? 1 : 0;
        nrUlFeatureMatrixOob += fv.ul_matrix_out_of_range ? 1 : 0;
        nrFeatureComponentCountMismatch +=
          !fv.out_of_range && fv.component_count !== v.components.length ? 1 : 0;
        for (const x of fv.components) {
          for (const key of ["dl_feature_group", "ul_feature_group"]) {
            if (x[key]?.out_of_range) nrFeatureGroupOob += 1;
          }
          const perCc = [
            ...(x.dl_feature_group?.per_cc ?? []),
            ...(x.ul_per_cc_descriptors ?? []),
          ];
          for (const cc of perCc) {
            if (
              cc.out_of_range === true ||
              cc.bandwidth_mhz == null ||
              cc.mimo_layers == null ||
              cc.scs_khz == null
            ) {
              nrPerCcDescriptorInvalid += 1;
            }
          }
          if (x.rat === "NR") {
            if ((x.combo_dl_bw_per_cc_mhz?.length ?? 0) !== x.cc_count) nrDlDescriptorCcMismatch += 1;
            if (x.is_ul) {
              const expected = componentClass(x.ul_class_code, x.rat, x.band)[1];
              if ((x.combo_ul_bw_per_cc_mhz?.length ?? 0) !== expected) nrUlDescriptorCcMismatch += 1;
              for (const cc of x.ul_per_cc_descriptors ?? []) {
                if (cc.unresolved_descriptor) nrUlDescriptorUnresolved += 1;
              }
            }
          }
          if (x.rat === "LTE") {
            lteFeatureSetOob += x.lte_dl_feature_set?.out_of_range ? 1 : 0;
            if (x.is_ul && x.lte_ul_feature_set?.out_of_range) lteFeatureSetOob += 1;
            for (const set of [x.lte_dl_feature_set, x.lte_ul_feature_set]) {
              for (const cc of set?.per_cc ?? []) {
                if (cc.out_of_range === true || cc.mimo_layers == null) ltePerCcDescriptorUnresolved += 1;
              }
            }
            const dlLen = (x.combo_dl_mimo_per_cc_layers ?? []).length;
            const ulLen = (x.combo_ul_mimo_per_cc_layers ?? []).length;
            if (
              dlLen !== x.cc_count ||
              (x.is_ul && ulLen !== componentClass(x.ul_class_code, x.rat, x.band)[1])
            ) {
              lteFeatureSetCcMismatch += 1;
            }
          }
        }
      }
    }
  }

  const audit = {
    lte_candidate_count: lteTable.count,
    lte_reference_oob: lteTable.refs.reduce((n, r) => n + (r >= lteTable.count ? 1 : 0), 0),
    nr_candidate_count: nr.length,
    nr_variant_count: nrVariantCount,
    nr_component_variant_count: nrComponentVariantCount,
    nr_feature_variant_count: nrFeatureVariantCount,
    nr_feature_matrix_oob: nrFeatureMatrixOob,
    nr_physical_row_oob: nrPhysicalRowOob,
    nr_empty_feature_variants: nrEmptyFeatureVariants,
    nr_ul_feature_matrix_oob: nrUlFeatureMatrixOob,
    nr_feature_group_oob: nrFeatureGroupOob,
    nr_per_cc_descriptor_invalid: nrPerCcDescriptorInvalid,
    nr_feature_component_count_mismatch: nrFeatureComponentCountMismatch,
    nr_dl_descriptor_cc_mismatch: nrDlDescriptorCcMismatch,
    nr_ul_descriptor_cc_mismatch: nrUlDescriptorCcMismatch,
    nr_ul_descriptor_unresolved: nrUlDescriptorUnresolved,
    lte_feature_set_oob: lteFeatureSetOob,
    lte_per_cc_descriptor_unresolved: ltePerCcDescriptorUnresolved,
    lte_feature_set_cc_mismatch: lteFeatureSetCcMismatch,
    nr_variant_range_oob: nrVariantRangeOob,
    unknown_ul_class_codes: [...unknownUlClassCodes].sort((a, b) => a - b),
    cc_mismatches: candidates.reduce((n, c) => n + (c.cc_sum_matches ? 0 : 1), 0),
    band_slot1_encoding_violations: bandTable.encoding_violations.length,
  };

  return {
    profile,
    profile_id: profileId,
    source_file: name ?? profile,
    layout: layoutMetadata(layout),
    slot2_policy: includeSlot2 ? "STRONG_INFERENCE" : "RAW_ONLY",
    lte_candidates: lteTable.records,
    nr_candidates: nr,
    audit,
  };
}

// Audit fields that fail requireValidBank.
const AUDIT_ERROR_FIELDS = [
  "lte_reference_oob", "nr_variant_range_oob", "unknown_ul_class_codes",
  "nr_feature_matrix_oob", "nr_ul_feature_matrix_oob", "nr_physical_row_oob",
  "nr_empty_feature_variants", "nr_feature_group_oob", "nr_per_cc_descriptor_invalid",
  "nr_feature_component_count_mismatch", "nr_dl_descriptor_cc_mismatch",
  "nr_ul_descriptor_cc_mismatch", "nr_ul_descriptor_unresolved",
  "lte_feature_set_oob", "lte_per_cc_descriptor_unresolved", "lte_feature_set_cc_mismatch",
  "cc_mismatches", "band_slot1_encoding_violations",
];

export function requireValidBank(bank) {
  const errors = {};
  for (const key of AUDIT_ERROR_FIELDS) {
    const value = bank.audit[key];
    // Truthiness: an empty list (unknown_ul_class_codes) is falsy.
    const truthy = Array.isArray(value) ? value.length > 0 : Boolean(value);
    if (truthy) errors[key] = value;
  }
  if (Object.keys(errors).length) {
    const repr = `{${Object.entries(errors)
      .map(([k, v]) => `'${k}': ${JSON.stringify(v)}`)
      .join(", ")}}`;
    throw new Error(`${bank.source_file}: capability audit failed: ${repr}`);
  }
}

// --- viewer table generation ---------------------------------------------------------

function compSortKey(comp, isUl = false) {
  let band;
  try {
    band = Number(comp.band ?? 0);
  } catch {
    band = 0;
  }
  const bwClass = String(comp[isUl ? "ul_class_letter" : "class_letter"] ?? "") || "";
  return [band, bwClass];
}

// Stable descending sort by tuple.
function byCompSortKeyDesc(isUl) {
  return (a, b) => {
    const [bandA, clsA] = compSortKey(a, isUl);
    const [bandB, clsB] = compSortKey(b, isUl);
    if (bandA !== bandB) return bandB - bandA;
    return clsA < clsB ? 1 : clsA > clsB ? -1 : 0;
  };
}

const joinMimo = (comps, key) =>
  comps.map((c) => (c[key] ?? []).map(String).join("+") || "").join(" + ");

// Join per-CC values with '+', showing '?' for anything the bank did not
// resolve.
const perCcText = (values) =>
  values?.length ? values.map((v) => (v == null ? "?" : String(v))).join("+") : "?";

export function generateAppleTables(bank) {
  // 1. Standalone LTE CA
  const lteRows = [];
  for (const candidate of bank.lte_candidates ?? []) {
    const rawComps = candidate.components ?? [];
    if (!rawComps.length) continue;
    const comps = [...rawComps].sort(byCompSortKeyDesc(false));
    const ulComps = [...rawComps.filter((c) => c.is_ul)].sort(byCompSortKeyDesc(true));
    const bcsSets = candidate.bcs_sets ?? [];
    const bcsStr = bcsSets.length ? bcsSets.map(String).join(", ") : "0";
    lteRows.push({
      "LTE DL": comps.map((c) => `${c.band}${c.class_letter}`).join(" + "),
      "MIMO DL": comps.map((c) => String(c.dl_mimo_layers || 2)).join(" + "),
      "LTE UL": ulComps.length
        ? ulComps.map((c) => `${c.band}${c.ul_class_letter || "A"}`).join(" + ")
        : "",
      "MIMO UL": ulComps.length ? ulComps.map(() => "1").join(" + ") : "",
      BCS: bcsStr,
    });
  }

  // 2. NR-Only, EN-DC, and NRDC (FR1+FR2)
  const endcRows = [];
  const nrcaRows = [];
  const nrdcRows = [];

  for (const candidate of bank.nr_candidates ?? []) {
    const bcsLte = candidate.bcs_lte_sets ?? [];
    const bcsNr = candidate.bcs_nr_sets ?? [];
    const allBcs = [...new Set([...bcsLte, ...bcsNr])].sort((a, b) => a - b);
    const bcsStr = allBcs.length ? allBcs.map(String).join(", ") : "0";

    for (const variant of candidate.variants ?? []) {
      for (const feature of variant.feature_variants ?? []) {
        const comps = feature.components ?? [];
        if (!comps.length) continue;

        const hasLte = comps.some((c) => c.rat === "LTE");
        const hasFr1 = comps.some((c) => c.rat === "NR" && c.band < 257);
        const hasFr2 = comps.some((c) => c.rat === "NR" && c.band >= 257);

        if (hasLte) {
          const lteComps = [...comps.filter((c) => c.rat === "LTE")].sort(byCompSortKeyDesc(false));
          const nrComps = [...comps.filter((c) => c.rat === "NR")].sort(byCompSortKeyDesc(false));
          const lteUl = [...lteComps.filter((c) => c.is_ul)].sort(byCompSortKeyDesc(true));
          const nrUl = [...nrComps.filter((c) => c.is_ul)].sort(byCompSortKeyDesc(true));
          endcRows.push({
            "LTE DL": lteComps.map((c) => `${c.band}${c.class_letter}`).join(" + "),
            "LTE MIMO DL": lteComps.map((c) => perCcText(c.combo_dl_mimo_per_cc_layers)).join(" + "),
            "NR DL": nrComps.map((c) => `${c.band}${c.class_letter}`).join(" + "),
            "NR MIMO DL": joinMimo(nrComps, "combo_dl_mimo_per_cc_layers") || "2",
            "NR BW DL (MHz)": joinMimo(nrComps, "combo_dl_bw_per_cc_mhz"),
            "LTE UL": lteUl.length
              ? lteUl.map((c) => `${c.band}${c.ul_class_letter || "A"}`).join(" + ")
              : "",
            "LTE MIMO UL": lteUl.length ? lteUl.map((c) => perCcText(c.combo_ul_mimo_per_cc_layers)).join(" + ") : "",
            "NR UL": nrUl.length
              ? nrUl.map((c) => `${c.band}${c.ul_class_letter || "A"}`).join(" + ")
              : "",
            "NR MIMO UL": joinMimo(nrUl, "combo_ul_mimo_per_cc_layers") || "1",
            "NR BW UL (MHz)": joinMimo(nrUl, "combo_ul_bw_per_cc_mhz"),
            BCS: bcsStr,
          });
        } else if (hasFr1 && hasFr2) {
          const fr1Comps = [...comps.filter((c) => c.rat === "NR" && c.band < 257)].sort(byCompSortKeyDesc(false));
          const fr2Comps = [...comps.filter((c) => c.rat === "NR" && c.band >= 257)].sort(byCompSortKeyDesc(false));
          const fr1Ul = [...fr1Comps.filter((c) => c.is_ul)].sort(byCompSortKeyDesc(true));
          const fr2Ul = [...fr2Comps.filter((c) => c.is_ul)].sort(byCompSortKeyDesc(true));
          nrdcRows.push({
            "FR1 DL": fr1Comps.map((c) => `${c.band}${c.class_letter}`).join(" + "),
            "FR1 MIMO DL": joinMimo(fr1Comps, "combo_dl_mimo_per_cc_layers") || "2",
            "FR1 BW DL (MHz)": joinMimo(fr1Comps, "combo_dl_bw_per_cc_mhz"),
            "FR2 DL": fr2Comps.map((c) => `${c.band}${c.class_letter}`).join(" + "),
            "FR2 MIMO DL": joinMimo(fr2Comps, "combo_dl_mimo_per_cc_layers") || "2",
            "FR2 BW DL (MHz)": joinMimo(fr2Comps, "combo_dl_bw_per_cc_mhz"),
            "FR1 UL": fr1Ul.length
              ? fr1Ul.map((c) => `${c.band}${c.ul_class_letter || "A"}`).join(" + ")
              : "",
            "FR1 MIMO UL": joinMimo(fr1Ul, "combo_ul_mimo_per_cc_layers") || "1",
            "FR1 BW UL (MHz)": joinMimo(fr1Ul, "combo_ul_bw_per_cc_mhz"),
            "FR2 UL": fr2Ul.length
              ? fr2Ul.map((c) => `${c.band}${c.ul_class_letter || "A"}`).join(" + ")
              : "",
            "FR2 MIMO UL": joinMimo(fr2Ul, "combo_ul_mimo_per_cc_layers") || "1",
            "FR2 BW UL (MHz)": joinMimo(fr2Ul, "combo_ul_bw_per_cc_mhz"),
            BCS: bcsStr,
          });
        } else {
          const nrComps = [...comps.filter((c) => c.rat === "NR")].sort(byCompSortKeyDesc(false));
          const nrUl = [...nrComps.filter((c) => c.is_ul)].sort(byCompSortKeyDesc(true));
          nrcaRows.push({
            "NR DL": nrComps.map((c) => `${c.band}${c.class_letter}`).join(" + "),
            "MIMO DL": joinMimo(nrComps, "combo_dl_mimo_per_cc_layers") || "2",
            "BW DL (MHz)": joinMimo(nrComps, "combo_dl_bw_per_cc_mhz"),
            "NR UL": nrUl.length
              ? nrUl.map((c) => `${c.band}${c.ul_class_letter || "A"}`).join(" + ")
              : "",
            "MIMO UL": joinMimo(nrUl, "combo_ul_mimo_per_cc_layers") || "1",
            "BW UL (MHz)": joinMimo(nrUl, "combo_ul_bw_per_cc_mhz"),
            BCS: bcsStr,
          });
        }
      }
    }
  }

  return {
    lte_ca: lteRows,
    endc: endcRows,
    nr_ca: nrcaRows,
    nrdc: nrdcRows,
  };
}

// --- DIAG export ----------------------------------------------------------------------

export const CLASS_INDEX = { A: 1, B: 2, C: 3, D: 4, E: 5, F: 6 };

// Wire enum indices for bandwidth and antenna strings.
function enumAssignments() {
  const bwNames = [
    "DEFAULT", "5", "10", "15", "20", "20_20", "20_20_20", "20_20_20_20", "20_20_20_20_20",
    "25", "30", "40", "50", "50_50", "50_50_50", "50_50_50_50", "50_50_50_50_50",
    "60", "70", "80", "90", "100", "100_60", "100_100", "100_100_100",
    "100_100_100_100", "100_100_100_100_100", "100_100_100_100_100_100",
    "100_100_100_100_100_100_100", "100_100_100_100_100_100_100_100",
    "40_40", "60_40", "100_40", "200", "200_200", "200_200_200", "200_200_200_200",
    "10_10", "25_25", "40_10", "40_20", "35", "30_20", "60_60", "30_30", "45",
    "50_5", "50_10", "50_15", "50_20", "40_15", "15_15", "30_25", "20_10", "20_15",
    "5_5", "80_80", "80_20", "40_30", "100_90", "30_10", "100_20", "80_40", "50_40",
    "100_50", "100_80",
  ];
  const result = {};
  bwNames.forEach((name, i) => {
    result[`BW_${name}`] = i;
  });
  const antennaNames = ["INVALID", "1", "2", "4"];
  for (let count = 2; count <= 8; count++) {
    antennaNames.push(Array(count).fill("1").join("_"));
    for (let leading = 1; leading <= count; leading++) {
      antennaNames.push([...Array(leading).fill("2"), ...Array(count - leading).fill("1")].join("_"));
    }
    for (let leading = 1; leading <= count; leading++) {
      antennaNames.push([...Array(leading).fill("4"), ...Array(count - leading).fill("2")].join("_"));
    }
  }
  antennaNames.push("8", "8_4", "8_4_4", "8_8", "6", "4_8", "6_4", "4_6", "6_6");
  antennaNames.forEach((name, i) => {
    result[`ANTENNA_${name}`] = i;
  });
  return result;
}

const BW_EXTENSION_BASE = 66;
const BW_EXTENSION_LIMIT = 127;
const BW_EXTENSION_TUPLES = ["35_35", "45_45", "40_40_40", "100_40_40", "100_100_40"];

// Fresh per-call wire-enum state (see the module header notes): the
// ANTENNA_/BW_ enum extensions accumulate in encounter order.
function createWireEnums() {
  const ENUMS = enumAssignments();
  const ANTENNA_ENUM = {};
  for (const [name, value] of Object.entries(ENUMS)) {
    if (name.startsWith("ANTENNA_")) ANTENNA_ENUM[name] = value;
  }
  let antennaExtensionBase = Math.max(...Object.values(ANTENNA_ENUM)) + 1;
  const antennaExtensions = new Map();
  const BW_ENUM = { ...ENUMS };
  const bwExtensions = new Map();
  BW_EXTENSION_TUPLES.forEach((name, i) => {
    const index = BW_EXTENSION_BASE + i;
    BW_ENUM[`BW_${name}`] = index;
    bwExtensions.set(index, name); // pre-seeded: the 5 fixed extension tuples
  });

  function antenna(layers) {
    if (!layers || layers.some((v) => v === null || v === undefined)) return ENUMS["ANTENNA_INVALID"];
    const name = "ANTENNA_" + layers.map(String).join("_");
    if (!(name in ANTENNA_ENUM)) {
      const index = antennaExtensionBase + antennaExtensions.size;
      if (index > 127) throw new Error(`no DL antenna wire index left for ${name}`);
      ANTENNA_ENUM[name] = index;
      antennaExtensions.set(index, [...layers]);
    }
    return ANTENNA_ENUM[name];
  }

  function bandwidth(values) {
    if (!values || values.some((v) => v === null || v === undefined)) return ENUMS["BW_DEFAULT"];
    const name = "BW_" + values.map(String).join("_");
    let index = BW_ENUM[name];
    if (index === undefined) {
      index = BW_EXTENSION_BASE + bwExtensions.size;
      if (index > BW_EXTENSION_LIMIT) throw new Error(`no wire index left for ${name}`);
      BW_ENUM[name] = index;
      bwExtensions.set(index, name.slice(3));
    }
    return index;
  }

  return { ENUMS, antenna, bandwidth };
}

// b826_v22_component: pack one component into a 10-byte B826 v22 wire record.
export function b826V22Component(bg) {
  if (bg.band > 0x1ff) throw new Error(`band ${bg.band} exceeds 9 bits`);
  const dlAnt = Number(bg.dl_max_antennas_index);
  const ulAnt = Number(bg.ul_max_antennas_index);
  const dlBw = Number(bg.dl_bw_per_cc);
  const ulBw = Number(bg.ul_bw_per_cc);
  const checks = [
    ["dl_ant", dlAnt, 127],
    ["ul_ant", ulAnt, 31],
    ["dl_bw", dlBw, 127],
    ["ul_bw", ulBw, 127],
    ["dl_class", Number(bg.dl_bw_class), 31],
    ["ul_class", Number(bg.ul_bw_class), 31],
  ];
  for (const [name, value, limit] of checks) {
    if (!(value >= 0 && value <= limit)) {
      throw new Error(`${name}=${value} exceeds B826 v22 range 0..${limit}`);
    }
  }
  const head =
    Number(bg.band) |
    ((bg.tech === 2 ? 1 : 0) << 9) |
    ((Number(bg.dl_bw_class) & 0x1f) << 10) |
    ((dlAnt & 1) << 15);
  const b1 = ((dlAnt >> 1) & 0x3f) | ((Number(bg.ul_bw_class) & 3) << 6);
  const b2 = ((Number(bg.ul_bw_class) >> 2) & 7) | ((ulAnt & 0x1f) << 3);
  const qam = Number(bg.ul_qam_cap_index) & 3;
  const b3 = ((qam & 1) << 2) | (((qam >> 1) & 1) << 1) | ((dlBw & 1) << 7);
  const b4 = ((dlBw >> 1) & 0x3f) | ((ulBw & 3) << 6);
  const b5 = (ulBw >> 2) & 0x1f;
  const out = new Uint8Array(10);
  const dv = new DataView(out.buffer);
  dv.setUint16(0, head, true);
  out[2] = b1;
  out[3] = b2;
  out[4] = b3;
  out[5] = b4;
  out[6] = b5;
  return out;
}

// keepNoUl=true and zeroUlFields=false defaults.
export function b0cdBlobs(bank, wire, keepNoUl = true, zeroUlFields = false) {
  const blobs = [];
  for (const candidate of bank.lte_candidates) {
    if (!keepNoUl && !candidate.components.some((c) => c.is_ul)) continue;
    const components = [];
    for (const c of candidate.components) {
      const ul = CLASS_INDEX[c.ul_class_letter] ?? 0;
      const packed = new Uint8Array(7); // "<HBBBBB": u16 band + 5 bytes
      const dv = new DataView(packed.buffer);
      dv.setUint16(0, c.band, true);
      packed[2] = CLASS_INDEX[c.class_letter] ?? 0;
      packed[3] = ul;
      packed[4] = wire.antenna([c.dl_mimo_layers]);
      packed[5] = zeroUlFields ? 0 : ul ? wire.ENUMS["ANTENNA_1"] : 0;
      packed[6] = zeroUlFields ? 0 : ul ? 1 : 0;
      components.push(packed);
    }
    if (components.length) {
      const blob = new Uint8Array(1 + components.length * 7);
      blob[0] = components.length;
      components.forEach((c, i) => blob.set(c, 1 + i * 7));
      blobs.push(blob);
    }
  }
  return blobs;
}

// Payloads with byte0=41 and byte1=combo_count.
export function packetiseB0cd(blobs, packetCombos) {
  const packets = [];
  for (let i = 0; i < blobs.length; i += packetCombos) {
    const cur = blobs.slice(i, i + packetCombos);
    const total = cur.reduce((n, b) => n + b.length, 0);
    const out = new Uint8Array(2 + total);
    out[0] = 41;
    out[1] = cur.length;
    let p = 2;
    for (const b of cur) {
      out.set(b, p);
      p += b.length;
    }
    packets.push(out);
  }
  return packets;
}

const bytesKey = (u8) => {
  let s = "";
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return s;
};

// B826 source: 3 = EN-DC, 4 = NR-CA, 5 = NRDC (FR1+FR2).
function b826Source(components) {
  if (components.some((c) => c.rat === "LTE")) return 3;
  const ranges = new Set(components.map((c) => c.band > 256));
  return ranges.size === 2 ? 5 : 4;
}

// ul_tx_switch_type: C4020 FR1 switched uplink classification (2+1 NR UL -> Option 1).
function ulTxSwitchType(bank, components) {
  if (bank.layout?.name !== "C4020") return 0;
  const nrComponents = components.filter((c) => c.rat === "NR");
  if (!nrComponents.length || nrComponents.some((c) => c.band > 256)) return 0;
  const active = components
    .filter((c) => c.rat === "NR" && c.is_ul)
    .map((c) => c.combo_ul_mimo_per_cc_layers ?? []);
  const sortedActive = [...active].sort((a, b) => {
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
  });
  const eq =
    sortedActive.length === 2 &&
    sortedActive[0].length === 1 && sortedActive[0][0] === 1 &&
    sortedActive[1].length === 1 && sortedActive[1][0] === 2;
  return eq ? 1 : 0;
}

// NR combination records for B826 v22 framing.
function nrRecords(bank, wire, category, source) {
  const records = [];
  for (const candidate of bank.nr_candidates) {
    if (candidate.category !== category) continue;
    for (const variant of candidate.variants) {
      for (const feature of variant.feature_variants) {
        if (source !== null && b826Source(feature.components) !== source) continue;
        const groups = [];
        for (const c of feature.components) {
          const isNr = c.rat === "NR";
          const ulClass = c.ul_class_code;
          groups.push({
            band: c.band,
            tech: isNr ? 2 : 1,
            dl_bw_class: c.class_code,
            dl_bw_per_cc: isNr ? wire.bandwidth(c.combo_dl_bw_per_cc_mhz ?? []) : 0,
            ul_bw_class: ulClass,
            ul_bw_per_cc: isNr && ulClass ? wire.bandwidth(c.combo_ul_bw_per_cc_mhz ?? []) : 0,
            dl_max_antennas_index: wire.antenna(c.combo_dl_mimo_per_cc_layers ?? []),
            ul_max_antennas_index: ulClass ? wire.antenna(c.combo_ul_mimo_per_cc_layers ?? []) : 0,
            ul_qam_cap_index: 0,
          });
        }
        if (groups.length) {
          records.push({ groups, ul_tx_switch_type: ulTxSwitchType(bank, feature.components) });
        }
      }
    }
  }
  return records;
}

const nrRecordKey = (record) => {
  let wire = "";
  for (const g of record.groups) wire += bytesKey(b826V22Component(g));
  return `${record.ul_tx_switch_type}\u0000${wire}`;
};

function dedupe(items, keyFn) {
  const seen = new Set();
  const result = [];
  for (const item of items) {
    const value = keyFn(item);
    if (!seen.has(value)) {
      seen.add(value);
      result.push(item);
    }
  }
  return result;
}

// Frame combination records into complete DIAG packets.
function b826V22Packets(records, source, packetCombos) {
  const encoded = [];
  for (const { groups, ul_tx_switch_type } of records) {
    const count = groups.length;
    if (!(count >= 1 && count <= 15)) {
      throw new Error(`component count ${count} out of range [1, 15]`);
    }
    const features = (count << 6) | ((ul_tx_switch_type & 3) << 13);
    const body = new Uint8Array(15 + count * 10);
    const dv = new DataView(body.buffer);
    dv.setUint16(0, features, true);
    groups.forEach((g, i) => body.set(b826V22Component(g), 15 + i * 10));
    encoded.push(body);
  }
  const total = encoded.length;
  if (total > 65535) {
    throw new Error("B826 v22 supports at most 65535 combinations per source; export banks separately");
  }
  const out = [];
  for (let start = 0; start < total; start += packetCombos) {
    const cur = encoded.slice(start, start + packetCombos);
    const size = cur.reduce((n, b) => n + b.length, 0);
    const packet = new Uint8Array(11 + size);
    const dv = new DataView(packet.buffer);
    dv.setUint16(0, 22, true);
    dv.setUint16(2, 0, true);
    dv.setUint16(4, total, true);
    dv.setUint16(6, start, true);
    dv.setUint16(8, cur.length, true);
    packet[10] = source;
    let p = 11;
    for (const b of cur) {
      packet.set(b, p);
      p += b.length;
    }
    out.push(packet);
  }
  return out;
}

// DIAG hexdump as text: header lines + "# <label>\nPayload: <hex>\n\n".
function diagText(packets) {
  const lines = [
    "# Headerless Qualcomm DIAG log payloads; one Payload block per complete wire payload.",
    "# 0xB0CD uses v41; 0xB826 uses v22.",
    "",
  ];
  for (const [label, payload] of packets) {
    lines.push(`# ${label}`, `Payload: ${hex(payload)}`, "");
  }
  return lines.join("\n");
}

// exportAppleDiag(parsed, "b0cd" | "b826") -> [{ filename, text }]
// filename mirrors the qcom exportModule naming so main.js's textFor tails and
// Import-to-parser keep working: `${stem}_0xB0CD_v41.txt` / `${stem}_0xB826_v22.txt`.
export function exportAppleDiag(parsed, format) {
  if (format !== "b0cd" && format !== "b826") {
    throw new Error(`Unsupported export format: ${format}`);
  }
  const stem = parsed.profile;
  const wire = createWireEnums(); // fresh extension state per call (see module header notes)
  let packets;
  if (format === "b0cd") {
    const lte = dedupe(b0cdBlobs(parsed, wire, true, false), bytesKey);
    const b0cdPackets = packetiseB0cd(lte, 100);
    packets = b0cdPackets.map((packet, i) => [`LTE-CA packet ${i + 1}/${b0cdPackets.length}`, packet]);
  } else {
    const labelled = [];
    for (const [label, category, source] of [["ENDC", 2, 3], ["NRCA", 1, 4], ["NRDC", 1, 5]]) {
      const rows = dedupe(nrRecords(parsed, wire, category, source), nrRecordKey);
      const pkts = b826V22Packets(rows, source, Math.max(1, rows.length));
      for (const packet of pkts) labelled.push([`${label} source=${source} complete payload`, packet]);
    }
    packets = labelled;
  }
  const filename = format === "b0cd" ? `${stem}_0xB0CD_v41.txt` : `${stem}_0xB826_v22.txt`;
  return [{ filename, text: diagText(packets) }];
}
