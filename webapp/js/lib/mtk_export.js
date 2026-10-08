// Stage-D wire-format exports for MTK DRDI cards (B826 v21 + B0CD v41) — the
// formats the uecaps parser's QNR/QLTE importers consume. Out of feature
// scope: cap_prune and the per-family file writers (the worker
// only needs the combined B826 text and the B0CD v41 file text).
//
// Byte-exactness contract (spec §5, differential-tested against
// webapp/goldens/mtk/diag.json): every produced text must equal the golden
// reference output for the same card byte-for-byte. The two-layer dedup
// matters: buildB826 first drops structurally identical component rows
// (`repr(comps)`-style identity — realized here as a stable JSON key over
// dicts built in the same field order), then buildB826Log drops combos that
// ENCODE to identical bytes (mimo_index canonicalizes e.g. [2,4] and [4,2] to
// the same antenna enum, so both layers can fire on the same input).
//
// Fidelity notes (spec §6): LE byte packing is done with plain arithmetic
// (struct "<HBBBBB"/"<HHHHHB" layouts), index tables are insertion-ordered
// Maps keyed by "_"-joined digit tuples, and error cases become typed errors
// with identical message strings.
import { bump } from "./debug.js";
import { sha256Hex } from "./hash.js";
import { classify } from "./mtk_universal.js";

// Physical carriers per LTE bandwidth class, indexed by the 0-based class
// byte. A=1 B=2 C=2 D=3 E=4 F=5.
export const LTE_CLASS_CCS = [1, 2, 2, 3, 4, 5];
export const LTE_UL_ABSENT = 6;

const B826_VERSION = 21;
const SOURCE_ENDC = 3;
const SOURCE_NRCA = 4;
const SOURCE_NRDC = 5;
const SOURCE_TAGS = { 3: "RF_ENDC", 4: "RF_NRCA", 5: "RF_NRDC" };

// ---------------------------------------------------------------- B826 tables

// BW_NAMES: index 0 is the "DEFAULT" placeholder and is NOT a
// key of BW_TO_INDEX — 67 encodable names, indices 1..67.
export const BW_NAMES = [
  "DEFAULT", "5", "10", "15", "20", "20_20", "20_20_20",
  "20_20_20_20", "20_20_20_20_20", "25", "30", "40", "50",
  "50_50", "50_50_50", "50_50_50_50", "50_50_50_50_50", "60",
  "70", "80", "90", "100", "100_60", "100_100", "100_100_100",
  "100_100_100_100", "100_100_100_100_100",
  "100_100_100_100_100_100", "100_100_100_100_100_100_100",
  "100_100_100_100_100_100_100_100", "40_40", "60_40",
  "100_40", "200", "200_200", "200_200_200", "200_200_200_200",
  "10_10", "25_25", "40_10", "40_20", "35", "30_20", "60_60",
  "30_30", "45", "50_5", "50_10", "50_15", "50_20", "40_15",
  "15_15", "30_25", "20_10", "20_15", "5_5", "80_80", "80_20",
  "40_30", "100_90", "30_10", "100_20", "80_40", "50_40",
  "100_50", "100_80",
  "35_35", "45_45",
];

export const BW_TO_INDEX = new Map(
  BW_NAMES.flatMap((name, idx) => (name === "DEFAULT" ? [] : [[name, idx]])),
);

export const SCS_TO_INDEX = new Map([
  [15, 1], [30, 2], [60, 3], [120, 4], [240, 5],
]);

// Antenna tables: INVALID, the plain 1/2/4 enums, then for
// every carrier count 2..8 the all-ones vector followed by the descending
// 2-leading and 4-leading mixes, closed by the explicit 8/6-carrier tails.
// 90 entries; both directions are kept (the reverse map is what the
// reference decoder reads).
function antennaTables() {
  const names = ["INVALID", "1", "2", "4"];
  for (let count = 2; count <= 8; count++) {
    names.push(Array(count).fill("1").join("_"));
    for (let leading = 1; leading <= count; leading++) {
      names.push([...Array(leading).fill("2"), ...Array(count - leading).fill("1")].join("_"));
    }
    for (let leading = 1; leading <= count; leading++) {
      names.push([...Array(leading).fill("4"), ...Array(count - leading).fill("2")].join("_"));
    }
  }
  names.push("8", "8_4", "8_4_4", "8_8", "6", "4_8", "6_4", "4_6", "6_6");
  const fwd = new Map(); // layers key -> index
  const rev = new Map(); // index -> layers array
  names.forEach((name, idx) => {
    const layers = name === "INVALID" ? [] : name.split("_").map(Number);
    fwd.set(layers.join("_"), idx);
    rev.set(idx, layers);
  });
  return [fwd, rev];
}

export const ANT_TO_INDEX = antennaTables()[0];
export const INDEX_TO_ANT = antennaTables()[1];

export function mimoIndex(layers) {
  if (!layers || layers.length === 0) return 0;
  const key = layers.map(Number);
  const direct = ANT_TO_INDEX.get(key.join("_"));
  if (direct !== undefined) return direct;
  const canonical = [...key].sort((a, b) => b - a);
  const idx = ANT_TO_INDEX.get(canonical.join("_"));
  if (idx !== undefined) return idx;
  throw new Error(`B826 antenna enum cannot encode MIMO vector [${key.join(", ")}]`);
}

// The bandwidth-EXT enum path is dead code upstream (BW_EXT_ENABLE = False)
// and is not implemented here.
// Returns [index, ok, rawKey, collapsed] — `collapsed` carries the ORIGINAL
// bandwidth list only for the two-distinct-values collapse (the caller feeds
// it to the unsupported counter); it is null in every other branch.
export function bwIndex(values) {
  if (!values || values.length === 0) return [0, true, [], null];
  const key = values.map(Number);
  let idx = BW_TO_INDEX.get(key.join("_"));
  if (idx !== undefined) return [idx, true, key, null];
  const canonical = [...key].sort((a, b) => b - a);
  idx = BW_TO_INDEX.get(canonical.join("_"));
  if (idx !== undefined) return [idx, true, canonical, null];
  if (new Set(key).size === 1 && BW_TO_INDEX.has(String(key[0]))) {
    return [BW_TO_INDEX.get(String(key[0])), true, [key[0]], null];
  }
  const distinct = [...new Set(key)].sort((a, b) => b - a);
  if (distinct.length === 2 && BW_TO_INDEX.has(distinct.join("_"))) {
    return [BW_TO_INDEX.get(distinct.join("_")), true, distinct, key];
  }
  return [0, false, key, null];
}

// -------------------------------------------------------------- B826 encoding

// One 9-byte component record. All inputs are
// the ALREADY-SHIFTED dict values b826ComponentRows produced (classes are the
// wire enums, i.e. raw + 1, UL absent = 0).
export function encodeComponent(component, unsupported) {
  const band = Number(component.band);
  if (!(0 < band && band < 512)) {
    throw new Error(`B826 v21 band out of 9-bit range: ${band}`);
  }
  const isNr = component.rat === "NR";
  const dlClass = Number(component.dl_class);
  const ulClass = Number(component.ul_class);
  const dlMimo = mimoIndex(component.dl_mimo);
  const ulMimo = ulClass ? mimoIndex(component.ul_mimo) : 0;
  if (dlMimo > 0x7f) throw new Error(`DL MIMO index ${dlMimo} exceeds B826 field`);
  if (ulMimo > 0x1f) throw new Error(`UL MIMO index ${ulMimo} exceeds B826 field`);

  const head = band | ((isNr ? 1 : 0) << 9) | ((dlClass & 0x1f) << 10) | ((dlMimo & 1) << 15);
  const byte1 = ((dlMimo >> 1) & 0x3f) | ((ulClass & 0x03) << 6);
  const byte2 = ((ulClass >> 2) & 0x07) | ((ulMimo & 0x1f) << 3);
  let byte3 = 0;
  let byte4 = 0;
  let byte5 = 0;

  if (isNr) {
    const scsIdx = SCS_TO_INDEX.get(Number(component.scs));
    if (scsIdx === undefined) throw new Error(`B826 v21 has no SCS index for ${component.scs} kHz`);
    const [dlIdx, dlOk, dlRaw, dlCollapsed] = bwIndex(component.dl_bw);
    const [ulIdx, ulOk] = bwIndex(component.ul_bw);
    if (!dlOk) {
      bumpUnsupported(unsupported, `('DL', ${band}, ${pyTuple(component.dl_bw)})`);
    } else if (dlCollapsed !== null) {
      bumpUnsupported(unsupported, `('DL-collapsed', ${band}, ${pyTuple(dlCollapsed)}, ${pyTuple(dlRaw)})`);
    }
    if (ulClass && !ulOk) {
      bumpUnsupported(unsupported, `('UL', ${band}, ${pyTuple(component.ul_bw)})`);
    }
    byte3 |= (scsIdx & 0x01) << 7;
    byte4 |= (scsIdx >> 1) & 0x03;
    byte4 |= (dlIdx & 0x3f) << 2;
    byte5 |= (dlIdx >> 6) & 0x01;
    byte5 |= (ulIdx & 0x7f) << 1;
  }
  const out = new Uint8Array(9);
  out[0] = head & 0xff;
  out[1] = (head >> 8) & 0xff;
  out[2] = byte1 & 0xff;
  out[3] = byte2 & 0xff;
  out[4] = byte3 & 0xff;
  out[5] = byte4 & 0xff;
  out[6] = byte5 & 0xff;
  // bytes 7-8 stay 0x00 (struct pack's trailing b"\x00\x00")
  return out;
}

// Counter semantics: missing keys start at 0.
function bumpUnsupported(counter, key) {
  counter.set(key, (counter.get(key) ?? 0) + 1);
}

// One combo record: 3 zero bytes, "<H" features ((count & 0xF) << 3),
// 24 reserved zero bytes, then the 9-byte components.
export function encodeCombo(components, unsupported) {
  const count = components.length;
  if (!(1 <= count && count <= 15)) {
    throw new Error(`B826 v21 supports 1..15 components, got ${count}`);
  }
  const comboFeatures = (count & 0x0f) << 3;
  const out = new Uint8Array(29 + count * 9);
  out[3] = comboFeatures & 0xff;
  out[4] = (comboFeatures >> 8) & 0xff;
  let off = 29;
  for (const c of components) {
    out.set(encodeComponent(c, unsupported), off);
    off += 9;
  }
  return out;
}

// Log build: dedup whole combo payloads (byte equality,
// keep-first), then "<HHHHHB" header (VERSION, 0, total, 0, total, source).
function buildB826Log(componentRows, source) {
  const unsupported = new Map();
  const encoded = [];
  const seen = new Set();
  for (const components of componentRows) {
    const raw = encodeCombo(components, unsupported);
    const key = bytesHex(raw);
    if (seen.has(key)) continue;
    seen.add(key);
    encoded.push(raw);
  }
  const total = encoded.length;
  if (total > 0xffff) throw new Error("B826 log item exceeds uint16 combo count");
  // "<HHHHHB": version, reserved=0, total, index=0, num=total, source.
  const header = new Uint8Array(11);
  header[0] = B826_VERSION & 0xff;
  header[1] = 0;
  header[2] = 0;
  header[3] = 0;
  header[4] = total & 0xff;
  header[5] = (total >> 8) & 0xff;
  header[6] = 0;
  header[7] = 0;
  header[8] = total & 0xff;
  header[9] = (total >> 8) & 0xff;
  header[10] = source & 0xff;
  const blob = concatBytes([header, ...encoded]);
  return [blob, unsupported, componentRows.length, total];
}

const bytesHex = (bytes) => {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
};

// Int-tuple string form for the unsupported-counter keys: "(7,)" for a
// single element, "(100, 50)" otherwise (cosmetic — keys never reach a file).
const pyTuple = (values) =>
  values.length === 1 ? `(${values[0]},)` : `(${values.join(", ")})`;

// Project one decoded combo onto the wire
// dicts. Classes shift +1 into the wire enum (UL absent = 0); LTE MIMO falls
// back to [2] per carrier when the row carries none; NR drops the whole combo
// when a component has no resolved CCs, and only CCs with a resolved UL keep
// their UL MIMO/BW entries. Dict FIELD ORDER is load-bearing: the stable dedup
// key below serializes these objects, so the field order above is normative.
export function b826ComponentRows(combos) {
  const rows = [];
  const seen = new Set();
  for (const cb of combos) {
    const comps = [];
    for (const c of cb.lte) {
      const n = Math.max(1, c.dl_mimo.length);
      const ulCcs = c.ul_class < LTE_CLASS_CCS.length ? LTE_CLASS_CCS[c.ul_class] : 1;
      comps.push({
        rat: "LTE", band: c.band,
        dl_class: c.dl_class + 1,
        ul_class: c.has_ul ? c.ul_class + 1 : 0,
        dl_mimo: c.dl_mimo.length ? c.dl_mimo : Array(n).fill(2),
        ul_mimo: c.has_ul ? Array(ulCcs).fill(1) : [],
      });
    }
    for (const c of cb.nr) {
      if (!c.ccs.length) {
        comps.length = 0;
        break;
      }
      const ul = c.ccs.filter((cc) => cc.ul_mimo);
      comps.push({
        rat: "NR", band: c.band,
        dl_class: c.dl_class + 1,
        ul_class: c.has_ul ? c.ul_class + 1 : 0,
        dl_mimo: c.ccs.map((cc) => cc.dl_mimo || 2),
        dl_bw: c.ccs.map((cc) => cc.dl_bw_mhz || 20),
        ul_mimo: c.has_ul && ul.length ? ul.map((cc) => cc.ul_mimo) : [],
        ul_bw: c.has_ul && ul.length ? ul.map((cc) => cc.ul_bw_mhz) : [],
        scs: c.ccs[0].scs_khz,
      });
    }
    if (!comps.length) continue;
    // The same field order is baked into the dicts
    // above, so this stable JSON key collapses exactly the structurally
    // identical rows.
    const key = JSON.stringify(comps);
    if (seen.has(key)) continue;
    seen.add(key);
    rows.push(comps);
  }
  return rows;
}

// Pure encode of one family (no file I/O).
export function buildB826(combos, source, tag = null) {
  bump("buildB826");
  tag = tag || SOURCE_TAGS[source] || `SOURCE${source}`;
  const rows = b826ComponentRows(combos);
  const [blob, unsupported, nIn, nOut] = buildB826Log(rows, source);
  return {
    tag,
    source,
    blob,
    records: nOut,
    inputRows: nIn,
    unsupported: Object.fromEntries(unsupported),
    hex: bytesHex(blob).toUpperCase(),
    sha256: sha256Hex(blob),
    // The "# header / Payload:" text block.
    block(device) {
      return (
        `# 0xB826 v21 ${this.tag} (source=${this.source}) ${device}\n` +
        `# records=${this.records}\n` +
        `Payload: ${this.hex}\n`
      );
    },
  };
}

// Combined text: EN-DC first, then NRCA, then the v21
// RF_NRDC block ONLY when validated mixed FR1/FR2 rows exist. Each block
// already ends in a newline, so joining with "\n" leaves one blank line
// between blocks.
export function buildB826CombinedText(combos, device) {
  const [endc, nrAll] = classify(combos, 1);
  const nrdc = nrAll.filter(
    (row) => row.nr.some((c) => c.band < 257) && row.nr.some((c) => c.band >= 257),
  );
  const nrdcSet = new Set(nrdc);
  const nrca = nrAll.filter((row) => !nrdcSet.has(row));
  const results = [buildB826(endc, SOURCE_ENDC), buildB826(nrca, SOURCE_NRCA)];
  if (nrdc.length) results.push(buildB826(nrdc, SOURCE_NRDC));
  return { text: results.map((r) => r.block(device)).join("\n"), results };
}

// ------------------------------------------------------------------ B0CD v41

// Raised when a normalized LTE row cannot be represented.
export class B0cdError extends Error {
  constructor(message) {
    super(message);
    this.name = "B0cdError";
  }
}

// Antenna index for the descending-sorted MIMO layers (ANT_TO_INDEX lookup).
function b0cdAntennaIndex(layers) {
  const values = [...layers].map(Number).sort((a, b) => b - a);
  const idx = ANT_TO_INDEX.get(values.join("_"));
  if (idx === undefined) {
    throw new B0cdError(`0xB0CD v41 has no antenna enum for LTE MIMO (${values.length === 1 ? `${values[0]},` : values.join(", ")})`);
  }
  return idx;
}

// One 7-byte "<HBBBBB" record.
function b0cdComponent(component) {
  const band = Number(component.band);
  const dlClass = Number(component.dl_class);
  const ulClass = Number(component.ul_class);
  if (!(1 <= band && band <= 0x1ff)) {
    throw new B0cdError(`0xB0CD v41 LTE band is out of range: ${band}`);
  }
  if (!(0 <= dlClass && dlClass < 26)) {
    throw new B0cdError(`0xB0CD v41 DL class is out of range: ${dlClass}`);
  }
  if (ulClass !== LTE_UL_ABSENT && !(0 <= ulClass && ulClass < 26)) {
    throw new B0cdError(`0xB0CD v41 UL class is out of range: ${ulClass}`);
  }
  const dlMimo = b0cdAntennaIndex(component.dl_mimo.length ? component.dl_mimo : [2]);
  let qcomUlClass;
  let ulMimo;
  if (ulClass === LTE_UL_ABSENT) {
    qcomUlClass = 0;
    ulMimo = 0;
  } else {
    if (!(ulClass < LTE_CLASS_CCS.length)) {
      // Unreachable from decoded rows, which pin UL classes to 0..5 or the
      // absent code 6; kept as a defensive check.
      throw new B0cdError(`0xB0CD v41 UL class is out of range: ${ulClass}`);
    }
    qcomUlClass = ulClass + 1;
    ulMimo = b0cdAntennaIndex(Array(LTE_CLASS_CCS[ulClass]).fill(1));
  }
  const out = new Uint8Array(7);
  out[0] = band & 0xff;
  out[1] = (band >> 8) & 0xff;
  out[2] = (dlClass + 1) & 0xff;
  out[3] = qcomUlClass & 0xff;
  out[4] = dlMimo & 0xff;
  out[5] = ulMimo & 0xff;
  out[6] = 0;
  return out;
}

// Headerless v41 payloads from LTE-only
// normalized combinations (NR-bearing rows are skipped). Records dedup
// keep-first on the encoded bytes; packets carry at most 100 records.
export function buildB0cdV41(lteCombos, packetCombos = 100) {
  bump("buildB0cd");
  if (!(1 <= packetCombos && packetCombos <= 0xff)) {
    throw new B0cdError("packet_combos must fit in one byte");
  }
  const records = [];
  const seen = new Set();
  for (const combo of lteCombos) {
    if (combo.nr.length) continue;
    const components = combo.lte.map((c) => b0cdComponent(c));
    if (!components.length) continue;
    if (components.length > 6) {
      throw new B0cdError("0xB0CD v41 supports at most six LTE components per combination");
    }
    const record = new Uint8Array(1 + components.length * 7);
    record[0] = components.length;
    let off = 1;
    for (const c of components) {
      record.set(c, off);
      off += 7;
    }
    const key = bytesHex(record);
    if (seen.has(key)) continue;
    seen.add(key);
    records.push(record);
  }
  const packets = [];
  for (let start = 0; start < records.length; start += packetCombos) {
    const chunk = records.slice(start, start + packetCombos);
    const packet = new Uint8Array(2 + chunk.reduce((n, r) => n + r.length, 0));
    packet[0] = 41;
    packet[1] = chunk.length;
    let off = 2;
    for (const r of chunk) {
      packet.set(r, off);
      off += r.length;
    }
    packets.push(packet);
  }
  return {
    packets,
    records: records.length,
    sha256: sha256Hex(concatBytes(packets)),
  };
}

const concatBytes = (list) => {
  const out = new Uint8Array(list.reduce((n, b) => n + b.length, 0));
  let off = 0;
  for (const b of list) {
    out.set(b, off);
    off += b.length;
  }
  return out;
};

// The v41 payloads as importer-friendly text, no file write
// (BCS omitted, UL MIMO one layer per UL CC, UL-QAM unknown=0).
export function buildB0cdText(lteCombos, device) {
  const result = buildB0cdV41(lteCombos);
  const lines = [
    "# Headerless 0xB0CD v41 LTE capability payloads.",
    `# Device: ${device}`,
    "# Derived from MediaTek DRDI, not captured Qualcomm DIAG data.",
    "# MTK supplies band/class/DL-MIMO; BCS is omitted. UL MIMO is one layer per UL CC and UL-QAM is 0 (unknown).",
    `# records=${result.records}; packets=${result.packets.length}; sha256=${result.sha256}`,
    "",
  ];
  result.packets.forEach((packet, i) => {
    lines.push(`# LTE CA packet ${i + 1}/${result.packets.length}`, `Payload: ${bytesHex(packet).toUpperCase()}`, "");
  });
  return { text: lines.join("\n"), result };
}
