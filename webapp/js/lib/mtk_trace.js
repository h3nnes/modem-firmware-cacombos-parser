// Stage-D text exports for MTK DRDI cards: a text-exact port of the python
// reference's mtk_trace.py — the two reconstructed capability logs the
// uecaps parser's MNR (ImportMtkNr) and M (ImportMTKLte) importers consume.
// These are reconstructed records, not captured runtime traces: IDs belong to
// each output file and reference the normalized firmware features.
//
// Byte-exactness contract (spec §5, differential-tested against
// webapp/goldens/mtk/diag.json): feature/FS registration happens DURING the
// per-combo walk, i.e. even a combo the trailing dedup key skips has already
// registered its features (a no-op for output, but it pins the order in which
// lines are appended). FSC indices are 1-based over the dedup key set, so the
// CA block labels them idx-1. TraceError messages are part of the contract
// (spec §6) and are reproduced verbatim.
import { bump } from "./debug.js";

export class TraceError extends Error {
  constructor(message) {
    super(message);
    this.name = "TraceError";
  }
}

// EUTRA UL carrier counts per bandwidth class (mtk_trace.py LTE_WEIGHTS).
const LTE_WEIGHTS = [1, 2, 2, 3, 4, 5];
const LAYERS = { 1: "ONE", 2: "TWO", 4: "FOUR", 8: "EIGHT" };

function layer(value) {
  if (value === null || value === undefined) return "UNKNOWN";
  if (!(value in LAYERS)) throw new TraceError(`unsupported MIMO layer count: ${value}`);
  return LAYERS[value] + "_LAYERS";
}

function classLetter(value) {
  if (!(0 <= value && value < 26)) {
    throw new TraceError(`MTK trace importer requires a single-letter class; got ${value}`);
  }
  return String.fromCharCode(65 + value);
}

// mtk_trace.py _header: the three lines every MTK trace file starts with.
function header(device) {
  return [
    "# Reconstructed from MediaTek firmware; not a captured modem log.",
    "# Device: " + String(device).replaceAll("\n", " ").replaceAll("\r", " "),
    "# Modulation is unknown. LTE UL MIMO uses one layer per configured carrier.",
  ];
}

const FR2_MIN_BAND = 257;
const NR_SCS_KHZ = [15, 30, 60, 120];

// mtk_trace.py render_nr_trace: ordered NR DL/UL per-CC bandwidth, SCS, MIMO
// and classes. Returns { text, meta }.
export function renderNrTrace(combos, device) {
  bump("renderMtkNrTrace");
  const lines = header(device);
  const features = new Map(); // (rat, direction) -> Map<key, idx>
  const sets = new Map(); // (rat, direction) -> Map<ids key, idx>
  const bodies = [];
  const seen = new Set();
  const families = new Map();

  const feature = (rat, direction, scs, bw, mimo) => {
    if (rat === "N" && !NR_SCS_KHZ.includes(scs)) {
      // ImportMtkNr silently maps any other SCS string to 15 kHz.
      throw new TraceError(`MTK NR importer cannot represent SCS ${scs} kHz`);
    }
    const nsKey = `${rat}/${direction}`;
    let table = features.get(nsKey);
    if (!table) {
      table = new Map();
      features.set(nsKey, table);
    }
    const key = `${scs}|${bw}|${mimo}`;
    if (!table.has(key)) {
      const idx = table.size + 1;
      table.set(key, idx);
      if (rat === "N") {
        if (bw !== null && bw !== undefined && (!Number.isInteger(bw) || bw <= 0)) {
          throw new TraceError(`invalid native bandwidth: ${bw}`);
        }
        const field = direction === "DL" ? "mimo" : "cb_mimo";
        lines.push(
          `[CAP] NR ${direction} FSpCC[${idx}], scs[NL1_CAP_SCS_${scs}KHZ], ` +
            `bw[NL1_CAP_BW${bw || 0}], bw90m[NL1_CAP_NOT_SUPPORT], ` +
            `${field}[NL1_CAP_MIMO_${layer(mimo)}], modulation[UNKNOWN]`,
        );
      } else {
        lines.push(`[CAP] EUTRA ${direction} FSpCC[${idx}], mimo[NL1_CAP_MIMO_${layer(mimo)}]`);
      }
    }
    return table.get(key);
  };

  const featureSet = (rat, direction, ids) => {
    if (!ids.length) return "_0";
    // python: (8 if DL else 4) for NR, else 5 EUTRA carriers per FS.
    const limit = rat === "N" ? (direction === "DL" ? 8 : 4) : 5;
    if (ids.length > limit) {
      throw new TraceError(`MTK importer supports at most ${limit} ${rat} ${direction} carriers per FS`);
    }
    const nsKey = `${rat}/${direction}`;
    let table = sets.get(nsKey);
    if (!table) {
      table = new Map();
      sets.set(nsKey, table);
    }
    const key = ids.join("|");
    if (!table.has(key)) {
      const idx = table.size + 1;
      table.set(key, idx);
      const name = rat === "N" ? "NR" : "EUTRA";
      lines.push(
        `[CAP] ${name} ${direction} FS[${idx}], FS${direction}pCC ID` +
          ids.map((i) => `[${i}]`).join(""),
      );
    }
    return `${rat}${table.get(key)}`;
  };

  for (const combo of combos) {
    if (!combo.nr.length) continue;
    const dl = [];
    const ul = [];
    const pairs = [];
    for (const [rat, components] of [["E", combo.lte], ["N", combo.nr]]) {
      for (const component of components) {
        const prefix = rat === "E" ? "B" : "N";
        dl.push(`${prefix}${component.band}${classLetter(component.dl_class)}`);
        ul.push(
          component.has_ul ? `${prefix}${component.band}${classLetter(component.ul_class)}` : "0",
        );
        let dlIds;
        let ulIds;
        if (rat === "E") {
          dlIds = component.dl_mimo.map((m) => feature(rat, "DL", null, null, m));
          ulIds = component.has_ul
            ? Array(LTE_WEIGHTS[component.ul_class]).fill(feature(rat, "UL", null, null, 1))
            : [];
        } else {
          dlIds = component.ccs.map((cc) => feature(rat, "DL", cc.scs_khz, cc.dl_bw_mhz, cc.dl_mimo));
          ulIds = component.ccs
            .filter((cc) => component.has_ul && cc.ul_mimo !== null && cc.ul_mimo !== undefined)
            .map((cc) => feature(rat, "UL", cc.scs_khz, cc.ul_bw_mhz, cc.ul_mimo));
        }
        if (!dlIds.length) throw new TraceError("missing DL per-carrier features");
        pairs.push(`[${featureSet(rat, "DL", dlIds)}/${featureSet(rat, "UL", ulIds)}]`);
      }
    }
    const key = `${dl.join("|")}/${ul.join("|")}/${pairs.join("|")}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const idx = seen.size;
    bodies.push(`[CAP] FSC[${idx}], D/U${pairs.join("")}`);
    bodies.push(
      `[CAP] CA idx [${idx - 1}] NL1 bc, num[${dl.length}] DL: ${dl.join("_")} ` +
        `UL: ${ul.join("_")} FSC[${idx}]`,
    );
    const family = combo.lte.length
      ? "endc"
      : combo.nr.some((c) => c.band < FR2_MIN_BAND) && combo.nr.some((c) => c.band >= FR2_MIN_BAND)
        ? "nrdc"
        : "nrca";
    families.set(family, (families.get(family) ?? 0) + 1);
  }
  const text = [...lines, ...bodies].join("\n") + "\n";
  return {
    text,
    meta: {
      records: seen.size,
      families: Object.fromEntries(families),
      modulation: "unknown",
      unknown_bandwidth: "NL1_CAP_BW0",
    },
  };
}

// mtk_trace.py render_lte_log: the CA_COMB_INFO importer supports one 2/4-layer
// value per component. Returns { text, meta }.
export function renderLteLog(combos, device) {
  bump("renderMtkLteLog");
  const records = [];
  const seen = new Set();
  let mixed = 0;
  for (const combo of combos) {
    if (combo.nr.length || !combo.lte.length) continue;
    const row = [];
    for (const c of combo.lte) {
      if (!(0 <= c.dl_class && c.dl_class < 6 && 0 <= c.ul_class && c.ul_class <= 6)) {
        throw new TraceError("LTE importer requires MTK A..F classes / UL-absent=6");
      }
      if (!c.dl_mimo.length || c.dl_mimo.some((m) => m !== 2 && m !== 4)) {
        throw new TraceError("LTE CA_COMB_INFO importer supports only known 2/4-layer MIMO");
      }
      if (new Set(c.dl_mimo).size > 1) mixed += 1;
      // Do not claim every carrier supports the strongest carrier's MIMO.
      row.push([c.band, c.ul_class, c.dl_class, Math.min(...c.dl_mimo)]);
    }
    const key = JSON.stringify(row);
    if (seen.has(key)) continue;
    seen.add(key);
    records.push(row);
  }
  const lines = [
    ...header(device),
    "# BCS unknown: zero placeholders are required by ImportMTKLte; no BCS support is asserted.",
    "# Mixed per-carrier DL MIMO is projected to the minimum per logical component.",
    "MSG_ID_ERRC_RCM_UE_PRE_CA_COMB_INFO",
    `bandwidth_comb_set = Array[${records.length}]`,
  ];
  for (let i = 0; i < records.length; i++) lines.push(`bandwidth_comb_set[${i}] = 0x0`);
  records.forEach((row, idx) => {
    lines.push(`band_comb[${idx}]`, `band_param_num = ${row.length}`, `band_param = Array[${row.length}]`);
    row.forEach((param, i) => {
      const [band, ul, dlClass] = param;
      lines.push(`band_param[${i}]`, `band = ${band}`, `class_ul = ${ul}`, `class_dl = ${dlClass}`);
    });
    lines.push(`band_mimo = Array[${row.length}]`);
    row.forEach((param, i) => {
      lines.push(`band_mimo[${i}]`, `mimo = ERRC_CAPA_CA_MIMO_CAPA_${layer(param[3])}`);
    });
  });
  const text = lines.join("\n") + "\n";
  return {
    text,
    meta: {
      records: records.length,
      bcs: "unknown; zero placeholder",
      mimo_projection: "minimum per logical component",
      mixed_mimo_components_projected: mixed,
    },
  };
}
