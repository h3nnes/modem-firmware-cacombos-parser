// Stage-C viewer tables for MTK DRDI cards: the reference viewer's 5-key
// envelope {lte_ca, nr_sa, nr_ca, endc, nrdc} (tab order LTE, NR SA, NRCA,
// EN-DC, NRDC). The 4-key subset stays valid for qcom/apple cards; nr_sa is
// present only for MediaTek cards, and cardcache.isValidTablesShape validates
// it as an optional key.
//
// Row schema (reference build_tables, cell-for-cell): rows are grouped per
// COMBO by the presentation family — LTE-only (row-table rows and any
// LTE-only capability combo) -> lte_ca; FR1∧FR2 mix -> nrdc; exactly one
// physical NR CC -> nr_sa; otherwise nr_ca; LTE+NR -> endc. Components are
// sorted descending by band then class (Qualcomm presentation order, stable
// sort), tokens are `<band><class-letter>` (A..Z, out-of-range "[n]"), and
// every list joins with " + ". UL columns keep only the carriers that have an
// uplink (an absent UL simply does not contribute a cell). Per-CC values
// flatten each carrier's CCs into one " + "-joined list; null renders "?".
// Across lteRows + nrRows, structurally identical combos are deduped
// (keep-first) via comboKey. Every value is a display string.
import { comboKey } from "./mtk_universal.js";

export const FAMILY_KEYS = { LTE: "lte_ca", "NR SA (1CC)": "nr_sa", "NR-CA": "nr_ca", "EN-DC": "endc", NRDC: "nrdc" };

// main.py _class_name: letters for the observed range, [n] beyond.
const classLabel = (v) => (v >= 0 && v < 26 ? String.fromCharCode(65 + v) : `[${v}]`);

// FR1/FR2 presentation boundary of guiFamilyCounts (nrdc split).
const FR2_MIN_BAND = 257;

function familyFor(combo) {
  if (combo.lte.length) return combo.nr.length ? "EN-DC" : "LTE";
  if (!combo.nr.length) return null;
  if (combo.nr.some((c) => c.band < FR2_MIN_BAND) && combo.nr.some((c) => c.band >= FR2_MIN_BAND)) return "NRDC";
  return combo.nr_physical_ccs === 1 ? "NR SA (1CC)" : "NR-CA";
}

// Qualcomm presentation: descending band/class order (stable sort).
function ordered(components, ul = false) {
  return components
    .filter((c) => !ul || c.has_ul)
    .sort((a, b) => b.band - a.band || (ul ? b.ul_class - a.ul_class : b.dl_class - a.dl_class));
}

const bands = (components, ul = false) =>
  components.map((c) => `${c.band}${classLabel(ul ? c.ul_class : c.dl_class)}`).join(" + ");
const values = (vals) => vals.map((v) => (v === null || v === undefined ? "?" : String(v))).join(" + ");

function nrValues(components, field, ul = false) {
  const out = [];
  for (const c of components) for (const cc of c.ccs) if (!ul || cc.ul_mimo !== null) out.push(cc[field]);
  return values(out);
}

function nrColumns(dl, ul, prefix = "") {
  return {
    [`${prefix}MIMO DL`]: nrValues(dl, "dl_mimo"),
    [`${prefix}SCS DL (kHz)`]: nrValues(dl, "scs_khz"),
    [`${prefix}BW DL (MHz)`]: nrValues(dl, "dl_bw_mhz"),
    [`${prefix}MIMO UL`]: nrValues(ul, "ul_mimo", true),
    [`${prefix}SCS UL (kHz)`]: nrValues(ul, "scs_khz", true),
    [`${prefix}BW UL (MHz)`]: nrValues(ul, "ul_bw_mhz", true),
  };
}

// Viewer tables for one card: `combos` are the profile's decoded capability
// (or Tensor secondary) rows, `lteRows` its LTE CA row-table rows. Columns are
// only what the MTK decoder supplies (no LTE BW/SCS/UL MIMO, QAM, BCS or UL TX
// switch).
export function generateMtkTables(combos, lteRows = []) {
  const tables = { lte_ca: [], nr_sa: [], nr_ca: [], endc: [], nrdc: [] };
  const seen = new Set();
  for (const rows of [lteRows, combos]) {
    for (const combo of rows) {
      const family = familyFor(combo);
      const key = comboKey(combo);
      if (family === null || seen.has(key)) continue;
      seen.add(key);
      const lteDl = ordered(combo.lte);
      const lteUl = ordered(combo.lte, true);
      const nrDl = ordered(combo.nr);
      const nrUl = ordered(combo.nr, true);
      const lteMimo = values(lteDl.flatMap((c) => c.dl_mimo));
      let row;
      if (family === "LTE") {
        row = { "LTE DL": bands(lteDl), "MIMO DL": lteMimo, "LTE UL": bands(lteUl, true) };
      } else if (family === "EN-DC") {
        const f = nrColumns(nrDl, nrUl, "NR ");
        row = {
          "LTE DL": bands(lteDl), "LTE MIMO DL": lteMimo,
          "NR DL": bands(nrDl), "NR MIMO DL": f["NR MIMO DL"],
          "NR SCS DL (kHz)": f["NR SCS DL (kHz)"], "NR BW DL (MHz)": f["NR BW DL (MHz)"],
          "LTE UL": bands(lteUl, true), "NR UL": bands(nrUl, true),
          "NR MIMO UL": f["NR MIMO UL"], "NR SCS UL (kHz)": f["NR SCS UL (kHz)"], "NR BW UL (MHz)": f["NR BW UL (MHz)"],
        };
      } else if (family === "NRDC") {
        row = {};
        const groups = {};
        for (const fr of ["FR1", "FR2"]) {
          groups[fr] = [nrDl.filter((c) => (c.band < FR2_MIN_BAND) === (fr === "FR1")), nrUl.filter((c) => (c.band < FR2_MIN_BAND) === (fr === "FR1"))];
        }
        for (const direction of ["DL", "UL"]) {
          for (const fr of ["FR1", "FR2"]) {
            const [dl, ul] = groups[fr];
            const f = nrColumns(dl, ul, `${fr} `);
            row[`${fr} ${direction}`] = bands(direction === "UL" ? ul : dl, direction === "UL");
            for (const feature of ["MIMO", "SCS", "BW"]) {
              const name = `${fr} ${feature} ${direction}${feature === "SCS" ? " (kHz)" : feature === "BW" ? " (MHz)" : ""}`;
              row[name] = f[name];
            }
          }
        }
      } else {
        const f = nrColumns(nrDl, nrUl);
        row = { "NR DL": bands(nrDl) };
        for (const [name, value] of Object.entries(f)) if (name.includes(" DL")) row[name] = value;
        row["NR UL"] = bands(nrUl, true);
        for (const [name, value] of Object.entries(f)) if (name.includes(" UL")) row[name] = value;
      }
      tables[FAMILY_KEYS[family]].push(row);
    }
  }
  return tables;
}
