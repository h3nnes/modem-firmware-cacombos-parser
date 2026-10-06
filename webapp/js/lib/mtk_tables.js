// Stage-C viewer tables for MTK DRDI cards (design spec §4): the same 4-key
// envelope the qcom/apple paths produce — {lte_ca, nr_ca, endc, nrdc} — so the
// existing ComboViewer, compare view and worker-side card cache work unchanged
// (cardcache.isValidTablesShape hard-requires exactly these four array keys;
// the viewer is schema-generic and takes its columns from the row keys).
//
// Row schemas (spec §4, one row per decoded combo in decode order — python's
// export path does NOT sort, and the per-profile inputs are already deduped by
// dedupExact, so nothing is re-sorted or re-deduped here):
// - LTE CA (the profile's invariant-valid LTE CA row-table rows):
//   `Band | DL class | UL class | MIMO DL`, parallel per-component lists.
// - EN-DC: `LTE DL | NR DL | MIMO DL | SCS | BW DL (MHz)`; MIMO/SCS/BW are the
//   NR side's per-CC values (LTE carriers carry no SCS in the MTK decode).
// - NR-CA: `NR DL | SCS | BW DL (MHz) | MIMO DL | MIMO UL` per CC.
// - NR-DC: same per-CC columns with the FR1/FR2 band split (`FR1 DL`/`FR2 DL`),
//   matching the apple NRDC layout. NR-DC rows exist only when one combo really
//   mixes band <257 with band >=257 (guiFamilyCounts' presentation split).
//
// Cell rendering follows the apple table conventions so the viewer's band
// coloring, numeric sort and copy menu behave: band columns carry
// `<band><class-letter>` tokens ("1A", "78C"), per-CC values join with "+"
// within a component and components with " + ", unresolved values render "?",
// and an absent LTE uplink (ul_class == LTE_UL_ABSENT) renders the em dash.
// Every value is a display string. Grammar-classified LTE-only combos are
// dropped, exactly like every python export path (classify's third bucket is
// never rendered; the LTE CA tab shows the dedicated row-table rows).
import { classify } from "./mtk_universal.js";

// mtk_export.py CLASS_LETTERS; main.py _class_name spells out-of-range
// classes as "class<n>" instead of failing the whole table.
const CLASS_LETTERS = "ABCDEFGHIJKL";

// FR1/FR2 presentation boundary of guiFamilyCounts/mtk_trace (nrdc split).
const FR2_MIN_BAND = 257;

const classLetter = (v) => (v >= 0 && v < CLASS_LETTERS.length ? CLASS_LETTERS[v] : `class${v}`);

const lteToken = (c) => `${c.band}${classLetter(c.dl_class)}`;
const nrToken = lteToken;
const lteUlCell = (c) => (c.has_ul ? classLetter(c.ul_class) : "—");

// per-CC text (_per_cc_text convention): "+"-joined per component, "?" for
// anything the decode left unresolved (NR UL MIMO/BW are null without UL).
const perCcText = (values) => values.map((v) => (v == null ? "?" : String(v))).join("+");

const joinCc = (comps, pick) => comps.map((c) => perCcText(c.ccs.map(pick))).join(" + ");

const nrPerCcCells = (comps) => ({
  SCS: joinCc(comps, (cc) => cc.scs_khz),
  "BW DL (MHz)": joinCc(comps, (cc) => cc.dl_bw_mhz),
  "MIMO DL": joinCc(comps, (cc) => cc.dl_mimo),
  "MIMO UL": joinCc(comps, (cc) => cc.ul_mimo),
});

// Viewer tables for one card: `combos` are the profile's decoded capability
// (or Tensor secondary) rows, `lteRows` its LTE CA row-table rows.
export function generateMtkTables(combos, lteRows = []) {
  const [endc, nr] = classify(combos, 1);
  const mixed = nr.filter(
    (row) => row.nr.some((c) => c.band < FR2_MIN_BAND) && row.nr.some((c) => c.band >= FR2_MIN_BAND),
  );
  const mixedSet = new Set(mixed);
  const nrca = nr.filter((row) => !mixedSet.has(row));

  const lteCa = lteRows.map((cb) => ({
    Band: cb.lte.map((c) => String(c.band)).join(" + "),
    "DL class": cb.lte.map((c) => classLetter(c.dl_class)).join(" + "),
    "UL class": cb.lte.map(lteUlCell).join(" + "),
    "MIMO DL": cb.lte.map((c) => c.dl_mimo.map(String).join("+")).join(" + "),
  }));
  const nrCa = nrca.map((cb) => ({
    "NR DL": cb.nr.map(nrToken).join(" + "),
    ...nrPerCcCells(cb.nr),
  }));
  const endcRows = endc.map((cb) => ({
    "LTE DL": cb.lte.map(lteToken).join(" + "),
    "NR DL": cb.nr.map(nrToken).join(" + "),
    // EN-DC carries one NR triplet per row (spec §4): DL MIMO, SCS and DL
    // bandwidth of the NR side's physical carriers.
    "MIMO DL": joinCc(cb.nr, (cc) => cc.dl_mimo),
    SCS: joinCc(cb.nr, (cc) => cc.scs_khz),
    "BW DL (MHz)": joinCc(cb.nr, (cc) => cc.dl_bw_mhz),
  }));
  const nrdcRows = mixed.map((cb) => ({
    "FR1 DL": cb.nr.filter((c) => c.band < FR2_MIN_BAND).map(nrToken).join(" + "),
    "FR2 DL": cb.nr.filter((c) => c.band >= FR2_MIN_BAND).map(nrToken).join(" + "),
    ...nrPerCcCells(cb.nr),
  }));

  return { lte_ca: lteCa, nr_ca: nrCa, endc: endcRows, nrdc: nrdcRows };
}
