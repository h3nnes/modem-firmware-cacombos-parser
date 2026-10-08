// Card-vs-card comparison for cards imported without a UE-capability CSV —
// band-token extraction from the web-table cells (via bandcolors bandSegments
// canonicals), sorted-tuple combo sets and CA-only
// intersection/jaccard/recall/precision (first card is the reference) — plus
// the LTE/NR band presence diff table the workbench comparison view renders.
import { bandSegments } from "./lib/bandcolors.js";

// Canonical bands ("B42", "n78") present in a band-column cell.
export function bandCanonicals(cell, header) {
  return bandSegments(cell, header)
    .filter((seg) => seg.canonical !== null)
    .map((seg) => seg.canonical);
}

// Set of sorted-tuple combos, serialized "+"-joined.
export function comboSetFromRows(rows, bandHeader) {
  const combos = new Set();
  for (const row of rows) {
    const bands = bandCanonicals(String(row[bandHeader] ?? ""), bandHeader);
    if (bands.length) combos.add(bands.sort().join("+"));
  }
  return combos;
}

// Pair stats against a reference set. Only CA combos (2+ bands) participate.
export function pairStats(setA, setB) {
  const caOnly = (s) => new Set([...s].filter((c) => c.split("+").length > 1));
  const a = caOnly(setA);
  const b = caOnly(setB);
  const inter = new Set([...a].filter((c) => b.has(c)));
  const union = new Set([...a, ...b]);
  return {
    inter: inter.size,
    jaccard: union.size ? inter.size / union.size : 0.0,
    recall: a.size ? inter.size / a.size : 0.0,
    precision: b.size ? inter.size / b.size : 0.0,
  };
}

// Numeric-friendly band order: B bands before n bands, then band number, then
// the bw-class letter (UI presentation choice).
function canonicalSortKey(canonical) {
  const m = /^([Bn])(\d+)([A-Z])?$/.exec(canonical);
  if (!m) return [2, 0, canonical];
  return [m[1] === "B" ? 0 : 1, Number(m[2]), m[3] || ""];
}

const cmpTuple = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function cmpArrays(a, b) {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const order = cmpTuple(a[i], b[i]);
    if (order !== 0) return order;
  }
  return cmpTuple(a.length, b.length);
}

// entries: [{ label, tables }] with tables = {lte_ca, nr_ca, endc, nrdc}.
// Returns one section per kind: union band list, per-card presence flags and
// the pairwise CA-combo stats for every (reference, other) pair.
export function compareCards(entries) {
  const kinds = [
    { kind: "LTE", tableKey: "lte_ca", bandHeader: "LTE DL" },
    { kind: "NR", tableKey: "nr_ca", bandHeader: "NR DL" },
  ];
  const sections = [];
  for (const { kind, tableKey, bandHeader } of kinds) {
    const comboSets = entries.map((entry) => comboSetFromRows(entry.tables && entry.tables[tableKey] ? entry.tables[tableKey] : [], bandHeader));
    const bandSets = entries.map((entry) => {
      const rows = entry.tables && entry.tables[tableKey] ? entry.tables[tableKey] : [];
      const set = new Set();
      for (const row of rows) {
        for (const band of bandCanonicals(String(row[bandHeader] ?? ""), bandHeader)) set.add(band);
      }
      return set;
    });
    const bandSet = new Set();
    for (const set of bandSets) {
      for (const band of set) bandSet.add(band);
    }
    const bands = [...bandSet].sort((x, y) => cmpArrays(canonicalSortKey(x), canonicalSortKey(y)));
    const presence = {};
    for (const band of bands) {
      presence[band] = bandSets.map((set) => set.has(band));
    }
    const stats = [];
    for (let i = 0; i < entries.length; i++) {
      for (let j = i + 1; j < entries.length; j++) {
        const s = pairStats(comboSets[i], comboSets[j]);
        stats.push({ a: entries[i].label, b: entries[j].label, ...s });
      }
    }
    sections.push({ kind, bandHeader, bands, presence, stats });
  }
  return sections;
}
