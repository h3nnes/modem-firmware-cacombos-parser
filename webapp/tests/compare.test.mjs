// Unit tests for the card-vs-card comparison logic where it applies to
// card-vs-card: band-token extraction from web-table cells (via bandcolors
// bandSegments canonicals), combo-set extraction (sorted tuples), pair stats
// (CA-only jaccard/recall/precision) and the LTE/NR band presence diff rows.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  bandCanonicals,
  comboSetFromRows,
  pairStats,
  compareCards,
} from "../js/compare.js";

const CARD_A = {
  lte_ca: [
    { "LTE DL": "1A + 3A", "LTE MIMO DL": "2 + 2" },
    { "LTE DL": "42E", "LTE MIMO DL": "4" },
  ],
  nr_ca: [
    { "NR DL": "78A + 41C", "MIMO DL": "4 + 4" },
    { "NR DL": "28A", "MIMO DL": "2" },
    { "NR DL": "41C", "MIMO DL": "4" }, // duplicate combo set with row 0? no: single band
  ],
  endc: [],
  nrdc: [],
};

const CARD_B = {
  lte_ca: [
    { "LTE DL": "3A + 1A", "LTE MIMO DL": "2 + 2" }, // same combo as A row 0 (sorted equal)
    { "LTE DL": "7A", "LTE MIMO DL": "2" },
    { "LTE DL": "1A", "LTE MIMO DL": "2" },
  ],
  nr_ca: [
    { "NR DL": "78A + 41C", "MIMO DL": "4 + 4" },
    { "NR DL": "41A", "MIMO DL": "2" },
  ],
  endc: [],
  nrdc: [],
};

test("bandCanonicals extracts canonical band tokens from a band-column cell", () => {
  assert.deepEqual(bandCanonicals("42E + 7A", "LTE DL"), ["B42", "B7"]);
  assert.deepEqual(bandCanonicals("78A + 41C", "NR DL"), ["n78", "n41"]);
  assert.deepEqual(bandCanonicals("XX + 7A", "LTE DL"), ["B7"]); // unparsable dropped
  assert.deepEqual(bandCanonicals("", "LTE DL"), []);
  assert.deepEqual(bandCanonicals("1A", "MIMO DL"), []); // non-band column: no tokens
  assert.deepEqual(bandCanonicals("B3A", "NR DL"), ["B3"]); // prefixed keeps B
});

test("comboSetFromRows: sorted-tuple combos like compare_ca.py:104-107", () => {
  // Tokens sorted as strings within the row ("tuple(sorted(bands))"), "+"-joined.
  const set = comboSetFromRows(CARD_A.lte_ca, "LTE DL");
  assert.equal(set.size, 2); // {"B1+B3", "B42"}
  assert.ok(set.has("B1+B3"));
  assert.ok(set.has("B42"));
  // Card B row 0 has the same bands in reverse order -> same combo string.
  const setB = comboSetFromRows(CARD_B.lte_ca, "LTE DL");
  assert.ok(setB.has("B1+B3"));
  assert.ok(setB.has("B7"));
  assert.ok(setB.has("B1"));
});

test("pairStats ports compare_ca.py:169-176 (CA-only intersection/jaccard/recall/precision)", () => {
  const a = comboSetFromRows(CARD_A.lte_ca, "LTE DL"); // {"B1+B3","B42"}
  const b = comboSetFromRows(CARD_B.lte_ca, "LTE DL"); // {"B1+B3","B7","B1"}
  const stats = pairStats(a, b);
  // CA-only (len>1): A={"B1+B3"}, B={"B1+B3"} -> inter=1, union=1
  assert.equal(stats.inter, 1);
  assert.equal(stats.jaccard, 1);
  assert.equal(stats.recall, 1); // A is the reference
  assert.equal(stats.precision, 1);
  // No CA combos at all -> all zeros.
  const empty = pairStats(comboSetFromRows([], "LTE DL"), comboSetFromRows([{ "LTE DL": "1A" }], "LTE DL"));
  assert.deepEqual(empty, { inter: 0, jaccard: 0, recall: 0, precision: 0 });
});

test("compareCards: LTE/NR presence diff rows + per-pair stats", () => {
  const result = compareCards([
    { label: "cardA", tables: CARD_A },
    { label: "cardB", tables: CARD_B },
  ]);
  assert.equal(result.length, 2);
  const lte = result[0];
  assert.equal(lte.kind, "LTE");
  assert.equal(lte.bandHeader, "LTE DL");
  // Union of canonical bands, sorted numerically per band: B1, B3, B7, B42
  assert.deepEqual(lte.bands, ["B1", "B3", "B7", "B42"]);
  assert.deepEqual(lte.presence["B1"], [true, true]);
  assert.deepEqual(lte.presence["B3"], [true, true]);
  assert.deepEqual(lte.presence["B7"], [false, true]);
  assert.deepEqual(lte.presence["B42"], [true, false]);
  const nr = result[1];
  assert.equal(nr.kind, "NR");
  assert.equal(nr.bandHeader, "NR DL");
  assert.deepEqual(nr.bands, ["n28", "n41", "n78"]);
  assert.deepEqual(nr.presence["n78"], [true, true]);
  assert.deepEqual(nr.presence["n28"], [true, false]);
  assert.deepEqual(nr.presence["n41"], [true, true]);
  // Pair stats live on each kind entry (reference = first card).
  // A CA-only = {"n41+n78"}; B CA-only = {"n41+n78"} -> full overlap.
  assert.deepEqual(nr.stats, [{ a: "cardA", b: "cardB", inter: 1, jaccard: 1, recall: 1, precision: 1 }]);
});

test("compareCards: empty tables yield empty sections without crashing", () => {
  const result = compareCards([{ label: "x", tables: { lte_ca: [], nr_ca: [], endc: [], nrdc: [] } }]);
  assert.deepEqual(result[0].bands, []);
  assert.deepEqual(result[0].presence, {});
  assert.deepEqual(result[0].stats, []);
});
