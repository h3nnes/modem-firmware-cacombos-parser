// Differential test: viewer.js band/column sort keys vs the Tk viewer's real
// _band_sort_key/_column_sort_key. The in-repo probe script bandsort_ref.py
// execs the viewer code verbatim and prints sort keys plus
// fully sorted (forward + reversed, stability-sensitive) orders; this test
// spawns it and pins the JS port to the exact same output.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { bandSortKey, columnSortKey, compareKeys, sortRows } from "../js/viewer.js";

function runProbe() {
  const res = spawnSync("python3", [new URL("./bandsort_ref.py", import.meta.url).pathname], {
    encoding: "utf8",
  });
  if (res.error || res.status !== 0) return null;
  const line = res.stdout.split("\n").find((l) => l.startsWith("VIEWER_SORT = "));
  if (!line) return null;
  return JSON.parse(line.slice("VIEWER_SORT = ".length));
}

test("bandSortKey unit cases (port of viewer.py _band_sort_key)", () => {
  assert.deepEqual(bandSortKey("8A"), [0, [[8, "A"]]]);
  assert.deepEqual(bandSortKey("8A + 11A"), [0, [[8, "A"], [11, "A"]]]); // numeric: 8 < 11
  assert.deepEqual(bandSortKey("8C + 8A"), [0, [[8, "C"], [8, "A"]]]); // letter tie-break, not re-sorted
  assert.deepEqual(bandSortKey("1"), [0, [[1, ""]]]);
  assert.deepEqual(bandSortKey("1 + 2 + 3"), [0, [[1, ""], [2, ""], [3, ""]]]);
  // Any unparsable token -> (1, cell): B-prefixed "B3A" is NOT band-sortable.
  assert.deepEqual(bandSortKey("B3A"), [1, "B3A"]);
  assert.deepEqual(bandSortKey("n78"), [1, "n78"]);
  assert.deepEqual(bandSortKey(""), [1, ""]);
  assert.deepEqual(bandSortKey("42e"), [1, "42e"]); // lowercase letter rejected
  assert.deepEqual(bandSortKey(" 42E"), [1, " 42E"]); // leading space rejected
  assert.deepEqual(bandSortKey("8-"), [1, "8-"]);
  assert.deepEqual(bandSortKey("x + 1A"), [1, "x + 1A"]);
  assert.deepEqual(bandSortKey("999Z"), [0, [[999, "Z"]]]); // digits + one letter A-Z
  assert.deepEqual(bandSortKey("0007A"), [0, [[7, "A"]]]); // int() semantics
  assert.deepEqual(bandSortKey("٠٧A"), [0, [[7, "A"]]]); // Python int() reads Nd digits
  assert.deepEqual(bandSortKey("+5"), [1, "+5"]); // plain regex has no sign
});

test("compareKeys implements Python tuple comparison over the key shapes", () => {
  // kind decides first: parsable bands (0) before unparsable (1)
  assert.equal(compareKeys([0, [[1, ""]]], [1, "x"]), -1);
  assert.equal(compareKeys([1, "abc"], [0, [[1, ""]]]), 1);
  // positional pair compare, prefix-equal -> shorter tuple is smaller
  assert.deepEqual(bandSortKey("1A + 1A"), [0, [[1, "A"], [1, "A"]]]);
  assert.equal(compareKeys(bandSortKey("8A"), bandSortKey("11A")), -1); // 8 < 11 numerically
  assert.equal(compareKeys(bandSortKey("8A"), bandSortKey("8C")), -1);
  assert.equal(compareKeys(bandSortKey("1"), bandSortKey("1A")), -1); // (1,"") < (1,"A")
  assert.equal(compareKeys(bandSortKey("1 + 2"), bandSortKey("1 + 2 + 3")), -1);
  assert.equal(compareKeys(bandSortKey("1 + 2 + 3"), bandSortKey("1 + 2")), 1);
  assert.equal(compareKeys(bandSortKey("1A"), bandSortKey("1A")), 0);
  // non-band numeric-else-string keys
  assert.equal(compareKeys([0, 256], [0, 64]), 1);
  assert.equal(compareKeys([1, "abc"], [1, "abd"]), -1);
});

test("columnSortKey: band columns use bandSortKey, others numeric-else-string", () => {
  assert.deepEqual(columnSortKey("LTE DL")({ "LTE DL": "8A" }), [0, [[8, "A"]]]);
  assert.deepEqual(columnSortKey("NR DL")({ "NR DL": "n78" }), [1, "n78"]);
  assert.deepEqual(columnSortKey("MIMO DL")({ "MIMO DL": "4" }), [0, 4]);
  assert.deepEqual(columnSortKey("MIMO DL")({ "MIMO DL": "1 + 4" }), [1, "1 + 4"]);
  assert.deepEqual(columnSortKey("BCS")({ BCS: "All" }), [1, "All"]);
  assert.deepEqual(columnSortKey("DL (QAM)")({ "DL (QAM)": "256" }), [0, 256]);
  // missing key: str(r.get(col, "")) == ""
  assert.deepEqual(columnSortKey("MIMO DL")({}), [1, ""]);
  // Python int() whitespace/sign/Nd semantics
  assert.deepEqual(columnSortKey("NonNumeric")({ NonNumeric: " 5 " }), [0, 5]);
  assert.deepEqual(columnSortKey("NonNumeric")({ NonNumeric: "+5" }), [0, 5]);
  assert.deepEqual(columnSortKey("NonNumeric")({ NonNumeric: "-5" }), [0, -5]);
  assert.deepEqual(columnSortKey("NonNumeric")({ NonNumeric: "007" }), [0, 7]);
  assert.deepEqual(columnSortKey("NonNumeric")({ NonNumeric: "٢٥٦" }), [0, 256]);
  assert.deepEqual(columnSortKey("NonNumeric")({ NonNumeric: "5.0" }), [1, "5.0"]);
  assert.deepEqual(columnSortKey("NonNumeric")({ NonNumeric: "1_0" }), [0, 10]); // PEP 515 separators
  assert.deepEqual(columnSortKey("NonNumeric")({ NonNumeric: "_1" }), [1, "_1"]);
  assert.deepEqual(columnSortKey("NonNumeric")({ NonNumeric: "1_" }), [1, "1_"]);
  assert.deepEqual(columnSortKey("NonNumeric")({ NonNumeric: "5\n" }), [0, 5]);
});

test("sortRows: sorted orders match Python sorted(key=..., reverse=...) incl. stability", () => {
  // "LTE DL" is a band column: keys are band tuples.
  const rows = [{ "LTE DL": "11A" }, { "LTE DL": "8A" }, { "LTE DL": "8A" }, { "LTE DL": "B3A" }, { "LTE DL": "8C" }];
  // forward: 8A, 8A, 8C, 11A, B3A — duplicates keep original order
  assert.deepEqual(sortRows(rows, "LTE DL").map((r) => r["LTE DL"]), ["8A", "8A", "8C", "11A", "B3A"]);
  // reverse=True is a reversed comparison, NOT a reversed list: equal keys
  // keep their original relative order (8A, 8A stay in place).
  assert.deepEqual(sortRows(rows, "LTE DL", true).map((r) => r["LTE DL"]), ["B3A", "11A", "8C", "8A", "8A"]);
  assert.deepEqual(sortRows([{ "LTE DL": "2" }, { "LTE DL": "10" }], "LTE DL").map((r) => r["LTE DL"]), ["2", "10"]);
  // non-band column: numeric-else-string
  assert.deepEqual(sortRows([{ v: "abc" }, { v: "2" }], "v").map((r) => r.v), ["2", "abc"]);
  // sortRows does not mutate its input
  assert.deepEqual(rows.map((r) => r["LTE DL"]), ["11A", "8A", "8A", "B3A", "8C"]);
});

test("differential: sort keys + sorted orders match viewer.py exactly", (t) => {
  const probe = runProbe();
  if (!probe) return t.skip("python3 probe unavailable");
  for (const [i, cell] of probe.BAND_CELLS.entries()) {
    assert.deepEqual(bandSortKey(cell), probe.BAND_KEYS[i], `bandSortKey(${JSON.stringify(cell)})`);
  }
  for (const caseDef of probe.COL_CASES) {
    const col = caseDef.col;
    const key = columnSortKey(col);
    const rows = caseDef.values.map((v) => ({ [col]: v }));
    for (const [i, row] of rows.entries()) {
      assert.deepEqual(key(row), caseDef.keys[i], `columnSortKey(${col})(${JSON.stringify(caseDef.values[i])})`);
    }
    assert.deepEqual(sortRows(rows, col).map((r) => r[col]), caseDef.sorted, `sortRows ${col}`);
    assert.deepEqual(sortRows(rows, col, true).map((r) => r[col]), caseDef.sorted_reverse, `sortRows ${col} reverse`);
  }
});
