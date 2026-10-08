// Unit tests for the exporter filename builder and the plain download()
// helper's blob/revoke plumbing (DOM part is browser-only).
import { test } from "node:test";
import assert from "node:assert/strict";
import { csvFilename, TAB_LABELS } from "../js/exporter.js";

test("csvFilename mirrors viewer.py export_current_tab_csv defaults", () => {
  // identity present: rf_config_<identity>_<label lower>.csv
  assert.equal(csvFilename("1426_0_0_0170", "LTE"), "rf_config_1426_0_0_0170_lte.csv");
  assert.equal(csvFilename("1426_0_0_0170", "NRCA"), "rf_config_1426_0_0_0170_nrca.csv");
  assert.equal(csvFilename("615_0_0", "ENDC"), "rf_config_615_0_0_endc.csv");
  assert.equal(csvFilename("1426_0_0_0170", "NRDC"), "rf_config_1426_0_0_0170_nrdc.csv");
  // no identity: <label lower>_combos.csv
  assert.equal(csvFilename(null, "LTE"), "lte_combos.csv");
  assert.equal(csvFilename("", "NRCA"), "nrca_combos.csv");
  assert.equal(csvFilename(undefined, "ENDC"), "endc_combos.csv");
});

test("TAB_LABELS map table keys to viewer tab labels", () => {
  assert.deepEqual(TAB_LABELS, { lte_ca: "LTE", nr_ca: "NRCA", endc: "ENDC", nrdc: "NRDC" });
});
