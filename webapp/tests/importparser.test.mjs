// Unit tests for the uecaps.hennes.xyz import helpers (pure logic only).
// DOM/fetch wiring lives in main.js and is verified by the suite + manual pass
// (no browser harness exists on this machine — established precedent).
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildImportEntries, resultUrl } from "../js/importparser.js";

const B0CD = "# rf_config_1426_0_0_0170.mbn [LTE] b0cd_v41\nPayload: 0011aa\n\n";
const B826 = "# rf_config_1426_0_0_0170.mbn [NR] b826_v22\nPayload: 0022bb\n\n";
const NAME = "rf_config_1426_0_0_0170.mbn";

test("buildImportEntries: both packet sets -> QLTE+QNR entries with dense indexes", () => {
  const { entries, files } = buildImportEntries(B0CD, B826, NAME);
  assert.deepEqual(entries, [
    { inputIndexes: [0], type: "QLTE", description: NAME },
    { inputIndexes: [1], type: "QNR", description: NAME },
  ]);
  assert.deepEqual(files, [
    { filename: `${NAME}.b0cd.txt`, text: B0CD },
    { filename: `${NAME}.b826.txt`, text: B826 },
  ]);
});

test("buildImportEntries: b0cd only -> single QLTE entry, index 0", () => {
  const { entries, files } = buildImportEntries(B0CD, "", NAME);
  assert.deepEqual(entries, [{ inputIndexes: [0], type: "QLTE", description: NAME }]);
  assert.equal(files.length, 1);
  assert.equal(files[0].filename, `${NAME}.b0cd.txt`);
});

test("buildImportEntries: b826 only -> single QNR entry, index 0 (dense)", () => {
  const { entries, files } = buildImportEntries("", B826, NAME);
  assert.deepEqual(entries, [{ inputIndexes: [0], type: "QNR", description: NAME }]);
  assert.equal(files.length, 1);
  assert.equal(files[0].filename, `${NAME}.b826.txt`);
});

test("buildImportEntries: whitespace-only text counts as empty", () => {
  const { entries } = buildImportEntries("   \n", B826, NAME);
  assert.deepEqual(entries, [{ inputIndexes: [0], type: "QNR", description: NAME }]);
});

test("buildImportEntries: both empty -> throws 'No DIAG packets to import'", () => {
  assert.throws(() => buildImportEntries("", "", NAME), /No DIAG packets to import/);
  assert.throws(() => buildImportEntries(undefined, null, NAME), /No DIAG packets to import/);
});

test("buildImportEntries: description passes through as-is", () => {
  const { entries } = buildImportEntries(B0CD, B826, "  keep  me.mbn ");
  assert.equal(entries[0].description, "  keep  me.mbn ");
  assert.equal(entries[1].description, "  keep  me.mbn ");
});

// MTK DRDI cards (Stage D): the reconstructed trace texts upload as types
// MNR ("MEDIATEK NR Trace Log") and M ("MEDIATEK CA_COMB_INFO") — the server's
// LogType.kt spells both; RequestMultiPart carries type + inputIndexes exactly
// like the QLTE/QNR entries.
const MNR = "# Reconstructed from MediaTek firmware; not a captured modem log.\n[CAP] FSC[1], D/U[N1/N1]\n";
const M = "MSG_ID_ERRC_RCM_UE_PRE_CA_COMB_INFO\nbandwidth_comb_set = Array[1]\n";

test("buildImportEntries: MTK trace texts -> MNR+M entries with dense indexes", () => {
  const { entries, files } = buildImportEntries("", "", NAME, MNR, M);
  assert.deepEqual(entries, [
    { inputIndexes: [0], type: "MNR", description: NAME },
    { inputIndexes: [1], type: "M", description: NAME },
  ]);
  assert.deepEqual(files, [
    { filename: `${NAME}.mtk_nr.txt`, text: MNR },
    { filename: `${NAME}.mtk_lte.txt`, text: M },
  ]);
});

test("buildImportEntries: mtk_nr only -> single MNR entry, index 0 (dense)", () => {
  const { entries, files } = buildImportEntries("", "", NAME, MNR, "");
  assert.deepEqual(entries, [{ inputIndexes: [0], type: "MNR", description: NAME }]);
  assert.equal(files.length, 1);
  assert.equal(files[0].filename, `${NAME}.mtk_nr.txt`);
});

test("buildImportEntries: mtk_lte only -> single M entry, index 0 (dense)", () => {
  const { entries, files } = buildImportEntries(undefined, null, NAME, "", M);
  assert.deepEqual(entries, [{ inputIndexes: [0], type: "M", description: NAME }]);
  assert.equal(files[0].filename, `${NAME}.mtk_lte.txt`);
});

test("buildImportEntries: mixed qcom + MTK texts keep the QLTE,QNR,MNR,M order", () => {
  const { entries, files } = buildImportEntries(B0CD, B826, NAME, MNR, M);
  assert.deepEqual(entries.map((e) => e.type), ["QLTE", "QNR", "MNR", "M"]);
  assert.deepEqual(entries.map((e) => e.inputIndexes), [[0], [1], [2], [3]]);
  assert.deepEqual(files.map((f) => f.filename), [
    `${NAME}.b0cd.txt`,
    `${NAME}.b826.txt`,
    `${NAME}.mtk_nr.txt`,
    `${NAME}.mtk_lte.txt`,
  ]);
});

test("buildImportEntries: all four empty -> throws covering the MTK arms too", () => {
  assert.throws(() => buildImportEntries("", "", NAME, "", ""), /No DIAG packets to import/);
});

test("resultUrl: /view/multi/?id= with the id query-encoded", () => {
  assert.equal(
    resultUrl("550e8400-e29b-41d4-a716-446655440000"),
    "https://uecaps.hennes.xyz/view/multi/?id=550e8400-e29b-41d4-a716-446655440000"
  );
  assert.equal(resultUrl("a b&c"), "https://uecaps.hennes.xyz/view/multi/?id=a%20b%26c");
});
