// MTK Stage-D tests: the reconstructed trace logs (webapp/js/lib/mtk_trace.js).
// Synthetic pins carry python-generated expected texts (mtk-drdi-combo-parser/
// mtk_trace.py on the same fixtures): the shared 3-line header, FSpCC/FS
// registration order
// and dedup, the FS carrier limits (NR DL 8 / UL 4 / EUTRA 5), the 1-based FSC
// indices with the CA block's idx-1 labels, the family tally, and every
// TraceError message. The corpus-gated BYTE differential for both trace
// formats lives in mtk_export.test.mjs so the suite shares one scan per image.
import test from "node:test";
import assert from "node:assert/strict";
import { MtkCombo, LteComponent, NrComponent, NrCC } from "../js/lib/mtk_universal.js";
import { renderNrTrace, renderLteLog, TraceError } from "../js/lib/mtk_trace.js";

const errOf = (fn) => {
  try {
    fn();
    return null;
  } catch (err) {
    return err;
  }
};

// B1A dl / A ul / 4 layers; B3C dl / no UL (class 6) / 2+4 layers.
const lte1 = new LteComponent(1, 0, 0, [4]);
const lte2 = new LteComponent(3, 2, 6, [2, 4]);
// n78A one CC (15 kHz, 4L, 50 MHz, 1L UL); n257B two CCs with absent UL.
const nr1 = new NrComponent(78, 0, 0, [new NrCC(15, 4, 50, 1, 50)]);
const nr2 = new NrComponent(257, 1, 0x1c, [
  new NrCC(120, 2, 100, null, null),
  new NrCC(30, 4, 40, 2, 40),
]);

test("nr trace: FSpCC/FS registration, FSC indices and the CA lines (python-pinned)", () => {
  const endc = new MtkCombo([lte1, lte2], [nr1]);
  const nrca = new MtkCombo([], [nr1]);
  const nrdc = new MtkCombo([], [nr1, nr2]);
  const { text, meta } = renderNrTrace([endc, nrca, nrdc, endc], "device-x");
  // The trailing duplicate endc re-registers only existing feature/FS keys
  // (no new lines) and its body is dropped by the dedup key — records stay 3.
  assert.equal(
    text,
    "# Reconstructed from MediaTek firmware; not a captured modem log.\n"
      + "# Device: device-x\n"
      + "# Modulation is unknown. LTE UL MIMO uses one layer per configured carrier.\n"
      + "[CAP] EUTRA DL FSpCC[1], mimo[NL1_CAP_MIMO_FOUR_LAYERS]\n"
      + "[CAP] EUTRA UL FSpCC[1], mimo[NL1_CAP_MIMO_ONE_LAYERS]\n"
      + "[CAP] EUTRA DL FS[1], FSDLpCC ID[1]\n"
      + "[CAP] EUTRA UL FS[1], FSULpCC ID[1]\n"
      + "[CAP] EUTRA DL FSpCC[2], mimo[NL1_CAP_MIMO_TWO_LAYERS]\n"
      + "[CAP] EUTRA DL FS[2], FSDLpCC ID[2][1]\n"
      + "[CAP] NR DL FSpCC[1], scs[NL1_CAP_SCS_15KHZ], bw[NL1_CAP_BW50], bw90m[NL1_CAP_NOT_SUPPORT], mimo[NL1_CAP_MIMO_FOUR_LAYERS], modulation[UNKNOWN]\n"
      + "[CAP] NR UL FSpCC[1], scs[NL1_CAP_SCS_15KHZ], bw[NL1_CAP_BW50], bw90m[NL1_CAP_NOT_SUPPORT], cb_mimo[NL1_CAP_MIMO_ONE_LAYERS], modulation[UNKNOWN]\n"
      + "[CAP] NR DL FS[1], FSDLpCC ID[1]\n"
      + "[CAP] NR UL FS[1], FSULpCC ID[1]\n"
      + "[CAP] NR DL FSpCC[2], scs[NL1_CAP_SCS_120KHZ], bw[NL1_CAP_BW100], bw90m[NL1_CAP_NOT_SUPPORT], mimo[NL1_CAP_MIMO_TWO_LAYERS], modulation[UNKNOWN]\n"
      + "[CAP] NR DL FSpCC[3], scs[NL1_CAP_SCS_30KHZ], bw[NL1_CAP_BW40], bw90m[NL1_CAP_NOT_SUPPORT], mimo[NL1_CAP_MIMO_FOUR_LAYERS], modulation[UNKNOWN]\n"
      + "[CAP] NR DL FS[2], FSDLpCC ID[2][3]\n"
      + "[CAP] FSC[1], D/U[E1/E1][E2/_0][N1/N1]\n"
      + "[CAP] CA idx [0] NL1 bc, num[3] DL: B1A_B3C_N78A UL: B1A_0_N78A FSC[1]\n"
      + "[CAP] FSC[2], D/U[N1/N1]\n"
      + "[CAP] CA idx [1] NL1 bc, num[1] DL: N78A UL: N78A FSC[2]\n"
      + "[CAP] FSC[3], D/U[N1/N1][N2/_0]\n"
      + "[CAP] CA idx [2] NL1 bc, num[2] DL: N78A_N257B UL: N78A_0 FSC[3]\n",
  );
  // 1-based FSC indices counted AFTER insertion; families tally endc/nrdc/nrca.
  assert.deepEqual(meta, {
    records: 3,
    families: { endc: 1, nrca: 1, nrdc: 1 },
    modulation: "unknown",
    unknown_bandwidth: "NL1_CAP_BW0",
  });
});

test("nr trace: absent UL renders 0 tokens and _0 feature-set halves", () => {
  const noUl = new MtkCombo([], [new NrComponent(78, 0, 0x1c, [new NrCC(30, 2, 40, null, null)])]);
  const { text } = renderNrTrace([noUl], "d");
  assert.equal(
    text,
    "# Reconstructed from MediaTek firmware; not a captured modem log.\n"
      + "# Device: d\n"
      + "# Modulation is unknown. LTE UL MIMO uses one layer per configured carrier.\n"
      + "[CAP] NR DL FSpCC[1], scs[NL1_CAP_SCS_30KHZ], bw[NL1_CAP_BW40], bw90m[NL1_CAP_NOT_SUPPORT], mimo[NL1_CAP_MIMO_TWO_LAYERS], modulation[UNKNOWN]\n"
      + "[CAP] NR DL FS[1], FSDLpCC ID[1]\n"
      + "[CAP] FSC[1], D/U[N1/_0]\n"
      + "[CAP] CA idx [0] NL1 bc, num[1] DL: N78A UL: 0 FSC[1]\n",
  );
});

test("nr trace: the device line sanitizes CR/LF like the python header", () => {
  // python str.replace("\n", " ").replace("\r", " "): each CR and LF becomes
  // its own space, so "dev\r\nice" renders with two spaces.
  const { text } = renderNrTrace([], "dev\r\nice");
  assert.match(text, /^# Device: dev  ice\n/m);
  assert.equal(text.split("\n").length, 4); // header only, trailing newline
});

test("nr trace: TraceError messages are exact", () => {
  const mk = (ccs) => new MtkCombo([], [new NrComponent(78, 0, 0x1c, ccs)]);
  assert.equal(
    errOf(() => renderNrTrace([mk([new NrCC(240, 2, 100, null, null)])], "d")).message,
    "MTK NR importer cannot represent SCS 240 kHz",
  );
  assert.equal(
    errOf(() => renderNrTrace([new MtkCombo([], [new NrComponent(78, 26, 0x1c, [new NrCC(15, 2, 100, null, null)])])], "d")).message,
    "MTK trace importer requires a single-letter class; got 26",
  );
  assert.equal(
    errOf(() => renderNrTrace([mk([new NrCC(15, 3, 100, null, null)])], "d")).message,
    "unsupported MIMO layer count: 3",
  );
  assert.equal(
    errOf(() => renderNrTrace([mk([new NrCC(15, 2, 0, null, null)])], "d")).message,
    "invalid native bandwidth: 0",
  );
  // FS carrier limits: NR DL 8, NR UL 4, EUTRA 5.
  assert.equal(
    errOf(() => renderNrTrace([mk(Array(9).fill(new NrCC(15, 2, 100, null, null)))], "d")).message,
    "MTK importer supports at most 8 N DL carriers per FS",
  );
  assert.equal(
    errOf(() => renderNrTrace([new MtkCombo([], [new NrComponent(78, 0, 0, Array(5).fill(new NrCC(15, 2, 100, 2, 100)))])], "d")).message,
    "MTK importer supports at most 4 N UL carriers per FS",
  );
  assert.equal(
    errOf(() => renderNrTrace([new MtkCombo([new LteComponent(1, 0, 0, Array(6).fill(2))], [nr1])], "d")).message,
    "MTK importer supports at most 5 E DL carriers per FS",
  );
  // An NR-bearing combo whose LTE component carries no DL MIMO per-CC values.
  assert.equal(
    errOf(() => renderNrTrace([new MtkCombo([new LteComponent(1, 0, 0, [])], [nr1])], "d")).message,
    "missing DL per-carrier features",
  );
  // NR component without resolved CCs -> no DL features at all.
  assert.equal(
    errOf(() => renderNrTrace([new MtkCombo([], [new NrComponent(78, 0, 0x1c, [])])], "d")).message,
    "missing DL per-carrier features",
  );
  // LTE-only combos are skipped entirely — none of the errors above fire.
  assert.match(renderNrTrace([new MtkCombo([new LteComponent(1, 26, 0, [])], [])], "d").text, /^# Reconstructed/);
});

test("lte log: row layout, min projection and mixed counter (python-pinned)", () => {
  const l3 = new LteComponent(7, 1, 1, [2]);
  const combos = [new MtkCombo([lte1, lte2], []), new MtkCombo([lte1, lte2], []), new MtkCombo([l3], [])];
  const { text, meta } = renderLteLog(combos, "device-x");
  // The duplicate second combo increments the mixed counter (lte2 carries
  // 2+4 layers) BEFORE the dedup key drops it — python counts pre-dedup.
  assert.equal(
    text,
    "# Reconstructed from MediaTek firmware; not a captured modem log.\n"
      + "# Device: device-x\n"
      + "# Modulation is unknown. LTE UL MIMO uses one layer per configured carrier.\n"
      + "# BCS unknown: zero placeholders are required by ImportMTKLte; no BCS support is asserted.\n"
      + "# Mixed per-carrier DL MIMO is projected to the minimum per logical component.\n"
      + "MSG_ID_ERRC_RCM_UE_PRE_CA_COMB_INFO\n"
      + "bandwidth_comb_set = Array[2]\n"
      + "bandwidth_comb_set[0] = 0x0\n"
      + "bandwidth_comb_set[1] = 0x0\n"
      + "band_comb[0]\n"
      + "band_param_num = 2\n"
      + "band_param = Array[2]\n"
      + "band_param[0]\n"
      + "band = 1\n"
      + "class_ul = 0\n"
      + "class_dl = 0\n"
      + "band_param[1]\n"
      + "band = 3\n"
      + "class_ul = 6\n"
      + "class_dl = 2\n"
      + "band_mimo = Array[2]\n"
      + "band_mimo[0]\n"
      + "mimo = ERRC_CAPA_CA_MIMO_CAPA_FOUR_LAYERS\n"
      + "band_mimo[1]\n"
      + "mimo = ERRC_CAPA_CA_MIMO_CAPA_TWO_LAYERS\n"
      + "band_comb[1]\n"
      + "band_param_num = 1\n"
      + "band_param = Array[1]\n"
      + "band_param[0]\n"
      + "band = 7\n"
      + "class_ul = 1\n"
      + "class_dl = 1\n"
      + "band_mimo = Array[1]\n"
      + "band_mimo[0]\n"
      + "mimo = ERRC_CAPA_CA_MIMO_CAPA_TWO_LAYERS\n",
  );
  assert.deepEqual(meta, {
    records: 2,
    bcs: "unknown; zero placeholder",
    mimo_projection: "minimum per logical component",
    mixed_mimo_components_projected: 2,
  });
});

test("lte log: TraceError messages are exact", () => {
  assert.equal(
    errOf(() => renderLteLog([new MtkCombo([new LteComponent(1, 6, 6, [2])], [])], "d")).message,
    "LTE importer requires MTK A..F classes / UL-absent=6",
  );
  assert.equal(
    errOf(() => renderLteLog([new MtkCombo([new LteComponent(1, 0, 7, [2])], [])], "d")).message,
    "LTE importer requires MTK A..F classes / UL-absent=6",
  );
  assert.equal(
    errOf(() => renderLteLog([new MtkCombo([new LteComponent(1, 0, 0, [8])], [])], "d")).message,
    "LTE CA_COMB_INFO importer supports only known 2/4-layer MIMO",
  );
  assert.equal(
    errOf(() => renderLteLog([new MtkCombo([new LteComponent(1, 0, 0, [])], [])], "d")).message,
    "LTE CA_COMB_INFO importer supports only known 2/4-layer MIMO",
  );
  // NR-bearing combos and empty LTE lists are skipped, not validated.
  assert.match(renderLteLog([new MtkCombo([lte1], [nr1]), new MtkCombo([], [])], "d").text, /bandwidth_comb_set = Array\[0\]/);
});
