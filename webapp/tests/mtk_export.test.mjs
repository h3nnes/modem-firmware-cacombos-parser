// MTK Stage-D tests: the wire-format export ports (webapp/js/lib/
// mtk_export.js). Synthetic pins use hand-verified vectors generated from the
// python reference (mtk-drdi-combo-parser/mtk_export.py): index-table
// geometry, encode_component bit packing, the two-layer B826 dedup, B0CD v41
// record/packet framing and the exact file-text lines. The corpus-gated
// BYTE differential then compares every produced file of every card of both
// sample images against webapp/goldens/mtk/diag.json (the python reference's
// per-card export texts) — b826/b0cd here, and the mtk_nr/mtk_lte trace texts
// in the same loop so the whole suite shares one scan per image.
//
// goldens/mtk/diag.json is an oversized reference dump excluded from git
// (regenerate with tools/generate_mtk_goldens.py); the differential skips
// cleanly without it, exactly like the apple golden tests. No python3 probe
// is needed — the test never regenerates goldens, it only reads them.
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { MtkCombo, LteComponent, NrComponent, NrCC } from "../js/lib/mtk_universal.js";
import {
  BW_NAMES,
  BW_TO_INDEX,
  SCS_TO_INDEX,
  ANT_TO_INDEX,
  mimoIndex,
  bwIndex,
  encodeComponent,
  encodeCombo,
  buildB826,
  buildB826CombinedText,
  buildB0cdV41,
  buildB0cdText,
  B0cdError,
} from "../js/lib/mtk_export.js";
import { mtkCardCombos, scanMtk } from "../js/lib/mtk_scan.js";
import { renderLteLog, renderNrTrace } from "../js/lib/mtk_trace.js";
import { sourceFor } from "../js/lib/source.js";
import { CORPUS_DIR } from "./helpers.mjs";

const bytesHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
const errOf = (fn) => {
  try {
    fn();
    return null;
  } catch (err) {
    return err;
  }
};

// --- synthetic fixtures (shared by the B826 and trace pins) --------------------

// B1A dl / A ul / 4 layers; B3C dl / no UL (class 6) / 2+4 layers.
const lte1 = new LteComponent(1, 0, 0, [4]);
const lte2 = new LteComponent(3, 2, 6, [2, 4]);
// n78A one CC (15 kHz, 4L, 50 MHz, 1L UL); n257B two CCs with absent UL.
const nr1 = new NrComponent(78, 0, 0, [new NrCC(15, 4, 50, 1, 50)]);
const nr2 = new NrComponent(257, 1, 0x1c, [
  new NrCC(120, 2, 100, null, null),
  new NrCC(30, 4, 40, 2, 40),
]);

// --- index-table geometry (python antenna_tables()/BW_NAMES) -------------------

test("b826 tables: 68 BW names with 67 encodable indices and stable pins", () => {
  assert.equal(BW_NAMES.length, 68);
  assert.equal(BW_TO_INDEX.size, 67);
  assert.ok(!BW_TO_INDEX.has("DEFAULT"));
  assert.equal(BW_TO_INDEX.get("20"), 4);
  assert.equal(BW_TO_INDEX.get("50_20"), 49);
  assert.equal(BW_TO_INDEX.get("100_50"), 64);
  assert.equal(BW_TO_INDEX.get("100_80"), 65);
  assert.equal(BW_TO_INDEX.get("45_45"), 67); // last name, index 67
  assert.deepEqual([...SCS_TO_INDEX.entries()], [[15, 1], [30, 2], [60, 3], [120, 4], [240, 5]]);
});

test("b826 tables: 90-entry antenna enum with the python layout", () => {
  // INVALID + 1/2/4 + per count 2..8 (all-ones + 2-leading + 4-leading) + tails.
  assert.equal(ANT_TO_INDEX.size, 90);
  assert.equal(ANT_TO_INDEX.get("INVALID"), undefined); // keyed by layers, never "INVALID"
  assert.equal(ANT_TO_INDEX.get("2"), 2);
  assert.equal(ANT_TO_INDEX.get("4"), 3);
  assert.equal(ANT_TO_INDEX.get("1_1"), 4);
  assert.equal(ANT_TO_INDEX.get("2_1"), 5);
  assert.equal(ANT_TO_INDEX.get("2_2"), 6);
  assert.equal(ANT_TO_INDEX.get("4_2"), 7);
  assert.equal(ANT_TO_INDEX.get("4_4"), 8);
  assert.equal(ANT_TO_INDEX.get("1_1_1"), 9);
  assert.equal(ANT_TO_INDEX.get("8"), 81);
  assert.equal(ANT_TO_INDEX.get("8_4"), 82);
  assert.equal(ANT_TO_INDEX.get("6"), 85);
  assert.equal(ANT_TO_INDEX.get("6_6"), 89); // last tail entry
});

test("b826 mimoIndex canonicalizes via the descending sort and rejects strangers", () => {
  assert.equal(mimoIndex([]), 0);
  assert.equal(mimoIndex(null), 0);
  assert.equal(mimoIndex([4, 2]), 7); // canonical (4,2)
  assert.equal(mimoIndex([2, 4]), 7); // same enum after sorting
  assert.equal(mimoIndex([2, 2, 2]), 12);
  const err = errOf(() => mimoIndex([3, 3]));
  assert.ok(err instanceof Error);
  assert.equal(err.message, "B826 antenna enum cannot encode MIMO vector [3, 3]");
});

test("b826 bwIndex resolution chain: direct, canonical, collapsed, distinct, unsupported", () => {
  assert.deepEqual(bwIndex([]), [0, true, [], null]);
  assert.deepEqual(bwIndex([50]), [12, true, [50], null]);
  assert.deepEqual(bwIndex([50, 20]), [49, true, [50, 20], null]);
  assert.deepEqual(bwIndex([20, 50]), [49, true, [50, 20], null]); // canonical
  // all-equal collapses to the single-carrier name, no unsupported marker
  assert.deepEqual(bwIndex([40, 40, 40]), [11, true, [40], null]);
  // two distinct values collapse and report the raw list as "collapsed"
  assert.deepEqual(bwIndex([100, 50, 100]), [64, true, [100, 50], [100, 50, 100]]);
  assert.deepEqual(bwIndex([7, 7]), [0, false, [7, 7], null]); // not encodable
});

// --- encode_component bit packing (python-verified vectors) --------------------

test("b826 encodeComponent packs the 9-byte little-endian layout byte-exactly", () => {
  const vectors = [
    // LTE b1 A/A, DL 4 layers, UL 1 layer on 1 carrier
    { rat: "LTE", band: 1, dl_class: 1, ul_class: 1, dl_mimo: [4], ul_mimo: [1] },
    // LTE b3 C/-, DL 2+4 layers (enum 7), UL absent
    { rat: "LTE", band: 3, dl_class: 3, ul_class: 0, dl_mimo: [2, 4], ul_mimo: [] },
    // LTE b511 (9-bit max), DL class 26 (5-bit field), DL 2 layers
    { rat: "LTE", band: 511, dl_class: 26, ul_class: 0, dl_mimo: [2], ul_mimo: [] },
    // NR n78, DL 4+2 layers (50+20 MHz), UL 1+1 layers, SCS 30 kHz
    {
      rat: "NR", band: 78, dl_class: 1, ul_class: 2, dl_mimo: [4, 2], dl_bw: [50, 20],
      ul_mimo: [1, 1], ul_bw: [50, 20], scs: 30,
    },
    // NR n257, DL 2 layers 100 MHz, UL class 29 (absent sentinel + 1), SCS 120
    {
      rat: "NR", band: 257, dl_class: 2, ul_class: 0x1d, dl_mimo: [2], dl_bw: [100],
      ul_mimo: [], ul_bw: [], scs: 120,
    },
    // NR n41, three 2-layer 40 MHz carriers, UL 1-layer each, SCS 15
    {
      rat: "NR", band: 41, dl_class: 1, ul_class: 1, dl_mimo: [2, 2, 2], dl_bw: [40, 40, 40],
      ul_mimo: [1, 1, 1], ul_bw: [40, 40, 40], scs: 15,
    },
  ];
  const want = [
    "018441080000000000",
    "038C03000000000000",
    "FF6901000000000000",
    "4E86832000C5620000",
    "010B41070056000000",
    "29064648802C160000",
  ];
  vectors.forEach((v, i) => assert.equal(bytesHex(encodeComponent(v, new Map())), want[i], `vector ${i}`));
});

test("b826 encodeComponent tracks unsupported bandwidths like the python counter", () => {
  // DL [7,7] is not encodable -> ("DL", band, (7, 7)); UL [7] -> ("UL", band, (7,)).
  const unsupported = new Map();
  assert.equal(
    bytesHex(encodeComponent(
      { rat: "NR", band: 78, dl_class: 1, ul_class: 2, dl_mimo: [4, 2], dl_bw: [7, 7], ul_mimo: [1, 1], ul_bw: [7], scs: 30 },
      unsupported,
    )),
    "4E8683200001000000", // dl_bw/ul_bw indices 0
  );
  assert.deepEqual([...unsupported.entries()], [
    ["('DL', 78, (7, 7))", 1],
    ["('UL', 78, (7,))", 1],
  ]);
  // The two-distinct collapse keeps encoding (100_50) and marks the raw list.
  const collapsed = new Map();
  assert.equal(
    bytesHex(encodeComponent(
      { rat: "NR", band: 78, dl_class: 1, ul_class: 2, dl_mimo: [4, 2], dl_bw: [100, 50, 100], ul_mimo: [1, 1], ul_bw: [100, 50, 100], scs: 30 },
      collapsed,
    )),
    "4E8683200001810000",
  );
  assert.deepEqual([...collapsed.entries()], [
    ["('DL-collapsed', 78, (100, 50, 100), (100, 50))", 1],
  ]);
});

test("b826 encodeComponent refuses out-of-range bands and MIMO vectors", () => {
  assert.equal(
    errOf(() => encodeComponent({ rat: "LTE", band: 512, dl_class: 1, ul_class: 0, dl_mimo: [2], ul_mimo: [] }, new Map())).message,
    "B826 v21 band out of 9-bit range: 512",
  );
  assert.equal(
    errOf(() => encodeComponent({ rat: "LTE", band: 0, dl_class: 1, ul_class: 0, dl_mimo: [2], ul_mimo: [] }, new Map())).message,
    "B826 v21 band out of 9-bit range: 0",
  );
  assert.equal(
    errOf(() => encodeComponent({ rat: "LTE", band: 1, dl_class: 1, ul_class: 0, dl_mimo: [3, 3], ul_mimo: [] }, new Map())).message,
    "B826 antenna enum cannot encode MIMO vector [3, 3]",
  );
});

test("b826 encodeCombo frames 3 + 2 + 24 header bytes and the count nibble", () => {
  const blob = encodeCombo(
    [
      { rat: "LTE", band: 1, dl_class: 1, ul_class: 1, dl_mimo: [4], ul_mimo: [1] },
      { rat: "NR", band: 78, dl_class: 1, ul_class: 0x1d, dl_mimo: [4], dl_bw: [50], ul_mimo: [], ul_bw: [], scs: 30 },
    ],
    new Map(),
  );
  assert.equal(blob.length, 29 + 2 * 9);
  assert.equal(bytesHex(blob), "00000010000000000000000000000000000000000000000000000000000184410800000000004E8641070031000000");
  const err = errOf(() => encodeCombo(Array(16).fill({ rat: "LTE", band: 1, dl_class: 1, ul_class: 1, dl_mimo: [2], ul_mimo: [1] }), new Map()));
  assert.equal(err.message, "B826 v21 supports 1..15 components, got 16");
});

test("b826 buildB826 dedups twice: structural rows first, encoded bytes second", () => {
  // Same LTE row twice: the structural key collapses it before encoding.
  const dup = buildB826([new MtkCombo([lte1], [nr1]), new MtkCombo([lte1], [nr1])], 3);
  assert.equal(dup.records, 1);
  assert.equal(dup.inputRows, 1);
  // mimo [2,4] and [4,2] rows are structurally distinct (python repr differs,
  // so BOTH stay) but encode to identical bytes, so the byte-level dedup of
  // build_log drops the second one.
  const c1 = new MtkCombo([new LteComponent(1, 0, 6, [2, 4])], [nr1]);
  const c2 = new MtkCombo([new LteComponent(1, 0, 6, [4, 2])], [nr1]);
  const both = buildB826([c1, c2], 4);
  assert.equal(both.records, 1);
  assert.equal(both.inputRows, 2);
  assert.equal(both.tag, "RF_NRCA");
  assert.equal(both.source, 4);
  // The 11-byte header: version 21, reserved 0, total, index 0, num=total, source.
  const blob = both.blob;
  assert.equal(blob.length, 11 + 29 + 2 * 9); // one deduped 2-component combo
  assert.deepEqual([...blob.subarray(0, 11)], [21, 0, 0, 0, 1, 0, 0, 0, 1, 0, 4]);
});

test("b826 block text: two newline-terminated header lines plus the hex payload", () => {
  const result = buildB826([new MtkCombo([lte1], [nr1])], 3);
  assert.equal(
    result.block("device-x"),
    "# 0xB826 v21 RF_ENDC (source=3) device-x\n"
      + "# records=1\n"
      + `Payload: ${bytesHex(result.blob)}\n`,
  );
  assert.match(result.block("d"), /^# 0xB826 v21 RF_ENDC \(source=3\) d\n# records=1\nPayload: [0-9A-F]+\n$/);
});

test("b826 combined text: ENDC block, NRCA block, NRDC block only when mixed", () => {
  const endc = new MtkCombo([lte1, lte2], [nr1]);
  const nrca = new MtkCombo([], [nr1]);
  const nrdc = new MtkCombo([], [nr1, nr2]);
  const { text, results } = buildB826CombinedText([endc, nrca, nrdc], "device-x");
  // python-generated (build_b826 x3 + combined_b826_text on the same combos).
  assert.equal(
    text,
    "# 0xB826 v21 RF_ENDC (source=3) device-x\n# records=1\nPayload: 15000000010000000100030000001800000000000000000000000000000000000000000000000000018441080000000000038C030000000000004E8641088030180000\n"
      + "\n"
      + "# 0xB826 v21 RF_NRCA (source=4) device-x\n# records=1\nPayload: 150000000100000001000400000008000000000000000000000000000000000000000000000000004E8641088030180000\n"
      + "\n"
      + "# 0xB826 v21 RF_NRDC (source=5) device-x\n# records=1\nPayload: 150000000100000001000500000010000000000000000000000000000000000000000000000000004E8641088030180000018B03000082000000\n",
  );
  assert.deepEqual(results.map((r) => [r.tag, r.source, r.records]), [
    ["RF_ENDC", 3, 1],
    ["RF_NRCA", 4, 1],
    ["RF_NRDC", 5, 1],
  ]);
  // Without a genuine FR1/FR2 mix there is no third block (pure-FR2 rows are
  // NR-CA in the export classification, only the presentation split is nrdc).
  const noNrdc = buildB826CombinedText([endc, nrca], "device-x");
  assert.equal(noNrdc.results.length, 2);
  assert.equal(noNrdc.text.split("# 0xB826").length - 1, 2);
});

// --- B0CD v41 -------------------------------------------------------------------

test("b0cd v41: 7-byte records, len prefix, 100-combo packets, byte dedup", () => {
  const l3 = new LteComponent(7, 1, 1, [2]);
  const combos = [
    new MtkCombo([lte1, lte2], []),
    new MtkCombo([lte1, lte2], []), // structural duplicate of the first
    new MtkCombo([l3], []),
  ];
  const result = buildB0cdV41(combos);
  assert.equal(result.records, 2);
  assert.equal(result.packets.length, 1);
  assert.deepEqual(result.packets.map(bytesHex), [
    // packet = [41, 2] + record(b1A 4L, ul 1x1) + record(b3C, 4+2L DL, no UL)
    "29020201000101030100030003000700000107000202020400",
  ]);
  assert.equal(result.sha256, "a0494ea90f2d7dbe36e8838b339f0f04eab21682d8c8b5c78ded11622a1d9082");
});

test("b0cd v41: packet framing splits above 100 records", () => {
  const combos = Array.from({ length: 101 }, (_, i) => new MtkCombo([new LteComponent((i % 80) + 1, i % 6, (i + 1) % 6, [2])], []));
  const result = buildB0cdV41(combos);
  assert.equal(result.records, 101);
  assert.equal(result.packets.length, 2);
  assert.equal(result.packets[0][0], 41);
  assert.equal(result.packets[0][1], 100);
  assert.equal(result.packets[1][0], 41);
  assert.equal(result.packets[1][1], 1);
});

test("b0cd v41: exact file text including the MTK provenance lines", () => {
  const l3 = new LteComponent(7, 1, 1, [2]);
  const combos = [new MtkCombo([lte1, lte2], []), new MtkCombo([l3], [])];
  const { text } = buildB0cdText(combos, "device-x");
  assert.equal(
    text,
    "# Headerless 0xB0CD v41 LTE capability payloads.\n"
      + "# Device: device-x\n"
      + "# Derived from MediaTek DRDI, not captured Qualcomm DIAG data.\n"
      + "# MTK supplies band/class/DL-MIMO; BCS is omitted. UL MIMO is one layer per UL CC and UL-QAM is 0 (unknown).\n"
      + "# records=2; packets=1; sha256=a0494ea90f2d7dbe36e8838b339f0f04eab21682d8c8b5c78ded11622a1d9082\n"
      + "\n"
      + "# LTE CA packet 1/1\n"
      + "Payload: 29020201000101030100030003000700000107000202020400\n",
  );
});

test("b0cd v41: B0cdError messages are exact", () => {
  const seven = errOf(() => buildB0cdV41([new MtkCombo(Array(7).fill(lte1), [])]));
  assert.ok(seven instanceof B0cdError);
  assert.equal(seven.message, "0xB0CD v41 supports at most six LTE components per combination");
  const band = errOf(() => buildB0cdV41([new MtkCombo([new LteComponent(0, 0, 0, [2])], [])]));
  assert.ok(band instanceof B0cdError);
  assert.equal(band.message, "0xB0CD v41 LTE band is out of range: 0");
  const dlClass = errOf(() => buildB0cdV41([new MtkCombo([new LteComponent(1, 26, 0, [2])], [])]));
  assert.equal(dlClass.message, "0xB0CD v41 DL class is out of range: 26");
  // 8-layer DL MIMO is encodable (8_8 enum); an unknown vector is not.
  assert.ok(!(errOf(() => buildB0cdV41([new MtkCombo([new LteComponent(1, 0, 0, [8, 8])], [])])) instanceof B0cdError));
  const mimo = errOf(() => buildB0cdV41([new MtkCombo([new LteComponent(1, 0, 0, [3])], [])]));
  assert.ok(mimo instanceof B0cdError);
  assert.equal(mimo.message, "0xB0CD v41 has no antenna enum for LTE MIMO (3,)");
});

// --- corpus-gated BYTE differential (all four export formats, both images) ------

const mtkImages = [
  "Oppo_Find_X10_Pro_Max_5G_PMX110-modem.img",
  "mtk_pocox8pro_d8500u_modem.img",
];

const mtkDifferentialAvailable = () =>
  mtkImages.every((img) => existsSync(join(CORPUS_DIR, img))) &&
  existsSync(new URL("../goldens/mtk/diag.json", import.meta.url));

for (const img of mtkImages) {
  const imgPath = join(CORPUS_DIR, img);
  const stem = img.replace(/\.[^.]+$/, "");

  test(
    `mtk export differential: b826/b0cd/mtk_nr/mtk_lte equal the python golden bytes for every card of ${stem}`,
    { skip: !mtkDifferentialAvailable() },
    async () => {
      const golden = await readFile(new URL("../goldens/mtk/diag.json", import.meta.url)).then(JSON.parse);
      const src = await sourceFor(imgPath);
      try {
        // scanMtk seeds the card-open image state through onMtkImage; the
        // differential reuses exactly that memoized summary like the worker.
        let seeded = null;
        const out = await scanMtk(src, img, () => false, {
          onMtkImage: (parts, summary) => {
            seeded = { parts, summary };
          },
        });
        assert.ok(seeded, "the scan must hand over the decoded image state");
        assert.ok(out.records.length, "mtk scan produced cards");
        // The device embedded in every golden text is the image stem (python
        // CLI: args.device = args.stem = Path(img).stem).
        let compared = 0;
        for (const record of out.records) {
          const key = `${stem}/bank${record.mtk.bankIndex}/profile${record.mtk.profile}`;
          assert.ok(golden[key], `golden entry ${key}`);
          const parsed = mtkCardCombos(seeded.summary, record.mtk.bankIndex, record.mtk.profile);
          const produced = {
            b826: buildB826CombinedText(parsed.combos, stem).text,
            b0cd: buildB0cdText(parsed.lteCombos, stem).text,
            mtk_nr: renderNrTrace(parsed.combos, stem).text,
            mtk_lte: renderLteLog(parsed.lteCombos, stem).text,
          };
          for (const [fmt, text] of Object.entries(produced)) {
            const want = golden[key][fmt];
            if (want === undefined) continue; // format gated off for this card
            assert.equal(text, want, `${key} ${fmt}: byte-exact`);
            compared += 1;
          }
        }
        // Every card produced every format in the corpus (both sides non-empty
        // on all eight cards) — keep the count pinned so a future gating
        // change shows up here instead of silently shrinking the differential.
        assert.equal(compared, out.records.length * 4);
      } finally {
        await src.close();
      }
    },
  );
}
