// MTK Stage-C tests: the generateMtkTables viewer-table projection (synthetic
// schema pins, corpus-independent) and the corpus-gated golden differential —
// for every card of both sample images, generateMtkTables(mtkCardCombos(...))
// must equal the python reference's tables.json golden key-order-sensitively,
// with the scan records' counts matching the committed manifest.json.
//
// goldens/mtk/{tables,diag}.json are oversized reference dumps excluded from
// git (regenerate with tools/generate_mtk_goldens.py); the differential skips
// cleanly without them, exactly like the apple golden tests.
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import {
  MtkCombo,
  LteComponent,
  NrComponent,
  NrCC,
} from "../js/lib/mtk_universal.js";
import { generateMtkTables } from "../js/lib/mtk_tables.js";
import { mtkCardCombos } from "../js/lib/mtk_scan.js";
import { scanMtk } from "../js/lib/mtk_scan.js";
import { isValidTablesShape } from "../js/cardcache.js";
import { sourceFor } from "../js/lib/source.js";
import { CORPUS_DIR, deepEqualOrdered } from "./helpers.mjs";

// --- synthetic schema pins (reference row schema, cell-for-cell) --------------

// B1A dl / A ul / 4 layers; B3C dl / no UL (class 6) / 2+4 layers.
const lte1 = new LteComponent(1, 0, 0, [4]);
const lte2 = new LteComponent(3, 2, 6, [2, 4]);
// n78A one CC (15 kHz, 4L, 50 MHz, 1L UL); n257B two CCs with absent UL.
const nr1 = new NrComponent(78, 0, 0, [new NrCC(15, 4, 50, 1, 50)]);
const nr2 = new NrComponent(257, 1, 0x1c, [
  new NrCC(120, 2, 100, null, null),
  new NrCC(30, 4, 40, 2, 40),
]);

test("mtk tables: EN-DC rows carry the LTE/NR tokens plus per-direction NR columns", () => {
  const endc = new MtkCombo([lte1, lte2], [nr1]);
  const tables = generateMtkTables([endc]);
  deepEqualOrdered(tables, {
    lte_ca: [],
    nr_sa: [],
    nr_ca: [],
    endc: [
      {
        "LTE DL": "3C + 1A",
        "LTE MIMO DL": "2 + 4 + 4",
        "NR DL": "78A",
        "NR MIMO DL": "4",
        "NR SCS DL (kHz)": "15",
        "NR BW DL (MHz)": "50",
        "LTE UL": "1A",
        "NR UL": "78A",
        "NR MIMO UL": "1",
        "NR SCS UL (kHz)": "15",
        "NR BW UL (MHz)": "50",
      },
    ],
    nrdc: [],
  });
});

test("mtk tables: single-CC NR rows are NR SA; multi-CC rows are NR-CA", () => {
  const fr1 = new MtkCombo([], [nr1]);
  const fr2 = new MtkCombo([], [nr2]);
  const tables = generateMtkTables([fr1, fr2]);
  deepEqualOrdered(tables, {
    lte_ca: [],
    // Pure-FR1 single-CC -> NR SA; the two-CC FR2 row -> NR-CA.
    nr_sa: [
      {
        "NR DL": "78A",
        "MIMO DL": "4",
        "SCS DL (kHz)": "15",
        "BW DL (MHz)": "50",
        "NR UL": "78A",
        "MIMO UL": "1",
        "SCS UL (kHz)": "15",
        "BW UL (MHz)": "50",
      },
    ],
    nr_ca: [
      {
        "NR DL": "257B",
        "MIMO DL": "2 + 4",
        "SCS DL (kHz)": "120 + 30",
        "BW DL (MHz)": "100 + 40",
        "NR UL": "",
        "MIMO UL": "",
        "SCS UL (kHz)": "",
        "BW UL (MHz)": "",
      },
    ],
    endc: [],
    nrdc: [],
  });
  // A component without an uplink contributes no UL cells at all (its CCs are
  // dropped from the UL columns even when a CC carries ul_mimo).
  const noUl = new MtkCombo([], [new NrComponent(78, 0, 0x1c, [new NrCC(15, 4, 50, null, null)])]);
  assert.equal(generateMtkTables([noUl]).nr_sa[0]["NR UL"], "");
});

test("mtk tables: NRDC split keeps the FR1/FR2 band and value columns", () => {
  const mixed = new MtkCombo([], [nr1, nr2]);
  const tables = generateMtkTables([mixed]);
  deepEqualOrdered(tables, {
    lte_ca: [],
    nr_sa: [],
    nr_ca: [],
    endc: [],
    nrdc: [
      {
        "FR1 DL": "78A",
        "FR1 MIMO DL": "4",
        "FR1 SCS DL (kHz)": "15",
        "FR1 BW DL (MHz)": "50",
        "FR2 DL": "257B",
        "FR2 MIMO DL": "2 + 4",
        "FR2 SCS DL (kHz)": "120 + 30",
        "FR2 BW DL (MHz)": "100 + 40",
        "FR1 UL": "78A",
        "FR1 MIMO UL": "1",
        "FR1 SCS UL (kHz)": "15",
        "FR1 BW UL (MHz)": "50",
        "FR2 UL": "",
        "FR2 MIMO UL": "",
        "FR2 SCS UL (kHz)": "",
        "FR2 BW UL (MHz)": "",
      },
    ],
  });
});

test("mtk tables: LTE CA rows are the descending-order token triple", () => {
  const tables = generateMtkTables([], [new MtkCombo([lte1, lte2], [])]);
  deepEqualOrdered(tables, {
    lte_ca: [{ "LTE DL": "3C + 1A", "MIMO DL": "2 + 4 + 4", "LTE UL": "1A" }],
    nr_sa: [],
    nr_ca: [],
    endc: [],
    nrdc: [],
  });
});

test("mtk tables: 5-key envelope, cache-shape compatible, deduped across both lists", () => {
  const endc = new MtkCombo([lte1], [nr1]);
  const dup = new MtkCombo([lte1], [nr1]);
  const tables = generateMtkTables([endc, dup, new MtkCombo([], [nr1])], []);
  // Exactly the five array keys, in the reference tab order (LTE, NR SA,
  // NRCA, EN-DC, NRDC); the optional nr_sa key keeps 4-key shapes valid.
  assert.deepEqual(Object.keys(tables), ["lte_ca", "nr_sa", "nr_ca", "endc", "nrdc"]);
  assert.ok(isValidTablesShape(tables));
  assert.equal(isValidTablesShape({ lte_ca: [], nr_ca: [], endc: [], nrdc: [] }), true);
  assert.equal(isValidTablesShape({ lte_ca: [], nr_ca: [], endc: [], nrdc: [], nr_sa: 4 }), false);
  // Dedup is keep-first over comboKey across lteRows AND combos: the second
  // structurally identical EN-DC row collapses, the single-CC NR row (a
  // different combo) stays.
  assert.equal(tables.endc.length, 1);
  assert.equal(tables.nr_sa.length, 1);
  // A row-table LTE row equal to a capability LTE-only combo is counted once.
  const lteOnly = new MtkCombo([lte1], []);
  const twice = generateMtkTables([lteOnly], [lteOnly]);
  assert.equal(twice.lte_ca.length, 1);
  // Grammar-classified empty combos render nowhere.
  const none = generateMtkTables([new MtkCombo([], [])], []);
  assert.equal(none.lte_ca.length + none.nr_sa.length + none.nr_ca.length + none.endc.length + none.nrdc.length, 0);
});

test("mtk tables: empty inputs yield five empty tables (valid cache entries)", () => {
  const tables = generateMtkTables([], []);
  assert.deepEqual(tables, { lte_ca: [], nr_sa: [], nr_ca: [], endc: [], nrdc: [] });
  assert.ok(isValidTablesShape(tables));
});

// --- corpus-gated golden differential -----------------------------------------

const mtkImages = [
  "Oppo_Find_X10_Pro_Max_5G_PMX110-modem.img",
  "mtk_pocox8pro_d8500u_modem.img",
];

function python3Available() {
  // Probe-and-skip convention (mtk_scan.test.mjs): no python3, no differential.
  return spawnSync("python3", ["-c", "pass"]).status === 0;
}

const mtkGoldenDumpsAvailable = () =>
  existsSync(new URL("../goldens/mtk/tables.json", import.meta.url)) &&
  existsSync(new URL("../goldens/mtk/manifest.json", import.meta.url));

const mtkDifferentialAvailable = () =>
  python3Available() &&
  mtkImages.every((img) => existsSync(join(CORPUS_DIR, img))) &&
  mtkGoldenDumpsAvailable();

const loadGolden = (name) => readFile(new URL(`../goldens/mtk/${name}.json`, import.meta.url)).then(JSON.parse);

for (const img of mtkImages) {
  const imgPath = join(CORPUS_DIR, img);
  const stem = img.replace(/\.[^.]+$/, "");

  test(
    `mtk tables differential: generateMtkTables equals the python golden for every card of ${stem}`,
    { skip: !mtkDifferentialAvailable() },
    async () => {
      const [golden, manifest] = await Promise.all([loadGolden("tables"), loadGolden("manifest")]);
      const image = manifest.images[stem];
      assert.ok(image, `manifest entry for ${stem}`);
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
        assert.ok(out, "mtk scan handled the corpus image");
        assert.equal(out.records.length, Object.keys(image.cards).length, "card count");
        for (const record of out.records) {
          const key = `${stem}/bank${record.mtk.bankIndex}/profile${record.mtk.profile}`;
          assert.ok(golden[key], `golden entry ${key}`);
          const parsed = mtkCardCombos(seeded.summary, record.mtk.bankIndex, record.mtk.profile);
          const tables = generateMtkTables(parsed.combos, parsed.lteCombos);
          deepEqualOrdered(tables, golden[key], key);
          // Scan counts (what the card list shows) match the reference counts,
          // and the table row counts match them in turn.
          assert.deepEqual(record.mtk.counts, image.cards[key].counts, `${key}: counts`);
          assert.deepEqual(
            {
              lte_ca: tables.lte_ca.length,
              nr_sa: tables.nr_sa.length,
              nr_ca: tables.nr_ca.length,
              endc: tables.endc.length,
              nrdc: tables.nrdc.length,
            },
            image.cards[key].rows,
            `${key}: row counts`,
          );
        }
      } finally {
        await src.close();
      }
    },
  );
}
