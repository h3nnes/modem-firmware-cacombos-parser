// MTK Stage-B tests: grammar decode, feature resolution, profile decode, LTE
// CA row tables, supported-band lists, the Tensor secondary decoder, the
// flat/MD800 loader and the scanMtk record envelope. Synthetic fixtures are
// hand-built grid/CDF/flat images (corpus-independent, builders in
// mtk_fixtures.mjs); the corpus-gated section diffs decodeMtkSummary and
// scanMtk against the python reference (tests/mtk_ref_report.py) for both
// sample images and pins the qcom fall-through.
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { gzipSync } from "node:zlib";
import { join } from "node:path";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { writeFile, unlink } from "node:fs/promises";
import {
  BANDMAP_LEN,
  BANDMAP_PREFIX,
  BW_FAMILIES,
  LTE_UL_ABSENT,
  LTE_WEIGHT_PREFIX,
  NR_UL_ABSENT_CANON,
  NR_WEIGHT_PREFIX,
  SUPPORTED_BAND_PAD,
  SUPPORTED_BAND_SLOTS,
  UniversalError,
  Reporter,
  Image,
  Bank,
  TensorCdfLoader,
  GrammarParser,
  MtkCombo,
  LteComponent,
  NrComponent,
  NrCC,
  classify,
  comboKey,
  dedupExact,
  guiFamilyCounts,
  discoverRomTables,
  scanLteRowsBank,
  chooseLteBank,
  discoverSupportedBandList,
  decodeTensorSecondary,
} from "../js/lib/mtk_universal.js";
import { scanMtk, decodeMtkSummary, selectLoader } from "../js/lib/mtk_scan.js";
import { scanSource } from "../js/lib/analyzer.js";
import { unwrapBytes } from "../js/lib/mtk_containers.js";
import { nr15Probe, headerGeometry } from "../js/lib/mtk_nr15.js";
import { sha256HexAsync } from "../js/lib/hash.js";
import { sha384HexSync } from "../js/lib/mtk_hash.js";
import { sourceFor } from "../js/lib/source.js";
import { CORPUS_DIR, corpusAvailable, deepEqualOrdered } from "./helpers.mjs";
import {
  concatParts,
  u16le,
  u32le,
  writeU32,
  writeU16,
  romArea,
  descriptorMatrix,
  capImage,
  lteRowImage,
  mtkPartition,
  buildGridImage,
  buildFlatImage,
} from "./mtk_fixtures.mjs";

// --- combo row model ---------------------------------------------------------

test("mtk combo model: classify, dedup and gui_family_counts match python", () => {
  const lte = new LteComponent(1, 0, LTE_UL_ABSENT, [4]);
  const nr1 = new NrComponent(1, 0, NR_UL_ABSENT_CANON, [new NrCC(30, 2, 5, null, null)]);
  const nr2 = new NrComponent(257, 1, 1, [new NrCC(120, 4, 100, 2, 60)]);
  const endc = new MtkCombo([lte], [nr1]);
  const nrca = new MtkCombo([], [nr1]);
  const nrdc = new MtkCombo([], [nr1, nr2]);
  const lteOnly = new MtkCombo([lte], []);
  assert.deepEqual(classify([endc, nrca, nrdc, lteOnly], 1).map((x) => x.length), [1, 2, 1]);
  assert.equal(comboKey(endc),
    comboKey(new MtkCombo([new LteComponent(1, 0, 6, [4])], [new NrComponent(1, 0, 0x1c, [new NrCC(30, 2, 5, null, null)])])));
  assert.notEqual(comboKey(endc), comboKey(nrca));
  assert.deepEqual(guiFamilyCounts([endc, nrca, nrdc, lteOnly]), { endc: 1, nr_sa: 1, nrca: 0, nrdc: 1, lte: 1 });
  // keep-first dedup over structurally equal rows
  const dup = dedupExact([endc, new MtkCombo([new LteComponent(1, 0, 6, [4])], [nr1]), nrca]);
  assert.equal(dup.length, 2);
  assert.equal(dup[0], endc);
});

// --- grammar -----------------------------------------------------------------

test("mtk grammar: descriptor invariants reject malformed records", () => {
  const { rom } = romArea();
  const tables = discoverRomTables(rom, new Reporter());
  const loader = { tables, _candidateArrays: new Map() };
  const parser = new GrammarParser(loader, new Reporter());
  const drdi = new Uint8Array(0x200);
  const im = new Image(0x6b000000, 0, 0, 0x200, 0x6b000000, drdi, "t");
  const VA = (r) => 0x6b000000 + r;
  const seed = (mutate) => {
    const d = new Uint8Array(0x100);
    // NR descriptor at 0x00: 2 records (band 1 ul 0x1c dl 0; band 3 ul 1 dl 1), 3 rows
    writeU32(d, 0x00, 2); writeU32(d, 0x04, VA(0x10)); writeU32(d, 0x08, 3); writeU32(d, 0x0c, VA(0x20));
    writeU16(d, 0x10, 1); d[0x12] = 0x1c; d[0x13] = 0;
    writeU16(d, 0x14, 3); d[0x16] = 1; d[0x17] = 1;
    d.set([1, 0, 1, 0, 1, 2, 1, 2, 2], 0x20);
    mutate(d);
    drdi.set(d, 0);
  };
  const probe = (mutate) => {
    seed(mutate);
    return parser._decodeDesc(im, VA(0x00), true);
  };
  assert.ok(probe(() => {}) !== null, "baseline descriptor must decode");
  assert.equal(probe((d) => writeU32(d, 0x00, 0)), null, "count 0 rejected");
  assert.equal(probe((d) => writeU32(d, 0x00, 17)), null, "count 17 rejected");
  assert.equal(probe((d) => writeU16(d, 0x10, 1025)), null, "band > 1024 rejected");
  assert.equal(probe((d) => { d[0x13] = 12; }), null, "DL class without weight rejected");
  assert.equal(probe((d) => writeU32(d, 0x08, 5)), null, "variant_count % units != 0 rejected");
  assert.equal(probe((d) => { d[0x20] = 5; }), null, "invalid NR SCS enum rejected");
  assert.equal(probe((d) => writeU32(d, 0x0c, VA(0x200))), null, "FSC pointer outside image rejected");
  // LTE descriptor: band-map index 0 maps to band 0 (void) -> rejected; an FSC
  // DL-MIMO status byte of 4 is outside the code-proven alphabet.
  const lte = new Uint8Array(0x40);
  writeU32(lte, 0x00, 1); writeU32(lte, 0x04, VA(0x10)); writeU32(lte, 0x08, 1); writeU32(lte, 0x0c, VA(0x14));
  lte[0x10] = 0; lte[0x11] = LTE_UL_ABSENT; lte[0x12] = 0;
  lte[0x14] = 0; lte[0x15] = 1;
  drdi.set(lte, 0);
  assert.equal(parser._decodeDesc(im, VA(0x00), false), null, "LTE band 0 rejected");
  lte[0x10] = 1; lte[0x14] = 0; lte[0x15] = 4;
  drdi.set(lte, 0);
  assert.equal(parser._decodeDesc(im, VA(0x00), false), null, "LTE FSC status 4 rejected");
});

// --- synthetic end-to-end decode ---------------------------------------------

test("mtk decode: synthetic grid image decodes ENDC + LTE rows with dedup", async () => {
  const fixture = buildGridImage();
  const parts = await unwrapBytes(fixture.image, "synthetic.img");
  const summary = await decodeMtkSummary(parts);
  assert.equal(summary.loader, "grid");
  assert.equal(summary.capability_bank, "0x6b000000");
  assert.equal(summary.capability_bank_index, 0);
  assert.equal(summary.lte_bank, "0x6b100000");
  assert.equal(summary.lte_bank_index, 1);
  // Candidate run of 5 (two shared nodes) decodes 5 identical rows -> 1.
  const p = summary.profiles[0];
  assert.equal(p.candidate_array.count, 5);
  assert.equal(p.candidate_array.nr_descriptors, 5);
  assert.equal(p.candidate_array.lte_descriptors, 5);
  assert.equal(p.decoded_rows, 1);
  assert.deepEqual(p.kinds, { endc: 1, nrca: 0, lte: 0 });
  assert.deepEqual(p.gui_counts, { endc: 1, nr_sa: 0, nrca: 0, nrdc: 0, lte: 0 });
  assert.equal(p.feature_tables_found, 3);
  assert.equal(p.feature_resolution.order_hint, "DL_FIRST");
  assert.deepEqual(p.feature_pair_search,
    { tables: 3, dl_admissible: 2, ul_admissible: 3, max_dl_id: 3, max_ul_id: 1, capped: false });
  // Exact decoded row: LTE b1 + NR n1/n3 resolved through the feature tables.
  const row = summary._perProfile.get(0)[0];
  assert.deepEqual([row.lte[0].band, row.lte[0].dl_class, row.lte[0].ul_class, row.lte[0].dl_mimo], [1, 0, 6, [4]]);
  assert.deepEqual([row.nr[0].band, row.nr[0].dl_class, row.nr[0].ul_class], [1, 0, 0x1c]);
  assert.deepEqual([row.nr[0].ccs[0].scs_khz, row.nr[0].ccs[0].dl_mimo, row.nr[0].ccs[0].dl_bw_mhz], [30, 2, 5]);
  assert.equal(row.nr[0].ccs[0].ul_mimo, null);
  assert.deepEqual([row.nr[1].band, row.nr[1].dl_class, row.nr[1].ul_class], [3, 1, 1]);
  assert.deepEqual(row.nr[1].ccs.map((c) => [c.scs_khz, c.dl_mimo, c.dl_bw_mhz, c.ul_mimo, c.ul_bw_mhz]),
    [[15, 4, 10, 1, 15], [30, 8, 15, 1, 15]]);
  // LTE CA rows: 5 identical rows dedup to 1 for the profile.
  assert.deepEqual(summary.lte_profiles, { 0: 1 });
  assert.equal(summary.lte_union_exact_rows, 1);
  assert.deepEqual(summary.gui_counts, { endc: 1, nr_sa: 0, nrca: 0, nrdc: 0, lte: 0 });
  assert.deepEqual(summary.union,
    { exact_rows: 1, kinds: { endc: 1, nrca: 0, lte: 0 }, complete: true, unresolved_profiles: [] });
  // Validation issue stream: codes in python emission order.
  assert.deepEqual(summary.validation.issues.map((i) => i.code),
    ["rom_tables", "grid_loader", "capability_bank", "candidate_array",
      "feature_orientation", "lte_row_table", "lte_bank"]);
  assert.equal(summary.validation.issues.find((i) => i.code === "lte_row_table").context.row_layout, "legacy32");
  assert.deepEqual(summary.supported_bands, {});
});

test("mtk decode: two valid candidate subruns keep the longest and warn", async () => {
  const fixture = buildGridImage({ splitRun: true });
  const parts = await unwrapBytes(fixture.image, "synthetic.img");
  const summary = await decodeMtkSummary(parts);
  const p = summary.profiles[0];
  assert.equal(p.candidate_array.count, 4);
  assert.equal(p.candidate_array.raw_pointer_run_count, 4);
  const warn = summary.validation.issues.find((i) => i.code === "candidate_subrun_discarded");
  assert.ok(warn, "candidate_subrun_discarded warning emitted");
  assert.deepEqual(warn.context.subrun_lengths, [4, 4]);
  assert.equal(p.decoded_rows, 1);
});

test("mtk decode: broken profile fails soft with a tool-mtk warning", async () => {
  const fixture = buildGridImage({ brokenProfile1: true });
  const parts = await unwrapBytes(fixture.image, "synthetic.img");
  const summary = await decodeMtkSummary(parts);
  assert.equal(summary.profiles.length, 1);
  assert.equal(summary.profiles[0].profile, 0);
  assert.equal(summary._warnings.length, 1);
  assert.equal(summary._warnings[0].tool, "mtk");
  assert.match(summary._warnings[0].message, /LTE DL MIMO status 3 is unsupported\/rejected/);
  assert.match(summary._warnings[0].message, /profile skipped/);
});

test("mtk decode: no resolvable feature pair aborts with the python error", async () => {
  // Make every table fail DL-side admissibility (absent object at the
  // referenced DL feature ids): no (DL, UL) assignment survives, matching
  // python's "no capability profile could be resolved" abort.
  const { rom, matrixOff } = romArea();
  const capVa = 0x6b000000;
  const capLen = 0x200;
  const capSrc = 0x1000;
  const drdi = new Uint8Array(0x1400);
  const cap = capImage({ vaBase: capVa });
  drdi.set(cap.im, capSrc);
  for (const base of [capSrc + cap.dlObj, capSrc + cap.ulObj + 3, capSrc + cap.ulLongObj]) {
    // objects 1 and 2 become absent (mimo_status 3)
    drdi[base] = 3; drdi[base + 1] = 20; drdi[base + 2] = 1;
    drdi[base + 3] = 3; drdi[base + 4] = 20; drdi[base + 5] = 1;
  }
  descriptorMatrix(rom, matrixOff, [
    { src: capSrc, va: capVa, len: capLen },
    { src: capSrc + capLen, va: capVa, len: 16 },
    { src: capSrc + capLen + 16, va: 0x6b100000, len: 16 },
    { src: capSrc + capLen + 32, va: 0x6b100000, len: 16 },
  ]);
  const parts = await unwrapBytes(mtkPartition([
    { name: "md1rom", data: rom },
    { name: "md1drdi", data: drdi },
  ]), "synthetic.img");
  await assert.rejects(
    () => decodeMtkSummary(parts),
    (err) => err instanceof UniversalError
      && /no capability profile could be resolved/.test(err.message),
  );
});

// --- LTE row tables ----------------------------------------------------------

test("mtk lte rows: extended36 layout wins when flagged rows are present", async () => {
  const { rom, matrixOff } = romArea();
  const capVa = 0x6b000000;
  const lteVa = 0x6b100000;
  const capSrc = 0x1000;
  const capLen = 0x200;
  const lteSrc = 0x1200;
  const lteLen = 0x100;
  const drdi = new Uint8Array(lteSrc + lteLen + 16);
  drdi.set(capImage({ vaBase: capVa }).im, capSrc);
  drdi.set(lteRowImage({ vaBase: lteVa, stride: 36, mimo: 3 }).im, lteSrc);
  descriptorMatrix(rom, matrixOff, [
    { src: capSrc, va: capVa, len: capLen },
    { src: capSrc + capLen, va: capVa, len: 16 },
    { src: lteSrc, va: lteVa, len: lteLen },
    { src: lteSrc + lteLen, va: lteVa, len: 16 },
  ]);
  const parts = await unwrapBytes(mtkPartition([
    { name: "md1rom", data: rom },
    { name: "md1drdi", data: drdi },
  ]), "synthetic.img");
  const summary = await decodeMtkSummary(parts);
  const issue = summary.validation.issues.find((i) => i.code === "lte_row_table");
  assert.ok(issue, "lte_row_table found");
  assert.equal(issue.context.row_layout, "extended36");
  assert.equal(issue.context.row_stride, 36);
  assert.deepEqual(summary.lte_profiles, { 0: 1 });
});

test("mtk lte rows: MIMO status byte 4 maps to 8 layers", async () => {
  const { rom, matrixOff } = romArea();
  const capVa = 0x6b000000;
  const lteVa = 0x6b100000;
  const capSrc = 0x1000;
  const capLen = 0x200;
  const lteSrc = 0x1200;
  const lteLen = 0x100;
  const drdi = new Uint8Array(lteSrc + lteLen + 16);
  drdi.set(capImage({ vaBase: capVa }).im, capSrc);
  // mimo byte 4 = "8Rx allowed for forward compatibility" — the corpus never
  // exercises it, so the 2/3/4->{2,4,8} projection is pinned here.
  drdi.set(lteRowImage({ vaBase: lteVa, stride: 32, mimo: 4 }).im, lteSrc);
  descriptorMatrix(rom, matrixOff, [
    { src: capSrc, va: capVa, len: capLen },
    { src: capSrc + capLen, va: capVa, len: 16 },
    { src: lteSrc, va: lteVa, len: lteLen },
    { src: lteSrc + lteLen, va: lteVa, len: 16 },
  ]);
  const parts = await unwrapBytes(mtkPartition([
    { name: "md1rom", data: rom },
    { name: "md1drdi", data: drdi },
  ]), "synthetic.img");
  const summary = await decodeMtkSummary(parts);
  assert.deepEqual(summary.lte_profiles, { 0: 1 });
  const row = summary._lteProfiles.get(0)[0];
  assert.deepEqual([row.lte[0].band, row.lte[0].dl_class, row.lte[0].ul_class], [1, 0, LTE_UL_ABSENT]);
  assert.deepEqual(row.lte[0].dl_mimo, [8]);
});

test("mtk lte rows: runs shorter than four entries are not tables", () => {
  const { rom } = romArea();
  const tables = discoverRomTables(rom, new Reporter());
  const lteVa = 0x6b100000;
  const drdi = new Uint8Array(0x200);
  drdi.set(lteRowImage({ vaBase: lteVa, rows: 3 }).im, 0);
  const rep = new Reporter();
  const bank = new Bank(lteVa, [new Image(lteVa, 0, 0, 0x100, lteVa, drdi, "b")], 1);
  const rows = scanLteRowsBank(bank, tables, rep);
  assert.equal(rows.size, 0);
  assert.equal(rep.issues.some((i) => i.code === "lte_row_table"), false);
});

test("mtk lte rows: choose_lte_bank keeps every bank and ranks the primary", () => {
  const { rom } = romArea();
  const tables = discoverRomTables(rom, new Reporter());
  const drdi = new Uint8Array(0x400);
  drdi.set(lteRowImage({ vaBase: 0x6b100000, rows: 6 }).im, 0x000);
  drdi.set(lteRowImage({ vaBase: 0x6b200000, rows: 4 }).im, 0x200);
  const banks = [
    new Bank(0x6b100000, [new Image(0x6b100000, 0, 0x000, 0x100, 0x6b100000, drdi, "b0")], 0),
    new Bank(0x6b200000, [new Image(0x6b200000, 0, 0x200, 0x100, 0x6b200000 - 0x200, drdi, "b1")], 1),
  ];
  const loader = { banks, tables };
  const rep = new Reporter();
  const [primary, merged] = chooseLteBank(loader, banks[0], rep);
  assert.ok(primary, "primary bank selected");
  assert.equal(primary.bank_va, 0x6b100000);
  assert.deepEqual([...merged.keys()], [0]);
  assert.equal(merged.get(0).length, 1);
  assert.deepEqual(loader.lte_rows_by_bank[0].get(0).length, 6);
  assert.deepEqual(loader.lte_rows_by_bank[1].get(0).length, 4);
  const info = rep.issues.find((i) => i.code === "lte_bank");
  assert.equal(info.context.banks, 2);
  assert.equal(info.context.per_bank[0].primary, true);
  const rep2 = new Reporter();
  const emptyLoader = { banks: [], tables };
  const [, empty] = chooseLteBank(emptyLoader, null, rep2);
  assert.equal(empty.size, 0);
  assert.ok(rep2.issues.some((i) => i.code === "lte_bank_missing"));
});

// --- supported bands ---------------------------------------------------------

test("mtk supported bands: 40-slot padded list with ROM pointer proof", () => {
  const rom = new Uint8Array(0x100);
  const drdi = new Uint8Array(0xd0);
  const bankVa = 0x6b200000;
  const im = new Image(bankVa, 0, 0x40, 0x90, bankVa - 0x40, drdi, "t");
  const bands = [1, 3, 5, 8, 19, 28, 38, 40, 41, 48, 77, 78];
  const vals = [];
  for (const b of bands) vals.push(...u16le(b));
  for (let i = bands.length; i < SUPPORTED_BAND_SLOTS; i++) vals.push(...u16le(SUPPORTED_BAND_PAD));
  drdi.set(new Uint8Array(vals), 0x40);
  writeU32(rom, 0x10, bankVa);
  const rep = new Reporter();
  const bank = { images: [im], bank_va: bankVa, table_index: 3 };
  const out = discoverSupportedBandList({ rom }, bank, "LTE", rep);
  assert.equal(out.rat, "LTE");
  assert.equal(out.bank_index, 3);
  assert.deepEqual(out.profiles[0].bands, bands);
  assert.equal(out.profiles[0].relative_off, "0x0");
  assert.equal(out.profiles[0].runtime_va, "0x6b200000");
  assert.deepEqual(out.profiles[0].rom_pointer_refs, ["0x10"]);
  assert.deepEqual(out.union, bands);
  assert.deepEqual(out.intersection, bands);
  assert.equal(out.profiles_consistent, true);
  // Too few used slots is rejected.
  const drdi2 = new Uint8Array(0xd0);
  const short = [];
  for (const b of [1, 2, 3]) short.push(...u16le(b));
  for (let i = 3; i < SUPPORTED_BAND_SLOTS; i++) short.push(...u16le(SUPPORTED_BAND_PAD));
  drdi2.set(new Uint8Array(short), 0x40);
  const im2 = new Image(bankVa, 0, 0x40, 0x90, bankVa - 0x40, drdi2, "t2");
  assert.deepEqual(
    discoverSupportedBandList({ rom }, { images: [im2], bank_va: bankVa, table_index: 3 }, "NR", new Reporter()),
    {},
  );
  // Without a ROM pointer the table is not proved.
  assert.deepEqual(
    discoverSupportedBandList({ rom: new Uint8Array(0x100) }, bank, "NR", new Reporter()),
    {},
  );
});

// --- tensor secondary --------------------------------------------------------

// Synthetic split-CDF fixture: bank 5 carries LTE CA rows, bank 6 the ordinary
// FR1 capability profile (aliased pointers), bank 8 the FR2 secondary
// catalogue rooted by ROM pointer words. All pointers carry the 0x60000000
// alias, exactly like Tensor images.
function buildTensorFixture({ withSecondary = true } = {}) {
  const ALIAS = TensorCdfLoader.ALIAS;
  const bounds = Array.from({ length: 11 }, (_, i) => 0x100000 + i * 0x10000);
  const bank5 = bounds[5];
  const bank6 = bounds[6];
  const bank8 = bounds[8];
  const { rom, matrixOff } = romArea();
  const data = new Uint8Array(0x600);
  const lteSrc = 0x000;
  const capSrc = 0x100;
  const fr2Src = 0x200;
  data.set(lteRowImage({ vaBase: bank5, alias: ALIAS }).im, lteSrc);
  data.set(capImage({ vaBase: bank6, alias: ALIAS }).im, capSrc);
  let candArrR = 0;
  let dlFeatR = 0;
  let ulFeatR = 0;
  if (withSecondary) {
    const im = new Uint8Array(0x400);
    const VA8 = (r) => (bank8 + r + ALIAS) >>> 0;
    const nodes = 33; // 32 ENDC rows + 1 single-FR2 (excluded)
    const arrOff = 0;
    const nodeOff = arrOff + (nodes + 1) * 4;
    const nrDesc = nodeOff + nodes * 16;
    const nrRec = nrDesc + 0x10;
    const nrFsc = nrRec + 4;
    const lteDesc = nrFsc + 6 + 2;
    const lteRec = lteDesc + 0x10;
    const lteFsc = lteRec + 3;
    const dlObj = lteFsc + 2 + 6;
    const dlTab = dlObj + 24 + 4;
    const ulObj = dlTab + 36 + 4;
    const ulTab = ulObj + 24 + 4;
    for (let k = 0; k < nodes; k++) {
      const off = nodeOff + k * 16;
      const hasLte = k < nodes - 1;
      writeU32(im, arrOff + 4 * k, VA8(off));
      writeU32(im, off, 0);
      writeU32(im, off + 4, 0);
      writeU32(im, off + 8, hasLte ? VA8(lteDesc) : 0);
      writeU32(im, off + 12, VA8(nrDesc));
    }
    writeU32(im, arrOff + nodes * 4, 0); // zero terminator
    // NR descriptor: band 257, UL omitted (0xff), DL class 6 (FR2 weight 2).
    writeU32(im, nrDesc, 1); writeU32(im, nrDesc + 4, VA8(nrRec));
    writeU32(im, nrDesc + 8, 2); writeU32(im, nrDesc + 12, VA8(nrFsc));
    writeU16(im, nrRec, 257); im[nrRec + 2] = 0xff; im[nrRec + 3] = 6;
    im.set([1, 0, 1, 1, 0, 1], nrFsc);
    // LTE descriptor (band 1, UL absent, class 0).
    writeU32(im, lteDesc, 1); writeU32(im, lteDesc + 4, VA8(lteRec));
    writeU32(im, lteDesc + 8, 1); writeU32(im, lteDesc + 12, VA8(lteFsc));
    im[lteRec] = 1; im[lteRec + 1] = LTE_UL_ABSENT; im[lteRec + 2] = 0;
    im[lteFsc] = 0; im[lteFsc + 1] = 1;
    // Feature pointer arrays (8 entries each, absent entry first).
    im.set([3, 20, 1], dlObj);
    for (let k = 1; k < 8; k++) im.set([0, 0, 1], dlObj + 3 * k);
    for (let k = 0; k < 8; k++) writeU32(im, dlTab + 4 * k, VA8(dlObj + 3 * k));
    writeU32(im, dlTab + 32, 0);
    im.set([3, 20, 1], ulObj);
    for (let k = 1; k < 8; k++) im.set([0, 2, 1], ulObj + 3 * k);
    for (let k = 0; k < 8; k++) writeU32(im, ulTab + 4 * k, VA8(ulObj + 3 * k));
    writeU32(im, ulTab + 32, 0);
    candArrR = arrOff;
    dlFeatR = dlTab;
    ulFeatR = ulTab;
    data.set(im, fr2Src);
  }
  // ROM roots for the secondary decoder (aliased bank-8 addresses); the
  // dictionary area ends at matrixOff, which is free space here.
  const romRoots = rom.slice();
  writeU32(romRoots, matrixOff, (bank8 + candArrR + ALIAS) >>> 0);
  writeU32(romRoots, matrixOff + 4, (bank8 + dlFeatR + ALIAS) >>> 0);
  writeU32(romRoots, matrixOff + 8, (bank8 + ulFeatR + ALIAS) >>> 0);
  // CDF header: 0x30000 bytes; digests at 164, bounds, then 641 slot offsets.
  const header = new Uint8Array(0x30000);
  const digOff = 164;
  const bndOff = digOff + 640 * 48;
  const slotOff = bndOff + 11 * 4;
  [[slotOff, 641 * 4], [bndOff, 11 * 4], [digOff, 640 * 48]].forEach(([o, s], i) => {
    writeU32(header, 4 + i * 8, o);
    writeU32(header, 8 + i * 8, s);
  });
  bounds.forEach((b, i) => writeU32(header, bndOff + 4 * i, b));
  // Slot map: three live slots, everything else zero-length stubs.
  // Slot map: three live slots at their data offsets, everything else
  // zero-length stubs at the running position. The first live slot starts at
  // offset 0, so stub banks never see a nonzero slot after their first stub.
  const live = new Map([[320, [lteSrc, 0x100]], [384, [capSrc, 0x100]], [512, [fr2Src, 0x400]]]);
  const offsets = [];
  let pos = 0;
  for (let s = 0; s < 640; s++) {
    if (live.has(s)) {
      const [src, size] = live.get(s);
      offsets[s] = src;
      pos = src + size;
    } else {
      offsets[s] = pos;
    }
  }
  offsets[640] = pos;
  offsets.forEach((o, s) => writeU32(header, slotOff + 4 * s, o));
  // Slot digests: every slot is SHA-384 validated before any byte is trusted.
  const hexBytes = (s) => new Uint8Array((s.match(/../g) ?? []).map((h) => parseInt(h, 16)));
  for (let s = 0; s < 640; s++) {
    const dig = sha384HexSync(data.subarray(offsets[s], offsets[s + 1]));
    header.set(hexBytes(dig), digOff + s * 48);
  }
  return { rom: romRoots, header, data };
}

test("mtk tensor secondary: FR2 bank decodes with omitted-UL normalization", async () => {
  const { rom, header, data } = buildTensorFixture();
  const summary = await decodeMtkSummary({ rom, drdi: header, drdi_data: data, report: {} });
  assert.equal(summary.loader, "tensor");
  assert.equal(summary.capability_bank_index, 6);
  assert.deepEqual(summary.physical_lte_profiles, { 5: { 0: 1 } });
  assert.equal(summary.secondary_profiles.length, 1);
  const s = summary.secondary_profiles[0];
  assert.equal(s.bank_index, 8);
  assert.equal(s.profile, 0);
  assert.equal(s.decoded_rows, 1);
  assert.equal(s.expanded_rows, 33);
  assert.equal(s.excluded_single_fr2, 1);
  assert.equal(s.candidate_count, 33);
  assert.deepEqual(s.kinds, { endc: 1, nrca: 0, lte: 0 });
  assert.equal(s.lte_count, 1);
  const row = summary._secondary[0].combos[0];
  assert.equal(row.nr[0].band, 257);
  assert.equal(row.nr[0].ul_class, NR_UL_ABSENT_CANON);
  assert.equal(row.nr[0].ccs[0].dl_bw_mhz, 5);
  assert.equal(row.nr[0].ccs[0].ul_mimo, null);
});

test("mtk tensor secondary: unprovable bank warns and leaves extraction intact", async () => {
  const { rom, header, data } = buildTensorFixture({ withSecondary: false });
  const loader = await TensorCdfLoader.create(rom, header, data, new Reporter());
  const rep = new Reporter();
  assert.deepEqual(decodeTensorSecondary(loader, 8, rep), []);
  assert.ok(rep.issues.some((i) => i.code === "tensor_secondary_unresolved"));
  const summary = await decodeMtkSummary({ rom, drdi: header, drdi_data: data, report: {} });
  assert.equal(summary.loader, "tensor");
  assert.equal(summary.profiles.length, 1);
  assert.ok(summary.validation.issues.some((i) => i.code === "tensor_secondary_unresolved"));
});

// --- flat (MD800) loader ------------------------------------------------------

function pythonRefAvailable() {
  // The python reference + interpreter: needed for the flat differential (the
  // reference parser has a FlatLoader, so flat IS differentially testable).
  return spawnSync("python3", ["-c", "pass"]).status === 0
    && existsSync(join(CORPUS_DIR, "mtk-drdi-combo-parser"));
}

test("mtk flat loader: relocation proof claims the pointer-run image and decodes it", async () => {
  const fixture = buildFlatImage();
  const parts = await unwrapBytes(fixture.image, "flat.img");
  const [loader, attempts] = await selectLoader(parts);
  assert.equal(loader.name, "flat");
  // Family order: grid is tried (and recorded) before flat; nr15 never
  // activates without its marker/trailer.
  assert.deepEqual(attempts, [
    { loader: "grid", accepted: false, evidence: "dense-run score 0", reason: "no modern bank descriptors found" },
    { loader: "flat", accepted: true, evidence: "2 runtime pointer runs, 1 relocations proved by grammar" },
  ]);
  const summary = await decodeMtkSummary(parts);
  assert.equal(summary.loader, "flat");
  assert.equal(summary.capability_bank, "0x6b000000");
  assert.equal(summary.capability_bank_index, 0);
  assert.equal(summary.profiles.length, 1);
  const p = summary.profiles[0];
  // No ROM profile table in the fixture: profiles are numbered from 1.
  assert.equal(p.profile, 1);
  assert.equal(p.image.label, "flat/profile1");
  assert.equal(p.candidate_array.count, 64);
  assert.equal(p.candidate_array.source, "loader_hint");
  assert.equal(p.candidate_array.raw_pointer_run_count, 64);
  assert.equal(p.decoded_rows, 1);
  assert.deepEqual(p.kinds, { endc: 1, nrca: 0, lte: 0 });
  assert.deepEqual(summary.gui_counts, { endc: 1, nr_sa: 0, nrca: 0, nrdc: 0, lte: 0 });
  // The LTE row pointer array was recovered by the row_bias 4 probe: 64
  // identical rows dedup to one in the union, 64 stay per-array.
  assert.deepEqual(summary.lte_profiles, { 0: 64 });
  assert.equal(summary.lte_union_exact_rows, 1);
  assert.deepEqual(summary.validation.issues.map((i) => i.code),
    // Two rom_tables entries: the failed grid attempt's BaseLoader constructor
    // records its dictionary discovery before the grid rejection (python does
    // the same — pinned by the flat differential below).
    ["rom_tables", "rom_tables", "flat_loader", "capability_bank", "candidate_array",
      "feature_orientation", "lte_table"]);
  const scan = await scanMtk(
    { size: fixture.image.length, read: async (off, l) => fixture.image.subarray(off, off + l) },
    "flat.img",
  );
  assert.equal(scan.records.length, 1);
  assert.equal(scan.records[0].name, "Bank 0 profile 1");
  assert.equal(scan.records[0].mtk.loader, "flat");
  assert.deepEqual(scan.records[0].mtk.counts, { endc: 1, nr_sa: 0, nrca: 0, nrdc: 0, lte: 0 });
});

test("mtk flat differential: decodeMtkSummary equals python for the synthetic flat image", { skip: !pythonRefAvailable() }, async () => {
  const fixture = buildFlatImage();
  const path = join(tmpdir(), `mtk-flat-fixture-${process.pid}.img`);
  await writeFile(path, fixture.image);
  try {
    const expected = pythonRef(path);
    const parts = await unwrapBytes(fixture.image, "flat.img");
    const summary = await decodeMtkSummary(parts);
    const live = { ...summary };
    for (const k of Object.keys(live)) if (k.startsWith("_")) delete live[k];
    deepEqualOrdered(live, expected, "synthetic flat image");
  } finally {
    await unlink(path).catch(() => {});
  }
});

// --- NR15 probe + loader family order -----------------------------------------

// CHECK_HEADER v6 trailer + indexed NR15 bandwidth enum, per headerGeometry.
function nr15TrailerRom({ drdiLen = 0x80, corrupt = null } = {}) {
  const rom = new Uint8Array(0x400);
  // Indexed pattern: (index, u16 bw) pairs + count terminator.
  const tbl = BW_FAMILIES.nr15_13;
  tbl.forEach((bw, i) => writeU32(rom, 0x10 + i * 4, i | (bw << 16)));
  writeU32(rom, 0x10 + tbl.length * 4, tbl.length);
  const off = rom.length - 0x200;
  for (let i = 0; i < "CHECK_HEADER".length; i++) rom[off + i] = "CHECK_HEADER".charCodeAt(i);
  writeU32(rom, off + 12, 6);
  writeU32(rom, off + 0x16c, 0x20); // DRDI source offset inside the rom image
  writeU32(rom, off + 0x170, drdiLen);
  writeU32(rom, rom.length - 4, 0x200);
  if (corrupt === "size") writeU32(rom, rom.length - 4, 0x201);
  if (corrupt === "pattern") writeU32(rom, 0x10 + tbl.length * 4, 99);
  return rom;
}

test("mtk nr15 probe: CHECK_HEADER trailer + indexed enum geometry", () => {
  const drdi = new Uint8Array(0x80);
  assert.equal(nr15Probe(nr15TrailerRom(), drdi), true);
  // Wrong trailer size field, broken pattern terminator, wrong DRDI length.
  assert.equal(nr15Probe(nr15TrailerRom({ corrupt: "size" }), drdi), false);
  assert.equal(nr15Probe(nr15TrailerRom({ corrupt: "pattern" }), drdi), false);
  assert.equal(nr15Probe(nr15TrailerRom(), new Uint8Array(0x81)), false);
  // No trailer at all.
  assert.equal(nr15Probe(nr15TrailerRom().subarray(0, 0x100), drdi), false);
  // headerGeometry returns [trailer offset, source offset] on success.
  const [off, source] = headerGeometry(nr15TrailerRom(), 0x80);
  assert.equal(off, 0x400 - 0x200);
  assert.equal(source, 0x20);
});

test("mtk loader order: nr15 activates before grid only on its markers, corpus stays grid-only", async () => {
  // A MOLY.NR15.-marked rom with a modern20 enum (no nr15 enum): the nr15
  // attempt is recorded FIRST and fails, then grid — with a descriptor
  // matrix — accepts. This pins the family order of selectLoader.
  const grid = buildGridImage();
  const markedRom = concatParts([grid.rom, [..."MOLY.NR15."].map((c) => c.charCodeAt(0))]);
  const markedParts = await unwrapBytes(mtkPartition([
    { name: "md1rom", data: markedRom },
    { name: "md1drdi", data: grid.drdi },
  ]), "marked.img");
  {
    const [loader, attempts] = await selectLoader(markedParts);
    assert.equal(loader.name, "grid");
    assert.deepEqual(attempts.map((a) => a.loader), ["nr15", "grid"]);
    assert.equal(attempts[0].accepted, false);
    assert.match(attempts[0].reason, /indexed 13-entry bandwidth enum/);
    assert.equal(attempts[1].accepted, true);
  }
  // Unmarked grid image: NO nr15 attempt is recorded (activation silence).
  {
    const parts = await unwrapBytes(grid.image, "grid.img");
    const [loader, attempts] = await selectLoader(parts);
    assert.equal(loader.name, "grid");
    assert.deepEqual(attempts, [
      { loader: "grid", accepted: true, evidence: attempts[0].evidence },
    ]);
    assert.match(attempts[0].evidence, /descriptor dense-run score/);
  }
  // Unmatched rom (marker present but nothing else): every family recorded,
  // in order, and the total-rejection message keeps the contract.
  {
    const rom = new Uint8Array(0x100);
    rom.set([..."xMOLY.NR15.y"].map((c) => c.charCodeAt(0)), 0x10);
    const parts = { rom, drdi: new Uint8Array(0x40), drdi_data: null };
    await assert.rejects(
      () => selectLoader(parts),
      (err) => {
        assert.ok(err instanceof UniversalError);
        assert.match(err.message, /^no container loader accepted this image; attempts: /);
        assert.match(err.message, /"loader": "nr15"/);
        assert.match(err.message, /"loader": "grid"/);
        assert.match(err.message, /"loader": "flat"/);
        return true;
      },
    );
  }
});

// --- scanMtk -----------------------------------------------------------------

test("mtk scanMtk: records, envelope and monotonic progress on the synthetic image", async () => {
  const fixture = buildGridImage();
  const buf = fixture.image;
  const source = { size: buf.length, read: async (off, len) => buf.subarray(off, off + len) };
  const progress = [];
  const out = await scanMtk(source, "synthetic.img", () => false, {
    onScanProgress: (info) => progress.push(info),
  });
  assert.ok(out, "mtk scan recognized the synthetic image");
  assert.equal(out.records.length, 1);
  const rec = out.records[0];
  assert.equal(rec.generation, "MediaTek DRDI");
  assert.equal(rec.name, "Bank 0 profile 0");
  assert.equal(rec.inner_path, "bank0/profile0");
  assert.equal(rec.size, 0x200);
  assert.equal(rec.hwid, 0);
  assert.equal(rec.fsid, 0);
  assert.equal(rec.bid, 0);
  assert.equal(rec.external, true);
  assert.equal(rec.source_path, "synthetic.img");
  assert.equal(rec.lte_combos, null);
  assert.equal(rec.nr_combos, null);
  assert.equal(rec.sha256,
    await (async () => {
      const parts = await unwrapBytes(buf, "synthetic.img");
      return sha256HexAsync(parts.drdi.slice(fixture.capSrc, fixture.capSrc + fixture.capLen));
    })());
  assert.deepEqual(rec.mtk, {
    bankIndex: 0,
    profile: 0,
    loader: "grid",
    layout: null,
    imageMeta: {
      bank_va: "0x6b000000",
      source_offset: "0x1000",
      length: 0x200,
      relocation: "0x6afff000",
      alias: "0x0",
    },
    counts: { endc: 1, nr_sa: 0, nrca: 0, nrdc: 0, lte: 1 },
  });
  assert.deepEqual(out.warnings, []);
  // Progress: (0, total) first, non-decreasing, ends at total.
  assert.ok(progress.length >= 2);
  assert.deepEqual(progress[0], { stage: "mtk", done: 0, total: 1 });
  assert.deepEqual(progress[progress.length - 1], { stage: "mtk", done: 1, total: 1 });
  for (let i = 1; i < progress.length; i++) {
    assert.ok(progress[i].done >= progress[i - 1].done);
    assert.ok(progress[i].done <= progress[i].total);
  }
});

test("mtk scanMtk: tensor packaging yields capability, secondary and bank-only records", async () => {
  const { rom, header, data } = buildTensorFixture();
  const buf = mtkPartition([
    { name: "md1rom", data: rom },
    { name: "md1drdi_hdr", data: header },
    { name: "md1drdi_data", data },
  ]);
  const source = { size: buf.length, read: async (off, len) => buf.subarray(off, off + len) };
  const out = await scanMtk(source, "tensor.img", () => false, {});
  assert.ok(out, "tensor image scanned");
  assert.deepEqual(out.records.map((r) => `${r.mtk.bankIndex}/${r.mtk.profile}`), ["5/0", "6/0", "8/0"]);
  const [lteRec, capRec, secRec] = out.records;
  assert.deepEqual(lteRec.mtk.counts, { endc: 0, nr_sa: 0, nrca: 0, nrdc: 0, lte: 1 });
  assert.equal(lteRec.mtk.layout, "legacy32");
  assert.deepEqual(capRec.mtk.counts, { endc: 1, nr_sa: 0, nrca: 0, nrdc: 0, lte: 0 });
  assert.deepEqual(secRec.mtk.counts, { endc: 1, nr_sa: 0, nrca: 0, nrdc: 0, lte: 1 });
  assert.equal(secRec.mtk.loader, "tensor");
  assert.deepEqual(out.warnings, []);
});

test("mtk scanSource: slotted between apple and FAT16 without disturbing other paths", async () => {
  const fixture = buildGridImage();
  const buf = fixture.image;
  const source = { size: buf.length, read: async (off, len) => buf.subarray(off, off + len) };
  const { records } = await scanSource(source, "synthetic_mtk.img", {});
  assert.equal(records.length, 1);
  assert.equal(records[0].generation, "MediaTek DRDI");
  assert.equal(records[0].mtk.bankIndex, 0);
});

test("mtk scanMtk: fall-through pins for non-MTK inputs", async () => {
  const scan = (buf, name) => scanMtk(
    { size: buf.length, read: async (off, len) => buf.subarray(off, off + len) }, name,
  );
  // Random bytes: no gate match.
  const random = new Uint8Array(0x10000).map((_, i) => (i * 37 + 11) & 0xff);
  assert.equal(await scan(random, "random.bin"), null);
  // Gzip WITHOUT a modem role token in the name: never decompressed.
  const gz = gzipSync(new Uint8Array(4096).fill(7));
  assert.equal(await scan(gz, "unrelated-gzip.bin"), null);
  // Gzip WITH a role token but no modem inside: unwrap finds no set -> null.
  assert.equal(await scan(gz, "md1drdi.bin"), null);
  // Fake ext4 head (0x53ef at 1080) with garbage: parse failure -> null.
  const fakeExt4 = new Uint8Array(4096).fill(0xaa);
  fakeExt4[1080] = 0x53; fakeExt4[1081] = 0xef;
  assert.equal(await scan(fakeExt4, "whatever.img"), null);
});

// --- corpus-gated differential ----------------------------------------------

const mtkImages = [
  "Oppo_Find_X10_Pro_Max_5G_PMX110-modem.img",
  "mtk_pocox8pro_d8500u_modem.img",
];

function python3Available() {
  // Probe-and-skip convention (bandsort/diag tests): a machine without python3
  // skips the differentials instead of failing them.
  return spawnSync("python3", ["-c", "pass"]).status === 0;
}

const mtkDifferentialAvailable = () =>
  python3Available() && mtkImages.every((img) => existsSync(join(CORPUS_DIR, img)));

function pythonRef(imgPath) {
  const ref = join(CORPUS_DIR, "mtk-drdi-combo-parser");
  const res = spawnSync("python3", [new URL("./mtk_ref_report.py", import.meta.url).pathname, ref, imgPath], {
    encoding: "utf8",
    maxBuffer: 512 * 1024 * 1024,
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: "1" },
  });
  if (res.status !== 0) throw new Error(`mtk_ref_report.py failed: ${res.stderr.slice(0, 2000)}`);
  return JSON.parse(res.stdout);
}

for (const img of mtkImages) {
  const imgPath = join(CORPUS_DIR, img);

  test(`mtk differential: decodeMtkSummary equals python summary for ${img}`, { skip: !mtkDifferentialAvailable() }, async () => {
    const expected = pythonRef(imgPath);
    const src = await sourceFor(imgPath);
    try {
      const parts = await unwrapBytes(await src.read(0, src.size), img);
      const summary = await decodeMtkSummary(parts);
      const live = { ...summary };
      for (const k of Object.keys(live)) if (k.startsWith("_")) delete live[k];
      deepEqualOrdered(live, expected, img);
    } finally {
      await src.close();
    }
  });

  test(`mtk differential: scanMtk records and envelope for ${img}`, { skip: !mtkDifferentialAvailable() }, async () => {
    const expected = pythonRef(imgPath);
    const src = await sourceFor(imgPath);
    try {
      const progress = [];
      const out = await scanMtk(src, img, () => false, {
        onScanProgress: (info) => progress.push(info),
      });
      assert.ok(out, "mtk scan handled the corpus image");
      const capIndex = expected.capability_bank_index;
      assert.equal(out.records.length, expected.profiles.length);
      for (const p of expected.profiles) {
        const rec = out.records.find((r) => r.mtk.profile === p.profile && r.mtk.bankIndex === capIndex);
        assert.ok(rec, `record for profile ${p.profile}`);
        assert.equal(rec.name, `Bank ${capIndex} profile ${p.profile}`);
        assert.equal(rec.generation, "MediaTek DRDI");
        assert.equal(rec.inner_path, p.image.label);
        assert.equal(rec.size, p.image.length);
        assert.equal(rec.sha256, expected.profile_sha256[String(p.profile)]);
        assert.equal(rec.hwid, 0);
        assert.equal(rec.fsid, 0);
        assert.equal(rec.bid, 0);
        assert.equal(rec.external, true);
        assert.equal(rec.source_path, img);
        assert.equal(rec.lte_combos, null);
        assert.equal(rec.nr_combos, null);
        assert.equal(rec.mtk.loader, expected.loader);
        assert.equal(rec.mtk.bankIndex, capIndex);
        assert.equal(rec.mtk.profile, p.profile);
        assert.equal(rec.mtk.imageMeta.bank_va, p.image.bank_va);
        assert.equal(rec.mtk.imageMeta.source_offset, p.image.source_offset);
        assert.equal(rec.mtk.imageMeta.length, p.image.length);
        assert.equal(rec.mtk.imageMeta.relocation, p.image.relocation);
        assert.equal(rec.mtk.imageMeta.alias, p.image.alias);
        assert.ok(rec.mtk.layout === null || ["legacy32", "extended36"].includes(rec.mtk.layout));
        assert.deepEqual(rec.mtk.counts, {
          endc: p.gui_counts.endc,
          nr_sa: p.gui_counts.nr_sa,
          nrca: p.gui_counts.nrca,
          nrdc: p.gui_counts.nrdc,
          lte: expected.lte_profiles[String(p.profile)] ?? 0,
        });
      }
      // Records sorted by (bank, profile); progress monotonic.
      for (let i = 1; i < out.records.length; i++) {
        const a = out.records[i - 1].mtk;
        const b = out.records[i].mtk;
        assert.ok(a.bankIndex < b.bankIndex || (a.bankIndex === b.bankIndex && a.profile < b.profile));
      }
      assert.equal(progress[0].stage, "mtk");
      assert.equal(progress[0].done, 0);
      assert.equal(progress[progress.length - 1].done, progress[progress.length - 1].total);
      for (let i = 1; i < progress.length; i++) {
        assert.ok(progress[i].done >= progress[i - 1].done);
      }
      assert.deepEqual(out.warnings, []);
    } finally {
      await src.close();
    }
  });
}

test("mtk negative: corpus images must not activate nr15 or flat (grid wins with a single attempt)", { skip: !mtkDifferentialAvailable() }, async () => {
  for (const img of mtkImages) {
    const imgPath = join(CORPUS_DIR, img);
    const src = await sourceFor(imgPath);
    try {
      const parts = await unwrapBytes(await src.read(0, src.size), img);
      const [loader, attempts] = await selectLoader(parts);
      assert.equal(loader.name, "grid", img);
      assert.equal(attempts.length, 1, `${img}: exactly one (grid) attempt`);
      assert.equal(attempts[0].loader, "grid");
      assert.equal(attempts[0].accepted, true);
    } finally {
      await src.close();
    }
  }
});

test("mtk differential: qcom corpus image falls through untouched", { skip: !corpusAvailable() }, async () => {
  const src = await sourceFor(join(CORPUS_DIR, "radio.img"));
  try {
    assert.equal(await scanMtk(src, "radio.img"), null);
  } finally {
    await src.close();
  }
});
