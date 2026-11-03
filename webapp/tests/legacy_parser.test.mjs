// JS API shape:
//   validateCandidate(data: Uint8Array, image, descriptorOffset, { exhaustive }) -> layout | null
//     layout: array of 11 positional fields:
//       [0] comboCount  [1] combosOffset  [2] groupsOffset  [3] antennaCount
//       [4] highestGroup  [5] countByteOffset  [6] comboSize  [7] groupSize
//       [8] descriptorLayout  [9] bandGroupLayout  [10] antennaVa (number|null)
//   makeDescriptor(data, image, descriptorOffset, layout?) -> Descriptor (camelCase fields)
//   classifyDescriptor(data, descriptor) -> "endc" | "nrca" | "lteca" | "unknown"
//   parseDescriptor(path: string, data, descriptor, { discovery, tableKind, detectedTableCount, embeddedPath? })
//     -> object with the exact snake_case key layout
//   parseLegacyModule(record: { name, inner_path }, blob: Uint8Array)
//     -> { metadata, legacy_tables, combinations, components }
//   readComboHeader(data, offset, countByteOffset=27) ->
//     [groupIndices(12), comboFlags, reservedByte1, reservedByte2, numBandEntries, reservedWord, envelopeMask, subsetMask]
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { Fat16Image } from "../js/lib/fat16.js";
import { sourceFor } from "../js/lib/source.js";
import { CORPUS_DIR, corpusAvailable, deepEqualOrdered } from "./helpers.mjs";
import { truncateParse } from "./golden_transform.mjs";
import {
  validateCandidate,
  makeDescriptor,
  classifyDescriptor,
  parseDescriptor,
  parseLegacyModule,
} from "../js/lib/legacy_parser.js";
import { sha256Hex } from "../js/lib/hash.js";

class FlatImage {
  static RECORDS_VA = 0x1000;
  static RECORDS_OFFSET = 64;

  constructor(data) {
    this.data = data;
  }

  vaToOffset(address, size = 1) {
    const offset = FlatImage.RECORDS_OFFSET + address - FlatImage.RECORDS_VA;
    if (address >= FlatImage.RECORDS_VA && 0 <= offset && offset <= this.data.length - size) return offset;
    return null;
  }

  offsetToVa(offset, size = 1) {
    if (0 <= offset && offset <= this.data.length - size) return 0x2000 + offset;
    return null;
  }
}

function component(rat, band, dlClass = 1) {
  const bandCode = rat | (band << 2) | (dlClass << 11);
  const out = new Uint8Array(8);
  new DataView(out.buffer).setUint16(0, bandCode, true);
  return out;
}

function inlineFixture(combos) {
  const data = new Uint8Array(FlatImage.RECORDS_OFFSET + combos.length * 100);
  const dv = new DataView(data.buffer);
  dv.setUint16(0, combos.length, true); // "<HHIHHIII>": count
  dv.setUint16(2, 0, true);             // padding
  dv.setUint32(4, FlatImage.RECORDS_VA, true);
  dv.setUint16(8, 81, true);
  dv.setUint16(10, 0, true);
  dv.setUint32(12, 0, true);
  dv.setUint32(16, 0, true);
  dv.setUint32(20, 0, true);
  combos.forEach((entries, comboIndex) => {
    const offset = FlatImage.RECORDS_OFFSET + comboIndex * 100;
    entries.forEach(([rat, band], position) => {
      data.set(component(rat, band), offset + position * 8);
    });
    data[offset + 96] = 2;
    data[offset + 98] = entries.length;
  });
  return data;
}

test("nr_ca inline descriptor and combos", () => {
  const data = inlineFixture([[[2, 79], [2, 41]], [[2, 78]]]);
  const image = new FlatImage(data);

  const layout = validateCandidate(data, image, 0, { exhaustive: true });
  assert.notEqual(layout, null);
  assert.equal(layout[8], "hi_inline_100");
  assert.equal(layout[0], 2);

  const descriptor = makeDescriptor(data, image, 0, layout);
  assert.equal(classifyDescriptor(data, descriptor), "nrca");
  const parsed = parseDescriptor("660_0_0.mbn", data, descriptor, {
    discovery: "unit test",
    tableKind: "nrca",
    detectedTableCount: 1,
  });
  assert.deepEqual(
    parsed.combinations.map((combo) => combo.combination),
    ["NRCA_n41+n79", "NRCA_n78"],
  );
  assert.equal(parsed.combinations[0].num_band_entries, 2);
  assert.equal(parsed.descriptor.descriptor_layout, "hi_inline_100");
});

test("endc inline descriptor", () => {
  const data = inlineFixture([[[1, 3], [2, 78]]]);
  const image = new FlatImage(data);
  const descriptor = makeDescriptor(data, image, 0);

  assert.equal(classifyDescriptor(data, descriptor), "endc");
  const parsed = parseDescriptor("660_0_0.mbn", data, descriptor, {
    discovery: "unit test",
    tableKind: "endc",
    detectedTableCount: 1,
  });
  const combo = parsed.combinations[0];
  assert.equal(combo.combination, "DC_B3_n78");
  assert.equal(combo.bcs_num, 0);
});

test("nonzero unused component is rejected", () => {
  const data = inlineFixture([[[2, 78]]]);
  data[FlatImage.RECORDS_OFFSET + 8] = 1;
  assert.equal(validateCandidate(data, new FlatImage(data), 0, { exhaustive: true }), null);
});

function magnusComponent(
  rat,
  band,
  dlClass = 1,
  { word0 = 0, dlBw = 14, dlAnt = 3, ulClass = 1, ulBw = 14, ulAnt = 1, feature = 10 } = {},
) {
  const out = new Uint8Array(12);
  const dv = new DataView(out.buffer);
  dv.setUint16(0, word0, true);
  out[2] = rat << 5;
  out[3] = dlClass;
  out[4] = dlBw;
  out[5] = dlAnt;
  out[6] = ulClass;
  out[7] = ulBw;
  out[8] = ulAnt;
  out[9] = feature;
  dv.setUint16(10, band, true);
  return out;
}

function magnusFixture(combos) {
  const data = new Uint8Array(FlatImage.RECORDS_OFFSET + combos.length * 150);
  const dv = new DataView(data.buffer);
  dv.setUint32(0, combos.length, true); // "<II4I>": 32-bit count
  dv.setUint32(4, FlatImage.RECORDS_VA, true);
  combos.forEach((entries, comboIndex) => {
    const offset = FlatImage.RECORDS_OFFSET + comboIndex * 150;
    entries.forEach(([rat, band, dlClass], position) => {
      data.set(magnusComponent(rat, band, dlClass, { word0: position + 3 }), offset + position * 12);
    });
    if (entries.length < 12) {
      const sentinel = offset + entries.length * 12;
      data[sentinel] = 0x02;
      data[sentinel + 1] = 0x00;
    }
    data[offset + 146] = 1;
    data[offset + 147] = entries.length;
    data[offset + 148] = 5;
  });
  return data;
}

test("native 150 endc descriptor and band location", () => {
  const data = magnusFixture([[[1, 39, 1], [2, 79, 3]]]);
  const image = new FlatImage(data);

  const layout = validateCandidate(data, image, 0, { exhaustive: true });
  assert.notEqual(layout, null);
  assert.equal(layout[8], "magnus_inline_150");
  assert.equal(layout[9], "magnus_native_12");

  const descriptor = makeDescriptor(data, image, 0, layout);
  assert.equal(classifyDescriptor(data, descriptor), "endc");
  const parsed = parseDescriptor("625_0_0.mbn", data, descriptor, {
    discovery: "unit test",
    tableKind: "endc",
    detectedTableCount: 1,
  });
  const combo = parsed.combinations[0];
  assert.equal(combo.combination, "DC_B39_n79");
  assert.equal(combo.combination_with_classes, "DC_B39A_n79C");
  assert.equal(combo.bcs_num, 5);
  assert.equal(combo.power_class_raw, 1);
  assert.deepEqual(
    combo.entries.map((entry) => [entry.rat, entry.band]),
    [["LTE", 39], ["NR", 79]],
  );
});

test("bad native 150 sentinel is rejected", () => {
  const data = magnusFixture([[[2, 78, 1]]]);
  data[FlatImage.RECORDS_OFFSET + 12] = 3;
  assert.equal(validateCandidate(data, new FlatImage(data), 0, { exhaustive: true }), null);
});

test("magnus native component exposes the magnus field set", () => {
  const data = magnusFixture([[[1, 39, 1], [2, 79, 3]]]);
  const image = new FlatImage(data);
  const descriptor = makeDescriptor(data, image, 0);

  // parseCombo builds a per-combo view of the record; entries carry the
  // magnus_native_12 key set and decoded component fields.
  const parsed = parseDescriptor("625_0_0.mbn", data, descriptor, {
    discovery: "unit test",
    tableKind: "endc",
    detectedTableCount: 1,
  });
  const [lte, nr] = parsed.combinations[0].entries;
  assert.deepEqual(Object.keys(lte), [
    "group_index",
    "file_offset",
    "file_offset_hex",
    "raw_hex",
    "raw_words",
    "native_word_0_raw",
    "tech_field_raw",
    "tech_field_hex",
    "band_code_raw",
    "band_code_hex",
    "band_code_high",
    "dl_bw_class_code",
    "dl_bw_class",
    "rat_id",
    "rat",
    "band",
    "band_label",
    "band_class_label",
    "dl_bw_code",
    "dl_bandwidth",
    "dl_bandwidth_parts_mhz",
    "ul_present",
    "ul_bw_class_code",
    "ul_bw_class",
    "band_group_layout",
    "field_2_unknown_high",
    "native_word1_prefix_bit",
    "native_word2_prefix_bit",
    "x75_word1_alignment_bit",
    "x75_word2_alignment_bit",
    "ul_bw_code",
    "ul_bandwidth",
    "ul_bandwidth_parts_mhz",
    "dl_antenna_index",
    "dl_antenna",
    "dl_antenna_pattern",
    "ul_antenna_index",
    "ul_antenna",
    "ul_antenna_pattern",
    "feature_byte_raw",
    "feature_byte_hex",
    "feature_word_3_raw",
    "feature_word_3_hex",
    "feature_word_4_raw",
    "feature_word_4_hex",
    "feature_word_5_raw",
    "feature_word_5_hex",
    "position",
  ]);
  assert.equal(lte.native_word_0_raw, 3);
  assert.equal(lte.ul_present, true);
  assert.equal(lte.dl_bw_class, "A");
  assert.equal(lte.dl_bw_class_code, 1);
  assert.equal(lte.ul_bw_class_code, 1);
  assert.equal(lte.dl_bandwidth, "50 MHz");
  assert.equal(lte.band_code_high, 0);
  assert.equal(lte.feature_byte_raw, 10);
  assert.equal(nr.dl_bw_class, "C");
  assert.equal(nr.rat, "NR");
  assert.equal(nr.band_code_raw, 79);
  assert.equal(nr.band_code_hex, "0x004F");
});

// --- golden (corpus-gated): differential parity for "Legacy ELF" records -----

test("legacy ELF records match Python goldens", { skip: !corpusAvailable() }, async () => {
  const corpus = JSON.parse(await readFile(new URL("../goldens/corpus.json", import.meta.url)));
  let checked = 0;
  for (const [img, recs] of Object.entries(corpus)) {
    const legacyRecs = recs.filter((r) => r.generation === "Legacy ELF");
    if (legacyRecs.length === 0) continue;
    const src = await sourceFor(join(CORPUS_DIR, img));
    const fat = new Fat16Image(src);
    await fat.init();
    const byPath = new Map((await fat.walk()).map((e) => [e.path, e]));
    const imgTag = img.replace(/\.[^.]+$/, "").slice(0, 40).replaceAll(" ", "_");
    for (const rec of legacyRecs) {
      const entry = byPath.get(rec.inner_path);
      assert.ok(entry, `${img}: missing ${rec.inner_path}`);
      const blob = await fat.readFile(entry);
      const parsed = parseLegacyModule({ name: rec.name, inner_path: rec.inner_path }, blob);
      const goldenPath = `../goldens/parse/${imgTag}__${rec.name.replaceAll("/", "_")}.json`;
      const expected = JSON.parse(await readFile(new URL(goldenPath, import.meta.url)));
      deepEqualOrdered(truncateParse(parsed), expected, `${img}/${rec.name}`);
      checked++;
    }
    await src.close();
  }
  assert.equal(checked, 47);
});

test("module_sha256 reuses record.sha256 when present, hashes only as fallback (legacy)", { skip: !corpusAvailable() }, async () => {
  const corpus = JSON.parse(await readFile(new URL("../goldens/corpus.json", import.meta.url)));
  let checked = 0;
  for (const [img, recs] of Object.entries(corpus)) {
    const legacyRecs = recs.filter((r) => r.generation === "Legacy ELF");
    if (legacyRecs.length === 0) continue;
    const src = await sourceFor(join(CORPUS_DIR, img));
    const fat = new Fat16Image(src);
    await fat.init();
    const byPath = new Map((await fat.walk()).map((e) => [e.path, e]));
    for (const rec of legacyRecs) {
      const entry = byPath.get(rec.inner_path);
      assert.ok(entry, `${img}: missing ${rec.inner_path}`);
      const blob = await fat.readFile(entry);
      const withDigest = parseLegacyModule({ ...rec, sha256: "aa".repeat(32) }, blob);
      assert.equal(withDigest.metadata.module_sha256, "aa".repeat(32), `${img}/${rec.name}`);
      const without = parseLegacyModule({ name: rec.name, inner_path: rec.inner_path }, blob);
      assert.equal(without.metadata.module_sha256, sha256Hex(blob), `${img}/${rec.name}`);
      checked++;
    }
    await src.close();
  }
  assert.ok(checked > 0, "expected corpus legacy records");
});
