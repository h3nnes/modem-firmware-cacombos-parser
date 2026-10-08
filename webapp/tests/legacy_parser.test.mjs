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
