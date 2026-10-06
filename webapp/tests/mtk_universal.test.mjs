// MTK universal parser Stage-A tests: ROM dictionary discovery (BW families,
// NR/LTE weights, band map nearest-copy rule), grid loader clustering/stub
// rules, tensor split-CDF geometry + SHA-384 validation, and a corpus-gated
// probe over both sample modem images. Synthetic tests are corpus-independent.
import test from "node:test";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import assert from "node:assert/strict";
import {
  BW_FAMILIES,
  BANDMAP_LEN,
  BANDMAP_PREFIX,
  FEATURE_SENTINEL,
  LTE_WEIGHT_PREFIX,
  LTE_WEIGHTS_EXPECTED,
  LTE_UL_ABSENT,
  MAX_CLASS_WEIGHT,
  NR_UL_ABSENT_CANON,
  NR_WEIGHT_PREFIX,
  SUPPORTED_BAND_PAD,
  SUPPORTED_BAND_SLOTS,
  SCS,
  DL_MIMO,
  UL_MIMO,
  VA_LO,
  VA_HI,
  VERSION,
  UniversalError,
  Reporter,
  RomTables,
  Image,
  Bank,
  GridLoader,
  TensorCdfLoader,
  discoverRomTables,
  findAll,
  readNrWeights,
  bwSites,
  lteWeightSites,
  bandMapSites,
  u16,
  u32,
} from "../js/lib/mtk_universal.js";
import { sha384HexAsync, sha384HexSync, crc32 } from "../js/lib/mtk_hash.js";
import { CORPUS_DIR } from "./helpers.mjs";

const hex = (n) => "0x" + n.toString(16);

function fill(len, seed) {
  // Stride-7 pattern: cannot contain the 03 14 01 feature sentinel, and the
  // table bytes stay clear of grid-descriptor shapes.
  const a = new Uint8Array(len);
  for (let i = 0; i < len; i++) a[i] = (0x40 + i * 7 + seed) & 0xff;
  return a;
}

function concatParts(parts) {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

const u16le = (n) => new Uint8Array([n & 0xff, (n >>> 8) & 0xff]);
const u32le = (n) => new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
const bytesFrom = (arr) => new Uint8Array(arr);

// LTE weights + terminator, BW enum, NR weights (immediately after the enum),
// band map — the layout that resolves through the "NR right after enum" rule.
function romTablesArea({ family = "modern20", byte95 = 0x00, mapFiller = 0x22, mapAt = null, nrAt = null } = {}) {
  const tbl = BW_FAMILIES[family];
  const enumLen = tbl.length * 2;
  const lteOff = 16;
  const bwOff = 24;
  const nrOff = nrAt ?? bwOff + enumLen; // NR weights start at bw_end
  const mapOff = mapAt ?? nrOff + tbl.length + 1;
  const parts = [];
  const put = (off, bytes) => { parts.push([off, bytes]); };
  const total = mapOff + BANDMAP_LEN + 16;
  const rom = new Uint8Array(total);
  const write = (off, bytes) => rom.set(bytes, off);
  write(lteOff, concatParts([LTE_WEIGHT_PREFIX, new Uint8Array([0, 0])]));
  write(bwOff, concatParts(tbl.map(u16le)));
  write(nrOff, concatParts([NR_WEIGHT_PREFIX, new Uint8Array([0xff])]));
  const map = new Uint8Array(BANDMAP_LEN);
  map.set(BANDMAP_PREFIX, 0);
  map.fill(mapFiller, BANDMAP_PREFIX.length);
  map[BANDMAP_LEN - 1] = byte95;
  write(mapOff, map);
  return { rom, lteOff, bwOff, nrOff, mapOff };
}

// Second, detached LTE table + NR pair for the legacy14 resolution ladder.
function detachedLteNr(rom, lteOff) {
  rom.set(LTE_WEIGHT_PREFIX, lteOff);
  rom[lteOff + 6] = 0;
  rom[lteOff + 7] = 0;
  rom.set(NR_WEIGHT_PREFIX, lteOff + 8);
  rom[lteOff + 8 + NR_WEIGHT_PREFIX.length] = 0xff;
}

test("mtk universal: module constants match the python reference", () => {
  assert.equal(VERSION, "0.4-universal");
  assert.deepEqual([...BW_FAMILIES.modern20], [5, 10, 15, 20, 25, 30, 40, 50, 60, 80, 100, 200, 400, 35, 45, 70, 90, 800, 1600, 2000]);
  assert.deepEqual([...BW_FAMILIES.legacy14], [5, 10, 15, 20, 25, 30, 40, 50, 60, 80, 90, 100, 200, 400]);
  assert.deepEqual([...LTE_WEIGHTS_EXPECTED], [1, 2, 2, 3, 4, 5]);
  assert.equal(MAX_CLASS_WEIGHT, 32);
  assert.equal(LTE_UL_ABSENT, 6);
  assert.equal(NR_UL_ABSENT_CANON, 0x1c);
  assert.equal(VA_LO, 0x60000000);
  assert.equal(VA_HI, 0x80000000);
  assert.equal(SUPPORTED_BAND_SLOTS, 40);
  assert.equal(SUPPORTED_BAND_PAD, 0xfffd);
  assert.deepEqual(SCS, { 0: 15, 1: 30, 2: 60, 3: 120, 4: 240 });
  assert.deepEqual(DL_MIMO, { 0: 2, 1: 4, 2: 8 });
  assert.deepEqual(UL_MIMO, { 0: 1, 1: 2, 2: 4 });
  assert.deepEqual([...FEATURE_SENTINEL], [0x03, 0x14, 0x01]);
  assert.deepEqual([...BANDMAP_PREFIX], [...Array(49).keys(), ...Array.from({ length: 7 }, (_, i) => 65 + i)]);
});

test("mtk universal: helper readers pin struct.unpack_from bounds parity", () => {
  assert.throws(() => u32(new Uint8Array(3), 0), /unpack_from requires a buffer of at least 4 bytes for unpacking 4 bytes at offset 0 \(actual buffer size is 3\)/);
  assert.throws(() => u16(new Uint8Array(2), 1), /unpack_from requires a buffer of at least 3 bytes for unpacking 2 bytes at offset 1 \(actual buffer size is 2\)/);
  const buf = new Uint8Array([0x78, 0x56, 0x34, 0x12]);
  assert.equal(u32(buf, 0), 0x12345678);
  assert.equal(u16(buf, 0), 0x5678);
});

test("mtk universal: findAll locates every non-overlapping occurrence", () => {
  const buf = new Uint8Array([1, 2, 1, 2, 1, 2]);
  assert.deepEqual(findAll(buf, new Uint8Array([1, 2])), [0, 2, 4]);
  assert.deepEqual(findAll(buf, new Uint8Array([1, 2]), 2), [0, 2]);
  assert.deepEqual(findAll(buf, new Uint8Array([9])), []);
});

test("mtk universal: NR weight reads stop at 0xFF/oversize and trim trailing zeros", () => {
  const rom = concatParts([NR_WEIGHT_PREFIX, new Uint8Array([0, 0, 0, 0xff, 1])]);
  assert.deepEqual(readNrWeights(rom, 0), [...NR_WEIGHT_PREFIX]);
  assert.deepEqual(readNrWeights(rom, 0, 96), [...NR_WEIGHT_PREFIX]);
  // Trailing zeros below the prefix length are dropped, kept values stay.
  const wide = concatParts([NR_WEIGHT_PREFIX, new Uint8Array([0, 0, 33, 9])]);
  assert.deepEqual(readNrWeights(wide, 0), [...NR_WEIGHT_PREFIX]);
  const kept = concatParts([NR_WEIGHT_PREFIX, new Uint8Array([0, 5])]);
  assert.deepEqual(readNrWeights(kept, 0), [...NR_WEIGHT_PREFIX, 0, 5]);
  const over = concatParts([NR_WEIGHT_PREFIX, new Uint8Array([0, 0, 0, 33])]);
  assert.deepEqual(readNrWeights(over, 0), [...NR_WEIGHT_PREFIX]);
  // Interior zeros are kept (they are unused class slots).
  const interior = new Uint8Array([...NR_WEIGHT_PREFIX.slice(0, 4), 0, ...NR_WEIGHT_PREFIX.slice(5), 0xff]);
  assert.deepEqual(readNrWeights(interior, 0), [...NR_WEIGHT_PREFIX.slice(0, 4), 0, ...NR_WEIGHT_PREFIX.slice(5)]);
  // cap bounds the read.
  assert.deepEqual(readNrWeights(concatParts([NR_WEIGHT_PREFIX, new Uint8Array(64).fill(1)]), 0, 13), [...NR_WEIGHT_PREFIX, 1]);
});

test("mtk universal: rom table discovery on a modern20 layout", () => {
  const { rom, bwOff, nrOff, lteOff, mapOff } = romTablesArea();
  const rep = new Reporter();
  const tables = discoverRomTables(rom, rep);
  assert.equal(tables.bw_family, "modern20");
  assert.equal(tables.bw.length, 20);
  assert.deepEqual(tables.nr_weights, [...NR_WEIGHT_PREFIX]);
  assert.deepEqual(tables.lte_weights, [...LTE_WEIGHTS_EXPECTED]);
  assert.equal(tables.bw_off, bwOff);
  assert.equal(tables.nr_weights_off, nrOff);
  assert.equal(tables.lte_weights_off, lteOff);
  assert.equal(tables.band_map_off, mapOff);
  assert.equal(tables.band_map_off_alternatives.length, 0);
  assert.equal(tables.nr_weights.length, 12);
  assert.equal(tables.bw[10], 100);
  const absent = tables.nr_ul_absent;
  assert.ok(absent.has(NR_UL_ABSENT_CANON));
  assert.ok(absent.has(0xff));
  assert.ok(!absent.has(0));
  assert.ok(!absent.has(3));
  const info = rep.issues.find((i) => i.code === "rom_tables");
  assert.ok(info, "rom_tables issue reported");
  assert.equal(info.level, "info");
  assert.equal(info.context.bw_family, "modern20");
  assert.equal(info.context.band_map_alternatives.length, 0);
  const d = tables.asDict();
  assert.equal(d.nr_class_table_len, 12);
  assert.equal(d.bw_off, hex(bwOff));
  assert.deepEqual(d.nr_ul_absent_low_values, Array.from({ length: 12 }, (_, i) => 12 + i));
});

test("mtk universal: legacy14 family resolves through the detached-LTE ladder", () => {
  const { rom, bwOff } = romTablesArea({ family: "legacy14" });
  // legacy14 needs a zero u16 terminator right after the enum, and NR weights
  // sit 8 bytes past a detached LTE table instead of directly after the enum.
  const { rom: rebuilt } = (() => {
    const tbl = BW_FAMILIES.legacy14;
    const bwOff2 = 16;
    const r = new Uint8Array(512);
    r.set(concatParts(tbl.map(u16le)), bwOff2);
    r.set(new Uint8Array([0, 0]), bwOff2 + tbl.length * 2); // short-family terminator
    detachedLteNr(r, 100);
    const map = new Uint8Array(BANDMAP_LEN);
    map.set(BANDMAP_PREFIX, 0);
    map.fill(0x22, BANDMAP_PREFIX.length);
    map[BANDMAP_LEN - 1] = 0;
    r.set(map, 200);
    return { rom: r };
  })();
  void bwOff;
  const tables = discoverRomTables(rebuilt, new Reporter());
  assert.equal(tables.bw_family, "legacy14");
  assert.equal(tables.bw.length, 14);
  assert.deepEqual(tables.nr_weights, [...NR_WEIGHT_PREFIX]);
  assert.deepEqual(tables.lte_weights, [...LTE_WEIGHTS_EXPECTED]);
  assert.equal(tables.nr_weights_off, 108);
  assert.equal(tables.lte_weights_off, 100);
});

test("mtk universal: unterminated legacy14 is refused, dual families are refused", () => {
  // legacy14 without the zero terminator is not a site.
  const noTerm = new Uint8Array(256);
  noTerm.set(concatParts(BW_FAMILIES.legacy14.map(u16le)), 0);
  noTerm.set(new Uint8Array([9, 9]), BW_FAMILIES.legacy14.length * 2);
  assert.throws(() => discoverRomTables(noTerm, new Reporter()), (e) => {
    assert.ok(e instanceof UniversalError);
    assert.equal(e.message, "no known MTK bandwidth enum found in md1rom. Known families: modern20(20 entries), legacy14(14 entries). A new family must be added explicitly rather than inferred.");
    return true;
  });
  // Both full families in one rom is ambiguous.
  const both = new Uint8Array(512);
  both.set(concatParts(BW_FAMILIES.modern20.map(u16le)), 0);
  both.set(concatParts(BW_FAMILIES.legacy14.map(u16le)), 64);
  both.set(new Uint8Array([0, 0]), 64 + BW_FAMILIES.legacy14.length * 2);
  detachedLteNr(both, 200);
  const map = new Uint8Array(BANDMAP_LEN);
  map.set(BANDMAP_PREFIX, 0);
  map[BANDMAP_LEN - 1] = 0xff;
  both.set(map, 320);
  assert.throws(() => discoverRomTables(both, new Reporter()), (e) => {
    assert.equal(e.message, "md1rom matches more than one bandwidth enum family: ['legacy14', 'modern20']");
    return true;
  });
});

test("mtk universal: band map byte95 rule and nearest-copy selection", () => {
  const makeMap = (byte95, filler) => {
    const map = new Uint8Array(BANDMAP_LEN);
    map.set(BANDMAP_PREFIX, 0);
    map.fill(filler, BANDMAP_PREFIX.length);
    map[BANDMAP_LEN - 1] = byte95;
    return map;
  };
  // byte95 must be 0x00 or 0xff.
  const bad95 = romTablesArea({ byte95: 0x33 });
  assert.throws(() => discoverRomTables(bad95.rom, new Reporter()), (e) => {
    assert.equal(e.message, "no validated 96-byte LTE internal-band map found in md1rom");
    return true;
  });
  // Two valid copies: the copy nearest the enum wins, the other is an alternative.
  const near = romTablesArea({ mapAt: 140 });
  const rom = new Uint8Array(600);
  rom.set(near.rom);
  rom.set(makeMap(0xff, 0x33), 400);
  const tables = discoverRomTables(rom, new Reporter());
  assert.equal(tables.band_map_off, 140);
  assert.deepEqual(tables.band_map_off_alternatives, [400]);
  assert.ok(Math.abs(tables.band_map_off - near.bwOff) < Math.abs(400 - near.bwOff));
  // Near copy absent -> the far copy is still discovered.
  const rom2 = new Uint8Array(600);
  rom2.set(near.rom.subarray(0, 140));
  rom2.set(makeMap(0xff, 0x33), 400);
  const t2 = discoverRomTables(rom2, new Reporter());
  assert.equal(t2.band_map_off, 400);
  assert.deepEqual(t2.band_map_off_alternatives, []);
});

test("mtk universal: site helpers filter candidates", () => {
  const { rom, bwOff } = romTablesArea();
  const sites = bwSites(rom);
  assert.equal(sites.length, 1);
  assert.equal(sites[0][0], "modern20");
  assert.equal(sites[0][1], bwOff);
  assert.equal(lteWeightSites(rom).length, 1);
  assert.equal(bandMapSites(rom).length, 1);
  assert.deepEqual([...rom.subarray(16, 22)], [...LTE_WEIGHT_PREFIX]);
});

// ---------------------------------------------------------------------------
// Grid loader fixtures
// ---------------------------------------------------------------------------

const VA_A = 0x62000000;
const VA_B = 0x62100000;
const DESC_OFF = 0x200;

function descriptor(sfHi, src, va, ln) {
  return concatParts([u32le(((sfHi << 28) | src) >>> 0), u32le(va), u32le(ln)]);
}

// bank: [{ src, ln }] -> descriptor block at consecutive offsets.
function gridRom({ banks, tables = true }) {
  const descBytes = [];
  for (const bank of banks) {
    for (const d of bank.descs) descBytes.push(descriptor(3, d.src, bank.va, d.ln));
  }
  const tablesArea = tables ? romTablesArea() : { rom: new Uint8Array(DESC_OFF) };
  const rom = new Uint8Array(DESC_OFF + descBytes.length * 12 + 64);
  rom.set(tablesArea.rom.subarray(0, Math.min(tablesArea.rom.length, DESC_OFF)));
  descBytes.forEach((d, i) => rom.set(d, DESC_OFF + i * 12));
  const drdi = fill(0x1000, 3);
  drdi.set(FEATURE_SENTINEL, 0x150);
  drdi.set(FEATURE_SENTINEL, 0x180);
  drdi.set(FEATURE_SENTINEL, 0x950);
  return { rom, drdi };
}

const STANDARD_BANKS = [
  { va: VA_A, descs: [{ src: 0x100, ln: 0x100 }, { src: 0x300, ln: 0x80 }, { src: 0x500, ln: 0x200 }, { src: 0x800, ln: 0x20 }] },
  { va: VA_B, descs: [{ src: 0x900, ln: 0x100 }, { src: 0xb00, ln: 0x80 }, { src: 0xc00, ln: 0x200 }, { src: 0xf00, ln: 0x20 }] },
];

test("mtk universal: grid descriptor scan, probe and dense clustering", () => {
  const { rom, drdi } = gridRom({ banks: STANDARD_BANKS });
  const hits = GridLoader.descriptorHits(rom, drdi);
  assert.deepEqual(hits.map((h) => h[0]), Array.from({ length: 8 }, (_, i) => DESC_OFF + i * 12));
  assert.equal(GridLoader.probe(rom, drdi), 8);
  // A descriptor ending exactly at EOF is included; an incomplete trailing word is not.
  const romEof = new Uint8Array(DESC_OFF + 12);
  romEof.set(descriptor(3, 0, VA_A, 0x40), DESC_OFF);
  assert.deepEqual(GridLoader.descriptorHits(romEof, fill(0x100, 1)).map((h) => h[0]), [DESC_OFF]);
  // sf hi nibble must be 3, va inside the DRDI window, ln within bounds.
  assert.deepEqual(GridLoader.descriptorHits(concatParts([descriptor(2, 0, VA_A, 0x40)]), fill(0x100, 1)), []);
  assert.deepEqual(GridLoader.descriptorHits(concatParts([descriptor(3, 0, 0x50000000, 0x40)]), fill(0x100, 1)), []);
  assert.deepEqual(GridLoader.descriptorHits(concatParts([descriptor(3, 0, VA_A, 0x8)]), fill(0x100, 1)), []);
  assert.deepEqual(GridLoader.descriptorHits(concatParts([descriptor(3, 0xf0, VA_A, 0x40)]), fill(0x100, 1)), []);
});

test("mtk universal: grid loader builds banks with stub-prefixed live profiles", () => {
  const { rom, drdi } = gridRom({ banks: STANDARD_BANKS });
  const rep = new Reporter();
  const loader = new GridLoader(rom, drdi, rep);
  assert.equal(loader.columns, 4);
  assert.equal(loader.descriptor_table_off, DESC_OFF);
  assert.equal(loader.banks.length, 2);
  const [a, b] = loader.banks;
  assert.equal(a.bank_va, VA_A);
  assert.equal(a.table_index, 0);
  assert.deepEqual(a.live_profiles, [0, 1, 2]);
  assert.equal(a.images.length, 3);
  assert.equal(b.table_index, 1);
  assert.deepEqual(b.live_profiles, [0, 1, 2]);
  const im0 = a.images[0];
  assert.equal(im0.profile, 0);
  assert.equal(im0.source_offset, 0x100);
  assert.equal(im0.length, 0x100);
  assert.equal(im0.relocation, (VA_A - 0x100) >>> 0);
  assert.equal(im0.label, "bank0/profile0");
  assert.equal(im0.alias, 0);
  assert.equal(im0.end_source, 0x200);
  assert.equal(im0.end_va, (VA_A + 0x100) >>> 0);
  assert.equal(im0.resolve(VA_A), 0x100);
  assert.equal(im0.resolve(VA_A + 0xff, 1), 0x1ff);
  assert.equal(im0.resolve(VA_A + 0x100), null);
  assert.equal(im0.containsVa(VA_A + 0x42), true);
  assert.equal(im0.u32(VA_A), u32(drdi, 0x100));
  assert.equal(im0.u16(VA_A), u16(drdi, 0x100));
  assert.deepEqual([...im0.read(VA_A, 4)], [...drdi.subarray(0x100, 0x104)]);
  assert.deepEqual(im0.toDict(), {
    bank_va: hex(VA_A), profile: 0, source_offset: hex(0x100), length: 0x100,
    relocation: hex((VA_A - 0x100) >>> 0), alias: "0x0", label: "bank0/profile0",
  });
  assert.deepEqual(loader.banks[1].toDict().live_profiles, [0, 1, 2]);
  const info = rep.issues.find((i) => i.code === "grid_loader");
  assert.equal(info.context.banks, 2);
  assert.deepEqual(info.context.live_counts, [3, 3]);
  assert.equal(info.context.columns, 4);
  void romTablesArea;
});

test("mtk universal: grid loader drops incoherent column counts (first-most-common wins)", () => {
  const banks = [
    { va: VA_A, descs: STANDARD_BANKS[0].descs },
    { va: VA_B, descs: [{ src: 0x900, ln: 0x40 }, { src: 0xa00, ln: 0x100 }] },
  ];
  const { rom, drdi } = gridRom({ banks });
  const loader = new GridLoader(rom, drdi, new Reporter());
  assert.equal(loader.columns, 4);
  assert.equal(loader.banks.length, 1);
  assert.equal(loader.banks[0].bank_va, VA_A);
});

test("mtk universal: grid loader error paths", () => {
  // No descriptors at all.
  const { rom: emptyRom, drdi } = gridRom({ banks: STANDARD_BANKS });
  const bare = new Uint8Array(DESC_OFF + 64);
  bare.set(emptyRom.subarray(0, DESC_OFF));
  assert.throws(() => new GridLoader(bare, drdi, new Reporter()), (e) => {
    assert.equal(e.message, "no modern bank descriptors found");
    return true;
  });
  // Scattered hits never form a >= 4 cluster.
  const scattered = gridRom({
    banks: [{ va: VA_A, descs: [{ src: 0x100, ln: 0x100 }] }],
  });
  const scatteredRom = new Uint8Array(0x800);
  scatteredRom.set(scattered.rom);
  scatteredRom.set(descriptor(3, 0x100, VA_A, 0x40), 0x400);
  scatteredRom.set(descriptor(3, 0x200, VA_A, 0x40), 0x600);
  scatteredRom.set(descriptor(3, 0x300, VA_A, 0x40), 0x610);
  assert.throws(() => new GridLoader(scatteredRom, scattered.drdi, new Reporter()), (e) => {
    assert.equal(e.message, "raw bank-descriptor hits did not form a coherent table");
    return true;
  });
  // Live profile after a stub breaks the observed MTK contract.
  const afterStub = gridRom({
    banks: [{ va: VA_A, descs: [{ src: 0x100, ln: 0x100 }, { src: 0x300, ln: 0x20 }, { src: 0x400, ln: 0x100 }, { src: 0x600, ln: 0x20 }] }],
  });
  assert.throws(() => new GridLoader(afterStub.rom, afterStub.drdi, new Reporter()), (e) => {
    assert.equal(e.message, `bank ${hex(VA_A)} has live profile 2 after a stub; descriptor geometry is likely wrong`);
    return true;
  });
});

test("mtk universal: capability bank selection by sentinel ranking + proof hook", () => {
  const { rom, drdi } = gridRom({ banks: STANDARD_BANKS });
  const rep = new Reporter();
  const loader = new GridLoader(rom, drdi, rep);
  const containsSentinel = (im) => {
    for (let i = im.source_offset; i + FEATURE_SENTINEL.length <= im.end_source; i++) {
      if (drdi[i] === 3 && drdi[i + 1] === 0x14 && drdi[i + 2] === 1) return true;
    }
    return false;
  };
  const prove = (im) => (containsSentinel(im) ? 5 : null);
  const cap = loader.capabilityBank(prove);
  assert.equal(cap.bank_va, VA_A);
  const info = rep.issues.find((i) => i.code === "capability_bank");
  assert.equal(info.context.bank_va, hex(VA_A));
  assert.equal(info.context.proof_profile, 0);
  assert.equal(info.context.proof_candidate_count, 5);
  assert.ok(info.context.sentinel_hits >= 2);
  // Selection is cached: a hookless call on the same loader returns the bank.
  assert.equal(cap, loader.capabilityBank());
  // No hook on a fresh loader -> configuration error; hook rejecting everything -> discovery error.
  const loaderFresh = new GridLoader(gridRom({ banks: STANDARD_BANKS }).rom, drdi, new Reporter());
  assert.throws(() => loaderFresh.capabilityBank(), /capability bank selection needs a CandidateNode proof hook/);
  // Banks without a proof fall through to the next candidate.
  const rep2 = new Reporter();
  const loader2 = new GridLoader(gridRom({ banks: STANDARD_BANKS }).rom, drdi, rep2);
  const cap2 = loader2.capabilityBank((im) => (im.bank_va === VA_A ? null : 4));
  assert.equal(cap2.bank_va, VA_B);
  assert.ok(rep2.issues.some((i) => i.code === "capability_bank_rejected" && i.context.bank_va === hex(VA_A)));
  assert.equal(rep2.issues.find((i) => i.code === "capability_bank").context.proof_profile, 0);
  // Hook rejecting everything -> discovery error.
  const loader3 = new GridLoader(gridRom({ banks: STANDARD_BANKS }).rom, drdi, new Reporter());
  assert.throws(() => loader3.capabilityBank(() => null), (e) => {
    assert.equal(e.message, "no live grid bank contains a structurally valid CandidateNode array");
    return true;
  });
});

// ---------------------------------------------------------------------------
// Tensor split-CDF fixtures
// ---------------------------------------------------------------------------

async function buildTensor({ corruptSlot = -1, drdiExtra = 0, slotPlan = new Map(), bankBounds = null } = {}) {
  const header = new Uint8Array(0x30000);
  const hv = new DataView(header.buffer);
  const secOff = [164, 164 + 641 * 4, 164 + 641 * 4 + 11 * 4];
  for (let i = 0; i < 20; i++) {
    const off = i < 3 ? secOff[i] : 0;
    const size = [641 * 4, 11 * 4, 640 * 48][i] ?? 0;
    hv.setUint32(4 + i * 8, off, true);
    hv.setUint32(8 + i * 8, size, true);
  }
  const liveDefault = new Map([[0, 0x100], [1, 0x20], [3 * 64, 0x80]]);
  const plan = slotPlan.size ? slotPlan : liveDefault;
  const offsets = new Uint32Array(641);
  let total = 0;
  for (let i = 0; i < 640; i++) {
    offsets[i] = total;
    total += plan.get(i) ?? 0;
  }
  offsets[640] = total;
  for (let i = 0; i < 641; i++) hv.setUint32(secOff[0] + i * 4, offsets[i], true);
  const bounds = bankBounds ?? Array.from({ length: 11 }, (_, i) => 0x60000000 + i * 0x100000);
  bounds.forEach((b, i) => hv.setUint32(secOff[1] + i * 4, b >>> 0, true));
  const drdi = fill(total + drdiExtra, 11);
  if ((plan.get(3 * 64) ?? 0) >= 0x40) drdi.set(FEATURE_SENTINEL, offsets[3 * 64] + 0x10);
  const digests = new Array(640);
  for (let slot = 0; slot < 640; slot++) {
    digests[slot] = await sha384HexAsync(drdi.subarray(offsets[slot], offsets[slot + 1]));
    const raw = new Uint8Array(48);
    for (let i = 0; i < 48; i++) raw[i] = parseInt(digests[slot].slice(i * 2, i * 2 + 2), 16);
    if (slot === corruptSlot) raw[0] ^= 0xff;
    header.set(raw, secOff[2] + slot * 48);
  }
  return { header, drdi, offsets, bounds, secOff, liveOffsets: offsets };
}

test("mtk universal: sha384 sync fallback matches native digests", async () => {
  const sizes = [0, 1, 55, 56, 63, 64, 111, 112, 127, 128, 129, 1000, 4096];
  for (const n of sizes) {
    const data = fill(n, 5);
    assert.equal(sha384HexSync(data), await sha384HexAsync(data), `len ${n}`);
  }
  assert.equal(sha384HexSync(new Uint8Array(0)), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
  assert.equal(sha384HexSync(new Uint8Array([0x61])), "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31");
});

test("mtk universal: tensor CDF probe geometry", async () => {
  const { header } = await buildTensor();
  assert.equal(TensorCdfLoader.probe(header), true);
  assert.equal(TensorCdfLoader.probe(header.subarray(0, 0x2ffff)), false);
  const bad = header.slice();
  new DataView(bad.buffer).setUint32(8 + 2 * 8, 640 * 48 - 1, true);
  assert.equal(TensorCdfLoader.probe(bad), false);
  const badOff = header.slice();
  new DataView(badOff.buffer).setUint32(4, 100, true); // section 0 offset below 164
  assert.equal(TensorCdfLoader.probe(badOff), false);
});

test("mtk universal: tensor CDF loader accepts good geometry and exposes aliased images", async () => {
  const rom = romTablesArea().rom; // super() runs ROM dictionary discovery first
  const { header, drdi, offsets, bounds } = await buildTensor();
  const rep = new Reporter();
  const loader = await TensorCdfLoader.create(rom, header, drdi, rep);
  assert.equal(loader.name, "tensor");
  assert.equal(loader.banks.length, 10);
  assert.equal(TensorCdfLoader.ALIAS, 0x60000000);
  const bank3 = loader.banks[3];
  assert.equal(bank3.bank_va, bounds[3]);
  assert.equal(bank3.table_index, 3);
  assert.deepEqual(bank3.live_profiles, [0]);
  const im = bank3.images[0];
  assert.equal(im.profile, 0);
  assert.equal(im.source_offset, offsets[3 * 64]);
  assert.equal(im.length, 0x80);
  assert.equal(im.alias, 0x60000000);
  assert.equal(im.label, "cdf-bank3/profile0");
  const ptr = 0x60000000 + bounds[3];
  assert.equal(im.resolve(ptr), im.source_offset);
  assert.equal(im.containsVa(ptr + 0x7f), true);
  assert.equal(im.containsVa(ptr + 0x80), false);
  assert.equal(im.u32(ptr), u32(drdi, im.source_offset));
  assert.deepEqual([...im.read(ptr, 8)], [...drdi.subarray(im.source_offset, im.source_offset + 8)]);
  assert.ok(rep.issues.some((i) => i.code === "cdf_integrity" && i.context.ok === 640 && i.context.bad === 0));
  assert.ok(rep.issues.some((i) => i.code === "tensor_loader" && i.context.banks === 10));
  // Trailing bytes after the last slot are reported, not rejected.
  const trailing = await buildTensor({ drdiExtra: 16 });
  const rep2 = new Reporter();
  const loader2 = await TensorCdfLoader.create(rom, trailing.header, trailing.drdi, rep2);
  assert.ok(rep2.issues.some((i) => i.code === "cdf_trailing_data" && i.context.trailing_bytes === 16));
  assert.equal(loader2.banks.length, 10);
});

test("mtk universal: tensor CDF loader validation rejections", async () => {
  const rom = romTablesArea().rom;
  const good = await buildTensor();
  // Corrupt SHA-384 digest for one slot.
  const corrupt = await buildTensor({ corruptSlot: 3 * 64 });
  await assert.rejects(
    () => TensorCdfLoader.create(rom, corrupt.header, corrupt.drdi, new Reporter()),
    (e) => {
      assert.equal(e.message, "CDF SHA-384 validation failed for 1/640 slots");
      return true;
    },
  );
  // Wrong header geometry (constructor path, before ROM discovery).
  const badShape = good.header.slice();
  new DataView(badShape.buffer).setUint32(8 + 2 * 8, 640 * 47, true);
  assert.throws(() => new TensorCdfLoader(rom, badShape, good.drdi, new Reporter()), (e) => {
    assert.equal(e.message, "split-CDF header failed section geometry (expected 0x30000, 641 offsets, 11 bounds, 640 SHA-384 digests)");
    return true;
  });
  // Non-monotone slot offsets.
  const badOffsets = await buildTensor({ slotPlan: new Map([[0, 0x100], [1, 0x20]]) });
  new DataView(badOffsets.header.buffer).setUint32(badOffsets.secOff[0] + 5 * 4, 0xffffffff, true);
  await assert.rejects(
    () => TensorCdfLoader.create(rom, badOffsets.header, badOffsets.drdi, new Reporter()),
    (e) => {
      assert.equal(e.message, "CDF slot offsets are not monotone");
      return true;
    },
  );
  // Bank bounds must strictly increase.
  const flatBounds = await buildTensor({ bankBounds: Array.from({ length: 11 }, () => 0x60000000) });
  await assert.rejects(
    () => TensorCdfLoader.create(rom, flatBounds.header, flatBounds.drdi, new Reporter()),
    (e) => {
      assert.equal(e.message, "CDF bank bounds are not strictly increasing");
      return true;
    },
  );
  // Final slot offset beyond the data buffer.
  await assert.rejects(
    () => TensorCdfLoader.create(rom, good.header, good.drdi.subarray(0, good.offsets[640] - 1), new Reporter()),
    (e) => {
      assert.equal(e.message, `CDF final slot offset ${hex(good.offsets[640])} exceeds data size ${hex(good.offsets[640] - 1)}`);
      return true;
    },
  );
  // Live image after a stub.
  const afterStub = await buildTensor({ slotPlan: new Map([[3 * 64, 0x100], [3 * 64 + 2, 0x80]]) });
  await assert.rejects(
    () => TensorCdfLoader.create(rom, afterStub.header, afterStub.drdi, new Reporter()),
    (e) => {
      assert.equal(e.message, "CDF bank 3 has live image after stub at profile 2");
      return true;
    },
  );
});

test("mtk universal: tensor capability bank by sentinel + proof hook", async () => {
  const rom = romTablesArea().rom;
  const { header, drdi } = await buildTensor();
  const rep = new Reporter();
  const loader = await TensorCdfLoader.create(rom, header, drdi, rep);
  const prove = (im) => (im.profile === 0 && im.bank_va === loader.banks[3].bank_va ? 7 : null);
  const cap = loader.capabilityBank(prove);
  assert.equal(cap.table_index, 3);
  const info = rep.issues.find((i) => i.code === "capability_bank");
  assert.equal(info.message, "selected CDF capability bank by sentinel + CandidateNode proof");
  assert.equal(info.context.proof_candidate_count, 7);
  assert.equal(info.context.sentinel_profiles, 1);
  assert.throws(() => loader.capabilityBank(), /capability bank selection needs a CandidateNode proof hook/);
  const loader2 = await TensorCdfLoader.create(rom, header, drdi, new Reporter());
  assert.throws(() => loader2.capabilityBank(() => null), (e) => {
    assert.equal(e.message, "no CDF bank containing feature sentinels also contains a 100%-valid CandidateNode array");
    return true;
  });
});

// ---------------------------------------------------------------------------

test("mtk universal: Reporter collects issues and enforces checks", () => {
  const rep = new Reporter();
  rep.info("c", "i", { a: 1 });
  rep.warn("c2", "w");
  rep.fail("c3", "f");
  rep.check("ok", true, { v: 1 });
  assert.throws(() => rep.check("bad", false, { why: "x" }), (e) => {
    assert.ok(e instanceof UniversalError);
    assert.equal(e.message, "check failed: bad: {'why': 'x'}");
    return true;
  });
  const d = rep.asDict();
  assert.deepEqual(d.issues.map((i) => i.level), ["info", "warning", "error"]);
  assert.deepEqual(d.checks, [{ name: "ok", passed: true, v: 1 }, { name: "bad", passed: false, why: "x" }]);
});

test("mtk universal: Image/Bank record helpers", () => {
  const drdi = fill(64, 8);
  const im = new Image(0x62000000, 2, 16, 32, 0x62000000 - 16, drdi, "bank0/profile2", 0x40000000);
  const ptr = 0x40000000 + 0x62000000; // aliased runtime pointer to image byte 0
  assert.equal(im.resolve(ptr), 16);
  assert.equal(im.resolve(ptr + 31), 47);
  assert.equal(im.resolve(ptr + 32), null);
  assert.equal(im.resolve(0x62000000), null); // unaliased va falls outside through the alias path
  assert.equal(im.containsVa(ptr + 31), true);
  assert.deepEqual([...im.read(ptr, 4)], [...drdi.subarray(16, 20)]);
  assert.equal(new Image(1, 0, 0, 8, 1, drdi).candidate_hint, null);
  const bank = new Bank(0x62000000, [im], 0);
  assert.deepEqual(bank.live_profiles, [2]);
  assert.deepEqual(bank.toDict(), {
    table_index: 0,
    bank_va: "0x62000000",
    live_profiles: [2],
    images: [im.toDict()],
  });
});

// ---------------------------------------------------------------------------
// Corpus-gated probe (both sample modem images)
// ---------------------------------------------------------------------------

const MTK_CORPUS = [
  {
    file: "Oppo_Find_X10_Pro_Max_5G_PMX110-modem.img",
    romBytes: 50659328,
    drdiBytes: 43922704,
    romSha256: "c56c960c283a04c5deea92492c9595e0c449416b128d719fea9f20ee26332c59",
    drdiSha256: "8b0b505e8220fcc38d591f604d217d343ee626daedab366370ee0e5ef566a128",
    processedBytes: 280470471,
  },
  {
    file: "mtk_pocox8pro_d8500u_modem.img",
    romBytes: 41353216,
    drdiBytes: 27283968,
    romSha256: "4dc97b67a9b3838a0ae8030003797b5f156872234321e53a11b37a96f7df6ce5",
    drdiSha256: "b0c255e2565b80033621944d6c901772d2ae7184b659dbcadf387ed1f08f0b9d",
    processedBytes: 205689971,
  },
];
const mtkCorpusAvailable = () => MTK_CORPUS.every((c) => existsSync(join(CORPUS_DIR, c.file)));

test("mtk corpus probe: unwrap + grid loader + rom tables on both sample images", { skip: !mtkCorpusAvailable() }, async () => {
  const { unwrapBytes } = await import("../js/lib/mtk_containers.js");
  for (const spec of MTK_CORPUS) {
    const data = await readFile(join(CORPUS_DIR, spec.file)); // single read, no copies
    const parts = await unwrapBytes(data, spec.file);
    assert.deepEqual(parts.report.layers.map((l) => l.format), ["mtk", "gzip"], spec.file);
    assert.equal(parts.report.packaging, "single-drdi", spec.file);
    assert.equal(parts.report.identical_sets, 1, spec.file);
    assert.equal(parts.report.processed_bytes, spec.processedBytes, spec.file);
    assert.equal(parts.rom.length, spec.romBytes, spec.file);
    assert.equal(parts.drdi.length, spec.drdiBytes, spec.file);
    assert.equal(parts.drdi_data, null, spec.file);
    assert.equal(parts.report.selected.md1rom.sha256, spec.romSha256, spec.file);
    assert.equal(parts.report.selected.md1drdi.sha256, spec.drdiSha256, spec.file);
    // Loader probe succeeds and ROM dictionaries resolve on the real md1rom.
    assert.ok(GridLoader.probe(parts.rom, parts.drdi) > 0, `${spec.file}: grid probe`);
    const rep = new Reporter();
    const tables = discoverRomTables(parts.rom, rep);
    assert.equal(tables.bw_family, "modern20", spec.file);
    assert.ok(tables.nr_weights.length >= 12, `${spec.file}: nr weights`);
    assert.deepEqual(tables.lte_weights, [...LTE_WEIGHTS_EXPECTED], spec.file);
    assert.equal(tables.lte_band_map.length, BANDMAP_LEN, spec.file);
    assert.ok(tables.nr_ul_absent.has(NR_UL_ABSENT_CANON), spec.file);
  }
});
