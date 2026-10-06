// Shared synthetic MTK fixture builders (extracted from mtk_scan.test.mjs so
// the worker protocol tests can assemble multi-file parts imports from the
// same hand-built grid images). All corpus-independent.
import {
  BANDMAP_LEN,
  BANDMAP_PREFIX,
  BW_FAMILIES,
  LTE_UL_ABSENT,
  LTE_WEIGHT_PREFIX,
  NR_WEIGHT_PREFIX,
} from "../js/lib/mtk_universal.js";

export const concatParts = (parts) => {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
};

export const u16le = (n) => new Uint8Array([n & 0xff, (n >>> 8) & 0xff]);
export const u32le = (n) => new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
export const writeU32 = (a, off, v) => a.set(u32le(v >>> 0), off);
export const writeU16 = (a, off, v) => { a[off] = v & 0xff; a[off + 1] = (v >>> 8) & 0xff; };

// ROM dictionary area: LTE weights at 16, BW enum at 24, NR weights directly
// after the enum, band map after that (the layout that resolves through the
// "NR right after enum" rule of discover_rom_tables).
export function romArea() {
  const tbl = BW_FAMILIES.modern20;
  const lteOff = 16;
  const bwOff = 24;
  const nrOff = bwOff + tbl.length * 2;
  const mapOff = nrOff + tbl.length + 1;
  const matrixOff = (mapOff + BANDMAP_LEN + 3) & ~3;
  const rom = new Uint8Array(matrixOff + 0x100);
  rom.set(concatParts([LTE_WEIGHT_PREFIX, new Uint8Array([0, 0])]), lteOff);
  rom.set(concatParts(tbl.map(u16le)), bwOff);
  rom.set(concatParts([NR_WEIGHT_PREFIX, new Uint8Array([0xff])]), nrOff);
  const map = new Uint8Array(BANDMAP_LEN);
  map.set(BANDMAP_PREFIX, 0);
  map[BANDMAP_LEN - 1] = 0;
  rom.set(map, mapOff);
  return { rom, lteOff, bwOff, nrOff, mapOff, matrixOff };
}

// 12-byte grid descriptor matrix entries: { src, va, len }.
export function descriptorMatrix(rom, off, entries) {
  entries.forEach((e, i) => {
    const o = off + i * 12;
    writeU32(rom, o, (0x30000000 | e.src) >>> 0);
    writeU32(rom, o + 4, e.va);
    writeU32(rom, o + 8, e.len);
  });
}

// One capability-bank profile image. Layout (all words 4-aligned relative to
// the image start so the pointer-run scan sees them):
//   candidate pointer run (5 nodes, or two 4-node runs around a zero word),
//   two candidate nodes sharing one LTE+NR descriptor pair, then three feature
//   tables: DL (5 objects), UL (4 objects, with an absent object at index 2 so
//   the UL table is refused as a DL side — the corpus' asymmetry that makes
//   the (DL, UL) winner unique), and a longer 6-object UL variant.
// brokenLteMimo flips the LTE FSC MIMO status byte to 3, which decodes nowhere.
export function capImage({ vaBase, alias = 0, splitRun = false, brokenLteMimo = false } = {}) {
  const len = 0x200;
  const im = new Uint8Array(len);
  const VA = (r) => (vaBase + r + alias) >>> 0;
  const put = (off, v) => writeU32(im, off, v);
  const nodeBase = splitRun ? 0x30 : 0x20;
  const c1Off = nodeBase;
  const c2Off = nodeBase + 0x10;
  const nrDesc = nodeBase + 0x20;
  const nrRec = nrDesc + 0x10;
  const nrFsc = nrRec + 8;
  const lteDesc = 0x80;
  const lteRec = 0x90;
  const lteFsc = 0x98;
  const dlObj = 0xa0;
  const dlTab = 0xb0;
  const ulObj = 0xc8;
  const ulTab = 0xd4;
  const ulLongObj = 0xe8;
  const ulLongTab = 0xfc;
  // Candidate pointer run(s): [C1, C2, C1, C2, C1] or two 4-entry runs.
  if (!splitRun) {
    for (let k = 0; k < 5; k++) put(4 * k, k % 2 ? VA(c2Off) : VA(c1Off));
  } else {
    for (let k = 0; k < 4; k++) put(4 * k, VA(c1Off));
    for (let k = 0; k < 4; k++) put(0x14 + 4 * k, VA(c1Off));
  }
  // Candidate nodes share both descriptors (dedup path).
  for (const c of [c1Off, c2Off]) {
    put(c, 0); put(c + 4, 0);
    put(c + 8, VA(lteDesc)); put(c + 12, VA(nrDesc));
  }
  // NR descriptor: 2 records, 3 FSC rows (units 1+2, one variant).
  put(nrDesc, 2); put(nrDesc + 4, VA(nrRec)); put(nrDesc + 8, 3); put(nrDesc + 12, VA(nrFsc));
  // record 0: band 1, UL absent (0x1c), DL class 0 (weight 1)
  writeU16(im, nrRec, 1); im[nrRec + 2] = 0x1c; im[nrRec + 3] = 0;
  // record 1: band 3, UL class 1 (weight 2), DL class 1 (weight 2)
  writeU16(im, nrRec + 4, 3); im[nrRec + 6] = 1; im[nrRec + 7] = 1;
  // FSC rows: (scs, ulFeatureIdx, dlFeatureIdx); the UL feature ids stop at 1
  // so the absent UL object at index 2 never enters the closure domain. The
  // last row's DL id 3 is the mimo_status-2 object (8 layers) — this pins the
  // DL_MIMO status-2 mapping that the corpus never exercises.
  im.set([1, 0, 1, 0, 1, 2, 1, 1, 3], nrFsc);
  // LTE descriptor: 1 record, 1 FSC row (units 1, one variant).
  put(lteDesc, 1); put(lteDesc + 4, VA(lteRec)); put(lteDesc + 8, 1); put(lteDesc + 12, VA(lteFsc));
  // record: band-map index 1 (band 1), UL absent (6), DL class 0
  im[lteRec] = 1; im[lteRec + 1] = LTE_UL_ABSENT; im[lteRec + 2] = 0;
  im[lteFsc] = 0; im[lteFsc + 1] = brokenLteMimo ? 3 : 1;
  // DL feature table: absent entry + 4 supported objects.
  im.set([3, 20, 1, 0, 0, 1, 1, 1, 0, 2, 2, 1, 1, 1, 0], dlObj);
  for (let k = 0; k < 5; k++) put(dlTab + 4 * k, VA(dlObj + 3 * k));
  // UL feature table: absent entry, one active object, an absent object at
  // index 2 (blocks DL-side admissibility without touching the closure
  // domain), one more active object.
  im.set([3, 20, 1, 0, 2, 1, 3, 20, 1, 0, 4, 1], ulObj);
  for (let k = 0; k < 4; k++) put(ulTab + 4 * k, VA(ulObj + 3 * k));
  // Longer UL variant (6 objects), admissible on both sides but with more
  // slack, so the (DL, UL) winner stays unique like on the corpus.
  im.set([3, 20, 1, 0, 2, 1, 1, 3, 0, 0, 4, 1, 1, 5, 0, 2, 6, 1], ulLongObj);
  for (let k = 0; k < 6; k++) put(ulLongTab + 4 * k, VA(ulLongObj + 3 * k));
  return { im, len, dlObj, ulObj, ulLongObj };
}

// LTE CA row table bank image: `rows` identical contiguous rows of `stride`
// bytes (32 legacy / 36 extended), all mapping to the same single-band combo.
export function lteRowImage({ vaBase, alias = 0, stride = 32, rows = 5, mimo = 2 } = {}) {
  const len = 0x100;
  const im = new Uint8Array(len);
  const VA = (r) => (vaBase + r + alias) >>> 0;
  const recOff = rows * stride + 0x10;
  const mimoOff = recOff + 8;
  const compOff = mimoOff + 8;
  for (let k = 0; k < rows; k++) {
    const off = k * stride;
    if (stride === 36) {
      writeU32(im, off + 4, 0xffff0000); // flags: 0xFFFF in the high half
      writeU32(im, off + 12, 1); // component count
      writeU32(im, off + 16, VA(recOff));
      writeU32(im, off + 20, 1); // mimo count
      writeU32(im, off + 24, VA(mimoOff));
      writeU32(im, off + 28, VA(compOff));
      writeU32(im, off + 32, 1); // component count copy
    } else {
      // legacy32: [8 arbitrary bytes][c0][p0][c1][p1][c2][p2]
      writeU32(im, off + 8, 1);
      writeU32(im, off + 12, VA(recOff));
      writeU32(im, off + 16, 1);
      writeU32(im, off + 20, VA(mimoOff));
      writeU32(im, off + 24, 0);
      writeU32(im, off + 28, 0);
    }
  }
  // record: band-map index 1 (band 1), UL absent, DL class 0 (weight 1)
  im[recOff] = 1; im[recOff + 1] = LTE_UL_ABSENT; im[recOff + 2] = 0;
  im[mimoOff] = mimo;
  im[compOff] = mimo;
  return { im, len };
}

// Wrap members in one MTK partition container (80-byte headers + data).
export function mtkPartition(members) {
  const parts = [];
  for (const { name, data } of members) {
    const header = new Uint8Array(512);
    header[0] = 0x88; header[1] = 0x16; header[2] = 0x88; header[3] = 0x58;
    const dv = new DataView(header.buffer);
    dv.setUint32(4, data.length, true);
    for (let i = 0; i < name.length; i++) header[8 + i] = name.charCodeAt(i) & 0x7f;
    dv.setUint32(48, 0x58891689, true);
    dv.setUint32(52, 512, true);
    parts.push(header, data);
  }
  return concatParts(parts);
}

// Synthetic grid image: capability bank 0 with one live profile (plus an
// optional second, broken profile) and an LTE row bank 1.
export function buildGridImage({ brokenProfile1 = false, splitRun = false } = {}) {
  const { rom, matrixOff } = romArea();
  const capVa = 0x6b000000;
  const lteVa = 0x6b100000;
  const capLen = 0x200;
  const cap1Len = brokenProfile1 ? 0x200 : 16;
  const lteLen = 0x100;
  const capSrc = 0x1000;
  const cap1Src = capSrc + capLen;
  const lteSrc = cap1Src + cap1Len;
  const lte1Src = lteSrc + lteLen;
  const drdi = new Uint8Array(lte1Src + 16);
  drdi.set(capImage({ vaBase: capVa, splitRun }).im, capSrc);
  if (brokenProfile1) {
    // Same bank VA: profile images mount at their own relocation.
    drdi.set(capImage({ vaBase: capVa, brokenLteMimo: true }).im, cap1Src);
  }
  drdi.set(lteRowImage({ vaBase: lteVa }).im, lteSrc);
  descriptorMatrix(rom, matrixOff, [
    { src: capSrc, va: capVa, len: capLen },
    { src: cap1Src, va: capVa, len: cap1Len },
    { src: lteSrc, va: lteVa, len: lteLen },
    { src: lte1Src, va: lteVa, len: 16 },
  ]);
  return {
    image: mtkPartition([
      { name: "md1rom", data: rom },
      { name: "md1drdi", data: drdi },
    ]),
    rom, drdi,
    capVa, lteVa, capSrc, capLen,
  };
}

// Flat (MD800) fixture: one 64-word CandidateNode pointer run whose node
// objects start exactly one word after the run (the loader's bias-4 adjacency
// hypothesis), a 64-word LTE row pointer array with the same +4 object offset
// (row_bias 4), and the shared dictionary rom WITHOUT a descriptor matrix (the
// grid attempt must fail). Structures mirror capImage's, shifted past the run.
export function buildFlatImage() {
  const { rom } = romArea();
  const RELOC = 0x6b000000;
  const VA = (r) => (RELOC + r) >>> 0;
  const nodes = 64;
  const arrOff = 0;
  const c1Off = nodes * 4 + 4; // 0x104: one word after the run ends (bias 4)
  const c2Off = c1Off + 0x10;
  const nrDesc = c2Off + 0x10;
  const nrRec = nrDesc + 0x10;
  const nrFsc = nrRec + 8;
  const lteDesc = 0x160;
  const lteRec = 0x170;
  const lteFsc = 0x178;
  const dlObj = 0x184;
  const dlTab = 0x194;
  const ulObj = 0x1ac;
  const ulTab = 0x1b8;
  const ulLongObj = 0x1cc;
  const ulLongTab = 0x1e0;
  const lteArrOff = 0x200; // 64-word LTE row pointer array
  const lteRowObj = lteArrOff + nodes * 4 + 4; // 0x304: row_bias 4 adjacency
  const lteRecOff = 0x31c;
  const lteMimoOff = 0x324;
  const len = 0x400;
  const im = new Uint8Array(len);
  const put = (off, v) => writeU32(im, off, v);
  // Candidate pointer run: 64 words alternating between the two nodes.
  for (let k = 0; k < nodes; k++) put(arrOff + 4 * k, k % 2 ? VA(c2Off) : VA(c1Off));
  // Candidate nodes + descriptors + feature tables (same content as capImage).
  for (const c of [c1Off, c2Off]) {
    put(c, 0); put(c + 4, 0);
    put(c + 8, VA(lteDesc)); put(c + 12, VA(nrDesc));
  }
  put(nrDesc, 2); put(nrDesc + 4, VA(nrRec)); put(nrDesc + 8, 3); put(nrDesc + 12, VA(nrFsc));
  writeU16(im, nrRec, 1); im[nrRec + 2] = 0x1c; im[nrRec + 3] = 0;
  writeU16(im, nrRec + 4, 3); im[nrRec + 6] = 1; im[nrRec + 7] = 1;
  im.set([1, 0, 1, 0, 1, 2, 1, 1, 3], nrFsc);
  put(lteDesc, 1); put(lteDesc + 4, VA(lteRec)); put(lteDesc + 8, 1); put(lteDesc + 12, VA(lteFsc));
  im[lteRec] = 1; im[lteRec + 1] = LTE_UL_ABSENT; im[lteRec + 2] = 0;
  im[lteFsc] = 0; im[lteFsc + 1] = 1;
  im.set([3, 20, 1, 0, 0, 1, 1, 1, 0, 2, 2, 1, 1, 1, 0], dlObj);
  for (let k = 0; k < 5; k++) put(dlTab + 4 * k, VA(dlObj + 3 * k));
  im.set([3, 20, 1, 0, 2, 1, 3, 20, 1, 0, 4, 1], ulObj);
  for (let k = 0; k < 4; k++) put(ulTab + 4 * k, VA(ulObj + 3 * k));
  im.set([3, 20, 1, 0, 2, 1, 1, 3, 0, 0, 4, 1, 1, 5, 0, 2, 6, 1], ulLongObj);
  for (let k = 0; k < 6; k++) put(ulLongTab + 4 * k, VA(ulLongObj + 3 * k));
  // LTE row pointer array: 64 words pointing at one row object laid out for
  // the row_bias 4 probe ([pad][c0][p0][c1][p1]).
  for (let k = 0; k < nodes; k++) put(lteArrOff + 4 * k, VA(lteRowObj));
  put(lteRowObj, 0);
  put(lteRowObj + 4, 1); // c0
  put(lteRowObj + 8, VA(lteRecOff)); // p0
  put(lteRowObj + 12, 1); // c1
  put(lteRowObj + 16, VA(lteMimoOff)); // p1
  im[lteRecOff] = 1; im[lteRecOff + 1] = LTE_UL_ABSENT; im[lteRecOff + 2] = 0;
  im[lteMimoOff] = 2;
  return {
    image: mtkPartition([
      { name: "md1rom", data: rom },
      { name: "md1drdi", data: im },
    ]),
    rom,
    drdi: im,
    RELOC,
  };
}
