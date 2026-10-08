import { test } from "node:test";
import assert from "node:assert/strict";
import { StructReader, hex, hexToBytes, indexOfBytes } from "../js/lib/bytes.js";
import { utf8 } from "../js/lib/bytes.js";

test("struct reader reads LE formats and raises on short read", () => {
  const b = new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
  const r = new StructReader(b.buffer, b.byteOffset, b.byteLength);
  assert.equal(r.u16(0), 0x0201);
  assert.equal(r.u32(2), 0x06050403); // bytes[2..5] = 03 04 05 06; plan said 0x04030201 (u32(0)) — plan bug
  assert.deepEqual(r.unpack("<HBBBBB", 0), [0x0201, 0x03, 0x04, 0x05, 0x06, 0x07]);
  assert.throws(() => r.u32(6), RangeError);
});

test("unpackFrom matches struct '<HHIHHIII>' fixture layout", () => {
  const fields = [0x0a0b, 0x0c0d, 0x10203040, 0x0102, 0x0304, 0x0506, 0x0708, 0x090a];
  const size = 2+2+4+2+2+4+4+4; // 24
  const buf = new ArrayBuffer(size); const dv = new DataView(buf);
  let o = 0;
  for (const [fmt, v] of [["H",fields[0]],["H",fields[1]],["I",fields[2]],["H",fields[3]],["H",fields[4]],["I",fields[5]],["I",fields[6]],["I",fields[7]]]) {
    if (fmt === "H") dv.setUint16(o, v, true); else dv.setUint32(o, v, true);
    o += fmt === "H" ? 2 : 4;
  }
  const r = new StructReader(buf);
  assert.deepEqual(r.unpack("<HHIHHIII", 0), fields);
});

test("unpack/sizeOf expand Python repeat counts", () => {
  const buf = new ArrayBuffer(10);
  const dv = new DataView(buf);
  for (let i = 0; i < 5; i++) dv.setUint16(i * 2, 100 + i, true);
  const r = new StructReader(buf);
  assert.deepEqual(r.unpack("<5H", 0), [100, 101, 102, 103, 104]);
  const b4 = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
  assert.deepEqual(new StructReader(b4.buffer).unpack("2H", 0), [0x0201, 0x0403]);
  assert.equal(r.sizeOf("<5H>"), 10);
  assert.equal(r.sizeOf("<12H>"), 24);
  assert.equal(r.sizeOf("<8I>"), 32);
  assert.equal(r.sizeOf("<IIIBBH>"), 16);
});

test("StructReader accepts Uint8Array views with byte offsets", () => {
  const b = new Uint8Array([0, 0, 0xaa, 0xbb]);
  const view = b.subarray(2);
  const r = new StructReader(view);
  assert.equal(r.u16(0), 0xbbaa);
  assert.throws(() => r.u32(0), RangeError);
});

test("hex roundtrip + indexOfBytes", () => {
  const b = [0xde, 0xad, 0xbe, 0xef];
  assert.equal(hex(new Uint8Array(b)), "deadbeef");
  assert.deepEqual([...hexToBytes("deadbeef")], b);
  const hay = new Uint8Array([0, 0x3a, 0xff, 0x26, 0xed, 0]);
  assert.equal(indexOfBytes(hay, [0x3a, 0xff, 0x26, 0xed], 0), 1);
  assert.equal(indexOfBytes(hay, [0x3a], 2), -1);
  assert.equal(indexOfBytes(hay, [], 3), 3); // empty needle matches at from (Python bytes.find parity)
  assert.equal(indexOfBytes(hay, [0xed], 0), 4); // match at last valid index
  assert.equal(indexOfBytes(hay, [0xed], 5), -1);
});

test("signed readers i16/i32 decode little-endian negatives", () => {
  const b = new Uint8Array(6);
  const dv = new DataView(b.buffer);
  dv.setInt16(0, -2, true);
  dv.setInt32(2, -1000, true);
  const r = new StructReader(b.buffer);
  assert.equal(r.i16(0), -2);
  assert.equal(r.i32(2), -1000);
});

test("sizeOf computes packed struct sizes", () => {
  const r = new StructReader(new ArrayBuffer(0));
  assert.equal(r.sizeOf("<HHIHHIII"), 24);
  assert.equal(r.sizeOf("BBH"), 4);
  assert.throws(() => r.sizeOf("Q"), Error);
});

test("utf8 decodes with replacement semantics", () => {
  const b = new TextEncoder().encode("héllo");
  assert.equal(utf8(b, 0, b.length), "héllo");
  assert.equal(utf8(new Uint8Array([0x61, 0xff, 0x62]), 0, 3), "a\uFFFDb");
});

test("utf8 keeps a leading U+FEFF like Python .decode('utf-8', 'replace')", () => {
  // TextDecoder strips a leading EF BB BF by default; Python's decoder keeps
  // the U+FEFF character (ignoreBOM: true is the "do not strip" setting).
  assert.equal(utf8(new Uint8Array([0xef, 0xbb, 0xbf]), 0, 3), "\uFEFF");
  assert.equal(utf8(new Uint8Array([0xef, 0xbb, 0xbf, 0x41]), 0, 4), "\uFEFFA");
  // A mid-stream BOM was never stripped; it must survive as well.
  assert.equal(utf8(new Uint8Array([0x41, 0xef, 0xbb, 0xbf, 0x42]), 0, 5), "A\uFEFFB");
});

test("hex() lowercases all 256 byte values and handles empty input", () => {
  const all = new Uint8Array(256);
  for (let i = 0; i < 256; i++) all[i] = i;
  const expected = Array.from(all, (b) => b.toString(16).padStart(2, "0")).join("");
  assert.equal(hex(all), expected);
  assert.equal(hex(new Uint8Array(0)), "");
  const view = all.subarray(250); // subarray view must work
  assert.equal(hex(view), "fafbfcfdfeff");
});
